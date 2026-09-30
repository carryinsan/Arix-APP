import fs from 'fs';
import path from 'path';
import vm from 'vm';
import crypto from 'crypto';

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

// Helper to interact with Upstash REST
async function redis(command, ...args) {
    if (!UPSTASH_URL || !UPSTASH_TOKEN) {
        throw new Error('Upstash credentials are not set in environment variables.');
    }
    const res = await fetch(`${UPSTASH_URL}/`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${UPSTASH_TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify([command, ...args])
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    return data.result;
}

// Cookie parser
function parseCookies(cookieHeader) {
    const list = {};
    if (!cookieHeader) return list;
    cookieHeader.split(`;`).forEach(function(cookie) {
        let [ name, ...rest] = cookie.split(`=`);
        name = name?.trim();
        if (!name) return;
        const value = rest.join(`=`).trim();
        if (!value) return;
        list[name] = decodeURIComponent(value);
    });
    return list;
}

// Generate random ID
function genId(len = 16) {
    return crypto.randomBytes(len).toString('hex');
}

export default async function handler(req, res) {
    try {
        const host = req.headers.host || '';
        const mainDomain = 'arix-app.vercel.com'; // You can change this to match your actual main domain if different
        
        // --- SUBDOMAIN ROUTING (USER APPS) ---
        if (host !== mainDomain && host !== `www.${mainDomain}` && !host.includes('localhost') && !host.includes('vercel.app')) {
            let slug = host.split('.')[0];
            
            let projectId = await redis('GET', `slug:${slug}`);
            if (!projectId) {
                return res.status(404).send(`Project '${slug}' not found.`);
            }
            
            let urlPath = req.url.split('?')[0];
            if (urlPath === '/') urlPath = '/index.html';
            
            // Check if file exists in redis
            let fileContent = await redis('HGET', `files:${projectId}`, urlPath);
            
            if (fileContent !== null) {
                let ext = urlPath.split('.').pop().toLowerCase();
                let mimeType = 'text/plain';
                if (ext === 'html') mimeType = 'text/html';
                else if (ext === 'css') mimeType = 'text/css';
                else if (ext === 'js') mimeType = 'application/javascript';
                else if (ext === 'json') mimeType = 'application/json';
                else if (ext === 'svg') mimeType = 'image/svg+xml';
                
                res.setHeader('Content-Type', mimeType);
                return res.status(200).send(fileContent);
            }
            
            // API Routes execution
            if (urlPath.startsWith('/api/')) {
                let apiFile = urlPath + '.js';
                let apiContent = await redis('HGET', `files:${projectId}`, apiFile);
                if (apiContent === null) {
                    return res.status(404).json({error: 'API endpoint not found'});
                }
                
                let envVars = await redis('HGETALL', `env:${projectId}`);
                let env = {};
                if (envVars && Array.isArray(envVars)) {
                     for (let i=0; i<envVars.length; i+=2) {
                          env[envVars[i]] = envVars[i+1];
                     }
                }
                
                return new Promise((resolve) => {
                    const wrapper = `
                        ${apiContent}
                        (async () => {
                            try {
                                if (typeof handler === 'function') {
                                    await handler(req, res);
                                } else if (typeof GET === 'function' && req.method === 'GET') {
                                    const response = await GET(req);
                                    if(response) {
                                        res.status(response.status || 200).send(await response.text());
                                    }
                                } else if (typeof POST === 'function' && req.method === 'POST') {
                                    const response = await POST(req);
                                    if(response) {
                                        res.status(response.status || 200).send(await response.text());
                                    }
                                } else {
                                    res.status(500).json({error: 'No valid handler exported'});
                                }
                            } catch (e) {
                                res.status(500).json({error: 'Function Execution Error: ' + e.message});
                            }
                        })();
                    `;
                    
                    const executionContext = vm.createContext({
                        req, res, console, fetch, process: { env }, URL, URLSearchParams
                    });
                    
                    try {
                        vm.runInContext(wrapper, executionContext, { timeout: 10000 });
                        // Don't resolve immediately, let the user's code call res.send
                        // If they don't call it, it will eventually timeout in Vercel.
                    } catch(err) {
                        res.status(500).json({error: 'Compile Error: ' + err.message});
                        resolve();
                    }
                });
            }
            
            return res.status(404).send('404 Not Found in this project.');
        }

        // --- PLATFORM API ---
        if (req.url.startsWith('/api/platform/')) {
            const urlParts = req.url.split('?')[0].split('/');
            const action = urlParts[3];
            
            // Allow parsing JSON body
            const getBody = () => {
                return new Promise((resolve) => {
                    let body = '';
                    req.on('data', chunk => body += chunk.toString());
                    req.on('end', () => {
                        try { resolve(JSON.parse(body || '{}')); } 
                        catch (e) { resolve({}); }
                    });
                });
            };

            // Session check with 7 days rolling expiration
            const getUserId = async () => {
                const apiKey = req.headers['authorization']?.split(' ')[1];
                if (apiKey) {
                    const uId = await redis('GET', `apikey:${apiKey}`);
                    if (uId) return uId;
                }
                const cookies = parseCookies(req.headers.cookie);
                const token = cookies.token;
                if (!token) return null;
                const userId = await redis('GET', `session:${token}`);
                if (userId) {
                    // Extend for 7 days
                    await redis('EXPIRE', `session:${token}`, 7 * 24 * 60 * 60);
                    res.setHeader('Set-Cookie', `token=${token}; Max-Age=${7 * 24 * 60 * 60}; HttpOnly; Path=/; SameSite=Lax`);
                    return userId;
                }
                return null;
            };

            if (req.method === 'GET' && action === 'me') {
                const userId = await getUserId();
                if (!userId) return res.status(401).json({error: 'Unauthorized'});
                const user = await redis('HGETALL', `user:${userId}`);
                return res.json({userId, ...convertHashToObject(user)});
            }

            if (req.method === 'POST' && action === 'logout') {
                const cookies = parseCookies(req.headers.cookie);
                if (cookies.token) await redis('DEL', `session:${cookies.token}`);
                res.setHeader('Set-Cookie', `token=; Max-Age=0; HttpOnly; Path=/; SameSite=Lax`);
                return res.json({success:true});
            }

            // GITHUB OAUTH
            if (req.method === 'GET' && action === 'oauth' && urlParts[4] === 'github') {
                const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
                if (!GITHUB_CLIENT_ID) return res.status(500).send('Github OAuth not configured');
                const redirect = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=user:email`;
                res.writeHead(302, { Location: redirect });
                return res.end();
            }

            if (req.method === 'GET' && action === 'oauth' && urlParts[4] === 'github_callback') {
                const query = new URLSearchParams(req.url.split('?')[1]);
                const code = query.get('code');
                const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
                const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
                
                // Exchange code
                const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
                    body: JSON.stringify({client_id: GITHUB_CLIENT_ID, client_secret: GITHUB_CLIENT_SECRET, code})
                });
                const tokenData = await tokenRes.json();
                
                // Get user info
                const userRes = await fetch('https://api.github.com/user', {
                    headers: {'Authorization': `Bearer ${tokenData.access_token}`}
                });
                const userData = await userRes.json();
                
                // Login or Register
                const email = userData.email || userData.login + '@github.com';
                let userId = await redis('GET', `email:${email}`);
                if (!userId) {
                    userId = genId();
                    await redis('SET', `email:${email}`, userId);
                    await redis('HSET', `user:${userId}`, 'email', email, 'name', userData.name || userData.login, 'provider', 'github');
                }
                
                // Set Session (7 days)
                const token = genId(32);
                await redis('SETEX', `session:${token}`, 7 * 24 * 60 * 60, userId);
                res.setHeader('Set-Cookie', `token=${token}; Max-Age=${7 * 24 * 60 * 60}; HttpOnly; Path=/; SameSite=Lax`);
                
                res.writeHead(302, { Location: '/' });
                return res.end();
            }

            // Fallback Password/Email auth for testing if OAuth isn't setup
            if (req.method === 'POST' && action === 'devlogin') {
                const body = await getBody();
                const email = body.email;
                if (!email) return res.status(400).json({error: 'Email required'});
                let userId = await redis('GET', `email:${email}`);
                if (!userId) {
                    userId = genId();
                    await redis('SET', `email:${email}`, userId);
                    await redis('HSET', `user:${userId}`, 'email', email, 'name', email.split('@')[0]);
                }
                const token = genId(32);
                await redis('SETEX', `session:${token}`, 7 * 24 * 60 * 60, userId);
                res.setHeader('Set-Cookie', `token=${token}; Max-Age=${7 * 24 * 60 * 60}; HttpOnly; Path=/; SameSite=Lax`);
                return res.json({success: true, userId});
            }

            // Require Auth for below routes
            const userId = await getUserId();
            if (!userId) return res.status(401).json({error: 'Unauthorized'});

            // PROJECTS
            if (action === 'projects') {
                if (req.method === 'GET') {
                    const pIds = await redis('SMEMBERS', `user:${userId}:projects`);
                    const projects = [];
                    for (let id of (pIds || [])) {
                        const p = await redis('HGETALL', `project:${id}`);
                        if(p) projects.push({id, ...convertHashToObject(p)});
                    }
                    return res.json(projects);
                }
                if (req.method === 'POST') {
                    const body = await getBody();
                    const slug = body.slug.toLowerCase().replace(/[^a-z0-9-]/g, '');
                    // Check if slug taken
                    const exists = await redis('GET', `slug:${slug}`);
                    if (exists) return res.status(400).json({error: 'Subdomain already taken'});
                    
                    const pId = genId();
                    await redis('HSET', `project:${pId}`, 'name', body.name, 'slug', slug, 'ownerId', userId);
                    await redis('SET', `slug:${slug}`, pId);
                    await redis('SADD', `user:${userId}:projects`, pId);
                    
                    // Create default files
                    await redis('HSET', `files:${pId}`, '/index.html', '<h1>Hello World</h1>\n<p>Deployed on Arix-APP.</p>');
                    
                    return res.json({id: pId, slug});
                }
            }

            if (req.url.includes('/files')) {
                const pId = urlParts[4];
                // Check ownership
                const owner = await redis('HGET', `project:${pId}`, 'ownerId');
                if (owner !== userId) return res.status(403).json({error: 'Forbidden'});
                
                if (req.method === 'GET') {
                    const files = await redis('HGETALL', `files:${pId}`);
                    return res.json(convertHashToObject(files || []));
                }
                if (req.method === 'POST' || req.method === 'PUT') {
                    const body = await getBody();
                    // path and content
                    let p = body.path;
                    if(!p.startsWith('/')) p = '/' + p;
                    if(p.includes('../')) return res.status(400).json({error: 'Invalid path'});
                    await redis('HSET', `files:${pId}`, p, body.content);
                    return res.json({success:true});
                }
                if (req.method === 'DELETE') {
                    const body = await getBody();
                    await redis('HDEL', `files:${pId}`, body.path);
                    return res.json({success:true});
                }
            }

            if (req.url.includes('/env')) {
                const pId = urlParts[4];
                const owner = await redis('HGET', `project:${pId}`, 'ownerId');
                if (owner !== userId) return res.status(403).json({error: 'Forbidden'});
                
                if (req.method === 'GET') {
                    const envs = await redis('HGETALL', `env:${pId}`);
                    return res.json(convertHashToObject(envs || []));
                }
                if (req.method === 'POST') {
                    const body = await getBody();
                    await redis('HSET', `env:${pId}`, body.key, body.value);
                    return res.json({success:true});
                }
                if (req.method === 'DELETE') {
                    const body = await getBody();
                    await redis('HDEL', `env:${pId}`, body.key);
                    return res.json({success:true});
                }
            }

            // API KEYS FOR EXTERNAL AI DEPLOYMENTS
            if (action === 'apikeys') {
                if (req.method === 'GET') {
                    const keys = await redis('SMEMBERS', `user:${userId}:apikeys`);
                    return res.json(keys || []);
                }
                if (req.method === 'POST') {
                    const key = 'arix_' + genId(24);
                    await redis('SET', `apikey:${key}`, userId);
                    await redis('SADD', `user:${userId}:apikeys`, key);
                    return res.json({key});
                }
                if (req.method === 'DELETE') {
                    const body = await getBody();
                    await redis('DEL', `apikey:${body.key}`);
                    await redis('SREM', `user:${userId}:apikeys`, body.key);
                    return res.json({success:true});
                }
            }

            return res.status(404).json({error: 'Platform API not found'});
        }

        // --- FRONTEND ---
        // If nothing matched, serve the index.html for the main domain
        try {
            const indexPath = path.join(process.cwd(), 'index.html');
            const html = fs.readFileSync(indexPath, 'utf8');
            res.setHeader('Content-Type', 'text/html');
            return res.status(200).send(html);
        } catch (e) {
            return res.status(500).send('Error loading frontend UI. Make sure index.html is deployed.');
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
}

function convertHashToObject(arr) {
    const obj = {};
    for (let i = 0; i < arr.length; i += 2) {
        obj[arr[i]] = arr[i + 1];
    }
    return obj;
}
