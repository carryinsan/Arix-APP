import vm from 'vm';
import crypto from 'crypto';

export default async function (req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Upstash Redis Configuration
    const UPSTASH_REDIS_REST_URL = process.env.UPSTASH_REDIS_REST_URL;
    const UPSTASH_REDIS_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

    async function redisCommand(command, ...args) {
        if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) {
            console.warn("Upstash credentials not found.");
            return null;
        }
        const response = await fetch(`${UPSTASH_REDIS_REST_URL}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify([command, ...args])
        });
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        return data.result;
    }

    try {
        const url = new URL(req.url, `https://${req.headers.host}`);
        const action = url.searchParams.get('action') || (req.body && req.body.action);

        // Session and API Key handling
        let user = null;
        
        // Check API Key first
        const authHeader = req.headers.authorization || '';
        if (authHeader.startsWith('Bearer arix_')) {
            const token = authHeader.split(' ')[1];
            const userId = await redisCommand('GET', `apikey_lookup:${token}`);
            if (userId) {
                user = { id: userId, isApiKey: true };
            }
        }

        // If no API key, check session
        const cookies = req.headers.cookie || '';
        const sessionIdMatch = cookies.match(/sessionId=([^;]+)/);
        let sessionId = sessionIdMatch ? sessionIdMatch[1] : null;

        if (!user && sessionId) {
            const userData = await redisCommand('GET', `session:${sessionId}`);
            if (userData) {
                user = JSON.parse(userData);
                // Extend session
                await redisCommand('EXPIRE', `session:${sessionId}`, 7 * 24 * 60 * 60);
            }
        }

        const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
        const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
        const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
        const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
        
        const host = req.headers.host;
        const protocol = host.includes('localhost') ? 'http' : 'https';
        const callbackUrl = `${protocol}://${host}/api/backend?action=oauth_callback`;

        switch (action) {
            case 'auth':
                const provider = url.searchParams.get('provider');
                if (provider === 'github') {
                    if (!GITHUB_CLIENT_ID) return res.status(500).json({ error: "GITHUB_CLIENT_ID not configured" });
                    return res.redirect(302, `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUrl + '&provider=github')}`);
                } else if (provider === 'google') {
                    if (!GOOGLE_CLIENT_ID) return res.status(500).json({ error: "GOOGLE_CLIENT_ID not configured" });
                    return res.redirect(302, `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUrl + '&provider=google')}&response_type=code&scope=email%20profile`);
                }
                return res.status(400).json({ error: "Invalid provider" });
                
            case 'oauth_callback':
                const code = url.searchParams.get('code');
                const authProvider = url.searchParams.get('provider');
                if (!code) return res.status(400).json({ error: "Missing authorization code" });

                let authenticatedUser = null;

                if (authProvider === 'github') {
                    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
                        method: 'POST',
                        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            client_id: GITHUB_CLIENT_ID,
                            client_secret: GITHUB_CLIENT_SECRET,
                            code,
                            redirect_uri: callbackUrl + '&provider=github'
                        })
                    });
                    const tokenData = await tokenRes.json();
                    if (tokenData.error) throw new Error(tokenData.error_description || tokenData.error);
                    
                    const userRes = await fetch('https://api.github.com/user', {
                        headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
                    });
                    const userData = await userRes.json();
                    
                    authenticatedUser = {
                        id: `github_${userData.id}`,
                        email: userData.email,
                        name: userData.name || userData.login,
                        avatar: userData.avatar_url
                    };
                } else if (authProvider === 'google') {
                    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            client_id: GOOGLE_CLIENT_ID,
                            client_secret: GOOGLE_CLIENT_SECRET,
                            code,
                            grant_type: 'authorization_code',
                            redirect_uri: callbackUrl + '&provider=google'
                        })
                    });
                    const tokenData = await tokenRes.json();
                    if (tokenData.error) throw new Error(tokenData.error_description || tokenData.error);
                    
                    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
                        headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
                    });
                    const userData = await userRes.json();
                    
                    authenticatedUser = {
                        id: `google_${userData.id}`,
                        email: userData.email,
                        name: userData.name,
                        avatar: userData.picture
                    };
                } else {
                    return res.status(400).json({ error: "Invalid provider" });
                }

                const newSessionId = 'sess_' + crypto.randomUUID();
                await redisCommand('SET', `session:${newSessionId}`, JSON.stringify(authenticatedUser), 'EX', 7 * 24 * 60 * 60);
                
                res.setHeader('Set-Cookie', `sessionId=${newSessionId}; Path=/; HttpOnly; Max-Age=${7 * 24 * 60 * 60}; SameSite=Lax`);
                return res.redirect(302, '/');

            case 'session':
                return res.status(200).json({ user });

            case 'logout':
                if (sessionId) {
                    await redisCommand('DEL', `session:${sessionId}`);
                    res.setHeader('Set-Cookie', `sessionId=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax`);
                }
                return res.status(200).json({ success: true });

            case 'listProjects':
                if (!user) return res.status(401).json({ error: 'Unauthorized' });
                const projectsData = await redisCommand('SMEMBERS', `user:${user.id}:projects`);
                return res.status(200).json({ projects: projectsData || [] });

            case 'createProject':
                if (!user) return res.status(401).json({ error: 'Unauthorized' });
                const { projectName } = req.body || {};
                if (!projectName) return res.status(400).json({ error: 'Missing projectName' });
                
                // Sanitize project name
                const safeName = projectName.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
                const newProjectId = `${user.id}_${safeName}`;
                
                await redisCommand('SADD', `user:${user.id}:projects`, newProjectId);
                return res.status(200).json({ success: true, projectId: newProjectId });

            case 'getFiles':
                if (!user) return res.status(401).json({ error: 'Unauthorized' });
                const projectId = url.searchParams.get('projectId');
                if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
                if (!projectId.startsWith(user.id + '_')) return res.status(403).json({ error: 'Forbidden' });
                
                const filesData = await redisCommand('HGETALL', `project:${projectId}:files`);
                
                const files = {};
                if (filesData) {
                     for (let i = 0; i < filesData.length; i += 2) {
                        files[filesData[i]] = JSON.parse(filesData[i+1]);
                     }
                }
                return res.status(200).json(files);

            case 'saveFile':
                if (!user) return res.status(401).json({ error: 'Unauthorized' });
                const { projectId: savePid, path, content } = req.body;
                if (!savePid || !path) return res.status(400).json({ error: 'Missing data' });
                
                // Ensure user owns this project
                if (!savePid.startsWith(user.id + '_')) {
                    return res.status(403).json({ error: 'Forbidden' });
                }

                // Prevent path traversal
                if (path.includes('..')) return res.status(400).json({ error: 'Invalid path' });

                await redisCommand('HSET', `project:${savePid}:files`, path, JSON.stringify({ content }));
                return res.status(200).json({ success: true });

            case 'generateApiKey':
                if (!user) return res.status(401).json({ error: 'Unauthorized' });
                const oldKey = await redisCommand('GET', `apikey:${user.id}`);
                if (oldKey) {
                    await redisCommand('DEL', `apikey_lookup:${oldKey}`);
                }
                const newKey = 'arix_' + crypto.randomBytes(32).toString('hex');
                await redisCommand('SET', `apikey:${user.id}`, newKey);
                await redisCommand('SET', `apikey_lookup:${newKey}`, user.id);
                return res.status(200).json({ apiKey: newKey });

            case 'getApiKey':
                if (!user) return res.status(401).json({ error: 'Unauthorized' });
                const existingKey = await redisCommand('GET', `apikey:${user.id}`);
                return res.status(200).json({ apiKey: existingKey });

            case 'deploy':
                if (!user) return res.status(401).json({ error: 'Unauthorized' });
                const { projectId: depPid } = req.body;
                if (!depPid) return res.status(400).json({ error: 'Missing projectId' });
                
                // In a real app, this would trigger a build worker queue.
                // For this serverless implementation, we just mark it ready
                // and link to a simulated subdomain route on this same API.
                const deploymentId = 'dep_' + crypto.randomUUID();
                await redisCommand('SET', `deployment:${deploymentId}`, JSON.stringify({ projectId: depPid, status: 'READY' }));
                await redisCommand('SET', `domain:${depPid}.arix-app.vercel.com`, deploymentId);

                // Simulation: The user goes to a wildcard subdomain, which points back here.
                // We'll simulate this by providing a direct URL to the runtime action.
                return res.status(200).json({ 
                    success: true, 
                    url: `https://${req.headers.host}/api/backend?action=runtime&projectId=${depPid}&route=/`
                });

            case 'runtime':
                // This simulates the proxy/wildcard subdomain routing and sandboxed execution
                const runPid = url.searchParams.get('projectId');
                let route = url.searchParams.get('route') || '/';
                if (!runPid) return res.status(404).send('Project not found');

                // Prevent path traversal in route
                if (route.includes('..')) return res.status(400).send('Invalid route');

                const runFilesData = await redisCommand('HGETALL', `project:${runPid}:files`);
                const runFiles = {};
                if (runFilesData) {
                     for (let i = 0; i < runFilesData.length; i += 2) {
                        runFiles[runFilesData[i]] = JSON.parse(runFilesData[i+1]);
                     }
                }

                // If routing to /api/*, execute in sandbox
                if (route.startsWith('/api/')) {
                    const filePath = route.substring(1) + '.js'; // e.g., api/users.js
                    const file = runFiles[filePath];
                    if (!file) return res.status(404).json({ error: 'Function not found' });

                    // Enhance sandbox security (within the limits of standard Node.js vm)
                    // Freezing standard objects to prevent trivial prototype pollution escapes
                    const safeConsole = Object.freeze({
                        log: (...args) => console.log(...args),
                        error: (...args) => console.error(...args)
                    });

                    const sandbox = {
                        console: safeConsole,
                        setTimeout,
                        clearTimeout,
                        Buffer,
                        URL,
                        String: Object.freeze(String),
                        Number: Object.freeze(Number),
                        Array: Object.freeze(Array),
                        Object: Object.freeze(Object),
                        Promise: Object.freeze(Promise)
                        // Explicitly DO NOT EXPOSE process, require, or FS
                    };
                    vm.createContext(sandbox);

                    try {
                        // Compile user code into a self-executing function that returns the default export.
                        // This avoids brittle regex replaces for `export default`
                        const code = `
                            "use strict";
                            (() => {
                                let __defaultExport;
                                const exports = new Proxy({}, {
                                    set: (obj, prop, value) => {
                                        if (prop === 'default') __defaultExport = value;
                                        obj[prop] = value;
                                        return true;
                                    }
                                });
                                // Fake module system
                                const module = { exports };
                                
                                // Clean up export syntax
                                ${file.content.replace(/export default/, 'module.exports.default = ')}
                                
                                return module.exports.default || __defaultExport;
                            })();
                        `;
                        const script = new vm.Script(code);
                        const fn = script.runInContext(sandbox, { 
                            timeout: 1000,
                            displayErrors: true,
                        });
                        
                        if (typeof fn !== 'function') {
                            throw new Error('Default export is not a function');
                        }

                        // Sanitize the req object to prevent sandbox escapes via prototype pollution
                        const safeReq = {
                            method: req.method,
                            url: req.url,
                            headers: Object.assign({}, req.headers),
                            query: Object.fromEntries(url.searchParams.entries()),
                            body: typeof req.body === 'object' ? JSON.parse(JSON.stringify(req.body || {})) : req.body
                        };
                        Object.freeze(safeReq);

                        // Execute the user's function with a safe response mock
                        const userRes = {
                            status: (code) => { res.status(code); return userRes; },
                            json: (data) => res.json(data),
                            send: (data) => res.send(data),
                            setHeader: (k, v) => res.setHeader(k, v)
                        };
                        
                        await fn(safeReq, userRes);
                        return; // Done
                    } catch (err) {
                        console.error('Sandbox execution error:', err);
                        return res.status(500).json({ error: 'Function execution failed' });
                    }
                }

                // Otherwise, serve static files
                if (route === '/') route = 'index.html';
                // Strip leading slash if present in runFiles keys
                let searchPath = route.startsWith('/') ? route.substring(1) : route;
                
                const staticFile = runFiles[searchPath] || runFiles['public/' + searchPath];
                
                if (staticFile) {
                    if (searchPath.endsWith('.html')) res.setHeader('Content-Type', 'text/html');
                    else if (searchPath.endsWith('.css')) res.setHeader('Content-Type', 'text/css');
                    else if (searchPath.endsWith('.js')) res.setHeader('Content-Type', 'application/javascript');
                    else if (searchPath.endsWith('.json')) res.setHeader('Content-Type', 'application/json');
                    
                    return res.status(200).send(staticFile.content);
                }

                return res.status(404).send('Not found');

            case 'health':
                return res.status(200).json({ status: 'ok' });
            default:
                return res.status(400).json({ error: 'Unknown action' });
        }
    } catch (error) {
        console.error('Backend Error:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
