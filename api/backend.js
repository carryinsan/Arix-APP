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

        // Default local user (OAuth removed)
        let user = { id: 'default_user', name: 'Developer', email: 'dev@local' };

        switch (action) {
            case 'session':
                return res.status(200).json({ user });

            case 'logout':
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
