export const config = { runtime: 'edge' };

/*
 * ARIX-APP backend — Edge-only, dependency-free control plane.
 *
 * Required env:
 *   UPSTASH_REDIS_REST_URL
 *   UPSTASH_REDIS_REST_TOKEN
 *   ARIX_APP_SECRET                  (32+ random chars)
 *   ARIX_APP_URL                     (recommended canonical https://... origin)
 *
 *
 * Deployment (required only for real Vercel deployments):
 *   VERCEL_TOKEN
 *   VERCEL_TEAM_ID                    (optional)
 *   ARIX_BASE_DOMAIN                  (optional vanity domain)
 *
 * AI API publishing (optional; publishing remains real, but invocation returns
 * an explicit configuration error until a server-side AI upstream is configured):
 *   ARIX_AI_BASE_URL                  (OpenAI-compatible /chat/completions URL or base URL)
 *   ARIX_AI_API_KEY
 *   ARIX_AI_MODEL
 *
 * Everything persistent for ARIX-APP itself lives in Upstash Redis. No local
 * filesystem, cookies containing secrets, client-side master keys, or in-memory
 * persistence are used.
 */

const ENV = (typeof process !== 'undefined' && process.env) ? process.env : {};
const APP_SECRET = ENV.ARIX_APP_SECRET || '';
const REDIS_URL = ENV.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = ENV.UPSTASH_REDIS_REST_TOKEN || '';
const VERCEL_TOKEN = ENV.VERCEL_TOKEN || '';
const VERCEL_TEAM_ID = ENV.VERCEL_TEAM_ID || '';
const BASE_DOMAIN = (ENV.ARIX_BASE_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
const APP_URL = (ENV.ARIX_APP_URL || '').trim().replace(/\/$/, '');
const SESSION_TTL = 60 * 60 * 24 * 7;
const LOCK_TTL = 20;
const MAX_BODY = 8 * 1024 * 1024;
const MAX_FILE = 5 * 1024 * 1024;
const MAX_PROJECT = 25 * 1024 * 1024;
const MAX_FILES = 1000;
const CHUNK_CHARS = 600_000;
const COOKIE = '__Host-arix_session';
const USER_AGENT = 'Arix-App/1.0 (+https://arix-app.vercel.app)';

function now() { return Date.now(); }
function json(data) { return JSON.stringify(data); }
function safeInt(v, fallback = 0) { const n = Number(v); return Number.isFinite(n) ? n : fallback; }
function b64u(bytes) {
  let bin = ''; for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function fromB64u(s) {
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s.replace(/-/g,'+').replace(/_/g,'/') + pad);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function randomId(prefix='id') {
  return `${prefix}_${b64u(crypto.getRandomValues(new Uint8Array(18)))}`;
}
async function sha256(value) {
  const bytes = value instanceof Uint8Array ? value : new TextEncoder().encode(String(value));
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}
async function hmacSha256(keyBytes, value) {
  const key = await crypto.subtle.importKey('raw', keyBytes, {name:'HMAC', hash:'SHA-256'}, false, ['sign','verify']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value)));
}
function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array)) a = new TextEncoder().encode(String(a));
  if (!(b instanceof Uint8Array)) b = new TextEncoder().encode(String(b));
  if (a.length !== b.length) return false;
  let x = 0; for (let i=0;i<a.length;i++) x |= a[i] ^ b[i];
  return x === 0;
}
async function requireAppSecret() {
  if (!APP_SECRET || APP_SECRET.length < 32) throw httpErr(503, 'SERVER_NOT_CONFIGURED', 'ARIX_APP_SECRET must be configured with at least 32 characters.');
}
function httpErr(status, code, message, extra={}) { const e = new Error(message); e.status=status; e.code=code; e.extra=extra; return e; }
function reqOrigin(req) { try { return new URL(req.url).origin; } catch { return ''; } }
function appOrigin(req) {
  const configured = APP_URL && /^https:\/\//i.test(APP_URL) ? APP_URL : '';
  return configured || reqOrigin(req);
}
function isBrowserRequest(req) { return Boolean(req.headers.get('cookie') || req.headers.get('origin')); }
function setHeaderSafe(h, k, v) { if (v != null) h.set(k, v); }
function response(data, status=200, opts={}) {
  const headers = new Headers({
    'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store, max-age=0',
    'x-content-type-options':'nosniff',
    'x-frame-options':'DENY',
    'referrer-policy':'same-origin',
    'permissions-policy':'camera=(), microphone=(), geolocation=()',
    'cross-origin-opener-policy':'same-origin',
    'cross-origin-resource-policy':'same-origin',
    'x-robots-tag':'noindex, nofollow',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'"
  });
  if (opts.cors) {
    headers.set('access-control-allow-origin', '*');
    headers.set('access-control-allow-methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    headers.set('access-control-allow-headers', 'Authorization, Content-Type, X-API-Key, X-CSRF-Token');
    headers.set('access-control-max-age','600');
  }
  if (opts.cookie) headers.append('set-cookie', opts.cookie);
  return new Response(json(data), {status, headers});
}
function textResponse(body, status=200, contentType='text/plain; charset=utf-8') {
  const headers = new Headers({
    'content-type': contentType,
    'cache-control':'no-store',
    'x-content-type-options':'nosniff',
    'content-security-policy':"default-src 'none'; frame-ancestors 'none'"
  });
  return new Response(body, {status, headers});
}

async function redis(path, options={}) {
  if (!REDIS_URL || !REDIS_TOKEN) throw httpErr(503, 'REDIS_NOT_CONFIGURED', 'Upstash Redis is not configured.');
  const url = REDIS_URL.replace(/\/$/,'') + '/' + path.map(x => encodeURIComponent(String(x))).join('/');
  const r = await fetch(url, {method: options.method || 'GET', headers:{'Authorization':`Bearer ${REDIS_TOKEN}`,'User-Agent':USER_AGENT, ...(options.headers||{})}, body: options.body});
  const raw = await r.text();
  let data; try { data = raw ? JSON.parse(raw) : null; } catch { throw httpErr(502,'REDIS_INVALID_RESPONSE','Upstash returned an invalid response.'); }
  if (!r.ok || data?.error) throw httpErr(502,'REDIS_ERROR', data?.error || `Upstash request failed (${r.status}).`);
  return data?.result;
}
async function redisCmd(cmd, args=[]) {
  const body = JSON.stringify([cmd, ...args]);
  const u = REDIS_URL.replace(/\/$/,'');
  const r = await fetch(u, {method:'POST', headers:{'Authorization':`Bearer ${REDIS_TOKEN}`,'Content-Type':'application/json','User-Agent':USER_AGENT}, body});
  const raw=await r.text(); let d; try { d=JSON.parse(raw); } catch { throw httpErr(502,'REDIS_INVALID_RESPONSE','Upstash returned an invalid response.'); }
  if(!r.ok || d?.error) throw httpErr(502,'REDIS_ERROR',d?.error || 'Upstash command failed.');
  return d.result;
}
async function redisPipeline(commands) {
  const u = REDIS_URL.replace(/\/$/,'') + '/pipeline';
  const r = await fetch(u,{method:'POST',headers:{'Authorization':`Bearer ${REDIS_TOKEN}`,'Content-Type':'application/json','User-Agent':USER_AGENT},body:JSON.stringify(commands)});
  const raw=await r.text(); let d; try { d=JSON.parse(raw); } catch { throw httpErr(502,'REDIS_INVALID_RESPONSE','Upstash returned an invalid response.'); }
  if(!r.ok) throw httpErr(502,'REDIS_ERROR','Upstash pipeline failed.');
  for(const x of d){ if(x?.error) throw httpErr(502,'REDIS_ERROR',x.error); }
  return d.map(x=>x.result);
}
async function redisTx(commands) {
  const u = REDIS_URL.replace(/\/$/,'') + '/multi-exec';
  const r = await fetch(u,{method:'POST',headers:{'Authorization':`Bearer ${REDIS_TOKEN}`,'Content-Type':'application/json','User-Agent':USER_AGENT},body:JSON.stringify(commands)});
  const raw=await r.text(); let d; try { d=JSON.parse(raw); } catch { throw httpErr(502,'REDIS_INVALID_RESPONSE','Upstash returned an invalid response.'); }
  if(!r.ok || d?.error) throw httpErr(502,'REDIS_ERROR',d?.error || 'Upstash transaction failed.');
  for(const x of d){ if(x?.error) throw httpErr(502,'REDIS_ERROR',x.error); }
  return d.map(x=>x.result);
}

function parseCookie(req, name) {
  const all=req.headers.get('cookie')||'';
  for(const part of all.split(';')) { const [k,...rest]=part.trim().split('='); if(k===name) return rest.join('='); }
  return '';
}
function sessionCookie(id, maxAge=SESSION_TTL) {
  return `${COOKIE}=${id}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}
function clearCookie() { return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`; }

function assertSameOrigin(req) {
  const origin=req.headers.get('origin');
  if (!origin) return;
  if (origin !== reqOrigin(req)) throw httpErr(403,'ORIGIN_REJECTED','Cross-origin browser mutation rejected.');
}

async function rateLimit(key, limit, windowSec) {
  const bucket = `rl:${key}:${Math.floor(now()/1000/windowSec)}`;
  const n = await redisCmd('INCR',[bucket]);
  if (n === 1) await redisCmd('EXPIRE',[bucket,windowSec]);
  if (Number(n) > limit) throw httpErr(429,'RATE_LIMITED','Too many requests. Please retry later.',{retryAfter:windowSec});
}

async function acquireLock(lockKey) {
  const val=randomId('lock');
  const got=await redisCmd('SET',[lockKey,val,'NX','EX',LOCK_TTL]);
  if(got !== 'OK') throw httpErr(409,'BUSY','A concurrent update is already in progress.');
  return async()=>{
    try {
      await redisCmd('EVAL',["if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end",1,lockKey,val]);
    } catch { /* best effort; TTL remains the safety net */ }
  };
}

async function getJson(key) { const s=await redisCmd('GET',[key]); if(s==null) return null; try{return JSON.parse(s)}catch{throw httpErr(502,'DATA_CORRUPT',`Invalid stored JSON for ${key}.`)} }
async function setJson(key,obj,ex=null) { const a=['SET',key,JSON.stringify(obj)]; if(ex) a.push('EX',ex); await redisCmd(a[0],a.slice(1)); }

function normalizePath(p) {
  if(typeof p!=='string') throw httpErr(400,'INVALID_PATH','Path must be a string.');
  let s=p.replace(/\\/g,'/').replace(/^\/+/, '');
  if(!s || s.length>512 || s.includes('\0')) throw httpErr(400,'INVALID_PATH','Invalid file path.');
  const parts=s.split('/');
  const out=[];
  for(const part of parts){
    if(!part || part==='.') continue;
    if(part==='..') throw httpErr(400,'PATH_TRAVERSAL','Parent traversal is not allowed.');
    if(/[\u0000-\u001f\u007f]/.test(part)) throw httpErr(400,'INVALID_PATH','Control characters are not allowed in paths.');
    if(part.length>180) throw httpErr(400,'INVALID_PATH','A path segment is too long.');
    out.push(part);
  }
  s=out.join('/');
  if(!s) throw httpErr(400,'INVALID_PATH','Path cannot be empty.');
  const low=s.toLowerCase();
  if(low.startsWith('.git/') || low==='.git' || low.startsWith('.vercel/') || low.endsWith('/.env') || low==='.env' || low.startsWith('.env.') || low.endsWith('.pem') || low.endsWith('.key') || low.endsWith('.p12') || low.endsWith('.pfx'))
    throw httpErr(400,'PROTECTED_PATH','This path is reserved or unsafe.');
  if(/(^|\/)(id_rsa|id_dsa|id_ecdsa|credentials|service-account\.json|secrets?)(\.|\/|$)/i.test(s))
    throw httpErr(400,'PROTECTED_PATH','This filename is not allowed.');
  return s;
}
function projectSlug(name) {
  const s=String(name||'').trim().toLowerCase().replace(/[^a-z0-9-_]+/g,'-').replace(/^-+|-+$/g,'').replace(/--+/g,'-');
  if(s.length<2) throw httpErr(400,'INVALID_PROJECT_NAME','Project name must produce a 2+ character slug.');
  return s.slice(0,48);
}
function validateEnvKey(key) {
  if(!/^[A-Z_][A-Z0-9_]{0,127}$/.test(key)) throw httpErr(400,'INVALID_ENV_KEY','Environment variable names must match [A-Z_][A-Z0-9_]*.');
  const blocked=['ARIX_APP_SECRET','UPSTASH_REDIS_REST_TOKEN','UPSTASH_REDIS_REST_URL','VERCEL_TOKEN'];
  if(blocked.includes(key)) throw httpErr(400,'PROTECTED_ENV_KEY','This environment variable is reserved by the platform.');
}
function safeProjectName(name) { return projectSlug(name).slice(0,40); }
function fileMime(path) {
  const ext=(path.split('.').pop()||'').toLowerCase();
  const map={html:'text/html',htm:'text/html',js:'text/javascript',mjs:'text/javascript',cjs:'text/javascript',css:'text/css',json:'application/json',md:'text/markdown',txt:'text/plain',svg:'image/svg+xml',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',webp:'image/webp',ico:'image/x-icon',ts:'text/typescript',tsx:'text/typescript',jsx:'text/javascript',xml:'application/xml',csv:'text/csv'};
  return map[ext]||'application/octet-stream';
}
function isTextMime(m) { return /^text\//.test(m)||/javascript|json|xml|typescript/.test(m); }
function fromBase64(s) { try{return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}catch{throw httpErr(400,'INVALID_BASE64','File content is not valid base64.');} }
function toBase64(bytes) { return b64u(bytes); }
function b64std(bytes) { let bin=''; for(const b of bytes) bin+=String.fromCharCode(b); return btoa(bin); }
function bytesToUtf8(bytes) { try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{throw httpErr(400,'INVALID_UTF8','Text file is not valid UTF-8.');} }

async function fileKey(projectId,path) { return `f:${projectId}:${await sha256(path)}`; }
async function fileMeta(projectId,path) { return getJson(await fileKey(projectId,path)); }
async function loadFile(projectId, path) {
  const meta=await fileMeta(projectId,path); if(!meta) throw httpErr(404,'FILE_NOT_FOUND','File not found.');
  const keys=[]; for(let i=0;i<meta.chunks;i++) keys.push(`fc:${projectId}:${meta.sha256}:${i}`);
  const chunks=await redisPipeline(keys.map(k=>['GET',k]));
  if(chunks.some(x=>typeof x!=='string')) throw httpErr(502,'FILE_DATA_MISSING','File data is incomplete.');
  const std=chunks.join('');
  return {meta,base64:std};
}
async function listFiles(projectId) {
  const paths=await redisCmd('SMEMBERS',[`pf:${projectId}`]) || [];
  const cmds=[]; for(const path of paths) cmds.push(['GET',await fileKey(projectId,path)]);
  if(!cmds.length) return [];
  const metas=await redisPipeline(cmds);
  return metas.filter(Boolean).map(x=>{try{return JSON.parse(x)}catch{return null}}).filter(Boolean).sort((a,b)=>a.path.localeCompare(b.path));
}
async function totalProjectBytes(projectId) { return safeInt(await redisCmd('GET',[`pb:${projectId}`]),0); }

async function createSnapshot(projectId, reason, actorId) {
  const lock=await acquireLock(`lock:snapshot:${projectId}`); try {
    const files=await listFiles(projectId);
    const revision=safeInt(await redisCmd('INCR',[`pr:${projectId}`]),1);
    const snapshotId=randomId('snap');
    const snapshot={id:snapshotId,projectId,revision,reason:String(reason||'save').slice(0,120),actorId,createdAt:now(),files:files.map(f=>({path:f.path,sha256:f.sha256,size:f.size,chunks:f.chunks,mime:f.mime,updatedAt:f.updatedAt}))};
    await setJson(`s:${projectId}:${snapshotId}`,snapshot);
    await redisPipeline([
      ['LPUSH',`ps:${projectId}`,snapshotId],
      ['LTRIM',`ps:${projectId}`,0,99],
      ['SET',`pcurr:${projectId}`,snapshotId]
    ]);
    await setJson(`p:${projectId}`,{...(await getJson(`p:${projectId}`)),revision,updatedAt:now()});
    return snapshot;
  } finally { await lock(); }
}

async function restoreSnapshot(projectId,snapshotId,actorId) {
  const p=await getJson(`p:${projectId}`); if(!p) throw httpErr(404,'PROJECT_NOT_FOUND','Project not found.');
  const s=await getJson(`s:${projectId}:${snapshotId}`); if(!s) throw httpErr(404,'SNAPSHOT_NOT_FOUND','Snapshot not found.');
  const lock=await acquireLock(`lock:files:${projectId}`); try {
    const existing=await listFiles(projectId); const wanted=new Map(s.files.map(f=>[f.path,f]));
    for(const f of existing){ if(!wanted.has(f.path)){ await deleteFileInternal(projectId,f.path); } }
    for(const f of s.files){
      const source=await loadFile(projectId,f.path).catch(()=>null);
      if(!source || source.meta.sha256!==f.sha256){
        const keys=[]; for(let i=0;i<f.chunks;i++) keys.push(`fc:${projectId}:${f.sha256}:${i}`);
        const vals=await redisPipeline(keys.map(k=>['GET',k]));
        if(vals.some(v=>typeof v!=='string')) throw httpErr(409,'SNAPSHOT_DATA_UNAVAILABLE','Snapshot content is no longer available.');
        const m={...f}; await setJson(await fileKey(projectId,f.path),m); await redisPipeline(vals.map((v,i)=>['SET',`fc:${projectId}:${f.sha256}:${i}`,v]));
        await redisCmd('SADD',[`pf:${projectId}`,f.path]);
      }
    }
    await createSnapshot(projectId,'rollback',actorId);
  } finally { await lock(); }
  return await getJson(`p:${projectId}`);
}

async function deleteFileInternal(projectId,path) {
  const m=await fileMeta(projectId,path); if(!m) return;
  await redisCmd('DEL',[await fileKey(projectId,path)]);
  const keys=[]; for(let i=0;i<m.chunks;i++) keys.push(`fc:${projectId}:${m.sha256}:${i}`);
  if(keys.length) await redisCmd('DEL',keys);
  await redisCmd('SREM',[`pf:${projectId}`,path]);
  await redisCmd('INCRBY',[`pb:${projectId}`,-m.size]);
}

async function saveFileInternal(projectId,path,base64,size,reason='save') {
  const bytes=fromBase64(base64); if(bytes.length>MAX_FILE) throw httpErr(413,'FILE_TOO_LARGE',`Maximum file size is ${MAX_FILE} bytes.`);
  if(bytes.length>MAX_PROJECT) throw httpErr(413,'PROJECT_TOO_LARGE','Project storage quota exceeded.');
  const old=await fileMeta(projectId,path); const oldSize=old?.size||0; const oldSha=old?.sha256||'';
  if(oldSha===await sha256(base64)) return old;
  const current=await totalProjectBytes(projectId); const next=current-oldSize+bytes.length;
  if(next>MAX_PROJECT) throw httpErr(413,'PROJECT_STORAGE_QUOTA','Project storage quota exceeded.');
  const lock=await acquireLock(`lock:files:${projectId}`); try {
    const hash=await sha256(base64); const chunkCount=Math.ceil(base64.length/CHUNK_CHARS); const keys=[];
    for(let i=0;i<chunkCount;i++){ const chunk=base64.slice(i*CHUNK_CHARS,(i+1)*CHUNK_CHARS); const k=`fc:${projectId}:${hash}:${i}`; keys.push(k); }
    const cmds=[]; for(let i=0;i<chunkCount;i++){ cmds.push(['SET',keys[i],base64.slice(i*CHUNK_CHARS,(i+1)*CHUNK_CHARS)]); }
    const meta={path,size:bytes.length,mime:fileMime(path),chunks:chunkCount,sha256:hash,updatedAt:now()};
    cmds.push(['SET',await fileKey(projectId,path),JSON.stringify(meta)]);
    cmds.push(['SADD',`pf:${projectId}`,path]);
    cmds.push(['SET',`pb:${projectId}`,next]);
    await redisPipeline(cmds);
    if(old && old.sha256!==hash){ const oldKeys=[]; for(let i=0;i<old.chunks;i++) oldKeys.push(`fc:${projectId}:${old.sha256}:${i}`); if(oldKeys.length) await redisCmd('DEL',oldKeys); }
    await createSnapshot(projectId,reason,'system');
    return meta;
  } finally { await lock(); }
}

async function createGuestIdentity() {
  const userId=randomId('guest');
  const user={id:userId,email:`${userId}@guest.arix.invalid`,name:'Guest',avatar:'',createdAt:now(),updatedAt:now(),provider:'guest'};
  await redisTx([['SET',`u:${userId}`,JSON.stringify(user)],['SADD',`up:${userId}:projects`,'__none__']]);
  return user;
}
async function ensureGuestSession(req) {
  const existing=await getSession(req);
  if(existing) return {session:existing,setCookie:null};
  const user=await createGuestIdentity();
  const session=await createSession(user.id);
  return {session,setCookie:sessionCookie(session.id)};
}

async function getSession(req) {
  const id=parseCookie(req,COOKIE); if(!id) return null;
  const s=await getJson(`sess:${id}`); if(!s) return null;
  if(s.expiresAt<=now()){ await redisCmd('DEL',[`sess:${id}`]); return null; }
  const expiresAt=now()+SESSION_TTL*1000;
  await setJson(`sess:${id}`,{...s,lastSeenAt:now(),expiresAt},SESSION_TTL);
  return {...s,expiresAt};
}
async function requireSession(req) { const s=await getSession(req); if(!s) throw httpErr(401,'AUTH_REQUIRED','Please sign in.'); return s; }
async function requireCsrf(req,session) { const token=req.headers.get('x-csrf-token')||''; if(!token || !timingSafeEqual(fromB64uSafe(token),fromB64uSafe(session.csrf))) throw httpErr(403,'CSRF_REJECTED','Missing or invalid CSRF token.'); }
function fromB64uSafe(s){ try{return fromB64u(s)}catch{return new Uint8Array()}; }

async function createSession(userId) {
  const id=randomId('sess'), csrf=b64u(crypto.getRandomValues(new Uint8Array(32))), createdAt=now();
  const s={id,userId,csrf,createdAt,lastSeenAt:createdAt,expiresAt:createdAt+SESSION_TTL*1000};
  await setJson(`sess:${id}`,s,SESSION_TTL); return s;
}

async function encrypt(value) {
  await requireAppSecret();
  const base=new TextEncoder().encode(APP_SECRET); const dk=new Uint8Array(await crypto.subtle.digest('SHA-256',base));
  const key=await crypto.subtle.importKey('raw',dk,{name:'AES-GCM'},false,['encrypt']); const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(value)));
  return `${b64u(iv)}.${b64u(ct)}`;
}
async function decrypt(blob) {
  await requireAppSecret(); const [a,b]=String(blob||'').split('.'); if(!a||!b) throw httpErr(502,'DECRYPT_FAILED','Stored secret is malformed.');
  const dk=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(APP_SECRET))); const key=await crypto.subtle.importKey('raw',dk,{name:'AES-GCM'},false,['decrypt']);
  try{ const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64u(a)},key,fromB64u(b)); return new TextDecoder().decode(pt); } catch { throw httpErr(502,'DECRYPT_FAILED','Stored secret could not be decrypted.'); }
}


async function requireProject(req, session, pid, needed='viewer') {
  const p=await getJson(`p:${pid}`); if(!p) throw httpErr(404,'PROJECT_NOT_FOUND','Project not found.');
  if(p.ownerId===session.userId) return p;
  const member=await getJson(`pm:${pid}:${session.userId}`); const rank={viewer:1,developer:2,admin:3,owner:4};
  if(!member || rank[member.role]<rank[needed]) throw httpErr(403,'FORBIDDEN','You do not have access to this project.');
  return p;
}
async function requireOrgRole(session,orgId,needed='viewer') {
  const m=await getJson(`om:${orgId}:${session.userId}`); if(!m) throw httpErr(403,'FORBIDDEN','You are not a member of this organization.'); const rank={viewer:1,developer:2,admin:3,owner:4}; if(rank[m.role]<rank[needed]) throw httpErr(403,'FORBIDDEN','Insufficient organization role.'); return m;
}

async function createProject(session, body) {
  const name=String(body.name||'').trim(); const slug=projectSlug(name);
  const lock=await acquireLock('lock:slug:'+slug); try {
    let final=slug; if(await redisCmd('EXISTS',[`sl:${final}`])) final=`${slug}-${b64u(crypto.getRandomValues(new Uint8Array(3))).toLowerCase().slice(0,5)}`;
    await redisCmd('SET',[`sl:${final}`,session.userId,'NX']);
    const id=randomId('prj'); const p={id,ownerId:session.userId,name:name.slice(0,80),slug:final,revision:0,createdAt:now(),updatedAt:now(),framework:body.framework||'static',installCommand:String(body.installCommand||'npm install').slice(0,200),buildCommand:String(body.buildCommand||'').slice(0,200),outputDirectory:String(body.outputDirectory||'').slice(0,120),vercelProjectId:'',vercelProjectName:final,publishedDeploymentId:'',github:null,createdVia:'web'};
    await redisTx([
      ['SET',`p:${id}`,JSON.stringify(p)],
      ['SADD',`up:${session.userId}:projects`,id],
      ['SET',`pcurr:${id}`,'' ],
      ['SET',`pb:${id}`,'0']
    ]);
    return p;
  } finally { await lock(); }
}

async function updateProject(session,pid,body) {
  const p=await requireProject({headers:()=>{}},session,pid,'developer').catch(async e=>{if(e?.code==='FORBIDDEN')throw e; return getJson(`p:${pid}`)});
  const next={...p}; if(body.name!==undefined) next.name=String(body.name).trim().slice(0,80); if(body.framework!==undefined) next.framework=String(body.framework).slice(0,40); if(body.installCommand!==undefined) next.installCommand=String(body.installCommand).slice(0,200); if(body.buildCommand!==undefined) next.buildCommand=String(body.buildCommand).slice(0,200); if(body.outputDirectory!==undefined) next.outputDirectory=String(body.outputDirectory).slice(0,120); next.updatedAt=now();
  await setJson(`p:${pid}`,next); return next;
}

async function createVercelProject(name) {
  if(!VERCEL_TOKEN) throw httpErr(503,'VERCEL_NOT_CONFIGURED','VERCEL_TOKEN is not configured; deployment is unavailable.');
  const q=new URLSearchParams(); if(VERCEL_TEAM_ID) q.set('teamId',VERCEL_TEAM_ID);
  const r=await fetch(`https://api.vercel.com/v9/projects${q.toString()?'?'+q:''}`,{method:'POST',headers:{Authorization:`Bearer ${VERCEL_TOKEN}`,'Content-Type':'application/json'},body:JSON.stringify({name,framework:null})});
  const d=await r.json().catch(()=>null);
  if(r.ok) return d;
  if(r.status===409 || /already exists/i.test(d?.error?.message||'')){
    const rr=await fetch(`https://api.vercel.com/v9/projects/${encodeURIComponent(name)}${q.toString()?'?'+q:''}`,{headers:{Authorization:`Bearer ${VERCEL_TOKEN}`}}); const dd=await rr.json().catch(()=>null); if(rr.ok) return dd;
  }
  throw httpErr(502,'VERCEL_PROJECT_CREATE_FAILED',d?.error?.message||'Vercel project could not be created.');
}
async function vercelRequest(path, method='GET', body=null) {
  if(!VERCEL_TOKEN) throw httpErr(503,'VERCEL_NOT_CONFIGURED','VERCEL_TOKEN is not configured.');
  const q=path.includes('?')?'&':'?'; const full=path+(VERCEL_TEAM_ID?(q+'teamId='+encodeURIComponent(VERCEL_TEAM_ID)):'');
  const r=await fetch(`https://api.vercel.com${full}`,{method,headers:{Authorization:`Bearer ${VERCEL_TOKEN}`,'Content-Type':'application/json'},body:body==null?undefined:JSON.stringify(body)});
  const d=await r.json().catch(()=>null); if(!r.ok) throw httpErr(r.status===429?429:502,'VERCEL_API_ERROR',d?.error?.message||`Vercel API failed (${r.status}).`); return d;
}
async function syncVercelEnv(projectId, vars) {
  if(!vars.length) return;
  for(const v of vars){
    await vercelRequest(`/v10/projects/${encodeURIComponent(projectId)}/env?upsert=true`,'POST',{key:v.key,value:v.value,type:'encrypted',target:v.target});
  }
}
async function deployProject(session,pid,body) {
  const p=await requireProject({headers:()=>{}},session,pid,'developer').catch(async e=>{if(e?.code==='FORBIDDEN')throw e;return getJson(`p:${pid}`)});
  await rateLimit(`deploy:${session.userId}`,10,3600);
  const metas=await listFiles(pid); if(!metas.length) throw httpErr(400,'NO_FILES','Add at least one file before deploying.'); if(metas.length>MAX_FILES) throw httpErr(413,'TOO_MANY_FILES','Too many files.');
  const total=metas.reduce((a,b)=>a+b.size,0); if(total>6*1024*1024) throw httpErr(413,'DEPLOYMENT_PAYLOAD_TOO_LARGE','For this two-file Edge control plane, a deployment payload is capped at 6 MB.');
  let vpId=p.vercelProjectId; if(!vpId){ const vp=await createVercelProject(safeProjectName(p.name)); vpId=vp.id; p.vercelProjectId=vpId; p.vercelProjectName=vp.name||safeProjectName(p.name); await setJson(`p:${pid}`,{...p,updatedAt:now()}); }
  const envs=await listEnvInternal(pid); await syncVercelEnv(vpId,envs.map(v=>({...v,value: v._value, target:v.target})).map(({key,value,target})=>({key,value,target})));
  const files=[];
  for(const m of metas){ const f=await loadFile(pid,m.path); files.push({file:m.path,data:f.base64,encoding:'base64'}); }
  const snapshotId=body.snapshotId || await redisCmd('GET',[`pcurr:${pid}`]);
  if(body.snapshotId){ const snap=await getJson(`s:${pid}:${body.snapshotId}`); if(!snap) throw httpErr(404,'SNAPSHOT_NOT_FOUND','Snapshot not found.'); }
  const target=body.target==='production'?'production':'preview';
  const projectSettings={framework:null};
  if(p.installCommand) projectSettings.installCommand=p.installCommand;
  if(p.buildCommand) projectSettings.buildCommand=p.buildCommand;
  if(p.outputDirectory) projectSettings.outputDirectory=p.outputDirectory;
  const deployBody={name:safeProjectName(p.name),project:vpId,files,projectSettings,target};
  const d=await vercelRequest('/v13/deployments','POST',deployBody);
  let vanityUrl='';
  if(BASE_DOMAIN && target==='production'){
    const candidate=`${p.slug}.${BASE_DOMAIN}`;
    try {
      await vercelRequest(`/v10/projects/${encodeURIComponent(vpId)}/domains`,'POST',{name:candidate});
      vanityUrl=`https://${candidate}`;
    } catch { /* only use the verified Vercel deployment URL when vanity setup is not available */ }
  }
  const rec={id:randomId('dep'),projectId:pid,vercelDeploymentId:d.id,createdAt:now(),status:d.readyState||d.status||'QUEUED',target,url:vanityUrl|| (d.url?`https://${d.url}`:''),snapshotId,rawState:d.readyState||d.status||'QUEUED'};
  await redisTx([
    ['SET',`dep:${rec.id}`,JSON.stringify(rec)],
    ['LPUSH',`pdeps:${pid}`,rec.id],
    ['LTRIM',`pdeps:${pid}`,0,49],
    ['SET',`p:lastdep:${pid}`,rec.id],
  ]);
  p.publishedDeploymentId=rec.id; p.updatedAt=now(); await setJson(`p:${pid}`,p);
  return {...rec,vercel:d};
}
async function getDeployment(session,id) { const d=await getJson(`dep:${id}`); if(!d) throw httpErr(404,'DEPLOYMENT_NOT_FOUND','Deployment not found.'); await requireProject({headers:()=>{}},session,d.projectId,'viewer').catch(async e=>{if(e?.code==='FORBIDDEN')throw e;}); if(d.vercelDeploymentId&&VERCEL_TOKEN){ try{ const v=await vercelRequest(`/v13/deployments/${encodeURIComponent(d.vercelDeploymentId)}`); d.status=v.readyState||v.status||d.status; d.url=v.url?`https://${v.url}`:d.url; d.rawState=v.readyState||v.status; await setJson(`dep:${id}`,d);}catch{} } return d; }

async function listEnvInternal(pid) {
  const keys=await redisCmd('SMEMBERS',[`env:${pid}`])||[]; if(!keys.length) return [];
  const vals=await redisPipeline(keys.map(k=>['GET',`e:${pid}:${k}`])); const out=[];
  for(const s of vals){ if(!s) continue; const v=JSON.parse(s); v._value=await decrypt(v.enc); delete v.enc; out.push(v); } return out;
}
async function envSummary(pid) { const all=await listEnvInternal(pid); return all.map(v=>({key:v.key,target:v.target,updatedAt:v.updatedAt,masked:true})); }

async function createApiKey(session, body) {
  const name=String(body.name||'Arix API key').trim().slice(0,80); const secret=`arx_live_${b64u(crypto.getRandomValues(new Uint8Array(30)))}`; const hash=await sha256(secret); const id=randomId('key');
  const rec={id,userId:session.userId,name,hash,createdAt:now(),lastUsedAt:0,status:'active'}; await setJson(`key:${hash}`,rec); await redisCmd('SADD',[`keys:${session.userId}`,id]); await setJson(`keyid:${id}`,rec);
  return {id,name,createdAt:rec.createdAt,status:'active',apiKey:secret};
}
async function authenticateApiKey(req) {
  const auth=req.headers.get('authorization')||req.headers.get('x-api-key')||''; const token=auth.startsWith('Bearer ')?auth.slice(7).trim():auth.trim();
  if(!/^arx_live_[A-Za-z0-9_-]{20,}$/.test(token)) throw httpErr(401,'API_KEY_REQUIRED','A valid Arix API key is required.'); const hash=await sha256(token); const rec=await getJson(`key:${hash}`); if(!rec || rec.status!=='active') throw httpErr(401,'API_KEY_INVALID','Invalid or revoked Arix API key.');
  if(now()-safeInt(rec.lastUsedAt,0)>60_000){rec.lastUsedAt=now(); await setJson(`key:${hash}`,rec); await setJson(`keyid:${rec.id}`,rec);} return rec;
}

async function publishAI(req, session, body) {
  const name=String(body.name||'My Arix AI').trim().slice(0,80); const slug=projectSlug(body.slug||name); const id=randomId('ai');
  if(await redisCmd('EXISTS',[`aislug:${slug}`])) throw httpErr(409,'AI_SLUG_TAKEN','That AI slug is already in use.');
  const cfg={id,userId:session.userId,name,slug,systemPrompt:String(body.systemPrompt||'').slice(0,12000),model:String(body.model||ENV.ARIX_AI_MODEL||'').slice(0,120),publishedAt:now(),updatedAt:now(),status:'published'};
  await redisTx([['SET',`ai:${id}`,JSON.stringify(cfg)],['SET',`aislug:${slug}`,id],['SADD',`ais:${session.userId}`,id]]);
  const endpoint=`${appOrigin(req)}${endpointPathForAI(id)}`;
  return {...cfg,invokeEndpoint:endpoint,configurationReady:Boolean(ENV.ARIX_AI_BASE_URL && ENV.ARIX_AI_API_KEY && (ENV.ARIX_AI_MODEL||cfg.model))};
}
function endpointPathForAI(id){ return `/api/backend?action=public-ai&ai=${encodeURIComponent(id)}`; }

async function invokePublishedAI(req, body) {
  const key=await authenticateApiKey(req); const ai=await getJson(`ai:${String(body.ai||'')}`); if(!ai || ai.userId!==key.userId || ai.status!=='published') throw httpErr(404,'AI_NOT_FOUND','Published AI not found.');
  await rateLimit(`public-ai:${key.id}`,120,60);
  const messages=Array.isArray(body.messages)?body.messages.slice(-40):[]; if(!messages.length) throw httpErr(400,'MESSAGES_REQUIRED','At least one message is required.');
  if(messages.some(m=>!m||!['user','assistant','system'].includes(m.role)||typeof m.content!=='string'||m.content.length>20_000)) throw httpErr(400,'INVALID_MESSAGES','Invalid message payload.');
  if(!ENV.ARIX_AI_BASE_URL || !ENV.ARIX_AI_API_KEY) throw httpErr(503,'AI_RUNTIME_NOT_CONFIGURED','AI invocation is not configured on the server. No simulated response is returned.');
  const upstream=ENV.ARIX_AI_BASE_URL.endsWith('/chat/completions')?ENV.ARIX_AI_BASE_URL:ENV.ARIX_AI_BASE_URL.replace(/\/$/,'')+'/chat/completions';
  const outMsgs=[]; if(ai.systemPrompt) outMsgs.push({role:'system',content:ai.systemPrompt}); for(const m of messages) outMsgs.push({role:m.role,content:m.content});
  const r=await fetch(upstream,{method:'POST',headers:{Authorization:`Bearer ${ENV.ARIX_AI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:body.model||ai.model||ENV.ARIX_AI_MODEL,messages:outMsgs,temperature:typeof body.temperature==='number'?Math.max(0,Math.min(2,body.temperature)):0.2,stream:false})});
  const d=await r.json().catch(()=>null); if(!r.ok) throw httpErr(r.status===429?429:502,'AI_UPSTREAM_ERROR',d?.error?.message||'The configured AI upstream rejected the request.');
  return {id:ai.id,name:ai.name,model:d.model||ai.model||ENV.ARIX_AI_MODEL,output:d.choices?.[0]?.message?.content??'',raw:d.choices?.[0]||null,usage:d.usage||null};
}

function b64hex(bytes){ let s=''; for(const b of bytes)s+=b.toString(16).padStart(2,'0'); return s; }

async function api(req) {
  const url=new URL(req.url); const action=url.searchParams.get('action')||'health'; const method=req.method.toUpperCase();
  if(method==='OPTIONS') return response({ok:true},200,{cors:true});
  if(action==='health') return response({ok:true,service:'Arix-App',time:new Date().toISOString(),storage:'upstash-redis',deployment:Boolean(VERCEL_TOKEN),authentication:'guest-session',sessionTtlDays:7,ai:Boolean(ENV.ARIX_AI_BASE_URL&&ENV.ARIX_AI_API_KEY)});
  if(action==='public-ai') { if(method!=='POST') throw httpErr(405,'METHOD_NOT_ALLOWED','POST required.'); return response(await invokePublishedAI(req,await readBody(req)),200,{cors:true}); }
  if(action==='bootstrap' && method==='GET'){
    assertSameOrigin(req);
    const {session,setCookie}=await ensureGuestSession(req);
    const user=await getJson(`u:${session.userId}`);
    return response({ok:true,user,csrf:session.csrf,sessionExpiresAt:session.expiresAt,authentication:'guest'},200,setCookie?{cookie:setCookie}:{});
  }

  const session=await requireSession(req); assertSameOrigin(req);
  if(action==='me' && method==='GET'){ const user=await getJson(`u:${session.userId}`); if(!user) throw httpErr(401,'AUTH_REQUIRED','Account not found.'); return response({user:{...user},csrf:session.csrf,sessionExpiresAt:session.expiresAt}); }
  const body=(method==='POST'||method==='PUT'||method==='PATCH'||method==='DELETE')?await readBody(req):{};
  if(['me','projects-create','project-update','file-save','file-create','file-delete','file-rename','file-duplicate','env-upsert','env-delete','deploy','rollback','api-key-create','api-key-revoke','ai-publish'].includes(action)) await requireCsrf(req,session);

  if(action==='projects' && method==='GET'){ const ids=(await redisCmd('SMEMBERS',[`up:${session.userId}:projects`])||[]).filter(x=>x!=='__none__'); const vals=await Promise.all(ids.map(id=>getJson(`p:${id}`))); return response(vals.filter(Boolean).sort((a,b)=>b.updatedAt-a.updatedAt)); }
  if(action==='projects-create' && method==='POST'){ return response(await createProject(session,body),201); }
  if(action==='project' && method==='GET'){ return response(await requireProject(req,session,url.searchParams.get('id'),'viewer')); }
  if(action==='project-update' && method==='PATCH'){ return response(await updateProject(session,url.searchParams.get('id'),body)); }
  if(action==='files' && method==='GET'){ await requireProject(req,session,url.searchParams.get('id'),'viewer'); return response(await listFiles(url.searchParams.get('id'))); }
  if(action==='file' && method==='GET'){ await requireProject(req,session,url.searchParams.get('id'),'viewer'); const path=normalizePath(url.searchParams.get('path')||''); const f=await loadFile(url.searchParams.get('id'),path); return response({meta:f.meta,base64:f.base64}); }
  if(action==='file-save' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); return response(await saveFileInternal(body.projectId,normalizePath(body.path),String(body.base64||''),safeInt(body.size,0),body.reason||'save')); }
  if(action==='file-create' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); const path=normalizePath(body.path); if(await fileMeta(body.projectId,path)) throw httpErr(409,'FILE_EXISTS','A file already exists at that path.'); return response(await saveFileInternal(body.projectId,path,b64std(new Uint8Array()),0,'create'),201); }
  if(action==='file-delete' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); const lock=await acquireLock(`lock:files:${body.projectId}`); try{await deleteFileInternal(body.projectId,normalizePath(body.path));await createSnapshot(body.projectId,'delete',session.userId);}finally{await lock();} return response({ok:true}); }
  if(action==='file-rename' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); const old=normalizePath(body.from), next=normalizePath(body.to); if(await fileMeta(body.projectId,next)) throw httpErr(409,'FILE_EXISTS','Target already exists.'); const f=await loadFile(body.projectId,old); const lock=await acquireLock(`lock:files:${body.projectId}`); try{await deleteFileInternal(body.projectId,old);await saveFileWithoutSnapshot(body.projectId,next,f.base64,f.meta.size);await createSnapshot(body.projectId,'rename',session.userId);}finally{await lock();} return response({ok:true}); }
  if(action==='file-duplicate' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); const from=normalizePath(body.from), to=normalizePath(body.to); if(await fileMeta(body.projectId,to)) throw httpErr(409,'FILE_EXISTS','Target already exists.'); const f=await loadFile(body.projectId,from); return response(await saveFileInternal(body.projectId,to,f.base64,f.meta.size,'duplicate'),201); }
  if(action==='file-search' && method==='GET'){ const pid=url.searchParams.get('id'); await requireProject(req,session,pid,'viewer'); const q=(url.searchParams.get('q')||'').slice(0,200).toLowerCase(); if(!q) return response([]); const metas=await listFiles(pid); const out=[]; for(const m of metas.slice(0,200)){ if(!isTextMime(m.mime)||m.size>1_500_000) continue; const f=await loadFile(pid,m.path); const txt=bytesToUtf8(fromBase64(f.base64)); const i=txt.toLowerCase().indexOf(q); if(i>=0) out.push({path:m.path,index:i,preview:txt.slice(Math.max(0,i-80),Math.min(txt.length,i+180))}); if(out.length>=50)break;} return response(out); }
  if(action==='snapshots' && method==='GET'){ const pid=url.searchParams.get('id'); await requireProject(req,session,pid,'viewer'); const ids=await redisCmd('LRANGE',[`ps:${pid}`,0,49])||[]; const vals=await Promise.all(ids.map(id=>getJson(`s:${pid}:${id}`))); return response(vals.filter(Boolean).map(s=>({id:s.id,revision:s.revision,reason:s.reason,createdAt:s.createdAt,fileCount:s.files.length,size:s.files.reduce((a,b)=>a+b.size,0)}))); }
  if(action==='rollback' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); return response(await restoreSnapshot(body.projectId,body.snapshotId,session.userId)); }
  if(action==='env' && method==='GET'){ await requireProject(req,session,url.searchParams.get('id'),'viewer'); return response(await envSummary(url.searchParams.get('id'))); }
  if(action==='env-upsert' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); validateEnvKey(body.key); if(typeof body.value!=='string'||body.value.length>100_000)throw httpErr(413,'ENV_TOO_LARGE','Environment value is too large.'); const target=Array.isArray(body.target)?body.target.filter(x=>['production','preview','development'].includes(x)):[body.target||'production']; const enc=await encrypt(body.value); const v={key:body.key,enc,target,updatedAt:now()}; await redisTx([['SET',`e:${body.projectId}:${body.key}`,JSON.stringify(v)],['SADD',`env:${body.projectId}`,body.key]]); return response({key:v.key,target:v.target,updatedAt:v.updatedAt,masked:true}); }
  if(action==='env-delete' && method==='POST'){ await requireProject(req,session,body.projectId,'developer'); validateEnvKey(body.key); await redisTx([['DEL',`e:${body.projectId}:${body.key}`],['SREM',`env:${body.projectId}`,body.key]]); return response({ok:true}); }
  if(action==='deploy' && method==='POST'){ return response(await deployProject(session,body.projectId,body),201); }
  if(action==='deployments' && method==='GET'){ const pid=url.searchParams.get('id'); await requireProject(req,session,pid,'viewer'); const ids=await redisCmd('LRANGE',[`pdeps:${pid}`,0,49])||[]; const vals=await Promise.all(ids.map(id=>getJson(`dep:${id}`))); return response(vals.filter(Boolean)); }
  if(action==='deployment' && method==='GET'){ return response(await getDeployment(session,url.searchParams.get('id'))); }
  if(action==='logs' && method==='GET'){ const dep=await getDeployment(session,url.searchParams.get('id')); if(!dep.vercelDeploymentId||!VERCEL_TOKEN) return response({deploymentId:dep.id,events:[],message:'Vercel log access is unavailable until deployment credentials are configured.'}); try{ const v=await vercelRequest(`/v3/deployments/${encodeURIComponent(dep.vercelDeploymentId)}/events?limit=100`); return response({deploymentId:dep.id,events:Array.isArray(v)?v:(v?.events||v||[])}); }catch(e){ throw httpErr(502,'VERCEL_LOGS_FAILED',e.message||'Could not read deployment events.'); } }
  if(action==='api-keys' && method==='GET'){ const ids=await redisCmd('SMEMBERS',[`keys:${session.userId}`])||[]; const vals=await Promise.all(ids.map(id=>getJson(`keyid:${id}`))); return response(vals.filter(Boolean).map(k=>({id:k.id,name:k.name,status:k.status,createdAt:k.createdAt,lastUsedAt:k.lastUsedAt}))); }
  if(action==='api-key-create' && method==='POST'){ return response(await createApiKey(session,body),201); }
  if(action==='api-key-revoke' && method==='POST'){ const id=String(body.id||''); const k=await getJson(`keyid:${id}`); if(!k||k.userId!==session.userId)throw httpErr(404,'API_KEY_NOT_FOUND','API key not found.'); k.status='revoked'; await setJson(`keyid:${id}`,k); await setJson(`key:${k.hash}`,k); return response({ok:true}); }
  if(action==='ai-publish' && method==='POST'){ return response(await publishAI(req,session,body),201); }
  if(action==='ai-list' && method==='GET'){ const ids=await redisCmd('SMEMBERS',[`ais:${session.userId}`])||[]; const vals=await Promise.all(ids.map(id=>getJson(`ai:${id}`))); return response(vals.filter(Boolean)); }
  if(action==='usage' && method==='GET'){ const pid=url.searchParams.get('id'); await requireProject(req,session,pid,'viewer'); return response({projectId:pid,files:(await listFiles(pid)).length,bytes:await totalProjectBytes(pid),snapshots:safeInt(await redisCmd('LLEN',[`ps:${pid}`]),0),deployments:safeInt(await redisCmd('LLEN',[`pdeps:${pid}`]),0)}); }
  throw httpErr(404,'NOT_FOUND','Unknown action.');
}

async function readBody(req){
  const len=safeInt(req.headers.get('content-length'),0); if(len>MAX_BODY) throw httpErr(413,'REQUEST_TOO_LARGE',`Request exceeds ${MAX_BODY} bytes.`); const raw=await req.text(); if(raw.length>MAX_BODY)throw httpErr(413,'REQUEST_TOO_LARGE',`Request exceeds ${MAX_BODY} bytes.`); if(!raw)return {}; try{return JSON.parse(raw)}catch{throw httpErr(400,'INVALID_JSON','Request body must be valid JSON.');} }

export default async function handler(req){
  try{
    if(req.method==='GET' && new URL(req.url).pathname==='/api/backend') return await api(req);
    if(new URL(req.url).pathname==='/api/backend') return await api(req);
    return textResponse('Arix-App backend endpoint.');
  }catch(e){
    const status=e?.status||500; const code=e?.code||'INTERNAL_ERROR'; const msg=status>=500&&code==='INTERNAL_ERROR'?'An internal error occurred. No fake or simulated result was generated.':String(e?.message||'Request failed.');
    return response({ok:false,error:{code,message:msg}, ...(e?.extra||{})},status,{cors:(new URL(req.url).searchParams.get('action')==='public-ai')});
  }
}
