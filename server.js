// Railway / Node.js host for worker.js (the same Worker code, unchanged except 4 small patches).
// Variables (Railway -> Variables):
//   ADMIN_PASSWORD  (required)  panel password          ADMIN_USER (optional, default admin)
//   DATA_FILE       (optional)  default /data/data.json  (mount a Volume at /data to keep data across deploys)
//   PORT            set by Railway automatically
import './cf-shim.js';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { WebSocketServer } from 'ws';
import worker from './worker.js';

process.on('unhandledRejection', (e) => console.log('unhandledRejection:', e && e.message ? e.message : e));
process.on('uncaughtException', (e) => console.log('uncaughtException:', e && e.stack ? e.stack : e));

/* ---------- KV replacement: in-memory map saved to a JSON file ---------- */
class FileKV {
  constructor(file) {
    this.file = file;
    this.m = new Map();
    this.timer = null;
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const [k, e] of Object.entries(raw)) if (!e.x || e.x > Date.now()) this.m.set(k, e);
      console.log('data loaded:', file, this.m.size, 'keys');
    } catch (_) { console.log('no data file yet:', file); }
  }
  alive(k) {
    const e = this.m.get(k);
    if (!e) return null;
    if (e.x && e.x <= Date.now()) { this.m.delete(k); return null; }
    return e;
  }
  async get(k, type) {
    const e = this.alive(k);
    if (!e) return null;
    const t = typeof type === 'string' ? type : type && type.type;
    return t === 'json' ? JSON.parse(e.v) : e.v;
  }
  async put(k, v, o) {
    const x = o && o.expirationTtl ? Date.now() + o.expirationTtl * 1000 : o && o.expiration ? o.expiration * 1000 : 0;
    this.m.set(k, { v: typeof v === 'string' ? v : String(v), x });
    this.dirty();
  }
  async delete(k) { this.m.delete(k); this.dirty(); }
  async list(o = {}) {
    const keys = [];
    for (const k of [...this.m.keys()]) if (this.alive(k) && (!o.prefix || k.startsWith(o.prefix))) keys.push({ name: k });
    return { keys, list_complete: true };
  }
  dirty() { if (!this.timer) this.timer = setTimeout(() => this.flush(), 1500); }
  flush() { // async: never blocks the event loop (and so never stalls live connections)
    clearTimeout(this.timer); this.timer = null;
    if (this.writing) { this.again = true; return; }
    this.writing = true;
    const tmp = this.file + '.tmp';
    fs.promises.writeFile(tmp, JSON.stringify(Object.fromEntries(this.m)))
      .then(() => fs.promises.rename(tmp, this.file))
      .catch((e) => console.log('cannot save data file:', e.message))
      .finally(() => { this.writing = false; if (this.again) { this.again = false; this.dirty(); } });
  }
  flushSync() { // used only on shutdown
    clearTimeout(this.timer); this.timer = null;
    try {
      const tmp = this.file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.m)));
      fs.renameSync(tmp, this.file);
    } catch (e) { console.log('cannot save data file:', e.message); }
  }
}

let dataFile = process.env.DATA_FILE || '/data/data.json';
try { fs.mkdirSync(path.dirname(dataFile), { recursive: true }); fs.accessSync(path.dirname(dataFile), fs.constants.W_OK); }
catch (_) { console.log('WARNING:', path.dirname(dataFile), 'is not writable -> using ./data.json (data is lost on redeploy unless a Volume is mounted at /data)'); dataFile = './data.json'; }
const kv = new FileKV(dataFile);
for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => { kv.flushSync(); process.exit(0); });

const env = {
  KV: kv,
  ADMIN: process.env.ADMIN_PASSWORD || process.env.ADMIN,
  ADMIN_USER: process.env.ADMIN_USER || undefined,
  PROXY_IP: process.env.PROXY_IP || undefined,
  FREE_WRITES: '1000000000', FREE_READS: '1000000000', FREE_REQUESTS: '1000000000',
};
if (globalThis.__CF_FRONT) console.log('CF_FRONT is ON: subscription links may use Cloudflare clean IPs (the domain must be proxied by Cloudflare)');
if (!env.ADMIN) console.log('WARNING: ADMIN_PASSWORD is not set - the panel will refuse to open');

const ctx = {
  waitUntil(p) { Promise.resolve(p).catch((e) => console.log('waitUntil error:', e && e.message ? e.message : e)); },
  passThroughOnException() {},
};

/* ---------- Node request -> Fetch Request ---------- */
function clientIp(req) {
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return (xf || String(req.headers['x-real-ip'] || '') || (req.socket.remoteAddress || '')).replace(/^::ffff:/, '');
}
function toRequest(req) {
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(',')[0].trim();
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) v.forEach((x) => headers.append(k, x)); else if (v !== undefined) headers.set(k, v);
  }
  headers.set('cf-connecting-ip', clientIp(req)); // never trust a client-sent value
  const init = { method: req.method, headers };
  if (req.method !== 'GET' && req.method !== 'HEAD') { init.body = Readable.toWeb(req); init.duplex = 'half'; }
  const request = new Request(`${proto}://${host}${req.url}`, init);
  Object.defineProperty(request, 'cf', { value: { colo: '' } });
  return request;
}

const server = http.createServer(async (req, res) => {
  try {
    const resp = await worker.fetch(toRequest(req), env, ctx);
    res.statusCode = resp.status;
    for (const [k, v] of resp.headers) if (k.toLowerCase() !== 'set-cookie') res.setHeader(k, v);
    const sc = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
    if (sc.length) res.setHeader('set-cookie', sc);
    if (!resp.body || req.method === 'HEAD') { res.end(); return; }
    res.flushHeaders();
    const body = Readable.fromWeb(resp.body);
    body.on('error', () => res.destroy());
    res.on('close', () => body.destroy());
    body.pipe(res);
  } catch (e) {
    console.log('http error:', e && e.message ? e.message : e);
    if (!res.headersSent) { res.statusCode = 500; res.end('Internal error'); } else res.destroy();
  }
});

const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, maxPayload: 64 * 1024 * 1024, handleProtocols: (p) => p.values().next().value });
server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});
  try {
    const resp = await worker.fetch(toRequest(req), env, ctx);
    if (resp && resp.webSocket) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.isAlive = true;
        ws.on('pong', () => { ws.isAlive = true; });
        resp.webSocket._attach(ws);
      });
    } else {
      const text = resp && resp.text ? await resp.text() : 'Bad Request';
      socket.end(`HTTP/1.1 ${(resp && resp.status) || 400} Error\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(text)}\r\nConnection: close\r\n\r\n${text}`);
    }
  } catch (e) {
    console.log('upgrade error:', e && e.message ? e.message : e);
    socket.destroy();
  }
});

// Keep-alive + cleanup: ping every 25 s; a client that never answers (phone went offline) is dropped so its sockets/RAM are freed.
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch (_) {}
  }
}, 25000).unref();

server.requestTimeout = 0;
server.timeout = 0;
server.keepAliveTimeout = 65000;
const PORT = Number(process.env.PORT) || 3000;
server.listen(PORT, '0.0.0.0', () => console.log('listening on 0.0.0.0:' + PORT));
