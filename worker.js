// VLESS over WebSocket - Cloudflare Worker (v13: + backup/restore, panel password, login rate-limit, user notes/disable/devices,
//   expiry-from-first-use, Clash/sing-box subscriptions, per-operator verified IPs, multi-port, ProxyIP ranking)
// - KV-stored config, multi-UUID, subscription, admin panel (advanced UI)
// - Automatic ProxyIP: direct first, then relay candidates resolved via DoH (TXT/A/AAAA)
// - UDP DNS over DoH, Blob-safe WebSocket frames
//
// Bindings / variables:
//   DB        (D1 database binding, recommended) -> config/stats/auth storage. Table is created automatically.
//   KV        (KV namespace binding, optional)   -> only used as the one-time migration source when DB is
//                                                  added; without DB the Worker keeps using KV as before.
//   ADMIN     (variable/secret, required)  -> password for /panel
//   ADMIN_USER (variable, optional)        -> panel username (default: admin)
//   PROXY_IP  (optional)                   -> extra relay entries (comma/newline separated)
//
// Routes:
//   /panel        -> admin panel
//   /sub/<token>  -> base64 subscription (all users x all addresses)

import { connect } from './cf-shim.js';
// Panel name: set APP_NAME in the environment variables to change it (default below).
const APP_NAME = ((typeof process !== 'undefined' && process.env && process.env.APP_NAME) || 'naderoxyn').replace(/[<>&"'`$\\\r\n]/g, '').slice(0, 40).trim() || 'naderoxyn';

const CONFIG_KEY = 'config';
// Config/verified-IP cache per Worker instance. A panel change (e.g. disabling a user) reaches other
// instances within this time. Longer = fewer KV reads.
const CACHE_TTL = 120 * 1000;
const MAX_USERS = 20;
const MAX_LIST = 50;
const BYTES_PER_GB = 1024 * 1024 * 1024;
const MAX_QUOTA_GB = 100000;

const DEFAULT_AUTO_DOMAIN = 'proxyip.cmliussss.net'; // same source edgetunnel uses (per-colo: <colo>.<domain>)
const DOH = 'https://cloudflare-dns.com/dns-query';
const DEFAULT_CLEAN_IP_URLS = [
  'https://addressesapi.090227.xyz/CloudFlareYes',
  'https://ip.164746.xyz/ipTop10.html',
];
const CLEAN_IP_TIMEOUT = 4000;
const CLEAN_IP_CACHE_TTL = 10 * 60 * 1000;
const MAX_CLEAN_IP_URLS = 6;
const GEOIP_URL = 'http://ip-api.com/batch?fields=query,countryCode,status';
const GEOIP_BATCH_MAX = 100;
const GEOIP_TIMEOUT = 4000;
const GEOIP_CACHE_TTL = 24 * 60 * 60 * 1000;
const MAX_COUNTRIES = 10;
const DIAG_KEY = 'diag'; // temporary connection log (only while the admin switches it on, auto-off after 15 minutes)
const DIAG_MINUTES = 15;
const ERRLOG_KEY = 'errlog'; // last exceptions seen by the Worker (shown in the panel, tools tab)
const errCache = { list: [], lastWrite: 0 };
const MAX_AUTO_ADDRS = 10;
const EMERGENCY_KEY = 'emergency'; // separate storage key: the emergency list never touches users' cards or normal links
const MAX_EMERGENCY = 1000;
const VERIFIED_IN_SUB = 30; // verified IPs (from the IP test tab) put into every subscription / user link
const DIRECT_TIMEOUT = 3000;
const PROXY_TIMEOUT = 2500;
const MAX_PROXY_TRIES = 6;
const PROXY_CACHE_TTL = 5 * 60 * 1000;
const DIRECT_FAIL_TTL = 5 * 60 * 1000;

const AUTH_KEY = 'auth';
const HEALTHY_KEY = 'healthy';
const OPERATORS = { mci: 'همراه اول', mci6: 'همراه اول IPv6', irancell: 'ایرانسل', irancell6: 'ایرانسل IPv6', rightel: 'رایتل', samantel: 'سامانتل', tci: 'مخابرات / ADSL', other: 'سایر' };
// IPv6 lists are kept apart from the IPv4 ones: own verified list, own subscription link, never mixed into users' links.
const V6_OPS = new Set(['mci6', 'irancell6']);
const CF_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const FPS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'randomized', 'random'];
const ALPNS = ['', 'http/1.1', 'h2,http/1.1'];
const HEALTHY_MAX_AGE = 7 * 24 * 3600 * 1000; // verified IPs older than this are not used in subscriptions
const HEALTHY_KEEP = 14 * 24 * 3600 * 1000;   // ... and are dropped from storage after this
const HEALTHY_MAX_PER_OP = 60;
const LOGIN_MAX_FAILS = 5;
const LOGIN_BLOCK_SEC = 15 * 60;
const MAX_NOTE = 120;
const DAILY_KEEP = 30;
const PROXY_BAD_TTL = 10 * 60 * 1000;
const FLUSH_CHOICES = [5, 10, 30, 60]; // minutes between usage write-backs (panel setting)
const DEFAULT_FLUSH_MIN = 10;
const KV_DAYS_KEEP = 14;
const KV_FREE_WRITES = 1000;   // Cloudflare KV free plan: writes per day
const KV_FREE_READS = 100000;  // ... reads per day
const D1_FREE_WRITES = 100000;   // Cloudflare D1 free plan: rows written per day
const D1_FREE_READS = 5000000;   // ... rows read per day
let WRITE_LIMIT = KV_FREE_WRITES; // set per request from the active storage backend
const REQ_FREE = 100000;       // Workers free plan: requests per day (each tunnel / page / subscription fetch = 1)
const DAY_MS = 24 * 3600 * 1000;
const TEHRAN_OFFSET = 12600000; // UTC+3:30 (no DST)
// Only these destinations are counted by name in the per-datacenter statistics (everything else is
// lumped together), so the panel never stores a log of what users browse.
const WATCH_SITES = ['chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com', 'gemini.google.com', 'google.com', 'youtube.com', 'instagram.com', 'x.com', 'telegram.org'];
const MAX_COLOS = 30;

let cache = { value: null, at: 0 };

export default {
  async fetch(request, env, ctx) {
    try {
      kvOps.q++;
      WRITE_LIMIT = Number(env.FREE_WRITES) || (dbOf(env) ? D1_FREE_WRITES : KV_FREE_WRITES);
      if (!dbOf(env) && !env.KV) {
        return new Response('Neither a D1 binding named "DB" nor a KV binding named "KV" is set', { status: 500 });
      }

      if (request.method === 'POST') {
        // diagnostics only: POSTs that are neither panel nor tunnel requests (wrong path / content type)
        const pth = new URL(request.url).pathname;
        const ct0 = (request.headers.get('content-type') || '').toLowerCase();
        if (!pth.startsWith('/panel')) {
          diagLog(env, ctx, 'other', 'post', 'POST ' + pth.slice(0, 60) + ' ct=' + (ct0.slice(0, 40) || '-'));
        }
      }

      if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
        const cfg = await getConfig(env);
        return handleWebSocket(request, env, cfg, ctx);
      }

      const url = new URL(request.url);

      if (url.pathname.startsWith('/sub/')) {
        return await handleSub(request, env, url);
      }
      if (url.pathname.startsWith('/status/')) {
        return await handleStatus(request, env, url);
      }
      if (url.pathname === '/panel' || url.pathname.startsWith('/panel/')) {
        return await handleAdmin(request, env, url);
      }

      return decoyHome(); // anything that is not the panel / a subscription / a tunnel looks like a plain nginx server
    } catch (err) {
      try { return errorResponse(request, env, ctx, err); } catch (_) {
        return new Response('Temporary error', { status: 503, headers: { 'Content-Type': 'text/plain' } }); // last resort: never let an exception escape (that would be Cloudflare error 1101)
      }
    }
  },
};

function recordError(env, ctx, request, err) {
  try {
    const e = {
      t: Date.now(),
      p: new URL(request.url).pathname.replace(/^(\/(?:sub|status))\/.*/, '$1/…').slice(0, 80), // never store the secret link parts
      n: String((err && err.name) || '').slice(0, 30),
      m: String((err && err.message) || err || '').replace(/\s+/g, ' ').slice(0, 220),
    };
    errCache.list.push(e);
    if (errCache.list.length > 30) errCache.list.shift();
    if (Date.now() - errCache.lastWrite < 5000) return;
    errCache.lastWrite = Date.now();
    const job = (async () => {
      let stored = [];
      try { const d = await kvGet(env, ERRLOG_KEY); stored = d && Array.isArray(d.list) ? d.list : []; } catch (_) { /* storage may be what failed */ }
      const merged = stored.concat(errCache.list.filter((x) => !stored.some((y) => y.t === x.t && y.m === x.m))).sort((a, b) => a.t - b.t).slice(-30);
      errCache.list = merged;
      await kvPut(env, ERRLOG_KEY, JSON.stringify({ list: merged }));
    })().catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(job);
  } catch (_) { /* recording must never fail a request */ }
}

async function loadErrors(env) {
  let stored = [];
  try { const d = await kvGet(env, ERRLOG_KEY); stored = d && Array.isArray(d.list) ? d.list : []; } catch (_) { /* ignore */ }
  const merged = stored.concat(errCache.list.filter((x) => !stored.some((y) => y.t === x.t && y.m === x.m)));
  return merged.sort((a, b) => a.t - b.t).slice(-30);
}

// Turns any exception of a request into a normal 503/500 page (never a Cloudflare 1101) and remembers it for the panel.
function errorResponse(request, env, ctx, err) {
  recordError(env, ctx, request, err);
  console.log('request error:', err && err.message ? err.message : err);
  const temporary = /KV|D1|SQLITE|storage|network|connection|timeout/i.test(String((err && err.message) || ''));
  const text = 'خطای موقت؛ چند لحظه بعد دوباره تلاش کنید';
  if (new URL(request.url).pathname.startsWith('/panel/api/')) {
    // Admin API only: add the real reason (and which storage is active) so a failure can be diagnosed from the toast.
    const why = String((err && err.message) || err || '').replace(/\s+/g, ' ').slice(0, 140);
    const detail = (dbOf(env) ? 'D1' : env.KV ? 'KV' : 'no storage') + ': ' + why;
    return new Response(JSON.stringify({ error: text + ' [' + detail + ']' }), { status: temporary ? 503 : 500, headers: { 'Content-Type': 'application/json' } });
  }
  return new Response(text, { status: temporary ? 503 : 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}

/* ================================ Config (KV) ================================ */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ENTRY_RE = /^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.\-]+)(:\d{1,5})?$/;
const DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9.\-]{1,251}[a-zA-Z0-9]$/;
const URL_RE = /^https:\/\/[a-zA-Z0-9][a-zA-Z0-9.\-]{1,251}[a-zA-Z0-9](?::\d{1,5})?(?:\/[^\s]*)?$/;
const COUNTRY_RE = /^[A-Z]{2}$/;

function randomToken() {
  const b = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

/* ---- KV access: every operation goes through here so it can be counted ---- */
const kvOps = { w: 0, r: 0, q: 0 }; // q = Worker requests // operations by this Worker instance not yet added to the persisted daily totals
// With a D1 binding named DB everything is stored in one table (k, v, exp). Without it the Worker
// falls back to the KV binding exactly as before. The names kvGet/kvPut/kvDel are kept so no
// other code had to change.
// The D1 binding is normally called DB, but any D1 binding is accepted (found by its API), so a different
// variable name in the dashboard (D1, db, my-db ...) still works.
const dbCache = new WeakMap();
function dbOf(env) {
  if (!env) return null;
  if (env.DB) return env.DB;
  if (dbCache.has(env)) return dbCache.get(env);
  let found = null;
  for (const k of Object.keys(env)) {
    const v = env[k];
    if (v && typeof v === 'object' && typeof v.prepare === 'function' && typeof v.batch === 'function') { found = v; break; }
  }
  dbCache.set(env, found);
  return found;
}
// D1 now and then answers "network connection lost" / "timeout" for a single query; one quiet retry hides most of them.
async function d1Retry(fn) {
  try {
    return await fn();
  } catch (e) {
    if (!/network|connection|timeout|temporar|overload|reset|unavailable|internal/i.test(String((e && e.message) || ''))) throw e;
    await new Promise((r) => setTimeout(r, 150));
    return await fn();
  }
}
let dbReady = null;
function d1Init(env) {
  if (!dbReady) {
    dbReady = (async () => {
      await dbOf(env).prepare('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp INTEGER) WITHOUT ROWID').run();
      const done = await dbOf(env).prepare("SELECT 1 AS x FROM kv WHERE k = '__migrated'").first();
      if (!done) {
        // One-time copy of the existing data from KV, so users / password / settings survive the switch.
        if (env.KV) {
          for (const key of [CONFIG_KEY, AUTH_KEY, HEALTHY_KEY, EMERGENCY_KEY]) {
            const raw = await env.KV.get(key); // text; throws on failure -> nothing is marked as migrated
            if (raw !== null) await dbOf(env).prepare('INSERT OR IGNORE INTO kv (k, v, exp) VALUES (?1, ?2, NULL)').bind(key, raw).run();
          }
        }
        await dbOf(env).prepare("INSERT OR IGNORE INTO kv (k, v, exp) VALUES ('__migrated', '1', NULL)").run();
      }
    })().catch((e) => { dbReady = null; throw e; });
  }
  return dbReady;
}
async function kvGet(env, key) {
  kvOps.r++;
  if (!dbOf(env)) return env.KV.get(key, 'json');
  await d1Init(env);
  const row = await d1Retry(() => dbOf(env).prepare('SELECT v, exp FROM kv WHERE k = ?1').bind(key).first());
  if (!row || (row.exp && row.exp < Date.now())) return null;
  return JSON.parse(row.v); // corrupt data throws (never looks like "no config yet")
}
async function kvPut(env, key, value, opts) {
  kvOps.w++;
  if (!dbOf(env)) return opts ? env.KV.put(key, value, opts) : env.KV.put(key, value);
  await d1Init(env);
  const exp = opts && opts.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : null;
  const up = dbOf(env).prepare('INSERT INTO kv (k, v, exp) VALUES (?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp').bind(key, value, exp);
  if (exp) { // expiring keys (login rate-limit): purge old expired rows in the same round trip
    await d1Retry(() => dbOf(env).batch([up, dbOf(env).prepare('DELETE FROM kv WHERE exp IS NOT NULL AND exp < ?1').bind(Date.now())]));
  } else {
    await d1Retry(() => up.run());
  }
}
async function kvDel(env, key) {
  kvOps.w++;
  if (!dbOf(env)) return env.KV.delete(key);
  await d1Init(env);
  await d1Retry(() => dbOf(env).prepare('DELETE FROM kv WHERE k = ?1').bind(key).run());
}

let migrationRetryAt = 0;

async function getConfig(env, force = false) {
  if (!force && cache.value && Date.now() - cache.at < CACHE_TTL) return cache.value;

  // A failed read (quota exhausted, transient KV error) must NOT look like "no config yet":
  // that would generate a fresh config and overwrite every user. Serve the last good copy or fail.
  let cfg = null;
  try {
    cfg = await kvGet(env, CONFIG_KEY);
  } catch (e) {
    if (cache.value) return cache.value;
    throw new Error('storage read failed: ' + ((e && e.message) || e));
  }

  let dirty = false;
  let fresh = false; // nothing stored yet: the config we are about to create only exists if it gets saved
  if (!cfg || typeof cfg !== 'object') { cfg = {}; dirty = true; fresh = true; }

  // Migrate from v1 ({ uuid })
  if (!Array.isArray(cfg.users)) {
    cfg.users = [];
    if (UUID_RE.test(cfg.uuid || '')) cfg.users.push({ uuid: cfg.uuid.toLowerCase(), name: 'default' });
    delete cfg.uuid;
    dirty = true;
  }
  if (!cfg.users.length) { cfg.users.push({ uuid: crypto.randomUUID(), name: 'default' }); dirty = true; }
  for (const u of cfg.users) {
    if (u.expiresAt !== null && !Number.isFinite(u.expiresAt)) { u.expiresAt = null; dirty = true; }
    if (u.quotaBytes !== null && !Number.isFinite(u.quotaBytes)) { u.quotaBytes = null; dirty = true; }
    if (!Number.isFinite(u.usedBytes)) { u.usedBytes = 0; dirty = true; }
    if (typeof u.disabled !== 'boolean') { u.disabled = false; dirty = true; }
    if (typeof u.note !== 'string') { u.note = ''; dirty = true; }
    if (u.expireAfterDays !== null && !(Number.isInteger(u.expireAfterDays) && u.expireAfterDays > 0)) { u.expireAfterDays = null; dirty = true; }
    if (u.firstUsedAt !== null && !Number.isFinite(u.firstUsedAt)) { u.firstUsedAt = null; dirty = true; }
    if (u.maxDevices !== null && !(Number.isInteger(u.maxDevices) && u.maxDevices > 0)) { u.maxDevices = null; dirty = true; }
    if (!u.daily || typeof u.daily !== 'object' || Array.isArray(u.daily)) { u.daily = {}; dirty = true; }
  }
  if (!cfg.subToken) { cfg.subToken = randomToken(); dirty = true; }

  // Migrate from v2-v4 ({ proxyIp })
  if (!cfg.proxyMode) {
    if (typeof cfg.proxyIp === 'string' && cfg.proxyIp.trim()) {
      cfg.proxyMode = 'custom';
      cfg.proxyList = cfg.proxyIp.trim();
    } else {
      cfg.proxyMode = 'auto';
    }
    delete cfg.proxyIp;
    dirty = true;
  }
  if (typeof cfg.proxyList !== 'string') { cfg.proxyList = ''; dirty = true; }
  if (!cfg.autoDomain) { cfg.autoDomain = DEFAULT_AUTO_DOMAIN; dirty = true; }
  if (typeof cfg.autoPerColo !== 'boolean') { cfg.autoPerColo = true; dirty = true; }
  if (typeof cfg.addrs !== 'string') { cfg.addrs = ''; dirty = true; }
  if (typeof cfg.cleanIpEnabled !== 'boolean') { cfg.cleanIpEnabled = false; dirty = true; }
  if (typeof cfg.cleanIpUrls !== 'string') { cfg.cleanIpUrls = DEFAULT_CLEAN_IP_URLS.join('\n'); dirty = true; }
  if (typeof cfg.countryFilter !== 'string') { cfg.countryFilter = ''; dirty = true; }
  if (cfg.addrMode !== 'auto' && cfg.addrMode !== 'manual') { cfg.addrMode = 'manual'; dirty = true; }
  if (!Number.isInteger(cfg.addrCount) || cfg.addrCount < 1 || cfg.addrCount > MAX_AUTO_ADDRS) { cfg.addrCount = 3; dirty = true; }
  if (typeof cfg.ports !== 'string' || !parsePorts(cfg.ports).length) { cfg.ports = '443'; dirty = true; }
  if (!FPS.includes(cfg.fp)) { cfg.fp = 'chrome'; dirty = true; }
  if (!ALPNS.includes(cfg.alpn)) { cfg.alpn = ''; dirty = true; }
  if (typeof cfg.fragment !== 'boolean') { cfg.fragment = false; dirty = true; }
  if (!FLUSH_CHOICES.includes(cfg.flushMin)) { cfg.flushMin = DEFAULT_FLUSH_MIN; dirty = true; }
  if (!cfg.stats || typeof cfg.stats !== 'object' || !cfg.stats.colos || typeof cfg.stats.colos !== 'object') { cfg.stats = { since: Date.now(), colos: {} }; dirty = true; }

  // Writing back the normalised config (new fields added by an upgrade) is housekeeping, not a
  // requirement for serving traffic. If the write fails - typically because the daily KV write
  // quota is used up - keep working from the in-memory copy instead of taking the panel, the
  // subscription links and every tunnel down, and try again later. Only a brand-new config must
  // be saved, otherwise each instance would invent a different UUID.
  if (dirty && (fresh || Date.now() >= migrationRetryAt)) {
    try {
      await kvPut(env, CONFIG_KEY, JSON.stringify(cfg));
    } catch (e) {
      if (fresh) throw e;
      migrationRetryAt = Date.now() + 15 * 60000;
    }
  }
  cache = { value: cfg, at: Date.now() };
  return cfg;
}

async function saveConfig(env, cfg) {
  await kvPut(env, CONFIG_KEY, JSON.stringify(cfg));
  cache = { value: cfg, at: Date.now() };
}

function splitList(text) {
  return String(text || '').split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
}

function cleanList(text, max) {
  const items = splitList(text);
  if (items.length > max) throw new Error(`حداکثر ${max} مورد مجاز است`);
  for (const it of items) if (!ENTRY_RE.test(it)) throw new Error('مقدار نامعتبر: ' + it);
  return items;
}

function cleanUrlList(text, max) {
  const items = splitList(text);
  if (items.length > max) throw new Error(`حداکثر ${max} آدرس مجاز است`);
  for (const it of items) if (!URL_RE.test(it)) throw new Error('آدرس نامعتبر (باید با https شروع شود): ' + it);
  return items;
}

function parseCountryList(text, max) {
  const items = String(text || '')
    .split(/[\s,;]+/)
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
  const uniq = [...new Set(items)];
  if (uniq.length > max) throw new Error(`حداکثر ${max} کد کشور مجاز است`);
  for (const c of uniq) if (!COUNTRY_RE.test(c)) throw new Error('کد کشور نامعتبر (باید دو حرفی باشد): ' + c);
  return uniq;
}

function dedupeAddrs(list) {
  const seen = new Set();
  const out = [];
  for (const [a, p] of list) {
    const k = a + ':' + p;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push([a, p]);
  }
  return out;
}

// Manual IPs saved on one user (user card) come first in that user's links; the shared list follows.
function userAddrs(u, addrs) {
  const own = splitList(u && u.ips).map((s) => {
    const [a, p] = splitHostPort(s);
    return [a, p || 443];
  });
  return own.length ? dedupeAddrs([...own, ...addrs]) : addrs;
}

// ---- connection diagnostics (WS) ----
// Off by default. When the admin switches it on, tunnel events (request arrived, what the client sent, which
// destination, why it closed) are kept in a short list that is written to storage at most every 2 seconds.
const diagCache = { until: 0, events: [], at: 0, dirty: false, flushing: false, lastFlush: 0 };

async function diagLoad(env, force = false) {
  if (!force && Date.now() - diagCache.at < 8000) return diagCache;
  diagCache.at = Date.now();
  try {
    const d = await kvGet(env, DIAG_KEY);
    const stored = d && Array.isArray(d.events) ? d.events : [];
    diagCache.until = (d && Number(d.until)) || 0;
    if (diagCache.dirty) {
      const k = (e) => e.t + '|' + e.st + '|' + e.m;
      const seen = new Set(stored.map(k));
      diagCache.events = stored.concat(diagCache.events.filter((e) => !seen.has(k(e)))).sort((a, b) => a.t - b.t).slice(-150);
    } else {
      diagCache.events = stored.slice(-150);
    }
  } catch (_) { /* keep what we have */ }
  return diagCache;
}

async function diagFlush(env) {
  if (diagCache.flushing) return;
  diagCache.flushing = true;
  try {
    for (let i = 0; i < 4 && diagCache.dirty; i++) {
      const wait = 2000 - (Date.now() - diagCache.lastFlush);
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      diagCache.dirty = false;
      diagCache.lastFlush = Date.now();
      await kvPut(env, DIAG_KEY, JSON.stringify({ until: diagCache.until, events: diagCache.events }));
    }
  } catch (_) { /* diagnostics must never break a tunnel */ } finally { diagCache.flushing = false; }
}

function diagLog(env, ctx, tr, st, msg) {
  const job = (async () => {
    const d = await diagLoad(env);
    if (!d.until || d.until < Date.now()) return;
    d.events.push({ t: Date.now(), tr, st, m: String(msg == null ? '' : msg).slice(0, 160) });
    if (d.events.length > 150) d.events.splice(0, d.events.length - 150);
    d.dirty = true;
    await diagFlush(env);
  })().catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(job);
}

function maskIp(ip) {
  ip = String(ip || '');
  if (ip.includes(':')) return ip.split(':').slice(0, 2).join(':') + ':...';
  const p = ip.split('.');
  return p.length === 4 ? p[0] + '.' + p[1] + '.x.x' : ip;
}

// Emergency list: free-form ip:port lines kept apart from everything else (see ?list=emergency in handleSub).
async function loadEmergency(env) {
  const e = await kvGet(env, EMERGENCY_KEY);
  return e && typeof e.text === 'string' ? e.text : '';
}

function emergencyPairs(text) {
  return dedupeAddrs(splitList(text).map((s) => {
    const [a, p] = splitHostPort(s);
    return [a, p || 443];
  }));
}

function parsePorts(text) {
  const out = [];
  for (const x of String(text || '').split(/[\s,;]+/)) {
    const n = parseInt(x, 10);
    if (CF_PORTS.includes(n) && !out.includes(n)) out.push(n);
  }
  return out;
}

// Entries on the default port (443) are repeated for every enabled Cloudflare HTTPS port.
function expandPorts(list, ports) {
  if (!ports.length || (ports.length === 1 && ports[0] === 443)) return list;
  const out = [];
  for (const [a, p] of list) {
    if (p === 443) for (const pt of ports) out.push([a, pt]);
    else out.push([a, p]);
  }
  return dedupeAddrs(out);
}

function dayKey(ts = Date.now()) {
  return new Date(ts + TEHRAN_OFFSET).toISOString().slice(0, 10);
}

function pruneDaily(u) {
  const keys = Object.keys(u.daily || {}).sort();
  while (keys.length > DAILY_KEEP) delete u.daily[keys.shift()];
}

function linkOpts(cfg) {
  return { fp: cfg.fp || 'chrome', alpn: cfg.alpn || '' };
}

/* ---------------- verified ("healthy") IPs, measured from the admin's own device ---------------- */

let healthyCache = { v: null, at: 0 };

async function loadHealthy(env, force = false, strict = false) {
  if (!force && healthyCache.v && Date.now() - healthyCache.at < CACHE_TTL) return healthyCache.v;
  let h = null;
  try {
    h = await kvGet(env, HEALTHY_KEY);
  } catch (e) {
    if (healthyCache.v) return healthyCache.v;
    if (strict) throw new Error('storage read failed: ' + ((e && e.message) || e));
    return { ops: {} }; // read-only use (subscriptions): degrade to "no verified IPs", never cached
  }
  if (!h || typeof h !== 'object' || !h.ops || typeof h.ops !== 'object') h = { ops: {} };
  healthyCache = { v: h, at: Date.now() };
  return h;
}

async function saveHealthy(env, h) {
  await kvPut(env, HEALTHY_KEY, JSON.stringify(h));
  healthyCache = { v: h, at: Date.now() };
}

function bestForOp(h, op, n) {
  const m = (h.ops && h.ops[op]) || {};
  const now = Date.now();
  return Object.entries(m)
    .filter(([, v]) => v && v.fail === 0 && Number.isFinite(v.ms) && now - v.at < HEALTHY_MAX_AGE)
    .sort((a, b) => a[1].ms - b[1].ms)
    .slice(0, n)
    .map(([k]) => { const [a, p] = splitHostPort(k); return [a, p || 443]; });
}

// Best verified IPs across ALL operators (used when the subscription does not say which operator).
function bestAnyOp(h, n) {
  const now = Date.now();
  const best = new Map();
  for (const [opName, m] of Object.entries((h && h.ops) || {})) {
    if (V6_OPS.has(opName)) continue;
    for (const [k, v] of Object.entries(m || {})) {
      if (!v || v.fail !== 0 || !Number.isFinite(v.ms) || now - v.at >= HEALTHY_MAX_AGE) continue;
      const c = best.get(k);
      if (c === undefined || v.ms < c) best.set(k, v.ms);
    }
  }
  return [...best].sort((a, b) => a[1] - b[1]).slice(0, n).map(([k]) => { const [a, p] = splitHostPort(k); return [a, p || 443]; });
}

// Iranian operator from the ASN of whoever fetches the subscription (only a hint; ?op= wins).
const OP_ASN = { 197207: 'mci', 44244: 'irancell', 57218: 'rightel', 58224: 'tci', 12880: 'tci', 48159: 'tci' };

function mergeReport(h, op, results) {
  const m = (h.ops[op] = h.ops[op] || {});
  const now = Date.now();
  for (const r of results) {
    const key = r.addr + ':' + r.port;
    const cur = m[key];
    if (Number.isFinite(r.ms) && r.ms > 0) {
      const ms = cur && cur.fail === 0 && Number.isFinite(cur.ms) ? Math.round(cur.ms * 0.4 + r.ms * 0.6) : Math.round(r.ms);
      m[key] = { ms, at: now, fail: 0 };
    } else if (cur) {
      cur.fail = (cur.fail || 0) + 1;
      if (cur.fail >= 3) delete m[key];
    }
  }
  for (const [k, v] of Object.entries(m)) if (!v || now - v.at > HEALTHY_KEEP) delete m[k];
  const keep = Object.entries(m).sort((a, b) => (a[1].fail - b[1].fail) || (a[1].ms - b[1].ms)).slice(0, HEALTHY_MAX_PER_OP);
  h.ops[op] = Object.fromEntries(keep);
}

function healthySummary(h) {
  const out = {};
  const now = Date.now();
  for (const op of Object.keys(OPERATORS)) {
    out[op] = Object.entries((h.ops && h.ops[op]) || {})
      .filter(([, v]) => v && v.fail === 0)
      .sort((a, b) => a[1].ms - b[1].ms)
      .slice(0, 30)
      .map(([key, v]) => ({ key, ms: v.ms, ageMin: Math.round((now - v.at) / 60000) }));
  }
  return out;
}

// Address(es) the CLIENT connects to (goes into the vless:// link as host:port), as opposed
// to the ProxyIP relay the Worker itself uses to reach blocked destinations. In 'auto' mode
// this reuses the same public clean-IP sources and country filter as the ProxyIP tab, since
// both need the same kind of thing: a currently-reachable Cloudflare edge IP.
async function getConnectAddrs(cfg, host, o = {}) {
  if (globalThis.__RAILWAY) return [[host, 443]]; // Railway: only this domain works (Cloudflare clean IPs would not reach it)
  const manual = splitList(cfg.addrs).map((s) => {
    const [a, p] = splitHostPort(s);
    return [a, p || 443];
  });
  const ports = parsePorts(cfg.ports);

  // Verified IPs (saved from the IP test tab) go into EVERY subscription, so a newly created user
  // gets them too. Operator-specific list when known (?op= or detected), otherwise the best overall.
  // The domain itself stays as the last entry so the link still works if all IPs stop answering.
  if (o.env) {
    try {
      const h = await loadHealthy(o.env);
      let best = o.op && OPERATORS[o.op] ? bestForOp(h, o.op, VERIFIED_IN_SUB) : [];
      if (!best.length) best = bestAnyOp(h, VERIFIED_IN_SUB);
      if (best.length) {
        const list = [...expandPorts(manual, ports), ...best];
        if (!manual.length) list.push([host, 443]);
        return dedupeAddrs(list);
      }
    } catch (_) {}
  }

  let base;
  if (cfg.addrMode !== 'auto') {
    base = manual.length ? manual : [[host, 443]];
  } else {
    let auto = [];
    try {
      const urls = splitList(cfg.cleanIpUrls);
      const raw = await fetchCleanIps(urls.length ? urls : DEFAULT_CLEAN_IP_URLS);
      let countries = [];
      try { countries = parseCountryList(cfg.countryFilter, MAX_COUNTRIES); } catch (_) {}
      const filtered = countries.length ? await filterByCountry(raw, countries).catch(() => raw) : raw;
      auto = filtered.slice(0, cfg.addrCount).map(([ip, port]) => [ip, port || 443]);
    } catch (_) {}
    const combined = dedupeAddrs([...manual, ...auto]);
    base = combined.length ? combined : [[host, 443]];
  }
  return expandPorts(base, ports);
}

function vlessLink(u, host, addr, port, o = {}) {
  const suffix = addr === host ? (port === 443 ? '' : `-${port}`) : `-${addr}${port === 443 ? '' : ':' + port}`;
  const label = encodeURIComponent(u.name + suffix);
  let q = `encryption=none&security=tls&sni=${host}&fp=${o.fp || 'chrome'}&type=ws&host=${host}&path=%2F%3Fed%3D2048`;
  if (o.alpn) q += `&alpn=${encodeURIComponent(o.alpn)}`;
  return `vless://${u.uuid}@${addr}:${port}?${q}#${label}`;
}

/* ============================== Subscription =============================== */

function b64utf8(str) {
  let bin = '';
  for (const b of new TextEncoder().encode(str)) bin += String.fromCharCode(b);
  return btoa(bin);
}

function yq(x) { return JSON.stringify(String(x)); } // a JSON string is a valid YAML double-quoted scalar

function outboundNames(users, addrs) {
  const seen = new Set();
  const out = [];
  for (const u of users) {
    for (const [a, p] of userAddrs(u, addrs)) {
      let n = `${u.name} ${a}:${p}`;
      while (seen.has(n)) n += '\u200b';
      seen.add(n);
      out.push({ u, a, p, n });
    }
  }
  return out;
}

function buildClash(users, addrs, host, cfg) {
  const items = outboundNames(users, addrs);
  const fp = cfg.fp === 'randomized' ? 'random' : cfg.fp;
  const alpn = cfg.alpn ? cfg.alpn.split(',') : [];
  const proxies = items.map(({ u, a, p, n }) => [
    `  - name: ${yq(n)}`, '    type: vless', `    server: ${yq(stripBrackets(a))}`, `    port: ${p}`, `    uuid: ${yq(u.uuid)}`,
    '    udp: true', '    tls: true', `    servername: ${yq(host)}`, '    network: ws', `    client-fingerprint: ${fp}`,
    ...(alpn.length ? ['    alpn:', ...alpn.map((x) => `      - ${yq(x)}`)] : []),
    '    ws-opts:', '      path: "/?ed=2048"', '      headers:', `        Host: ${yq(host)}`,
  ].join('\n')).join('\n');
  const names = items.map((x) => `      - ${yq(x.n)}`).join('\n');
  return [
    'mixed-port: 7890', 'allow-lan: false', 'mode: rule', 'log-level: warning',
    'dns:', '  enable: true', '  ipv6: false', '  nameserver:', '    - https://1.1.1.1/dns-query',
    'proxies:', proxies,
    'proxy-groups:',
    '  - name: PROXY', '    type: select', '    proxies:', '      - AUTO', names,
    '  - name: AUTO', '    type: url-test', '    url: "http://www.gstatic.com/generate_204"', '    interval: 300', '    tolerance: 50', '    proxies:', names,
    'rules:', '  - MATCH,PROXY', '',
  ].join('\n');
}

function buildSingbox(users, addrs, host, cfg, inbound) {
  const items = outboundNames(users, addrs);
  const tags = items.map((x) => x.n);
  const outs = items.map(({ u, a, p, n }) => {
    const tls = { enabled: true, server_name: host, utls: { enabled: true, fingerprint: cfg.fp } };
    if (cfg.alpn) tls.alpn = cfg.alpn.split(',');
    if (cfg.fragment) { tls.fragment = true; tls.fragment_fallback_delay = '500ms'; }
    return {
      type: 'vless', tag: n, server: stripBrackets(a), server_port: p, uuid: u.uuid, packet_encoding: 'xudp', tls,
      transport: { type: 'ws', path: '/', headers: { Host: host }, max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol' },
    };
  });
  // Phone/desktop apps need a TUN inbound to actually capture traffic (a bare local proxy port does
  // nothing there), plus DNS and routing rules. ?inbound=mixed gives only the local proxy on
  // 127.0.0.1:2080 (for sing-box run without admin rights). Needs sing-box 1.12 or newer.
  // No TUN `stack` option on purpose: deprecated in sing-box 1.15 (removed in 1.17); the app picks its own.
  const inbounds = inbound === 'mixed'
    ? [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }]
    : [
        { type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], auto_route: true, strict_route: true },
        { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
      ];
  return JSON.stringify({
    log: { level: 'warn' },
    dns: {
      servers: [
        { type: 'https', tag: 'dns-remote', server: '8.8.8.8', detour: 'proxy' },
        { type: 'local', tag: 'dns-local' },
      ],
      final: 'dns-remote',
      strategy: 'ipv4_only',
    },
    inbounds,
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: ['auto', ...tags], default: 'auto' },
      { type: 'urltest', tag: 'auto', outbounds: tags, url: 'http://www.gstatic.com/generate_204', interval: '5m' },
      ...outs,
      { type: 'direct', tag: 'direct' },
    ],
    route: {
      rules: [
        { action: 'sniff' },
        { protocol: 'dns', action: 'hijack-dns' },
        // The Worker carries only TCP (and DNS). Apps such as Instagram try QUIC (UDP 443) first and hang while
        // waiting; rejecting other UDP makes them fall back to TCP immediately.
        { network: 'udp', action: 'reject' },
        { ip_is_private: true, outbound: 'direct' },
      ],
      final: 'proxy',
      auto_detect_interface: true,
      default_domain_resolver: 'dns-local', // for the vless server name when the domain itself is used as a server
    },
  }, null, 2);
}

// /sub/<token>                 -> all active users (base64 list of vless:// links)
// /sub/<token>/<uuid>          -> one user (+ usage/expiry headers that clients can display)
// ?format=base64|clash|singbox   ?op=mci|irancell|rightel|tci|other
async function handleSub(request, env, url) {
  const cfg = await getConfig(env);
  const parts = url.pathname.slice('/sub/'.length).split('/');
  if (!safeEqual(parts[0], cfg.subToken)) return decoyNotFound();

  const onlyUuid = (parts[1] || '').toLowerCase();
  let users = cfg.users.filter((u) => !u.disabled);
  if (onlyUuid) users = users.filter((u) => u.uuid === onlyUuid);
  if (!users.length) return decoyNotFound();

  const format = (url.searchParams.get('format') || 'base64').toLowerCase();
  let op = url.searchParams.get('op') || '';
  if (!OPERATORS[op]) op = OP_ASN[request.cf && request.cf.asn] || '';
  const emergency = url.searchParams.get('list') === 'emergency';
  let addrs;
  if (!emergency && V6_OPS.has(url.searchParams.get('op'))) {
    // IPv6-only link: only verified IPv6 addresses (no IPv4, no domain, no users' own manual IPs)
    op = url.searchParams.get('op');
    addrs = bestForOp(await loadHealthy(env), op, VERIFIED_IN_SUB);
    if (!addrs.length) return decoyNotFound();
    users = users.map((u) => ({ ...u, ips: '' }));
  } else if (emergency) {
    // Only the emergency list; users' own manual IPs, shared IPs and verified IPs are not mixed in.
    addrs = emergencyPairs(await loadEmergency(env));
    if (!addrs.length) return decoyNotFound();
    users = users.map((u) => ({ ...u, ips: '' }));
  } else {
    addrs = await getConnectAddrs(cfg, url.host, { env, op });
  }
  const o = linkOpts(cfg);

  const headers = {
    'Cache-Control': 'no-store',
    'profile-title': 'base64:' + b64utf8(onlyUuid ? APP_NAME + ' - ' + users[0].name : APP_NAME),
    'profile-update-interval': '6',
  };
  if (onlyUuid) {
    const u = users[0];
    const ui = [`upload=0`, `download=${Math.round(u.usedBytes || 0)}`];
    if (u.quotaBytes) ui.push(`total=${u.quotaBytes}`);
    if (u.expiresAt) ui.push(`expire=${Math.floor(u.expiresAt / 1000)}`);
    headers['subscription-userinfo'] = ui.join('; ');
  }

  if (format === 'clash' || format === 'clashmeta') {
    return new Response(buildClash(users, addrs, url.host, cfg), { headers: { ...headers, 'Content-Type': 'text/yaml; charset=utf-8' } });
  }
  if (format === 'singbox' || format === 'sing-box') {
    return new Response(buildSingbox(users, addrs, url.host, cfg, (url.searchParams.get('inbound') || '').toLowerCase()), { headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' } });
  }
  const lines = [];
  for (const u of users) for (const [a, p] of userAddrs(u, addrs)) lines.push(vlessLink(u, url.host, a, p, o));
  return new Response(btoa(lines.join('\n')), { headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' } });
}

/* ============================ Proxy IP resolution ============================ */

const proxyCache = new Map(); // key -> { list, at }
const directFail = new Map(); // host -> expiresAt

function splitHostPort(s) {
  s = String(s).trim();
  let m = s.match(/^(\[[^\]]+\])(?::(\d+))?$/);
  if (m) return [m[1], m[2] ? parseInt(m[2], 10) : null];
  m = s.match(/^([^:]+)(?::(\d+))?$/);
  if (m) return [m[1], m[2] ? parseInt(m[2], 10) : null];
  return [s, null];
}

function isIpLiteral(a) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(a) || a.startsWith('[');
}

function buildProxyEntries(cfg, env, colo) {
  if (cfg.proxyMode === 'off') return [];
  const out = [...splitList(cfg.proxyList)];
  if (env.PROXY_IP) out.push(...splitList(env.PROXY_IP));
  if (cfg.proxyMode === 'auto') {
    const d = cfg.autoDomain || DEFAULT_AUTO_DOMAIN;
    if (cfg.autoPerColo && colo) out.push(`${String(colo).toLowerCase()}.${d}`);
    out.push(d);
  }
  return [...new Set(out)];
}

async function doh(name, type) {
  const r = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: 'application/dns-json' },
    signal: AbortSignal.timeout(3000),
  });
  if (!r.ok) return [];
  const j = await r.json();
  return Array.isArray(j.Answer) ? j.Answer : [];
}

function parseTxt(data) {
  return String(data)
    .replace(/"/g, ' ')
    .replace(/\\010/g, ',')
    .split(/[\s,]+/)
    .filter(Boolean);
}

function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// entry -> [[addr, port|null], ...]
async function resolveEntry(entry) {
  const [addr, port] = splitHostPort(entry);
  if (isIpLiteral(addr)) return [[addr, port]];

  const [txt, a] = await Promise.all([doh(addr, 'TXT').catch(() => []), doh(addr, 'A').catch(() => [])]);

  const out = [];
  for (const r of txt) {
    if (r.type !== 16) continue;
    for (const s of parseTxt(r.data)) out.push(splitHostPort(s));
  }
  if (out.length) return shuffle(out);

  for (const r of a) if (r.type === 1) out.push([r.data, port]);
  if (out.length) return shuffle(out);

  const aaaa = await doh(addr, 'AAAA').catch(() => []);
  for (const r of aaaa) if (r.type === 28) out.push([`[${r.data}]`, port]);
  return shuffle(out);
}

// Pull IPv4 (optionally :port) tokens out of whatever a public "clean IP" source
// returns (plain text, HTML, JSON, CSV) - format varies by source and changes over time,
// so this stays deliberately forgiving rather than parsing a specific schema.
function extractIps(text, defaultPort, max) {
  const re = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?/g;
  const seen = new Set();
  const out = [];
  let m;
  while ((m = re.exec(text)) && out.length < max) {
    if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) continue;
    const ip = `${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
    if (seen.has(ip)) continue;
    seen.add(ip);
    const port = m[5] ? parseInt(m[5], 10) : defaultPort;
    out.push([ip, port > 0 && port < 65536 ? port : defaultPort]);
  }
  return out;
}

const cleanIpCache = new Map(); // urls-key -> { list, at }
const sourceStats = new Map(); // url -> { ok, count, ms, error, at } (last fetch attempt, per isolate)

function recordSourceStat(url, stat) {
  if (sourceStats.size > 50) sourceStats.clear();
  sourceStats.set(url, { ...stat, at: Date.now() });
}

// Forces a fresh fetch of every configured source and reports how each one did.
async function checkCleanSources(urls) {
  const list = await fetchCleanIps(urls, true);
  return {
    total: list.length,
    sources: urls.map((u) => ({ url: u, ...(sourceStats.get(u) || { ok: false, count: 0, ms: 0, error: 'بدون نتیجه' }) })),
  };
}

// Fetches the admin's configured public "clean IP" list URLs and extracts candidate
// IPs from each. These are third-party lists outside our control, so every fetch is
// timeboxed and a failing/unreachable source is skipped rather than failing the batch.
async function fetchCleanIps(urls, force = false) {
  if (!urls.length) return [];
  const key = urls.join('|');
  const c = cleanIpCache.get(key);
  if (!force && c && Date.now() - c.at < CLEAN_IP_CACHE_TTL) return c.list;

  const results = await Promise.allSettled(
    urls.map(async (u) => {
      const t0 = Date.now();
      try {
        const r = await fetch(u, { signal: AbortSignal.timeout(CLEAN_IP_TIMEOUT), headers: { accept: 'text/plain,*/*' } });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const text = await r.text();
        const found = extractIps(text, 443, 30);
        recordSourceStat(u, { ok: found.length > 0, count: found.length, ms: Date.now() - t0, error: found.length ? '' : 'هیچ آی‌پی‌ای در پاسخ پیدا نشد' });
        return found;
      } catch (e) {
        recordSourceStat(u, { ok: false, count: 0, ms: Date.now() - t0, error: String((e && e.message) || e).slice(0, 80) });
        throw e;
      }
    })
  );

  const seen = new Set();
  const list = [];
  for (const r of results) {
    if (r.status !== 'fulfilled') continue;
    for (const [ip, port] of r.value) {
      const k = ip + ':' + port;
      if (seen.has(k)) continue;
      seen.add(k);
      list.push([ip, port]);
    }
  }
  if (cleanIpCache.size > 20) cleanIpCache.clear();
  cleanIpCache.set(key, { list, at: list.length ? Date.now() : Date.now() - CLEAN_IP_CACHE_TTL + 30 * 1000 });
  return list;
}

const geoCache = new Map(); // ip -> { cc, at }

function stripBrackets(ip) {
  return ip.startsWith('[') && ip.endsWith(']') ? ip.slice(1, -1) : ip;
}

// Looks up the country of each IP via ip-api.com's free batch endpoint (no key, ~45 req/min,
// up to 100 IPs per call) and caches results for a day. Best-effort: an IP whose country
// could not be determined (lookup failed, rate-limited, IP reserved, etc.) is treated as
// non-matching rather than blocking the whole batch.
async function lookupCountries(ips) {
  const now = Date.now();
  const need = ips.filter((ip) => {
    const c = geoCache.get(ip);
    return !c || now - c.at >= GEOIP_CACHE_TTL;
  });

  for (let i = 0; i < need.length; i += GEOIP_BATCH_MAX) {
    const batch = need.slice(i, i + GEOIP_BATCH_MAX);
    try {
      const r = await fetch(GEOIP_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(batch.map(stripBrackets)),
        signal: AbortSignal.timeout(GEOIP_TIMEOUT),
      });
      if (!r.ok) continue;
      const rows = await r.json();
      if (!Array.isArray(rows)) continue;
      rows.forEach((row, idx) => {
        const ip = batch[idx];
        const cc = row && row.status === 'success' && row.countryCode ? row.countryCode : null;
        geoCache.set(ip, { cc, at: now });
      });
    } catch (_) {
      // leave these IPs unresolved for this call; they'll be treated as non-matching below
    }
  }
  if (geoCache.size > 5000) geoCache.clear();
}

async function filterByCountry(list, countries) {
  if (!countries.length) return list;
  const ips = [...new Set(list.map(([ip]) => ip))];
  await lookupCountries(ips);
  // If the lookup service answered for none of them (outage / rate limit) we cannot tell which
  // country anything is in; using the unfiltered list beats having no relay at all.
  if (!ips.some((ip) => geoCache.has(ip))) return list;
  return list.filter(([ip]) => {
    const c = geoCache.get(ip);
    return c && c.cc && countries.includes(c.cc);
  });
}

async function getProxies(cfg, env, colo, force = false) {
  const entries = buildProxyEntries(cfg, env, colo);
  const cleanUrls = cfg.proxyMode !== 'off' && cfg.cleanIpEnabled ? splitList(cfg.cleanIpUrls) : [];
  let countries = [];
  if (cfg.proxyMode !== 'off') {
    try { countries = parseCountryList(cfg.countryFilter, MAX_COUNTRIES); } catch (_) {}
  }
  if (!entries.length && !cleanUrls.length) return { entries, cleanUrls, countries, list: [] };

  const key = entries.join('|') + '||' + cleanUrls.join('|') + '||' + countries.join(',');
  const c = proxyCache.get(key);
  if (!force && c && Date.now() - c.at < PROXY_CACHE_TTL) return { entries, cleanUrls, countries, list: c.list };

  const [groups, cleanList] = await Promise.all([
    Promise.all(entries.map((e) => resolveEntry(e).catch(() => []))),
    cleanUrls.length ? fetchCleanIps(cleanUrls, force).catch(() => []) : Promise.resolve([]),
  ]);

  const seen = new Set();
  const raw = [];
  const push = (a, p) => {
    const k = `${a}:${p || ''}`;
    if (seen.has(k)) return;
    seen.add(k);
    raw.push([a, p]);
  };
  const longest = Math.max(0, ...groups.map((g) => g.length));
  for (let i = 0; i < longest; i++) for (const g of groups) if (i < g.length) push(g[i][0], g[i][1]);
  for (const [a, p] of cleanList) push(a, p);

  const list = countries.length ? await filterByCountry(raw, countries).catch(() => raw) : raw;

  if (proxyCache.size > 50) proxyCache.clear();
  // Empty results are re-tried after 30s instead of the full TTL
  proxyCache.set(key, { list, at: list.length ? Date.now() : Date.now() - PROXY_CACHE_TTL + 30 * 1000 });
  return { entries, cleanUrls, countries, list };
}

function isDirectBlocked(host) {
  const t = directFail.get(host);
  if (!t) return false;
  if (t < Date.now()) { directFail.delete(host); return false; }
  return true;
}

function markDirectFail(host) {
  if (directFail.size > 2000) directFail.clear();
  directFail.set(host, Date.now() + DIRECT_FAIL_TTL);
}

function withTimeout(p, ms, msg = 'timeout') {
  let t;
  return Promise.race([
    p,
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(msg)), ms); }),
  ]).finally(() => clearTimeout(t));
}

/* ================================ Admin panel ================================ */

const SEC_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};

// The panel page (only) may open https connections to arbitrary hosts: the "IP quality" tab
// measures reachability of Cloudflare IPs from the admin's own device.
const PANEL_CSP = SEC_HEADERS['Content-Security-Policy'].replace("connect-src 'self'", "connect-src 'self' https:");

function html(body, status = 200, panel = false) {
  const h = { 'Content-Type': 'text/html; charset=utf-8', ...SEC_HEADERS };
  if (panel) h['Content-Security-Policy'] = PANEL_CSP;
  return new Response(body, { status, headers: h });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/* ------------------------------ Panel authentication ------------------------------ */

// Password precedence: if a password was set from the panel (stored salted+hashed in KV) only that
// one works; otherwise the ADMIN variable is used. To recover a forgotten panel password, delete
// the KV key "auth" - the ADMIN variable works again.
async function getAuth(env) {
  return (await kvGet(env, AUTH_KEY)) || {}; // a KV failure propagates: never fall back to the ADMIN variable by accident
}

async function sessionToken(env, auth) {
  return sha256('nps1|' + String(env.ADMIN_USER || 'admin') + '|' + String(env.ADMIN) + '|' + (auth.hash || '') + '|' + (auth.sess || ''));
}

async function passwordOk(env, auth, pass) {
  if (auth.hash && auth.salt) return safeEqual(await sha256(auth.salt + '|' + pass), auth.hash);
  return safeEqual(await sha256(pass), await sha256(String(env.ADMIN)));
}

function authCookie(token) {
  return `auth=${token}; Path=/panel; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}

async function getRl(env, ip) {
  try { return (await kvGet(env, 'rl:' + ip)) || {}; } catch (_) { return {}; }
}

async function handleAdmin(request, env, url) {
  if (!env.ADMIN) return new Response('ADMIN variable is not set', { status: 500 });

  const auth = await getAuth(env);
  const token = await sessionToken(env, auth);
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const authed = safeEqual(cookies.auth || '', token);
  const path = url.pathname;

  if (request.method === 'POST' && path === '/panel/login') {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rl = await getRl(env, ip);
    if (rl.until && rl.until > Date.now()) {
      return html(loginPage('تلاش‌های ناموفق زیاد بود؛ ' + Math.ceil((rl.until - Date.now()) / 60000) + ' دقیقه‌ی دیگر دوباره تلاش کنید'), 429);
    }
    let pass = '', user = '';
    try { const fd = await request.formData(); pass = String(fd.get('password') || ''); user = String(fd.get('username') || ''); } catch (_) { return html(loginPage('درخواست نامعتبر است'), 400); }
    const passGood = await passwordOk(env, auth, pass);
    const userGood = safeEqual(await sha256(user), await sha256(String(env.ADMIN_USER || 'admin')));
    if (passGood && userGood) {
      if (rl.n || rl.until) { try { await kvDel(env, 'rl:' + ip); } catch (_) {} }
      return new Response(null, { status: 302, headers: { Location: '/panel', 'Set-Cookie': authCookie(token) } });
    }
    try {
      const n = (rl.n || 0) + 1;
      const rec = n >= LOGIN_MAX_FAILS ? { n: 0, until: Date.now() + LOGIN_BLOCK_SEC * 1000 } : { n };
      await kvPut(env, 'rl:' + ip, JSON.stringify(rec), { expirationTtl: LOGIN_BLOCK_SEC + 60 });
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 600));
    return html(loginPage('نام کاربری یا رمز اشتباه است'), 401);
  }

  if (path.startsWith('/panel/api/')) {
    if (!authed) return json({ error: 'unauthorized' }, 401);
    return await handleApi(request, env, url, path.slice('/panel/api/'.length));
  }

  if (!authed) return html(loginPage(''));
  return html(panelPage(), 200, true);
}

function sanitizeBackup(b) {
  const c = b && typeof b === 'object' ? (b.config && typeof b.config === 'object' ? b.config : b) : null;
  if (!c || !Array.isArray(c.users) || !c.users.length) throw new Error('فایل پشتیبان معتبر نیست');
  if (c.users.length > MAX_USERS) throw new Error(`بیش از ${MAX_USERS} کاربر در فایل است`);
  const num = (v) => (Number.isFinite(v) ? v : null);
  const seen = new Set();
  const users = [];
  for (const u of c.users) {
    const uuid = String((u && u.uuid) || '').toLowerCase();
    if (!UUID_RE.test(uuid) || seen.has(uuid)) throw new Error('UUID نامعتبر یا تکراری در فایل: ' + uuid.slice(0, 40));
    seen.add(uuid);
    const daily = {};
    if (u.daily && typeof u.daily === 'object') {
      for (const [k, v] of Object.entries(u.daily)) if (/^\d{4}-\d{2}-\d{2}$/.test(k) && Number.isFinite(v) && v >= 0) daily[k] = v;
    }
    const nu = {
      uuid,
      name: String(u.name || 'user').trim().slice(0, 32) || 'user',
      note: String(u.note || '').slice(0, MAX_NOTE),
      disabled: !!u.disabled,
      expiresAt: num(u.expiresAt),
      quotaBytes: Number.isFinite(u.quotaBytes) && u.quotaBytes > 0 ? u.quotaBytes : null,
      usedBytes: Number.isFinite(u.usedBytes) && u.usedBytes > 0 ? u.usedBytes : 0,
      expireAfterDays: Number.isInteger(u.expireAfterDays) && u.expireAfterDays > 0 ? u.expireAfterDays : null,
      firstUsedAt: num(u.firstUsedAt),
      maxDevices: Number.isInteger(u.maxDevices) && u.maxDevices > 0 ? u.maxDevices : null,
      ips: (() => { try { return cleanList(u.ips || '', 20).join('\n'); } catch (_) { return ''; } })(),
      daily,
    };
    pruneDaily(nu);
    users.push(nu);
  }
  const count = Number.isInteger(c.addrCount) && c.addrCount >= 1 && c.addrCount <= MAX_AUTO_ADDRS ? c.addrCount : 3;
  const next = {
    users,
    subToken: /^[0-9a-f]{32,64}$/.test(String(c.subToken || '')) ? c.subToken : randomToken(),
    proxyMode: ['auto', 'custom', 'off'].includes(c.proxyMode) ? c.proxyMode : 'auto',
    proxyList: cleanList(c.proxyList || '', MAX_LIST).join('\n'),
    autoDomain: DOMAIN_RE.test(String(c.autoDomain || '').toLowerCase()) ? String(c.autoDomain).toLowerCase() : DEFAULT_AUTO_DOMAIN,
    autoPerColo: c.autoPerColo !== false,
    addrs: cleanList(c.addrs || '', 20).join('\n'),
    cleanIpEnabled: !!c.cleanIpEnabled,
    cleanIpUrls: cleanUrlList(c.cleanIpUrls || '', MAX_CLEAN_IP_URLS).join('\n'),
    countryFilter: parseCountryList(c.countryFilter || '', MAX_COUNTRIES).join(','),
    addrMode: c.addrMode === 'auto' ? 'auto' : 'manual',
    addrCount: count,
    ports: parsePorts(c.ports).join(',') || '443',
    fp: FPS.includes(c.fp) ? c.fp : 'chrome',
    alpn: ALPNS.includes(c.alpn) ? c.alpn : '',
    fragment: !!c.fragment,
    flushMin: FLUSH_CHOICES.includes(c.flushMin) ? c.flushMin : DEFAULT_FLUSH_MIN,
  };
  const healthy = { ops: {} };
  const hh = b && b.healthy && b.healthy.ops;
  if (hh && typeof hh === 'object') {
    for (const op of Object.keys(OPERATORS)) {
      const m = hh[op];
      if (!m || typeof m !== 'object') continue;
      const out = {};
      for (const [k, v] of Object.entries(m)) {
        if (!/^[a-zA-Z0-9.\-\[\]:]{3,80}:\d{1,5}$/.test(k)) continue;
        if (!v || !Number.isFinite(v.ms) || !Number.isFinite(v.at)) continue;
        out[k] = { ms: Math.round(v.ms), at: v.at, fail: Number.isInteger(v.fail) && v.fail >= 0 ? v.fail : 0 };
      }
      healthy.ops[op] = Object.fromEntries(Object.entries(out).slice(0, HEALTHY_MAX_PER_OP));
    }
  }
  // emergency list (backups made before it existed simply do not have the field -> keep the current list)
  let emergency = null;
  if (b && b.emergency && typeof b.emergency === 'object') {
    // line by line: a bad line is dropped instead of making the whole restore fail
    const items = [];
    for (const line of String(b.emergency.text || '').split(/[\r\n]+/).slice(0, MAX_EMERGENCY * 2)) {
      let it = null;
      try { it = cleanList(line, 1)[0] || null; } catch (_) { it = null; }
      if (!it) continue;
      const port = splitHostPort(it)[1];
      if (port === null || (port > 0 && port < 65536)) items.push(it);
    }
    emergency = [...new Set(items)].slice(0, MAX_EMERGENCY).join('\n');
  }
  return { next, healthy, emergency };
}

async function handleApi(request, env, url, action) {
  const colo = (request.cf && request.cf.colo) || '';

  if (request.method === 'GET' && action === 'state') {
    return json(await publicState(await getConfig(env, true), url, colo, env));
  }
  if (request.method === 'GET' && action === 'backup') {
    const cfg = await getConfig(env, true);
    const healthy = await loadHealthy(env, true);
    const emergency = { text: await loadEmergency(env) };
    return new Response(JSON.stringify({ app: 'nader-proxy', version: 2, exportedAt: new Date().toISOString(), config: cfg, healthy, emergency }, null, 2), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="nader-proxy-backup-${dayKey()}.json"`,
        'Cache-Control': 'no-store',
      },
    });
  }
  if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405);

  // CSRF hardening (cookie is SameSite=Strict as well)
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) return json({ error: 'forbidden origin' }, 403);
  if (!(request.headers.get('content-type') || '').includes('application/json')) {
    return json({ error: 'content-type must be application/json' }, 415);
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}
  if (!body || typeof body !== 'object') body = {};

  if (action === 'logout') {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'auth=; Path=/panel; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
      },
    });
  }

  const cfg = await getConfig(env, true);
  const findUser = () => {
    const uuid = String(body.uuid || '').toLowerCase();
    const u = cfg.users.find((x) => x.uuid === uuid);
    if (!u) throw new Error('کاربر پیدا نشد');
    return u;
  };
  const HOST_RE = /^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.\-]{1,253})$/;

  try {
    switch (action) {
      case 'user/add': {
        if (cfg.users.length >= MAX_USERS) throw new Error(`حداکثر ${MAX_USERS} کاربر`);
        const name = String(body.name || '').trim().slice(0, 32) || 'user';
        cfg.users.push({
          uuid: crypto.randomUUID(), name, note: '', disabled: false, expiresAt: null, quotaBytes: null, usedBytes: 0,
          expireAfterDays: null, firstUsedAt: null, maxDevices: null, daily: {},
        });
        break;
      }
      case 'user/delete': {
        if (cfg.users.length <= 1) throw new Error('حداقل یک کاربر لازم است');
        const uuid = String(body.uuid || '').toLowerCase();
        cfg.users = cfg.users.filter((u) => u.uuid !== uuid);
        break;
      }
      case 'user/rename': {
        const u = findUser();
        const name = String(body.name || '').trim().slice(0, 32);
        if (!name) throw new Error('نام خالی است');
        u.name = name;
        break;
      }
      case 'user/set-meta': {
        const u = findUser();
        const name = String(body.name || '').trim().slice(0, 32);
        if (!name) throw new Error('نام خالی است');
        u.name = name;
        u.note = String(body.note || '').trim().slice(0, MAX_NOTE);
        const dev = String(body.maxDevices == null ? '' : body.maxDevices).trim();
        if (!dev) u.maxDevices = null;
        else {
          const n = Number(dev);
          if (!Number.isInteger(n) || n < 1 || n > 50) throw new Error('تعداد دستگاه باید عددی بین ۱ تا ۵۰ باشد');
          u.maxDevices = n;
        }
        if (body.ips !== undefined) u.ips = cleanList(body.ips, 20).join('\n');
        break;
      }
      case 'user/toggle': {
        const u = findUser();
        u.disabled = !!body.disabled;
        break;
      }
      case 'user/set-limits': {
        const u = findUser();
        const mode = String(body.expireMode || 'none');
        if (mode === 'date') {
          const t = Date.parse(String(body.expiresAt || '').trim() + 'T23:59:59');
          if (!Number.isFinite(t)) throw new Error('تاریخ نامعتبر است');
          u.expiresAt = t; u.expireAfterDays = null; u.firstUsedAt = null;
        } else if (mode === 'days') {
          const n = Number(String(body.expireDays || '').trim());
          if (!Number.isInteger(n) || n < 1 || n > 3650) throw new Error('تعداد روز باید عددی بین ۱ تا ۳۶۵۰ باشد');
          u.expireAfterDays = n;
          if (u.firstUsedAt) u.expiresAt = u.firstUsedAt + n * DAY_MS;
          else u.expiresAt = null;
        } else if (mode === 'none') {
          u.expiresAt = null; u.expireAfterDays = null; u.firstUsedAt = null;
        } else throw new Error('نوع انقضا نامعتبر است');

        const gbStr = String(body.quotaGB || '').trim();
        if (!gbStr) {
          u.quotaBytes = null;
        } else {
          const gb = Number(gbStr);
          if (!Number.isFinite(gb) || gb <= 0 || gb > MAX_QUOTA_GB) throw new Error('حجم نامعتبر است');
          u.quotaBytes = Math.round(gb * BYTES_PER_GB);
        }
        break;
      }
      case 'user/restart-first-use': {
        const u = findUser();
        if (!u.expireAfterDays) throw new Error('این کاربر انقضای «از اولین اتصال» ندارد');
        u.firstUsedAt = null; u.expiresAt = null;
        break;
      }
      case 'user/reset-usage': {
        findUser().usedBytes = 0;
        break;
      }
      case 'proxy/save': {
        const mode = String(body.proxyMode || '');
        if (!['auto', 'custom', 'off'].includes(mode)) throw new Error('حالت نامعتبر');
        const domain = String(body.autoDomain || DEFAULT_AUTO_DOMAIN).trim().toLowerCase();
        if (!DOMAIN_RE.test(domain)) throw new Error('دامنه‌ی منبع خودکار نامعتبر است');
        cfg.proxyMode = mode;
        cfg.proxyList = cleanList(body.proxyList, MAX_LIST).join('\n');
        cfg.autoDomain = domain;
        cfg.autoPerColo = !!body.autoPerColo;
        cfg.cleanIpEnabled = !!body.cleanIpEnabled;
        cfg.cleanIpUrls = cleanUrlList(body.cleanIpUrls, MAX_CLEAN_IP_URLS).join('\n');
        cfg.countryFilter = parseCountryList(body.countryFilter, MAX_COUNTRIES).join(',');
        break;
      }
      case 'addr/save': {
        cfg.addrs = cleanList(body.addrs, 20).join('\n');
        const mode = String(body.addrMode || '');
        if (!['manual', 'auto'].includes(mode)) throw new Error('حالت نامعتبر');
        const count = parseInt(body.addrCount, 10);
        if (!Number.isInteger(count) || count < 1 || count > MAX_AUTO_ADDRS) {
          throw new Error(`تعداد باید بین ۱ تا ${MAX_AUTO_ADDRS} باشد`);
        }
        cfg.addrMode = mode;
        cfg.addrCount = count;
        break;
      }
      case 'settings/save': {
        const fp = String(body.fp || '');
        if (!FPS.includes(fp)) throw new Error('اثر انگشت TLS نامعتبر است');
        const alpn = String(body.alpn || '');
        if (!ALPNS.includes(alpn)) throw new Error('مقدار ALPN نامعتبر است');
        const ports = parsePorts(Array.isArray(body.ports) ? body.ports.join(',') : body.ports);
        if (!ports.length) throw new Error('حداقل یک پورت انتخاب کنید');
        const fm = body.flushMin == null || body.flushMin === '' ? cfg.flushMin : parseInt(body.flushMin, 10);
        if (!FLUSH_CHOICES.includes(fm)) throw new Error('فاصله‌ی ذخیره نامعتبر است');
        cfg.fp = fp; cfg.alpn = alpn; cfg.ports = ports.join(','); cfg.fragment = !!body.fragment; cfg.flushMin = fm;
        break;
      }
      case 'stats/reset': {
        cfg.stats = { since: Date.now(), colos: {} };
        break;
      }
      case 'sub/regen': {
        cfg.subToken = randomToken();
        break;
      }
      case 'test': {
        const host = String(body.host || 'chatgpt.com').trim().toLowerCase();
        if (!/^[a-z0-9][a-z0-9.\-]{0,251}[a-z0-9]$/.test(host)) throw new Error('آدرس سایت نامعتبر است');
        return json(await runTest(cfg, env, colo, host));
      }
      case 'sources/check': {
        const urls = splitList(cfg.cleanIpUrls);
        if (!urls.length) throw new Error('هیچ آدرس منبعی تنظیم نشده است');
        return json(await checkCleanSources(urls));
      }
      case 'ips/candidates': {
        const urls = splitList(cfg.cleanIpUrls);
        let raw = [];
        try { raw = await fetchCleanIps(urls.length ? urls : DEFAULT_CLEAN_IP_URLS); } catch (_) {}
        const toPair = (x) => { const [a, p] = splitHostPort(x); return [a, p || 443]; };
        const extra = cleanList(body.extra || '', 40).map(toPair);
        const manual = splitList(cfg.addrs).map(toPair);
        const wantV6 = V6_OPS.has(String(body.op || ''));
        const list = dedupeAddrs([...extra, ...manual, ...raw]).filter(([a]) => String(a).startsWith('[') === wantV6).slice(0, 40);
        return json({ candidates: list.map(([addr, port]) => ({ addr, port })), ports: parsePorts(cfg.ports) });
      }
      case 'ips/report': {
        const op = String(body.op || '');
        if (!OPERATORS[op]) throw new Error('اپراتور نامعتبر است');
        const results = [];
        for (const r of (Array.isArray(body.results) ? body.results.slice(0, 120) : [])) {
          const addr = String((r && r.addr) || '');
          const port = parseInt(r && r.port, 10);
          if (!HOST_RE.test(addr) || !(port > 0 && port < 65536)) continue;
          if (addr.startsWith('[') !== V6_OPS.has(op)) continue; // IPv6 results only go to the IPv6 lists, IPv4 only to IPv4
          results.push({ addr, port, ms: Number.isFinite(r.ms) && r.ms > 0 && r.ms < 60000 ? r.ms : null });
        }
        if (!results.length) throw new Error('نتیجه‌ای برای ذخیره نیست');
        const h = await loadHealthy(env, true, true);
        mergeReport(h, op, results);
        await saveHealthy(env, h);
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'emergency/save': {
        const items = cleanList(body.text, MAX_EMERGENCY);
        for (const it of items) {
          const [, port] = splitHostPort(it);
          if (port !== null && !(port > 0 && port < 65536)) throw new Error('پورت نامعتبر: ' + it);
        }
        if (!items.length) throw new Error('لیست خالی است');
        await kvPut(env, EMERGENCY_KEY, JSON.stringify({ text: [...new Set(items)].join('\n'), at: Date.now() }));
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'errors/clear': {
        errCache.list = [];
        await kvDel(env, ERRLOG_KEY);
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'diag/start': {
        diagCache.until = Date.now() + DIAG_MINUTES * 60000;
        diagCache.events = [];
        diagCache.dirty = false;
        diagCache.at = Date.now();
        await kvPut(env, DIAG_KEY, JSON.stringify({ until: diagCache.until, events: [] }));
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'diag/stop': {
        diagCache.until = 0;
        diagCache.at = Date.now();
        await kvPut(env, DIAG_KEY, JSON.stringify({ until: 0, events: diagCache.events }));
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'diag/clear': {
        diagCache.events = [];
        diagCache.dirty = false;
        diagCache.at = Date.now();
        await kvPut(env, DIAG_KEY, JSON.stringify({ until: diagCache.until, events: [] }));
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'emergency/clear': {
        await kvDel(env, EMERGENCY_KEY);
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'ips/clear': {
        const op = String(body.op || '');
        if (!OPERATORS[op]) throw new Error('اپراتور نامعتبر است');
        const h = await loadHealthy(env, true, true);
        if (body.key) { if (h.ops[op]) delete h.ops[op][String(body.key)]; } else h.ops[op] = {};
        await saveHealthy(env, h);
        return json({ ok: true, state: await publicState(cfg, url, colo, env) });
      }
      case 'password/change': {
        const auth = await getAuth(env);
        if (!(await passwordOk(env, auth, String(body.current || '')))) throw new Error('رمز فعلی درست نیست');
        const next = String(body.next || '');
        if (next.length < 8) throw new Error('رمز جدید باید حداقل ۸ کاراکتر باشد');
        if (next.length > 128) throw new Error('رمز جدید خیلی طولانی است');
        const salt = randomToken();
        const rec = { salt, hash: await sha256(salt + '|' + next), sess: randomToken() };
        await kvPut(env, AUTH_KEY, JSON.stringify(rec));
        return new Response(JSON.stringify({ ok: true }), {
          headers: { 'Content-Type': 'application/json', 'Set-Cookie': authCookie(await sessionToken(env, rec)) },
        });
      }
      case 'password/logout-all': {
        const auth = await getAuth(env);
        const rec = { ...auth, sess: randomToken() };
        await kvPut(env, AUTH_KEY, JSON.stringify(rec));
        return new Response(JSON.stringify({ ok: true }), {
          headers: { 'Content-Type': 'application/json', 'Set-Cookie': authCookie(await sessionToken(env, rec)) },
        });
      }
      case 'restore': {
        const { next, healthy, emergency } = sanitizeBackup(body.backup);
        for (const k of Object.keys(cfg)) delete cfg[k];
        Object.assign(cfg, next);
        await saveHealthy(env, healthy);
        if (emergency !== null) {
          if (emergency) await kvPut(env, EMERGENCY_KEY, JSON.stringify({ text: emergency, at: Date.now() }));
          else await kvDel(env, EMERGENCY_KEY);
        }
        break;
      }
      default:
        return json({ error: 'not found' }, 404);
    }
  } catch (e) {
    return json({ error: e && e.message ? e.message : String(e) }, 400);
  }

  await saveConfig(env, cfg);
  return json({ ok: true, state: await publicState(cfg, url, colo, env) });
}

async function publicState(cfg, url, colo, env) {
  const host = url.host;
  const addrs = await getConnectAddrs(cfg, host, { env });
  const o = linkOpts(cfg);
  const healthy = env ? await loadHealthy(env) : { ops: {} };
  const emText = env ? await loadEmergency(env) : '';
  const dg = env ? await diagLoad(env, true) : diagCache;
  const errList = env ? await loadErrors(env) : [];
  const emPairs = emergencyPairs(emText);
  const now = Date.now();
  const days = [];
  for (let i = 13; i >= 0; i--) days.push(dayKey(now - i * DAY_MS));
  const base = `https://${host}/sub/${cfg.subToken}`;
  return {
    host,
    colo,
    maxUsers: MAX_USERS,
    subUrl: base,
    proxyMode: cfg.proxyMode,
    proxyList: cfg.proxyList,
    autoDomain: cfg.autoDomain,
    autoDomainDefault: DEFAULT_AUTO_DOMAIN,
    autoPerColo: cfg.autoPerColo,
    cleanIpEnabled: cfg.cleanIpEnabled,
    cleanIpUrls: cfg.cleanIpUrls,
    cleanIpUrlsDefault: DEFAULT_CLEAN_IP_URLS.join('\n'),
    maxCleanIpUrls: MAX_CLEAN_IP_URLS,
    countryFilter: cfg.countryFilter,
    maxCountries: MAX_COUNTRIES,
    addrs: cfg.addrs,
    addrMode: cfg.addrMode,
    addrCount: cfg.addrCount,
    errors: errList.slice().reverse().slice(0, 20),
    diag: { on: dg.until > Date.now(), until: dg.until, events: dg.events.slice(-100) },
    maxAutoAddrs: MAX_AUTO_ADDRS,
    maxEmergency: MAX_EMERGENCY,
    fp: cfg.fp,
    alpn: cfg.alpn,
    fragment: cfg.fragment,
    flushMin: cfg.flushMin,
    flushChoices: FLUSH_CHOICES,
    emergency: { store: dbOf(env) ? 'D1' : 'KV', text: emText, count: emPairs.length, nonTls: emPairs.filter(([, p]) => !CF_PORTS.includes(p)).length },
    kv: {
      backend: env && dbOf(env) ? 'D1' : 'KV',
      freeWrites: Number(env && env.FREE_WRITES) || (env && dbOf(env) ? D1_FREE_WRITES : KV_FREE_WRITES),
      freeReads: Number(env && env.FREE_READS) || (env && dbOf(env) ? D1_FREE_READS : KV_FREE_READS),
      freeRequests: Number(env && env.FREE_REQUESTS) || REQ_FREE,
      pending: { w: kvOps.w, r: kvOps.r, q: kvOps.q },
      days: Object.entries((cfg.stats && cfg.stats.kv) || {}).sort().slice(-7).map(([d, v]) => ({ d, w: v.w || 0, r: v.r || 0, q: v.q || 0 })),
    },
    ports: parsePorts(cfg.ports),
    cfPorts: CF_PORTS,
    fps: FPS,
    alpns: ALPNS,
    operators: OPERATORS,
    ipv6Ops: [...V6_OPS],
    healthy: healthySummary(healthy),
    daily: days.map((d) => ({ d, bytes: cfg.users.reduce((n, u) => n + ((u.daily && u.daily[d]) || 0), 0) })),
    stats: {
      since: (cfg.stats && cfg.stats.since) || Date.now(),
      colos: Object.entries((cfg.stats && cfg.stats.colos) || {}).map(([colo, t]) => ({
        colo, conns: t.conns, ok: t.ok, fail: t.fail, relay: t.relay, lastErr: t.lastErr || '', lastErrAt: t.lastErrAt || 0,
        hosts: Object.entries(t.hosts || {}).map(([name, v]) => ({ name, ok: v[0], fail: v[1] })).sort((a, b) => (b.ok + b.fail) - (a.ok + a.fail)),
      })).sort((a, b) => b.conns - a.conns),
    },
    quality: {
      since: wsStats.since, conns: wsStats.conns, ok: wsStats.ok, fail: wsStats.fail, rejected: wsStats.rejected,
      proxies: [...proxyStats.entries()].map(([addr, s]) => ({
        addr, ok: s.ok, fail: s.fail, ms: s.ms, consec: s.consec, bad: s.consec >= 3 && now - s.lastFail < PROXY_BAD_TTL,
      })).sort((a, b) => (a.bad - b.bad) || ((a.ms == null ? 1e9 : a.ms) - (b.ms == null ? 1e9 : b.ms))).slice(0, 30),
    },
    users: cfg.users.map((u) => ({
      uuid: u.uuid,
      name: u.name,
      note: u.note || '',
      disabled: !!u.disabled,
      expiresAt: u.expiresAt || null,
      expireAfterDays: u.expireAfterDays || null,
      firstUsedAt: u.firstUsedAt || null,
      pendingStart: !!(u.expireAfterDays && !u.firstUsedAt),
      maxDevices: u.maxDevices || null,
      quotaBytes: u.quotaBytes || null,
      usedBytes: (u.usedBytes || 0) + (pendingUsage.get(u.uuid) || 0),
      status: checkUserStatus(u),
      warn: userWarn(u),
      daily: days.map((d) => (u.daily && u.daily[d]) || 0),
      subUrl: `${base}/${u.uuid}`,
      statusUrl: `${url.origin}/status/${cfg.subToken}/${u.uuid}`,
      ips: u.ips || '',
      links: userAddrs(u, addrs).map(([a, p]) => ({ label: (a === host ? 'پیش‌فرض' : a) + (p === 443 ? '' : ':' + p), url: vlessLink(u, host, a, p, o) })),
    })),
  };
}

/* ---------------------------- Connectivity test tool ---------------------------- */

// Connects to addr:port, does TLS with SNI = host, sends a GET and checks for an HTTP response.
async function httpProbe(addr, port, host) {
  const t0 = Date.now();
  let sock;
  try {
    sock = connect({ hostname: addr, port }, { secureTransport: 'starttls' });
    await withTimeout(sock.opened, 3000, 'connect timeout');
    const tls = sock.startTls({ expectedServerHostname: host });
    const w = tls.writable.getWriter();
    const req = `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
    await withTimeout(w.write(new TextEncoder().encode(req)), 4000, 'write timeout');
    const r = tls.readable.getReader();
    const { value } = await withTimeout(r.read(), 4000, 'no response');
    const head = new TextDecoder().decode(value || new Uint8Array(0)).split('\r\n')[0];
    return { ok: /^HTTP\/\d/.test(head), status: head.slice(0, 40), ms: Date.now() - t0 };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 120), ms: Date.now() - t0 };
  } finally {
    try { sock && sock.close(); } catch (_) {}
  }
}

async function runTest(cfg, env, colo, host) {
  const { entries, countries, list } = await getProxies(cfg, env, colo, true);
  const ranked = proxyRank(list).slice(0, 6);
  try { await lookupCountries([...new Set(ranked.map(([a]) => a))]); } catch (_) {}
  const [direct, ...cands] = await Promise.all([
    httpProbe(host, 443, host),
    ...ranked.map(([a, p]) =>
      httpProbe(a, p || 443, host).then((r) => {
        recordProxy(proxyKey(a, p), r.ok, r.ms);
        return { addr: a, port: p || 443, cc: (geoCache.get(a) || {}).cc || null, ...r };
      })
    ),
  ]);
  return { host, colo, entries, countries, resolved: list.length, direct, candidates: cands };
}

/* ---------------------------------- Pages ---------------------------------- */

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const STYLE = `
:root{
  --bg:#f1f3f7;--surface:#ffffff;--surface-2:#f6f8fb;--ink:#0e1a2c;--ink-2:#3a4a60;--muted:#64738a;
  --line:#dde3ec;--line-2:#c9d2df;
  --brand:#2450c8;--brand-ink:#ffffff;--brand-soft:#e7edfb;--live:#0e9d8d;--live-soft:#dcf3ef;
  --ok:#11785a;--ok-soft:#dcf1e9;--warn:#96610a;--warn-soft:#faefd6;--bad:#c02a36;--bad-soft:#fbe4e6;
  --mono:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;
  --sans:Vazirmatn,IRANSans,"Noto Sans Arabic UI","Segoe UI",Tahoma,Arial,sans-serif;
  --r:12px;--r-sm:8px;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#0a101a;--surface:#111a27;--surface-2:#0e1621;--ink:#e6ecf5;--ink-2:#b3bfd0;--muted:#8391a6;
  --line:#213047;--line-2:#2d3f5a;
  --brand:#7c9dff;--brand-ink:#0a1633;--brand-soft:#16223c;--live:#33d2bf;--live-soft:#0f302d;
  --ok:#52d1a2;--ok-soft:#0f2e25;--warn:#e8b352;--warn-soft:#33270d;--bad:#f37b84;--bad-soft:#36151a;
  color-scheme:dark;
}}
:root[data-theme=dark]{
  --bg:#0a101a;--surface:#111a27;--surface-2:#0e1621;--ink:#e6ecf5;--ink-2:#b3bfd0;--muted:#8391a6;
  --line:#213047;--line-2:#2d3f5a;
  --brand:#7c9dff;--brand-ink:#0a1633;--brand-soft:#16223c;--live:#33d2bf;--live-soft:#0f302d;
  --ok:#52d1a2;--ok-soft:#0f2e25;--warn:#e8b352;--warn-soft:#33270d;--bad:#f37b84;--bad-soft:#36151a;
  color-scheme:dark;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14.5px;line-height:1.8;-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--brand);outline-offset:2px}

/* shell: sidebar on wide screens, sticky top bar on phones */
.shell{min-height:100vh}
.side{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px;padding:10px 14px 0;background:var(--surface);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
.brand svg{width:30px;height:30px;flex:none}
.brand b{font-size:16px;font-weight:800;letter-spacing:-.01em}
.side-actions{display:flex;gap:2px}
.iconbtn{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:var(--r-sm);background:none;color:var(--muted);cursor:pointer}
.iconbtn:hover{background:var(--surface-2);color:var(--ink)}
.ic{width:20px;height:20px;flex:none;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.tabs{order:3;width:100%;display:flex;gap:2px;overflow-x:auto;scrollbar-width:none;margin:0 -14px;padding:0 10px}
.tabs::-webkit-scrollbar{display:none}
.tab{display:inline-flex;align-items:center;gap:7px;flex:none;background:none;border:0;border-bottom:2px solid transparent;color:var(--muted);padding:10px 11px 9px;cursor:pointer;font-size:13.5px;font-weight:600;white-space:nowrap}
.tab .ic{width:18px;height:18px}
.tab:hover{color:var(--ink)}
.tab.on{color:var(--brand);border-bottom-color:var(--brand)}
.main{max-width:880px;margin:0 auto;padding:18px 14px 56px}
.page-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:2px 0 16px}
.page-head h1{margin:0;font-size:21px;font-weight:800;letter-spacing:-.015em}
.pill{display:inline-flex;align-items:center;gap:7px;padding:3px 11px;border:1px solid var(--line);border-radius:999px;background:var(--surface);font-size:12.5px;color:var(--ink-2)}
.pill .dot{width:7px;height:7px;border-radius:50%;background:var(--live);box-shadow:0 0 0 3px var(--live-soft)}
@media (min-width:880px){
  .shell{display:grid;grid-template-columns:236px minmax(0,1fr)}
  .side{position:sticky;top:0;height:100vh;flex-direction:column;flex-wrap:nowrap;align-items:stretch;gap:0;padding:18px 12px 14px;border-bottom:0;border-inline-end:1px solid var(--line)}
  .brand{flex:none;padding:0 8px 18px}
  .tabs{order:0;flex:1;width:auto;flex-direction:column;overflow:visible;margin:0;padding:0;gap:2px}
  .tab{border-bottom:0;border-inline-start:3px solid transparent;border-radius:var(--r-sm);padding:9px 12px;font-size:14px}
  .tab:hover{background:var(--surface-2)}
  .tab.on{background:var(--brand-soft);border-inline-start-color:var(--brand)}
  .side-actions{order:2;justify-content:flex-start;padding-top:10px;border-top:1px solid var(--line);margin-top:10px}
  .main{width:100%;padding:28px 32px 64px}
  .page-head h1{font-size:23px}
}

/* sections */
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:16px 16px 14px;margin-bottom:12px}
.card>h3{margin:-2px 0 12px;padding-bottom:11px;border-bottom:1px solid var(--line);font-size:15px;font-weight:700}
.card h4{margin:16px 0 6px;font-size:13px;font-weight:700;color:var(--ink-2)}
.card h4:first-child{margin-top:0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:12px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r);overflow:hidden}
.stat{padding:11px 16px;border-inline-start:1px solid var(--line);min-width:0}
.stat:first-child{border-inline-start:0}
.stat span{display:block;color:var(--muted);font-size:12px}
.stat b{display:block;font-size:16px;font-weight:700;word-break:break-all}
@media (max-width:560px){.stat{border-inline-start:0;border-top:1px solid var(--line)}.stat:first-child{border-top:0}.stats{grid-template-columns:1fr 1fr}.stat:nth-child(2){border-top:0}.stat:nth-child(even){border-inline-start:1px solid var(--line)}}
.route{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.node{background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-sm);padding:6px 12px;font-size:13.5px;font-weight:600}
.node small{display:block;color:var(--muted);font-size:11.5px;font-weight:400}
.node.hot{border-color:var(--live);background:var(--live-soft)}
.arrow{color:var(--line-2);font-size:14px}

/* status and text */
.badge{display:inline-flex;align-items:center;gap:6px;padding:1px 10px;border-radius:999px;font-size:12px;font-weight:700;line-height:1.7}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.badge.ok{background:var(--ok-soft);color:var(--ok)}
.badge.warn{background:var(--warn-soft);color:var(--warn)}
.badge.bad{background:var(--bad-soft);color:var(--bad)}
.ok{color:var(--ok)}.bad{color:var(--bad)}
.note{color:var(--muted);font-size:12.5px;line-height:1.85;margin:8px 0 0}
.note.warn{color:var(--ink-2);background:var(--warn-soft);border-inline-start:3px solid var(--warn);border-radius:var(--r-sm);padding:8px 12px}
.verdict{padding:10px 14px;border-radius:var(--r-sm);background:var(--brand-soft);border-inline-start:3px solid var(--brand);margin:10px 0;font-size:13.5px}
.ltr{direction:ltr;text-align:left;font-family:var(--mono);font-size:12.5px}
.bar{background:var(--surface-2);border:1px solid var(--line);border-radius:4px;overflow:hidden;height:7px;margin:7px 0}
.bar>div{height:100%;background:var(--brand)}
.bar.warn>div{background:var(--warn)}
.bar.bad>div{background:var(--bad)}

/* forms */
input[type=text],input[type=password],input[type=date],input:not([type]),textarea,select{width:100%;min-height:42px;background:var(--surface);color:var(--ink);border:1px solid var(--line-2);border-radius:var(--r-sm);padding:8px 12px;margin:4px 0 10px}
input[type=file]{width:100%;margin:4px 0 10px;font-size:13px}
select{appearance:auto;min-width:150px}
input:hover,textarea:hover,select:hover{border-color:var(--muted)}
input:focus,textarea:focus,select:focus{border-color:var(--brand);outline:2px solid var(--brand-soft);outline-offset:0}
textarea{font-family:var(--mono);font-size:13px;direction:ltr;resize:vertical;line-height:1.6}
input.ltr{font-family:var(--mono)}
input[type=checkbox],input[type=radio]{width:auto;min-height:0;margin:5px 0 0;accent-color:var(--brand)}
.fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:2px 12px}
.field{min-width:0}
.field label{display:block;font-size:12.5px;color:var(--muted);margin-bottom:0}
.field input,.field select{margin:3px 0 10px}
.opt{display:flex;gap:10px;align-items:flex-start;padding:8px 0;cursor:pointer}
.ports{display:flex;flex-wrap:wrap;gap:0 20px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:40px;padding:6px 18px;border:1px solid var(--brand);border-radius:var(--r-sm);background:var(--brand);color:var(--brand-ink);font-weight:700;font-size:14px;cursor:pointer;text-decoration:none;margin:2px 0}
.btn:hover{filter:brightness(1.08)}
.btn:active{transform:translateY(1px)}
.btn.sm{min-height:34px;padding:3px 13px;font-size:13px}
.btn.ghost{background:transparent;color:var(--ink);border-color:var(--line-2);font-weight:600}
.btn.ghost:hover{background:var(--surface-2);filter:none}
.btn.danger{background:transparent;color:var(--bad);border-color:var(--bad);font-weight:600}
.btn.danger:hover{background:var(--bad-soft);filter:none}
.btn[disabled]{opacity:.5;cursor:wait}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
code.blk{display:block;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-sm);padding:8px 11px;margin:6px 0;word-break:break-all;direction:ltr;text-align:left;font-family:var(--mono);font-size:12px;line-height:1.6}
.qrbox{background:#fff;border:1px solid var(--line);border-radius:var(--r-sm);padding:12px;margin:8px 0;display:block;width:fit-content;max-width:100%;color:#333}
.qrbox[hidden]{display:none}
.qrbox svg{display:block;margin:0 auto;max-width:100%;height:auto}

/* tables scroll inside their section on narrow screens */
table{display:block;max-width:100%;overflow-x:auto;border-collapse:collapse;font-size:13px}
th,td{text-align:start;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;white-space:nowrap;background:var(--surface-2)}
td.ltr{white-space:nowrap}
tbody tr:hover td{background:var(--surface-2)}

/* users: one collapsible row each */
details.user{border:1px solid var(--line);border-radius:var(--r);background:var(--surface);margin-bottom:8px}
details.user[open]{border-color:var(--line-2)}
details.user>summary{list-style:none;display:flex;align-items:center;gap:12px;padding:12px 14px;cursor:pointer;border-radius:var(--r)}
details.user>summary::-webkit-details-marker{display:none}
details.user>summary::after{content:"";width:8px;height:8px;border-inline-end:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);margin-inline-start:auto;flex:none;transition:transform .15s}
details.user[open]>summary::after{transform:rotate(-135deg)}
details.user>summary:hover{background:var(--surface-2)}
.u-main{display:flex;flex-direction:column;gap:2px;min-width:0;flex:1}
.u-line{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.u-line b{font-size:14.5px}
.u-usage{font-size:12px;color:var(--muted)}
.u-body{padding:2px 14px 14px;border-top:1px solid var(--line)}
.u-actions{display:flex;gap:8px;flex-wrap:wrap;padding:10px 0 2px}
details.u-sub{margin-top:10px}
details.u-sub>summary{cursor:pointer;color:var(--brand);font-size:13px;font-weight:600}

/* chart */
.chart{position:relative;display:flex;align-items:flex-end;gap:5px;height:150px;margin:6px 0 2px;padding-top:6px;border-bottom:1px solid var(--line-2);background:repeating-linear-gradient(to top,transparent 0,transparent 36px,var(--line) 36px,var(--line) 37px)}
.chart .col{flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;min-width:0}
.chart i{display:block;width:100%;background:var(--brand);border-radius:3px 3px 0 0;min-height:2px}
.chart .col:last-child i{background:var(--live)}
.days{display:flex;gap:5px;margin-bottom:2px}
.days span{flex:1;text-align:center;font-size:10.5px;color:var(--muted)}
.chart.mini{height:34px;gap:2px;margin:8px 0;padding-top:0;background:none}
.chart.mini i{border-radius:2px 2px 0 0}
.chart-meta{display:flex;justify-content:space-between;gap:8px;font-size:12.5px;color:var(--muted);margin-bottom:2px}

/* toast + login + boot */
#toast{position:fixed;inset-inline:0;bottom:22px;display:flex;justify-content:center;pointer-events:none;z-index:50;padding:0 14px}
#toast div{background:var(--ink);color:var(--bg);padding:9px 18px;border-radius:var(--r-sm);font-size:13.5px;font-weight:600;box-shadow:0 8px 24px rgba(0,0,0,.28);animation:tin .16s ease-out}
#toast div.bad{background:var(--bad);color:#fff}
@keyframes tin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.boot{display:flex;align-items:center;justify-content:center;gap:12px;min-height:60vh;color:var(--muted)}
.boot svg{width:34px;height:34px}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:30px 26px 26px;text-align:center}
.login svg{width:52px;height:52px;margin-bottom:14px}
.login h1{margin:0 0 4px;font-size:22px;font-weight:800;letter-spacing:-.015em}
.login p.sub{margin:0 0 22px;color:var(--muted);font-size:13.5px}
.login form{text-align:start}
.login .btn{width:100%;min-height:46px;font-size:15px}
.login .err{background:var(--bad-soft);color:var(--bad);border-radius:var(--r-sm);padding:8px 12px;font-size:13px;font-weight:600;margin:0 0 14px;text-align:center}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

const BRAND_MARK = '<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="9" fill="var(--brand)"/><path d="M9.5 23V9.5L22.5 23V9.5" fill="none" stroke="var(--brand-ink)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><circle cx="24.5" cy="7.5" r="2.5" fill="var(--live)"/></svg>';

function loginPage(msg) {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>${APP_NAME} | ورود</title><style>${STYLE}</style></head>
<body><div class="login-wrap"><div class="login">${BRAND_MARK}<h1>${APP_NAME}</h1><p class="sub">نام کاربری و رمز عبور را وارد کنید</p>
${msg ? `<p class="err" role="alert">${esc(msg)}</p>` : ''}
<form method="POST" action="/panel/login">
<input type="text" name="username" placeholder="نام کاربری" aria-label="نام کاربری" autocomplete="username" autofocus required>
<input type="password" name="password" placeholder="رمز عبور" aria-label="رمز عبور" autocomplete="current-password" required>
<button class="btn" type="submit">ورود</button></form></div></div></body></html>`;
}

// qrcode-generator 2.0.4 (MIT, Kazuhiko Arase), minified and embedded so QR codes work without any CDN.
const QR_LIB = "var qrcode=(function(){var P=function(x,w){var g=236,l=17,n=x,s=O[w],t=null,r=0,h=null,i=[],v={},_=function(a,f){r=n*4+17,t=(function(e){for(var u=new Array(e),o=0;o<e;o+=1){u[o]=new Array(e);for(var d=0;d<e;d+=1)u[o][d]=null}return u})(r),B(0,0),B(r-7,0),B(0,r-7),E(),T(),m(a,f),n>=7&&N(a),h==null&&(h=nr(n,s,i)),U(h,f)},B=function(a,f){for(var e=-1;e<=7;e+=1)if(!(a+e<=-1||r<=a+e))for(var u=-1;u<=7;u+=1)f+u<=-1||r<=f+u||(0<=e&&e<=6&&(u==0||u==6)||0<=u&&u<=6&&(e==0||e==6)||2<=e&&e<=4&&2<=u&&u<=4?t[a+e][f+u]=!0:t[a+e][f+u]=!1)},y=function(){for(var a=0,f=0,e=0;e<8;e+=1){_(!0,e);var u=k.getLostPoint(v);(e==0||a>u)&&(a=u,f=e)}return f},T=function(){for(var a=8;a<r-8;a+=1)t[a][6]==null&&(t[a][6]=a%2==0);for(var f=8;f<r-8;f+=1)t[6][f]==null&&(t[6][f]=f%2==0)},E=function(){for(var a=k.getPatternPosition(n),f=0;f<a.length;f+=1)for(var e=0;e<a.length;e+=1){var u=a[f],o=a[e];if(t[u][o]==null)for(var d=-2;d<=2;d+=1)for(var c=-2;c<=2;c+=1)d==-2||d==2||c==-2||c==2||d==0&&c==0?t[u+d][o+c]=!0:t[u+d][o+c]=!1}},N=function(a){for(var f=k.getBCHTypeNumber(n),e=0;e<18;e+=1){var u=!a&&(f>>e&1)==1;t[Math.floor(e/3)][e%3+r-8-3]=u}for(var e=0;e<18;e+=1){var u=!a&&(f>>e&1)==1;t[e%3+r-8-3][Math.floor(e/3)]=u}},m=function(a,f){for(var e=s<<3|f,u=k.getBCHTypeInfo(e),o=0;o<15;o+=1){var d=!a&&(u>>o&1)==1;o<6?t[o][8]=d:o<8?t[o+1][8]=d:t[r-15+o][8]=d}for(var o=0;o<15;o+=1){var d=!a&&(u>>o&1)==1;o<8?t[8][r-o-1]=d:o<9?t[8][15-o-1+1]=d:t[8][15-o-1]=d}t[r-8][8]=!a},U=function(a,f){for(var e=-1,u=r-1,o=7,d=0,c=k.getMaskFunction(f),p=r-1;p>0;p-=2)for(p==6&&(p-=1);;){for(var b=0;b<2;b+=1)if(t[u][p-b]==null){var C=!1;d<a.length&&(C=(a[d]>>>o&1)==1);var A=c(u,p-b);A&&(C=!C),t[u][p-b]=C,o-=1,o==-1&&(d+=1,o=7)}if(u+=e,u<0||r<=u){u-=e,e=-e;break}}},H=function(a,f){for(var e=0,u=0,o=0,d=new Array(f.length),c=new Array(f.length),p=0;p<f.length;p+=1){var b=f[p].dataCount,C=f[p].totalCount-b;u=Math.max(u,b),o=Math.max(o,C),d[p]=new Array(b);for(var A=0;A<d[p].length;A+=1)d[p][A]=255&a.getBuffer()[A+e];e+=b;var R=k.getErrorCorrectPolynomial(C),I=K(d[p],R.getLength()-1),S=I.mod(R);c[p]=new Array(R.getLength()-1);for(var A=0;A<c[p].length;A+=1){var X=A+S.getLength()-c[p].length;c[p][A]=X>=0?S.getAt(X):0}}for(var Z=0,A=0;A<f.length;A+=1)Z+=f[A].totalCount;for(var J=new Array(Z),Q=0,A=0;A<u;A+=1)for(var p=0;p<f.length;p+=1)A<d[p].length&&(J[Q]=d[p][A],Q+=1);for(var A=0;A<o;A+=1)for(var p=0;p<f.length;p+=1)A<c[p].length&&(J[Q]=c[p][A],Q+=1);return J},nr=function(a,f,e){for(var u=Y.getRSBlocks(a,f),o=G(),d=0;d<e.length;d+=1){var c=e[d];o.put(c.getMode(),4),o.put(c.getLength(),k.getLengthInBits(c.getMode(),a)),c.write(o)}for(var p=0,d=0;d<u.length;d+=1)p+=u[d].dataCount;if(o.getLengthInBits()>p*8)throw\"code length overflow. (\"+o.getLengthInBits()+\">\"+p*8+\")\";for(o.getLengthInBits()+4<=p*8&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=p*8||(o.put(g,8),o.getLengthInBits()>=p*8));)o.put(l,8);return H(o,u)};v.addData=function(a,f){f=f||\"Byte\";var e=null;switch(f){case\"Numeric\":e=$(a);break;case\"Alphanumeric\":e=W(a);break;case\"Byte\":e=V(a);break;case\"Kanji\":e=q(a);break;default:throw\"mode:\"+f}i.push(e),h=null},v.isDark=function(a,f){if(a<0||r<=a||f<0||r<=f)throw a+\",\"+f;return t[a][f]},v.getModuleCount=function(){return r},v.make=function(){if(n<1){for(var a=1;a<40;a++){for(var f=Y.getRSBlocks(a,s),e=G(),u=0;u<i.length;u++){var o=i[u];e.put(o.getMode(),4),e.put(o.getLength(),k.getLengthInBits(o.getMode(),a)),o.write(e)}for(var d=0,u=0;u<f.length;u++)d+=f[u].dataCount;if(e.getLengthInBits()<=d*8)break}n=a}_(!1,y())},v.createTableTag=function(a,f){a=a||2,f=typeof f>\"u\"?a*4:f;var e=\"\";e+='<table style=\"',e+=\" border-width: 0px; border-style: none;\",e+=\" border-collapse: collapse;\",e+=\" padding: 0px; margin: \"+f+\"px;\",e+='\">',e+=\"<tbody>\";for(var u=0;u<v.getModuleCount();u+=1){e+=\"<tr>\";for(var o=0;o<v.getModuleCount();o+=1)e+='<td style=\"',e+=\" border-width: 0px; border-style: none;\",e+=\" border-collapse: collapse;\",e+=\" padding: 0px; margin: 0px;\",e+=\" width: \"+a+\"px;\",e+=\" height: \"+a+\"px;\",e+=\" background-color: \",e+=v.isDark(u,o)?\"#000000\":\"#ffffff\",e+=\";\",e+='\"/>';e+=\"</tr>\"}return e+=\"</tbody>\",e+=\"</table>\",e},v.createSvgTag=function(a,f,e,u){var o={};typeof arguments[0]==\"object\"&&(o=arguments[0],a=o.cellSize,f=o.margin,e=o.alt,u=o.title),a=a||2,f=typeof f>\"u\"?a*4:f,e=typeof e==\"string\"?{text:e}:e||{},e.text=e.text||null,e.id=e.text?e.id||\"qrcode-description\":null,u=typeof u==\"string\"?{text:u}:u||{},u.text=u.text||null,u.id=u.text?u.id||\"qrcode-title\":null;var d=v.getModuleCount()*a+f*2,c,p,b,C,A=\"\",R;for(R=\"l\"+a+\",0 0,\"+a+\" -\"+a+\",0 0,-\"+a+\"z \",A+='<svg version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\"',A+=o.scalable?\"\":' width=\"'+d+'px\" height=\"'+d+'px\"',A+=' viewBox=\"0 0 '+d+\" \"+d+'\" ',A+=' preserveAspectRatio=\"xMinYMin meet\"',A+=u.text||e.text?' role=\"img\" aria-labelledby=\"'+F([u.id,e.id].join(\" \").trim())+'\"':\"\",A+=\">\",A+=u.text?'<title id=\"'+F(u.id)+'\">'+F(u.text)+\"</title>\":\"\",A+=e.text?'<description id=\"'+F(e.id)+'\">'+F(e.text)+\"</description>\":\"\",A+='<rect width=\"100%\" height=\"100%\" fill=\"white\" cx=\"0\" cy=\"0\"/>',A+='<path d=\"',b=0;b<v.getModuleCount();b+=1)for(C=b*a+f,c=0;c<v.getModuleCount();c+=1)v.isDark(b,c)&&(p=c*a+f,A+=\"M\"+p+\",\"+C+R);return A+='\" stroke=\"transparent\" fill=\"black\"/>',A+=\"</svg>\",A},v.createDataURL=function(a,f){a=a||2,f=typeof f>\"u\"?a*4:f;var e=v.getModuleCount()*a+f*2,u=f,o=e-f;return er(e,e,function(d,c){if(u<=d&&d<o&&u<=c&&c<o){var p=Math.floor((d-u)/a),b=Math.floor((c-u)/a);return v.isDark(b,p)?0:1}else return 1})},v.createImgTag=function(a,f,e){a=a||2,f=typeof f>\"u\"?a*4:f;var u=v.getModuleCount()*a+f*2,o=\"\";return o+=\"<img\",o+=' src=\"',o+=v.createDataURL(a,f),o+='\"',o+=' width=\"',o+=u,o+='\"',o+=' height=\"',o+=u,o+='\"',e&&(o+=' alt=\"',o+=F(e),o+='\"'),o+=\"/>\",o};var F=function(a){for(var f=\"\",e=0;e<a.length;e+=1){var u=a.charAt(e);switch(u){case\"<\":f+=\"&lt;\";break;case\">\":f+=\"&gt;\";break;case\"&\":f+=\"&amp;\";break;case'\"':f+=\"&quot;\";break;default:f+=u;break}}return f},ar=function(a){var f=1;a=typeof a>\"u\"?f*2:a;var e=v.getModuleCount()*f+a*2,u=a,o=e-a,d,c,p,b,C,A={\"\\u2588\\u2588\":\"\\u2588\",\"\\u2588 \":\"\\u2580\",\" \\u2588\":\"\\u2584\",\"  \":\" \"},R={\"\\u2588\\u2588\":\"\\u2580\",\"\\u2588 \":\"\\u2580\",\" \\u2588\":\" \",\"  \":\" \"},I=\"\";for(d=0;d<e;d+=2){for(p=Math.floor((d-u)/f),b=Math.floor((d+1-u)/f),c=0;c<e;c+=1)C=\"\\u2588\",u<=c&&c<o&&u<=d&&d<o&&v.isDark(p,Math.floor((c-u)/f))&&(C=\" \"),u<=c&&c<o&&u<=d+1&&d+1<o&&v.isDark(b,Math.floor((c-u)/f))?C+=\" \":C+=\"\\u2588\",I+=a<1&&d+1>=o?R[C]:A[C];I+=`\n`}return e%2&&a>0?I.substring(0,I.length-e-1)+Array(e+1).join(\"\\u2580\"):I.substring(0,I.length-1)};return v.createASCII=function(a,f){if(a=a||1,a<2)return ar(f);a-=1,f=typeof f>\"u\"?a*2:f;var e=v.getModuleCount()*a+f*2,u=f,o=e-f,d,c,p,b,C=Array(a+1).join(\"\\u2588\\u2588\"),A=Array(a+1).join(\"  \"),R=\"\",I=\"\";for(d=0;d<e;d+=1){for(p=Math.floor((d-u)/a),I=\"\",c=0;c<e;c+=1)b=1,u<=c&&c<o&&u<=d&&d<o&&v.isDark(p,Math.floor((c-u)/a))&&(b=0),I+=b?C:A;for(p=0;p<a;p+=1)R+=I+`\n`}return R.substring(0,R.length-1)},v.renderTo2dContext=function(a,f){f=f||2;for(var e=v.getModuleCount(),u=0;u<e;u++)for(var o=0;o<e;o++)a.fillStyle=v.isDark(u,o)?\"black\":\"white\",a.fillRect(o*f,u*f,f,f)},v};P.stringToBytesFuncs={default:function(x){for(var w=[],g=0;g<x.length;g+=1){var l=x.charCodeAt(g);w.push(l&255)}return w}},P.stringToBytes=P.stringToBytesFuncs.default,P.createStringToBytes=function(x,w){var g=(function(){for(var n=rr(x),s=function(){var T=n.read();if(T==-1)throw\"eof\";return T},t=0,r={};;){var h=n.read();if(h==-1)break;var i=s(),v=s(),_=s(),B=String.fromCharCode(h<<8|i),y=v<<8|_;r[B]=y,t+=1}if(t!=w)throw t+\" != \"+w;return r})(),l=63;return function(n){for(var s=[],t=0;t<n.length;t+=1){var r=n.charCodeAt(t);if(r<128)s.push(r);else{var h=g[n.charAt(t)];typeof h==\"number\"?(h&255)==h?s.push(h):(s.push(h>>>8),s.push(h&255)):s.push(l)}}return s}};var D={MODE_NUMBER:1,MODE_ALPHA_NUM:2,MODE_8BIT_BYTE:4,MODE_KANJI:8},O={L:1,M:0,Q:3,H:2},L={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7},k=(function(){var x=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],w=1335,g=7973,l=21522,n={},s=function(t){for(var r=0;t!=0;)r+=1,t>>>=1;return r};return n.getBCHTypeInfo=function(t){for(var r=t<<10;s(r)-s(w)>=0;)r^=w<<s(r)-s(w);return(t<<10|r)^l},n.getBCHTypeNumber=function(t){for(var r=t<<12;s(r)-s(g)>=0;)r^=g<<s(r)-s(g);return t<<12|r},n.getPatternPosition=function(t){return x[t-1]},n.getMaskFunction=function(t){switch(t){case L.PATTERN000:return function(r,h){return(r+h)%2==0};case L.PATTERN001:return function(r,h){return r%2==0};case L.PATTERN010:return function(r,h){return h%3==0};case L.PATTERN011:return function(r,h){return(r+h)%3==0};case L.PATTERN100:return function(r,h){return(Math.floor(r/2)+Math.floor(h/3))%2==0};case L.PATTERN101:return function(r,h){return r*h%2+r*h%3==0};case L.PATTERN110:return function(r,h){return(r*h%2+r*h%3)%2==0};case L.PATTERN111:return function(r,h){return(r*h%3+(r+h)%2)%2==0};default:throw\"bad maskPattern:\"+t}},n.getErrorCorrectPolynomial=function(t){for(var r=K([1],0),h=0;h<t;h+=1)r=r.multiply(K([1,M.gexp(h)],0));return r},n.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case D.MODE_NUMBER:return 10;case D.MODE_ALPHA_NUM:return 9;case D.MODE_8BIT_BYTE:return 8;case D.MODE_KANJI:return 8;default:throw\"mode:\"+t}else if(r<27)switch(t){case D.MODE_NUMBER:return 12;case D.MODE_ALPHA_NUM:return 11;case D.MODE_8BIT_BYTE:return 16;case D.MODE_KANJI:return 10;default:throw\"mode:\"+t}else if(r<41)switch(t){case D.MODE_NUMBER:return 14;case D.MODE_ALPHA_NUM:return 13;case D.MODE_8BIT_BYTE:return 16;case D.MODE_KANJI:return 12;default:throw\"mode:\"+t}else throw\"type:\"+r},n.getLostPoint=function(t){for(var r=t.getModuleCount(),h=0,i=0;i<r;i+=1)for(var v=0;v<r;v+=1){for(var _=0,B=t.isDark(i,v),y=-1;y<=1;y+=1)if(!(i+y<0||r<=i+y))for(var T=-1;T<=1;T+=1)v+T<0||r<=v+T||y==0&&T==0||B==t.isDark(i+y,v+T)&&(_+=1);_>5&&(h+=3+_-5)}for(var i=0;i<r-1;i+=1)for(var v=0;v<r-1;v+=1){var E=0;t.isDark(i,v)&&(E+=1),t.isDark(i+1,v)&&(E+=1),t.isDark(i,v+1)&&(E+=1),t.isDark(i+1,v+1)&&(E+=1),(E==0||E==4)&&(h+=3)}for(var i=0;i<r;i+=1)for(var v=0;v<r-6;v+=1)t.isDark(i,v)&&!t.isDark(i,v+1)&&t.isDark(i,v+2)&&t.isDark(i,v+3)&&t.isDark(i,v+4)&&!t.isDark(i,v+5)&&t.isDark(i,v+6)&&(h+=40);for(var v=0;v<r;v+=1)for(var i=0;i<r-6;i+=1)t.isDark(i,v)&&!t.isDark(i+1,v)&&t.isDark(i+2,v)&&t.isDark(i+3,v)&&t.isDark(i+4,v)&&!t.isDark(i+5,v)&&t.isDark(i+6,v)&&(h+=40);for(var N=0,v=0;v<r;v+=1)for(var i=0;i<r;i+=1)t.isDark(i,v)&&(N+=1);var m=Math.abs(100*N/r/r-50)/5;return h+=m*10,h},n})(),M=(function(){for(var x=new Array(256),w=new Array(256),g=0;g<8;g+=1)x[g]=1<<g;for(var g=8;g<256;g+=1)x[g]=x[g-4]^x[g-5]^x[g-6]^x[g-8];for(var g=0;g<255;g+=1)w[x[g]]=g;var l={};return l.glog=function(n){if(n<1)throw\"glog(\"+n+\")\";return w[n]},l.gexp=function(n){for(;n<0;)n+=255;for(;n>=256;)n-=255;return x[n]},l})();function K(x,w){if(typeof x.length>\"u\")throw x.length+\"/\"+w;var g=(function(){for(var n=0;n<x.length&&x[n]==0;)n+=1;for(var s=new Array(x.length-n+w),t=0;t<x.length-n;t+=1)s[t]=x[t+n];return s})(),l={};return l.getAt=function(n){return g[n]},l.getLength=function(){return g.length},l.multiply=function(n){for(var s=new Array(l.getLength()+n.getLength()-1),t=0;t<l.getLength();t+=1)for(var r=0;r<n.getLength();r+=1)s[t+r]^=M.gexp(M.glog(l.getAt(t))+M.glog(n.getAt(r)));return K(s,0)},l.mod=function(n){if(l.getLength()-n.getLength()<0)return l;for(var s=M.glog(l.getAt(0))-M.glog(n.getAt(0)),t=new Array(l.getLength()),r=0;r<l.getLength();r+=1)t[r]=l.getAt(r);for(var r=0;r<n.getLength();r+=1)t[r]^=M.gexp(M.glog(n.getAt(r))+s);return K(t,0).mod(n)},l}var Y=(function(){var x=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],w=function(n,s){var t={};return t.totalCount=n,t.dataCount=s,t},g={},l=function(n,s){switch(s){case O.L:return x[(n-1)*4+0];case O.M:return x[(n-1)*4+1];case O.Q:return x[(n-1)*4+2];case O.H:return x[(n-1)*4+3];default:return}};return g.getRSBlocks=function(n,s){var t=l(n,s);if(typeof t>\"u\")throw\"bad rs block @ typeNumber:\"+n+\"/errorCorrectionLevel:\"+s;for(var r=t.length/3,h=[],i=0;i<r;i+=1)for(var v=t[i*3+0],_=t[i*3+1],B=t[i*3+2],y=0;y<v;y+=1)h.push(w(_,B));return h},g})(),G=function(){var x=[],w=0,g={};return g.getBuffer=function(){return x},g.getAt=function(l){var n=Math.floor(l/8);return(x[n]>>>7-l%8&1)==1},g.put=function(l,n){for(var s=0;s<n;s+=1)g.putBit((l>>>n-s-1&1)==1)},g.getLengthInBits=function(){return w},g.putBit=function(l){var n=Math.floor(w/8);x.length<=n&&x.push(0),l&&(x[n]|=128>>>w%8),w+=1},g},$=function(x){var w=D.MODE_NUMBER,g=x,l={};l.getMode=function(){return w},l.getLength=function(t){return g.length},l.write=function(t){for(var r=g,h=0;h+2<r.length;)t.put(n(r.substring(h,h+3)),10),h+=3;h<r.length&&(r.length-h==1?t.put(n(r.substring(h,h+1)),4):r.length-h==2&&t.put(n(r.substring(h,h+2)),7))};var n=function(t){for(var r=0,h=0;h<t.length;h+=1)r=r*10+s(t.charAt(h));return r},s=function(t){if(\"0\"<=t&&t<=\"9\")return t.charCodeAt(0)-48;throw\"illegal char :\"+t};return l},W=function(x){var w=D.MODE_ALPHA_NUM,g=x,l={};l.getMode=function(){return w},l.getLength=function(s){return g.length},l.write=function(s){for(var t=g,r=0;r+1<t.length;)s.put(n(t.charAt(r))*45+n(t.charAt(r+1)),11),r+=2;r<t.length&&s.put(n(t.charAt(r)),6)};var n=function(s){if(\"0\"<=s&&s<=\"9\")return s.charCodeAt(0)-48;if(\"A\"<=s&&s<=\"Z\")return s.charCodeAt(0)-65+10;switch(s){case\" \":return 36;case\"$\":return 37;case\"%\":return 38;case\"*\":return 39;case\"+\":return 40;case\"-\":return 41;case\".\":return 42;case\"/\":return 43;case\":\":return 44;default:throw\"illegal char :\"+s}};return l},V=function(x){var w=D.MODE_8BIT_BYTE,g=x,l=P.stringToBytes(x),n={};return n.getMode=function(){return w},n.getLength=function(s){return l.length},n.write=function(s){for(var t=0;t<l.length;t+=1)s.put(l[t],8)},n},q=function(x){var w=D.MODE_KANJI,g=x,l=P.stringToBytesFuncs.SJIS;if(!l)throw\"sjis not supported.\";(function(t,r){var h=l(t);if(h.length!=2||(h[0]<<8|h[1])!=r)throw\"sjis not supported.\"})(\"\\u53CB\",38726);var n=l(x),s={};return s.getMode=function(){return w},s.getLength=function(t){return~~(n.length/2)},s.write=function(t){for(var r=n,h=0;h+1<r.length;){var i=(255&r[h])<<8|255&r[h+1];if(33088<=i&&i<=40956)i-=33088;else if(57408<=i&&i<=60351)i-=49472;else throw\"illegal char at \"+(h+1)+\"/\"+i;i=(i>>>8&255)*192+(i&255),t.put(i,13),h+=2}if(h<r.length)throw\"illegal char at \"+(h+1)},s},j=function(){var x=[],w={};return w.writeByte=function(g){x.push(g&255)},w.writeShort=function(g){w.writeByte(g),w.writeByte(g>>>8)},w.writeBytes=function(g,l,n){l=l||0,n=n||g.length;for(var s=0;s<n;s+=1)w.writeByte(g[s+l])},w.writeString=function(g){for(var l=0;l<g.length;l+=1)w.writeByte(g.charCodeAt(l))},w.toByteArray=function(){return x},w.toString=function(){var g=\"\";g+=\"[\";for(var l=0;l<x.length;l+=1)l>0&&(g+=\",\"),g+=x[l];return g+=\"]\",g},w},z=function(){var x=0,w=0,g=0,l=\"\",n={},s=function(r){l+=String.fromCharCode(t(r&63))},t=function(r){if(!(r<0)){if(r<26)return 65+r;if(r<52)return 97+(r-26);if(r<62)return 48+(r-52);if(r==62)return 43;if(r==63)return 47}throw\"n:\"+r};return n.writeByte=function(r){for(x=x<<8|r&255,w+=8,g+=1;w>=6;)s(x>>>w-6),w-=6},n.flush=function(){if(w>0&&(s(x<<6-w),x=0,w=0),g%3!=0)for(var r=3-g%3,h=0;h<r;h+=1)l+=\"=\"},n.toString=function(){return l},n},rr=function(x){var w=x,g=0,l=0,n=0,s={};s.read=function(){for(;n<8;){if(g>=w.length){if(n==0)return-1;throw\"unexpected end of file./\"+n}var r=w.charAt(g);if(g+=1,r==\"=\")return n=0,-1;if(r.match(/^\\s$/))continue;l=l<<6|t(r.charCodeAt(0)),n+=6}var h=l>>>n-8&255;return n-=8,h};var t=function(r){if(65<=r&&r<=90)return r-65;if(97<=r&&r<=122)return r-97+26;if(48<=r&&r<=57)return r-48+52;if(r==43)return 62;if(r==47)return 63;throw\"c:\"+r};return s},tr=function(x,w){var g=x,l=w,n=new Array(x*w),s={};s.setPixel=function(i,v,_){n[v*g+i]=_},s.write=function(i){i.writeString(\"GIF87a\"),i.writeShort(g),i.writeShort(l),i.writeByte(128),i.writeByte(0),i.writeByte(0),i.writeByte(0),i.writeByte(0),i.writeByte(0),i.writeByte(255),i.writeByte(255),i.writeByte(255),i.writeString(\",\"),i.writeShort(0),i.writeShort(0),i.writeShort(g),i.writeShort(l),i.writeByte(0);var v=2,_=r(v);i.writeByte(v);for(var B=0;_.length-B>255;)i.writeByte(255),i.writeBytes(_,B,255),B+=255;i.writeByte(_.length-B),i.writeBytes(_,B,_.length-B),i.writeByte(0),i.writeString(\";\")};var t=function(i){var v=i,_=0,B=0,y={};return y.write=function(T,E){if(T>>>E)throw\"length over\";for(;_+E>=8;)v.writeByte(255&(T<<_|B)),E-=8-_,T>>>=8-_,B=0,_=0;B=T<<_|B,_=_+E},y.flush=function(){_>0&&v.writeByte(B)},y},r=function(i){for(var v=1<<i,_=(1<<i)+1,B=i+1,y=h(),T=0;T<v;T+=1)y.add(String.fromCharCode(T));y.add(String.fromCharCode(v)),y.add(String.fromCharCode(_));var E=j(),N=t(E);N.write(v,B);var m=0,U=String.fromCharCode(n[m]);for(m+=1;m<n.length;){var H=String.fromCharCode(n[m]);m+=1,y.contains(U+H)?U=U+H:(N.write(y.indexOf(U),B),y.size()<4095&&(y.size()==1<<B&&(B+=1),y.add(U+H)),U=H)}return N.write(y.indexOf(U),B),N.write(_,B),N.flush(),E.toByteArray()},h=function(){var i={},v=0,_={};return _.add=function(B){if(_.contains(B))throw\"dup key:\"+B;i[B]=v,v+=1},_.size=function(){return v},_.indexOf=function(B){return i[B]},_.contains=function(B){return typeof i[B]<\"u\"},_};return s},er=function(x,w,g){for(var l=tr(x,w),n=0;n<w;n+=1)for(var s=0;s<x;s+=1)l.setPixel(s,n,g(s,n));var t=j();l.write(t);for(var r=z(),h=t.toByteArray(),i=0;i<h.length;i+=1)r.writeByte(h[i]);return r.flush(),\"data:image/gif;base64,\"+r};return P})();(function(){qrcode.stringToBytesFuncs[\"UTF-8\"]=function(P){function D(O){for(var L=[],k=0;k<O.length;k++){var M=O.charCodeAt(k);M<128?L.push(M):M<2048?L.push(192|M>>6,128|M&63):M<55296||M>=57344?L.push(224|M>>12,128|M>>6&63,128|M&63):(k++,M=65536+((M&1023)<<10|O.charCodeAt(k)&1023),L.push(240|M>>18,128|M>>12&63,128|M>>6&63,128|M&63))}return L}return D(P)}})(),(function(P){typeof define==\"function\"&&define.amd?define([],P):typeof exports==\"object\"&&(module.exports=P())})(function(){return qrcode});";

function panelPage() {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>${APP_NAME}</title><style>${STYLE}</style></head>
<body><div id="app"><div class="boot">${BRAND_MARK}<span>در حال بارگذاری…</span></div></div><div id="toast" role="status" aria-live="polite"></div>
<script>${QR_LIB}</script>
<script>var __name=function(t){return t};(${clientMain.toString()})();</script></body></html>`;
}

// Runs in the browser (serialised into the page via toString)
function clientMain() {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let S = null, tab = 'overview', testRes = null, testing = false, testHost = 'chatgpt.com';
  const SITE_LABELS = { 'chatgpt.com': 'ChatGPT', 'openai.com': 'OpenAI', 'claude.ai': 'Claude', 'anthropic.com': 'Anthropic', 'gemini.google.com': 'Gemini', 'google.com': 'Google', 'youtube.com': 'YouTube', 'instagram.com': 'Instagram', 'x.com': 'X', 'telegram.org': 'Telegram', other: 'سایر' };
  let srcRes = null, srcChecking = false;
  let qt = { op: 'mci', extra: '', running: false, stop: false, done: 0, total: 0, results: [] };
  let subSel = { format: 'base64', op: '' };

  async function api(path, body) {
    const opt = body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
    const r = await fetch('/panel/api/' + path, opt);
    if (r.status === 401) { location.reload(); throw new Error('نشست منقضی شد'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'خطا ' + r.status);
    return j;
  }

  let toastTimer = null;
  function toast(msg, bad) {
    const el = $('#toast');
    el.innerHTML = '<div class="' + (bad ? 'bad' : '') + '">' + esc(msg) + '</div>';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.innerHTML = ''; }, 2600);
  }

  async function doAct(path, body, okMsg) {
    try {
      const j = await api(path, body);
      if (j.state) S = j.state;
      toast(okMsg || 'انجام شد');
      render();
    } catch (e) { toast(e.message, true); }
  }

  function copy(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(() => toast('کپی شد'), () => window.prompt('کپی کنید:', t));
    } else { window.prompt('کپی کنید:', t); }
  }

  const ICONS = {
    overview: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.6-3.6 3.2-5.5 6.5-5.5s5.9 1.9 6.5 5.5"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18.5 14.8c1.7.7 2.8 2.3 3 5.2"/>',
    proxy: '<circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="6" r="2.5"/><path d="M8.5 18H15a3.5 3.5 0 0 0 0-7H9a3.5 3.5 0 0 1 0-7h6.5"/>',
    sub: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3A4 4 0 0 0 11 18.7l1-1"/>',
    quality: '<path d="M3 12h4l2.5-7 5 14 2.5-7h4"/>',
    tools: '<circle cx="12" cy="12" r="8.5"/><path d="M12 3.5V7M12 17v3.5M3.5 12H7M17 12h3.5"/><circle cx="12" cy="12" r="1.5"/>',
    settings: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>',
    theme: '<circle cx="12" cy="12" r="8.5"/><path d="M12 3.5a8.5 8.5 0 0 1 0 17z" fill="currentColor"/>',
    logout: '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M10 8l-4 4 4 4M6 12h10"/>',
  };
  const ic = (n) => '<svg class="ic" viewBox="0 0 24 24" aria-hidden="true">' + ICONS[n] + '</svg>';
  const MARK = '<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="9" fill="var(--brand)"/><path d="M9.5 23V9.5L22.5 23V9.5" fill="none" stroke="var(--brand-ink)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><circle cx="24.5" cy="7.5" r="2.5" fill="var(--live)"/></svg>';
  const openUsers = new Set();
  let renderedTab = null;

  function applyTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
    else document.documentElement.removeAttribute('data-theme');
    try { localStorage.setItem('np-theme', t); } catch (_) {}
  }
  function cycleTheme() {
    const cur = document.documentElement.getAttribute('data-theme') || 'auto';
    const next = cur === 'auto' ? 'light' : cur === 'light' ? 'dark' : 'auto';
    applyTheme(next);
    toast(next === 'auto' ? 'تم: مطابق دستگاه' : next === 'light' ? 'تم: روشن' : 'تم: تیره');
  }
  try { const t = localStorage.getItem('np-theme'); if (t) applyTheme(t); } catch (_) {}

  const modeLabel = { auto: 'خودکار', custom: 'فقط لیست دستی', off: 'غیرفعال' };

  function routeStrip() {
    const relay = S.proxyMode === 'off' ? 'بدون رله' : 'رله‌ی ProxyIP';
    return '<div class="route" aria-label="مسیر ترافیک">' +
      '<div class="node"><small>دستگاه شما</small>کلاینت</div><span class="arrow">←</span>' +
      '<div class="node hot"><small>دیتاسنتر ' + esc(S.colo || '؟') + '</small>Worker</div><span class="arrow">←</span>' +
      '<div class="node"><small>اول</small>مستقیم</div><span class="arrow">/</span>' +
      '<div class="node"><small>اگر نشد</small>' + esc(relay) + '</div><span class="arrow">←</span>' +
      '<div class="node"><small>مقصد</small>سایت</div></div>';
  }

  // QR codes: the qrcode-generator library (MIT) is embedded in the page, no network needed.
  function loadQr() {
    return window.qrcode ? Promise.resolve() : Promise.reject(new Error('کتابخانه‌ی بارکد در دسترس نیست'));
  }

  async function toggleQr(btn) {
    const blk = btn.closest('.linkblk') || btn.closest('.card');
    const box = blk && blk.querySelector('.qrbox');
    if (!box) return;
    if (!box.hidden) { box.hidden = true; return; }
    try {
      await loadQr();
      const qr = window.qrcode(0, 'M');
      qr.addData(btn.dataset.text);
      qr.make();
      box.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 4 }) +
        '<p class="note">این بارکد را با برنامه‌ی کلاینت (مثلاً v2rayNG) اسکن کنید.</p>';
      box.hidden = false;
    } catch (e) { toast(e.message || 'خطا در ساخت بارکد', true); }
  }

  function sourcesBlock() {
    if (srcChecking) return '<p class="note">در حال بررسی منابع…</p>';
    if (!srcRes) return '<p class="note">قبل از بررسی، تنظیمات را ذخیره کنید؛ بررسی روی آدرس‌های ذخیره‌شده انجام می‌شود.</p>';
    const okCount = srcRes.sources.filter((x) => x.ok).length;
    return '<div class="verdict">' + okCount + ' از ' + srcRes.sources.length + ' منبع جواب دادند؛ در مجموع ' + srcRes.total + ' آی‌پی یکتا پیدا شد.</div>' +
      '<table><tr><th>منبع</th><th>وضعیت</th><th>تعداد</th><th>زمان</th></tr>' +
      srcRes.sources.map((x) => '<tr><td class="ltr">' + esc(x.url) + '</td><td>' +
        (x.ok ? '<span class="ok">✔ سالم</span>' : '<span class="bad">✖ ' + esc(x.error || 'ناموفق') + '</span>') +
        '</td><td>' + x.count + '</td><td>' + x.ms + ' ms</td></tr>').join('') + '</table>';
  }

  const GB = 1073741824;
  function fmtBytes(b) { return b >= GB ? (b / GB).toFixed(2) + ' GB' : (b / 1048576).toFixed(b >= 10485760 ? 0 : 1) + ' MB'; }

  function statusBadge(u) {
    if (u.status === 'disabled') return '<span class="badge bad">غیرفعال</span>';
    if (u.status === 'expired') return '<span class="badge bad">منقضی‌شده</span>';
    if (u.status === 'quota') return '<span class="badge bad">اتمام حجم</span>';
    if (u.warn === 'quota') return '<span class="badge warn">نزدیک اتمام حجم</span>';
    if (u.warn === 'expiry') return '<span class="badge warn">انقضا نزدیک است</span>';
    if (u.pendingStart) return '<span class="badge warn">منتظر اولین اتصال</span>';
    return '<span class="badge ok">فعال</span>';
  }

  function chartHtml(days) {
    const max = Math.max(1, ...days.map((x) => x.bytes));
    const total = days.reduce((n, x) => n + x.bytes, 0);
    const today = days[days.length - 1];
    return '<div class="chart-meta"><span>جمع ۱۴ روز: <b>' + fmtBytes(total) + '</b></span><span>امروز: <b>' + fmtBytes(today.bytes) + '</b></span></div>' +
      '<div class="chart" role="img" aria-label="نمودار مصرف ۱۴ روز اخیر">' + days.map((x) =>
        '<div class="col" title="' + esc(x.d + ' : ' + fmtBytes(x.bytes)) + '"><i style="height:' + Math.round((x.bytes / max) * 100) + '%"></i></div>').join('') + '</div>' +
      '<div class="days">' + days.map((x) => '<span>' + esc(x.d.slice(8)) + '</span>').join('') + '</div>';
  }

  function subLink(op, format) {
    const q = [];
    if (format && format !== 'base64') q.push('format=' + format);
    if (op) q.push('op=' + op);
    return S.subUrl + (q.length ? '?' + q.join('&') : '');
  }

  function subFormatCard() {
    const fmts = [['base64', 'V2Ray / v2rayNG / Nekoray (Base64)'], ['clash', 'Clash Meta / Mihomo'], ['singbox', 'sing-box / Hiddify']];
    const url = subLink(subSel.op, subSel.format);
    return '<section class="card"><h3>لینک اشتراک بر اساس فرمت و اپراتور</h3>' +
      '<div class="fields"><div class="field"><label>فرمت</label><select id="sfmt">' + fmts.map((f) => '<option value="' + f[0] + '"' + (subSel.format === f[0] ? ' selected' : '') + '>' + esc(f[1]) + '</option>').join('') + '</select></div>' +
      '<div class="field"><label>اپراتور</label><select id="sop"><option value="">همه (لیست عمومی)</option>' +
      Object.keys(S.operators).map((k) => '<option value="' + esc(k) + '"' + (subSel.op === k ? ' selected' : '') + '>' + esc(S.operators[k]) + ' (' + ((S.healthy[k] || []).length) + ' آی‌پی تأییدشده)</option>').join('') + '</select></div></div>' +
      '<div class="linkblk"><code class="blk">' + esc(url) + '</code>' +
      '<button class="btn sm" data-copy="' + esc(url) + '">کپی</button> <button class="btn sm ghost" data-act="qr" data-text="' + esc(url) + '">بارکد</button><div class="qrbox" hidden></div></div>' +
      '<p class="note">اگر برای اپراتور انتخاب‌شده آی‌پی تأییدشده‌ای نباشد (تب «کیفیت آی‌پی»)، همان لیست عمومی داده می‌شود. لینک اختصاصی هر کاربر (با نمایش حجم و انقضا در کلاینت) در تب «کاربران» است.</p></section>';
  }

  function kvCard() {
    const days = S.kv.days;
    const today = days.length ? days[days.length - 1] : { d: '', w: 0, r: 0, q: 0 };
    const wp = Math.min(100, (today.w / S.kv.freeWrites) * 100), rp = Math.min(100, (today.r / S.kv.freeReads) * 100), qp = Math.min(100, (today.q / S.kv.freeRequests) * 100);
    const cls = (p) => (p >= 90 ? ' bad' : p >= 60 ? ' warn' : '');
    const rows = days.slice().reverse().map((x) => '<tr><td class="ltr">' + esc(x.d) + '</td><td>' + x.q + '</td><td>' + x.w + '</td><td>' + x.r + '</td></tr>').join('');
    const fm = S.flushChoices.map((m) => '<option value="' + m + '"' + (S.flushMin === m ? ' selected' : '') + '>هر ' + m + ' دقیقه</option>').join('');
    return '<section class="card"><h3>مصرف ' + S.kv.backend + '</h3>' +
      '<p class="note" style="margin-top:0">پلن رایگان Workers روزی ' + S.kv.freeRequests + ' درخواست می‌دهد؛ هر اتصال VPN، باز شدن پنل یا گرفتن اشتراک یک درخواست است (نه هر بایت)، پس برای چند کاربر کافی است. نوشتن در ' + S.kv.backend + ' سقف روزانه دارد (پلن رایگان: ' + S.kv.freeWrites + ' نوشتن و ' + S.kv.freeReads + ' خواندن در روز). مصرف کاربران و آمار دیتاسنتر در حافظه جمع می‌شود و طبق فاصله‌ی زیر یک‌جا نوشته می‌شود؛ هر چه روز پرمصرف‌تر باشد فاصله خودکار بیشتر می‌شود.</p>' +
      '<div class="row"><span>درخواست امروز</span><b>' + today.q + ' از ' + S.kv.freeRequests + '</b></div><div class="bar' + cls(qp) + '"><div style="width:' + qp.toFixed(1) + '%"></div></div>' +
      '<div class="row"><span>نوشتن امروز</span><b>' + today.w + ' از ' + S.kv.freeWrites + '</b></div><div class="bar' + cls(wp) + '"><div style="width:' + wp.toFixed(1) + '%"></div></div>' +
      '<div class="row"><span>خواندن امروز</span><b>' + today.r + ' از ' + S.kv.freeReads + '</b></div><div class="bar' + cls(rp) + '"><div style="width:' + rp.toFixed(1) + '%"></div></div>' +
      (rows ? '<table><tr><th>روز (UTC+3:30)</th><th>درخواست</th><th>نوشتن</th><th>خواندن</th></tr>' + rows + '</table>' : '<p class="note">هنوز داده‌ای ثبت نشده.</p>') +
      '<p class="note">فقط عملیات خود همین Worker شمرده می‌شود و عدد تقریبی است. عدد دقیق در داشبورد کلودفلر: Storage &amp; Databases ← ' + (S.kv.backend === 'D1' ? 'D1 SQL database' : 'KV') + ' ← Metrics. شمارنده‌ها با هر ذخیره‌ی مصرف به‌روز می‌شوند.</p>' +
      '<div class="fields"><div class="field"><label>فاصله‌ی ذخیره‌ی مصرف</label><select id="s-flush">' + fm + '</select></div></div>' +
      '<button class="btn" data-act="settings-save">ذخیره</button>' +
      '<p class="note warn">فاصله‌ی بیشتر یعنی نوشتن کمتر، ولی: (۱) عدد مصرف و اعمال سقف حجم تا همین فاصله دیرتر به‌روز می‌شود و ممکن است کمی از سقف رد شود، (۲) اگر Worker بین دو ذخیره ری‌استارت شود، مصرف آن بازه از دست می‌رود. اگر باز هم به سقف می‌خورید، پلن Workers Paid (حدود ۵ دلار در ماه) سقف نوشتن را به میلیون‌ها می‌رساند.</p></section>';
  }

  function coloStatsCard() {
    const cs = S.stats.colos;
    const since = new Date(S.stats.since).toISOString().slice(0, 10);
    if (!cs.length) {
      return '<section class="card"><h3>آمار به تفکیک دیتاسنتر</h3><p class="note">هنوز اتصالی ثبت نشده. بعد از چند دقیقه استفاده‌ی واقعی اینجا پر می‌شود.</p></section>';
    }
    const rows = cs.map((c) => {
      const done = c.ok + c.fail;
      const pct = done ? Math.round((c.ok / done) * 100) : 0;
      const sites = c.hosts.filter((h) => h.name !== 'other').map((h) => {
        const bad = h.fail > h.ok;
        return '<span class="badge ' + (bad ? 'bad' : (h.fail ? 'warn' : 'ok')) + '">' + esc(SITE_LABELS[h.name] || h.name) + ' ' + h.ok + '✔ ' + h.fail + '✖</span> ';
      }).join('');
      return '<tr><td class="ltr">' + esc(c.colo) + '</td><td>' + c.conns + '</td><td class="' + (pct < 70 ? 'bad' : 'ok') + '">' + pct + '٪</td><td>' + c.relay + '</td><td>' + (sites || '—') +
        (c.lastErr ? '<br><small class="note">آخرین خطا: ' + esc(c.lastErr) + '</small>' : '') + '</td></tr>';
    }).join('');
    return '<section class="card"><h3>آمار به تفکیک دیتاسنتر</h3>' +
      '<p class="note">هر آی‌پی تمیز ممکن است شما را به یک دیتاسنتر کلودفلر برساند و رله‌ها هم بر اساس همان دیتاسنتر انتخاب می‌شوند؛ برای همین «بعضی آی‌پی‌ها» با ChatGPT و Claude کار می‌کنند و بعضی نه. اینجا می‌بینید کدام دیتاسنتر خراب است. «موفق» یعنی سرور مقصد واقعاً داده برگردانده است.</p>' +
      '<table><tr><th>دیتاسنتر</th><th>اتصال</th><th>موفق</th><th>از رله</th><th>سایت‌ها</th></tr>' + rows + '</table>' +
      '<p class="note">از ' + esc(since) + ' ؛ فقط چند سایت شناخته‌شده به نام شمرده می‌شود و نام بقیه‌ی سایت‌ها ذخیره نمی‌شود. آمار با تأخیر تا یک دقیقه ثبت می‌شود.</p>' +
      '<button class="btn sm danger" data-act="stats-reset">پاک‌کردن آمار</button></section>';
  }

  function relayQualityCard() {
    const q = S.quality;
    const rate = q.conns ? Math.round((q.ok / q.conns) * 100) + '٪' : '—';
    const rows = q.proxies.length
      ? '<table><tr><th>رله</th><th>موفق</th><th>ناموفق</th><th>میانگین اتصال</th><th>وضعیت</th></tr>' +
        q.proxies.map((p) => '<tr><td class="ltr">' + esc(p.addr) + '</td><td>' + p.ok + '</td><td>' + p.fail + '</td><td>' + (p.ms == null ? '—' : p.ms + ' ms') + '</td><td>' +
          (p.bad ? '<span class="bad">موقتاً کنار گذاشته شد</span>' : '<span class="ok">فعال</span>') + '</td></tr>').join('') + '</table>'
      : '<p class="note">هنوز رله‌ای امتحان نشده؛ با «اجرای تست» یا با استفاده‌ی واقعی پر می‌شود.</p>';
    return '<section class="card"><h3>کیفیت رله‌ها (ProxyIP)</h3>' +
      '<div class="stats"><div class="stat"><span>اتصال‌ها</span><b>' + q.conns + '</b></div><div class="stat"><span>موفق</span><b>' + rate + '</b></div>' +
      '<div class="stat"><span>ناموفق</span><b>' + q.fail + '</b></div><div class="stat"><span>ردشده (کاربر/دستگاه)</span><b>' + q.rejected + '</b></div></div>' +
      rows + '<p class="note">رله‌ها بر اساس تأخیر مرتب می‌شوند و رله‌ای که ۳ بار پشت‌سرهم خراب شود ۱۰ دقیقه به انتهای صف می‌رود. این آمار فقط مربوط به همین نمونه‌ی در حال اجرای Worker است و با بازیافت آن صفر می‌شود.</p></section>';
  }

  // ---- IP quality test, run from THIS device (so the result is specific to the current network) ----
  async function pingOnce(addr, port, timeout) {
    const host = addr.indexOf(':') > -1 && addr[0] !== '[' ? '[' + addr + ']' : addr;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeout);
    const t0 = performance.now();
    try {
      await fetch('https://' + host + ':' + port + '/cdn-cgi/trace?_=' + Math.random().toString(36).slice(2),
        { mode: 'no-cors', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: ac.signal });
    } catch (_) { /* a certificate error still means the TLS handshake with that IP completed */ }
    clearTimeout(timer);
    const ms = Math.round(performance.now() - t0);
    if (ac.signal.aborted) return null;
    return ms < 5 ? null : ms; // ~0 ms = the browser refused the request locally, not a real measurement
  }

  async function pingBest(addr, port) {
    const a = await pingOnce(addr, port, 4000);
    if (a === null) return null;
    const b = await pingOnce(addr, port, 4000);
    return b === null ? a : Math.min(a, b);
  }

  function qResHtml() {
    if (!qt.results.length) return '';
    const okList = qt.results.filter((r) => r.ms != null).sort((a, b) => a.ms - b.ms);
    const bad = qt.results.length - okList.length;
    return '<div class="verdict">' + okList.length + ' مورد پاسخ داد، ' + bad + ' مورد بی‌پاسخ ماند.' + (qt.running ? ' (در حال تست…)' : '') + '</div>' +
      (okList.length ? '<table><tr><th>آدرس</th><th>تأخیر</th></tr>' +
        okList.slice(0, 30).map((r) => '<tr><td class="ltr">' + esc(r.addr) + ':' + r.port + '</td><td>' + r.ms + ' ms</td></tr>').join('') + '</table>' : '');
  }

  function updQ() {
    const p = $('#qprog'), r = $('#qres');
    if (p) p.textContent = qt.running ? 'در حال تست: ' + qt.done + ' از ' + qt.total : '';
    if (r) r.innerHTML = qResHtml();
  }

  // Cloudflare's published IPv4 ranges (cloudflare.com/ips-v4). "Discover" tests random addresses from them.
  const CF_V4 = [['173.245.48.0', 20], ['103.21.244.0', 22], ['103.22.200.0', 22], ['103.31.4.0', 22], ['141.101.64.0', 18], ['108.162.192.0', 18], ['190.93.240.0', 20], ['188.114.96.0', 20], ['197.234.240.0', 22], ['198.41.128.0', 17], ['162.158.0.0', 15], ['104.16.0.0', 13], ['104.24.0.0', 14], ['172.64.0.0', 13], ['131.0.72.0', 22]];
  const DISCOVER_COUNT = 80;

  // Cloudflare's IPv6 front-ends mostly embed an IPv4 in the last 32 bits (e.g. 2606:4700::6810:xxxx).
  // These are guesses at where live addresses are; the real test below decides what is kept.
  function randomCfIps6(count) {
    const prefixes = ['2606:4700::', '2606:4700:3030::', '2606:4700:3031::', '2606:4700:3032::', '2606:4700:3033::', '2606:4700:3034::', '2606:4700:3035::', '2606:4700:3036::', '2606:4700:3037::'];
    const his = [0x6810, 0x6811, 0x6812, 0x6813, 0x6814, 0x6815, 0x6816, 0x6817, 0xac40, 0xac41, 0xac42, 0xac43];
    const out = new Set();
    for (let guard = 0; out.size < count && guard < count * 20; guard++) {
      const pre = prefixes[Math.floor(Math.random() * prefixes.length)];
      const hi = his[Math.floor(Math.random() * his.length)];
      const lo = Math.floor(Math.random() * 65536);
      out.add('[' + pre + hi.toString(16) + ':' + lo.toString(16) + ']');
    }
    return [...out];
  }

  function randomCfIps(count) {
    const toN = (s) => { const p = s.split('.').map(Number); return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]; };
    const toIp = (n) => [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
    const ranges = CF_V4.map(([b, m]) => ({ base: toN(b), size: Math.pow(2, 32 - m) }));
    const total = ranges.reduce((a, r) => a + r.size, 0);
    const out = new Set();
    for (let guard = 0; out.size < count && guard < count * 30; guard++) {
      let x = Math.floor(Math.random() * total);
      for (const r of ranges) {
        if (x < r.size) { const n = r.base + x; if (n % 256 !== 0 && n % 256 !== 255) out.add(toIp(n)); break; }
        x -= r.size;
      }
    }
    return [...out];
  }

  async function runQuality(discover) {
    qt.running = true; qt.stop = false; qt.results = []; qt.done = 0; qt.total = 0; render();
    let c;
    try { c = await api('ips/candidates', { extra: qt.extra, op: qt.op }); }
    catch (e) { toast(e.message, true); qt.running = false; render(); return; }
    const ports = c.ports.length ? c.ports : [443];
    const seen = {}, pairs = [];
    for (const x of c.candidates) {
      for (const p of (x.port === 443 ? ports : [x.port])) {
        const k = x.addr + ':' + p;
        if (!seen[k]) { seen[k] = 1; pairs.push([x.addr, p]); }
      }
    }
    if (discover) {
      const isV6 = (S.ipv6Ops || []).includes(qt.op);
      for (const ip of (isV6 ? randomCfIps6(DISCOVER_COUNT) : randomCfIps(DISCOVER_COUNT))) {
        const k = ip + ':' + ports[0];
        if (!seen[k]) { seen[k] = 1; pairs.push([ip, ports[0]]); }
      }
    }
    pairs.length = Math.min(pairs.length, discover ? 130 : 90);
    qt.total = pairs.length;
    let idx = 0;
    const work = async () => {
      while (!qt.stop) {
        const i = idx++;
        if (i >= pairs.length) return;
        const ms = await pingBest(pairs[i][0], pairs[i][1]);
        qt.results.push({ addr: pairs[i][0], port: pairs[i][1], ms });
        qt.done++;
        updQ();
      }
    };
    await Promise.all([work(), work(), work(), work(), work(), work()]);
    qt.running = false; render();
    // Discover mode saves the responding addresses for the selected operator right away.
    const found = qt.results.filter((r) => r.ms != null);
    if (discover && !qt.stop && found.length) {
      await doAct('ips/report', { op: qt.op, results: found }, found.length + ' آی‌پی سالم برای «' + S.operators[qt.op] + '» ذخیره شد');
    } else if (discover && !qt.stop) {
      toast('آی‌پی سالمی پیدا نشد؛ دوباره تلاش کنید.', true);
    }
  }

  function verifiedBlock() {
    const ops = Object.keys(S.operators).filter((k) => S.healthy[k] && S.healthy[k].length);
    if (!ops.length) return '<p class="note">هنوز چیزی ذخیره نشده. یک تست بزنید و «ذخیره‌ی نتیجه» را بزنید.</p>';
    return ops.map((k) => {
      const rows = S.healthy[k].map((x) => '<tr><td class="ltr">' + esc(x.key) + '</td><td>' + x.ms + ' ms</td><td>' + (x.ageMin < 60 ? x.ageMin + ' دقیقه' : Math.round(x.ageMin / 60) + ' ساعت') + ' پیش</td>' +
        '<td><button class="btn sm ghost" data-act="q-remove" data-op="' + esc(k) + '" data-key="' + esc(x.key) + '">حذف</button></td></tr>').join('');
      return '<h4>' + esc(S.operators[k]) + ' (' + S.healthy[k].length + ')</h4><table><tr><th>آدرس</th><th>تأخیر</th><th>آخرین تست</th><th></th></tr>' + rows + '</table>' +
        '<div class="linkblk"><code class="blk">' + esc(subLink(k, 'base64')) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(subLink(k, 'base64')) + '">کپی Base64</button> ' +
        '<button class="btn sm ghost" data-copy="' + esc(subLink(k, 'clash')) + '">کپی Clash</button> ' +
        '<button class="btn sm ghost" data-copy="' + esc(subLink(k, 'singbox')) + '">کپی sing-box</button> ' +
        '<button class="btn sm ghost" data-act="qr" data-text="' + esc(subLink(k, 'base64')) + '">بارکد</button> ' +
        '<button class="btn sm danger" data-act="q-clear" data-op="' + esc(k) + '">پاک‌کردن لیست</button><div class="qrbox" hidden></div></div>';
    }).join('');
  }

  // Separate IPv6 links for one user (only operators that have verified IPv6 addresses); never mixed with the normal link.
  function v6Blocks(u) {
    return (S.ipv6Ops || []).filter((k) => S.healthy[k] && S.healthy[k].length).map((k) => {
      const base = u.subUrl + '?op=' + k;
      return '<h4>لینک IPv6 این کاربر — ' + esc(S.operators[k]) + ' (' + S.healthy[k].length + ')</h4><div class="linkblk"><code class="blk">' + esc(base) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(base) + '">کپی</button> ' +
        '<button class="btn sm ghost" data-copy="' + esc(base + '&format=clash') + '">کپی Clash</button> ' +
        '<button class="btn sm ghost" data-copy="' + esc(base + '&format=singbox') + '">کپی sing-box</button> ' +
        '<button class="btn sm ghost" data-act="qr" data-text="' + esc(base) + '">بارکد</button><div class="qrbox" hidden></div></div>';
    }).join('');
  }

  const DIAG_MINUTES_UI = 15;

  function diagCard() {
    const d = S.diag || { on: false, until: 0, events: [] };
    const mins = Math.max(0, Math.round((d.until - Date.now()) / 60000));
    const rows = d.events.slice().reverse().slice(0, 80).map((e) => '<tr><td class="ltr">' + new Date(e.t).toLocaleTimeString('en-GB') + '</td><td>' + esc(e.tr) + '</td><td>' + esc(e.st) + '</td><td class="ltr">' + esc(e.m) + '</td></tr>').join('');
    return '<section class="card"><h3>تشخیص اتصال (WS)</h3>' +
      '<p class="note">برای پیدا کردن اینکه چرا اتصال برقرار نمی‌شود: «شروع» را بزنید، در برنامه یک اتصال جدید بسازید، بعد «به‌روزرسانی» را بزنید. اگر اصلاً سطری با نوع ws نیامد، یعنی درخواست به سرور نرسیده (دامنه یا شبکه جلویش را گرفته). خودکار بعد از ' + DIAG_MINUTES_UI + ' دقیقه خاموش می‌شود و آی‌پی‌ها ناقص نمایش داده می‌شوند.</p>' +
      (d.on ? '<p class="note"><b>روشن است</b> (حدود ' + mins + ' دقیقه‌ی دیگر)</p>' : '<p class="note">خاموش است.</p>') +
      '<button class="btn" data-act="diag-start">شروع</button> ' +
      '<button class="btn ghost" data-act="refresh">به‌روزرسانی</button> ' +
      (d.on ? '<button class="btn ghost" data-act="diag-stop">توقف</button> ' : '') +
      '<button class="btn sm danger" data-act="diag-clear">پاک کردن</button>' +
      (rows ? '<div style="overflow-x:auto;margin-top:10px"><table><tr><th>ساعت</th><th>نوع</th><th>مرحله</th><th>جزئیات</th></tr>' + rows + '</table></div>' : '<p class="note">رویدادی ثبت نشده.</p>') +
      '</section>';
  }

  function errorsCard() {
    const list = S.errors || [];
    const rows = list.map((e) => '<tr><td class="ltr">' + new Date(e.t).toLocaleString('en-GB') + '</td><td class="ltr">' + esc(e.p) + '</td><td class="ltr">' + esc((e.n ? e.n + ': ' : '') + e.m) + '</td></tr>').join('');
    return '<section class="card"><h3>خطاهای اخیر Worker</h3>' +
      '<p class="note">هر خطای غیرمنتظره‌ی Worker اینجا ثبت می‌شود (به‌جای صفحه‌ی خطای 1101 کلودفلر، کاربر یک پیام «خطای موقت» می‌بیند). اگر این جدول خالی است و باز هم 1101 دیدید، یعنی خطا بیرون از این کد (مثلاً یک Worker یا فایل دیگر روی همان آدرس) رخ داده است.</p>' +
      (rows ? '<div style="overflow-x:auto"><table><tr><th>زمان</th><th>مسیر</th><th>خطا</th></tr>' + rows + '</table></div><button class="btn sm danger" data-act="err-clear">پاک کردن</button>' : '<p class="note">خطایی ثبت نشده.</p>') +
      '</section>';
  }

  function emergencyCard() {
    const e = S.emergency || { text: '', count: 0, nonTls: 0 };
    const links = (title, base) => {
      const u = (f) => base + (base.includes('?') ? '&' : '?') + 'list=emergency' + (f ? '&format=' + f : '');
      return '<div class="linkblk"><p class="note"><b>' + esc(title) + '</b></p><code class="blk">' + esc(u('')) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(u('')) + '">کپی Base64</button> ' +
        '<button class="btn sm ghost" data-copy="' + esc(u('clash')) + '">کپی Clash</button> ' +
        '<button class="btn sm ghost" data-copy="' + esc(u('singbox')) + '">کپی sing-box</button> ' +
        '<button class="btn sm ghost" data-act="qr" data-text="' + esc(u('')) + '">QR</button><div class="qrbox" hidden></div></div>';
    };
    const per = e.count ? S.users.map((x) => links('لینک اضطراری — ' + x.name, x.subUrl)).join('') : '';
    return '<section class="card"><h3>اضطراری — آی‌پی و پورت دلخواه</h3>' +
      '<p class="note">هر خط یک آی‌پی همراه پورت، مثل <span class="ltr">127.0.0.1:443</span> (تا ' + S.maxEmergency + ' خط). این لیست به کارت کاربرها و لینک عادی اضافه نمی‌شود و فقط از لینک‌های همین بخش می‌آید. آی‌پی‌ها تست نمی‌شوند و همین‌طور که هستند در لینک می‌روند.</p>' +
      '<textarea id="emtext" class="ltr" rows="6" placeholder="127.0.0.1:443">' + esc(e.text) + '</textarea>' +
      '<div class="field"><label>یا از فایل متنی (.txt) بخوانید</label><input type="file" id="emfile" accept=".txt,text/plain"></div>' +
      '<button class="btn ghost" data-act="em-load">بارگذاری فایل در کادر</button> ' +
      '<button class="btn" data-act="em-save">ذخیره‌ی لیست اضطراری</button> ' +
      (e.count ? '<button class="btn sm danger" data-act="em-clear">پاک کردن همه</button>' : '') +
      '<p class="note">ذخیره‌شده: ' + e.count + ' آی‌پی، در ' + esc(e.store || 'KV') + '.' + (e.store === 'D1' ? '' : ' D1 وصل نیست و همه‌چیز در KV (با سقف ۱۰۰۰ نوشتن در روز) ذخیره می‌شود.') + (e.nonTls ? ' ' + e.nonTls + ' مورد روی پورت‌هایی است که کلودفلر با TLS نمی‌پذیرد (مثل 80 و 2052)؛ احتمالاً وصل نمی‌شوند ولی در لینک می‌مانند.' : '') + '</p>' +
      (e.count ? links('لینک اضطراری — همه‌ی کاربران (به‌تعداد کاربران × آی‌پی‌ها ورودی دارد؛ سنگین است)', S.subUrl) + per +
        '<p class="note">لیست‌های بلند روی کلاینت سنگین‌اند؛ اگر کند شد، لیست را کوتاه‌تر کنید یا از لینک یک کاربر استفاده کنید.</p>' : '') +
      '</section>';
  }

  function fileText(input) {
    return new Promise((resolve, reject) => {
      const f = input && input.files && input.files[0];
      if (!f) { reject(new Error('فایلی انتخاب نشده است')); return; }
      const r = new FileReader();
      r.onload = () => resolve(String(r.result));
      r.onerror = () => reject(new Error('خواندن فایل ممکن نشد'));
      r.readAsText(f);
    });
  }

  const views = {
    overview() {
      const attention = S.users.filter((u) => u.status || u.warn);
      return '<div class="stats">' +
        '<div class="stat"><span>کاربران</span><b>' + S.users.length + ' از ' + S.maxUsers + '</b></div>' +
        '<div class="stat"><span>ProxyIP</span><b>' + esc(modeLabel[S.proxyMode] || S.proxyMode) + '</b></div>' +
        '<div class="stat"><span>دامنه‌ی Worker</span><b class="ltr">' + esc(S.host) + '</b></div></div>' +
        '<section class="card"><h3>مصرف روزانه</h3>' + chartHtml(S.daily) +
        '<p class="note">اعداد تقریبی‌اند و با تأخیر تا حدود یک دقیقه ثبت می‌شوند.</p></section>' +
        (attention.length ? '<section class="card"><h3>نیاز به توجه (' + attention.length + ')</h3>' +
          attention.map((u) => '<div class="row"><span><b>' + esc(u.name) + '</b> ' + statusBadge(u) + '</span></div>').join('') +
          '<p class="note"></p><button class="btn sm" data-act="tab" data-tab="users">مشاهده‌ی کاربران</button></section>' : '') +
        (function () {
          const d = S.kv.days, t = d.length ? d[d.length - 1] : null;
          if (!t || (t.w < S.kv.freeWrites * 0.6 && t.q < S.kv.freeRequests * 0.8)) return '';
          const why = t.q >= S.kv.freeRequests * 0.8 ? 'امروز حدود ' + t.q + ' درخواست از ' + S.kv.freeRequests + ' ثبت شده.' : 'امروز حدود ' + t.w + ' نوشتن از ' + S.kv.freeWrites + ' ثبت شده. در تب «تنظیمات» فاصله‌ی ذخیره را بیشتر کنید.';
          return '<section class="card"><h3>مصرف روزانه بالاست</h3><p class="note" style="margin-top:0">' + why + '</p>' +
            '<button class="btn sm" data-act="tab" data-tab="settings">رفتن به تنظیمات</button></section>';
        })() +
        '<section class="card"><h3>لینک اشتراک</h3><code class="blk">' + esc(S.subUrl) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(S.subUrl) + '">کپی لینک</button> ' +
        '<button class="btn sm ghost" data-act="qr" data-text="' + esc(S.subUrl) + '">بارکد</button><div class="qrbox" hidden></div>' +
        '<p class="note">این لینک را در کلاینت به‌عنوان Subscription اضافه کنید. لینک Clash، sing-box و لینک هر اپراتور در تب «اشتراک و آدرس‌ها» است.</p></section>' +
        '<section class="card"><h3>مسیر ترافیک</h3>' + routeStrip() +
        '<p class="note">سایت‌های پشت کلودفلر (مثل ChatGPT) از Worker مستقیم باز نمی‌شوند و به ProxyIP نیاز دارند. اگر سایتی باز نشد، از «تست اتصال» ببینید کدام مسیر جواب می‌دهد.</p></section>';
    },

    users() {
      const list = S.users.map((u) => {
        const id = esc(u.uuid);
        const mode = u.expireAfterDays ? 'days' : (u.expiresAt ? 'date' : 'none');
        const expiryVal = u.expiresAt ? new Date(u.expiresAt).toISOString().slice(0, 10) : '';
        const quotaVal = u.quotaBytes ? (u.quotaBytes / GB).toFixed(2) : '';
        const pct = u.quotaBytes ? Math.min(100, (u.usedBytes / u.quotaBytes) * 100) : 0;
        const dmax = Math.max(1, ...u.daily);
        const mini = '<div class="chart mini" title="مصرف ۱۴ روز اخیر">' + u.daily.map((v) => '<div class="col"><i style="height:' + Math.round((v / dmax) * 100) + '%"></i></div>').join('') + '</div>';
        const expInfo = u.expireAfterDays
          ? (u.firstUsedAt
            ? 'شروع از اولین اتصال: ' + new Date(u.firstUsedAt).toISOString().slice(0, 10) + ' — پایان: ' + new Date(u.expiresAt).toISOString().slice(0, 10)
            : 'هنوز متصل نشده؛ ' + u.expireAfterDays + ' روز بعد از اولین اتصال منقضی می‌شود.')
          : '';
        const opt = (v, label) => '<option value="' + v + '"' + (mode === v ? ' selected' : '') + '>' + label + '</option>';
        const used = fmtBytes(u.usedBytes) + (u.quotaBytes ? ' از ' + fmtBytes(u.quotaBytes) : ' — نامحدود');
        const expTxt = u.pendingStart ? u.expireAfterDays + ' روز پس از اولین اتصال' : (u.expiresAt ? 'تا ' + new Date(u.expiresAt).toISOString().slice(0, 10) : 'بدون انقضا');
        return '<details class="user" data-uuid="' + id + '"' + (openUsers.has(u.uuid) ? ' open' : '') + '><summary>' +
          '<div class="u-main"><div class="u-line"><b>' + esc(u.name) + '</b> ' + statusBadge(u) + '</div>' +
          '<div class="u-usage">' + esc(used) + ' · ' + esc(expTxt) + (u.note ? ' · ' + esc(u.note) : '') + '</div>' +
          (u.quotaBytes ? '<div class="bar' + (pct >= 100 ? ' bad' : pct >= 90 ? ' warn' : '') + '"><div style="width:' + pct.toFixed(1) + '%"></div></div>' : '') +
          '</div></summary><div class="u-body">' +
          '<div class="u-actions">' +
          '<button class="btn sm ghost" data-act="user-toggle" data-uuid="' + id + '" data-disabled="' + (u.disabled ? '0' : '1') + '">' + (u.disabled ? 'فعال‌سازی' : 'غیرفعال‌سازی') + '</button>' +
          '<button class="btn sm danger" data-act="user-delete" data-uuid="' + id + '">حذف کاربر</button></div>'+
          '<code class="blk">' + id + '</code>' +
          '<button class="btn sm ghost" data-copy="' + id + '">کپی UUID</button>' +
          '<h4>مشخصات</h4><div class="fields">' +
          '<div class="field"><label>نام</label><input type="text" class="m-name" maxlength="32" value="' + esc(u.name) + '"></div>' +
          '<div class="field"><label>یادداشت</label><input type="text" class="m-note" maxlength="120" value="' + esc(u.note) + '"></div>' +
          '<div class="field"><label>حداکثر دستگاه هم‌زمان</label><input type="text" inputmode="numeric" class="m-dev ltr" placeholder="نامحدود" value="' + esc(u.maxDevices || '') + '"></div></div>' +
          '<div class="field"><label>آی‌پی دستی این کاربر (هر خط یکی، اختیاری)</label><textarea class="m-ips ltr" rows="3" placeholder="104.16.1.1&#10;104.17.2.2:2053">' + esc(u.ips || '') + '</textarea></div>' +
          '<p class="note">این آی‌پی‌ها فقط در لینک همین کاربر و بالای لیست می‌آیند؛ بعدشان آی‌پی‌های دستی کلی و تأییدشده می‌آیند.</p>' +
          '<button class="btn sm" data-act="user-meta" data-uuid="' + id + '">ذخیره مشخصات</button>' +
          '<p class="note">دستگاه‌ها بر اساس آی‌پی کاربر شمرده می‌شوند و شمارش برای هر نمونه‌ی Worker جداست، پس تقریبی است؛ چند دستگاه پشت یک مودم یا هات‌اسپات یکی حساب می‌شوند.</p>' +
          '<h4>محدودیت‌ها</h4><div class="fields">' +
          '<div class="field"><label>نوع انقضا</label><select class="limit-mode">' + opt('none', 'بدون انقضا') + opt('date', 'تاریخ ثابت') + opt('days', 'چند روز از اولین اتصال') + '</select></div>' +
          '<div class="field"><label>تاریخ انقضا</label><input type="date" class="limit-expiry" value="' + esc(expiryVal) + '"></div>' +
          '<div class="field"><label>روز از اولین اتصال</label><input type="text" inputmode="numeric" class="limit-days ltr" placeholder="مثلاً 30" value="' + esc(u.expireAfterDays || '') + '"></div>' +
          '<div class="field"><label>سقف حجم (گیگابایت)</label><input type="text" inputmode="decimal" class="limit-quota ltr" placeholder="نامحدود" value="' + esc(quotaVal) + '"></div></div>' +
          '<button class="btn sm" data-act="user-limits" data-uuid="' + id + '">ذخیره محدودیت‌ها</button> ' +
          (u.expireAfterDays ? '<button class="btn sm ghost" data-act="user-restart" data-uuid="' + id + '">شروع دوباره‌ی انقضا</button>' : '') +
          (expInfo ? '<p class="note">' + esc(expInfo) + '</p>' : '') +
          '<p class="note">فقط فیلدِ مربوط به «نوع انقضا» اعمال می‌شود. مصرف تقریبی است و با تأخیر تا حدود یک دقیقه ثبت می‌شود (به دلیل معماری Workers، شمارش کاملاً لحظه‌ای و جهانی ممکن نیست).</p>' +
          '<div class="row"><span>مصرف: <b>' + fmtBytes(u.usedBytes) + '</b>' + (u.quotaBytes ? ' از ' + fmtBytes(u.quotaBytes) : ' (نامحدود)') + '</span>' +
          '<button class="btn sm ghost" data-act="user-reset-usage" data-uuid="' + id + '">ریست مصرف</button></div>' +
          mini +
          '<h4>صفحه‌ی وضعیت کاربر (برای فرستادن به خودش)</h4><div class="linkblk"><code class="blk">' + esc(u.statusUrl) + '</code>' +
          '<button class="btn sm" data-copy="' + esc(u.statusUrl) + '">کپی</button> <a class="btn sm ghost" href="' + esc(u.statusUrl) + '" target="_blank" rel="noopener">باز کردن</a>' +
          '<p class="note">کاربر با این صفحه حجم و روزهای باقی‌مانده را می‌بیند و لینک‌ها و بارکدها را خودش برمی‌دارد.</p></div>' +
          '<h4>لینک اشتراک این کاربر</h4><div class="linkblk"><code class="blk">' + esc(u.subUrl) + '</code>' +
          '<button class="btn sm" data-copy="' + esc(u.subUrl) + '">کپی</button> ' +
          '<button class="btn sm ghost" data-copy="' + esc(u.subUrl + '?format=clash') + '">کپی Clash</button> ' +
          '<button class="btn sm ghost" data-copy="' + esc(u.subUrl + '?format=singbox') + '">کپی sing-box</button> ' +
          '<button class="btn sm ghost" data-act="qr" data-text="' + esc(u.subUrl) + '">بارکد</button><div class="qrbox" hidden></div></div>' +
          v6Blocks(u) +
          '<details class="u-sub"><summary>لینک‌های VLESS تکی (' + u.links.length + ')</summary>' +
          u.links.map((l) =>
            '<div class="linkblk"><div class="row" style="margin-top:8px"><small class="note">' + esc(l.label) + '</small><span>' +
            '<button class="btn sm ghost" data-act="qr" data-text="' + esc(l.url) + '">بارکد</button> ' +
            '<button class="btn sm" data-copy="' + esc(l.url) + '">کپی لینک VLESS</button></span></div>' +
            '<code class="blk">' + esc(l.url) + '</code><div class="qrbox" hidden></div></div>').join('') +
          '</details></div></details>';
      }).join('');
      return '<div class="row" style="margin:0 2px 8px"><b>' + S.users.length + ' کاربر از ' + S.maxUsers + '</b><span class="note" style="margin:0">برای ویرایش، روی هر کاربر بزنید</span></div>' + list +
        '<section class="card" style="margin-top:14px"><h3>افزودن کاربر</h3><input id="newname" placeholder="نام کاربر" maxlength="32">' +
        '<button class="btn" data-act="user-add">افزودن</button></section>';
    },

    proxy() {
      const chk = (m) => (S.proxyMode === m ? 'checked' : '');
      return '<section class="card"><h3>ProxyIP</h3>' +
        '<p class="note">ابتدا اتصال مستقیم امتحان می‌شود. فقط اگر نشد، ترافیک از یک رله عبور می‌کند.</p>' +
        '<label class="opt"><input type="radio" name="pmode" value="auto" ' + chk('auto') + '><span><b>خودکار</b><br>' +
        '<small class="note">لیست دستی (اگر پر باشد) و بعد آدرس‌هایی که از دامنه‌ی منبع خودکار پیدا می‌شوند.</small></span></label>' +
        '<label class="opt"><input type="radio" name="pmode" value="custom" ' + chk('custom') + '><span><b>فقط لیست دستی</b></span></label>' +
        '<label class="opt"><input type="radio" name="pmode" value="off" ' + chk('off') + '><span><b>غیرفعال</b></span></label>' +
        '<h4>لیست دستی</h4><textarea id="plist" rows="5" placeholder="1.2.3.4:443&#10;relay.example.com">' + esc(S.proxyList) + '</textarea>' +
        '<p class="note">هر خط یک IP یا دامنه، با پورت اختیاری. اگر دامنه رکورد TXT با چند آدرس داشته باشد، همه‌ی آن‌ها استفاده می‌شود.</p>' +
        '<h4>دامنه‌ی منبع خودکار</h4><input id="pdomain" class="ltr" value="' + esc(S.autoDomain) + '">' +
        '<label class="opt"><input type="checkbox" id="pcolo" ' + (S.autoPerColo ? 'checked' : '') + '><span>' +
        'استفاده از پیشوند دیتاسنتر <span class="ltr">(' + esc((S.colo || '?').toLowerCase()) + '.' + esc(S.autoDomain) + ')</span></span></label>' +
        '<h4>دریافت خودکار آی‌پی تمیز از اینترنت</h4>' +
        '<label class="opt"><input type="checkbox" id="pclean" ' + (S.cleanIpEnabled ? 'checked' : '') + '><span><b>فعال</b><br>' +
        '<small class="note">علاوه بر لیست بالا، هر چند دقیقه یک‌بار از این آدرس‌ها یک فهرست آی‌پی تازه گرفته می‌شود و به‌عنوان کاندیدهای رله اضافه می‌شود.</small></span></label>' +
        '<textarea id="pcleanurls" rows="3" placeholder="https://...">' + esc(S.cleanIpUrls) + '</textarea>' +
        '<button class="btn sm ghost" data-act="clean-default" type="button">بازگشت به آدرس‌های پیش‌فرض</button> ' +
        '<button class="btn sm" data-act="check-sources" type="button"' + (srcChecking ? ' disabled' : '') + '>بررسی وضعیت منابع</button>' +
        sourcesBlock() +
        '<p class="note warn">این آدرس‌ها فهرست‌های عمومی شخص ثالث‌اند، در اختیار ما نیستند و ممکن است هر لحظه از کار بیفتند یا تغییر کنند. کیفیت و صحتشان تضمین‌شده نیست؛ فقط به‌عنوان کاندیدهای اضافه برای رله امتحان می‌شوند.</p>' +
        '<h4>محدود کردن به کشور خاص</h4>' +
        '<input id="pcountry" class="ltr" value="' + esc(S.countryFilter) + '" placeholder="US یا US,CA">' +
        '<p class="note">اختیاری. کد دو حرفی کشور (مثلاً US برای آمریکا)، با ویرگول جدا برای چند کشور. خالی = بدون فیلتر. کشور هر آی‌پی با یک سرویس شخص ثالث (ip-api.com) بررسی می‌شود؛ اگر این سرویس در دسترس نباشد، آن آی‌پی نادیده گرفته می‌شود.</p>' +
        '<button class="btn sm ghost" data-act="country-preset" type="button">پیشنهاد برای ChatGPT و Claude</button>' +
        '<p class="note">ChatGPT و Claude آی‌پی رله را می‌بینند و رله‌ی بعضی کشورها را قبول نمی‌کنند. پیشنهاد بالا کشورهایی را می‌گذارد که معمولاً پشتیبانی می‌شوند؛ فهرست پشتیبانی هر سرویس ممکن است عوض شود، پس با «تست ChatGPT + Claude» بررسی کنید.</p>' +
        '<button class="btn" data-act="proxy-save">ذخیره</button> ' +
        '<button class="btn ghost" data-act="proxy-default">بازگشت به دامنه‌ی پیش‌فرض</button>' +
        '<p class="note warn">رله یک سرور شخص ثالث است. ترافیک HTTPS تا مقصد رمزنگاری‌شده می‌ماند، اما رله می‌تواند نام سایت مقصد را ببیند و ترافیک بدون رمز (HTTP ساده) برایش قابل مشاهده است. اگر این برایتان مهم است از «فقط لیست دستی» با رله‌ی خودتان یا «غیرفعال» استفاده کنید.</p></section>';
    },

    sub() {
      const chk = (m) => (S.addrMode === m ? 'checked' : '');
      return '<section class="card"><h3>لینک اشتراک</h3><code class="blk">' + esc(S.subUrl) + '</code>' +
        '<button class="btn sm" data-copy="' + esc(S.subUrl) + '">کپی</button> ' +
        '<button class="btn sm ghost" data-act="qr" data-text="' + esc(S.subUrl) + '">بارکد</button> ' +
        '<button class="btn sm danger" data-act="sub-regen">ساخت لینک جدید</button>' +
        '<div class="qrbox" hidden></div>' +
        '<p class="note">هر کس این لینک را داشته باشد به همه‌ی کاربران دسترسی دارد. با ساخت لینک جدید، لینک قبلی از کار می‌افتد.</p></section>' +
        subFormatCard() +
        '<section class="card"><h3>آدرس‌های اتصال</h3>' +
        '<p class="note">این آدرس‌ها همان چیزی‌اند که در لینک VLESS و لینک اشتراک، جلوی نام کاربر قرار می‌گیرند و کلاینت برای <b>رسیدن به این Worker</b> به آن‌ها وصل می‌شود (SNI و Host همیشه دامنه‌ی Worker می‌ماند). اگر دامنه‌ی Worker در شبکه‌ی شما فیلتر است، از یک IP یا دامنه‌ی جایگزین استفاده کنید. با ProxyIP در تب قبلی اشتباه نشود؛ آن، آدرسی است که خود Worker برای رسیدن به سایت‌های مقصد استفاده می‌کند.</p>' +
        '<label class="opt"><input type="radio" name="amode" value="manual" ' + chk('manual') + '><span><b>دستی</b><br>' +
        '<small class="note">فقط آدرس‌هایی که پایین می‌نویسید استفاده می‌شوند.</small></span></label>' +
        '<label class="opt"><input type="radio" name="amode" value="auto" ' + chk('auto') + '><span><b>خودکار (آی‌پی تمیز)</b><br>' +
        '<small class="note">علاوه بر لیست دستی، چند آی‌پی از همان منبع‌ها و فیلتر کشوری که در تب ProxyIP تنظیم کرده‌اید اضافه می‌شود. برای این حالت، «دریافت خودکار آی‌پی تمیز» در تب ProxyIP لازم نیست فعال باشد؛ همین‌جا مستقل کار می‌کند.</small></span></label>' +
        '<textarea id="addrs" rows="5" placeholder="104.16.0.1&#10;example.com:2053">' + esc(S.addrs) + '</textarea>' +
        '<div id="acountwrap" style="' + (S.addrMode === 'auto' ? '' : 'display:none') + '">' +
        '<h4>تعداد آی‌پی خودکار</h4><input id="acount" type="text" inputmode="numeric" class="ltr" value="' + esc(S.addrCount) + '" style="max-width:100px">' +
        '<p class="note">حداکثر ' + S.maxAutoAddrs + ' عدد.</p></div>' +
        '<button class="btn" data-act="addr-save">ذخیره</button>' +
        '<p class="note warn">چرا اسکنر خودکار نداریم: طبق مستندات خود کلودفلر، خود Worker اجازه ندارد به هیچ آی‌پی‌ای که متعلق به کلودفلر باشد وصل شود (Outbound TCP sockets to Cloudflare IP ranges are blocked). چون همه‌ی این آدرس‌های اتصال دقیقاً همین‌جور آی‌پی‌هایی هستند، Worker نمی‌تواند خودش آن‌ها را تست کند؛ فقط می‌تواند از لیست منبع‌های بیرونی (بالا) استفاده کند یا هر آدرسی که خودتان دستی وارد کنید. اگر می‌خواهید مطمئن‌ترین آی‌پی برای شبکه‌ی خودتان را پیدا کنید، بهترین راه اجرای یک ابزار اسکن روی سیستم خودتان (مثل CloudflareSpeedTest) و افزودن دستی نتیجه به لیست بالاست.</p></section>';
    },

    tools() {
      const cell = (x) => x.ok ? '<span class="ok">✔ ' + esc(x.status || 'پاسخ داد') + '</span>' : '<span class="bad">✖ ' + esc(x.error || x.status || 'بدون پاسخ') + '</span>';
      const one = (r) => {
        const good = r.candidates.filter((c) => c.ok).length;
        const verdict = r.direct.ok
          ? 'اتصال مستقیم به این سایت کار می‌کند و به رله نیازی نیست.'
          : good
            ? 'اتصال مستقیم جواب نداد ولی ' + good + ' رله‌ی سالم پیدا شد. ProxyIP برای این سایت کار می‌کند.'
            : r.resolved
              ? 'هیچ‌کدام از ' + Math.min(r.resolved, 6) + ' رله‌ی امتحان‌شده جواب ندادند. لیست دستی یا دامنه‌ی منبع را عوض کنید.'
              : 'هیچ رله‌ای پیدا نشد. منبع خودکار رکوردی برنگرداند یا لیست دستی خالی است.';
        return '<h4>نتیجه برای ' + esc(r.host) + ' (دیتاسنتر ' + esc(r.colo || '؟') + ')</h4>' +
          '<div class="verdict">' + verdict + '</div>' +
          '<table><tr><th>مسیر</th><th>کشور</th><th>وضعیت</th><th>زمان</th></tr>' +
          '<tr><td>مستقیم</td><td>—</td><td>' + cell(r.direct) + '</td><td>' + r.direct.ms + ' ms</td></tr>' +
          r.candidates.map((c) => '<tr><td class="ltr">' + esc(c.addr) + ':' + c.port + '</td><td>' + esc(c.cc || '؟') + '</td><td>' + cell(c) + '</td><td>' + c.ms + ' ms</td></tr>').join('') +
          '</table><p class="note">منبع‌ها: <span class="ltr">' + esc(r.entries.join(' , ') || '—') + '</span> — ' + r.resolved + ' آدرس پیدا شد' +
          (r.countries.length ? '، فیلتر کشور: <span class="ltr">' + esc(r.countries.join(',')) + '</span>' : '') + '.</p>';
      };
      let out = '';
      if (testing) out = '<p class="note">در حال تست… (برای هر سایت تا حدود ۱۰ ثانیه)</p>';
      else if (testRes && testRes.length) {
        out = testRes.map(one).join('') +
          '<p class="note">چند سایت پشت کلودفلر (مثل ChatGPT و Claude) اتصال مستقیم را نمی‌پذیرند و فقط از مسیر رله باز می‌شوند. این سایت‌ها آی‌پی رله را هم می‌بینند و ممکن است رله‌ی بعضی کشورها یا دیتاسنترها را رد کنند؛ ستون «کشور» را نگاه کنید.</p>';
      }
      const chip = (h, t) => '<button class="btn sm ghost" data-act="test-chip" data-host="' + h + '">' + t + '</button> ';
      return '<section class="card"><h3>تست اتصال</h3>' +
        '<p class="note">از خود Worker، اتصال مستقیم و رله‌ها را برای یک سایت امتحان می‌کند. پاسخ 403 هم یعنی مسیر کار می‌کند.</p>' +
        '<input id="thost" class="ltr" value="' + esc(testHost) + '" placeholder="chatgpt.com">' +
        '<button class="btn" data-act="run-test"' + (testing ? ' disabled' : '') + '>اجرای تست</button> ' +
        '<button class="btn ghost" data-act="test-both"' + (testing ? ' disabled' : '') + '>تست ChatGPT + Claude</button>' +
        '<p class="note">میان‌بر: ' + chip('chatgpt.com', 'ChatGPT') + chip('claude.ai', 'Claude') + chip('google.com', 'Google') + '</p>' +
        out + '</section>' + coloStatsCard() + relayQualityCard() + diagCard() + errorsCard();
    },

    quality() {
      const opOpts = Object.keys(S.operators).map((k) => '<option value="' + esc(k) + '"' + (qt.op === k ? ' selected' : '') + '>' + esc(S.operators[k]) + '</option>').join('');
      return '<section class="card"><h3>تست کیفیت آی‌پی از دستگاه شما</h3>' +
        '<p class="note">این تست از خود مرورگر شما به هر آی‌پی و پورت وصل می‌شود و زمان برقراری اتصال امن (TLS) را می‌سنجد؛ پس نتیجه مخصوص همین اینترنت است. ' +
        'برای اپراتور درست، پنل را از روی همان اینترنت (مثلاً همراه اول) باز کنید و همان اپراتور را انتخاب کنید.</p>' +
        '<div class="field"><label>اپراتور فعلی شما</label><select id="qop">' + opOpts + '</select></div>' +
        ((S.ipv6Ops || []).includes(qt.op) ? '<p class="note">این فهرست فقط IPv6 است و جدا از فهرست IPv4 همین اپراتور نگه داشته می‌شود؛ لینک اشتراک جداگانه دارد و در کارت کاربرها یا لینک عادی نمی‌آید. تست فقط وقتی جواب می‌دهد که اینترنت همین دستگاه IPv6 داشته باشد. آی‌پی دستی را به‌شکل <span class="ltr">[2606:4700::6810:1234]:443</span> بنویسید.</p>' : '') +
        '<h4>آی‌پی‌های اضافه (اختیاری)</h4><textarea id="qextra" rows="3" placeholder="104.16.1.1&#10;104.17.2.2:2053">' + esc(qt.extra) + '</textarea>' +
        '<p class="note">کاندیدها از منبع‌های تب ProxyIP، لیست دستی تب «اشتراک» و همین کادر جمع می‌شوند (حداکثر ۴۰ آی‌پی). پورت‌های تست‌شده: <span class="ltr">' + esc(S.ports.join(', ')) + '</span> (از تب «تنظیمات»).</p>' +
        '<button class="btn" data-act="q-start"' + (qt.running ? ' disabled' : '') + '>شروع تست</button> ' +
        '<button class="btn" data-act="q-discover"' + (qt.running ? ' disabled' : '') + '>کشف و ذخیره‌ی خودکار آی‌پی</button> ' +
        (qt.running ? '<button class="btn ghost" data-act="q-stop">توقف</button> ' : '') +
        (!qt.running && qt.results.some((r) => r.ms != null) ? '<button class="btn" data-act="q-save">ذخیره‌ی نتیجه برای «' + esc(S.operators[qt.op]) + '»</button>' : '') +
        '<p class="note" id="qprog">' + (qt.running ? 'در حال تست: ' + qt.done + ' از ' + qt.total : '') + '</p>' +
        '<div id="qres">' + qResHtml() + '</div>' +
        '<p class="note warn">دو محدودیت: (۱) فقط دسترس‌پذیری و تأخیر خودِ آی‌پی سنجیده می‌شود؛ تضمین نمی‌کند فیلترینگ روی نام دامنه‌ی Worker هم عبور کند، پس چند آی‌پی بالای جدول را در کلاینت هم امتحان کنید. ' +
        '(۲) اگر شبکه اتصال‌های مسدودشده را سریع قطع کند (Reset)، ممکن است آی‌پی بسته هم «سالم» دیده شود. تست خود Worker برای آی‌پی‌های کلودفلر ممکن نیست، چون Workers اجازه‌ی اتصال به آی‌پی‌های کلودفلر را ندارد.</p></section>' +
        '<section class="card"><h3>آی‌پی‌های تأییدشده به تفکیک اپراتور</h3>' +
        '<p class="note">فقط مواردی که در ۷ روز اخیر سالم بوده‌اند وارد لینک اشتراک همه‌ی کاربران (از جمله کاربران جدید) می‌شوند؛ اپراتور از روی شبکه‌ی دریافت‌کننده‌ی لینک تشخیص داده می‌شود و اگر معلوم نبود، بهترین‌ها از همه‌ی اپراتورها می‌آیند؛ آی‌پی‌ای که ۳ تست پشت‌سرهم رد شود خودکار حذف می‌شود. برای تازه ماندن لیست، هر چند روز یک‌بار تست را تکرار کنید.</p>' +
        verifiedBlock() + '</section>' + emergencyCard();
    },

    settings() {
      const fpOpts = S.fps.map((f) => '<option value="' + f + '"' + (S.fp === f ? ' selected' : '') + '>' + f + '</option>').join('');
      const alpnOpts = S.alpns.map((a) => '<option value="' + esc(a) + '"' + (S.alpn === a ? ' selected' : '') + '>' + (a || 'پیش‌فرض کلاینت') + '</option>').join('');
      const portBoxes = S.cfPorts.map((p) => '<label class="opt"><input type="checkbox" class="s-port" value="' + p + '"' + (S.ports.indexOf(p) > -1 ? ' checked' : '') + '><span class="ltr">' + p + '</span></label>').join('');
      return '<section class="card"><h3>گزینه‌های اتصال (لینک‌ها و اشتراک)</h3>' +
        '<div class="fields"><div class="field"><label>اثر انگشت TLS (fp)</label><select id="s-fp">' + fpOpts + '</select></div>' +
        '<div class="field"><label>ALPN</label><select id="s-alpn">' + alpnOpts + '</select></div></div>' +
        '<h4>پورت‌ها</h4><div class="ports">' + portBoxes + '</div>' +
        '<p class="note">هر آدرس روی چند پورت پشتیبانی‌شده‌ی HTTPS کلودفلر در اشتراک می‌آید تا اگر یک پورت فیلتر شد بقیه کار کنند. تعداد لینک‌ها به همان نسبت زیاد می‌شود.</p>' +
        '<label class="opt"><input type="checkbox" id="s-frag"' + (S.fragment ? ' checked' : '') + '><span><b>فعال‌کردن Fragment در خروجی sing-box</b><br>' +
        '<small class="note">فقط در فایل sing-box اعمال می‌شود و به sing-box نسخه‌ی 1.12 یا جدیدتر نیاز دارد؛ روی نسخه‌های قدیمی‌تر پروفایل خطا می‌دهد. در v2rayNG و Clash، تنظیم Fragment را باید داخل خود برنامه فعال کنید و در لینک قرار نمی‌گیرد.</small></span></label>' +
        '<button class="btn" data-act="settings-save">ذخیره</button></section>' + kvCard() +
        '<section class="card"><h3>رمز عبور پنل</h3>' +
        '<input type="password" id="pw-cur" placeholder="رمز فعلی" autocomplete="current-password">' +
        '<input type="password" id="pw-new" placeholder="رمز جدید (حداقل ۸ کاراکتر)" autocomplete="new-password">' +
        '<input type="password" id="pw-new2" placeholder="تکرار رمز جدید" autocomplete="new-password">' +
        '<button class="btn" data-act="pw-change">تغییر رمز</button> <button class="btn ghost" data-act="pw-logout-all">خروج همه‌ی دستگاه‌ها</button>' +
        '<p class="note warn">بعد از تعیین رمز از اینجا، رمز متغیر ADMIN دیگر کار نمی‌کند. اگر رمز جدید را فراموش کردید، کلید <span class="ltr">auth</span> را از ' + (S.kv.backend === 'D1' ? 'جدول kv در D1' : 'KV') + ' حذف کنید تا رمز متغیر ADMIN دوباره فعال شود.</p></section>' +
        '<section class="card"><h3>پشتیبان‌گیری و بازیابی</h3>' +
        '<a class="btn sm" href="/panel/api/backup" download>دانلود فایل پشتیبان</a>' +
        '<p class="note">شامل کاربران (UUID، حجم، انقضا، آی‌پی دستی هر کاربر)، لینک اشتراک، همه‌ی تنظیمات، آی‌پی‌های تأییدشده‌ی همه‌ی اپراتورها (از جمله IPv6) و لیست اضطراری است. رمز پنل در آن نیست. فایل محرمانه است؛ هر کس آن را داشته باشد به کاربران دسترسی دارد.</p>' +
        '<h4>بازیابی</h4><input type="file" id="restorefile" accept="application/json,.json">' +
        '<button class="btn danger" data-act="restore">بازیابی از فایل</button>' +
        '<p class="note warn">بازیابی، کاربران و تنظیمات فعلی را کاملاً با محتوای فایل جایگزین می‌کند.</p></section>';
    },
  };

  function render() {
    if (!S) return;
    const tabs = [['overview', 'نمای کلی'], ['users', 'کاربران'], ['proxy', 'ProxyIP'], ['sub', 'اشتراک و آدرس‌ها'], ['quality', 'کیفیت آی‌پی'], ['tools', 'تست اتصال'], ['settings', 'تنظیمات']];
    const cur = tabs.filter((t) => t[0] === tab)[0] || tabs[0];
    const y = renderedTab === tab ? window.scrollY : 0;
    renderedTab = tab;
    $('#app').innerHTML =
      '<div class="shell"><aside class="side"><div class="brand">' + MARK + '<b>' + document.title.replace(/[<>&]/g, '') + '</b></div>' + // page <title> is the panel name
      '<div class="side-actions">' +
      '<button class="iconbtn" data-act="refresh" title="بروزرسانی" aria-label="بروزرسانی">' + ic('refresh') + '</button>' +
      '<button class="iconbtn" data-act="theme" title="تغییر تم" aria-label="تغییر تم">' + ic('theme') + '</button>' +
      '<button class="iconbtn" data-act="logout" title="خروج" aria-label="خروج">' + ic('logout') + '</button></div>' +
      '<nav class="tabs" aria-label="بخش‌ها">' + tabs.map((t) => '<button class="tab ' + (t[0] === tab ? 'on' : '') + '" data-act="tab" data-tab="' + t[0] + '"' + (t[0] === tab ? ' aria-current="page"' : '') + '>' + ic(t[0]) + '<span>' + t[1] + '</span></button>').join('') + '</nav></aside>' +
      '<main class="main"><div class="page-head"><h1>' + cur[1] + '</h1><span class="pill" title="دیتاسنتر کلودفلر که این صفحه را داده"><i class="dot"></i>' + esc(S.colo || '—') + '</span></div>' +
      views[tab]() + '</main></div>';
    window.scrollTo(0, y);
  }

  async function runTests(hosts) {
    const el = $('#thost');
    if (!hosts) { if (el) testHost = el.value.trim() || 'chatgpt.com'; hosts = [testHost]; }
    testing = true; testRes = []; render();
    for (const h of hosts) {
      try { testRes.push(await api('test', { host: h })); }
      catch (e) { toast(e.message, true); break; }
      render();
    }
    testing = false; render();
  }

  document.addEventListener('change', (e) => {
    const t = e.target;
    if (t.name === 'amode') {
      const w = $('#acountwrap');
      if (w) w.style.display = t.value === 'auto' ? '' : 'none';
    } else if (t.id === 'qop') { qt.op = t.value; render(); }
    else if (t.id === 'sfmt') { subSel.format = t.value; render(); }
    else if (t.id === 'sop') { subSel.op = t.value; render(); }
  });

  document.addEventListener('toggle', (e) => {
    const d = e.target;
    if (d && d.classList && d.classList.contains('user')) { if (d.open) openUsers.add(d.dataset.uuid); else openUsers.delete(d.dataset.uuid); }
  }, true);

  document.addEventListener('input', (e) => {
    if (e.target.id === 'qextra') qt.extra = e.target.value;
  });

  document.addEventListener('click', async (e) => {
    const c = e.target.closest('[data-copy]');
    if (c) { copy(c.dataset.copy); return; }
    const a = e.target.closest('[data-act]');
    if (!a) return;
    const act = a.dataset.act;
    if (act === 'tab') { tab = a.dataset.tab; render(); }
    else if (act === 'user-add') await doAct('user/add', { name: $('#newname').value }, 'کاربر اضافه شد');
    else if (act === 'user-delete') { if (window.confirm('این کاربر حذف شود؟')) await doAct('user/delete', { uuid: a.dataset.uuid }, 'کاربر حذف شد'); }
    else if (act === 'qr') await toggleQr(a);
    else if (act === 'check-sources') {
      srcChecking = true; srcRes = null; render();
      try { srcRes = await api('sources/check', {}); } catch (e) { toast(e.message, true); }
      srcChecking = false; render();
    }
    else if (act === 'user-meta') {
      const box = a.closest('.user');
      await doAct('user/set-meta', {
        uuid: a.dataset.uuid,
        name: box.querySelector('.m-name').value,
        note: box.querySelector('.m-note').value,
        maxDevices: box.querySelector('.m-dev').value,
        ips: box.querySelector('.m-ips').value,
      }, 'مشخصات ذخیره شد');
    }
    else if (act === 'user-toggle') await doAct('user/toggle', { uuid: a.dataset.uuid, disabled: a.dataset.disabled === '1' }, a.dataset.disabled === '1' ? 'کاربر غیرفعال شد' : 'کاربر فعال شد');
    else if (act === 'user-restart') { if (window.confirm('انقضا از اولین اتصال بعدی دوباره شروع شود؟')) await doAct('user/restart-first-use', { uuid: a.dataset.uuid }, 'انقضا ریست شد'); }
    else if (act === 'user-limits') {
      const box = a.closest('.user');
      await doAct('user/set-limits', {
        uuid: a.dataset.uuid,
        expireMode: box.querySelector('.limit-mode').value,
        expiresAt: box.querySelector('.limit-expiry').value,
        expireDays: box.querySelector('.limit-days').value,
        quotaGB: box.querySelector('.limit-quota').value,
      }, 'محدودیت‌ها ذخیره شد');
    }
    else if (act === 'user-reset-usage') { if (window.confirm('مصرف این کاربر صفر شود؟')) await doAct('user/reset-usage', { uuid: a.dataset.uuid }, 'مصرف صفر شد'); }
    else if (act === 'proxy-save') {
      const m = document.querySelector('input[name=pmode]:checked');
      await doAct('proxy/save', {
        proxyMode: m ? m.value : 'auto',
        proxyList: $('#plist').value,
        autoDomain: $('#pdomain').value,
        autoPerColo: $('#pcolo').checked,
        cleanIpEnabled: $('#pclean').checked,
        cleanIpUrls: $('#pcleanurls').value,
        countryFilter: $('#pcountry').value,
      }, 'تنظیمات ProxyIP ذخیره شد');
    }
    else if (act === 'proxy-default') { $('#pdomain').value = S.autoDomainDefault; $('#pcolo').checked = true; toast('دامنه‌ی پیش‌فرض گذاشته شد. برای اعمال ذخیره کنید.'); }
    else if (act === 'clean-default') { $('#pcleanurls').value = S.cleanIpUrlsDefault; toast('آدرس‌های پیش‌فرض گذاشته شد. برای اعمال ذخیره کنید.'); }
    else if (act === 'addr-save') {
      const m = document.querySelector('input[name=amode]:checked');
      await doAct('addr/save', {
        addrs: $('#addrs').value,
        addrMode: m ? m.value : 'manual',
        addrCount: $('#acount') ? $('#acount').value : 3,
      }, 'آدرس‌ها ذخیره شد');
    }
    else if (act === 'sub-regen') { if (window.confirm('لینک قبلی باطل می‌شود. ادامه؟')) await doAct('sub/regen', {}, 'لینک اشتراک جدید ساخته شد'); }
    else if (act === 'retry') location.reload();
    else if (act === 'refresh') { try { S = await api('state'); render(); toast('بروزرسانی شد'); } catch (err) { toast(err.message, true); } }
    else if (act === 'theme') cycleTheme();
    else if (act === 'run-test') await runTests();
    else if (act === 'test-both') await runTests(['chatgpt.com', 'claude.ai']);
    else if (act === 'test-chip') { testHost = a.dataset.host; await runTests([testHost]); }
    else if (act === 'stats-reset') { if (window.confirm('آمار پاک شود؟')) await doAct('stats/reset', {}, 'آمار پاک شد'); }
    else if (act === 'country-preset') { $('#pcountry').value = 'US,DE,NL,GB,FI,SE,CA'; toast('برای اعمال، ذخیره کنید.'); }
    else if (act === 'q-start') await runQuality();
    else if (act === 'q-discover') await runQuality(true);
    else if (act === 'err-clear') await doAct('errors/clear', {}, 'پاک شد');
    else if (act === 'diag-start') await doAct('diag/start', {}, 'ثبت رویدادها روشن شد');
    else if (act === 'diag-stop') await doAct('diag/stop', {}, 'ثبت رویدادها متوقف شد');
    else if (act === 'diag-clear') await doAct('diag/clear', {}, 'پاک شد');
    else if (act === 'em-load') {
      try {
        const t = await fileText($('#emfile'));
        $('#emtext').value = t;
        toast(t.split(/[\r\n]+/).filter((x) => x.trim()).length + ' خط خوانده شد؛ برای ثبت، «ذخیره‌ی لیست اضطراری» را بزنید.');
      } catch (err) { toast(err.message, true); }
    }
    else if (act === 'em-save') await doAct('emergency/save', { text: $('#emtext').value }, 'لیست اضطراری ذخیره شد');
    else if (act === 'em-clear') { if (window.confirm('کل لیست اضطراری پاک شود؟')) await doAct('emergency/clear', {}, 'لیست اضطراری پاک شد'); }
    else if (act === 'q-stop') { qt.stop = true; }
    else if (act === 'q-save') { if (qt.results.length) await doAct('ips/report', { op: qt.op, results: qt.results }, 'نتیجه برای اپراتور ذخیره شد'); }
    else if (act === 'q-clear') { if (window.confirm('لیست این اپراتور پاک شود؟')) await doAct('ips/clear', { op: a.dataset.op }, 'لیست پاک شد'); }
    else if (act === 'q-remove') await doAct('ips/clear', { op: a.dataset.op, key: a.dataset.key }, 'حذف شد');
    else if (act === 'settings-save') {
      const ports = Array.prototype.map.call(document.querySelectorAll('.s-port:checked'), (x) => Number(x.value));
      await doAct('settings/save', { fp: $('#s-fp').value, alpn: $('#s-alpn').value, ports, fragment: $('#s-frag').checked, flushMin: $('#s-flush').value }, 'تنظیمات ذخیره شد');
    }
    else if (act === 'pw-change') {
      const cur = $('#pw-cur').value, n1 = $('#pw-new').value, n2 = $('#pw-new2').value;
      if (n1 !== n2) { toast('تکرار رمز جدید یکسان نیست', true); return; }
      try { await api('password/change', { current: cur, next: n1 }); toast('رمز تغییر کرد'); $('#pw-cur').value = ''; $('#pw-new').value = ''; $('#pw-new2').value = ''; }
      catch (err) { toast(err.message, true); }
    }
    else if (act === 'pw-logout-all') {
      if (window.confirm('همه‌ی نشست‌های دیگر بسته می‌شوند. ادامه؟')) { try { await api('password/logout-all', {}); toast('انجام شد'); } catch (err) { toast(err.message, true); } }
    }
    else if (act === 'restore') {
      try {
        const txt = await fileText($('#restorefile'));
        let backup;
        try { backup = JSON.parse(txt); } catch (_) { throw new Error('فایل JSON معتبر نیست'); }
        if (window.confirm('کاربران و تنظیمات فعلی با محتوای فایل جایگزین می‌شود. ادامه؟')) await doAct('restore', { backup }, 'بازیابی انجام شد');
      } catch (err) { toast(err.message, true); }
    }
    else if (act === 'logout') { try { await api('logout', {}); } catch (_) {} location.reload(); }
  });

  api('state').then((j) => { S = j; render(); }).catch((e) => { $('#app').innerHTML = '<div class="boot" style="flex-direction:column;text-align:center;padding:20px"><span class="bad">' + esc(e.message) + '</span><button class="btn sm" data-act="retry">تلاش دوباره</button></div>'; });
}

function parseCookies(str) {
  const out = {};
  str.split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

async function sha256(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ================================ VLESS over WS ================================ */

// null = OK to use; otherwise a short reason ('expired' | 'quota').
// ---- user status page: /status/<subToken>/<uuid> (same two secrets as the subscription link) ----
// ---- decoy pages: what a stranger (or a scanner) sees when opening the domain ----
// The standard "Welcome to nginx!" page for the home page / unknown paths and nginx's own 404 page for wrong links.
const NGINX_HOME = '<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n\n<p>For online documentation and support please refer to\n<a href="http://nginx.org/">nginx.org</a>.<br/>\nCommercial support is available at\n<a href="http://nginx.com/">nginx.com</a>.</p>\n\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n';
const NGINX_404 = '<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n';
function decoyHome() {
  return new Response('Not Found', { status: 404 });
}
function decoyNotFound() {
  return new Response('Not Found', { status: 404 });
}

function escHtml(x) {
  return String(x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function handleStatus(request, env, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method not allowed', { status: 405 });
  const cfg = await getConfig(env);
  const parts = url.pathname.slice('/status/'.length).split('/');
  if (!safeEqual(parts[0], cfg.subToken)) return decoyNotFound();
  const u = cfg.users.find((x) => x.uuid === (parts[1] || '').toLowerCase());
  if (!u) return decoyNotFound();
  const used = Math.round((u.usedBytes || 0) + (pendingUsage.get(u.uuid) || 0));
  const days = [];
  for (let i = 13; i >= 0; i--) {
    const k = dayKey(Date.now() - i * DAY_MS);
    days.push([k, Math.round((u.daily && u.daily[k]) || 0)]);
  }
  const data = {
    name: u.name,
    status: checkUserStatus({ ...u, usedBytes: used }),
    used,
    quota: u.quotaBytes || null,
    expiresAt: u.expiresAt || null,
    expireAfterDays: !u.firstUsedAt && u.expireAfterDays ? u.expireAfterDays : null,
    maxDevices: u.maxDevices || null,
    days,
    base: `${url.origin}/sub/${cfg.subToken}/${u.uuid}`,
  };
  const body = statusPage(data);
  return new Response(request.method === 'HEAD' ? null : body, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex, nofollow',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    },
  });
}

function statusPage(data) {
  const json = JSON.stringify(data).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="light dark">
<title>وضعیت اشتراک ${escHtml(data.name)}</title><style>
:root{--bg:#f4f6fb;--card:#fff;--tx:#172033;--mu:#60708a;--bd:#dfe5f0;--ac:#2f5bea;--ok:#13875a;--bad:#c93a3a;--warn:#b7791f;--bar:#e6ebf5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1420;--card:#171e2e;--tx:#e8edf7;--mu:#97a6c0;--bd:#26304a;--ac:#7c9bff;--ok:#3fcf8e;--bad:#ff6b6b;--warn:#f2b84b;--bar:#26304a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.8 Tahoma,"Segoe UI",system-ui,sans-serif;padding:18px 14px 40px}
.w{max-width:560px;margin:0 auto}h1{font-size:19px;margin:6px 0 14px}h2{font-size:15px;margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:16px;margin-bottom:14px}
.badge{display:inline-block;padding:2px 12px;border-radius:99px;font-size:13px;font-weight:700;color:#fff}.b-ok{background:var(--ok)}.b-bad{background:var(--bad)}.b-warn{background:var(--warn)}
.row{display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px dashed var(--bd)}.row:last-child{border:0}.row span:first-child{color:var(--mu)}
.bar{height:12px;background:var(--bar);border-radius:99px;overflow:hidden;margin:8px 0}.bar i{display:block;height:100%;background:var(--ac);border-radius:99px}
.note{color:var(--mu);font-size:13px;margin:6px 0 0}code{display:block;direction:ltr;text-align:left;word-break:break-all;background:var(--bg);border:1px solid var(--bd);border-radius:10px;padding:8px 10px;font:12px/1.5 ui-monospace,Consolas,monospace;margin:8px 0}
button{font:inherit;cursor:pointer;border:1px solid var(--ac);background:var(--ac);color:#fff;border-radius:10px;padding:6px 14px;margin:2px 0 2px 6px}button.g{background:transparent;color:var(--ac)}
details{margin-top:8px}summary{cursor:pointer;color:var(--ac);padding:4px 0}.qr{text-align:center;margin-top:8px}.qr svg{max-width:210px;width:100%;height:auto;background:#fff;padding:6px;border-radius:10px}
.chart{display:flex;align-items:flex-end;gap:4px;height:80px;direction:ltr;margin-top:6px}.chart i{flex:1;background:var(--ac);border-radius:4px 4px 0 0;min-height:2px;opacity:.85}.lg{display:flex;justify-content:space-between;color:var(--mu);font-size:11px;direction:ltr}
</style></head><body><div class="w"><h1>وضعیت اشتراک <span id="nm"></span></h1><div id="app"></div></div>
<script>${QR_LIB}</script>
<script type="application/json" id="d">${json}</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('d').textContent),app=document.getElementById('app');
function e(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
var GB=1073741824;function fb(b){return b>=GB?(b/GB).toFixed(2)+' GB':(b/1048576).toFixed(b>=10485760?0:1)+' MB'}
function fd(t){try{return new Intl.DateTimeFormat('fa-IR-u-ca-persian',{dateStyle:'long'}).format(new Date(t))}catch(x){return new Date(t).toLocaleDateString()}}
document.getElementById('nm').textContent=D.name;
var st={disabled:['غیرفعال','b-bad'],expired:['منقضی‌شده','b-bad'],quota:['حجم تمام شده','b-bad']};
var badge=D.status?st[D.status]:['فعال','b-ok'];
var warn='';
if(!D.status&&D.quota&&D.used>=D.quota*0.9){badge=['رو به اتمام','b-warn']}
var now=Date.now(),left=D.expiresAt?Math.ceil((D.expiresAt-now)/86400000):null;
if(!D.status&&left!==null&&left<=3){badge=['رو به اتمام','b-warn']}
var rows='<div class="row"><span>وضعیت</span><span><span class="badge '+badge[1]+'">'+badge[0]+'</span></span></div>';
if(D.quota){var pct=Math.min(100,Math.round(D.used/D.quota*100)),rem=Math.max(0,D.quota-D.used);
rows+='<div class="row"><span>مصرف</span><span>'+fb(D.used)+' از '+fb(D.quota)+'</span></div>';
rows+='<div class="bar"><i style="width:'+pct+'%"></i></div><div class="row"><span>باقی‌مانده</span><span>'+fb(rem)+'</span></div>'}
else rows+='<div class="row"><span>مصرف</span><span>'+fb(D.used)+' (حجم نامحدود)</span></div>';
if(D.expiresAt){rows+='<div class="row"><span>پایان اعتبار</span><span>'+fd(D.expiresAt)+(left>0?' ('+left.toLocaleString('fa-IR')+' روز مانده)':'')+'</span></div>'}
else if(D.expireAfterDays){rows+='<div class="row"><span>اعتبار</span><span>'+D.expireAfterDays.toLocaleString('fa-IR')+' روز پس از اولین اتصال</span></div>'}
else rows+='<div class="row"><span>اعتبار</span><span>بدون محدودیت زمانی</span></div>';
if(D.maxDevices)rows+='<div class="row"><span>دستگاه هم‌زمان</span><span>حداکثر '+D.maxDevices.toLocaleString('fa-IR')+'</span></div>';
var h='<div class="card">'+rows+'<p class="note">مصرف تقریبی است و تا حدود یک دقیقه تأخیر دارد.</p></div>';
var mx=0;D.days.forEach(function(x){if(x[1]>mx)mx=x[1]});
if(mx>0){h+='<div class="card"><h2>مصرف ۱۴ روز اخیر</h2><div class="chart">'+D.days.map(function(x){return'<i title="'+e(x[0])+': '+fb(x[1])+'" style="height:'+Math.max(3,Math.round(x[1]/mx*100))+'%"></i>'}).join('')+'</div><div class="lg"><span>'+e(D.days[0][0].slice(5))+'</span><span>'+e(D.days[13][0].slice(5))+'</span></div></div>'}
function blk(t,u){return'<div class="lk"><p class="note"><b>'+e(t)+'</b></p><code>'+e(u)+'</code><button data-c="'+e(u)+'">کپی</button><button class="g" data-q="'+e(u)+'">بارکد</button><div class="qr" hidden></div></div>'}
if(D.status==='disabled'){h+='<div class="card"><p>این اشتراک غیرفعال است. برای فعال‌سازی با پشتیبان خود تماس بگیرید.</p></div>'}
else{
h+='<div class="card"><h2>لینک اشتراک</h2>'+blk('لینک اصلی (برای بیشتر برنامه‌ها)',D.base)+
'<p class="note">در برنامه، گزینه‌ی افزودن «اشتراک / Subscription» را بزنید و این لینک را بچسبانید. اگر آی‌پی‌ها یا تنظیمات عوض شد، اشتراک را در برنامه به‌روزرسانی کنید.</p>'+
'<details><summary>فرمت‌ها و روش‌های دیگر</summary>'+
blk('Clash',D.base+'?format=clash')+blk('sing-box',D.base+'?format=singbox')+'</details></div>'}
app.innerHTML=h;
function copy(t,b){function ok(){var o=b.textContent;b.textContent='کپی شد ✓';setTimeout(function(){b.textContent=o},1400)}
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok,fb2)}else fb2();
function fb2(){var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();try{document.execCommand('copy');ok()}catch(x){}document.body.removeChild(a)}}
app.addEventListener('click',function(ev){var b=ev.target.closest('button');if(!b)return;
if(b.dataset.c)copy(b.dataset.c,b);
else if(b.dataset.q){var box=b.parentNode.querySelector('.qr');if(!box.hidden){box.hidden=true;return}
try{var q=qrcode(0,'M');q.addData(b.dataset.q);q.make();box.innerHTML=q.createSvgTag({cellSize:5,margin:4});box.hidden=false}catch(x){}}});
})();
</script></body></html>`;
}

function checkUserStatus(user) {
  if (user.disabled) return 'disabled';
  if (user.expiresAt && Date.now() > user.expiresAt) return 'expired';
  if (user.quotaBytes && (user.usedBytes || 0) >= user.quotaBytes) return 'quota';
  return null;
}

// Panel-only hint: about to run out (>=90% of quota, or expiry within 3 days).
function userWarn(user) {
  const now = Date.now();
  if (user.quotaBytes && (user.usedBytes || 0) >= user.quotaBytes * 0.9) return 'quota';
  if (user.expiresAt && user.expiresAt > now && user.expiresAt - now < 3 * DAY_MS) return 'expiry';
  return null;
}

// Usage accounting is buffered per Worker instance and written to KV at most once a minute
// (a KV write per closed connection would exhaust the free daily write limit and hit KV's
// one-write-per-second-per-key limit). Consequences: the persisted total can lag by up to a
// minute (or until the next connection closes) and a recycled instance loses its unflushed bytes.
// Quota is still enforced live during a transfer (see trackBytes).
const pendingUsage = new Map(); // uuid -> bytes not yet persisted
const coloPending = new Map(); // colo -> { conns, ok, fail, relay, lastErr, hosts: { name: [ok, fail] } } not yet persisted

function watchName(host) {
  const h = String(host || '').toLowerCase();
  for (const w of WATCH_SITES) if (h === w || h.endsWith('.' + w)) return w;
  return 'other';
}

function recordColo(colo, host, ok, viaRelay, err) {
  const c = String(colo || '?').toUpperCase().slice(0, 8);
  let e = coloPending.get(c);
  if (!e) { e = { conns: 0, ok: 0, fail: 0, relay: 0, lastErr: '', hosts: {} }; coloPending.set(c, e); }
  e.conns++;
  if (ok) e.ok++; else { e.fail++; e.lastErr = String(err || 'error').slice(0, 60); }
  if (viaRelay) e.relay++;
  const w = watchName(host);
  const hs = (e.hosts[w] = e.hosts[w] || [0, 0]);
  hs[ok ? 0 : 1]++;
}

// Flush now if the once-a-minute window is open; otherwise make sure a delayed flush is armed so
// bytes counted just after a flush are not left waiting for some future connection to close.
let flushTimer = null;

function flushInterval() {
  const base = Math.max(1, (cache.value && cache.value.flushMin) || DEFAULT_FLUSH_MIN) * 60000;
  // The busier the day has been for KV writes, the rarer the write-backs become.
  const w = todayWrites;
  const r = w / WRITE_LIMIT;
  return base * (r >= 0.7 ? 12 : r >= 0.45 ? 4 : r >= 0.25 ? 2 : 1);
}

function nextFlushDelay() {
  return Math.max(lastUsageFlush + flushInterval() - Date.now(), flushBackoffUntil - Date.now(), 0);
}

function armFlush(env) {
  if (flushTimer) return;
  flushTimer = setTimeout(() => { flushTimer = null; flushPending(env); }, nextFlushDelay());
}

function scheduleFlush(env, ctx) {
  if (usageFlushing || nextFlushDelay() > 0) { armFlush(env); return; }
  const p = flushPending(env);
  if (ctx && ctx.waitUntil) ctx.waitUntil(p);
}
let lastUsageFlush = Date.now(); // a fresh instance waits a full interval before its first write
let usageFlushing = false;
let todayWrites = 0;            // KV writes counted today (all instances), as of the last write-back
let flushBackoffUntil = 0;      // after a failed write-back (e.g. quota exhausted) wait before retrying

function queueUsage(env, ctx, uuid, bytes) {
  if (!bytes) return;
  pendingUsage.set(uuid, (pendingUsage.get(uuid) || 0) + bytes);
  scheduleFlush(env, ctx);
}

async function flushPending(env) {
  if (usageFlushing || (!pendingUsage.size && !coloPending.size)) return;
  usageFlushing = true;
  const batch = new Map(pendingUsage);
  pendingUsage.clear();
  const colos = new Map(coloPending);
  coloPending.clear();
  const ops = { w: kvOps.w, r: kvOps.r, q: kvOps.q };
  kvOps.w = 0; kvOps.r = 0; kvOps.q = 0;
  lastUsageFlush = Date.now();
  try {
    const cfg = await getConfig(env, true);
    const d = dayKey();
    for (const [uuid, bytes] of batch) {
      const u = cfg.users.find((x) => x.uuid === uuid);
      if (!u) continue;
      u.usedBytes = (u.usedBytes || 0) + bytes;
      u.daily = u.daily || {};
      u.daily[d] = (u.daily[d] || 0) + bytes;
      pruneDaily(u);
    }
    if (colos.size) {
      const st = cfg.stats = cfg.stats && cfg.stats.colos ? cfg.stats : { since: Date.now(), colos: {} };
      for (const [c, e] of colos) {
        const t = (st.colos[c] = st.colos[c] || { conns: 0, ok: 0, fail: 0, relay: 0, lastErr: '', lastErrAt: 0, hosts: {} });
        t.conns += e.conns; t.ok += e.ok; t.fail += e.fail; t.relay += e.relay;
        if (e.lastErr) { t.lastErr = e.lastErr; t.lastErrAt = Date.now(); }
        for (const [w, v] of Object.entries(e.hosts)) {
          const h = (t.hosts[w] = t.hosts[w] || [0, 0]);
          h[0] += v[0]; h[1] += v[1];
        }
      }
      const keys = Object.keys(st.colos);
      if (keys.length > MAX_COLOS) {
        keys.sort((a, b) => st.colos[a].conns - st.colos[b].conns);
        for (const k of keys.slice(0, keys.length - MAX_COLOS)) delete st.colos[k];
      }
    }
    // daily KV operation totals (this Worker's own operations; see the gauge in the panel)
    const st2 = cfg.stats = cfg.stats && cfg.stats.colos ? cfg.stats : { since: Date.now(), colos: {} };
    st2.kv = st2.kv && typeof st2.kv === 'object' ? st2.kv : {};
    const k = (st2.kv[d] = st2.kv[d] || { w: 0, r: 0 });
    k.w += ops.w; k.r += ops.r; k.q = (k.q || 0) + ops.q;
    for (const key of Object.keys(st2.kv).sort().slice(0, -KV_DAYS_KEEP)) delete st2.kv[key];
    todayWrites = k.w + 1;
    await saveConfig(env, cfg);
  } catch (_) {
    for (const [uuid, bytes] of batch) pendingUsage.set(uuid, (pendingUsage.get(uuid) || 0) + bytes);
    for (const [c, e] of colos) if (!coloPending.has(c)) coloPending.set(c, e);
    kvOps.w += ops.w; kvOps.r += ops.r; kvOps.q += ops.q;
    flushBackoffUntil = Date.now() + 15 * 60000;
  } finally {
    usageFlushing = false;
  }
}

// Expiry that starts at the first connection ("N days from first use").
async function markFirstUse(env, uuid, ts) {
  try {
    const cfg = await getConfig(env, true);
    const u = cfg.users.find((x) => x.uuid === uuid);
    if (u && u.expireAfterDays && !u.firstUsedAt) {
      u.firstUsedAt = ts;
      u.expiresAt = ts + u.expireAfterDays * DAY_MS;
      await saveConfig(env, cfg);
    }
  } catch (_) {}
}

// Simultaneous-device limit. Devices are counted as distinct client IPs with an open (or very
// recent) connection. Best-effort: tracked per Worker instance, so it cannot be exact worldwide,
// and several devices behind one NAT/hotspot count as one.
const deviceMap = new Map(); // uuid -> Map(ip -> { n, last })

function deviceAcquire(user, ip) {
  if (!user.maxDevices) return true;
  let m = deviceMap.get(user.uuid);
  if (!m) { m = new Map(); deviceMap.set(user.uuid, m); }
  const now = Date.now();
  for (const [k, v] of m) if (v.n <= 0 && now - v.last > 120000) m.delete(k);
  let e = m.get(ip);
  if (!e) {
    if (m.size >= user.maxDevices) return false;
    e = { n: 0, last: now };
    m.set(ip, e);
  }
  e.n++; e.last = now;
  return true;
}

function deviceRelease(user, ip) {
  const m = deviceMap.get(user.uuid);
  const e = m && m.get(ip);
  if (e) { e.n = Math.max(0, e.n - 1); e.last = Date.now(); }
}

/* ------------------------- Connection quality statistics ------------------------- */

const wsStats = { since: Date.now(), conns: 0, ok: 0, fail: 0, rejected: 0 };
const proxyStats = new Map(); // "addr:port" -> { ok, fail, consec, ms, lastOk, lastFail } (per Worker instance)

function proxyKey(a, p) { return a + ':' + (p || ''); }

function recordProxy(key, ok, ms) {
  if (proxyStats.size > 500) proxyStats.clear();
  const s = proxyStats.get(key) || { ok: 0, fail: 0, consec: 0, ms: null, lastOk: 0, lastFail: 0 };
  if (ok) {
    s.ok++; s.consec = 0; s.lastOk = Date.now();
    if (Number.isFinite(ms)) s.ms = s.ms == null ? ms : Math.round(s.ms * 0.7 + ms * 0.3);
  } else {
    s.fail++; s.consec++; s.lastFail = Date.now();
  }
  proxyStats.set(key, s);
}

// Fastest known relays first, unknown ones next, recently failing ones last.
function proxyRank(list) {
  const now = Date.now();
  const score = ([a, p]) => {
    const s = proxyStats.get(proxyKey(a, p));
    if (!s) return 1500;
    if (s.consec >= 3 && now - s.lastFail < PROXY_BAD_TTL) return 1e6;
    return (s.ms == null ? 1500 : s.ms) + s.consec * 800;
  };
  return list.map((x, i) => [x, i]).sort((p, q) => score(p[0]) - score(q[0]) || p[1] - q[1]).map((x) => x[0]);
}

function handleWebSocket(request, env, cfg, ctx) {
  const usersById = new Map(cfg.users.map((u) => [u.uuid.replace(/-/g, ''), u]));
  const colo = (request.cf && request.cf.colo) || '';
  const hasProxy = globalThis.__RAILWAY ? false :
    buildProxyEntries(cfg, env, colo).length > 0 ||
    (cfg.proxyMode !== 'off' && cfg.cleanIpEnabled && splitList(cfg.cleanIpUrls).length > 0);

  let client = null;
  let server;
  {
    [client, server] = Object.values(new WebSocketPair());
    // compat date >= 2026-03-17 delivers binary frames as Blob by default; force ArrayBuffer (before accept)
    server.binaryType = 'arraybuffer';
    try { server.accept({ allowHalfOpen: true }); } catch (_) { server.accept(); }
  }

  let remoteSocket = null;
  let remoteWriter = null;
  let udpHandler = null;
  let switching = null;
  let closed = false;
  let activeUser = null;
  let bytesThisConn = 0;
  let deviceHeld = null;
  let marked = false;
  const markResult = (h, ok, via, err) => {
    if (marked) return;
    marked = true;
    recordColo(colo, h.address, ok, via, err);
    armFlush(env);
  };
  const onData = (h, via, n) => { markResult(h, true, via); trackBytes(n); };
  const onEnd = (h, via) => () => { markResult(h, false, via, 'no response'); closeAll(); };
  let rankedProxies = null;
  let lastRecheck = Date.now();
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  const tr = 'ws';
  const connT0 = Date.now();
  const dlog = (st, m) => diagLog(env, ctx, tr, st, m);
  dlog('start', ((request.cf && request.cf.httpProtocol) || '?') + ' colo=' + (colo || '?') + ' ip=' + maskIp(clientIp) + ' ct=' + ((request.headers.get('content-type') || '-').slice(0, 40)));

  // Checked on every chunk in both directions so a quota is enforced mid-transfer, not just
  // at connection start. The persisted usedBytes total is only reconciled at connection close
  // (see flushUsage) - see the code comment there for why this can't be perfectly real-time.
  // Long-lived connections would otherwise keep working after the user was disabled, deleted or
  // expired in the panel (the user object was captured when the connection was opened).
  // Re-validate against the (cached) config about once a minute.
  function recheckUser() {
    if (!activeUser || closed || Date.now() - lastRecheck < 60000) return;
    lastRecheck = Date.now();
    getConfig(env).then((c) => {
      const fresh = c.users.find((x) => x.uuid === activeUser.uuid);
      if (!fresh || checkUserStatus(fresh)) { wsStats.rejected++; closeAll(); return; }
      activeUser = fresh;
    }).catch(() => {});
  }

  function trackBytes(n) {
    bytesThisConn += n;
    recheckUser();
    if (activeUser && activeUser.expiresAt && Date.now() > activeUser.expiresAt) { closeAll(); return; }
    if (activeUser && activeUser.quotaBytes && (activeUser.usedBytes || 0) + (pendingUsage.get(activeUser.uuid) || 0) + bytesThisConn >= activeUser.quotaBytes) {
      closeAll();
    }
  }

  const closeAll = () => {
    if (closed) return;
    closed = true;
    dlog('end', 'bytes=' + bytesThisConn + ' ' + Math.round((Date.now() - connT0) / 1000) + 's' + (activeUser ? ' user=' + activeUser.name : ' (no valid user)'));
    try { remoteSocket && remoteSocket.close(); } catch (_) {}
    try { server.close(1000, 'closed'); } catch (_) {}
    if (deviceHeld) { deviceRelease(deviceHeld.user, deviceHeld.ip); deviceHeld = null; }
    if (activeUser && bytesThisConn > 0) queueUsage(env, ctx, activeUser.uuid, bytesThisConn);
  };

  async function openRemote(host, port, payload, timeoutMs) {
    const sock = connect({ hostname: host, port });
    try {
      await withTimeout(sock.opened, timeoutMs, 'connect timeout');
      const writer = sock.writable.getWriter();
      const prev = remoteSocket;
      remoteSocket = sock;
      remoteWriter = writer;
      if (prev && prev !== sock) { try { prev.close(); } catch (_) {} }
      if (payload && payload.byteLength) {
        await writer.write(payload);
        trackBytes(payload.byteLength);
      }
      return sock;
    } catch (e) {
      try { sock.close(); } catch (_) {}
      throw e;
    }
  }

  // Try relay candidates in order. Returns true when one was connected.
  async function tryProxies(h, from, budget) {
    if (budget <= 0) return false;
    if (!rankedProxies) rankedProxies = proxyRank((await getProxies(cfg, env, colo)).list);
    const list = rankedProxies;
    let tries = 0;
    for (let k = from; k < list.length && tries < budget; k++, tries++) {
      const [addr, p] = list[k];
      try {
        const t0 = Date.now();
        const key = proxyKey(addr, p);
        const sock = await openRemote(addr, p || h.port, h.payload, PROXY_TIMEOUT);
        const left = budget - tries - 1;
        let first = false;
        // A relay only counts as good once it actually returns data (connecting alone proves little).
        pipeRemoteToWs(
          sock, server, h.version,
          () => { recordProxy(key, false); return retryViaProxies(h, k + 1, left); },
          onEnd(h, true),
          (n) => { if (!first) { first = true; recordProxy(key, true, Date.now() - t0); } onData(h, true, n); }
        );
        return true;
      } catch (e) {
        recordProxy(proxyKey(addr, p), false);
        console.log('proxy candidate failed:', addr, e && e.message ? e.message : e);
      }
    }
    return false;
  }

  function retryViaProxies(h, from, budget) {
    switching = tryProxies(h, from, budget).finally(() => { switching = null; });
    return switching;
  }

  async function connectSequence(h) {
    let lastErr = null;
    if (!hasProxy || !isDirectBlocked(h.address)) {
      try {
        const sock = await openRemote(h.address, h.port, h.payload, DIRECT_TIMEOUT);
        pipeRemoteToWs(sock, server, h.version, hasProxy ? () => retryViaProxies(h, 0, MAX_PROXY_TRIES) : null, onEnd(h, false), (n) => onData(h, false, n));
        return;
      } catch (e) {
        lastErr = e;
        if (!hasProxy) throw e;
        markDirectFail(h.address);
      }
    }
    const ok = await tryProxies(h, 0, MAX_PROXY_TRIES);
    if (!ok) throw lastErr || new Error('no working relay for ' + h.address);
  }

  async function onChunk(data) {
    if (closed) return;
    if (switching) await switching;

    if (udpHandler) {
      await udpHandler(data);
      return;
    }
    if (remoteWriter) {
      trackBytes(data.byteLength);
      await remoteWriter.write(data);
      return;
    }

    const h = parseVless(data, usersById);
    if (h.error) throw new Error(h.error);
    dlog('vless', h.address + ':' + h.port + (h.isUdp ? ' udp' : ''));

    const user = usersById.get(h.id);
    const status = user ? checkUserStatus(user) : 'invalid';
    if (status) { wsStats.rejected++; throw new Error('user ' + status); }
    if (!deviceAcquire(user, clientIp)) { wsStats.rejected++; throw new Error('device limit'); }
    deviceHeld = { user, ip: clientIp };
    activeUser = user;
    if (user.expireAfterDays && !user.firstUsedAt) {
      user.firstUsedAt = Date.now();
      user.expiresAt = user.firstUsedAt + user.expireAfterDays * DAY_MS;
      const fp = markFirstUse(env, user.uuid, user.firstUsedAt);
      if (ctx && ctx.waitUntil) ctx.waitUntil(fp);
    }

    // UDP: only DNS (port 53) is supported, forwarded over DoH
    if (h.isUdp) {
      if (h.port !== 53) throw new Error('UDP is only supported for DNS (port 53)');
      udpHandler = createDnsHandler(server, h.version);
      if (h.payload.byteLength) await udpHandler(h.payload);
      return;
    }

    wsStats.conns++;
    try { await connectSequence(h); wsStats.ok++; dlog('connect-ok', h.address + ':' + h.port); } catch (e) { wsStats.fail++; markResult(h, false, hasProxy, (e && e.message) || 'connect failed'); throw e; }
  }

  // Process messages sequentially to avoid race conditions
  let queue = Promise.resolve();
  const enqueue = (data) => {
    queue = queue
      .then(async () => onChunk(await toBytes(data)))
      .catch((e) => {
        console.log('vless error:', e && e.message ? e.message : e);
        dlog('error', (e && e.message) || String(e));
        closeAll();
      });
  };

  server.addEventListener('message', (event) => {
    const d = event.data;
    if (typeof d === 'string') return;
    enqueue(d);
  });
  server.addEventListener('close', closeAll);
  server.addEventListener('error', closeAll);

  // Only treat the header as early data if it really is a VLESS header for one of our UUIDs
  // (some clients send plain subprotocol names such as "binary" in this header).
  const early = decodeEarlyData(request.headers.get('sec-websocket-protocol'));
  if (early && early.byteLength >= 24) {
    const id = Array.from(early.slice(1, 17)).map((x) => x.toString(16).padStart(2, '0')).join('');
    if (usersById.has(id)) enqueue(early);
  }

  return { status: 101, webSocket: client, headers: new Headers() }; // Node's Response cannot have status 101
}

// Normalise whatever the runtime hands us (ArrayBuffer, Blob, typed array) to Uint8Array.
async function toBytes(d) {
  if (d instanceof Uint8Array) return d;
  if (d instanceof ArrayBuffer) return new Uint8Array(d);
  if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  if (typeof Blob !== 'undefined' && d instanceof Blob) return new Uint8Array(await d.arrayBuffer());
  return new Uint8Array(0);
}

// onEmpty() may return a promise resolving to true when it took over (e.g. reconnected via a relay)
async function pipeRemoteToWs(remote, ws, version, onEmpty, closeAll, onBytes) {
  let header = new Uint8Array([version, 0]);
  let gotData = false;

  try {
    await remote.readable.pipeTo(
      new WritableStream({
        write(chunk) {
          gotData = true;
          if (onBytes) onBytes(chunk.byteLength);
          if (ws.readyState !== 1) return;
          if (header) {
            const out = new Uint8Array(header.length + chunk.byteLength);
            out.set(header, 0);
            out.set(chunk, header.length);
            ws.send(out);
            header = null;
          } else {
            ws.send(chunk);
          }
        },
      })
    );
  } catch (_) {}

  if (!gotData && onEmpty) {
    try { if (await onEmpty()) return; } catch (_) {}
  }
  closeAll();
}

// UDP DNS over VLESS: payload is [2-byte length][DNS query] repeated.
// Each query is forwarded to a DoH server and answered in the same framing.
function createDnsHandler(ws, version) {
  let headerSent = false;
  let buf = new Uint8Array(0);

  return async (chunk) => {
    const merged = new Uint8Array(buf.length + chunk.length);
    merged.set(buf, 0);
    merged.set(chunk, buf.length);
    buf = merged;

    while (buf.length >= 2) {
      const len = (buf[0] << 8) | buf[1];
      if (buf.length < 2 + len) break;
      const query = buf.slice(2, 2 + len);
      buf = buf.slice(2 + len);

      let answer;
      try {
        const resp = await fetch(DOH, {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
          body: query,
          signal: AbortSignal.timeout(5000),
        });
        if (!resp.ok) continue; // drop this query (the client retries) but keep the connection
        answer = new Uint8Array(await resp.arrayBuffer());
      } catch (_) {
        continue;
      }

      const prefix = headerSent ? 0 : 2;
      const out = new Uint8Array(prefix + 2 + answer.length);
      if (!headerSent) {
        out[0] = version;
        out[1] = 0;
        headerSent = true;
      }
      out[prefix] = (answer.length >> 8) & 0xff;
      out[prefix + 1] = answer.length & 0xff;
      out.set(answer, prefix + 2);

      if (ws.readyState === 1) ws.send(out);
    }
  };
}

function parseVless(buf, usersById) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (b.length < 24) return { error: 'header too short' };

  const version = b[0];
  const id = Array.from(b.slice(1, 17)).map((x) => x.toString(16).padStart(2, '0')).join('');
  if (!usersById.has(id)) return { error: 'invalid uuid' };

  const addonLen = b[17];
  let i = 18 + addonLen;

  const cmd = b[i++];
  if (cmd !== 1 && cmd !== 2) return { error: 'unsupported command ' + cmd };

  const port = (b[i] << 8) | b[i + 1];
  i += 2;

  const atype = b[i++];
  let address = '';

  if (atype === 1) {
    address = Array.from(b.slice(i, i + 4)).join('.');
    i += 4;
  } else if (atype === 2) {
    const len = b[i++];
    address = new TextDecoder().decode(b.slice(i, i + len));
    i += len;
  } else if (atype === 3) {
    const parts = [];
    for (let k = 0; k < 8; k++) parts.push(((b[i + k * 2] << 8) | b[i + k * 2 + 1]).toString(16));
    address = parts.join(':');
    i += 16;
  } else {
    return { error: 'unknown address type' };
  }

  if (!address) return { error: 'empty address' };
  if (i > b.length || !port) return { error: 'truncated header' };
  return { version, id, address, port, payload: b.slice(i), isUdp: cmd === 2 };
}

function decodeEarlyData(s) {
  if (!s) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch (_) {
    return null;
  }
}
