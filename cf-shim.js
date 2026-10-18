// Replacements for the Cloudflare-only APIs the Worker uses, built on plain Node.js:
//   connect()      (cloudflare:sockets)  -> net / tls
//   WebSocketPair  (Workers runtime)     -> small EventTarget bridged to a real "ws" socket by server.js
import net from 'node:net';
import tls from 'node:tls';
import { Readable, Writable } from 'node:stream';
import { webcrypto } from 'node:crypto';

globalThis.__RAILWAY = true; // worker.js: no ProxyIP relays, subscription links use only this domain
if (!globalThis.crypto) globalThis.crypto = webcrypto;

function wrap(sock, tlsMode) {
  let r = null, w = null;
  const opened = new Promise((res, rej) => {
    sock.once(tlsMode ? 'secureConnect' : 'connect', () => res({}));
    sock.once('error', rej);
  });
  opened.catch(() => {});
  const closed = new Promise((res) => sock.once('close', () => res()));
  sock.on('error', () => {}); // errors surface through the streams / "opened"; never crash the process
  sock.setNoDelay(true);
  return {
    opened,
    closed,
    get readable() { return (r ||= Readable.toWeb(sock)); },
    get writable() { return (w ||= Writable.toWeb(sock)); },
    close() {
      if (sock.destroyed) return;
      if (sock.connecting) { sock.destroy(); return; }
      try { sock.end(); } catch (_) {}
      setTimeout(() => sock.destroy(), 5000).unref();
    },
    startTls(o = {}) {
      const t = tls.connect({ socket: sock, servername: o.expectedServerHostname });
      return wrap(t, true);
    },
  };
}

export function connect(addr, opts = {}) {
  const host = String(addr.hostname).replace(/^\[|\]$/g, '');
  const sock = net.connect({ host, port: Number(addr.port) });
  const s = wrap(sock, false);
  if (opts && opts.secureTransport === 'on') return wrap(tls.connect({ host, port: Number(addr.port), servername: host }), true);
  return s;
}

class WsEnd extends EventTarget {
  constructor() {
    super();
    this.binaryType = 'arraybuffer';
    this._ws = null;
    this._q = [];
    this._closed = false;
  }
  accept() {}
  get readyState() { return this._closed ? 3 : 1; }
  send(d) {
    if (this._closed) return;
    if (this._ws) { if (this._ws.readyState === 1) this._ws.send(d); } else this._q.push(d);
  }
  close(code, reason) {
    if (this._closed) return;
    this._closed = true;
    if (!this._ws) return;
    try { this._ws.close(code && code !== 1005 && code !== 1006 ? code : 1000, String(reason || '').slice(0, 100)); } catch (_) { try { this._ws.terminate(); } catch (_) {} }
  }
  _attach(ws) {
    this._ws = ws;
    ws.on('message', (data, isBinary) => {
      let d;
      if (isBinary) {
        const b = Buffer.isBuffer(data) ? data : Buffer.concat([].concat(data));
        d = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
      } else d = data.toString();
      this.dispatchEvent(new MessageEvent('message', { data: d }));
    });
    const end = (type) => () => {
      if (type === 'close' && this._closed === 'done') return;
      this._closed = this._closed || true;
      this.dispatchEvent(new Event(type));
    };
    ws.on('close', end('close'));
    ws.on('error', end('error'));
    for (const d of this._q.splice(0)) this.send(d);
    if (this._closed) this.close(1000, 'closed');
  }
}

globalThis.WebSocketPair = class WebSocketPair {
  constructor() {
    this[0] = new WsEnd(); // client end (only used as a token for server.js)
    this[1] = this[0];     // server end: the Worker talks to this one
  }
};
