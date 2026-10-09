// ============================================================
// TGProxyNode — Telegram Web Proxy on Cloudflare Workers
// Version: 8.0.0
// Multi-proxy · single worker · Persian bot · t.me/webproxy
// ============================================================

import { connect } from "cloudflare:sockets";

export const VERSION = "8.0.0";
export const BRAND = "TGProxyNode";
export const TAGLINE = "Telegram Proxy Node on the Edge";

// ============================================================
// protocol.js
// ============================================================
const FRAME = Object.freeze({
  OPEN: 0x01, DATA: 0x02, CLOSE: 0x03, WINDOW: 0x04,
  PING: 0x05, PONG: 0x06, HELLO: 0x10, WELCOME: 0x11, BYE: 0x1f,
});
const HEADER_SIZE = 8;
const MAX_PAYLOAD = 1024 * 1024;
const MAX_BATCH_FRAMES = 4096;
const INITIAL_WINDOW = 4 * 1024 * 1024;
const DATA_CHUNK = 64 * 1024;
const MAX_WS_MESSAGE = 2 * 1024 * 1024;

function encodeFrame(type, streamId, payload = new Uint8Array()) {
  if (streamId < 0 || streamId > 0xffffff || payload.length > MAX_PAYLOAD) throw new Error("invalid frame");
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out[0] = type; out[1] = streamId >>> 16; out[2] = streamId >>> 8; out[3] = streamId;
  new DataView(out.buffer).setUint32(4, payload.length);
  out.set(payload, HEADER_SIZE);
  return out;
}
function parseFrames(input) {
  const frames = []; let offset = 0;
  while (offset < input.length) {
    if (frames.length >= MAX_BATCH_FRAMES || input.length - offset < HEADER_SIZE) throw new Error("bad batch");
    const view = new DataView(input.buffer, input.byteOffset + offset, HEADER_SIZE);
    const length = view.getUint32(4);
    if (length > MAX_PAYLOAD || offset + HEADER_SIZE + length > input.length) throw new Error("bad payload");
    frames.push({
      type: input[offset],
      streamId: (input[offset + 1] << 16) | (input[offset + 2] << 8) | input[offset + 3],
      payload: input.subarray(offset + HEADER_SIZE, offset + HEADER_SIZE + length),
    });
    offset += HEADER_SIZE + length;
  }
  if (!frames.length) throw new Error("empty batch");
  return frames;
}
function u32(v) { const o = new Uint8Array(4); new DataView(o.buffer).setUint32(0, v); return o; }
function clampInt(v, min, max, fb) { const n = Number.parseInt(v, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fb; }

// ============================================================
// mtproxy.js
// ============================================================
const TAGS = new Set([0xefefefef, 0xeeeeeeee, 0xdddddddd]);
const TELEGRAM_DCS = Object.freeze({
  1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100",
  4: "149.154.167.91", 5: "149.154.171.5",
});
class AesCtrStream {
  constructor(k, iv) {
    if (k.length !== 32 || iv.length !== 16) throw new Error("bad AES material");
    this.keyPromise = crypto.subtle.importKey("raw", k, "AES-CTR", false, ["encrypt"]);
    this.counter = new Uint8Array(iv); this.spare = new Uint8Array();
  }
  async crypt(input) {
    const src = input instanceof Uint8Array ? input : new Uint8Array(input);
    const out = new Uint8Array(src.length); let pos = 0;
    if (this.spare.length) {
      const n = Math.min(this.spare.length, src.length);
      for (let i = 0; i < n; i++) out[i] = src[i] ^ this.spare[i];
      this.spare = this.spare.subarray(n); pos = n;
    }
    if (pos < src.length) {
      const need = src.length - pos, blocks = Math.ceil(need / 16);
      const zeros = new Uint8Array(blocks * 16);
      const key = await this.keyPromise;
      const ks = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: this.counter, length: 128 }, key, zeros));
      addBlocks(this.counter, blocks);
      for (let i = 0; i < need; i++) out[pos + i] = src[pos + i] ^ ks[i];
      if (need < ks.length) this.spare = ks.subarray(need);
    }
    return out;
  }
}
function addBlocks(c, blocks) {
  let carry = blocks;
  for (let i = 15; i >= 0 && carry; i--) {
    const sum = c[i] + (carry & 255); c[i] = sum & 255;
    carry = Math.floor(carry / 256) + (sum >>> 8);
  }
}
function reverse(b) { return Uint8Array.from(b).reverse(); }
function concat(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }
async function sha256(b) { return new Uint8Array(await crypto.subtle.digest("SHA-256", b)); }
function parseProxySecret(value) {
  const s = String(value || "").toLowerCase();
  if (/^[0-9a-f]{32}$/.test(s)) return { bridge: hex(s), inner: hex(s), mode: "plain" };
  if (/^dd[0-9a-f]{32}$/.test(s)) return { bridge: hex(s), inner: hex(s.slice(2)), mode: "dd" };
  if (/^ee/.test(s)) throw new Error("FakeTLS secrets are not supported in WEB mode");
  throw new Error("PROXY_SECRET must be 32 hex characters, optionally prefixed with dd");
}
function hex(s) { const x = new Uint8Array(s.length / 2); for (let i = 0; i < x.length; i++) x[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16); return x; }
async function acceptClientHandshake(packet, secret) {
  if (packet.length !== 64) throw new Error("bad handshake length");
  const material = packet.subarray(8, 56), rev = reverse(material);
  const decKey = await sha256(concat(material.subarray(0, 32), secret));
  const dec = new AesCtrStream(decKey, material.subarray(32, 48));
  const encKey = await sha256(concat(rev.subarray(0, 32), secret));
  const enc = new AesCtrStream(encKey, rev.subarray(32, 48));
  const plain = await dec.crypt(packet);
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const tag = view.getUint32(56, true), dcId = view.getInt16(60, true);
  if (!TAGS.has(tag) || !TELEGRAM_DCS[Math.abs(dcId)]) throw new Error("invalid MTProxy handshake");
  return { tag, dcId, clientDecrypt: dec, clientEncrypt: enc };
}
async function createTelegramHandshake(tag, dcId) {
  let nonce;
  do { nonce = new Uint8Array(64); crypto.getRandomValues(nonce); } while (reserved(nonce));
  const v = new DataView(nonce.buffer); v.setUint32(56, tag, true); v.setInt16(60, dcId, true); nonce[62] = nonce[63] = 0;
  const material = nonce.subarray(8, 56), rev = reverse(material);
  const encrypt = new AesCtrStream(material.subarray(0, 32), material.subarray(32, 48));
  const decrypt = new AesCtrStream(rev.subarray(0, 32), rev.subarray(32, 48));
  const encrypted = await encrypt.crypt(nonce);
  const wire = new Uint8Array(nonce); wire.set(encrypted.subarray(56), 56);
  return { wire, encrypt, decrypt };
}
function reserved(n) {
  const v = new DataView(n.buffer, n.byteOffset, n.byteLength), x = v.getUint32(0, true);
  return n[0] === 0xef || x === 0x44414548 || x === 0x54534f50 || x === 0x20544547 ||
         x === 0xeeeeeeee || x === 0xdddddddd || v.getUint32(4, true) === 0;
}

// ============================================================
// session.js
// ============================================================
const LIMITS = Object.freeze({
  itemCost: 256,
  ingressBytes: 8 * 1024 * 1024, ingressItems: 128,
  uplinkBytes: 8 * 1024 * 1024, uplinkItems: 8192,
  streamBytes: INITIAL_WINDOW + 1024 * 1024, streamItems: 4096,
  downlinkBytes: 8 * 1024 * 1024, downlinkItems: 8192,
  handshakeTimeout: 15000, connectTimeout: 10000, writeTimeout: 30000,
});
class RelaySession {
  constructor(ctx, env, connectFn) {
    this.ctx = ctx; this.env = env; this.connect = connectFn;
    this.initialized = false; this.closed = false; this.ws = null;
    this.streams = new Map(); this.closedIds = new Set();
    this.maxStreams = clampInt(env.MAX_STREAMS, 1, 128, 64);
    this.messageChain = Promise.resolve();
    this.ingressBytes = 0; this.ingressItems = 0;
    this.uplinkBytes = 0; this.uplinkItems = 0;
    this.downlinkBytes = 0; this.downlinkItems = 0;
    this.downlinkWaiters = new Set();
    this.secret = null; this.proxyId = null;
  }
  async fetch(request) {
    const url = new URL(request.url);
    if (this.closed) return new Response("session closed", { status: 404 });
    if (!this.proxyId) {
      const proxyId = request.headers.get("X-Proxy-Id") || "";
      if (!/^[A-Za-z0-9]{8,32}$/.test(proxyId)) return new Response("invalid proxy id", { status: 400 });
      const meta = await this.env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
      if (!meta) return new Response("proxy not found", { status: 404 });
      if (!meta.enabled) return new Response("proxy disabled", { status: 403 });
      this.proxyId = proxyId;
      this.secret = parseProxySecret(meta.secret).inner;
    }
    if (url.pathname === "/internal/init" && request.method === "POST") {
      if (!this.initialized) { await this.ctx.storage.put({ expiresAt: Date.now() + 10 * 60 * 1000 }); this.initialized = true; }
      return new Response(null, { status: 204 });
    }
    if (url.pathname === "/internal/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("expected websocket", { status: 426 });
      if (!this.initialized) {
        const expiresAt = await this.ctx.storage.get("expiresAt");
        if (this.closed || !expiresAt || expiresAt < Date.now()) return new Response("unknown session", { status: 404 });
        this.initialized = true;
      }
      if (this.ws) return new Response("already connected", { status: 409 });
      const pair = new WebSocketPair();
      const client = pair[0], server = pair[1];
      server.accept(); this.ws = server;
      server.addEventListener("message", (e) => this.enqueueMessage(e.data));
      server.addEventListener("close", () => this.shutdown("websocket_close"));
      server.addEventListener("error", () => this.shutdown("websocket_error"));
      const proto = request.headers.get("X-TProxy-Protocol") || "";
      const echo = proto.split(",").map((v) => v.trim()).find((v) => v.startsWith("tproxy-v1.")) || "";
      return new Response(null, { status: 101, webSocket: client, headers: echo ? { "Sec-WebSocket-Protocol": echo } : {} });
    }
    if (url.pathname === "/internal/close" && request.method === "POST") {
      this.shutdown("session_delete"); return new Response(null, { status: 204 });
    }
    return new Response("not found", { status: 404 });
  }
  enqueueMessage(data) {
    if (this.closed) return;
    const length = data instanceof Blob ? data.size : data instanceof ArrayBuffer ? data.byteLength : 0;
    if (!length || length > MAX_WS_MESSAGE) return this.protocolError("invalid_websocket_message");
    const cost = length + LIMITS.itemCost;
    if (this.ingressBytes + cost > LIMITS.ingressBytes || this.ingressItems >= LIMITS.ingressItems) return this.protocolError("ingress_queue_limit");
    this.ingressBytes += cost; this.ingressItems++;
    this.messageChain = this.messageChain.then(() => this.onMessage(data))
      .catch(() => this.protocolError("message_handler_failed"))
      .finally(() => { this.ingressBytes -= cost; this.ingressItems--; });
    this.ctx.waitUntil(this.messageChain);
  }
  async onMessage(data) {
    if (this.closed) return;
    if (data instanceof Blob) data = await data.arrayBuffer();
    if (this.closed) return;
    if (!(data instanceof ArrayBuffer) || !data.byteLength || data.byteLength > MAX_WS_MESSAGE) return this.protocolError("invalid_websocket_message");
    let frames;
    try { frames = parseFrames(new Uint8Array(data)); } catch { return this.protocolError("frame_parse_failed"); }
    for (const frame of frames) {
      if (frame.streamId === 0) {
        if (frame.type !== FRAME.PONG || frame.payload.length > 64) return this.protocolError("invalid_control_frame");
      } else if (frame.type === FRAME.OPEN) this.openStream(frame);
      else if (frame.type === FRAME.DATA) this.queueWrite(frame);
      else if (frame.type === FRAME.WINDOW) this.addWindow(frame);
      else if (frame.type === FRAME.CLOSE) {
        if (frame.payload.length) return this.protocolError("invalid_close");
        if (!this.streams.has(frame.streamId) && !this.closedIds.has(frame.streamId)) return this.protocolError("unknown_stream");
        this.closeStream(frame.streamId, false);
      } else return this.protocolError("unknown_frame_type");
      if (this.closed) return;
    }
  }
  openStream(frame) {
    const id = frame.streamId;
    if (!id || frame.payload.length || this.streams.has(id) || this.closedIds.has(id)) return this.protocolError("invalid_open");
    if (this.streams.size >= this.maxStreams) { this.rememberClosed(id); return this.sendFrame(FRAME.CLOSE, id); }
    const stream = {
      id, socket: null, writer: null, handshake: new Uint8Array(), handshakeBytes: 0,
      receiveWindow: INITIAL_WINDOW, sendCredit: INITIAL_WINDOW, closed: false,
      queue: [], queueHead: 0, pendingBytes: 0, pendingItems: 0, draining: false,
      abort: new AbortController(), sent: [], sentHead: 0, downlinkBytes: 0, downlinkItems: 0,
    };
    stream.handshakeTimer = setTimeout(() => this.closeStream(id, true), LIMITS.handshakeTimeout);
    this.streams.set(id, stream);
  }
  queueWrite(frame) {
    const stream = this.streams.get(frame.streamId);
    if (!stream) { if (this.closedIds.has(frame.streamId) && frame.payload.length) return; return this.protocolError("unknown_stream"); }
    const length = frame.payload.length;
    if (!length || length > stream.receiveWindow) return this.protocolError("invalid_data_window");
    const cost = length + HEADER_SIZE + LIMITS.itemCost;
    if (stream.pendingBytes + cost > LIMITS.streamBytes || stream.pendingItems >= LIMITS.streamItems ||
        this.uplinkBytes + cost > LIMITS.uplinkBytes || this.uplinkItems >= LIMITS.uplinkItems) return this.closeStream(stream.id, true);
    stream.receiveWindow -= length; stream.pendingBytes += cost; stream.pendingItems++;
    this.uplinkBytes += cost; this.uplinkItems++;
    stream.queue.push({ payload: new Uint8Array(frame.payload), cost });
    if (!stream.draining) { stream.draining = true; this.ctx.waitUntil(this.drainStream(stream)); }
  }
  releaseWrite(stream, item) {
    stream.pendingBytes -= item.cost; stream.pendingItems--;
    this.uplinkBytes -= item.cost; this.uplinkItems--;
  }
  async drainStream(stream) {
    try {
      while (!stream.closed && !this.closed && stream.queueHead < stream.queue.length) {
        const item = stream.queue[stream.queueHead]; stream.queue[stream.queueHead++] = null;
        try { await this.writeStream(stream, item.payload); } finally { this.releaseWrite(stream, item); }
        if (stream.queueHead === stream.queue.length) { stream.queue = []; stream.queueHead = 0; }
        else if (stream.queueHead >= 64) { stream.queue = stream.queue.slice(stream.queueHead); stream.queueHead = 0; }
      }
    } catch { this.closeStream(stream.id, true); }
    finally { stream.draining = false; }
  }
  active(s) { if (s.closed || this.closed) throw new Error("stream closed"); }
  async writeStream(stream, payload) {
    this.active(stream);
    let grant = payload.length;
    if (!stream.writer) {
      const take = Math.min(64 - stream.handshake.length, payload.length);
      const joined = new Uint8Array(stream.handshake.length + take);
      joined.set(stream.handshake); joined.set(payload.subarray(0, take), stream.handshake.length);
      stream.handshake = joined; stream.handshakeBytes += take;
      if (joined.length < 64) return;
      if (!this.secret) throw new Error("proxy secret not loaded");
      const client = await acceptClientHandshake(joined, this.secret);
      this.active(stream);
      const tg = await createTelegramHandshake(client.tag, client.dcId);
      this.active(stream);
      clearTimeout(stream.handshakeTimer); stream.handshakeTimer = null;
      const socket = this.connect({ hostname: TELEGRAM_DCS[Math.abs(client.dcId)], port: 443 }, { allowHalfOpen: false });
      stream.socket = socket;
      Promise.resolve(socket.closed).catch(() => {});
      await waitFor(socket.opened, stream.abort.signal, LIMITS.connectTimeout, "connect timeout");
      this.active(stream);
      stream.writer = socket.writable.getWriter();
      stream.clientDecrypt = client.clientDecrypt; stream.clientEncrypt = client.clientEncrypt;
      stream.tgEncrypt = tg.encrypt; stream.tgDecrypt = tg.decrypt;
      stream.handshake = new Uint8Array();
      await waitFor(stream.writer.write(tg.wire), stream.abort.signal, LIMITS.writeTimeout, "write timeout");
      this.active(stream);
      this.ctx.waitUntil(this.readStream(stream));
      grant = stream.handshakeBytes + payload.length - take;
      stream.handshakeBytes = 0;
      payload = payload.subarray(take);
    }
    for (let offset = 0; offset < payload.length; offset += DATA_CHUNK) {
      const plain = await stream.clientDecrypt.crypt(payload.subarray(offset, offset + DATA_CHUNK));
      this.active(stream);
      const encrypted = await stream.tgEncrypt.crypt(plain);
      this.active(stream);
      await waitFor(stream.writer.write(encrypted), stream.abort.signal, LIMITS.writeTimeout, "write timeout");
      this.active(stream);
    }
    this.grantWindow(stream, grant);
  }
  grantWindow(s, l) { if (s.closed || this.closed || !l) return; s.receiveWindow += l; this.sendFrame(FRAME.WINDOW, s.id, u32(l)); }
  addWindow(frame) {
    if (frame.payload.length !== 4) return this.protocolError("invalid_window");
    const amount = new DataView(frame.payload.buffer, frame.payload.byteOffset, 4).getUint32(0);
    if (!amount) return this.protocolError("invalid_window");
    const stream = this.streams.get(frame.streamId);
    if (!stream) { if (this.closedIds.has(frame.streamId)) return; return this.protocolError("unknown_stream"); }
    if (amount > INITIAL_WINDOW - stream.sendCredit) return this.protocolError("window_overflow");
    stream.sendCredit += amount;
    let remaining = amount;
    while (remaining) {
      const item = stream.sent[stream.sentHead];
      const used = Math.min(remaining, item.remaining);
      item.remaining -= used; remaining -= used;
      stream.downlinkBytes -= used; this.downlinkBytes -= used;
      if (!item.remaining) {
        const overhead = HEADER_SIZE + LIMITS.itemCost;
        stream.downlinkBytes -= overhead; this.downlinkBytes -= overhead;
        stream.downlinkItems--; this.downlinkItems--;
        stream.sent[stream.sentHead++] = null;
      }
    }
    if (stream.sentHead === stream.sent.length) { stream.sent = []; stream.sentHead = 0; }
    else if (stream.sentHead >= 64) { stream.sent = stream.sent.slice(stream.sentHead); stream.sentHead = 0; }
    this.wakeDownlink();
  }
  downlinkRoom(s) {
    if (this.downlinkItems >= LIMITS.downlinkItems) return 0;
    return Math.max(0, Math.min(DATA_CHUNK, s.sendCredit, LIMITS.downlinkBytes - this.downlinkBytes - HEADER_SIZE - LIMITS.itemCost));
  }
  async waitDownlink(s) { while (!s.closed && !this.closed && !this.downlinkRoom(s)) await new Promise((r) => this.downlinkWaiters.add(r)); return !s.closed && !this.closed; }
  wakeDownlink() { const w = [...this.downlinkWaiters]; this.downlinkWaiters.clear(); for (const r of w) r(); }
  async readStream(stream) {
    const reader = stream.socket.readable.getReader();
    try {
      while (await this.waitDownlink(stream)) {
        const { value, done } = await reader.read();
        if (done || stream.closed || this.closed) break;
        const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
        let offset = 0;
        while (offset < bytes.length && await this.waitDownlink(stream)) {
          const size = Math.min(bytes.length - offset, this.downlinkRoom(stream));
          if (!size) continue;
          const cost = size + HEADER_SIZE + LIMITS.itemCost;
          stream.sendCredit -= size; stream.sent.push({ remaining: size });
          stream.downlinkBytes += cost; stream.downlinkItems++;
          this.downlinkBytes += cost; this.downlinkItems++;
          const plain = await stream.tgDecrypt.crypt(bytes.subarray(offset, offset + size));
          this.active(stream);
          const encrypted = await stream.clientEncrypt.crypt(plain);
          this.active(stream);
          this.sendFrame(FRAME.DATA, stream.id, encrypted);
          offset += size;
        }
      }
    } catch {}
    finally { ignoreFailure(() => reader.cancel()); try { reader.releaseLock(); } catch {} this.closeStream(stream.id, true); }
  }
  closeStream(id, notify) {
    const stream = this.streams.get(id);
    if (!stream) return;
    this.streams.delete(id); this.rememberClosed(id);
    stream.closed = true;
    clearTimeout(stream.handshakeTimer); stream.handshakeTimer = null;
    stream.abort.abort();
    for (let i = stream.queueHead; i < stream.queue.length; i++) this.releaseWrite(stream, stream.queue[i]);
    stream.queue = []; stream.queueHead = 0; stream.handshake = new Uint8Array();
    this.downlinkBytes -= stream.downlinkBytes; this.downlinkItems -= stream.downlinkItems;
    stream.downlinkBytes = 0; stream.downlinkItems = 0; stream.sent = []; stream.sentHead = 0;
    this.wakeDownlink();
    ignoreFailure(() => stream.writer?.abort());
    ignoreFailure(() => stream.socket?.close());
    if (notify && !this.closed) this.sendFrame(FRAME.CLOSE, id);
  }
  rememberClosed(id) { this.closedIds.add(id); if (this.closedIds.size > 4096) this.closedIds.delete(this.closedIds.values().next().value); }
  sendFrame(type, streamId, payload = new Uint8Array()) {
    if (this.closed || !this.ws || this.ws.readyState !== 1) return;
    try { this.ws.send(encodeFrame(type, streamId, payload)); } catch { this.shutdown("websocket_send_failed"); }
  }
  protocolError(reason = "protocol_error") { this.sendFrame(FRAME.BYE, 0); this.shutdown(reason); }
  shutdown(reason = "shutdown") {
    if (this.closed) return;
    this.closed = true;
    for (const id of [...this.streams.keys()]) this.closeStream(id, false);
    this.wakeDownlink();
    try { this.ws?.close(1000, "session closed"); } catch {}
    this.ws = null;
    this.ctx.waitUntil(Promise.resolve(this.ctx.storage.delete("expiresAt")).catch(() => {}));
  }
}
function waitFor(promise, signal, timeout, reason) {
  return new Promise((resolve, reject) => {
    const aborted = () => finish(reject, new Error("stream closed"));
    let timer, settled = false;
    const finish = (settle, value) => {
      if (settled) return; settled = true;
      clearTimeout(timer); signal.removeEventListener("abort", aborted); settle(value);
    };
    Promise.resolve(promise).then(v => finish(resolve, v), e => finish(reject, e));
    if (signal.aborted) return aborted();
    signal.addEventListener("abort", aborted, { once: true });
    timer = setTimeout(() => finish(reject, new Error(reason)), timeout);
  });
}
function ignoreFailure(fn) { try { Promise.resolve(fn()).catch(() => {}); } catch {} }

// ============================================================
// Durable Object
// ============================================================
export class ProxySession extends RelaySession {
  constructor(ctx, env) { super(ctx, env, connect); }
}

// ============================================================
// bridge.js
// ============================================================
function bridgePage(host, bootstrap) {
  const scriptNonce = randomNonce();
  const config = JSON.stringify({ origin: `https://${host}`, bootstrap, batchLimit: MAX_WS_MESSAGE, maxPendingItems: 1024, connectTimeout: 15000 });
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Web Proxy</title></head>
<body><main><h1>Connection bridge</h1><p>This page is opened by a compatible Telegram client.</p></main>
<script nonce="${scriptNonce}">
(()=>{'use strict';
const cfg=${config};
let port=null, sessionToken='', socket=null, creating=false, closed=false;
const pending=[]; let pendingBytes=0;
const bootstrapAbort=new AbortController(); let connectTimer=null;
const fragment=new URLSearchParams(location.hash.slice(1));
const nonce=fragment.get('android')||'';
history.replaceState(null,'','/');
function status(state){try{port&&port.postMessage({t:'status',state})}catch{}}
function splitFrames(buffer){
 const input=new Uint8Array(buffer); let off=0,count=0,out=[];
 while(off<input.length){
  if(++count>4096||input.length-off<8)throw Error('bad frame');
  const view=new DataView(input.buffer,input.byteOffset+off,8); const len=view.getUint32(4);
  if(len>1048576||off+8+len>input.length)throw Error('bad frame');
  out.push(buffer.slice(off,off+8+len)); off+=8+len;
 }
 if(!out.length)throw Error('empty'); return out;
}
function sendToApp(buffer){for(const frame of splitFrames(buffer))port.postMessage(frame,[frame]);}
function fail(){if(closed)return;status('failed');close(false)}
async function createSession(hello){
 try{
  const response=await fetch(cfg.origin+'/api/v1/session',{method:'POST',headers:{Authorization:'Bearer '+cfg.bootstrap,'Content-Type':'application/octet-stream','X-Carrier-Mode':'websocket'},body:hello,mode:'same-origin',redirect:'error',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',signal:bootstrapAbort.signal});
  if(!response.ok||response.headers.get('X-Carrier-Mode')!=='websocket')throw Error('session');
  sessionToken=response.headers.get('X-Session-Token')||'';
  if(!/^[A-Za-z0-9_-]{43}$/.test(sessionToken))throw Error('token');
  const welcome=await response.arrayBuffer();
  if(closed)return;
  if(welcome.byteLength!==8||new Uint8Array(welcome)[0]!==0x11||new Uint8Array(welcome).slice(1).some(v=>v!==0))throw Error('welcome');
  sendToApp(welcome);
  if(!closed)openSocket();
 }catch(e){fail()}
}
function openSocket(){
 const target=cfg.origin.replace(/^https:/,'wss:')+'/api/v1/ws';
 socket=new WebSocket(target,'tproxy-v1.'+sessionToken); socket.binaryType='arraybuffer';
 socket.onopen=()=>{
  if(closed)return; clearTimeout(connectTimer);connectTimer=null;status('connected');
  try{for(const data of pending){if(socket.bufferedAmount+data.byteLength>cfg.batchLimit)return fail();socket.send(data)}}catch{return fail()}
  pending.length=0;pendingBytes=0;
 };
 socket.onmessage=e=>{if(closed)return;if(!(e.data instanceof ArrayBuffer)||!e.data.byteLength||e.data.byteLength>cfg.batchLimit)return fail();try{sendToApp(e.data)}catch{return fail()}};
 socket.onerror=()=>{}; socket.onclose=()=>{if(!closed)fail()};
}
function fromApp(data){
 if(closed)return;
 if(data instanceof ArrayBuffer){
  if(!data.byteLength||data.byteLength>cfg.batchLimit)return fail();
  try{splitFrames(data)}catch{return fail()}
  if(!creating){creating=true;connectTimer=setTimeout(fail,cfg.connectTimeout);createSession(data);return}
  if(!sessionToken||!socket||socket.readyState!==WebSocket.OPEN){if(pending.length>=cfg.maxPendingItems||pendingBytes+data.byteLength>cfg.batchLimit)return fail();pending.push(data);pendingBytes+=data.byteLength;return}
  if(socket.bufferedAmount+data.byteLength>cfg.batchLimit)return fail();
  try{socket.send(data)}catch{fail()}
 }else if(data&&data.t==='close')close(true);
}
function activate(next){port=next;port.onmessage=e=>fromApp(e.data);port.start&&port.start();status('connecting')}
const native=globalThis.TelegramWebProxy;
if(/^[A-Za-z0-9_-]{43}$/.test(nonce)&&native&&typeof native.postMessage==='function'){
 const adapter={onmessage:null,start(){},close(){native.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){for(const frame of splitFrames(value))native.postMessage(frame)}
  else native.postMessage(JSON.stringify(value));
 }};
 native.onmessage=e=>{let d=e.data;if(typeof d==='string'){try{d=JSON.parse(d)}catch{return}}adapter.onmessage&&adapter.onmessage({data:d})};
 activate(adapter);native.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce}));
}
addEventListener('message',e=>{
 if(closed||port||e.source!==parent||!e.data||e.data.t!=='tproxy-init'||e.data.v!==1||e.ports.length!==1)return;
 try{const u=new URL(e.origin);if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||!u.port)return}catch{return}
 activate(e.ports[0]);
});
function close(notify){if(closed)return;closed=true;clearTimeout(connectTimer);connectTimer=null;bootstrapAbort.abort();pending.length=0;pendingBytes=0;try{socket&&socket.close()}catch{}if(notify&&sessionToken)fetch(cfg.origin+'/api/v1/session',{method:'DELETE',headers:{Authorization:'Bearer '+sessionToken},keepalive:true,mode:'same-origin',redirect:'error',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'}).catch(()=>{});try{port&&port.close()}catch{}}
addEventListener('pagehide',()=>close(true),{once:true});
})();
</script></body></html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${scriptNonce}'; connect-src https://${host} wss://${host}; style-src 'none'; img-src 'none'; object-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; sandbox allow-same-origin allow-scripts`,
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    },
  });
}
function randomNonce() { const bytes = crypto.getRandomValues(new Uint8Array(18)); return btoa(String.fromCharCode(...bytes)); }

// ============================================================
// Worker entrypoint
// ============================================================
export default {
  async fetch(request, env, ctx) {
    try { return await route(request, env, ctx); }
    catch (error) { console.error("unhandled request error", error); return notFound(); }
  },
};

async function route(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === "/healthz") return Response.json({ ok: true, version: VERSION, carrier: "websocket" }, { headers: noStore() });
  if (url.pathname === "/bot/webhook" && request.method === "POST") return handleTelegramWebhook(request, env, ctx);
  if (url.pathname === "/api/v1/session") {
    if (request.headers.has("Cookie")) return notFound();
    if (request.method === "DELETE") return closeSession(request, env);
    if (request.method !== "POST" || !isBinary(request.headers.get("Content-Type"))) return notFound();
    return createSession(request, env);
  }
  if (url.pathname === "/api/v1/ws") {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return notFound();
    return relayWebSocket(request, env);
  }
  if (url.pathname === "/" && request.method === "GET") return handleRoot(url, env);
  return notFound();
}

// ---------- root: supports both ?bridge= and ?server=&secret= ----------
async function handleRoot(url, env) {
  const expectedHost = canonicalHost(env.PUBLIC_HOSTNAME || url.hostname);
  if (canonicalHost(url.hostname) !== expectedHost) return publicPage(env);

  // Path 1: ?bridge=<43char capability>
  const bridgeValue = exactBridgeQuery(url);
  if (bridgeValue) {
    // Find the proxy whose secret HMACs to this capability.
    const proxyId = await findProxyByCapability(env, expectedHost, bridgeValue);
    if (!proxyId) return publicPage(env);
    const meta = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
    if (!meta || !meta.enabled) return publicPage(env);
    const bootstrap = await createBootstrap(env, proxyId);
    return bridgePage(expectedHost, bootstrap);
  }

  // Path 2: ?server=&secret= (deep-link entry)
  const serverParam = url.searchParams.get("server");
  const secretParam = url.searchParams.get("secret");
  if (serverParam && secretParam) {
    if (canonicalHost(serverParam) !== expectedHost) return publicPage(env);
    const secret = String(secretParam).toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(secret)) return publicPage(env);
    const proxyId = await env.PROXY_REGISTRY.get(`secret:${secret}`, "text");
    if (!proxyId) return publicPage(env);
    const meta = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
    if (!meta || !meta.enabled) return publicPage(env);
    const bootstrap = await createBootstrap(env, proxyId);
    return bridgePage(expectedHost, bootstrap);
  }

  return publicPage(env);
}

function exactBridgeQuery(url) {
  if (url.searchParams.size !== 1 || !url.searchParams.has("bridge")) return null;
  const value = url.searchParams.get("bridge");
  return /^[A-Za-z0-9_-]{43}$/.test(value || "") && url.search === `?bridge=${value}` ? value : null;
}

async function findProxyByCapability(env, host, candidate) {
  // Iterate all proxies owned by current host — small N, fine.
  const all = (await env.PROXY_REGISTRY.get(`all:proxies`, "json")) || [];
  for (const id of all) {
    const meta = await env.PROXY_REGISTRY.get(`proxy:${id}`, "json");
    if (!meta || !meta.enabled) continue;
    if (!/^[0-9a-f]{32}$/.test(String(meta.secret || ""))) continue;
    const expected = base64url(await hmac(hexToBytes(meta.secret), new TextEncoder().encode(`tdesktop-web-proxy-bridge-v1\n${host}`)));
    if (constantTimeEqual(candidate, expected)) return id;
  }
  return null;
}

// ---------- /api/v1/session ----------
async function createSession(request, env) {
  const bootstrap = bearer(request);
  if (!bootstrap) return notFound();
  const proxyId = await verifyBootstrap(env, bootstrap);
  if (!proxyId) return notFound();
  const meta = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
  if (!meta || !meta.enabled) return notFound();
  const hello = await readHello(request);
  if (!isHello(hello)) return notFound();

  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const sessionToken = base64url(tokenBytes);
  await env.PROXY_REGISTRY.put(`session:${sessionToken}`, JSON.stringify({ proxyId, exp: Date.now() + 10 * 60 * 1000 }), { expirationTtl: 900 });

  const doId = env.PROXY_SESSIONS.idFromName(`s:${sessionToken}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  const init = await stub.fetch("https://session/internal/init", { method: "POST", headers: { "X-Proxy-Id": proxyId } });
  if (!init.ok) return notFound();

  const welcome = encodeFrame(FRAME.WELCOME, 0);
  return new Response(welcome, {
    status: 200,
    headers: { ...noStore(), "Content-Type": "application/octet-stream", "X-Session-Token": sessionToken, "X-Carrier-Mode": "websocket", "X-Down-Cursor": "0" },
  });
}

async function closeSession(request, env) {
  const token = bearer(request);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return notFound();
  const rec = await env.PROXY_REGISTRY.get(`session:${token}`, "json");
  if (!rec) return notFound();
  await env.PROXY_REGISTRY.delete(`session:${token}`);
  const doId = env.PROXY_SESSIONS.idFromName(`s:${token}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  await stub.fetch("https://session/internal/close", { method: "POST", headers: { "X-Proxy-Id": rec.proxyId } });
  return new Response(null, { status: 204, headers: noStore() });
}

async function relayWebSocket(request, env) {
  const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "").split(",").map((v) => v.trim());
  const proto = protocols.find((v) => v.startsWith("tproxy-v1."));
  const token = proto ? proto.slice("tproxy-v1.".length) : "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return notFound();
  const rec = await env.PROXY_REGISTRY.get(`session:${token}`, "json");
  if (!rec || rec.exp < Date.now()) return notFound();
  const doId = env.PROXY_SESSIONS.idFromName(`s:${token}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  return stub.fetch("https://session/internal/ws", {
    method: "GET",
    headers: { "Upgrade": "websocket", "X-TProxy-Protocol": proto, "X-Proxy-Id": rec.proxyId },
  });
}

// ---------- bootstrap ----------
async function createBootstrap(env, proxyId) {
  const ttl = clampInt(env.SESSION_TTL_SECONDS, 30, 600, 300);
  const payload = base64url(new TextEncoder().encode(JSON.stringify({ p: proxyId, e: Math.floor(Date.now() / 1000) + ttl })));
  const sig = base64url(await hmac(signingKey(env), new TextEncoder().encode(payload)));
  return `${payload}.${sig}`;
}
async function verifyBootstrap(env, token) {
  const [payload, sig, extra] = String(token).split(".");
  if (!payload || !sig || extra) return null;
  const expected = base64url(await hmac(signingKey(env), new TextEncoder().encode(payload)));
  if (!constantTimeEqual(sig, expected)) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(base64urlDecode(payload)));
    if (!Number.isInteger(data.e) || data.e < Math.floor(Date.now() / 1000)) return null;
    if (!/^[A-Za-z0-9]{8,32}$/.test(data.p)) return null;
    return data.p;
  } catch { return null; }
}
function signingKey(env) {
  const base = String(env.TELEGRAM_WEBHOOK_SECRET || env.TELEGRAM_BOT_TOKEN || "TGPN-default");
  return new TextEncoder().encode(`TGPN/bootstrap/v1\n${base}`);
}
async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}
function hexToBytes(hex) { const out = new Uint8Array(hex.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16); return out; }

// ---------- hello ----------
async function readHello(request) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const bytes = new Uint8Array(9);
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return bytes.subarray(0, length);
      if (length + value.length > bytes.length) { await reader.cancel(); return new Uint8Array(); }
      bytes.set(value, length); length += value.length;
    }
  } finally { reader.releaseLock(); }
}
function isHello(bytes) {
  try {
    const frames = parseFrames(bytes);
    return frames.length === 1 && frames[0].type === FRAME.HELLO && frames[0].streamId === 0 && frames[0].payload.length === 1 && frames[0].payload[0] === 1;
  } catch { return false; }
}

// ============================================================
// Telegram bot
// ============================================================
const USER_STATE = new Map();
const STATE_TTL_MS = 5 * 60 * 1000;
function cleanState() { const now = Date.now(); for (const [k, v] of USER_STATE) if (now - v.ts > STATE_TTL_MS) USER_STATE.delete(k); }

async function handleTelegramWebhook(request, env, ctx) {
  const secretHeader = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
  if (env.TELEGRAM_WEBHOOK_SECRET && secretHeader !== env.TELEGRAM_WEBHOOK_SECRET) return new Response("Forbidden", { status: 403 });
  let update;
  try { update = await request.json(); } catch { return new Response("OK"); }
  if (update.callback_query) {
    const cq = update.callback_query;
    ctx.waitUntil(answerCallback(env, cq.id, "").catch(() => {}));
    ctx.waitUntil(handleCallback(env, cq).catch((e) => console.error("callback failed", e)));
    return new Response("OK");
  }
  const msg = update.message || update.edited_message;
  if (!msg) return new Response("OK");
  const chatId = msg.chat.id;
  const userId = msg.from ? msg.from.id : 0;
  const text = (msg.text || "").trim();
  if (!userId) return new Response("OK");
  if (!isAuthorized(env, userId)) {
    ctx.waitUntil(sendTelegram(env, chatId, `⛔️ <b>دسترسی نداری</b>\n\nآیدی شما: <code>${userId}</code>`, { parse_mode: "HTML" }));
    return new Response("OK");
  }
  ctx.waitUntil(handleMessage(env, chatId, userId, text).catch((e) => {
    console.error("handleMessage failed", e);
    return sendTelegram(env, chatId, `❌ خطا: <code>${escapeHtml(String(e.message || e))}</code>`, { parse_mode: "HTML" });
  }));
  return new Response("OK");
}

async function handleMessage(env, chatId, userId, text) {
  cleanState();
  const stateKey = `${chatId}:${userId}`;
  const state = USER_STATE.get(stateKey);
  if (state?.action === "awaiting_name") {
    USER_STATE.delete(stateKey);
    return createProxyFlow(env, chatId, userId, text.slice(0, 48).trim() || `proxy-${Date.now()}`);
  }
  const parts = text.split(/\s+/);
  const cmd = (parts[0] || "").split("@")[0].toLowerCase();
  const args = parts.slice(1);
  switch (cmd) {
    case "/start": case "/menu": case "/help": return showMainMenu(env, chatId, userId);
    case "/new":
      if (args.length) return createProxyFlow(env, chatId, userId, args.join(" ").slice(0, 48));
      USER_STATE.set(stateKey, { action: "awaiting_name", ts: Date.now() });
      return sendTelegram(env, chatId, `✍️ <b>نام پروکسی جدید را بنویس</b>\n\nمثال: <code>myproxy</code>\n\nبرای لغو /cancel`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    case "/cancel": USER_STATE.delete(stateKey); return showMainMenu(env, chatId, userId);
    case "/list": return showProxyList(env, chatId, userId);
    case "/myid": return sendTelegram(env, chatId, `🆔 آیدی شما: <code>${userId}</code>`, { parse_mode: "HTML" });
    case "/version": return sendTelegram(env, chatId, `🌐 <b>TGPN</b> v${VERSION}`, { parse_mode: "HTML" });
    default:
      if (text.startsWith("/")) return sendTelegram(env, chatId, "❓ دستور ناشناخته. /help");
      return new Response("OK");
  }
}

async function showMainMenu(env, chatId, userId) {
  const list = (await env.PROXY_REGISTRY.get(`user:${userId}:proxies`, "json")) || [];
  const text = `🌐 <b>TGPN</b>  <code>v${VERSION}</code>\nسامانه مدیریت پروکسی تلگرام\n\n👤 <b>پروفایل شما</b>\n├ 📦 پروکسی‌های فعال: <b>${list.length}</b>\n└ 🟢 وضعیت: <b>فعال</b>\n\nاز دکمه‌های زیر استفاده کن 👇`;
  const keyboard = { inline_keyboard: [
    [{ text: "➕ ساخت پروکسی جدید", callback_data: "menu:new" }],
    [{ text: "📋 پروکسی‌های من", callback_data: "menu:list" }],
    [{ text: "ℹ️ راهنما", callback_data: "menu:help" }, { text: "🆔 آیدی من", callback_data: "menu:myid" }],
  ] };
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}
async function editMainMenu(env, chatId, msgId, userId) {
  const list = (await env.PROXY_REGISTRY.get(`user:${userId}:proxies`, "json")) || [];
  const text = `🌐 <b>TGPN</b>  <code>v${VERSION}</code>\nسامانه مدیریت پروکسی تلگرام\n\n👤 <b>پروفایل شما</b>\n├ 📦 پروکسی‌های فعال: <b>${list.length}</b>\n└ 🟢 وضعیت: <b>فعال</b>`;
  const keyboard = { inline_keyboard: [
    [{ text: "➕ ساخت پروکسی جدید", callback_data: "menu:new" }],
    [{ text: "📋 پروکسی‌های من", callback_data: "menu:list" }],
    [{ text: "ℹ️ راهنما", callback_data: "menu:help" }, { text: "🆔 آیدی من", callback_data: "menu:myid" }],
  ] };
  return editMessage(env, chatId, msgId, text, { parse_mode: "HTML", reply_markup: keyboard });
}
async function showHelp(env, chatId, edit = null) {
  const text = `📚 <b>راهنمای TGPN</b>\n\n<b>روش ساخت</b>\n۱. «ساخت پروکسی جدید» را بزن\n۲. یک نام وارد کن\n۳. دکمه «باز کردن در تلگرام» را بزن`;
  const keyboard = { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: "menu:home" }]] };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}
async function showProxyList(env, chatId, userId) {
  const list = (await env.PROXY_REGISTRY.get(`user:${userId}:proxies`, "json")) || [];
  if (!list.length) return sendTelegram(env, chatId, `📭 <b>هنوز پروکسی نداری</b>`,
    { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "➕ ساخت پروکسی", callback_data: "menu:new" }], [{ text: "🔙 بازگشت", callback_data: "menu:home" }]] } });
  let text = `📋 <b>پروکسی‌های شما</b> (${list.length})\n\n`;
  const rows = [];
  let i = 1;
  for (const id of list) {
    const m = await env.PROXY_REGISTRY.get(`proxy:${id}`, "json");
    if (!m) continue;
    const icon = m.enabled ? "🟢" : "🔴";
    text += `${i++}. ${icon} <b>${escapeHtml(m.name)}</b>\n<code>${m.id}</code>\n\n`;
    rows.push([{ text: `${icon} ${m.name}`, callback_data: `p:info:${m.id}` }]);
  }
  rows.push([{ text: "🔙 بازگشت", callback_data: "menu:home" }]);
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: { inline_keyboard: rows } });
}
async function showProxyInfo(env, chatId, userId, proxyId, edit = null) {
  const m = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
  const fail = (txt) => edit ? editMessage(env, chatId, edit, txt, { parse_mode: "HTML" }) : sendTelegram(env, chatId, txt, { parse_mode: "HTML" });
  if (!m) return fail(`❌ پروکسی پیدا نشد.`);
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return fail(`⛔️ این پروکسی مال شما نیست.`);
  const host = canonicalHost(env.PUBLIC_HOSTNAME || "");
  const tgLink = `https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${m.secret}`;
  const text = `📦 <b>${escapeHtml(m.name)}</b>\n\n🆔 <code>${m.id}</code>\n${m.enabled ? "🟢 فعال" : "🔴 غیرفعال"}\n\n🔑 <b>Secret</b>\n<code>${m.secret}</code>\n\n👇 برای اتصال، دکمه زیر را بزن`;
  const keyboard = { inline_keyboard: [
    [{ text: "📱 باز کردن در تلگرام", url: tgLink }],
    [{ text: "📋 کپی Secret", callback_data: `p:copy:${m.id}` }],
    [{ text: m.enabled ? "🔴 غیرفعال" : "🟢 فعال", callback_data: `p:toggle:${m.id}` }, { text: "🗑 حذف", callback_data: `p:del:${m.id}` }],
    [{ text: "🔙 لیست", callback_data: "menu:list" }],
  ] };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}
async function createProxyFlow(env, chatId, userId, rawName) {
  const name = String(rawName || "").trim().slice(0, 48) || `proxy-${Date.now()}`;
  const proxyId = randomId(12);
  const secret = randomHex(16);
  const meta = { id: proxyId, name, secret, createdAt: Date.now(), ownerTelegramId: userId, enabled: true };
  await env.PROXY_REGISTRY.put(`proxy:${proxyId}`, JSON.stringify(meta));
  await env.PROXY_REGISTRY.put(`secret:${secret}`, proxyId);
  const userKey = `user:${userId}:proxies`;
  const list = (await env.PROXY_REGISTRY.get(userKey, "json")) || [];
  list.push(proxyId);
  await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list));
  const allKey = `all:proxies`;
  const all = (await env.PROXY_REGISTRY.get(allKey, "json")) || [];
  all.push(proxyId);
  await env.PROXY_REGISTRY.put(allKey, JSON.stringify(all));
  const host = canonicalHost(env.PUBLIC_HOSTNAME || "");
  const tgLink = `https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${secret}`;
  const text = `✅ <b>پروکسی ساخته شد</b>\n\n📛 <b>${escapeHtml(name)}</b>\n🆔 <code>${proxyId}</code>\n🔑 <code>${secret}</code>\n\n👇 برای اتصال، دکمه زیر را بزن`;
  const keyboard = { inline_keyboard: [
    [{ text: "📱 باز کردن در تلگرام", url: tgLink }],
    [{ text: "📋 کپی Secret", callback_data: `p:copy:${proxyId}` }, { text: "ℹ️ جزئیات", callback_data: `p:info:${proxyId}` }],
    [{ text: "🔙 منوی اصلی", callback_data: "menu:home" }],
  ] };
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}
async function confirmDelete(env, chatId, proxyId, userId, edit = null) {
  const m = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
  if (!m) return;
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
  const text = `⚠️ <b>تأیید حذف</b>\n\n📛 <b>${escapeHtml(m.name)}</b>\n🆔 <code>${m.id}</code>\n\nبرگشت‌پذیر نیست.`;
  const keyboard = { inline_keyboard: [[{ text: "✅ حذف کن", callback_data: `p:delok:${proxyId}` }, { text: "❌ انصراف", callback_data: `p:info:${proxyId}` }]] };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}
async function handleCallback(env, cq) {
  const chatId = cq.message?.chat?.id;
  const msgId = cq.message?.message_id;
  const userId = cq.from?.id;
  const data = String(cq.data || "");
  if (!chatId || !msgId || !userId) return;
  if (!isAuthorized(env, userId)) return answerCallback(env, cq.id, "⛔️", true);
  try {
    if (data === "menu:home") return editMainMenu(env, chatId, msgId, userId);
    if (data === "menu:new") {
      USER_STATE.set(`${chatId}:${userId}`, { action: "awaiting_name", ts: Date.now() });
      return editMessage(env, chatId, msgId, `✍️ <b>نام پروکسی را بنویس</b>\n\nمثال: <code>myproxy</code>`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    if (data === "menu:list") {
      const list = (await env.PROXY_REGISTRY.get(`user:${userId}:proxies`, "json")) || [];
      if (!list.length) return editMessage(env, chatId, msgId, `📭 خالی`, { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "➕ ساخت", callback_data: "menu:new" }]] } });
      let text = `📋 <b>پروکسی‌ها</b>\n\n`;
      const rows = [];
      for (const id of list) {
        const m = await env.PROXY_REGISTRY.get(`proxy:${id}`, "json");
        if (!m) continue;
        const icon = m.enabled ? "🟢" : "🔴";
        text += `${icon} <b>${escapeHtml(m.name)}</b>\n<code>${m.id}</code>\n\n`;
        rows.push([{ text: `${icon} ${m.name}`, callback_data: `p:info:${m.id}` }]);
      }
      rows.push([{ text: "🔙 بازگشت", callback_data: "menu:home" }]);
      return editMessage(env, chatId, msgId, text, { parse_mode: "HTML", reply_markup: { inline_keyboard: rows } });
    }
    if (data === "menu:help") return showHelp(env, chatId, msgId);
    if (data === "menu:myid") return editMessage(env, chatId, msgId, `🆔 <code>${userId}</code>`, { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "menu:home" }]] } });
    const parts = data.split(":");
    if (parts[0] !== "p") return;
    const action = parts[1], proxyId = parts[2];
    if (action === "info") return showProxyInfo(env, chatId, userId, proxyId, msgId);
    if (action === "copy") {
      const m = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
      if (!m) return;
      const host = canonicalHost(env.PUBLIC_HOSTNAME || "");
      await sendTelegram(env, chatId, `📋 <code>https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${m.secret}</code>`, { parse_mode: "HTML" });
      return answerCallback(env, cq.id, "✓");
    }
    if (action === "toggle") {
      const m = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
      if (!m) return;
      if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
      m.enabled = !m.enabled;
      await env.PROXY_REGISTRY.put(`proxy:${proxyId}`, JSON.stringify(m));
      return showProxyInfo(env, chatId, userId, proxyId, msgId);
    }
    if (action === "del") return confirmDelete(env, chatId, proxyId, userId, msgId);
    if (action === "delok") {
      const m = await env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
      if (!m) return;
      if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
      await env.PROXY_REGISTRY.delete(`proxy:${proxyId}`);
      if (m.secret) await env.PROXY_REGISTRY.delete(`secret:${m.secret}`);
      const userKey = `user:${m.ownerTelegramId}:proxies`;
      const list = (await env.PROXY_REGISTRY.get(userKey, "json")) || [];
      await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list.filter((x) => x !== proxyId)));
      const allKey = `all:proxies`;
      const all = (await env.PROXY_REGISTRY.get(allKey, "json")) || [];
      await env.PROXY_REGISTRY.put(allKey, JSON.stringify(all.filter((x) => x !== proxyId)));
      return editMessage(env, chatId, msgId, `🗑 حذف شد`, { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "menu:home" }]] } });
    }
  } catch (e) { console.error(e); return answerCallback(env, cq.id, "❌", true); }
}

// ---------- telegram API ----------
const TG_API = "https://api.telegram.org/bot";
async function tgCall(env, method, body) {
  const token = env.TELEGRAM_BOT_TOKEN;
  if (!token) return null;
  try {
    const r = await fetch(`${TG_API}${token}/${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    return await r.json();
  } catch { return null; }
}
async function sendTelegram(env, chatId, text, opts = {}) { return tgCall(env, "sendMessage", { chat_id: chatId, text, disable_web_page_preview: true, ...opts }); }
async function editMessage(env, chatId, messageId, text, opts = {}) {
  const r = await tgCall(env, "editMessageText", { chat_id: chatId, message_id: messageId, text, disable_web_page_preview: true, ...opts });
  if (r && !r.ok) { const d = String(r.description || ""); if (!d.includes("not modified")) await sendTelegram(env, chatId, text, opts); }
  return r;
}
async function answerCallback(env, id, text, alert = false) { return tgCall(env, "answerCallbackQuery", { callback_query_id: id, text: text || "", show_alert: !!alert }); }

// ---------- access ----------
function isAuthorized(env, userId) {
  const raw = String(env.ADMIN_IDS || "").trim();
  if (!raw) return true;
  return raw.split(/[,\s]+/).filter(Boolean).map(Number).includes(Number(userId));
}
function isAdmin(env, userId) { return isAuthorized(env, userId); }

// ---------- public ----------
function publicPage(env) {
  const bot = env.TELEGRAM_BOT_USERNAME ? `https://t.me/${env.TELEGRAM_BOT_USERNAME}` : null;
  const html = `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TGPN v${VERSION}</title>
<style>body{margin:0;min-height:100vh;background:#0b0e13;color:#e7edf4;font:14px/1.6 ui-monospace,Menlo,monospace;display:grid;place-items:center}
.card{max-width:520px;padding:28px;background:#141a22;border:1px solid #29323e;border-radius:10px;text-align:center}
h1{margin:0 0 8px;font-size:20px}p{color:#8a96a5;margin:6px 0}a{color:#4d9fff;text-decoration:none}</style>
</head><body><div class="card"><h1>🌐 TGPN</h1><p>سرویس پروکسی وب تلگرام</p>
${bot ? `<p style="margin-top:18px"><a href="${bot}">→ مدیریت با بات تلگرام</a></p>` : ""}
<p style="font-size:10px;color:#5f6b79;margin-top:18px">v${VERSION}</p></div></body></html>`;
  return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

// ---------- helpers ----------
function notFound() { return new Response("<!doctype html><meta charset=utf-8><title>Not found</title><h1>Not found</h1>", { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } }); }
function noStore() { return { "Cache-Control": "no-store" }; }
function canonicalHost(v) { return String(v || "").trim().toLowerCase().replace(/\.$/, ""); }
function randomId(len) { const bytes = crypto.getRandomValues(new Uint8Array(len)); const a = "abcdefghijklmnopqrstuvwxyz0123456789"; return [...bytes].map((b) => a[b % a.length]).join(""); }
function randomHex(bytes) { const b = crypto.getRandomValues(new Uint8Array(bytes)); return [...b].map((x) => x.toString(16).padStart(2, "0")).join(""); }
function bearer(r) { const v = r.headers.get("Authorization") || ""; return v.startsWith("Bearer ") ? v.slice(7) : ""; }
function isBinary(v) { return /^application\/octet-stream(?:\s*;.*)?$/i.test(v || ""); }
function base64url(bytes) { let s = ""; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function base64urlDecode(v) { const p = v.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (v.length % 4)) % 4); const raw = atob(p); return Uint8Array.from(raw, (c) => c.charCodeAt(0)); }
function constantTimeEqual(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
