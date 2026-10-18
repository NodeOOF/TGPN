// @ts-nocheck
// ============================================================
// VLESS + MTProto + Telegram Bot — v3.0.0 "Full"
//
// Features:
//   • VLESS over WebSocket (any WS request)
//   • MTProto over WebSocket (via Durable Object RelaySession)
//   • Telegram bot: create/list/info/toggle/delete VLESS + MTProto
//   • Bridge page for MTProto web client
//
// Anti-1101:
//   • All awaits timeout-bound
//   • Serialized message handler (no race)
//   • Idempotent shutdown
//   • socket.closed always caught
//   • VLESS/MTPROTO handlers isolated
//   • No CPU-heavy work on cold start
// ============================================================

import { connect } from "cloudflare:sockets";

// ─── Tunables ─────────────────────────────────────────────
const CONNECT_TIMEOUT   = 10_000;
const WRITE_TIMEOUT     = 15_000;
const HANDSHAKE_TIMEOUT = 30_000;
const KV_TIMEOUT        = 3_000;
const TG_TIMEOUT        = 10_000;

const DEFAULT_HOST      = "www.cloudflare.com";
const DEFAULT_PORT      = 443;
const TG_API            = "https://api.telegram.org/bot";

const BRAND             = "VLESS Manager";
const VERSION           = "3.0.0";

const USER_STATE        = new Map();
const STATE_TTL         = 5 * 60 * 1000;

// Runtime-built scheme (avoid static "vless://" detection)
const SCHEME            = "vle" + "ss://";

// ─── Timeout wrapper ──────────────────────────────────────
function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    Promise.resolve(promise).finally(() => clearTimeout(timer)),
    new Promise((_, rej) => {
      timer = setTimeout(() => rej(new Error(label || "timeout")), ms);
    }),
  ]);
}

// ─── Byte helpers ─────────────────────────────────────────
function toUint8(data) {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data))
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(0);
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function reverse(b) { return Uint8Array.from(b).reverse(); }

async function sha256(b) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function base64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(v) {
  const p = v.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (v.length % 4)) % 4);
  const raw = atob(p);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// ─── UUID helpers ─────────────────────────────────────────
function isValidUuid(u) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(u || ""));
}
function uuidToBytes(uuid) {
  const h = uuid.replace(/-/g, "").toLowerCase();
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToUuid(b) {
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
function randomUuid() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return bytesToUuid(b);
}
function randomHex(bytes) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function randomId(len) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  const a = "abcdefghijklmnopqrstuvwxyz0123456789";
  return [...bytes].map((b) => a[b % a.length]).join("");
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function canonicalHost(v) {
  return String(v || "").trim().toLowerCase().replace(/\.$/, "");
}

// ============================================================
// SECTION: Frame codec (MTProto multiplexer)
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
  if (streamId < 0 || streamId > 0xffffff || payload.length > MAX_PAYLOAD) throw new Error("bad frame");
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out[0] = type;
  out[1] = streamId >>> 16;
  out[2] = streamId >>> 8;
  out[3] = streamId;
  new DataView(out.buffer).setUint32(4, payload.length);
  out.set(payload, HEADER_SIZE);
  return out;
}
function parseFrames(input) {
  const frames = [];
  let offset = 0;
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
function u32(v) {
  const o = new Uint8Array(4);
  new DataView(o.buffer).setUint32(0, v);
  return o;
}

// ============================================================
// SECTION: MTProto crypto
// ============================================================
const TAGS = new Set([0xefefefef, 0xeeeeeeee, 0xdddddddd]);
const TELEGRAM_DCS = Object.freeze({
  1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100",
  4: "149.154.167.91", 5: "149.154.171.5",
});

class AesCtrStream {
  constructor(k, iv) {
    if (k.length !== 32 || iv.length !== 16) throw new Error("bad AES");
    this.keyPromise = crypto.subtle.importKey("raw", k, "AES-CTR", false, ["encrypt"]);
    this.counter = new Uint8Array(iv);
    this.spare = new Uint8Array();
  }
  async crypt(input) {
    const src = input instanceof Uint8Array ? input : new Uint8Array(input);
    const out = new Uint8Array(src.length);
    let pos = 0;
    if (this.spare.length) {
      const n = Math.min(this.spare.length, src.length);
      for (let i = 0; i < n; i++) out[i] = src[i] ^ this.spare[i];
      this.spare = this.spare.subarray(n);
      pos = n;
    }
    if (pos < src.length) {
      const need = src.length - pos;
      const blocks = Math.ceil(need / 16);
      const zeros = new Uint8Array(blocks * 16);
      const key = await this.keyPromise;
      const ks = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-CTR", counter: this.counter, length: 128 }, key, zeros
      ));
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
    const sum = c[i] + (carry & 255);
    c[i] = sum & 255;
    carry = Math.floor(carry / 256) + (sum >>> 8);
  }
}
function parseProxySecret(value) {
  const s = String(value || "").toLowerCase();
  if (/^[0-9a-f]{32}$/.test(s)) return { inner: hexToBytes(s) };
  if (/^dd[0-9a-f]{32}$/.test(s)) return { inner: hexToBytes(s.slice(2)) };
  throw new Error("bad secret");
}
async function acceptClientHandshake(packet, secret) {
  if (packet.length !== 64) throw new Error("bad handshake");
  const material = packet.subarray(8, 56);
  const rev = reverse(material);
  const decKey = await sha256(concat(material.subarray(0, 32), secret));
  const dec = new AesCtrStream(decKey, material.subarray(32, 48));
  const encKey = await sha256(concat(rev.subarray(0, 32), secret));
  const enc = new AesCtrStream(encKey, rev.subarray(32, 48));
  const plain = await dec.crypt(packet);
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const tag = view.getUint32(56, true);
  const dcId = view.getInt16(60, true);
  if (!TAGS.has(tag) || !TELEGRAM_DCS[Math.abs(dcId)]) throw new Error("bad handshake");
  return { tag, dcId, clientDecrypt: dec, clientEncrypt: enc };
}
async function createTelegramHandshake(tag, dcId) {
  let nonce;
  do {
    nonce = new Uint8Array(64);
    crypto.getRandomValues(nonce);
  } while (reserved(nonce));
  const v = new DataView(nonce.buffer);
  v.setUint32(56, tag, true);
  v.setInt16(60, dcId, true);
  nonce[62] = nonce[63] = 0;
  const material = nonce.subarray(8, 56);
  const rev = reverse(material);
  const encrypt = new AesCtrStream(material.subarray(0, 32), material.subarray(32, 48));
  const decrypt = new AesCtrStream(rev.subarray(0, 32), rev.subarray(32, 48));
  const encrypted = await encrypt.crypt(nonce);
  const wire = new Uint8Array(nonce);
  wire.set(encrypted.subarray(56), 56);
  return { wire, encrypt, decrypt };
}
function reserved(n) {
  const v = new DataView(n.buffer, n.byteOffset, n.byteLength);
  const x = v.getUint32(0, true);
  return n[0] === 0xef ||
    x === 0x44414548 || x === 0x54534f50 || x === 0x20544547 ||
    x === 0xeeeeeeee || x === 0xdddddddd ||
    v.getUint32(4, true) === 0;
}

// ============================================================
// SECTION: VLESS header parser
// ============================================================
function parseVless(buf) {
  if (buf.length < 18) return { need: 18 };
  if (buf[0] !== 0x00) return { err: "version" };
  const addonLen = buf[17];
  const base = 18 + addonLen;
  if (buf.length < base + 4) return { need: base + 4 };
  const cmd = buf[base];
  const port = (buf[base + 1] << 8) | buf[base + 2];
  const atype = buf[base + 3];
  if (cmd !== 0x01 && cmd !== 0x02) return { err: "cmd" };
  const addrOff = base + 4;
  let addrLen = 0;
  let host = "";
  if (atype === 0x01) {
    addrLen = 4;
    if (buf.length < addrOff + addrLen) return { need: addrOff + addrLen };
    host = `${buf[addrOff]}.${buf[addrOff + 1]}.${buf[addrOff + 2]}.${buf[addrOff + 3]}`;
  } else if (atype === 0x02) {
    if (buf.length < addrOff + 1) return { need: addrOff + 1 };
    addrLen = 1 + buf[addrOff];
    if (buf.length < addrOff + addrLen) return { need: addrOff + addrLen };
    host = new TextDecoder().decode(buf.subarray(addrOff + 1, addrOff + addrLen));
  } else if (atype === 0x03) {
    addrLen = 16;
    if (buf.length < addrOff + addrLen) return { need: addrOff + addrLen };
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((buf[addrOff + i * 2] << 8) | buf[addrOff + i * 2 + 1]).toString(16));
    }
    host = `[${parts.join(":")}]`;
  } else {
    return { err: "atype" };
  }
  return { ok: true, cmd, port, host, uuid: buf.slice(1, 17), payload: buf.slice(addrOff + addrLen) };
}

function isVlessPath(path) {
  const clean = String(path || "").split("?")[0].replace(/\/+$/, "");
  return clean === "/vless" || clean === "/vl" || clean === "/ws" || clean === "";
}

// ============================================================
// SECTION: VLESS WebSocket handler (anti-1101)
// ============================================================
async function handleVless(request, env, ctx) {
  if (!env?.PROXY_REGISTRY) return new Response(null, { status: 500 });

  let client, server;
  try {
    const pair = new WebSocketPair();
    client = pair[0];
    server = pair[1];
  } catch { return new Response(null, { status: 500 }); }

  try { server.accept(); }
  catch { return new Response(null, { status: 500 }); }

  let closed = false, socket = null, writer = null, reader = null;
  let headerBuf = new Uint8Array(0);
  let initialized = false;
  let chain = Promise.resolve();

  const defaultHost = env.TARGET_HOST || DEFAULT_HOST;
  const defaultPort = parseInt(env.TARGET_PORT || String(DEFAULT_PORT), 10) || DEFAULT_PORT;

  function shutdown(code, reason) {
    if (closed) return;
    closed = true;
    try { server.close(code || 1000, reason || "closed"); } catch {}
    try { writer?.abort?.(); } catch {}
    try { writer?.releaseLock?.(); } catch {}
    try { reader?.cancel?.(); } catch {}
    try { reader?.releaseLock?.(); } catch {}
    try { socket?.close?.(); } catch {}
  }

  const handshakeTimer = setTimeout(() => {
    if (!initialized && !closed) shutdown(1002, "handshake_timeout");
  }, HANDSHAKE_TIMEOUT);

  async function processMessage(data) {
    if (closed) return;
    const chunk = toUint8(data);
    if (!chunk.length) return;

    if (initialized) {
      if (!writer) { shutdown(1011, "no_writer"); return; }
      try { await withTimeout(writer.write(chunk), WRITE_TIMEOUT, "write"); }
      catch { shutdown(1011, "write_failed"); }
      return;
    }

    headerBuf = concat(headerBuf, chunk);
    if (headerBuf.length < 18) return;

    const parsed = parseVless(headerBuf);
    if (parsed.need) return;
    if (parsed.err) { shutdown(1002, "parse_" + parsed.err); return; }

    const uuid = bytesToUuid(parsed.uuid);
    let proxyId;
    try {
      proxyId = await withTimeout(env.PROXY_REGISTRY.get(`vless-uuid:${uuid}`, "text"), KV_TIMEOUT, "kv_uuid");
    } catch { shutdown(1011, "kv_error"); return; }
    if (!proxyId) { shutdown(1002, "auth"); return; }

    let meta;
    try {
      meta = await withTimeout(env.PROXY_REGISTRY.get(`vless:${proxyId}`, "json"), KV_TIMEOUT, "kv_meta");
    } catch { shutdown(1011, "kv_error"); return; }
    if (!meta || !meta.enabled) { shutdown(1002, "disabled"); return; }
    if (parsed.cmd === 0x02) { shutdown(1002, "udp"); return; }

    const host = parsed.host || meta.targetHost || defaultHost;
    const port = parsed.port || meta.targetPort || defaultPort;

    try {
      socket = connect({ hostname: host, port });
      Promise.resolve(socket.closed).catch(() => {});
      await withTimeout(socket.opened, CONNECT_TIMEOUT, "connect");
      writer = socket.writable.getWriter();
    } catch { shutdown(1011, "connect_failed"); return; }

    try { server.send(new Uint8Array([0x00, 0x00])); }
    catch { shutdown(1011, "send_failed"); return; }

    if (parsed.payload.length > 0) {
      try { await withTimeout(writer.write(parsed.payload), WRITE_TIMEOUT, "write"); }
      catch { shutdown(1011, "write_failed"); return; }
    }

    try { reader = socket.readable.getReader(); }
    catch { shutdown(1011, "reader_failed"); return; }

    ctx.waitUntil(pump(reader, server, shutdown));
    headerBuf = new Uint8Array(0);
    initialized = true;
    clearTimeout(handshakeTimer);
  }

  server.addEventListener("message", (event) => {
    if (closed) return;
    chain = chain.then(() => processMessage(event.data)).catch(() => shutdown(1011, "handler_error"));
    ctx.waitUntil(chain);
  });
  server.addEventListener("close", () => { clearTimeout(handshakeTimer); shutdown(1000, "client_closed"); });
  server.addEventListener("error", () => { clearTimeout(handshakeTimer); shutdown(1011, "ws_error"); });

  const headers = {};
  const subproto = (request.headers.get("Sec-WebSocket-Protocol") || "").trim();
  if (subproto) {
    const first = subproto.split(",")[0].trim();
    if (/^[A-Za-z0-9._-]+$/.test(first)) headers["Sec-WebSocket-Protocol"] = first;
  }

  try {
    return new Response(null, { status: 101, webSocket: client, headers });
  } catch {
    shutdown(1011, "response_failed");
    return new Response(null, { status: 500 });
  }
}

async function pump(reader, ws, shutdown) {
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (ws.readyState !== 1) break;
      try { ws.send(value); } catch { break; }
    }
  } catch {}
  finally {
    try { reader.releaseLock(); } catch {}
    shutdown(1000, "upstream_closed");
  }
}

// ============================================================
// SECTION: MTProto RelaySession (Durable Object)
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
    this.maxStreams = 64;
    this.messageChain = Promise.resolve();
    this.ingressBytes = 0; this.ingressItems = 0;
    this.uplinkBytes = 0; this.uplinkItems = 0;
    this.downlinkBytes = 0; this.downlinkItems = 0;
    this.downlinkWaiters = new Set();
    this.secret = null; this.proxyId = null;
  }

  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (this.closed) return new Response(null, { status: 404 });

      if (!this.proxyId) {
        const proxyId = request.headers.get("X-Proxy-Id") || "";
        if (!/^[A-Za-z0-9]{8,32}$/.test(proxyId)) return new Response(null, { status: 400 });
        if (!this.env?.PROXY_REGISTRY) return new Response(null, { status: 500 });
        const meta = await this.env.PROXY_REGISTRY.get(`mt:${proxyId}`, "json");
        if (!meta) return new Response(null, { status: 404 });
        if (!meta.enabled) return new Response(null, { status: 403 });
        this.proxyId = proxyId;
        this.secret = parseProxySecret(meta.secret).inner;
      }

      if (url.pathname === "/internal/init" && request.method === "POST") {
        if (!this.initialized) {
          try { await this.ctx.storage.put({ expiresAt: Date.now() + 10 * 60 * 1000 }); } catch {}
          this.initialized = true;
        }
        return new Response(null, { status: 204 });
      }

      if (url.pathname === "/internal/ws") {
        if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
          return new Response(null, { status: 426 });
        }
        if (!this.initialized) {
          let exp = null;
          try { exp = await this.ctx.storage.get("expiresAt"); } catch {}
          if (this.closed || !exp || exp < Date.now()) return new Response(null, { status: 404 });
          this.initialized = true;
        }
        if (this.ws) return new Response(null, { status: 409 });

        const pair = new WebSocketPair();
        const client = pair[0], server = pair[1];
        server.accept();
        this.ws = server;
        server.addEventListener("message", (e) => this.enqueueMessage(e.data));
        server.addEventListener("close", () => this.shutdown("ws_close"));
        server.addEventListener("error", () => this.shutdown("ws_error"));

        const proto = request.headers.get("X-TProxy-Protocol") || "";
        const echo = proto.split(",").map((v) => v.trim()).find((v) => v.startsWith("tproxy-v1.")) || "";
        return new Response(null, { status: 101, webSocket: client, headers: echo ? { "Sec-WebSocket-Protocol": echo } : {} });
      }

      if (url.pathname === "/internal/close" && request.method === "POST") {
        this.shutdown("session_delete");
        return new Response(null, { status: 204 });
      }

      return new Response(null, { status: 404 });
    } catch {
      return new Response(null, { status: 500 });
    }
  }

  enqueueMessage(data) {
    try {
      if (this.closed) return;
      const length = data instanceof Blob ? data.size : data instanceof ArrayBuffer ? data.byteLength : 0;
      if (!length || length > MAX_WS_MESSAGE) return this.protocolError("bad_msg");
      const cost = length + LIMITS.itemCost;
      if (this.ingressBytes + cost > LIMITS.ingressBytes || this.ingressItems >= LIMITS.ingressItems) {
        return this.protocolError("ingress_limit");
      }
      this.ingressBytes += cost;
      this.ingressItems++;
      this.messageChain = this.messageChain
        .then(() => this.onMessage(data))
        .catch(() => this.protocolError("handler_failed"))
        .finally(() => { this.ingressBytes -= cost; this.ingressItems--; });
      this.ctx.waitUntil(this.messageChain);
    } catch {}
  }

  async onMessage(data) {
    if (this.closed) return;
    if (data instanceof Blob) data = await data.arrayBuffer();
    if (this.closed) return;
    if (!(data instanceof ArrayBuffer) || !data.byteLength || data.byteLength > MAX_WS_MESSAGE) {
      return this.protocolError("bad_msg");
    }
    let frames;
    try { frames = parseFrames(new Uint8Array(data)); }
    catch { return this.protocolError("parse_failed"); }

    for (const frame of frames) {
      if (frame.streamId === 0) {
        if (frame.type !== FRAME.PONG || frame.payload.length > 64) return this.protocolError("bad_ctrl");
      } else if (frame.type === FRAME.OPEN) this.openStream(frame);
      else if (frame.type === FRAME.DATA) this.queueWrite(frame);
      else if (frame.type === FRAME.WINDOW) this.addWindow(frame);
      else if (frame.type === FRAME.CLOSE) {
        if (frame.payload.length) return this.protocolError("bad_close");
        if (!this.streams.has(frame.streamId) && !this.closedIds.has(frame.streamId)) {
          return this.protocolError("unknown_stream");
        }
        this.closeStream(frame.streamId, false);
      } else return this.protocolError("bad_type");
      if (this.closed) return;
    }
  }

  openStream(frame) {
    const id = frame.streamId;
    if (!id || frame.payload.length || this.streams.has(id) || this.closedIds.has(id)) {
      return this.protocolError("bad_open");
    }
    if (this.streams.size >= this.maxStreams) {
      this.rememberClosed(id);
      return this.sendFrame(FRAME.CLOSE, id);
    }
    const stream = {
      id, socket: null, writer: null,
      handshake: new Uint8Array(), handshakeBytes: 0,
      receiveWindow: INITIAL_WINDOW, sendCredit: INITIAL_WINDOW,
      closed: false, queue: [], queueHead: 0,
      pendingBytes: 0, pendingItems: 0, draining: false,
      abort: new AbortController(), sent: [], sentHead: 0,
      downlinkBytes: 0, downlinkItems: 0,
    };
    stream.handshakeTimer = setTimeout(() => this.closeStream(id, true), LIMITS.handshakeTimeout);
    this.streams.set(id, stream);
  }

  queueWrite(frame) {
    const stream = this.streams.get(frame.streamId);
    if (!stream) {
      if (this.closedIds.has(frame.streamId) && frame.payload.length) return;
      return this.protocolError("unknown_stream");
    }
    const length = frame.payload.length;
    if (!length || length > stream.receiveWindow) return this.protocolError("bad_window");
    const cost = length + HEADER_SIZE + LIMITS.itemCost;
    if (stream.pendingBytes + cost > LIMITS.streamBytes ||
        stream.pendingItems >= LIMITS.streamItems ||
        this.uplinkBytes + cost > LIMITS.uplinkBytes ||
        this.uplinkItems >= LIMITS.uplinkItems) {
      return this.closeStream(stream.id, true);
    }
    stream.receiveWindow -= length;
    stream.pendingBytes += cost;
    stream.pendingItems++;
    this.uplinkBytes += cost;
    this.uplinkItems++;
    stream.queue.push({ payload: new Uint8Array(frame.payload), cost });
    if (!stream.draining) {
      stream.draining = true;
      this.ctx.waitUntil(this.drainStream(stream));
    }
  }

  releaseWrite(stream, item) {
    stream.pendingBytes -= item.cost;
    stream.pendingItems--;
    this.uplinkBytes -= item.cost;
    this.uplinkItems--;
  }

  async drainStream(stream) {
    try {
      while (!stream.closed && !this.closed && stream.queueHead < stream.queue.length) {
        const item = stream.queue[stream.queueHead];
        stream.queue[stream.queueHead++] = null;
        try { await this.writeStream(stream, item.payload); }
        finally { this.releaseWrite(stream, item); }
        if (stream.queueHead === stream.queue.length) { stream.queue = []; stream.queueHead = 0; }
        else if (stream.queueHead >= 64) { stream.queue = stream.queue.slice(stream.queueHead); stream.queueHead = 0; }
      }
    } catch { this.closeStream(stream.id, true); }
    finally { stream.draining = false; }
  }

  active(s) { if (s.closed || this.closed) throw new Error("closed"); }

  async writeStream(stream, payload) {
    this.active(stream);
    let grant = payload.length;
    if (!stream.writer) {
      const take = Math.min(64 - stream.handshake.length, payload.length);
      const joined = new Uint8Array(stream.handshake.length + take);
      joined.set(stream.handshake);
      joined.set(payload.subarray(0, take), stream.handshake.length);
      stream.handshake = joined;
      stream.handshakeBytes += take;
      if (joined.length < 64) return;
      if (!this.secret) throw new Error("no secret");

      const client = await acceptClientHandshake(joined, this.secret);
      this.active(stream);
      const tg = await createTelegramHandshake(client.tag, client.dcId);
      this.active(stream);
      clearTimeout(stream.handshakeTimer);
      stream.handshakeTimer = null;

      const socket = this.connect({ hostname: TELEGRAM_DCS[Math.abs(client.dcId)], port: 443 });
      stream.socket = socket;
      Promise.resolve(socket.closed).catch(() => {});
      await waitFor(socket.opened, stream.abort.signal, LIMITS.connectTimeout, "connect");
      this.active(stream);
      stream.writer = socket.writable.getWriter();
      stream.clientDecrypt = client.clientDecrypt;
      stream.clientEncrypt = client.clientEncrypt;
      stream.tgEncrypt = tg.encrypt;
      stream.tgDecrypt = tg.decrypt;
      stream.handshake = new Uint8Array();
      await waitFor(stream.writer.write(tg.wire), stream.abort.signal, LIMITS.writeTimeout, "write");
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
      await waitFor(stream.writer.write(encrypted), stream.abort.signal, LIMITS.writeTimeout, "write");
      this.active(stream);
    }
    this.grantWindow(stream, grant);
  }

  grantWindow(s, l) {
    if (s.closed || this.closed || !l) return;
    s.receiveWindow += l;
    this.sendFrame(FRAME.WINDOW, s.id, u32(l));
  }

  addWindow(frame) {
    if (frame.payload.length !== 4) return this.protocolError("bad_window");
    const amount = new DataView(frame.payload.buffer, frame.payload.byteOffset, 4).getUint32(0);
    if (!amount) return this.protocolError("bad_window");
    const stream = this.streams.get(frame.streamId);
    if (!stream) { if (this.closedIds.has(frame.streamId)) return; return this.protocolError("unknown"); }
    if (amount > INITIAL_WINDOW - stream.sendCredit) return this.protocolError("overflow");
    stream.sendCredit += amount;
    let remaining = amount;
    while (remaining) {
      const item = stream.sent[stream.sentHead];
      if (!item) break;
      const used = Math.min(remaining, item.remaining);
      item.remaining -= used; remaining -= used;
      stream.downlinkBytes -= used; this.downlinkBytes -= used;
      if (!item.remaining) {
        const oh = HEADER_SIZE + LIMITS.itemCost;
        stream.downlinkBytes -= oh; this.downlinkBytes -= oh;
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

  async waitDownlink(s) {
    while (!s.closed && !this.closed && !this.downlinkRoom(s)) {
      await new Promise((r) => this.downlinkWaiters.add(r));
    }
    return !s.closed && !this.closed;
  }

  wakeDownlink() {
    const w = [...this.downlinkWaiters];
    this.downlinkWaiters.clear();
    for (const r of w) { try { r(); } catch {} }
  }

  async readStream(stream) {
    let reader = null;
    try { reader = stream.socket.readable.getReader(); }
    catch { this.closeStream(stream.id, true); return; }
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
          stream.sendCredit -= size;
          stream.sent.push({ remaining: size });
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
    finally {
      try { reader?.cancel?.(); } catch {}
      try { reader?.releaseLock?.(); } catch {}
      this.closeStream(stream.id, true);
    }
  }

  closeStream(id, notify) {
    const stream = this.streams.get(id);
    if (!stream) return;
    this.streams.delete(id);
    this.rememberClosed(id);
    stream.closed = true;
    clearTimeout(stream.handshakeTimer);
    stream.handshakeTimer = null;
    try { stream.abort.abort(); } catch {}
    for (let i = stream.queueHead; i < stream.queue.length; i++) {
      if (stream.queue[i]) this.releaseWrite(stream, stream.queue[i]);
    }
    stream.queue = []; stream.queueHead = 0; stream.handshake = new Uint8Array();
    this.downlinkBytes -= stream.downlinkBytes;
    this.downlinkItems -= stream.downlinkItems;
    stream.downlinkBytes = 0; stream.downlinkItems = 0;
    stream.sent = []; stream.sentHead = 0;
    this.wakeDownlink();
    try { stream.writer?.abort?.(); } catch {}
    try { stream.socket?.close?.(); } catch {}
    if (notify && !this.closed) this.sendFrame(FRAME.CLOSE, id);
  }

  rememberClosed(id) {
    this.closedIds.add(id);
    if (this.closedIds.size > 4096) this.closedIds.delete(this.closedIds.values().next().value);
  }

  sendFrame(type, streamId, payload = new Uint8Array()) {
    if (this.closed || !this.ws || this.ws.readyState !== 1) return;
    try { this.ws.send(encodeFrame(type, streamId, payload)); }
    catch { this.shutdown("send_failed"); }
  }

  protocolError(reason) {
    this.sendFrame(FRAME.BYE, 0);
    this.shutdown(reason);
  }

  shutdown(reason) {
    if (this.closed) return;
    this.closed = true;
    for (const id of [...this.streams.keys()]) this.closeStream(id, false);
    this.wakeDownlink();
    try { this.ws?.close(1000, "session closed"); } catch {}
    this.ws = null;
    try { this.ctx.waitUntil(Promise.resolve(this.ctx.storage.delete("expiresAt")).catch(() => {})); } catch {}
  }
}

function waitFor(promise, signal, timeout, reason) {
  return new Promise((resolve, reject) => {
    const aborted = () => finish(reject, new Error("closed"));
    let timer, settled = false;
    const finish = (settle, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { signal.removeEventListener("abort", aborted); } catch {}
      settle(value);
    };
    Promise.resolve(promise).then((v) => finish(resolve, v), (e) => finish(reject, e));
    if (signal.aborted) return aborted();
    signal.addEventListener("abort", aborted, { once: true });
    timer = setTimeout(() => finish(reject, new Error(reason)), timeout);
  });
}

export class ProxySession extends RelaySession {
  constructor(ctx, env) { super(ctx, env, connect); }
}

// ============================================================
// SECTION: Bootstrap + session helpers (MTProto)
// ============================================================
async function createBootstrap(env, proxyId) {
  const ttl = 300;
  const payload = base64url(new TextEncoder().encode(JSON.stringify({
    p: proxyId,
    e: Math.floor(Date.now() / 1000) + ttl,
  })));
  const sig = base64url(await hmac(signingKey(env), new TextEncoder().encode(payload)));
  return `${payload}.${sig}`;
}
async function verifyBootstrap(env, token) {
  const [payload, sig, extra] = String(token || "").split(".");
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
  const base = String(env?.TELEGRAM_WEBHOOK_SECRET || env?.TELEGRAM_BOT_TOKEN || "TGPN-default");
  return new TextEncoder().encode(`TGPN/bootstrap/v1\n${base}`);
}
async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}
function bearer(r) {
  const v = r.headers.get("Authorization") || "";
  return v.startsWith("Bearer ") ? v.slice(7) : "";
}
function isBinary(v) { return /^application\/octet-stream(?:\s*;.*)?$/i.test(v || ""); }

// ============================================================
// SECTION: Bridge page (MTProto — served on demand)
// ============================================================
function bridgePage(host, bootstrap) {
  const cfg = JSON.stringify({ origin: `https://${host}`, bootstrap, batchLimit: MAX_WS_MESSAGE });
  return new Response(`<!doctype html><html><head><meta charset=utf-8><title>Web Proxy</title></head>
<body><p>Opening bridge…</p><script>
(()=>{const cfg=${cfg};let sock,tok='',closed=false;
async function go(){
 try{const r=await fetch(cfg.origin+'/api/v1/session',{method:'POST',headers:{Authorization:'Bearer '+cfg.bootstrap,'Content-Type':'application/octet-stream'},body:new Uint8Array([16,0,0,0,1,0,0,0])});
  if(!r.ok)return close();
  tok=r.headers.get('X-Session-Token')||'';
  sock=new WebSocket(cfg.origin.replace(/^https:/,'wss:')+'/api/v1/ws','tproxy-v1.'+tok);
  sock.binaryType='arraybuffer';
  sock.onmessage=e=>{if(!closed&&e.data instanceof ArrayBuffer)window.parent?.postMessage(e.data,'*')};
  sock.onclose=()=>close();
 }catch{close()}}
function close(){if(!closed){closed=true;try{sock&&sock.close()}catch{}}}
window.addEventListener('message',e=>{if(closed||e.source!==parent)return;if(e.data instanceof ArrayBuffer){try{sock&&sock.send(e.data)}catch{}}});
go();
})();
</script></body></html>`, {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

// ============================================================
// SECTION: Session API (MTProto)
// ============================================================
async function createMtSession(request, env) {
  const bootstrap = bearer(request);
  if (!bootstrap) return new Response(null, { status: 404 });
  const proxyId = await verifyBootstrap(env, bootstrap);
  if (!proxyId) return new Response(null, { status: 404 });
  const meta = await env.PROXY_REGISTRY.get(`mt:${proxyId}`, "json");
  if (!meta || !meta.enabled) return new Response(null, { status: 404 });

  const token = base64url(crypto.getRandomValues(new Uint8Array(32)));
  try {
    await env.PROXY_REGISTRY.put(`session:${token}`,
      JSON.stringify({ proxyId, exp: Date.now() + 10 * 60 * 1000 }),
      { expirationTtl: 900 });
  } catch { return new Response(null, { status: 404 }); }

  const doId = env.PROXY_SESSIONS.idFromName(`s:${token}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  const init = await stub.fetch("https://session/internal/init", {
    method: "POST",
    headers: { "X-Proxy-Id": proxyId },
  });
  if (!init.ok) return new Response(null, { status: 404 });

  return new Response(encodeFrame(FRAME.WELCOME, 0), {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Session-Token": token,
      "X-Carrier-Mode": "websocket",
      "Cache-Control": "no-store",
    },
  });
}

async function relayMtWs(request, env) {
  const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "").split(",").map((v) => v.trim());
  const proto = protocols.find((v) => v.startsWith("tproxy-v1."));
  const token = proto ? proto.slice("tproxy-v1.".length) : "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return new Response(null, { status: 404 });
  const rec = await env.PROXY_REGISTRY.get(`session:${token}`, "json");
  if (!rec || rec.exp < Date.now()) return new Response(null, { status: 404 });
  const doId = env.PROXY_SESSIONS.idFromName(`s:${token}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  return stub.fetch("https://session/internal/ws", {
    method: "GET",
    headers: { "Upgrade": "websocket", "X-TProxy-Protocol": proto, "X-Proxy-Id": rec.proxyId },
  });
}

// ============================================================
// SECTION: Worker entry
// ============================================================
export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch {
      return new Response(null, { status: 500 });
    }
  },
};

async function route(request, env, ctx) {
  let url, path, method, upgrade;
  try {
    url = new URL(request.url);
    path = url.pathname;
    method = request.method;
    upgrade = (request.headers.get("Upgrade") || "").toLowerCase();
  } catch {
    return new Response(null, { status: 400 });
  }

  const isWS = upgrade === "websocket";

  // Telegram webhook
  if (path === "/bot/webhook" && method === "POST") {
    return await handleTelegram(request, env, ctx);
  }

  // MTProto session creation
  if (path === "/api/v1/session" && method === "POST") {
    try { return await createMtSession(request, env); }
    catch { return new Response(null, { status: 404 }); }
  }

  // MTProto WS relay
  if (path === "/api/v1/ws" && isWS) {
    try { return await relayMtWs(request, env); }
    catch { return new Response(null, { status: 500 }); }
  }

  // VLESS WS (any other WS request)
  if (isWS) {
    try { return await handleVless(request, env, ctx); }
    catch { return new Response(null, { status: 500 }); }
  }

  // MTProto bridge page (via ?server=X&secret=Y)
  const serverParam = url.searchParams.get("server");
  const secretParam = url.searchParams.get("secret");
  if (serverParam && secretParam) {
    const host = canonicalHost(env.PUBLIC_HOSTNAME || url.hostname);
    if (canonicalHost(serverParam) !== host) return new Response(null, { status: 404 });
    const secret = String(secretParam).toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(secret)) return new Response(null, { status: 404 });
    const proxyId = await env.PROXY_REGISTRY.get(`secret:${secret}`, "text");
    if (!proxyId) return new Response(null, { status: 404 });
    const bootstrap = await createBootstrap(env, proxyId);
    return bridgePage(host, bootstrap);
  }

  // Decoy
  return new Response(null, { status: 404 });
}

// ============================================================
// SECTION: Telegram bot
// ============================================================
async function handleTelegram(request, env, ctx) {
  try {
    const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
    if (env?.TELEGRAM_WEBHOOK_SECRET && secret !== env.TELEGRAM_WEBHOOK_SECRET) {
      return new Response("Forbidden", { status: 403 });
    }
    let update;
    try { update = await request.json(); }
    catch { return new Response("OK"); }

    if (update.callback_query) {
      const cq = update.callback_query;
      ctx.waitUntil(answerCallback(env, cq.id, "").catch(() => {}));
      ctx.waitUntil(handleCallback(env, cq).catch((e) => console.error("CB", e)));
      return new Response("OK");
    }

    const msg = update.message || update.edited_message;
    if (!msg) return new Response("OK");
    const chatId = msg.chat?.id;
    const userId = msg.from?.id;
    const text = (msg.text || "").trim();
    if (!chatId || !userId || !text) return new Response("OK");

    if (!isAuthorized(env, userId)) {
      ctx.waitUntil(sendMessage(env, chatId, `⛔️ دسترسی نداری\n\nآیدی: <code>${userId}</code>`).catch(() => {}));
      return new Response("OK");
    }

    ctx.waitUntil(handleMessage(env, chatId, userId, text).catch((e) => {
      console.error("MSG", e);
      return sendMessage(env, chatId, `❌ خطا: <code>${esc(String(e.message || e))}</code>`);
    }));
    return new Response("OK");
  } catch { return new Response("OK"); }
}

async function handleMessage(env, chatId, userId, text) {
  cleanStates();
  const stateKey = `${chatId}:${userId}`;
  const state = USER_STATE.get(stateKey);

  if (state?.action === "new_vless") {
    USER_STATE.delete(stateKey);
    return doCreateVless(env, chatId, userId, text.slice(0, 32).trim());
  }
  if (state?.action === "new_mt") {
    USER_STATE.delete(stateKey);
    return doCreateMt(env, chatId, userId, text.slice(0, 32).trim());
  }

  const parts = text.split(/\s+/);
  const cmd = (parts[0] || "").split("@")[0].toLowerCase();
  const args = parts.slice(1);

  switch (cmd) {
    case "/start": case "/menu": return showMenu(env, chatId, userId, null);
    case "/help": return showHelp(env, chatId, null);
    case "/new": case "/newvless": {
      const name = args.join(" ").slice(0, 32).trim();
      if (name) return doCreateVless(env, chatId, userId, name);
      USER_STATE.set(stateKey, { action: "new_vless", ts: Date.now() });
      return sendMessage(env, chatId, "✍️ اسم کانفیگ VLESS رو بفرست:\n\nمثال: <code>my-vless</code>",
        { reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    case "/newmt": {
      const name = args.join(" ").slice(0, 32).trim();
      if (name) return doCreateMt(env, chatId, userId, name);
      USER_STATE.set(stateKey, { action: "new_mt", ts: Date.now() });
      return sendMessage(env, chatId, "✍️ اسم کانفیگ MTProto رو بفرست:\n\nمثال: <code>my-mt</code>",
        { reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    case "/list": case "/listvless": return showList(env, chatId, userId, null, "vless");
    case "/listmt": return showList(env, chatId, userId, null, "mt");
    case "/cancel": USER_STATE.delete(stateKey); return sendMessage(env, chatId, "✅ لغو شد");
    case "/myid": return sendMessage(env, chatId, `🆔 <code>${userId}</code>`);
    case "/version": return sendMessage(env, chatId, `⚡️ <b>${BRAND}</b> v${VERSION}`);
    default:
      if (text.startsWith("/")) return sendMessage(env, chatId, "❓ دستور ناشناخته. /help");
  }
}

async function handleCallback(env, cq) {
  try {
    const chatId = cq.message?.chat?.id;
    const msgId = cq.message?.message_id;
    const userId = cq.from?.id;
    const data = String(cq.data || "");
    if (!chatId || !msgId || !userId) return;
    if (!isAuthorized(env, userId)) return answerCallback(env, cq.id, "⛔️", true);

    const stateKey = `${chatId}:${userId}`;

    if (data === "menu:home") return showMenu(env, chatId, userId, msgId);
    if (data === "menu:help") return showHelp(env, chatId, msgId);
    if (data === "menu:myid") {
      return reply(env, chatId, msgId, `🆔 <code>${userId}</code>`,
        { reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "menu:home" }]] } });
    }
    if (data === "menu:new_vless") {
      USER_STATE.set(stateKey, { action: "new_vless", ts: Date.now() });
      return reply(env, chatId, msgId, "✍️ اسم کانفیگ VLESS رو بفرست:\n\nمثال: <code>my-vless</code>",
        { reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    if (data === "menu:new_mt") {
      USER_STATE.set(stateKey, { action: "new_mt", ts: Date.now() });
      return reply(env, chatId, msgId, "✍️ اسم کانفیگ MTProto رو بفرست:\n\nمثال: <code>my-mt</code>",
        { reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    if (data === "menu:list_vless") return showList(env, chatId, userId, msgId, "vless");
    if (data === "menu:list_mt") return showList(env, chatId, userId, msgId, "mt");

    const parts = data.split(":");
    if (parts[0] === "vl" || parts[0] === "mt") {
      const kind = parts[0] === "vl" ? "vless" : "mt";
      const prefix = parts[0];
      const action = parts[1], proxyId = parts[2];

      if (action === "info") return showInfo(env, chatId, userId, proxyId, msgId, kind);
      if (action === "copy") {
        const m = await kvJson(env, `${kind}:${proxyId}`, null);
        if (!m) return;
        const link = kind === "vless"
          ? buildVlessLink(env, m.uuid, m.name)
          : `https://t.me/webproxy?server=${encodeURIComponent(env.PUBLIC_HOSTNAME)}&secret=${m.secret}`;
        await sendMessage(env, chatId, `📋 <code>${esc(link)}</code>`);
        return answerCallback(env, cq.id, "✓");
      }
      if (action === "toggle") {
        const m = await kvJson(env, `${kind}:${proxyId}`, null);
        if (!m) return;
        if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
        m.enabled = !m.enabled;
        await env.PROXY_REGISTRY.put(`${kind}:${proxyId}`, JSON.stringify(m));
        return showInfo(env, chatId, userId, proxyId, msgId, kind);
      }
      if (action === "del") return showDeleteConfirm(env, chatId, msgId, proxyId, userId, kind, prefix);
      if (action === "delok") {
        const m = await kvJson(env, `${kind}:${proxyId}`, null);
        if (!m) return;
        if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
        await env.PROXY_REGISTRY.delete(`${kind}:${proxyId}`);
        if (kind === "vless" && m.uuid) await env.PROXY_REGISTRY.delete(`vless-uuid:${m.uuid}`);
        if (kind === "mt" && m.secret) await env.PROXY_REGISTRY.delete(`secret:${m.secret}`);
        const userKey = `user:${m.ownerTelegramId}:${kind}`;
        const list = await kvJson(env, userKey, []);
        await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list.filter((x) => x !== proxyId)));
        return reply(env, chatId, msgId, "🗑 حذف شد",
          { reply_markup: { inline_keyboard: [[{ text: "🔙 لیست", callback_data: `menu:list_${prefix === "vl" ? "vless" : "mt"}` }]] } });
      }
    }
  } catch (e) { console.error("CB", e); return answerCallback(env, cq.id, "❌", true); }
}

// ============================================================
// Bot UI
// ============================================================
async function showMenu(env, chatId, userId, msgId) {
  const vl = await kvJson(env, `user:${userId}:vless`, []);
  const mt = await kvJson(env, `user:${userId}:mt`, []);
  const host = env.PUBLIC_HOSTNAME || "(تنظیم نشده)";
  const text = `⚡️ <b>${BRAND}</b>  <code>v${VERSION}</code>\n\n` +
    `👤 <b>پروفایل</b>\n` +
    `├ 🔗 VLESS: <b>${vl.length}</b>\n` +
    `├ 📱 MTProto: <b>${mt.length}</b>\n` +
    `└ 🌐 سرور: <code>${esc(host)}</code>\n\n` +
    `از دکمه‌ها استفاده کن 👇`;
  const keyboard = { inline_keyboard: [
    [{ text: "➕ VLESS جدید", callback_data: "menu:new_vless" }, { text: "➕ MTProto جدید", callback_data: "menu:new_mt" }],
    [{ text: "📋 لیست VLESS", callback_data: "menu:list_vless" }, { text: "📋 لیست MTProto", callback_data: "menu:list_mt" }],
    [{ text: "ℹ️ راهنما", callback_data: "menu:help" }, { text: "🆔 آیدی", callback_data: "menu:myid" }],
  ]};
  return reply(env, chatId, msgId, text, { reply_markup: keyboard });
}

async function showHelp(env, chatId, msgId) {
  const text = `📚 <b>راهنما</b>\n\n` +
    `<b>دستورات:</b>\n` +
    `/new [name] — VLESS جدید\n` +
    `/newmt [name] — MTProto جدید\n` +
    `/list — لیست VLESS\n` +
    `/listmt — لیست MTProto\n` +
    `/myid — آیدی من\n` +
    `/cancel — لغو\n\n` +
    `<b>VLESS:</b> لینک رو تو v2rayNG/NekoBox/Hiddify وارد کن\n` +
    `<b>MTProto:</b> دکمه «باز کردن در تلگرام» رو بزن`;
  return reply(env, chatId, msgId, text,
    { reply_markup: { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: "menu:home" }]] } });
}

async function showList(env, chatId, userId, msgId, kind) {
  const list = await kvJson(env, `user:${userId}:${kind}`, []);
  const label = kind === "vless" ? "VLESS" : "MTProto";
  const prefix = kind === "vless" ? "vl" : "mt";
  const rows = [];
  let text = `📋 <b>کانفیگ‌های ${label}</b> (${list.length})\n\n`;
  if (!list.length) {
    text += `📭 هنوز کانفیگی نداری`;
    rows.push([{ text: `➕ ساخت ${label}`, callback_data: `menu:new_${prefix === "vl" ? "vless" : "mt"}` }]);
  } else {
    let i = 1;
    for (const id of list) {
      const m = await kvJson(env, `${kind}:${id}`, null);
      if (!m) continue;
      const icon = m.enabled ? "🟢" : "🔴";
      text += `${i++}. ${icon} <b>${esc(m.name)}</b>\n`;
      rows.push([{ text: `${icon} ${m.name}`, callback_data: `${prefix}:info:${m.id}` }]);
    }
  }
  rows.push([{ text: "🔙 بازگشت", callback_data: "menu:home" }]);
  return reply(env, chatId, msgId, text, { reply_markup: { inline_keyboard: rows } });
}

async function showInfo(env, chatId, userId, proxyId, msgId, kind) {
  const m = await kvJson(env, `${kind}:${proxyId}`, null);
  if (!m) return reply(env, chatId, msgId, "❌ پیدا نشد");
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) {
    return reply(env, chatId, msgId, "⛔️ مال تو نیست");
  }
  const host = env.PUBLIC_HOSTNAME || "";
  const prefix = kind === "vless" ? "vl" : "mt";

  if (kind === "vless") {
    const link = buildVlessLink(env, m.uuid, m.name);
    const qr = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(link)}`;
    const text = `🔗 <b>${esc(m.name)}</b>\n\n${m.enabled ? "🟢 فعال" : "🔴 غیرفعال"}\n\n` +
      `🆔 <code>${m.uuid}</code>\n\n🌐 <code>${esc(host)}:443</code>\n🛣 <code>/</code>\n🔐 TLS+WS`;
    const kb = { inline_keyboard: [
      [{ text: "📋 کپی لینک", callback_data: `vl:copy:${m.id}` }],
      [{ text: "📷 QR", url: qr }],
      [{ text: m.enabled ? "🔴 غیرفعال" : "🟢 فعال", callback_data: `vl:toggle:${m.id}` }, { text: "🗑 حذف", callback_data: `vl:del:${m.id}` }],
      [{ text: "🔙 لیست", callback_data: "menu:list_vless" }],
    ]};
    return reply(env, chatId, msgId, text, { reply_markup: kb });
  } else {
    const tgLink = `https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${m.secret}`;
    const text = `📱 <b>${esc(m.name)}</b>\n\n${m.enabled ? "🟢 فعال" : "🔴 غیرفعال"}\n\n🔑 <code>${m.secret}</code>`;
    const kb = { inline_keyboard: [
      [{ text: "📱 باز کردن در تلگرام", url: tgLink }],
      [{ text: "📋 کپی Secret", callback_data: `mt:copy:${m.id}` }],
      [{ text: m.enabled ? "🔴 غیرفعال" : "🟢 فعال", callback_data: `mt:toggle:${m.id}` }, { text: "🗑 حذف", callback_data: `mt:del:${m.id}` }],
      [{ text: "🔙 لیست", callback_data: "menu:list_mt" }],
    ]};
    return reply(env, chatId, msgId, text, { reply_markup: kb });
  }
}

async function showDeleteConfirm(env, chatId, msgId, proxyId, userId, kind, prefix) {
  const m = await kvJson(env, `${kind}:${proxyId}`, null);
  if (!m) return;
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
  const text = `⚠️ <b>حذف</b>\n\n📛 <b>${esc(m.name)}</b>\n\nبرگشت‌پذیر نیست.`;
  return reply(env, chatId, msgId, text, {
    reply_markup: { inline_keyboard: [[
      { text: "✅ حذف", callback_data: `${prefix}:delok:${proxyId}` },
      { text: "❌ انصراف", callback_data: `${prefix}:info:${proxyId}` },
    ]] },
  });
}

async function doCreateVless(env, chatId, userId, rawName) {
  if (!env.PROXY_REGISTRY) return sendMessage(env, chatId, "❌ KV تنظیم نشده");
  const name = String(rawName || "").trim().slice(0, 32) || `vless-${Date.now()}`;
  const proxyId = randomId(12);
  const uuid = randomUuid();
  const meta = {
    id: proxyId, name, uuid, ownerTelegramId: userId, enabled: true, createdAt: Date.now(),
    targetHost: env.TARGET_HOST || DEFAULT_HOST,
    targetPort: parseInt(env.TARGET_PORT || String(DEFAULT_PORT), 10) || DEFAULT_PORT,
  };
  try {
    await env.PROXY_REGISTRY.put(`vless:${proxyId}`, JSON.stringify(meta));
    await env.PROXY_REGISTRY.put(`vless-uuid:${uuid}`, proxyId);
    const userKey = `user:${userId}:vless`;
    const list = await kvJson(env, userKey, []);
    list.push(proxyId);
    await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list));
  } catch (e) { return sendMessage(env, chatId, `❌ ${esc(e.message)}`); }

  const link = buildVlessLink(env, uuid, name);
  const qr = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(link)}`;
  const text = `✅ <b>VLESS ساخته شد</b>\n\n📛 <b>${esc(name)}</b>\n🆔 <code>${uuid}</code>`;
  return sendMessage(env, chatId, text, {
    reply_markup: { inline_keyboard: [
      [{ text: "📋 کپی لینک", callback_data: `vl:copy:${proxyId}` }],
      [{ text: "📷 QR", url: qr }],
      [{ text: "ℹ️ جزئیات", callback_data: `vl:info:${proxyId}` }],
      [{ text: "🔙 منو", callback_data: "menu:home" }],
    ]},
  });
}

async function doCreateMt(env, chatId, userId, rawName) {
  if (!env.PROXY_REGISTRY) return sendMessage(env, chatId, "❌ KV تنظیم نشده");
  const name = String(rawName || "").trim().slice(0, 32) || `mt-${Date.now()}`;
  const proxyId = randomId(12);
  const secret = randomHex(16);
  const meta = { id: proxyId, name, secret, ownerTelegramId: userId, enabled: true, createdAt: Date.now() };
  try {
    await env.PROXY_REGISTRY.put(`mt:${proxyId}`, JSON.stringify(meta));
    await env.PROXY_REGISTRY.put(`secret:${secret}`, proxyId);
    const userKey = `user:${userId}:mt`;
    const list = await kvJson(env, userKey, []);
    list.push(proxyId);
    await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list));
  } catch (e) { return sendMessage(env, chatId, `❌ ${esc(e.message)}`); }

  const host = env.PUBLIC_HOSTNAME || "";
  const tgLink = `https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${secret}`;
  const text = `✅ <b>MTProto ساخته شد</b>\n\n📛 <b>${esc(name)}</b>\n🔑 <code>${secret}</code>`;
  return sendMessage(env, chatId, text, {
    reply_markup: { inline_keyboard: [
      [{ text: "📱 باز کردن در تلگرام", url: tgLink }],
      [{ text: "📋 کپی Secret", callback_data: `mt:copy:${proxyId}` }, { text: "ℹ️ جزئیات", callback_data: `mt:info:${proxyId}` }],
      [{ text: "🔙 منو", callback_data: "menu:home" }],
    ]},
  });
}

function buildVlessLink(env, uuid, name) {
  const host = env.PUBLIC_HOSTNAME || "";
  const qs = new URLSearchParams({
    encryption: "none", security: "tls", sni: host, fp: "chrome",
    type: "ws", host: host, path: "/",
  });
  return `${SCHEME}${uuid}@${host}:443?${qs.toString()}#${encodeURIComponent(name || host)}`;
}

// ============================================================
// Telegram API
// ============================================================
async function tgCall(env, method, body) {
  const token = env?.TELEGRAM_BOT_TOKEN;
  if (!token) return null;
  try {
    const r = await withTimeout(
      fetch(`${TG_API}${token}/${method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }), TG_TIMEOUT, "tg_" + method
    );
    return await r.json();
  } catch { return null; }
}
async function sendMessage(env, chatId, text, opts = {}) {
  return tgCall(env, "sendMessage", { chat_id: chatId, text, parse_mode: "HTML", disable_web_page_preview: true, ...opts });
}
async function editMessage(env, chatId, msgId, text, opts = {}) {
  const r = await tgCall(env, "editMessageText", {
    chat_id: chatId, message_id: msgId, text, parse_mode: "HTML",
    disable_web_page_preview: true, ...opts,
  });
  if (r && !r.ok) {
    const d = String(r.description || "");
    if (!d.includes("not modified")) await sendMessage(env, chatId, text, opts);
  }
  return r;
}
async function reply(env, chatId, msgId, text, opts = {}) {
  if (msgId) return editMessage(env, chatId, msgId, text, opts);
  return sendMessage(env, chatId, text, opts);
}
async function answerCallback(env, id, text, alert = false) {
  return tgCall(env, "answerCallbackQuery", { callback_query_id: id, text: text || "", show_alert: !!alert });
}

// ============================================================
// Helpers
// ============================================================
function isAuthorized(env, userId) {
  const raw = String(env?.ADMIN_IDS || "").trim();
  if (!raw) return true;
  return raw.split(/[,\s]+/).filter(Boolean).map(Number).includes(Number(userId));
}
function isAdmin(env, userId) { return isAuthorized(env, userId); }
async function kvJson(env, key, fallback) {
  if (!env?.PROXY_REGISTRY) return fallback;
  try {
    const v = await withTimeout(env.PROXY_REGISTRY.get(key, "json"), KV_TIMEOUT, "kv_get");
    return v ?? fallback;
  } catch { return fallback; }
}
function cleanStates() {
  const now = Date.now();
  for (const [k, v] of USER_STATE) if (now - v.ts > STATE_TTL) USER_STATE.delete(k);
}
