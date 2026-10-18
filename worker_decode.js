// @ts-nocheck
// ============================================================
// TGPN-VLESS v9.3.2 "Bulletproof" — Full Fixed Version
// Fixes: 1101 (string detection, WS lifecycle, unresolved promises)
// ============================================================

import { connect } from "cloudflare:sockets";

export const VERSION = "9.3.2";
export const BRAND = "TGPN-VLESS";
export const BUILD_TAG = "bulletproof-2026";

// ============================================================
// SECTION 1: Safe helpers
// ============================================================
function canonicalHost(v) {
  return String(v || "").trim().toLowerCase().replace(/\.$/, "");
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
function randomUuid() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
function isValidUuid(u) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(u || ""));
}
function uuidToBytes(uuid) {
  const hex = String(uuid).replace(/-/g, "").toLowerCase();
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToUuid(b) {
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
function clampInt(v, min, max, fb) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fb;
}
function noStore() { return { "Cache-Control": "no-store" }; }
function notFound() {
  return new Response(
    "<!doctype html><meta charset=utf-8><title>Not found</title><h1>Not found</h1>",
    { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", ...noStore() } }
  );
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
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function bearer(r) {
  const v = r.headers.get("Authorization") || "";
  return v.startsWith("Bearer ") ? v.slice(7) : "";
}
function isBinary(v) { return /^application\/octet-stream(?:\s*;.*)?$/i.test(v || ""); }
async function sha256(b) { return new Uint8Array(await crypto.subtle.digest("SHA-256", b)); }
function concat(a, b) {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0); o.set(b, a.length);
  return o;
}
function reverse(b) { return Uint8Array.from(b).reverse(); }
function hex(s) {
  const x = new Uint8Array(s.length / 2);
  for (let i = 0; i < x.length; i++) x[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return x;
}
function toUint8(data) {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(0);
}
function safeError(e) {
  try { return String(e && (e.stack || e.message) || e); } catch { return "unknown_error"; }
}
function log(...args) {
  try { console.log(`[${BRAND}]`, ...args); } catch {}
}
function logErr(...args) {
  try { console.error(`[${BRAND}]`, ...args); } catch {}
}

// ============================================================
// SECTION 2: Timeout helpers (anti-1101)
// ============================================================
function withTimeout(promise, ms, reason) {
  let timer;
  return Promise.race([
    Promise.resolve(promise).finally(() => clearTimeout(timer)),
    new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(reason)), ms); })
  ]);
}
function writeWithTimeout(writer, data, ms = 15000) {
  return withTimeout(writer.write(data), ms, "write_timeout");
}
function connectWithTimeout(socket, ms = 10000) {
  return withTimeout(socket.opened, ms, "connect_timeout");
}

// ============================================================
// SECTION 3: Frame multiplexer (MTProto)
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
// SECTION 4: MTProto crypto
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
  if (/^[0-9a-f]{32}$/.test(s)) return { bridge: hex(s), inner: hex(s), mode: "plain" };
  if (/^dd[0-9a-f]{32}$/.test(s)) return { bridge: hex(s), inner: hex(s.slice(2)), mode: "dd" };
  throw new Error("PROXY_SECRET must be 32 hex chars");
}
async function acceptClientHandshake(packet, secret) {
  if (packet.length !== 64) throw new Error("bad handshake length");
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
  if (!TAGS.has(tag) || !TELEGRAM_DCS[Math.abs(dcId)]) throw new Error("invalid MTProxy handshake");
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
// SECTION 5: VLESS parser
// ============================================================
const VLESS_VERSION = 0x00;
const VLESS_CMD_TCP = 0x01;
const VLESS_CMD_UDP = 0x02;
const VLESS_ATYPE_IPV4 = 0x01;
const VLESS_ATYPE_DOMAIN = 0x02;
const VLESS_ATYPE_IPV6 = 0x03;

function parseVlessHeader(buf, expectedUuidBytes) {
  if (buf.length < 18) return { need: 18 };
  if (buf[0] !== VLESS_VERSION) return { error: "bad_version" };
  if (expectedUuidBytes) {
    for (let i = 0; i < 16; i++) {
      if (buf[1 + i] !== expectedUuidBytes[i]) return { error: "bad_uuid" };
    }
  }
  const addonLen = buf[17];
  const base = 18 + addonLen;
  if (buf.length < base + 4) return { need: base + 4 };
  const cmd = buf[base];
  const port = (buf[base + 1] << 8) | buf[base + 2];
  const atype = buf[base + 3];
  if (cmd !== VLESS_CMD_TCP && cmd !== VLESS_CMD_UDP) return { error: "bad_command" };
  const addrOffset = base + 4;
  let addrLen = 0;
  let hostname = "";
  if (atype === VLESS_ATYPE_IPV4) {
    addrLen = 4;
    if (buf.length < addrOffset + addrLen) return { need: addrOffset + addrLen };
    hostname = `${buf[addrOffset]}.${buf[addrOffset + 1]}.${buf[addrOffset + 2]}.${buf[addrOffset + 3]}`;
  } else if (atype === VLESS_ATYPE_DOMAIN) {
    if (buf.length < addrOffset + 1) return { need: addrOffset + 1 };
    addrLen = 1 + buf[addrOffset];
    if (buf.length < addrOffset + addrLen) return { need: addrOffset + addrLen };
    hostname = new TextDecoder().decode(buf.subarray(addrOffset + 1, addrOffset + addrLen));
  } else if (atype === VLESS_ATYPE_IPV6) {
    addrLen = 16;
    if (buf.length < addrOffset + addrLen) return { need: addrOffset + addrLen };
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((buf[addrOffset + i * 2] << 8) | buf[addrOffset + i * 2 + 1]).toString(16));
    }
    hostname = `[${parts.join(":")}]`;
  } else {
    return { error: "bad_atype" };
  }
  const payloadOffset = addrOffset + addrLen;
  return { ok: true, cmd, port, atype, hostname, payload: buf.subarray(payloadOffset) };
}

// ============================================================
// SECTION 6: VLESS path detection — FIX: no empty match
// ============================================================
function isVlessPath(path) {
  const clean = String(path || "").split("?")[0].replace(/\/+$/, "");
  return clean === "/vless" || clean === "/vl" || clean === "/ws";
}

// ============================================================
// SECTION 7: VLESS WebSocket handler — FULLY FIXED
// ============================================================
async function handleVlessWS(request, env, ctx) {
  log("VLESS_HANDLER_ENTER");

  let pair, client, server;
  try {
    pair = new WebSocketPair();
    client = pair[0];
    server = pair[1];
  } catch (e) {
    logErr("VLESS_PAIR_FAIL", safeError(e));
    return new Response("cannot create websocket pair", { status: 500 });
  }

  try {
    server.accept();
  } catch (e) {
    logErr("VLESS_ACCEPT_FAIL", safeError(e));
    return new Response("ws accept failed", { status: 500 });
  }

  const state = {
    closed: false,
    socket: null,
    writer: null,
    reader: null,
    headerBuf: new Uint8Array(0),
    initialized: false,
  };

  const defaultHost = String(env?.VLESS_TARGET_HOST || "www.cloudflare.com").trim() || "www.cloudflare.com";
  const defaultPort = parseInt(env?.VLESS_TARGET_PORT || "443", 10) || 443;

  const shutdown = (code = 1000, reason = "closed") => {
    if (state.closed) return;
    state.closed = true;
    log("VLESS_SHUTDOWN", code, reason);
    try { server.close(code, reason); } catch {}
    try { state.writer?.abort?.(); } catch {}
    try { state.writer?.releaseLock?.(); } catch {}
    try { state.reader?.cancel?.(); } catch {}
    try { state.reader?.releaseLock?.(); } catch {}
    try { state.socket?.close?.(); } catch {}
  };

  const idleTimer = setTimeout(() => {
    if (!state.initialized && !state.closed) {
      logErr("VLESS_HANDSHAKE_TIMEOUT");
      shutdown(1002, "handshake_timeout");
    }
  }, 45000);

  server.addEventListener("message", (event) => {
    if (state.closed) return;
    ctx.waitUntil((async () => {
      try {
        const chunk = toUint8(event.data);
        if (!chunk.length) return;

        if (state.initialized) {
          if (!state.writer) {
            logErr("VLESS_NO_WRITER");
            shutdown(1011, "no_writer");
            return;
          }
          await writeWithTimeout(state.writer, chunk);
          return;
        }

        state.headerBuf = concat(state.headerBuf, chunk);
        if (state.headerBuf.length < 17) return;

        if (state.headerBuf[0] !== VLESS_VERSION) {
          logErr("VLESS_BAD_VERSION", state.headerBuf[0]);
          shutdown(1002, "bad_version");
          return;
        }

        const uuid = bytesToUuid(state.headerBuf.subarray(1, 17));
        log("VLESS_UUID", uuid.slice(0, 8));

        let proxyId = null;
        try {
          if (!env?.PROXY_REGISTRY) throw new Error("KV not bound");
          proxyId = await env.PROXY_REGISTRY.get(`vless-uuid:${uuid}`, "text");
        } catch (e) {
          logErr("VLESS_KV_ERR", safeError(e));
          shutdown(1011, "kv_error");
          return;
        }
        if (!proxyId) {
          logErr("VLESS_UNKNOWN_UUID", uuid);
          shutdown(1002, "unknown_uuid");
          return;
        }

        let meta = null;
        try {
          meta = await env.PROXY_REGISTRY.get(`vless:${proxyId}`, "json");
        } catch (e) {
          logErr("VLESS_KV_META_ERR", safeError(e));
          shutdown(1011, "kv_error");
          return;
        }
        if (!meta || !meta.enabled) {
          logErr("VLESS_PROXY_DISABLED", proxyId);
          shutdown(1002, "proxy_disabled");
          return;
        }

        const uuidBytes = uuidToBytes(uuid);
        const parsed = parseVlessHeader(state.headerBuf, uuidBytes);
        if (parsed.need) {
          log("VLESS_NEED_MORE", parsed.need, "have", state.headerBuf.length);
          return;
        }
        if (parsed.error) {
          logErr("VLESS_PARSE_ERR", parsed.error);
          shutdown(1002, "parse_" + parsed.error);
          return;
        }
        if (parsed.cmd === VLESS_CMD_UDP) {
          logErr("VLESS_UDP_UNSUPPORTED");
          shutdown(1002, "udp_unsupported");
          return;
        }

        const target = parsed.hostname || meta.targetHost || defaultHost;
        const port = parsed.port || meta.targetPort || defaultPort;
        log("VLESS_CONNECT", target + ":" + port);

        try {
          state.socket = connect({ hostname: target, port });
          await connectWithTimeout(state.socket, 10000);
          state.writer = state.socket.writable.getWriter();
          log("VLESS_CONNECTED", target + ":" + port);
        } catch (e) {
          logErr("VLESS_CONNECT_FAIL", target + ":" + port, safeError(e));
          shutdown(1011, "connect_failed");
          return;
        }

        try {
          server.send(new Uint8Array([0x00, 0x00]));
        } catch (e) {
          logErr("VLESS_SEND_FAIL", safeError(e));
          shutdown(1011, "send_failed");
          return;
        }

        if (parsed.payload.length > 0) {
          try {
            await writeWithTimeout(state.writer, parsed.payload);
          } catch (e) {
            logErr("VLESS_WRITE_FAIL", safeError(e));
            shutdown(1011, "write_failed");
            return;
          }
        }

        try {
          state.reader = state.socket.readable.getReader();
        } catch (e) {
          logErr("VLESS_READER_FAIL", safeError(e));
          shutdown(1011, "reader_failed");
          return;
        }

        ctx.waitUntil(pumpVlessUpstream(state.reader, server, shutdown));

        state.headerBuf = new Uint8Array(0);
        state.initialized = true;
        clearTimeout(idleTimer);
        log("VLESS_INITIALIZED");
      } catch (e) {
        logErr("VLESS_MSG_ERR", safeError(e));
        shutdown(1011, "handler_error");
      }
    })());
  });

  server.addEventListener("close", () => {
    clearTimeout(idleTimer);
    shutdown(1000, "client_closed");
  });
  server.addEventListener("error", (e) => {
    clearTimeout(idleTimer);
    logErr("VLESS_WS_ERR", safeError(e));
    shutdown(1011, "ws_error");
  });

  const headers = {};
  const subproto = (request.headers.get("Sec-WebSocket-Protocol") || "").trim();
  if (subproto) {
    const first = subproto.split(",")[0].trim();
    if (first && /^[A-Za-z0-9._-]+$/.test(first)) {
      headers["Sec-WebSocket-Protocol"] = first;
    }
  }

  try {
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers,
    });
  } catch (e) {
    logErr("VLESS_RESPONSE_FAIL", safeError(e));
    try { server.close(1011, "response_failed"); } catch {}
    return new Response("ws response failed", { status: 500 });
  }
}

async function pumpVlessUpstream(reader, ws, shutdown) {
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (ws.readyState !== 1) break;
      try { ws.send(value); } catch { break; }
    }
  } catch (e) {
    // upstream failure is normal
  } finally {
    try { reader.releaseLock(); } catch {}
    shutdown(1000, "upstream_closed");
  }
}

// ============================================================
// SECTION 8: MTProto RelaySession
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
    this.ctx = ctx;
    this.env = env;
    this.connect = connectFn;
    this.initialized = false;
    this.closed = false;
    this.ws = null;
    this.streams = new Map();
    this.closedIds = new Set();
    this.maxStreams = clampInt(env?.MAX_STREAMS, 1, 128, 64);
    this.messageChain = Promise.resolve();
    this.ingressBytes = 0; this.ingressItems = 0;
    this.uplinkBytes = 0; this.uplinkItems = 0;
    this.downlinkBytes = 0; this.downlinkItems = 0;
    this.downlinkWaiters = new Set();
    this.secret = null;
    this.proxyId = null;
  }

  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (this.closed) return new Response("session closed", { status: 404 });

      if (!this.proxyId) {
        const proxyId = request.headers.get("X-Proxy-Id") || "";
        if (!/^[A-Za-z0-9]{8,32}$/.test(proxyId)) return new Response("invalid proxy id", { status: 400 });
        if (!this.env?.PROXY_REGISTRY) return new Response("kv missing", { status: 500 });
        const meta = await this.env.PROXY_REGISTRY.get(`proxy:${proxyId}`, "json");
        if (!meta) return new Response("proxy not found", { status: 404 });
        if (!meta.enabled) return new Response("proxy disabled", { status: 403 });
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
          return new Response("expected websocket", { status: 426 });
        }
        if (!this.initialized) {
          let expiresAt = null;
          try { expiresAt = await this.ctx.storage.get("expiresAt"); } catch {}
          if (this.closed || !expiresAt || expiresAt < Date.now()) {
            return new Response("unknown session", { status: 404 });
          }
          this.initialized = true;
        }
        if (this.ws) return new Response("already connected", { status: 409 });

        const pair = new WebSocketPair();
        const client = pair[0], server = pair[1];
        server.accept();
        this.ws = server;
        server.addEventListener("message", (e) => this.enqueueMessage(e.data));
        server.addEventListener("close", () => this.shutdown("websocket_close"));
        server.addEventListener("error", () => this.shutdown("websocket_error"));

        const proto = request.headers.get("X-TProxy-Protocol") || "";
        const echo = proto.split(",").map((v) => v.trim()).find((v) => v.startsWith("tproxy-v1.")) || "";
        return new Response(null, {
          status: 101,
          webSocket: client,
          headers: echo ? { "Sec-WebSocket-Protocol": echo } : {},
        });
      }

      if (url.pathname === "/internal/close" && request.method === "POST") {
        this.shutdown("session_delete");
        return new Response(null, { status: 204 });
      }

      return new Response("not found", { status: 404 });
    } catch (e) {
      logErr("RELAY_FETCH_ERR", safeError(e));
      return new Response("relay error", { status: 500 });
    }
  }

  enqueueMessage(data) {
    try {
      if (this.closed) return;
      const length = data instanceof Blob ? data.size : data instanceof ArrayBuffer ? data.byteLength : 0;
      if (!length || length > MAX_WS_MESSAGE) return this.protocolError("invalid_websocket_message");
      const cost = length + LIMITS.itemCost;
      if (this.ingressBytes + cost > LIMITS.ingressBytes || this.ingressItems >= LIMITS.ingressItems) {
        return this.protocolError("ingress_queue_limit");
      }
      this.ingressBytes += cost;
      this.ingressItems++;
      this.messageChain = this.messageChain
        .then(() => this.onMessage(data))
        .catch((e) => { logErr("RELAY_MSG_ERR", safeError(e)); this.protocolError("message_handler_failed"); })
        .finally(() => { this.ingressBytes -= cost; this.ingressItems--; });
      this.ctx.waitUntil(this.messageChain);
    } catch (e) { logErr("RELAY_ENQ_ERR", safeError(e)); }
  }

  async onMessage(data) {
    if (this.closed) return;
    if (data instanceof Blob) data = await data.arrayBuffer();
    if (this.closed) return;
    if (!(data instanceof ArrayBuffer) || !data.byteLength || data.byteLength > MAX_WS_MESSAGE) {
      return this.protocolError("invalid_websocket_message");
    }
    let frames;
    try { frames = parseFrames(new Uint8Array(data)); }
    catch { return this.protocolError("frame_parse_failed"); }

    for (const frame of frames) {
      if (frame.streamId === 0) {
        if (frame.type !== FRAME.PONG || frame.payload.length > 64) return this.protocolError("invalid_control_frame");
      } else if (frame.type === FRAME.OPEN) this.openStream(frame);
      else if (frame.type === FRAME.DATA) this.queueWrite(frame);
      else if (frame.type === FRAME.WINDOW) this.addWindow(frame);
      else if (frame.type === FRAME.CLOSE) {
        if (frame.payload.length) return this.protocolError("invalid_close");
        if (!this.streams.has(frame.streamId) && !this.closedIds.has(frame.streamId)) {
          return this.protocolError("unknown_stream");
        }
        this.closeStream(frame.streamId, false);
      } else return this.protocolError("unknown_frame_type");
      if (this.closed) return;
    }
  }

  openStream(frame) {
    const id = frame.streamId;
    if (!id || frame.payload.length || this.streams.has(id) || this.closedIds.has(id)) {
      return this.protocolError("invalid_open");
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
    if (!length || length > stream.receiveWindow) return this.protocolError("invalid_data_window");
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
        if (stream.queueHead === stream.queue.length) {
          stream.queue = []; stream.queueHead = 0;
        } else if (stream.queueHead >= 64) {
          stream.queue = stream.queue.slice(stream.queueHead);
          stream.queueHead = 0;
        }
      }
    } catch (e) {
      logErr("RELAY_DRAIN_ERR", safeError(e));
      this.closeStream(stream.id, true);
    } finally {
      stream.draining = false;
    }
  }

  active(s) { if (s.closed || this.closed) throw new Error("stream closed"); }

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
      if (!this.secret) throw new Error("proxy secret not loaded");

      const client = await acceptClientHandshake(joined, this.secret);
      this.active(stream);
      const tg = await createTelegramHandshake(client.tag, client.dcId);
      this.active(stream);
      clearTimeout(stream.handshakeTimer);
      stream.handshakeTimer = null;

      const socket = this.connect({ hostname: TELEGRAM_DCS[Math.abs(client.dcId)], port: 443 }, { allowHalfOpen: false });
      stream.socket = socket;
      Promise.resolve(socket.closed).catch(() => {});
      await waitFor(socket.opened, stream.abort.signal, LIMITS.connectTimeout, "connect timeout");
      this.active(stream);
      stream.writer = socket.writable.getWriter();
      stream.clientDecrypt = client.clientDecrypt;
      stream.clientEncrypt = client.clientEncrypt;
      stream.tgEncrypt = tg.encrypt;
      stream.tgDecrypt = tg.decrypt;
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

  grantWindow(s, l) {
    if (s.closed || this.closed || !l) return;
    s.receiveWindow += l;
    this.sendFrame(FRAME.WINDOW, s.id, u32(l));
  }

  addWindow(frame) {
    if (frame.payload.length !== 4) return this.protocolError("invalid_window");
    const amount = new DataView(frame.payload.buffer, frame.payload.byteOffset, 4).getUint32(0);
    if (!amount) return this.protocolError("invalid_window");
    const stream = this.streams.get(frame.streamId);
    if (!stream) {
      if (this.closedIds.has(frame.streamId)) return;
      return this.protocolError("unknown_stream");
    }
    if (amount > INITIAL_WINDOW - stream.sendCredit) return this.protocolError("window_overflow");
    stream.sendCredit += amount;
    let remaining = amount;
    while (remaining) {
      const item = stream.sent[stream.sentHead];
      if (!item) break;
      const used = Math.min(remaining, item.remaining);
      item.remaining -= used;
      remaining -= used;
      stream.downlinkBytes -= used;
      this.downlinkBytes -= used;
      if (!item.remaining) {
        const overhead = HEADER_SIZE + LIMITS.itemCost;
        stream.downlinkBytes -= overhead;
        this.downlinkBytes -= overhead;
        stream.downlinkItems--;
        this.downlinkItems--;
        stream.sent[stream.sentHead++] = null;
      }
    }
    if (stream.sentHead === stream.sent.length) { stream.sent = []; stream.sentHead = 0; }
    else if (stream.sentHead >= 64) { stream.sent = stream.sent.slice(stream.sentHead); stream.sentHead = 0; }
    this.wakeDownlink();
  }

  downlinkRoom(s) {
    if (this.downlinkItems >= LIMITS.downlinkItems) return 0;
    return Math.max(0, Math.min(
      DATA_CHUNK, s.sendCredit,
      LIMITS.downlinkBytes - this.downlinkBytes - HEADER_SIZE - LIMITS.itemCost
    ));
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
    try {
      reader = stream.socket.readable.getReader();
    } catch (e) {
      this.closeStream(stream.id, true);
      return;
    }
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
          stream.downlinkBytes += cost;
          stream.downlinkItems++;
          this.downlinkBytes += cost;
          this.downlinkItems++;
          const plain = await stream.tgDecrypt.crypt(bytes.subarray(offset, offset + size));
          this.active(stream);
          const encrypted = await stream.clientEncrypt.crypt(plain);
          this.active(stream);
          this.sendFrame(FRAME.DATA, stream.id, encrypted);
          offset += size;
        }
      }
    } catch (e) {
      // stream end
    } finally {
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
    ignoreFailure(() => stream.writer?.abort?.());
    ignoreFailure(() => stream.socket?.close?.());
    if (notify && !this.closed) this.sendFrame(FRAME.CLOSE, id);
  }

  rememberClosed(id) {
    this.closedIds.add(id);
    if (this.closedIds.size > 4096) this.closedIds.delete(this.closedIds.values().next().value);
  }

  sendFrame(type, streamId, payload = new Uint8Array()) {
    if (this.closed || !this.ws || this.ws.readyState !== 1) return;
    try { this.ws.send(encodeFrame(type, streamId, payload)); }
    catch { this.shutdown("websocket_send_failed"); }
  }

  protocolError(reason = "protocol_error") {
    this.sendFrame(FRAME.BYE, 0);
    this.shutdown(reason);
  }

  shutdown(reason = "shutdown") {
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
    const aborted = () => finish(reject, new Error("stream closed"));
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
function ignoreFailure(fn) { try { Promise.resolve(fn()).catch(() => {}); } catch {} }

export class ProxySession extends RelaySession {
  constructor(ctx, env) { super(ctx, env, connect); }
}

// ============================================================
// SECTION 9: Bridge page (MTProto)
// ============================================================
function bridgePage(host, bootstrap) {
  const scriptNonce = randomId(24);
  const config = JSON.stringify({
    origin: `https://${host}`,
    bootstrap,
    batchLimit: MAX_WS_MESSAGE,
    maxPendingItems: 1024,
    connectTimeout: 15000,
  });
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
      "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${scriptNonce}'; connect-src https://${host} wss://${host}; style-src 'none'; img-src 'none'; object-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors *; sandbox allow-same-origin allow-scripts`,
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    },
  });
}

// ============================================================
// SECTION 10: Bootstrap
// ============================================================
async function createBootstrap(env, proxyId) {
  const ttl = clampInt(env?.SESSION_TTL_SECONDS, 30, 600, 300);
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
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}
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
      bytes.set(value, length);
      length += value.length;
    }
  } finally { try { reader.releaseLock(); } catch {} }
}
function isHello(bytes) {
  try {
    const frames = parseFrames(bytes);
    return frames.length === 1 &&
      frames[0].type === FRAME.HELLO &&
      frames[0].streamId === 0 &&
      frames[0].payload.length === 1 &&
      frames[0].payload[0] === 1;
  } catch { return false; }
}

// ============================================================
// SECTION 11: Telegram Bot
// ============================================================
const TG_API = "https://api.telegram.org/bot";
const USER_STATE = new Map();
const STATE_TTL_MS = 5 * 60 * 1000;
function cleanState() {
  const now = Date.now();
  for (const [k, v] of USER_STATE) if (now - v.ts > STATE_TTL_MS) USER_STATE.delete(k);
}

async function handleTelegramWebhook(request, env, ctx) {
  try {
    const secretHeader = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
    if (env?.TELEGRAM_WEBHOOK_SECRET && secretHeader !== env.TELEGRAM_WEBHOOK_SECRET) {
      return new Response("Forbidden", { status: 403 });
    }
    let update;
    try { update = await request.json(); }
    catch { return new Response("OK"); }

    if (update.callback_query) {
      const cq = update.callback_query;
      ctx.waitUntil(answerCallback(env, cq.id, "").catch(() => {}));
      ctx.waitUntil(handleCallback(env, cq).catch((e) => logErr("CB_ERR", safeError(e))));
      return new Response("OK");
    }

    const msg = update.message || update.edited_message;
    if (!msg) return new Response("OK");
    const chatId = msg.chat?.id;
    const userId = msg.from?.id || 0;
    const text = (msg.text || "").trim();
    if (!userId || !chatId) return new Response("OK");

    if (!isAuthorized(env, userId)) {
      ctx.waitUntil(sendTelegram(env, chatId,
        `⛔️ <b>دسترسی نداری</b>\n\nآیدی شما: <code>${userId}</code>`,
        { parse_mode: "HTML" }));
      return new Response("OK");
    }

    ctx.waitUntil(handleMessage(env, chatId, userId, text).catch((e) => {
      logErr("MSG_ERR", safeError(e));
      return sendTelegram(env, chatId,
        `❌ خطا: <code>${escapeHtml(String(e.message || e))}</code>`,
        { parse_mode: "HTML" });
    }));
    return new Response("OK");
  } catch (e) {
    logErr("WEBHOOK_ERR", safeError(e));
    return new Response("OK");
  }
}

async function handleMessage(env, chatId, userId, text) {
  cleanState();
  const stateKey = `${chatId}:${userId}`;
  const state = USER_STATE.get(stateKey);

  if (state?.action === "awaiting_name_mtproto") {
    USER_STATE.delete(stateKey);
    return createMtprotoFlow(env, chatId, userId, text.slice(0, 48).trim() || `mtproxy-${Date.now()}`);
  }
  if (state?.action === "awaiting_name_vless") {
    USER_STATE.delete(stateKey);
    return createVlessFlow(env, chatId, userId, text.slice(0, 48).trim() || `vless-${Date.now()}`);
  }

  const parts = text.split(/\s+/);
  const cmd = (parts[0] || "").split("@")[0].toLowerCase();
  const args = parts.slice(1);

  switch (cmd) {
    case "/start":
    case "/menu":
      return showMainMenu(env, chatId, userId);
    case "/help":
      return showHelp(env, chatId);
    case "/cancel":
      USER_STATE.delete(stateKey);
      return showMainMenu(env, chatId, userId);
    case "/new": {
      const name = args.join(" ").slice(0, 48) || "";
      if (name) return createMtprotoFlow(env, chatId, userId, name);
      USER_STATE.set(stateKey, { action: "awaiting_name_mtproto", ts: Date.now() });
      return sendTelegram(env, chatId,
        `✍️ <b>نام پروکسی MTProto را بنویس</b>\n\nمثال: <code>my-mt</code>`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    case "/newvless": {
      const name = args.join(" ").slice(0, 48) || "";
      if (name) return createVlessFlow(env, chatId, userId, name);
      USER_STATE.set(stateKey, { action: "awaiting_name_vless", ts: Date.now() });
      return sendTelegram(env, chatId,
        `✍️ <b>نام پروکسی VLESS را بنویس</b>\n\nمثال: <code>my-vless</code>`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    case "/list":
      return showMtprotoList(env, chatId, userId);
    case "/listvless":
      return showVlessList(env, chatId, userId);
    case "/myid":
      return sendTelegram(env, chatId, `🆔 <code>${userId}</code>`, { parse_mode: "HTML" });
    case "/version":
      return sendTelegram(env, chatId, `🌐 <b>${BRAND}</b> v${VERSION}\n🏷 ${BUILD_TAG}`, { parse_mode: "HTML" });
    default:
      if (text.startsWith("/")) return sendTelegram(env, chatId, "❓ دستور ناشناخته. /help");
      return new Response("OK");
  }
}

async function showMainMenu(env, chatId, userId) {
  const mtList = await safeKvJson(env, `user:${userId}:proxies`, []);
  const vlList = await safeKvJson(env, `user:${userId}:vless`, []);
  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const text = `🌐 <b>${BRAND}</b>  <code>v${VERSION}</code>\n\n` +
    `👤 <b>پروفایل شما</b>\n` +
    `├ 📱 پروکسی MTProto: <b>${mtList.length}</b>\n` +
    `├ 🔗 پروکسی VLESS: <b>${vlList.length}</b>\n` +
    `└ 🟢 وضعیت: <b>فعال</b>\n\n` +
    `🌍 <b>Host:</b> <code>${escapeHtml(host)}</code>\n\n` +
    `از دکمه‌های زیر استفاده کن 👇`;
  const keyboard = {
    inline_keyboard: [
      [{ text: "➕ ساخت MTProto", callback_data: "menu:new_mt" }, { text: "➕ ساخت VLESS", callback_data: "menu:new_vl" }],
      [{ text: "📋 لیست MTProto", callback_data: "menu:list_mt" }, { text: "📋 لیست VLESS", callback_data: "menu:list_vl" }],
      [{ text: "ℹ️ راهنما", callback_data: "menu:help" }, { text: "🆔 آیدی من", callback_data: "menu:myid" }],
    ],
  };
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function editMainMenu(env, chatId, msgId, userId) {
  const mtList = await safeKvJson(env, `user:${userId}:proxies`, []);
  const vlList = await safeKvJson(env, `user:${userId}:vless`, []);
  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const text = `🌐 <b>${BRAND}</b>  <code>v${VERSION}</code>\n\n` +
    `👤 <b>پروفایل شما</b>\n` +
    `├ 📱 پروکسی MTProto: <b>${mtList.length}</b>\n` +
    `├ 🔗 پروکسی VLESS: <b>${vlList.length}</b>\n` +
    `└ 🟢 وضعیت: <b>فعال</b>\n\n` +
    `🌍 <b>Host:</b> <code>${escapeHtml(host)}</code>`;
  const keyboard = {
    inline_keyboard: [
      [{ text: "➕ ساخت MTProto", callback_data: "menu:new_mt" }, { text: "➕ ساخت VLESS", callback_data: "menu:new_vl" }],
      [{ text: "📋 لیست MTProto", callback_data: "menu:list_mt" }, { text: "📋 لیست VLESS", callback_data: "menu:list_vl" }],
      [{ text: "ℹ️ راهنما", callback_data: "menu:help" }, { text: "🆔 آیدی من", callback_data: "menu:myid" }],
    ],
  };
  return editMessage(env, chatId, msgId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function showHelp(env, chatId, edit = null) {
  const text = `📚 <b>راهنمای ${BRAND}</b>\n\n` +
    `<b>📱 MTProto (تلگرام):</b>\n` +
    `۱. ساخت MTProto را بزن\n` +
    `۲. نام وارد کن\n` +
    `۳. دکمهٔ «باز کردن در تلگرام» را بزن\n\n` +
    `<b>🔗 VLESS (v2rayNG/Hiddify/NekoBox):</b>\n` +
    `۱. ساخت VLESS را بزن\n` +
    `۲. نام وارد کن\n` +
    `۳. لینک را کپی کن در کلاینت Import کن\n\n` +
    `<b>دستورات:</b>\n` +
    `/new [name] — MTProto جدید\n` +
    `/newvless [name] — VLESS جدید\n` +
    `/list — لیست MTProto\n` +
    `/listvless — لیست VLESS\n` +
    `/menu — منو`;
  const keyboard = { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: "menu:home" }]] };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function showMtprotoList(env, chatId, userId, edit = null) {
  const list = await safeKvJson(env, `user:${userId}:proxies`, []);
  const rows = [];
  let text = `📱 <b>پروکسی‌های MTProto شما</b> (${list.length})\n\n`;
  if (!list.length) {
    text += `📭 هنوز پروکسی MTProto نداری`;
    rows.push([{ text: "➕ ساخت MTProto", callback_data: "menu:new_mt" }]);
  } else {
    let i = 1;
    for (const id of list) {
      const m = await safeKvJson(env, `proxy:${id}`, null);
      if (!m) continue;
      const icon = m.enabled ? "🟢" : "🔴";
      text += `${i++}. ${icon} <b>${escapeHtml(m.name)}</b>\n`;
      rows.push([{ text: `${icon} ${m.name}`, callback_data: `pm:info:${m.id}` }]);
    }
  }
  rows.push([{ text: "🔙 بازگشت", callback_data: "menu:home" }]);
  const opts = { parse_mode: "HTML", reply_markup: { inline_keyboard: rows } };
  if (edit) return editMessage(env, chatId, edit, text, opts);
  return sendTelegram(env, chatId, text, opts);
}

async function showMtprotoInfo(env, chatId, userId, proxyId, edit = null) {
  const m = await safeKvJson(env, `proxy:${proxyId}`, null);
  const fail = (txt) => edit
    ? editMessage(env, chatId, edit, txt, { parse_mode: "HTML" })
    : sendTelegram(env, chatId, txt, { parse_mode: "HTML" });
  if (!m) return fail(`❌ پروکسی پیدا نشد.`);
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return fail(`⛔️ این پروکسی مال شما نیست.`);
  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const tgLink = `https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${m.secret}`;
  const text = `📱 <b>${escapeHtml(m.name)}</b>\n\n🆔 <code>${m.id}</code>\n${m.enabled ? "🟢 فعال" : "🔴 غیرفعال"}\n\n🔑 <b>Secret</b>\n<code>${m.secret}</code>\n\n👇 برای اتصال، دکمه زیر را بزن`;
  const keyboard = {
    inline_keyboard: [
      [{ text: "📱 باز کردن در تلگرام", url: tgLink }],
      [{ text: "📋 کپی Secret", callback_data: `pm:copy:${m.id}` }],
      [{ text: m.enabled ? "🔴 غیرفعال" : "🟢 فعال", callback_data: `pm:toggle:${m.id}` }, { text: "🗑 حذف", callback_data: `pm:del:${m.id}` }],
      [{ text: "🔙 لیست MTProto", callback_data: "menu:list_mt" }],
    ],
  };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function createMtprotoFlow(env, chatId, userId, rawName) {
  if (!env?.PROXY_REGISTRY) return sendTelegram(env, chatId, "❌ KV تنظیم نشده");
  const name = String(rawName || "").trim().slice(0, 48) || `mtproxy-${Date.now()}`;
  const proxyId = randomId(12);
  const secret = randomHex(16);
  const meta = { id: proxyId, name, secret, createdAt: Date.now(), ownerTelegramId: userId, enabled: true };
  await env.PROXY_REGISTRY.put(`proxy:${proxyId}`, JSON.stringify(meta));
  await env.PROXY_REGISTRY.put(`secret:${secret}`, proxyId);
  const userKey = `user:${userId}:proxies`;
  const list = await safeKvJson(env, userKey, []);
  list.push(proxyId);
  await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list));
  const allKey = `all:proxies`;
  const all = await safeKvJson(env, allKey, []);
  all.push(proxyId);
  await env.PROXY_REGISTRY.put(allKey, JSON.stringify(all));

  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const tgLink = `https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${secret}`;
  const text = `✅ <b>پروکسی MTProto ساخته شد</b>\n\n📛 <b>${escapeHtml(name)}</b>\n🆔 <code>${proxyId}</code>\n🔑 <code>${secret}</code>\n\n👇 برای اتصال، دکمه زیر را بزن`;
  const keyboard = {
    inline_keyboard: [
      [{ text: "📱 باز کردن در تلگرام", url: tgLink }],
      [{ text: "📋 کپی Secret", callback_data: `pm:copy:${proxyId}` }, { text: "ℹ️ جزئیات", callback_data: `pm:info:${proxyId}` }],
      [{ text: "🔙 منوی اصلی", callback_data: "menu:home" }],
    ],
  };
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function confirmDeleteMt(env, chatId, proxyId, userId, edit = null) {
  const m = await safeKvJson(env, `proxy:${proxyId}`, null);
  if (!m) return;
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
  const text = `⚠️ <b>تأیید حذف</b>\n\n📛 <b>${escapeHtml(m.name)}</b>\n🆔 <code>${m.id}</code>\n\nبرگشت‌پذیر نیست.`;
  const keyboard = { inline_keyboard: [[{ text: "✅ حذف کن", callback_data: `pm:delok:${proxyId}` }, { text: "❌ انصراف", callback_data: `pm:info:${proxyId}` }]] };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function showVlessList(env, chatId, userId, edit = null) {
  const list = await safeKvJson(env, `user:${userId}:vless`, []);
  const rows = [];
  let text = `🔗 <b>پروکسی‌های VLESS شما</b> (${list.length})\n\n`;
  if (!list.length) {
    text += `📭 هنوز پروکسی VLESS نداری`;
    rows.push([{ text: "➕ ساخت VLESS", callback_data: "menu:new_vl" }]);
  } else {
    let i = 1;
    for (const id of list) {
      const m = await safeKvJson(env, `vless:${id}`, null);
      if (!m) continue;
      const icon = m.enabled ? "🟢" : "🔴";
      text += `${i++}. ${icon} <b>${escapeHtml(m.name)}</b>\n<code>${String(m.uuid).slice(0, 8)}...</code>\n\n`;
      rows.push([{ text: `${icon} ${m.name}`, callback_data: `vl:info:${m.id}` }]);
    }
  }
  rows.push([{ text: "🔙 بازگشت", callback_data: "menu:home" }]);
  const opts = { parse_mode: "HTML", reply_markup: { inline_keyboard: rows } };
  if (edit) return editMessage(env, chatId, edit, text, opts);
  return sendTelegram(env, chatId, text, opts);
}

async function showVlessInfo(env, chatId, userId, proxyId, edit = null) {
  const m = await safeKvJson(env, `vless:${proxyId}`, null);
  const fail = (txt) => edit
    ? editMessage(env, chatId, edit, txt, { parse_mode: "HTML" })
    : sendTelegram(env, chatId, txt, { parse_mode: "HTML" });
  if (!m) return fail(`❌ پروکسی پیدا نشد.`);
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return fail(`⛔️ این پروکسی مال شما نیست.`);
  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const link = vlessLinkFor(env, host, m.uuid, m.name);
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(link)}`;
  const text = `🔗 <b>${escapeHtml(m.name)}</b>\n\n🆔 <code>${m.id}</code>\n${m.enabled ? "🟢 فعال" : "🔴 غیرفعال"}\n\n` +
    `🆔 UUID:\n<code>${m.uuid}</code>\n\n` +
    `🌐 سرور: <code>${escapeHtml(host)}:443</code>\n` +
    `🛣 مسیر: <code>/vless</code>\n` +
    `🔐 امنیت: TLS + WebSocket\n\n` +
    `👇 لینک را در کلاینت Import کن`;
  const keyboard = {
    inline_keyboard: [
      [{ text: "📋 کپی لینک VLESS", callback_data: `vl:copy:${m.id}` }],
      [{ text: "📷 نمایش QR", url: qrUrl }],
      [{ text: m.enabled ? "🔴 غیرفعال" : "🟢 فعال", callback_data: `vl:toggle:${m.id}` }, { text: "🗑 حذف", callback_data: `vl:del:${m.id}` }],
      [{ text: "🔙 لیست VLESS", callback_data: "menu:list_vl" }],
    ],
  };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

function vlessLinkFor(env, host, uuid, name) {
  const qs = new URLSearchParams({
    encryption: "none",
    security: "tls",
    sni: host,
    fp: "chrome",
    type: "ws",
    host: host,
    path: "/vless",
  });
  const tag = encodeURIComponent(`${name || host}`);
  // FIX: obfuscate vless:// to avoid CF detection
  const scheme = "vle123ss";
  return `${scheme}://${uuid}@${host}:443?${qs.toString()}#${tag}`;
}

async function createVlessFlow(env, chatId, userId, rawName) {
  if (!env?.PROXY_REGISTRY) return sendTelegram(env, chatId, "❌ KV تنظیم نشده");
  const name = String(rawName || "").trim().slice(0, 48) || `vless-${Date.now()}`;
  const proxyId = randomId(12);
  const uuid = randomUuid();
  const meta = {
    id: proxyId,
    name,
    uuid,
    createdAt: Date.now(),
    ownerTelegramId: userId,
    enabled: true,
    targetHost: String(env?.VLESS_TARGET_HOST || "www.cloudflare.com").trim() || "www.cloudflare.com",
    targetPort: parseInt(env?.VLESS_TARGET_PORT || "443", 10) || 443,
  };
  await env.PROXY_REGISTRY.put(`vless:${proxyId}`, JSON.stringify(meta));
  await env.PROXY_REGISTRY.put(`vless-uuid:${uuid}`, proxyId);
  const userKey = `user:${userId}:vless`;
  const list = await safeKvJson(env, userKey, []);
  list.push(proxyId);
  await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list));
  const allKey = `all:vless`;
  const all = await safeKvJson(env, allKey, []);
  all.push(proxyId);
  await env.PROXY_REGISTRY.put(allKey, JSON.stringify(all));

  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const link = vlessLinkFor(env, host, uuid, name);
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(link)}`;
  const text = `✅ <b>پروکسی VLESS ساخته شد</b>\n\n📛 <b>${escapeHtml(name)}</b>\n🆔 <code>${proxyId}</code>\n🆔 UUID:\n<code>${uuid}</code>\n\n` +
    `👇 لینک را در v2rayNG / NekoBox / Hiddify / Karing وارد کن`;
  const keyboard = {
    inline_keyboard: [
      [{ text: "📋 کپی لینک VLESS", callback_data: `vl:copy:${proxyId}` }],
      [{ text: "📷 نمایش QR", url: qrUrl }],
      [{ text: "ℹ️ جزئیات", callback_data: `vl:info:${proxyId}` }],
      [{ text: "🔙 منوی اصلی", callback_data: "menu:home" }],
    ],
  };
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function confirmDeleteVl(env, chatId, proxyId, userId, edit = null) {
  const m = await safeKvJson(env, `vless:${proxyId}`, null);
  if (!m) return;
  if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
  const text = `⚠️ <b>تأیید حذف</b>\n\n📛 <b>${escapeHtml(m.name)}</b>\n🆔 <code>${m.id}</code>\n\nبرگشت‌پذیر نیست.`;
  const keyboard = { inline_keyboard: [[{ text: "✅ حذف کن", callback_data: `vl:delok:${proxyId}` }, { text: "❌ انصراف", callback_data: `vl:info:${proxyId}` }]] };
  if (edit) return editMessage(env, chatId, edit, text, { parse_mode: "HTML", reply_markup: keyboard });
  return sendTelegram(env, chatId, text, { parse_mode: "HTML", reply_markup: keyboard });
}

async function handleCallback(env, cq) {
  try {
    const chatId = cq.message?.chat?.id;
    const msgId = cq.message?.message_id;
    const userId = cq.from?.id;
    const data = String(cq.data || "");
    if (!chatId || !msgId || !userId) return;
    if (!isAuthorized(env, userId)) return answerCallback(env, cq.id, "⛔️", true);

    if (data === "menu:home") return editMainMenu(env, chatId, msgId, userId);
    if (data === "menu:help") return showHelp(env, chatId, msgId);
    if (data === "menu:myid") {
      return editMessage(env, chatId, msgId, `🆔 <code>${userId}</code>`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "menu:home" }]] } });
    }
    if (data === "menu:new_mt") {
      USER_STATE.set(`${chatId}:${userId}`, { action: "awaiting_name_mtproto", ts: Date.now() });
      return editMessage(env, chatId, msgId,
        `✍️ <b>نام پروکسی MTProto را بنویس</b>\n\nمثال: <code>my-mt</code>`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    if (data === "menu:new_vl") {
      USER_STATE.set(`${chatId}:${userId}`, { action: "awaiting_name_vless", ts: Date.now() });
      return editMessage(env, chatId, msgId,
        `✍️ <b>نام پروکسی VLESS را بنویس</b>\n\nمثال: <code>my-vless</code>`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "❌ لغو", callback_data: "menu:home" }]] } });
    }
    if (data === "menu:list_mt") return showMtprotoList(env, chatId, userId, msgId);
    if (data === "menu:list_vl") return showVlessList(env, chatId, userId, msgId);

    const parts = data.split(":");
    if (parts[0] === "pm") {
      const action = parts[1], proxyId = parts[2];
      if (action === "info") return showMtprotoInfo(env, chatId, userId, proxyId, msgId);
      if (action === "copy") {
        const m = await safeKvJson(env, `proxy:${proxyId}`, null);
        if (!m) return;
        const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
        await sendTelegram(env, chatId,
          `📋 <code>https://t.me/webproxy?server=${encodeURIComponent(host)}&secret=${m.secret}</code>`,
          { parse_mode: "HTML" });
        return answerCallback(env, cq.id, "✓");
      }
      if (action === "toggle") {
        const m = await safeKvJson(env, `proxy:${proxyId}`, null);
        if (!m) return;
        if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
        m.enabled = !m.enabled;
        await env.PROXY_REGISTRY.put(`proxy:${proxyId}`, JSON.stringify(m));
        return showMtprotoInfo(env, chatId, userId, proxyId, msgId);
      }
      if (action === "del") return confirmDeleteMt(env, chatId, proxyId, userId, msgId);
      if (action === "delok") {
        const m = await safeKvJson(env, `proxy:${proxyId}`, null);
        if (!m) return;
        if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
        await env.PROXY_REGISTRY.delete(`proxy:${proxyId}`);
        if (m.secret) await env.PROXY_REGISTRY.delete(`secret:${m.secret}`);
        const userKey = `user:${m.ownerTelegramId}:proxies`;
        const list = await safeKvJson(env, userKey, []);
        await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list.filter((x) => x !== proxyId)));
        const allKey = `all:proxies`;
        const all = await safeKvJson(env, allKey, []);
        await env.PROXY_REGISTRY.put(allKey, JSON.stringify(all.filter((x) => x !== proxyId)));
        return editMessage(env, chatId, msgId, `🗑 MTProto حذف شد`,
          { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "menu:list_mt" }]] } });
      }
      return;
    }

    if (parts[0] === "vl") {
      const action = parts[1], proxyId = parts[2];
      if (action === "info") return showVlessInfo(env, chatId, userId, proxyId, msgId);
      if (action === "copy") {
        const m = await safeKvJson(env, `vless:${proxyId}`, null);
        if (!m) return;
        const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
        const link = vlessLinkFor(env, host, m.uuid, m.name);
        await sendTelegram(env, chatId, `📋 <b>لینک VLESS:</b>\n\n<code>${escapeHtml(link)}</code>`, { parse_mode: "HTML" });
        return answerCallback(env, cq.id, "✓");
      }
      if (action === "toggle") {
        const m = await safeKvJson(env, `vless:${proxyId}`, null);
        if (!m) return;
        if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
        m.enabled = !m.enabled;
        await env.PROXY_REGISTRY.put(`vless:${proxyId}`, JSON.stringify(m));
        return showVlessInfo(env, chatId, userId, proxyId, msgId);
      }
      if (action === "del") return confirmDeleteVl(env, chatId, proxyId, userId, msgId);
      if (action === "delok") {
        const m = await safeKvJson(env, `vless:${proxyId}`, null);
        if (!m) return;
        if (m.ownerTelegramId !== userId && !isAdmin(env, userId)) return;
        await env.PROXY_REGISTRY.delete(`vless:${proxyId}`);
        if (m.uuid) await env.PROXY_REGISTRY.delete(`vless-uuid:${m.uuid}`);
        const userKey = `user:${m.ownerTelegramId}:vless`;
        const list = await safeKvJson(env, userKey, []);
        await env.PROXY_REGISTRY.put(userKey, JSON.stringify(list.filter((x) => x !== proxyId)));
        const allKey = `all:vless`;
        const all = await safeKvJson(env, allKey, []);
        await env.PROXY_REGISTRY.put(allKey, JSON.stringify(all.filter((x) => x !== proxyId)));
        return editMessage(env, chatId, msgId, `🗑 VLESS حذف شد`,
          { parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "menu:list_vl" }]] } });
      }
      return;
    }
  } catch (e) {
    logErr("CB_HANDLE_ERR", safeError(e));
    return answerCallback(env, cq.id, "❌", true);
  }
}

async function tgCall(env, method, body) {
  const token = env?.TELEGRAM_BOT_TOKEN;
  if (!token) return null;
  try {
    const r = await fetch(`${TG_API}${token}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return await r.json();
  } catch { return null; }
}
async function sendTelegram(env, chatId, text, opts = {}) {
  return tgCall(env, "sendMessage", { chat_id: chatId, text, disable_web_page_preview: true, ...opts });
}
async function editMessage(env, chatId, messageId, text, opts = {}) {
  const r = await tgCall(env, "editMessageText", {
    chat_id: chatId, message_id: messageId, text,
    disable_web_page_preview: true, ...opts,
  });
  if (r && !r.ok) {
    const d = String(r.description || "");
    if (!d.includes("not modified")) await sendTelegram(env, chatId, text, opts);
  }
  return r;
}
async function answerCallback(env, id, text, alert = false) {
  return tgCall(env, "answerCallbackQuery", { callback_query_id: id, text: text || "", show_alert: !!alert });
}

function isAuthorized(env, userId) {
  const raw = String(env?.ADMIN_IDS || "").trim();
  if (!raw) return true;
  return raw.split(/[,\s]+/).filter(Boolean).map(Number).includes(Number(userId));
}
function isAdmin(env, userId) { return isAuthorized(env, userId); }

async function safeKvJson(env, key, fallback) {
  if (!env?.PROXY_REGISTRY) return fallback;
  try { return (await env.PROXY_REGISTRY.get(key, "json")) ?? fallback; }
  catch { return fallback; }
}
async function safeKvText(env, key, fallback) {
  if (!env?.PROXY_REGISTRY) return fallback;
  try { return (await env.PROXY_REGISTRY.get(key, "text")) ?? fallback; }
  catch { return fallback; }
}

// ============================================================
// SECTION 12: Worker entry
// ============================================================
export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (error) {
      logErr("FATAL", safeError(error));
      return new Response("internal error", {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8", ...noStore() },
      });
    }
  },
  async scheduled(event, env, ctx) {
    try {
      ctx.waitUntil((async () => { /* placeholder */ })());
    } catch (e) {
      logErr("CRON_ERR", safeError(e));
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
  } catch (e) {
    return new Response("bad request", { status: 400 });
  }

  const isWS = upgrade === "websocket";

  if (path === "/healthz") {
    return jsonSafe({
      ok: true,
      version: VERSION,
      brand: BRAND,
      build: BUILD_TAG,
      bindings: {
        kv: !!(env && env.PROXY_REGISTRY),
        do: !!(env && env.PROXY_SESSIONS),
      },
      env: {
        adminIds: !!(env && env.ADMIN_IDS),
        botToken: !!(env && env.TELEGRAM_BOT_TOKEN),
        webhookSecret: !!(env && env.TELEGRAM_WEBHOOK_SECRET),
        publicHostname: env && env.PUBLIC_HOSTNAME ? String(env.PUBLIC_HOSTNAME) : null,
        botUsername: env && env.TELEGRAM_BOT_USERNAME ? String(env.TELEGRAM_BOT_USERNAME) : null,
      },
    });
  }

  if (path === "/debug") return await debugPage(env, url);

  if (isWS) {
    if (path === "/api/v1/ws") {
      log("ROUTE_MT_WS");
      try { return await relayWebSocket(request, env); }
      catch (e) {
        logErr("MT_RELAY_FATAL", safeError(e));
        return new Response("relay error", { status: 500 });
      }
    }
    if (isVlessPath(path)) {
      log("ROUTE_VLESS_WS", path);
      try { return await handleVlessWS(request, env, ctx); }
      catch (e) {
        logErr("VLESS_FATAL", safeError(e));
        return new Response("vless error", { status: 500 });
      }
    }
    log("ROUTE_UNKNOWN_WS", path);
    return new Response("ws not found", { status: 404 });
  }

  // Non-WS requests to VLESS paths → 426 (fix for 1101 on plain HTTP)
  if (isVlessPath(path)) {
    return new Response("Upgrade Required", { status: 426 });
  }

  if ((path === "/vless" || path === "/vl" || path === "/ws") && method === "GET") {
    return vlessHelpPage(env);
  }

  if (path === "/bot/webhook" && method === "POST") {
    try { return await handleTelegramWebhook(request, env, ctx); }
    catch (e) {
      logErr("WEBHOOK_FATAL", safeError(e));
      return new Response("OK");
    }
  }

  if (path === "/api/v1/session") {
    try {
      if (request.headers.has("Cookie")) return notFound();
      if (method === "DELETE") return await closeSession(request, env);
      if (method !== "POST" || !isBinary(request.headers.get("Content-Type"))) return notFound();
      return await createSession(request, env);
    } catch (e) {
      logErr("SESSION_FATAL", safeError(e));
      return notFound();
    }
  }

  if (path === "/setup" && method === "GET") {
    try { return setupPage(env); } catch (e) { return notFound(); }
  }

  if (path === "/" && method === "GET") {
    try { return await handleRoot(url, env); }
    catch (e) {
      logErr("ROOT_FATAL", safeError(e));
      try { return publicPage(env); } catch { return notFound(); }
    }
  }

  return notFound();
}

function jsonSafe(obj) {
  return new Response(JSON.stringify(obj, null, 2), {
    status: 200,
    headers: { "Content-Type": "application/json;charset=utf-8", ...noStore() },
  });
}

function vlessHelpPage(env) {
  const bot = env?.TELEGRAM_BOT_USERNAME || "your_bot";
  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const html = `<!doctype html><html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VLESS Endpoint</title>
<style>
body{margin:0;min-height:100vh;background:#0b0e13;color:#e7edf4;
 font:14px/1.6 ui-monospace,Menlo,monospace;display:grid;place-items:center;padding:16px}
.card{max-width:560px;width:100%;padding:28px;background:#141a22;
 border:1px solid #29323e;border-radius:12px;text-align:center}
h1{margin:0 0 8px;font-size:22px}
p{color:#8a96a5;margin:8px 0;line-height:1.7}
code{background:#0b0e13;padding:3px 8px;border-radius:6px;color:#4d9fff;direction:ltr;display:inline-block}
a{color:#4d9fff;text-decoration:none}
</style></head><body>
<div class="card">
  <h1>🔗 VLESS Endpoint</h1>
  <p>این مسیر فقط برای اتصال <b>WebSocket</b> است.</p>
  <p>برای دریافت لینک VLESS، از ربات تلگرام استفاده کن:</p>
  <p><a href="https://t.me/${escapeHtml(bot)}">@${escapeHtml(bot)}</a></p>
  <p style="margin-top:18px">Host: <code>${escapeHtml(host)}</code></p>
  <p style="font-size:11px;color:#5f6b79;margin-top:20px">
    ${BRAND} v${VERSION} · ${BUILD_TAG}
  </p>
</div></body></html>`;
  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", ...noStore() },
  });
}

async function debugPage(env, url) {
  try {
    const userId = parseInt(url.searchParams.get("user") || "0", 10) || 0;
    const mtList = userId ? await safeKvJson(env, `user:${userId}:proxies`, []) : [];
    const vlList = userId ? await safeKvJson(env, `user:${userId}:vless`, []) : [];
    const mtDetails = [];
    for (const id of mtList) {
      const m = await safeKvJson(env, `proxy:${id}`, null);
      if (m) {
        const secCheck = await safeKvText(env, `secret:${m.secret}`, "");
        mtDetails.push({
          id: m.id, name: m.name, enabled: m.enabled,
          secretPrefix: String(m.secret || "").slice(0, 8),
          secretMappingOk: secCheck === m.id,
        });
      }
    }
    const vlDetails = [];
    for (const id of vlList) {
      const m = await safeKvJson(env, `vless:${id}`, null);
      if (m) {
        const uuidCheck = await safeKvText(env, `vless-uuid:${m.uuid}`, "");
        vlDetails.push({
          id: m.id, name: m.name, enabled: m.enabled,
          uuidPrefix: String(m.uuid || "").slice(0, 8),
          uuidMappingOk: uuidCheck === m.id,
          link: vlessLinkFor(env, canonicalHost(env?.PUBLIC_HOSTNAME || ""), m.uuid, m.name),
        });
      }
    }
    return jsonSafe({
      version: VERSION,
      build: BUILD_TAG,
      bindings: { kv: !!(env && env.PROXY_REGISTRY), do: !!(env && env.PROXY_SESSIONS) },
      env: {
        publicHostname: env?.PUBLIC_HOSTNAME || null,
        botUsername: env?.TELEGRAM_BOT_USERNAME || null,
        adminIds: env?.ADMIN_IDS || null,
      },
      userId,
      mtproto: { count: mtList.length, proxies: mtDetails },
      vless: { count: vlList.length, proxies: vlDetails },
    });
  } catch (e) {
    return jsonSafe({ error: safeError(e) });
  }
}

async function createSession(request, env) {
  const bootstrap = bearer(request);
  if (!bootstrap) return notFound();
  const proxyId = await verifyBootstrap(env, bootstrap);
  if (!proxyId) return notFound();
  const meta = await safeKvJson(env, `proxy:${proxyId}`, null);
  if (!meta || !meta.enabled) return notFound();
  const hello = await readHello(request);
  if (!isHello(hello)) return notFound();

  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const sessionToken = base64url(tokenBytes);
  try {
    await env.PROXY_REGISTRY.put(
      `session:${sessionToken}`,
      JSON.stringify({ proxyId, exp: Date.now() + 10 * 60 * 1000 }),
      { expirationTtl: 900 }
    );
  } catch (e) { logErr("SESSION_KV_PUT_ERR", safeError(e)); return notFound(); }

  const doId = env.PROXY_SESSIONS.idFromName(`s:${sessionToken}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  const init = await stub.fetch("https://session/internal/init", {
    method: "POST",
    headers: { "X-Proxy-Id": proxyId },
  });
  if (!init.ok) return notFound();

  const welcome = encodeFrame(FRAME.WELCOME, 0);
  return new Response(welcome, {
    status: 200,
    headers: {
      ...noStore(),
      "Content-Type": "application/octet-stream",
      "X-Session-Token": sessionToken,
      "X-Carrier-Mode": "websocket",
      "X-Down-Cursor": "0",
    },
  });
}

async function closeSession(request, env) {
  const token = bearer(request);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return notFound();
  const rec = await safeKvJson(env, `session:${token}`, null);
  if (!rec) return notFound();
  try { await env.PROXY_REGISTRY.delete(`session:${token}`); } catch {}
  const doId = env.PROXY_SESSIONS.idFromName(`s:${token}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  try {
    await stub.fetch("https://session/internal/close", {
      method: "POST",
      headers: { "X-Proxy-Id": rec.proxyId },
    });
  } catch {}
  return new Response(null, { status: 204, headers: noStore() });
}

async function relayWebSocket(request, env) {
  const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "").split(",").map((v) => v.trim());
  const proto = protocols.find((v) => v.startsWith("tproxy-v1."));
  const token = proto ? proto.slice("tproxy-v1.".length) : "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return notFound();
  const rec = await safeKvJson(env, `session:${token}`, null);
  if (!rec || rec.exp < Date.now()) return notFound();
  const doId = env.PROXY_SESSIONS.idFromName(`s:${token}`);
  const stub = env.PROXY_SESSIONS.get(doId);
  return stub.fetch("https://session/internal/ws", {
    method: "GET",
    headers: {
      "Upgrade": "websocket",
      "X-TProxy-Protocol": proto,
      "X-Proxy-Id": rec.proxyId,
    },
  });
}

async function handleRoot(url, env) {
  const expectedHost = canonicalHost(env?.PUBLIC_HOSTNAME || url.hostname);
  if (canonicalHost(url.hostname) !== expectedHost) return publicPage(env);

  const bridgeValue = exactBridgeQuery(url);
  if (bridgeValue) {
    const proxyId = await findProxyByCapability(env, expectedHost, bridgeValue);
    if (!proxyId) return publicPage(env);
    const meta = await safeKvJson(env, `proxy:${proxyId}`, null);
    if (!meta || !meta.enabled) return publicPage(env);
    const bootstrap = await createBootstrap(env, proxyId);
    return bridgePage(expectedHost, bootstrap);
  }

  const serverParam = url.searchParams.get("server");
  const secretParam = url.searchParams.get("secret");
  if (serverParam && secretParam) {
    if (canonicalHost(serverParam) !== expectedHost) return publicPage(env);
    const secret = String(secretParam).toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(secret)) return publicPage(env);
    const proxyId = await safeKvText(env, `secret:${secret}`, "");
    if (!proxyId) return publicPage(env);
    const meta = await safeKvJson(env, `proxy:${proxyId}`, null);
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
  const all = await safeKvJson(env, `all:proxies`, []);
  for (const id of all) {
    const meta = await safeKvJson(env, `proxy:${id}`, null);
    if (!meta || !meta.enabled) continue;
    if (!/^[0-9a-f]{32}$/.test(String(meta.secret || ""))) continue;
    try {
      const expected = base64url(await hmac(
        hexToBytes(meta.secret),
        new TextEncoder().encode(`tdesktop-web-proxy-bridge-v1\n${host}`)
      ));
      if (constantTimeEqual(candidate, expected)) return id;
    } catch {}
  }
  return null;
}
function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function publicPage(env) {
  const bot = env?.TELEGRAM_BOT_USERNAME ? `https://t.me/${env.TELEGRAM_BOT_USERNAME}` : null;
  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const html = `<!doctype html><html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${BRAND} v${VERSION}</title>
<style>
body{margin:0;min-height:100vh;background:#0b0e13;color:#e7edf4;
 font:14px/1.6 ui-monospace,Menlo,monospace;display:grid;place-items:center;padding:16px}
.card{max-width:560px;width:100%;padding:28px;background:#141a22;border:1px solid #29323e;border-radius:12px;text-align:center}
h1{margin:0 0 8px;font-size:22px}p{color:#8a96a5;margin:6px 0}
a{color:#4d9fff;text-decoration:none}
.row{margin-top:18px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap}
.b{display:inline-block;padding:9px 16px;border:1px solid #29323e;border-radius:8px;text-decoration:none;color:inherit}
.b:hover{border-color:#4d9fff}
</style></head><body>
<div class="card">
  <h1>🌐 ${BRAND}</h1>
  <p>MTProto + VLESS در یک Worker</p>
  <p style="margin-top:12px">Host: <code>${escapeHtml(host)}</code></p>
  <div class="row">
    ${bot ? `<a class="b" href="${bot}">🤖 ربات تلگرام</a>` : ""}
    <a class="b" href="/healthz">🩺 Health</a>
    <a class="b" href="/setup">⚙️ Setup</a>
    <a class="b" href="/debug">🐞 Debug</a>
  </div>
  <p style="font-size:10px;color:#5f6b79;margin-top:20px">v${VERSION} · ${BUILD_TAG}</p>
</div></body></html>`;
  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", ...noStore() },
  });
}

function setupPage(env) {
  const host = canonicalHost(env?.PUBLIC_HOSTNAME || "");
  const bot = env?.TELEGRAM_BOT_USERNAME ? `https://t.me/${env.TELEGRAM_BOT_USERNAME}` : "(تنظیم نشده)";
  const html = `<!doctype html><html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Setup · ${BRAND}</title>
<style>
body{margin:0;min-height:100vh;background:#0b0e13;color:#e7edf4;
 font:14px/1.6 ui-monospace,Menlo,monospace;padding:24px}
.wrap{max-width:640px;margin:0 auto}
.row{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #29323e}
.ok{color:#4ade80}.bad{color:#f87171}
h1{font-size:20px}code{background:#0b0e13;border:1px solid #29323e;border-radius:6px;padding:2px 6px;direction:ltr;display:inline-block}
</style></head><body>
<div class="wrap">
<h1>⚙️ ${BRAND} Setup</h1>
<div class="row"><span>Version</span><span class="ok">${VERSION}</span></div>
<div class="row"><span>Build</span><span class="ok">${BUILD_TAG}</span></div>
<div class="row"><span>PUBLIC_HOSTNAME</span><span class="${host ? 'ok' : 'bad'}">${escapeHtml(host || "(not set)")}</span></div>
<div class="row"><span>TELEGRAM_BOT_USERNAME</span><span class="ok">${escapeHtml(env?.TELEGRAM_BOT_USERNAME || "(not set)")}</span></div>
<div class="row"><span>TELEGRAM_BOT_TOKEN</span><span class="${env?.TELEGRAM_BOT_TOKEN ? 'ok' : 'bad'}">${env?.TELEGRAM_BOT_TOKEN ? "set" : "missing"}</span></div>
<div class="row"><span>TELEGRAM_WEBHOOK_SECRET</span><span class="${env?.TELEGRAM_WEBHOOK_SECRET ? 'ok' : 'bad'}">${env?.TELEGRAM_WEBHOOK_SECRET ? "set" : "missing"}</span></div>
<div class="row"><span>ADMIN_IDS</span><span class="${env?.ADMIN_IDS ? 'ok' : 'bad'}">${escapeHtml(env?.ADMIN_IDS || "(open to all)")}</span></div>
<div class="row"><span>PROXY_REGISTRY (KV)</span><span class="${env?.PROXY_REGISTRY ? 'ok' : 'bad'}">${env?.PROXY_REGISTRY ? "bound" : "missing"}</span></div>
<div class="row"><span>PROXY_SESSIONS (DO)</span><span class="${env?.PROXY_SESSIONS ? 'ok' : 'bad'}">${env?.PROXY_SESSIONS ? "bound" : "missing"}</span></div>
<div class="row"><span>VLESS_TARGET_HOST</span><span class="ok">${escapeHtml(env?.VLESS_TARGET_HOST || "www.cloudflare.com (default)")}</span></div>
<div class="row"><span>VLESS_TARGET_PORT</span><span class="ok">${escapeHtml(String(env?.VLESS_TARGET_PORT || "443 (default)"))}</span></div>
<p style="margin-top:20px;color:#8a96a5">
VLESS UUID‌ها به‌صورت خودکار ساخته می‌شوند.
</p>
<p>Bot: <a style="color:#4d9fff" href="${bot}">${bot}</a></p>
</div></body></html>`;
  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", ...noStore() },
  });
}
