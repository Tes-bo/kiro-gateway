// ---------------------------------------------------------------------------
// Relay mode: translate Kiro's CodeWhisperer requests into the Anthropic Messages
// API, send them to any compatible relay, then translate the upstream SSE stream in real time back into the AWS
// event-stream binary frames that Kiro can recognize.
//
// Official direct mode (official) is "swap credentials and pass through", with zero protocol translation; relay mode is "protocol translation".
// The two share the same endpoint-redirection mechanism, but each occupies its own port and they do not interfere.
//
// This file deliberately does not require("vscode"): all config reads, logging, and stats instrumentation are injected by extension.js
// at startup through init(), so the translation layer stays pure and a circular dependency with the main file is avoided.
// ---------------------------------------------------------------------------
"use strict";

const http = require("http");
const https = require("https");
const { StringDecoder } = require("string_decoder");

// --- Host injection ---------------------------------------------------------------
// extension.js calls init() during activate to hand these capabilities in. An empty implementation is the fallback,
// so if injection is forgotten there is simply no logging and no stats; it will not throw and interrupt the request.
let host = {
  prefs: () => ({}),
  isEnabled: () => false,
  log: () => {},
  version: () => "0.0.0",
  stats: {
    requestStarted: () => {},
    addOutBytes: () => {},
    requestFailed: () => {},
    requestFinished: () => {},
  },
  // Fixed prefix/suffix prompts: relay mode reuses that same config from the panel.
  applyPromptPrefs: (buf) => ({ buf, applied: "" }),
};

function init(impl) {
  host = { ...host, ...(impl || {}) };
  if (impl && impl.stats) host.stats = { ...host.stats, ...impl.stats };
}

function log(...args) {
  try { host.log(...args); } catch {}
}

function prefs() {
  try { return host.prefs() || {}; } catch { return {}; }
}

// ---------------------------------------------------------------------------
// AWS event-stream frame encoding
//
// Kiro's runtime endpoint returns application/vnd.amazon.eventstream: a sequence of binary frames,
// each frame = total length (4) + headers length (4) + prelude CRC (4) + headers + payload + message CRC (4).
// The relay returns text SSE, so every event has to be repacked in this format.
// ---------------------------------------------------------------------------
const EVENT_STREAM_CONTENT_TYPE = "application/vnd.amazon.eventstream";
const HEADER_TYPE_STRING = 7; // Header value type: UTF-8 string

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf, start, end) {
  let crc = 0xffffffff;
  for (let i = start; i < end; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ -1) >>> 0;
}

function encodeHeader(name, value) {
  const nameBuf = Buffer.from(name, "utf8");
  const valBuf = Buffer.from(value, "utf8");
  const buf = Buffer.alloc(1 + nameBuf.length + 1 + 2 + valBuf.length);
  let off = 0;
  buf.writeUInt8(nameBuf.length, off); off += 1;
  nameBuf.copy(buf, off); off += nameBuf.length;
  buf.writeUInt8(HEADER_TYPE_STRING, off); off += 1;
  buf.writeUInt16BE(valBuf.length, off); off += 2;
  valBuf.copy(buf, off);
  return buf;
}

function encodeFrame(headers, payload) {
  const headersLen = headers.length;
  const total = 12 + headersLen + payload.length + 4;
  const buf = Buffer.alloc(total);
  let off = 0;
  buf.writeUInt32BE(total, off); off += 4;
  buf.writeUInt32BE(headersLen, off); off += 4;
  // The prelude CRC covers only the first 8 bytes (the two length fields).
  buf.writeUInt32BE(crc32(buf, 0, 8), off); off += 4;
  headers.copy(buf, off); off += headersLen;
  payload.copy(buf, off); off += payload.length;
  // The message CRC covers through the end of the payload.
  buf.writeUInt32BE(crc32(buf, 0, off), off);
  return buf;
}

function encodeEvent(eventType, payload) {
  const headers = Buffer.concat([
    encodeHeader(":message-type", "event"),
    encodeHeader(":event-type", eventType),
    encodeHeader(":content-type", "application/json"),
  ]);
  return encodeFrame(headers, Buffer.from(JSON.stringify(payload), "utf8"));
}

function encodeException(exceptionType, payload) {
  const headers = Buffer.concat([
    encodeHeader(":message-type", "exception"),
    encodeHeader(":exception-type", exceptionType),
    encodeHeader(":content-type", "application/json"),
  ]);
  return encodeFrame(headers, Buffer.from(JSON.stringify(payload), "utf8"));
}

// Write an intermediate event object out as the corresponding CodeWhisperer frame. The bytes written are returned so the
// "output token estimate" in the stats lines up with official direct mode.
function writeEvent(res, ev) {
  let buf = null;
  if (ev.assistantResponseEvent) {
    buf = encodeEvent("assistantResponseEvent", ev.assistantResponseEvent);
  } else if (ev.messageMetadataEvent) {
    buf = encodeEvent("messageMetadataEvent", ev.messageMetadataEvent);
  } else if (ev.toolUseEvent) {
    // stop:true tells Kiro this tool call's input is complete and can be executed.
    buf = encodeEvent("toolUseEvent", { ...ev.toolUseEvent, stop: true });
  } else if (ev.reasoningContentEvent) {
    buf = encodeEvent("reasoningContentEvent", ev.reasoningContentEvent);
  } else if (ev.contextUsageEvent) {
    buf = encodeEvent("contextUsageEvent", ev.contextUsageEvent);
  } else if (ev.metadataEvent) {
    buf = encodeEvent("metadataEvent", ev.metadataEvent);
  }
  if (!buf) return 0;
  try { res.write(buf); } catch { return 0; }
  return buf.length;
}

// ---------------------------------------------------------------------------
// Upstream requests: the relay address may be a self-hosted http service, so use native http/https instead of fetch.
// ---------------------------------------------------------------------------
const UPSTREAM_TIMEOUT_MS = 30 * 60 * 1000; // Generation requests can take a long time; leave plenty of headroom
const PROBE_TIMEOUT_MS = 15 * 1000;         // Small requests such as the model list / usage

function requestUpstream(method, urlStr, headers, body, timeoutMs = UPSTREAM_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(String(urlStr || "").trim());
    } catch {
      reject(new Error("中转站地址无法解析: " + urlStr));
      return;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      reject(new Error("中转站地址需要以 http:// 或 https:// 开头"));
      return;
    }
    const lib = url.protocol === "http:" ? http : https;
    const payload = body === undefined ? undefined
      : Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
    const finalHeaders = { ...headers };
    if (payload) finalHeaders["content-length"] = String(payload.length);

    const req = lib.request(
      {
        method,
        hostname: url.hostname,
        port: url.port || (url.protocol === "http:" ? 80 : 443),
        path: url.pathname + url.search,
        headers: finalHeaders,
        timeout: timeoutMs,
      },
      (res) => resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: res })
    );
    req.on("error", (e) => reject(e));
    req.on("timeout", () => { req.destroy(new Error("中转站请求超时")); });
    if (payload) req.write(payload);
    req.end();
  });
}

// Read the response body into a string. The cap is protection: if the relay returns a large file, it must not exhaust memory.
const BODY_CAP = 2 * 1024 * 1024;
function readBody(stream) {
  return new Promise((resolve, reject) => {
    let data = "";
    let over = false;
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      if (over) return;
      data += chunk;
      if (data.length > BODY_CAP) { over = true; data = data.slice(0, BODY_CAP); }
    });
    stream.on("end", () => resolve(data));
    stream.on("error", reject);
  });
}

async function getJson(urlStr, headers, timeoutMs = PROBE_TIMEOUT_MS) {
  const res = await requestUpstream("GET", urlStr, { Accept: "application/json", ...headers }, undefined, timeoutMs);
  const text = await readBody(res.body);
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw new Error("HTTP " + res.statusCode + ": " + text.slice(0, 300));
  }
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// URL assembly
//
// The user may enter https://x.com, https://x.com/v1, or https://x.com/v1/. Normalize them into
// the Anthropic endpoint form "base + /messages", and keep the root address for the usage API.
// ---------------------------------------------------------------------------
function baseUrlRaw() {
  return String(prefs().baseUrl || "").trim().replace(/\/+$/, "");
}

// Anthropic endpoint: if /v1 was left off, append it automatically so a missing segment does not 404.
function resolveApiUrl(apiPath) {
  const base = baseUrlRaw();
  if (!base) return "";
  const p = apiPath.startsWith("/") ? apiPath : "/" + apiPath;
  if (/\/v\d+$/i.test(base)) return base + p;
  return base + "/v1" + p;
}

// Site root: usage / billing APIs are mounted on the site root, not under /v1.
function resolveRootUrl(urlPath) {
  const base = baseUrlRaw();
  if (!base) return "";
  const root = base.replace(/\/v\d+$/i, "");
  const p = urlPath.startsWith("/") ? urlPath : "/" + urlPath;
  return root + p;
}
// The relay's web address: stripping a trailing /v1 from baseUrl gives the site root. The panel's "web panel"
// button goes here -- the extension only speaks the API; bill details and top-up records still have to be viewed on their site.
// If it cannot be derived, return an empty string and the button hides itself.
function relaySiteUrl() {
  const base = baseUrlRaw();
  if (!base) return "";
  return base.replace(/\/v\d+$/i, "");
}

function relayApiKey() {
  return String(prefs().apiKey || "").trim();
}

// Whether the relay is fully configured. The panel and the KRS handler both use this to decide whether to prompt the user to fill it in.
function relayConfigured() {
  return !!baseUrlRaw() && !!relayApiKey();
}

// ---------------------------------------------------------------------------
// Model catalog: fetch a list from the relay's /v1/models and cache it.
//
// Kiro's model dropdown comes from CPS ListAvailableModels, so this list directly decides which models
// the user can pick in the editor.
// ---------------------------------------------------------------------------
const EFFORT_LEVELS = ["low", "medium", "high", "xhigh", "max"];
const DEFAULT_EFFORT_LEVEL = "high";
const EFFORT_SUFFIX_RE = /-(low|medium|high|xhigh|max)$/i;
const MODEL_TTL_MS = 60 * 1000;

let _modelCache = [];
let _modelCacheAt = 0;
let _modelAuthStyle = "";  // Auth style that succeeded last time; prefer it next time
let _modelLastError = "";

function parseContextWindow(m) {
  const raw = m.context_window ?? m.context_length ?? m.max_input_tokens
    ?? m.max_context_tokens ?? m.maxInputTokens ?? m.contextWindow;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

// Relay auth headers come in two styles: Anthropic's native x-api-key, and OpenAI-style
// Authorization: Bearer. Try both; whichever succeeds is the one we keep.
function buildModelHeaders(style, apiKey) {
  return style === "bearer"
    ? { Authorization: "Bearer " + apiKey, Accept: "application/json" }
    : { "x-api-key": apiKey, "anthropic-version": "2023-06-01", Accept: "application/json" };
}

function parseModelList(text) {
  const raw = JSON.parse(text);
  const arr = Array.isArray(raw.data) ? raw.data
    : Array.isArray(raw.models) ? raw.models
    : Array.isArray(raw) ? raw : [];
  return arr
    .filter((x) => !!x && typeof x === "object")
    .filter((x) => x.id || x.modelId)
    .map((x) => {
      const id = String(x.id || x.modelId);
      const levels = Array.isArray(x.effort_levels) ? x.effort_levels
        : Array.isArray(x.effortLevels) ? x.effortLevels : null;
      const effortLevels = levels ? levels.filter((e) => typeof e === "string") : undefined;
      const maxOutRaw = x.max_tokens ?? x.max_output_tokens ?? x.maxOutputTokens;
      const maxOut = Number(maxOutRaw);
      return {
        id,
        name: String(x.display_name || x.name || x.modelName || id),
        contextWindow: parseContextWindow(x),
        description: typeof x.description === "string" ? x.description : "",
        effortLevels: effortLevels && effortLevels.length ? effortLevels : undefined,
        effortSchemaPath: typeof x.effort_schema_path === "string" ? x.effort_schema_path
          : typeof x.effortSchemaPath === "string" ? x.effortSchemaPath : undefined,
        defaultEffortLevel: typeof x.default_effort_level === "string" ? x.default_effort_level
          : typeof x.defaultEffortLevel === "string" ? x.defaultEffortLevel : undefined,
        maxOutputTokens: Number.isFinite(maxOut) && maxOut > 0 ? maxOut : undefined,
      };
    });
}

async function fetchRelayModels(force = false) {
  const now = Date.now();
  if (!force && _modelCache.length && now - _modelCacheAt < MODEL_TTL_MS) return _modelCache;
  const apiKey = relayApiKey();
  const url = resolveApiUrl("/models");
  if (!apiKey || !url) return _modelCache;

  const order = _modelAuthStyle
    ? [_modelAuthStyle, _modelAuthStyle === "bearer" ? "x-api-key" : "bearer"]
    : ["x-api-key", "bearer"];
  let lastErr = "";
  for (const style of order) {
    try {
      const res = await requestUpstream("GET", url, buildModelHeaders(style, apiKey), undefined, PROBE_TIMEOUT_MS);
      const text = await readBody(res.body);
      // 401/403 means this auth style is the wrong fit; try the other one, and do not treat it as a hard error.
      if (res.statusCode === 401 || res.statusCode === 403) {
        lastErr = "HTTP " + res.statusCode + "（认证方式 " + style + " 被拒）";
        continue;
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new Error("HTTP " + res.statusCode + ": " + text.slice(0, 200));
      }
      const models = parseModelList(text);
      if (models.length) {
        _modelCache = models;
        _modelCacheAt = Date.now();
        _modelAuthStyle = style;
        _modelLastError = "";
        log("[中转站] 模型列表已更新: " + models.length + " 个（认证 " + style + "）");
      }
      return _modelCache;
    } catch (e) {
      lastErr = e?.message || String(e);
    }
  }
  _modelLastError = lastErr;
  log("!! [中转站] 拉取模型列表失败: " + lastErr);
  return _modelCache;
}

function modelSnapshot() {
  return {
    count: _modelCache.length,
    at: _modelCacheAt,
    auth: _modelAuthStyle || "",
    error: _modelLastError || "",
    ids: _modelCache.map((m) => m.id).slice(0, 200),
  };
}

function clearModelCache() {
  _modelCache = [];
  _modelCacheAt = 0;
  _modelLastError = "";
}

// Whether the relay separately offers a "base model + effort suffix" variant (e.g. xxx-high).
function hasEffortVariant(base, effort) {
  const target = (String(base || "") + "-" + String(effort || "")).toLowerCase();
  if (!base || !effort) return false;
  return _modelCache.some((m) => m.id.toLowerCase() === target);
}

function contextWindowForModel(id) {
  const hit = _modelCache.find((m) => m.id === id);
  return hit ? hit.contextWindow : 0;
}

function thinkingVariantOf(base) {
  const b = String(base || "").toLowerCase();
  if (!b || b.endsWith("-thinking")) return "";
  const hit = _modelCache.find((m) => m.id.toLowerCase() === b + "-thinking");
  return hit ? hit.id : "";
}

// Collapse xxx, xxx-high, and xxx-max into one base model plus a set of selectable effort levels, so Kiro's dropdown
// shows "one model + an effort picker" instead of a pile of entries that look duplicated.
function groupModelsByEffort(models) {
  const map = new Map();
  const order = [];
  const ensure = (baseId, src) => {
    let g = map.get(baseId);
    if (!g) {
      g = { baseId, name: baseId, description: "", efforts: new Set() };
      map.set(baseId, g);
      order.push(baseId);
    }
    if (src.contextWindow && !g.maxInputTokens) g.maxInputTokens = src.contextWindow;
    return g;
  };
  for (const m of models) {
    if (!m || !m.id) continue;
    const match = m.id.match(EFFORT_SUFFIX_RE);
    if (match) {
      const baseId = m.id.slice(0, m.id.length - match[0].length);
      ensure(baseId, m).efforts.add(match[1].toLowerCase());
    } else {
      const g = ensure(m.id, m);
      if (m.name) g.name = m.name;
      if (m.description) g.description = m.description;
      if (m.effortLevels && m.effortLevels.length) g.nativeEffortLevels = m.effortLevels;
      if (m.effortSchemaPath) g.effortSchemaPath = m.effortSchemaPath;
      if (m.defaultEffortLevel) g.defaultEffortLevel = m.defaultEffortLevel;
      if (m.maxOutputTokens && !g.maxOutputTokens) g.maxOutputTokens = m.maxOutputTokens;
    }
  }
  return order.map((id) => map.get(id));
}

// ---------------------------------------------------------------------------
// Thinking effort
//
// Kiro's model picker has max/xhigh/high/medium/low effort levels. A relay may not recognize that set, so
// translate it according to the config into a "model variant" or a "thinking budget".
// ---------------------------------------------------------------------------
const DEFAULT_EFFORT_BUDGETS = { low: 2048, medium: 4096, high: 8192, xhigh: 16384, max: 24576 };
const VALID_EFFORTS = new Set(EFFORT_LEVELS);
const EFFORT_CACHE_MAX = 200;
const _effortCache = new Map(); // conversationId -> effort

function getEffortMode() {
  const m = prefs().effortMode;
  return m === "off" || m === "modelVariant" || m === "thinkingBudget" ? m : "auto";
}

function normEffort(x) {
  if (typeof x !== "string") return "";
  const v = x.trim().toLowerCase();
  return VALID_EFFORTS.has(v) ? v : "";
}

function budgetForEffort(effort) {
  const e = normEffort(effort);
  if (!e) return 0;
  const override = prefs().effortBudgets || {};
  const v = Number(override[e]);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_EFFORT_BUDGETS[e];
}

// The effort level may be hidden in several places in the request body, depending on the Kiro version; check all of them.
function effortFromRequest(req) {
  const cm = req?.conversationState?.currentMessage?.userInputMessage;
  const candidates = [
    cm?.userInputMessageContext?.additionalModelRequestFields,
    cm?.additionalModelRequestFields,
    req?.additionalModelRequestFields,
    req?.conversationState?.additionalModelRequestFields,
  ];
  for (const f of candidates) {
    if (!f || typeof f !== "object") continue;
    const e = normEffort(f.output_config?.effort ?? f.reasoning?.effort);
    if (e) return e;
  }
  return "";
}

function rememberEffort(convId, effort) {
  if (!convId || !effort) return;
  if (_effortCache.size >= EFFORT_CACHE_MAX && !_effortCache.has(convId)) {
    const oldest = _effortCache.keys().next().value;
    if (oldest !== undefined) _effortCache.delete(oldest);
  }
  _effortCache.set(convId, effort);
}

// When the request body carries no effort level, fall back to the value remembered from the previous turn of the same conversation -- Kiro only writes
// it into the request body on the turn where the level is switched, and omits it on later turns.
function selectedEffort(req) {
  const convId = req?.conversationState?.conversationId || "";
  const fromReq = effortFromRequest(req);
  if (fromReq) {
    rememberEffort(convId, fromReq);
    return fromReq;
  }
  if (convId && _effortCache.has(convId)) return _effortCache.get(convId);
  return "";
}

// ---------------------------------------------------------------------------
// Translation layer: CodeWhisperer request body → Anthropic Messages request body
//
// The structure Kiro sends is roughly:
//   conversationState: {
//     conversationId, history: [...], currentMessage: {...}
//   }
// history alternates userInputMessage / assistantResponseMessage; tool calls and
// tool results are attached on the two sides respectively. On the Anthropic side it is a flat messages array plus content blocks.
// ---------------------------------------------------------------------------
// Last-resort fallback when the request contains no modelId at all. Only the last line of defense -- see fallbackModelId();
// prefer a model the relay itself reported. A hardcoded name may not be recognized if you switch relays.
const LAST_RESORT_MODEL_ID = "CLAUDE_SONNET_4_20250514_V1_0";

// The fallback model ID is taken from the first item of the model list already fetched (the same default buildCpsModelList hands to Kiro);
// only fall back to the constant when the list has not been fetched yet.
function fallbackModelId() {
  return _modelCache[0]?.id || LAST_RESORT_MODEL_ID;
}

// Thinking blocks in assistant history. Anthropic requires a thinking block to carry a signature before it can be sent back; if either piece is missing it
// cannot be included, or the upstream will assume the signature was tampered with and return an error.
function extractThinkingBlock(arm) {
  const rc = arm.reasoningContent;
  let text;
  let signature;
  if (rc && typeof rc === "object") {
    text = rc.reasoningText?.text;
    signature = rc.reasoningText?.signature ?? arm.reasoningSignature;
  } else if (typeof rc === "string") {
    text = rc;
    signature = arm.reasoningSignature;
  }
  if (text && signature) return { type: "thinking", thinking: text, signature };
  return null;
}

// Take the modelId from the latest user message -- if the user switches models midway, the newest one wins.
function latestModelId(req) {
  const items = [
    ...(req.conversationState?.history || []),
    ...(req.conversationState?.currentMessage ? [req.conversationState.currentMessage] : []),
  ];
  for (let i = items.length - 1; i >= 0; i--) {
    const id = items[i]?.userInputMessage?.modelId;
    if (id) return id;
  }
  return fallbackModelId();
}

function conversationIdOf(req) {
  return req?.conversationState?.conversationId || "unknown";
}

// Kiro internal model ID → relay model ID. Check the user's mapping table first, then the fallback model; if neither is set, pass it through as-is
// (many relays accept Kiro IDs directly).
function resolveModel(kiroModelId) {
  const mapping = prefs().modelMapping || {};
  if (mapping[kiroModelId]) return String(mapping[kiroModelId]);
  const def = String(prefs().defaultModel || "").trim();
  if (def) return def;
  return kiroModelId;
}

function parseToolSpec(spec) {
  const ts = spec.toolSpecification || spec;
  let schema;
  const raw = ts.inputSchema;
  if (raw && typeof raw === "object") {
    schema = raw.json && typeof raw.json === "object" ? raw.json : raw;
  }
  return { name: ts.name || "", description: ts.description, schema };
}

// Tool results come in many shapes (string, {text}, {json}, mixed arrays); squashing them to plain text is the most reliable.
function toolResultToText(content) {
  if (content == null) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    const parts = [];
    for (const item of content) {
      if (item == null) continue;
      if (typeof item === "string") { parts.push(item); continue; }
      if (typeof item === "object") {
        if (typeof item.text === "string") parts.push(item.text);
        else if (item.json !== undefined) parts.push(typeof item.json === "string" ? item.json : JSON.stringify(item.json));
        else parts.push(JSON.stringify(item));
        continue;
      }
      parts.push(String(item));
    }
    return parts.join("\n");
  }
  if (typeof content === "object") {
    if (typeof content.text === "string") return content.text;
    return JSON.stringify(content);
  }
  return String(content);
}

function parseToolInput(input) {
  if (typeof input === "string") {
    try { return JSON.parse(input); } catch { return {}; }
  }
  return input ?? {};
}

// Kiro stuffs "the currently open file", "#File references", and the like into userInputMessageContext.
// Anthropic has no corresponding field, so join them into marked text and append it after the user message.
function buildContextText(msg) {
  const parts = [];
  const ctx = msg.userInputMessageContext;
  for (const c of ctx?.additionalContext || []) {
    const inner = String(c.innerContext || "").trim();
    if (!inner) continue;
    const label = [c.name, c.description].filter(Boolean).join(" - ");
    parts.push("[Context" + (label ? ": " + label : "") + "]\n" + inner);
  }
  const editor = ctx?.editorState;
  if (editor?.document?.text) {
    parts.push("[Active file: " + (editor.document.relativeFilePath || "") + "]\n" + editor.document.text);
  }
  for (const d of editor?.relevantDocuments || []) {
    if (d?.text) parts.push("[File: " + (d.relativeFilePath || "") + "]\n" + d.text);
  }
  return parts.join("\n\n");
}

function buildUserText(msg) {
  const ctxText = buildContextText(msg);
  const content = msg.content || "";
  if (!ctxText) return content;
  return content ? content + "\n\n" + ctxText : ctxText;
}

function buildAnthropicRequest(req) {
  const state = req.conversationState || {};
  const items = [...(state.history || [])];
  if (state.currentMessage) items.push(state.currentMessage);

  const messages = [];
  let tools;

  for (const item of items) {
    if (item?.userInputMessage) {
      const uim = item.userInputMessage;
      const blocks = [];
      // Tool results must come first in this turn's user message; Anthropic requires them to immediately follow the matching tool_use.
      for (const tr of uim.userInputMessageContext?.toolResults || []) {
        blocks.push({ type: "tool_result", tool_use_id: tr.toolUseId, content: toolResultToText(tr.content) });
      }
      const text = buildUserText(uim);
      if (text) blocks.push({ type: "text", text });
      for (const img of uim.images || []) {
        blocks.push({
          type: "image",
          source: {
            type: "base64",
            media_type: "image/" + String(img.format || "png").toLowerCase(),
            data: img.source?.bytes,
          },
        });
      }
      if (blocks.length) {
        // When there is only one plain-text block, use the string form, skipping a layer of nesting, for better compatibility.
        messages.push({
          role: "user",
          content: blocks.length === 1 && blocks[0].type === "text" ? blocks[0].text : blocks,
        });
      }
      // The tool spec is resent every turn; overwrite it whenever one arrives, so what remains is the latest copy.
      if (uim.userInputMessageContext?.tools) {
        tools = uim.userInputMessageContext.tools.map((spec) => {
          const { name, description, schema } = parseToolSpec(spec);
          const input_schema = { type: "object", properties: schema?.properties ?? {} };
          if (schema?.required) input_schema.required = schema.required;
          return { name, description, input_schema };
        });
      }
    }

    if (item?.assistantResponseMessage) {
      const arm = item.assistantResponseMessage;
      const blocks = [];
      const thinking = extractThinkingBlock(arm);
      if (thinking) blocks.push(thinking);
      if (arm.content) blocks.push({ type: "text", text: arm.content });
      for (const tu of arm.toolUses || []) {
        blocks.push({ type: "tool_use", id: tu.toolUseId, name: tu.name, input: parseToolInput(tu.input) });
      }
      // An assistant message cannot be empty; put in a placeholder so the upstream does not reject the whole conversation.
      if (!blocks.length) blocks.push({ type: "text", text: "(no content)" });
      messages.push({
        role: "assistant",
        content: blocks.length === 1 && blocks[0].type === "text" ? blocks[0].text : blocks,
      });
    }
  }

  const model = resolveModel(latestModelId(req));
  const p = prefs();
  const maxTokens = Number(p.maxTokens) > 0 ? Number(p.maxTokens) : 32000;
  const body = { model, messages, max_tokens: maxTokens, stream: true };
  if (tools && tools.length) body.tools = tools;

  // Thinking mode: a model whose name contains thinking is treated as enabled by default, unless the user explicitly turns it off.
  let thinkCfg = thinkingConfig();
  if (/thinking/i.test(model) && thinkCfg.type !== "disabled") {
    thinkCfg = { type: "enabled", budget_tokens: thinkingBudget() };
  }
  if (thinkCfg.type === "enabled" && thinkCfg.budget_tokens) {
    setThinkingBudget(body, thinkCfg.budget_tokens);
  }

  applyCacheBreakpoints(body);
  return body;
}

function thinkingConfig() {
  const t = String(prefs().thinking || "auto");
  if (t === "enabled") return { type: "enabled", budget_tokens: thinkingBudget() };
  if (t === "disabled") return { type: "disabled" };
  return { type: "auto" };
}

function thinkingBudget() {
  const n = Number(prefs().thinkingBudget);
  return Number.isFinite(n) && n > 0 ? n : 8192;
}

// The thinking budget must leave margin for the body text, or the upstream errors immediately because budget >= max_tokens.
function setThinkingBudget(body, budget) {
  if (!budget || budget <= 0) return;
  const b = Math.min(budget, body.max_tokens - 4096);
  if (b >= 1024) body.thinking = { type: "enabled", budget_tokens: b };
}

function isAnthropicModel(model) {
  return /claude|anthropic/i.test(String(model || ""));
}

// Prompt-cache breakpoints: let the relay reuse a repeated conversation prefix. cache_control is an Anthropic-specific
// field; skip it by default for non-Claude models so a relay that does not recognize the field does not fail the whole request.
function applyCacheBreakpoints(body) {
  const mode = String(prefs().promptCaching || "auto");
  if (mode === "off") return;
  if (mode === "auto" && !isAnthropicModel(body.model)) return;

  const cc = () => ({ type: "ephemeral" });
  const MAX = 4; // Anthropic allows at most 4 breakpoints per request
  let used = 0;

  if (body.tools && body.tools.length && used < MAX) {
    body.tools[body.tools.length - 1].cache_control = cc();
    used++;
  }
  const msgs = body.messages;
  if (!msgs || !msgs.length) return;

  const mark = (idx) => {
    const m = msgs[idx];
    if (!m) return false;
    if (typeof m.content === "string") {
      if (!m.content) return false;
      m.content = [{ type: "text", text: m.content, cache_control: cc() }];
      return true;
    }
    for (let i = m.content.length - 1; i >= 0; i--) {
      const b = m.content[i];
      if (b.type === "text" || b.type === "tool_result") { b.cache_control = cc(); return true; }
    }
    return false;
  };

  // The first user message: the system-prompt portion, unchanged for the whole conversation, and the most worth caching.
  const firstUser = msgs.findIndex((m) => m.role === "user");
  if (firstUser >= 0 && used < MAX && mark(firstUser)) used++;

  // The second-to-last user message: so the previous turn's conversation prefix can hit the cache too.
  const userIdx = [];
  for (let i = 0; i < msgs.length; i++) if (msgs[i].role === "user") userIdx.push(i);
  if (userIdx.length >= 3 && used < MAX) {
    const target = userIdx[userIdx.length - 2];
    if (target !== firstUser) mark(target);
  }
}

// Apply Kiro's effort level to the request. Three ways to land it: if the relay itself has an effort-variant model, change the model name;
// otherwise convert it into a thinking budget; in modelVariant mode, fall back to the -thinking variant.
function applyEffort(body, effort) {
  if (!effort) return;
  const mode = getEffortMode();
  if (mode === "off") return;

  body.output_config = { effort };
  if (mode === "auto" || mode === "modelVariant") {
    if (hasEffortVariant(body.model, effort)) {
      body.model = body.model + "-" + effort;
      return;
    }
    if (mode === "modelVariant") {
      const tv = thinkingVariantOf(body.model);
      if (tv) {
        body.model = tv;
        setThinkingBudget(body, budgetForEffort(effort));
      }
      return;
    }
  }
  // Reaching here in auto mode means the relay has no matching effort variant: pass output_config through as-is,
  // and let the relay decide how to handle it. Do not force it into a thinking budget -- for a model that does not support thinking,
  // that would bounce the request straight back. For deterministic behavior, set effortMode explicitly to thinkingBudget.
  if (mode === "thinkingBudget") {
    setThinkingBudget(body, budgetForEffort(effort));
  }
}

// ---------------------------------------------------------------------------
// Stream converter: Anthropic SSE → CodeWhisperer events
//
// The upstream sends one "data: {...}" per line. The event sequence is roughly:
//   message_start → (content_block_start → content_block_delta* →
//   content_block_stop)* → message_delta → message_stop
// Each kind of delta maps to one Kiro event: body text goes out as assistantResponseEvent, thinking as
// reasoningContentEvent, and tool calls must accumulate their input and then send toolUseEvent all at once.
// ---------------------------------------------------------------------------
const FALLBACK_CONTEXT_WINDOW = 200000;

// Context window: use the relay's value if it reported one; otherwise the only option is to guess from the model name.
//
// When guessing, guess low. This value is the denominator; guessing high makes the computed occupancy ratio too small -- for example a real
// occupancy of 100K/200K (50%) becomes 10% if the window is guessed as 1000000. Kiro thinks it is still quite empty and does not trigger
// compression, then keeps stuffing more in until the upstream reports the context is over-length. Prefer overestimating occupancy so it compresses earlier; the only cost is compressing
// a bit more often. Underestimating means this conversation crashes outright.
// So a large value is used only when the relay explicitly reports the window. Something like "auto", where there is no way to know which model it will route to,
// is always computed with the conservative window.
function contextWindowForModelId(modelId) {
  const fromRelay = contextWindowForModel(modelId);
  if (fromRelay > 0) return fromRelay;
  const m = String(modelId || "").toLowerCase();
  // Use the large window only when the model name explicitly names a large-window generation; auto is not one of those.
  if (/(opus|sonnet)-4[.-](6|7|8)/.test(m) || /sonnet-5|fable[.-]?5/.test(m)) {
    return 1000000;
  }
  return FALLBACK_CONTEXT_WINDOW;
}

function contextUsagePercent(tokens, modelId) {
  if (!tokens || tokens <= 0) return null;
  const win = contextWindowForModelId(modelId);
  if (!win || win <= 0) return null;
  return Math.max(0, Math.min(100, (tokens / win) * 100));
}

class AnthropicStreamConverter {
  constructor(conversationId, modelId) {
    this.conversationId = conversationId;
    this.modelId = modelId;
    this.currentToolId = "";
    this.currentToolName = "";
    this.currentToolInput = "";
    this.inToolUse = false;
    this.inThinking = false;
    this.curSignature = "";
    this.startInputTokens = 0;
    this.pendingContextPct = null;
    this.sentContextPct = null;
    this.sawText = false;
    this.usage = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheCreationTokens: 0 };
  }

  // Handle one SSE line. Returns zero or more events waiting to be written.
  processLine(line) {
    if (!line.startsWith("data:")) return [];
    const payload = line.slice(line.indexOf(":") + 1).trim();
    if (!payload || payload === "[DONE]") return [];
    try {
      return this.handleEvent(JSON.parse(payload));
    } catch {
      return [];
    }
  }

  handleEvent(ev) {
    const out = [];

    if (ev.type === "message_start") {
      out.push({ messageMetadataEvent: { conversationId: this.conversationId } });
      const u = ev.message?.usage;
      if (u) {
        this.captureUsage(u);
        // Cache-read and cache-write tokens also occupy context, so they have to be counted in together.
        const total = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
        this.startInputTokens = total;
        // Emit immediately; do not hold it until flush(). Context occupancy means "how much of the input is used", and at message_start
        // that number is already fixed, so there is no reason to keep waiting. If it is held until the last moment, once the stream
        // is interrupted (account switch and resend, or an upstream error), this turn's percentage is lost, and Kiro's circle stays
        // stuck on the old value. Over several turns it drifts further and further, and by the time it catches up the context has already overflowed.
        out.push(...this.emitContextPct(contextUsagePercent(total, this.modelId)));
      }
      return out;
    }

    if (ev.type === "content_block_start") {
      const block = ev.content_block;
      if (block?.type === "tool_use") {
        this.inToolUse = true;
        this.currentToolId = block.id || "";
        this.currentToolName = block.name || "";
        this.currentToolInput = "";
      } else if (block?.type === "thinking") {
        this.inThinking = true;
        this.curSignature = "";
      }
      return out;
    }

    if (ev.type === "content_block_delta") {
      const d = ev.delta;
      if (d?.type === "text_delta" && d.text) {
        this.sawText = true;
        out.push({ assistantResponseEvent: { content: d.text, modelId: this.modelId } });
      } else if (d?.type === "thinking_delta" && d.thinking) {
        out.push({ reasoningContentEvent: { text: d.thinking } });
      } else if (d?.type === "signature_delta" && d.signature) {
        // The signature arrives in fragments; once it is accumulated, send it all at once at block_stop.
        this.curSignature += d.signature;
      } else if (d?.type === "input_json_delta" && d.partial_json) {
        this.currentToolInput += d.partial_json;
      }
      return out;
    }

    if (ev.type === "content_block_stop") {
      if (this.inThinking) {
        if (this.curSignature) out.push({ reasoningContentEvent: { signature: this.curSignature } });
        this.inThinking = false;
        this.curSignature = "";
      }
      if (this.inToolUse) {
        out.push({
          toolUseEvent: {
            toolUseId: this.currentToolId,
            name: this.currentToolName,
            input: this.currentToolInput || "{}",
          },
        });
        this.inToolUse = false;
        this.currentToolId = "";
        this.currentToolName = "";
        this.currentToolInput = "";
      }
      return out;
    }

    if (ev.type === "message_delta" && ev.usage) {
      this.captureUsage(ev.usage);
      // Some relays compute the context-occupancy percentage for us. They know the real window size, which is more accurate than
      // our guess from the model name, so emit it immediately and overwrite the earlier estimate.
      const relayPct = ev.usage.contextUsagePercentage;
      if (typeof relayPct === "number" && relayPct >= 0) {
        out.push(...this.emitContextPct(relayPct));
      }
      // Compute from the merged cumulative usage, not from this message_delta alone: the upstream often reports the full input breakdown
      // (including cache read/write) in message_start, and at message_delta only
      // adds an output_tokens. Trusting only the current event drops the cache portion, and the input token count comes out too small.
      const inTokens = this.usage.inputTokens + this.usage.cacheReadTokens + this.usage.cacheCreationTokens;
      out.push({
        metadataEvent: {
          type: "token_usage",
          inputTokens: inTokens || this.startInputTokens,
          outputTokens: this.usage.outputTokens || 0,
        },
      });
    }

    return out;
  }

  captureUsage(u) {
    if (typeof u.input_tokens === "number") this.usage.inputTokens = u.input_tokens;
    if (typeof u.output_tokens === "number") this.usage.outputTokens = u.output_tokens;
    if (typeof u.cache_read_input_tokens === "number") this.usage.cacheReadTokens = u.cache_read_input_tokens;
    if (typeof u.cache_creation_input_tokens === "number") this.usage.cacheCreationTokens = u.cache_creation_input_tokens;
  }

  // Emit context occupancy once (the percentage circle at the top of Kiro is drawn from this).
  // If the value matches the last one sent, do not resend, saving a meaningless frame; if it differs, send it, since the later one is more accurate.
  emitContextPct(pct) {
    if (pct === null || pct === undefined || !Number.isFinite(pct)) return [];
    const v = Math.max(0, Math.min(100, pct));
    if (this.sentContextPct !== null && Math.abs(this.sentContextPct - v) < 0.01) return [];
    this.sentContextPct = v;
    this.pendingContextPct = null;
    return [{ contextUsageEvent: { contextUsagePercentage: v } }];
  }

  // Wrap-up: fill in any unclosed tool call and the context-occupancy bar.
  flush() {
    const out = [];
    if (this.inToolUse) {
      out.push({
        toolUseEvent: {
          toolUseId: this.currentToolId,
          name: this.currentToolName,
          input: this.currentToolInput || "{}",
        },
      });
      this.inToolUse = false;
    }
    // Fallback: if nothing was sent for the whole turn (the upstream never reported usage at all), send one at the end.
    if (this.sentContextPct === null && this.pendingContextPct !== null) {
      out.push(...this.emitContextPct(this.pendingContextPct));
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Intent-classification intercept
//
// Before each conversation turn, Kiro first sends a "you are an intent classifier; decide whether this is chat/do/spec" request. This
// request is invisible to the user but costs one real call. Judge it locally by keywords and reply directly, saving that call.
// ---------------------------------------------------------------------------
const CLASSIFIER_SIGN_A = "You are an intent classifier for a language model";
const CLASSIFIER_SIGN_B = "(chat, do, spec)";

function allUserContents(req) {
  const state = req?.conversationState;
  const out = [];
  for (const item of state?.history || []) {
    const c = item?.userInputMessage?.content;
    if (typeof c === "string" && c) out.push(c);
  }
  const cur = state?.currentMessage?.userInputMessage?.content;
  if (typeof cur === "string" && cur) out.push(cur);
  return out;
}

function findClassifierContent(req) {
  for (const c of allUserContents(req)) {
    if (c.includes(CLASSIFIER_SIGN_A) && c.includes(CLASSIFIER_SIGN_B)) return c;
  }
  return "";
}

function isIntentClassifierRequest(req) {
  return findClassifierContent(req) !== "";
}

const SPEC_HINTS = [
  "create a spec", "create spec", "specification", "formal spec", "spec for",
  "spec document", "execute task", "start task", "next task",
  "实现规范", "创建规范", "生成规范", "需求文档",
];

function classifyIntent(prompt) {
  // The classifier prompt is very long; the user's actual words to judge come after this marker.
  const marker = "Here is the last user message:";
  const idx = prompt.lastIndexOf(marker);
  const tail = idx >= 0 ? prompt.slice(idx + marker.length) : prompt;
  const lower = tail.toLowerCase();
  if (SPEC_HINTS.some((h) => lower.includes(h))) return { chat: 0, do: 0.1, spec: 0.9 };
  return { chat: 0, do: 0.95, spec: 0.05 };
}

function buildIntentClassifierResponse(req, convId, modelId) {
  const probs = classifyIntent(findClassifierContent(req));
  return [
    { messageMetadataEvent: { conversationId: convId } },
    { assistantResponseEvent: { content: JSON.stringify(probs), modelId } },
  ];
}

// ---------------------------------------------------------------------------
// CPS: model list
//
// Kiro's model dropdown comes from ListAvailableModels. Here the relay's /v1/models result is translated
// into the structure Kiro recognizes, and an effort-selection schema is attached when needed.
// ---------------------------------------------------------------------------
async function buildCpsModelList() {
  const relay = await fetchRelayModels(false);
  const groups = groupModelsByEffort(relay);
  const mode = getEffortMode();

  const models = groups.map((g) => {
    const model = {
      modelId: g.baseId,
      modelName: g.name || g.baseId,
      description: g.description || "",
      promptCaching: {
        maximumCacheCheckpointsPerRequest: 4,
        minimumTokensPerCacheCheckpoint: 1024,
        supportsPromptCaching: true,
      },
      rateUnit: "Credit",
      supportedInputTypes: ["TEXT", "IMAGE"],
      tokenLimits: {
        maxInputTokens: g.maxInputTokens || 200000,
        maxOutputTokens: g.maxOutputTokens || 64000,
      },
    };

    // Effort source, one of three, in priority order: the relay's native declaration > inferred from model variants > supply the full set.
    let efforts = [];
    let schemaPath = "output_config";
    if (g.nativeEffortLevels && g.nativeEffortLevels.length) {
      efforts = g.nativeEffortLevels;
      if (g.effortSchemaPath) schemaPath = g.effortSchemaPath;
    } else if (mode === "modelVariant") {
      efforts = EFFORT_LEVELS.filter((e) => g.efforts.has(e));
    } else if (mode === "auto" || mode === "thinkingBudget") {
      efforts = [...EFFORT_LEVELS];
    }

    if (efforts.length) {
      model.additionalModelRequestFieldsSchema = {
        type: "object",
        properties: {
          [schemaPath]: {
            type: "object",
            properties: { effort: { type: "string", enum: efforts } },
          },
        },
      };
      model.defaultEffortLevel = g.defaultEffortLevel && efforts.includes(g.defaultEffortLevel)
        ? g.defaultEffortLevel
        : efforts.includes(DEFAULT_EFFORT_LEVEL) ? DEFAULT_EFFORT_LEVEL : efforts[0];
    }
    return model;
  });

  const result = { models };
  if (models.length) result.defaultModel = { modelId: models[0].modelId };
  return result;
}

// A fake profile: Kiro asks once at startup, and without an answer it gets stuck initializing. Relay mode has no real
// AWS-account concept; a structurally valid placeholder is enough.
function fakeProfile() {
  return {
    arn: "arn:aws:codewhisperer:us-east-1:000000000000:profile/KIROAPIKEYIDE",
    profileName: "Kiro Gateway",
    identityDetails: { region: "us-east-1" },
  };
}

// Fold the x-amz-target header and the URL path into one lowercase string that is easy to match.
function opProbe(req, urlPath) {
  const target = String(req.headers["x-amz-target"] || req.headers["x-amzn-target"] || "");
  const op = (target.split(".").pop() || "").replace(/[^a-z0-9]/gi, "").toLowerCase();
  const pathKey = String(urlPath || "").replace(/[^a-z0-9]/gi, "").toLowerCase();
  return { probe: op + " " + pathKey, op, pathKey, hasTarget: !!target };
}

// ---------------------------------------------------------------------------
// KRS: translate and forward generation requests
// ---------------------------------------------------------------------------
function beginEventStream(res) {
  res.writeHead(200, {
    "Content-Type": EVENT_STREAM_CONTENT_TYPE,
    "Transfer-Encoding": "chunked",
  });
  // Turn off Nagle: otherwise small incremental frames get buffered before sending, and the reply feels stuttery.
  try { res.socket?.setNoDelay(true); } catch {}
}

// Send a passage of text as a normal assistant reply. Used for cases like "not configured yet" -- better than throwing,
// because the user can see what to do directly in the chat box.
function writeSetupMessage(res, convId, msg) {
  beginEventStream(res);
  writeEvent(res, { messageMetadataEvent: { conversationId: convId } });
  writeEvent(res, { assistantResponseEvent: { content: msg, modelId: "relay-setup" } });
  res.end();
}

function makeRelayKrsHandler() {
  return function handle(req, res) {
    const urlRaw = req.url || "/";
    if (urlRaw === host.healthPath) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(host.healthMarker);
      return;
    }
    try { host.markProxyHit("KRS", req); } catch {}

    const method = req.method || "GET";
    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("error", (e) => log("!! [中转站/KRS] 读取请求失败: " + (e?.message || e)));
    req.on("end", async () => {
      let bodyBuf = Buffer.concat(chunks);
      const urlPath = urlRaw.split("?")[0];
      try {
        if (!host.isEnabled()) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end("{}");
          return;
        }
        const bodyText = bodyBuf.length ? bodyBuf.toString("utf8") : "";
        const isGenerate = urlPath === "/generateAssistantResponse"
          || urlPath === "/SendMessageStreaming"
          || (method === "POST" && bodyText.indexOf("conversationState") !== -1);

        if (isGenerate) {
          await handleGenerate(req, res, bodyBuf);
        } else if (method === "POST" && bodyText.indexOf('"jsonrpc"') !== -1 && bodyText.indexOf('"method"') !== -1) {
          handleMcpJsonRpc(res, bodyText);
        } else if (looksLikeManagementCall(req, urlPath)) {
          await handleManagementCall(req, res, urlPath);
        } else {
          log("[中转站/KRS] 未识别的请求: " + method + " " + urlPath);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end("{}");
        }
      } catch (e) {
        const msg = e?.message || String(e);
        log("!! [中转站/KRS] 出错: " + msg);
        if (!res.headersSent) {
          res.writeHead(500, {
            "Content-Type": "application/json",
            "x-amzn-errortype": "InternalServerException",
          });
        }
        try { res.end(JSON.stringify({ __type: "InternalServerException", message: msg })); } catch {}
      }
    });
  };
}

// Management calls that should go to CPS sometimes land on KRS (different Kiro versions resolve the generic fallback endpoint
// differently). Answer them in place so the model list does not go empty.
function looksLikeManagementCall(req, urlPath) {
  const { probe } = opProbe(req, urlPath);
  return probe.includes("availablemodels") || probe.includes("profile") || probe.includes("usagelimit");
}

async function handleManagementCall(req, res, urlPath) {
  const { probe, op, pathKey, hasTarget } = opProbe(req, urlPath);
  const contentType = hasTarget ? "application/x-amz-json-1.0" : "application/json";
  log("[中转站/KRS] 管理类调用改由本地应答: " + (op || pathKey));

  if (probe.includes("availablemodels")) {
    let payload = { models: [] };
    try { payload = await buildCpsModelList(); } catch (e) {
      log("!! [中转站/KRS] 构造模型列表失败: " + (e?.message || e));
    }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(JSON.stringify(payload));
    return;
  }
  if (probe.includes("profile")) {
    const isList = probe.includes("profiles");
    res.writeHead(200, { "Content-Type": contentType });
    res.end(JSON.stringify(isList ? { profiles: [fakeProfile()] } : { profile: fakeProfile() }));
    return;
  }
  res.writeHead(200, { "Content-Type": contentType });
  res.end("{}");
}

// Kiro sends InvokeMCPCommand to the runtime endpoint to probe for "server-hosted MCP tools". The relay
// has nothing like that, but returning {} is not valid JSON-RPC and makes Kiro's tool-discovery flow fail, which looks
// as if the tools are all gone. Return a valid "no remote tools" result; local tools are unaffected.
function handleMcpJsonRpc(res, rawBody) {
  let id = null;
  let rpcMethod = "";
  try {
    const parsed = JSON.parse(rawBody);
    id = parsed?.id ?? null;
    rpcMethod = typeof parsed?.method === "string" ? parsed.method : "";
  } catch {}
  log("[中转站/KRS] MCP: " + (rpcMethod || "(无法解析)"));

  // A message with no id is a notification; the protocol does not require a result in return.
  if (id === null || id === undefined) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("");
    return;
  }
  const version = host.version();
  let result;
  switch (rpcMethod) {
    case "initialize":
      result = {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "kiro-gateway", version },
      };
      break;
    case "tools/list": result = { tools: [] }; break;
    case "prompts/list": result = { prompts: [] }; break;
    case "resources/list": result = { resources: [] }; break;
    case "resources/templates/list": result = { resourceTemplates: [] }; break;
    default: result = {}; break;
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
}

async function handleGenerate(req, res, bodyBuf) {
  // Fixed prefix/suffix prompts are injected before translation, so the behavior matches official direct mode.
  const injected = host.applyPromptPrefs(bodyBuf);
  if (injected.applied) {
    bodyBuf = injected.buf;
    log("[中转站/KRS] 已注入" + injected.applied + "提示词");
  }

  let parsed;
  try {
    parsed = JSON.parse(bodyBuf.toString("utf8") || "{}");
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "请求体不是合法 JSON" }));
    return;
  }

  const convId = conversationIdOf(parsed);
  const kiroModel = latestModelId(parsed);

  if (!relayConfigured()) {
    const missing = [];
    if (!baseUrlRaw()) missing.push("· 缺少中转站地址");
    if (!relayApiKey()) missing.push("· 缺少 API Key");
    writeSetupMessage(res, convId,
      "⚠️ 中转站还没配置好。\n\n请在左侧「Kiro Gateway」面板的「中转站」页签里填写地址与 API Key 后再试。\n\n"
      + missing.join("\n"));
    return;
  }

  // Intent classification: judge it locally and save one upstream call.
  if (prefs().interceptIntentClassifier !== false && isIntentClassifierRequest(parsed)) {
    log("[中转站/KRS] 本地应答意图分类请求 conv=" + convId);
    beginEventStream(res);
    for (const ev of buildIntentClassifierResponse(parsed, convId, kiroModel)) writeEvent(res, ev);
    res.end();
    return;
  }

  const effort = selectedEffort(parsed);
  const anthropicBody = buildAnthropicRequest(parsed);
  applyEffort(anthropicBody, effort);
  const upstreamModel = anthropicBody.model;
  const payload = JSON.stringify(anthropicBody);
  const targetUrl = resolveApiUrl("/messages");

  // Stats follow the same scheme as official direct mode: request count, input/output volume, and failure count are the same set of numbers on the panel.
  host.stats.requestStarted(payload.length, "");
  let statEnded = false;
  const endOnce = (ok) => {
    if (statEnded) return;
    statEnded = true;
    if (!ok) host.stats.requestFailed("");
    host.stats.requestFinished();
  };

  const headers = {
    "content-type": "application/json",
    "x-api-key": relayApiKey(),
    // Some relays only accept OpenAI-style Authorization; sending both is the least trouble.
    authorization: "Bearer " + relayApiKey(),
    "anthropic-version": "2023-06-01",
    accept: "text/event-stream",
    "x-client": "kiro-gateway/" + host.version(),
  };

  log("-> [中转站/KRS] " + upstreamModel + " (kiro=" + kiroModel
    + (effort ? ", 档位=" + effort : "") + ") conv=" + convId);

  let upstream;
  try {
    upstream = await requestUpstream("POST", targetUrl, headers, payload);
  } catch (e) {
    const msg = e?.message || String(e);
    log("!! [中转站/KRS] 连接失败: " + msg);
    endOnce(false);
    // Explain the error as an assistant reply; that is more useful than a red 500.
    beginEventStream(res);
    writeEvent(res, { messageMetadataEvent: { conversationId: convId } });
    writeEvent(res, {
      assistantResponseEvent: { content: "❌ 无法连接中转站：" + msg, modelId: upstreamModel },
    });
    res.write(encodeException("InternalServerException", { message: msg }));
    res.end();
    return;
  }

  if (upstream.statusCode < 200 || upstream.statusCode >= 300) {
    const errText = await readBody(upstream.body);
    log("!! [中转站/KRS] 上游 HTTP " + upstream.statusCode + ": " + errText.slice(0, 300));
    endOnce(false);
    beginEventStream(res);
    writeEvent(res, { messageMetadataEvent: { conversationId: convId } });
    writeEvent(res, {
      assistantResponseEvent: {
        content: "❌ 上游返回 " + upstream.statusCode + "：\n\n" + errText.slice(0, 800),
        modelId: upstreamModel,
      },
    });
    res.write(encodeException("InternalServerException", { message: "Upstream " + upstream.statusCode }));
    res.end();
    return;
  }

  beginEventStream(res);
  await pumpStream(res, upstream.body, convId, upstreamModel, endOnce);
}

// Read the upstream SSE, translate, and write as it arrives. Nothing is written to disk and the whole body is never buffered, so the user sees character-by-character output.
function pumpStream(res, body, convId, modelId, endOnce) {
  return new Promise((resolve) => {
    const converter = new AnthropicStreamConverter(convId, modelId);
    const decoder = new StringDecoder("utf8");
    let buffer = "";
    let clientClosed = false;
    let finished = false;
    let outBytes = 0;

    const emit = (ev) => {
      const n = writeEvent(res, ev);
      if (n) outBytes += n;
    };

    const done = () => {
      if (finished) return;
      finished = true;
      res.removeListener("close", onClientClose);
      try {
        if (!clientClosed && !res.writableEnded) {
          for (const ev of converter.flush()) emit(ev);
          res.end();
        }
      } catch {}
      // Output volume is recorded from the bytes actually sent back, matching the accounting used by official direct mode.
      if (outBytes) host.stats.addOutBytes(outBytes, "");
      endOnce(true);
      resolve();
    };

    // The user clicked stop / reloaded the window: cut the upstream connection immediately, or the relay keeps charging.
    const onClientClose = () => {
      clientClosed = true;
      try { body.destroy(); } catch {}
      done();
    };
    res.on("close", onClientClose);

    const processBuffer = () => {
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, "");
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        for (const ev of converter.processLine(line)) {
          if (clientClosed) return;
          emit(ev);
        }
      }
    };

    body.on("data", (chunk) => {
      if (clientClosed) return;
      buffer += decoder.write(chunk);
      try { processBuffer(); } catch (e) {
        log("!! [中转站/KRS] 处理流出错: " + (e?.message || e));
      }
    });
    body.on("end", () => {
      buffer += decoder.end();
      try { processBuffer(); } catch {}
      done();
    });
    body.on("error", (e) => {
      log("!! [中转站/KRS] 上游流中断: " + (e?.message || e));
      done();
    });
  });
}

// ---------------------------------------------------------------------------
// CPS: control plane
// ---------------------------------------------------------------------------
function makeRelayCpsHandler() {
  return function handle(req, res) {
    const urlRaw = req.url || "/";
    if (urlRaw === host.healthPath) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(host.healthMarker);
      return;
    }
    req.resume(); // The control-plane request body is unused; drain it so the connection does not hang
    if (!host.isEnabled()) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
      return;
    }
    try { host.markProxyHit("CPS", req); } catch {}

    const urlPath = urlRaw.split("?")[0];
    const { probe, op, pathKey, hasTarget } = opProbe(req, urlPath);
    const contentType = hasTarget ? "application/x-amz-json-1.0" : "application/json";

    if (probe.includes("availablemodels")) {
      buildCpsModelList()
        .then((list) => {
          log("<- [中转站/CPS] ListAvailableModels (" + list.models.length + " 个模型)");
          res.writeHead(200, { "Content-Type": contentType });
          res.end(JSON.stringify(list));
        })
        .catch((e) => {
          log("!! [中转站/CPS] 构造模型列表失败: " + (e?.message || e));
          res.writeHead(200, { "Content-Type": contentType });
          res.end(JSON.stringify({ models: [] }));
        });
      return;
    }
    if (probe.includes("profile")) {
      const isList = probe.includes("profiles");
      res.writeHead(200, { "Content-Type": contentType });
      res.end(JSON.stringify(isList ? { profiles: [fakeProfile()] } : { profile: fakeProfile() }));
      return;
    }
    if (probe.includes("usagelimit")) {
      // The relay has no Kiro quota concept; an empty object is enough, and Kiro hides the quota bar.
      res.writeHead(200, { "Content-Type": contentType });
      res.end("{}");
      return;
    }
    log("[中转站/CPS] 未识别的控制面请求: " + (op || pathKey));
    res.writeHead(200, { "Content-Type": contentType });
    res.end("{}");
  };
}

// ---------------------------------------------------------------------------
// Usage lookup
//
// Relay usage APIs have no single standard. Probe the common styles one by one, use the first hit, and cache
// the probe result (next time ask that one directly instead of trying each).
// ---------------------------------------------------------------------------
const USAGE_SOURCE_TTL_MS = 30 * 60 * 1000;
const NEWAPI_QUOTA_DIVISOR = 500000; // New-API quota units → US dollars
let _usageSource = "";               // Style that hit last time
let _usageSourceAt = 0;

function usageSourceCached() {
  if (!_usageSource) return "";
  if (Date.now() - _usageSourceAt > USAGE_SOURCE_TTL_MS) return "";
  return _usageSource;
}

function rememberUsageSource(source) {
  _usageSource = source;
  _usageSourceAt = Date.now();
}

function clearUsageSource() {
  _usageSource = "";
  _usageSourceAt = 0;
}

const USAGE_SOURCE_LABEL = {
  kirotool: "KiroTool",
  newapi: "New-API / One-API",
  kiro2cc: "kiro2cc-proxy",
  billing: "OpenAI 兼容计费接口",
};

// KiroTool style: /api/pub/quota, includes per-request details, and the cache hit rate can be computed along the way.
async function tryPubQuota() {
  const key = relayApiKey();
  const data = await getJson(resolveRootUrl("/api/pub/quota"), { Authorization: "Bearer " + key });
  if (!data || (data.credit_limit === undefined && data.credit_used === undefined)) return null;

  const logs = Array.isArray(data.logs) ? data.logs : [];
  const modelMap = new Map();
  let totalInput = 0;
  let totalOutput = 0;
  let totalCacheRead = 0;
  let totalCacheWrite = 0;
  let cacheRecords = 0;

  for (const row of logs) {
    if (!row || typeof row !== "object") continue;
    const model = String(row.model ?? "unknown");
    const inTok = Number(row.prompt_tokens) || Number(row.est_prompt_tokens) || 0;
    const outTok = Number(row.completion_tokens) || 0;
    const credits = Number(row.credits) || 0;
    totalInput += inTok;
    totalOutput += outTok;
    // Cache-write field names differ by vendor; try them in turn, and if none is present count it as 0.
    totalCacheWrite += Number(row.cache_creation_tokens)
      || Number(row.cache_write_tokens)
      || Number(row.cache_creation_input_tokens)
      || 0;
    if (row.cache_tokens != null) {
      totalCacheRead += Number(row.cache_tokens) || 0;
      cacheRecords++;
    }
    const cur = modelMap.get(model) || { model, requests: 0, inputTokens: 0, outputTokens: 0, credits: 0 };
    cur.requests++;
    cur.inputTokens += inTok;
    cur.outputTokens += outTok;
    cur.credits += credits;
    modelMap.set(model, cur);
  }

  // Hit rate = cache reads / total input. Which denominator to use depends on whether the upstream prompt_tokens already includes cache
  // reads. Both conventions exist, and guessing wrong has an obvious effect:
  //   already included but added again → hit rate is cut in half (99% shows as 50%)
  //   not included and not added       → hit rate exceeds 100%
  // So infer from "whether cache reads exceed total input": if they do, the two were recorded separately, so add them.
  const cacheDenom = totalCacheRead > totalInput ? totalInput + totalCacheRead : totalInput;
  const cache = cacheRecords > 0
    ? {
        records: cacheRecords,
        cacheReadTokens: totalCacheRead,
        cacheWriteTokens: totalCacheWrite,
        // Carry the denominator out as well. The panel displays it as "total input tokens", so the accounting must match the hit rate.
        denomTokens: cacheDenom,
        hitRate: cacheDenom > 0 ? Math.min(1, totalCacheRead / cacheDenom) : null,
      }
    : null;

  let note = "";
  if (data.disabled === true) note = "（账号已禁用）";
  else if (data.expired === true) note = "（额度已过期）";

  return {
    source: "kirotool",
    name: (typeof data.key_preview === "string" ? data.key_preview : "") + note,
    creditLimit: data.credit_limit != null ? Number(data.credit_limit) : null,
    totalCredits: Number(data.credit_used) || 0,
    expiresAt: typeof data.expires_at === "string" ? data.expires_at : "",
    totalRequests: logs.length,
    totalInputTokens: totalInput,
    totalOutputTokens: totalOutput,
    byModel: [...modelMap.values()],
    cache,
  };
}

// New-API / One-API style: /api/user/self. Note that Authorization does not include a Bearer prefix.
async function tryNewApi() {
  const key = relayApiKey();
  const data = await getJson(resolveRootUrl("/api/user/self"), { Authorization: key });
  if (!data || data.success !== true) return null;
  const d = data.data;
  if (!d || typeof d.quota !== "number") return null;

  const used = Number(d.used_quota) || 0;
  const remain = Number(d.quota) || 0;
  const total = used + remain;
  return {
    source: "newapi",
    name: String(d.display_name || d.username || ""),
    creditLimit: total > 0 ? total / NEWAPI_QUOTA_DIVISOR : null,
    totalCredits: used / NEWAPI_QUOTA_DIVISOR,
    totalRequests: Number(d.request_count) || 0,
    totalInputTokens: 0,
    totalOutputTokens: 0,
    byModel: [],
    cache: null,
    expiresAt: "",
  };
}

// kiro2cc-proxy style: /api/user/usage. The field names are the camelCase set.
async function tryKiro2cc() {
  const key = relayApiKey();
  const data = await getJson(resolveRootUrl("/api/user/usage"), { "x-api-key": key });
  if (!data || data.totalRequests === undefined) return null;

  const byModel = Array.isArray(data.byModel)
    ? data.byModel.map((m) => ({
        model: String(m.model ?? ""),
        requests: Number(m.requests) || 0,
        inputTokens: Number(m.inputTokens) || 0,
        outputTokens: Number(m.outputTokens) || 0,
        credits: m.credits != null ? Number(m.credits) : Number(m.cost) || 0,
      }))
    : [];
  return {
    source: "kiro2cc",
    name: typeof data.name === "string" ? data.name : "",
    creditLimit: data.creditLimit != null ? Number(data.creditLimit)
      : data.spendingLimit != null ? Number(data.spendingLimit) : null,
    totalCredits: data.totalCredits != null ? Number(data.totalCredits) : Number(data.totalCost) || 0,
    expiresAt: typeof data.expiresAt === "string" ? data.expiresAt : "",
    totalRequests: Number(data.totalRequests) || 0,
    totalInputTokens: Number(data.totalInputTokens) || 0,
    totalOutputTokens: Number(data.totalOutputTokens) || 0,
    byModel,
    cache: null,
  };
}

// OpenAI-compatible billing API: subscription quota plus cumulative spend. A generic fallback.
async function tryBilling() {
  const key = relayApiKey();
  const auth = { Authorization: "Bearer " + key };
  const sub = await getJson(resolveRootUrl("/v1/dashboard/billing/subscription"), auth);
  if (!sub || (sub.hard_limit_usd === undefined && sub.total_granted === undefined && sub.hard_limit === undefined)) {
    return null;
  }
  const limit = Number(sub.hard_limit_usd ?? sub.hard_limit ?? sub.total_granted ?? 0) || 0;
  const accessUntil = Number(sub.access_until ?? 0) || 0;

  let usedUsd = 0;
  try {
    const p = (n) => String(n).padStart(2, "0");
    const ymd = (d) => d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
    const end = ymd(new Date(Date.now() + 86400000));
    const usage = await getJson(
      resolveRootUrl("/v1/dashboard/billing/usage?start_date=2020-01-01&end_date=" + end), auth);
    usedUsd = (Number(usage.total_usage) || 0) / 100; // This API's unit is cents
  } catch {}

  return {
    source: "billing",
    name: "",
    creditLimit: limit > 0 ? limit : null,
    totalCredits: usedUsd,
    expiresAt: accessUntil > 0 ? new Date(accessUntil * 1000).toISOString() : "",
    totalRequests: 0,
    totalInputTokens: 0,
    totalOutputTokens: 0,
    byModel: [],
    cache: null,
  };
}

const USAGE_PROBES = {
  kirotool: tryPubQuota,
  newapi: tryNewApi,
  kiro2cc: tryKiro2cc,
  billing: tryBilling,
};
const USAGE_PROBE_ORDER = ["kirotool", "newapi", "kiro2cc", "billing"];

async function fetchRelayUsage(force = false) {
  if (!relayConfigured()) {
    return { ok: false, message: "请先填写中转站地址与 API Key" };
  }
  if (force) clearUsageSource();

  // If the last probe hit, ask that one first and skip a few pointless probe round trips.
  const cached = usageSourceCached();
  const order = cached
    ? [cached, ...USAGE_PROBE_ORDER.filter((s) => s !== cached)]
    : USAGE_PROBE_ORDER;

  const tried = [];
  for (const source of order) {
    try {
      const hit = await USAGE_PROBES[source]();
      if (hit) {
        rememberUsageSource(source);
        log("[中转站] 用量接口: " + (USAGE_SOURCE_LABEL[source] || source));
        return {
          ok: true,
          at: Date.now(),
          sourceLabel: USAGE_SOURCE_LABEL[source] || source,
          siteUrl: relaySiteUrl(),
          ...hit,
        };
      }
      tried.push(source + " 响应结构不匹配");
    } catch (e) {
      tried.push(source + " " + shortErr(e));
    }
  }
  clearUsageSource();
  return {
    ok: false,
    message: "没能识别中转站的用量接口格式",
    tried,
  };
}

function shortErr(e) {
  const m = String(e?.message || e).replace(/\s+/g, " ").trim();
  const http = m.match(/^HTTP\s+(\d+)/i);
  if (http) return "HTTP " + http[1];
  return m.length > 60 ? m.slice(0, 57) + "…" : m;
}

// ---------------------------------------------------------------------------
// Connectivity test: the "Test connection" button on the panel. It only fetches the model list, sends no generation request, and costs nothing.
// ---------------------------------------------------------------------------
async function testRelayConnection() {
  const base = baseUrlRaw();
  const key = relayApiKey();
  if (!base) return { ok: false, message: "请先填写中转站地址" };
  if (!key) return { ok: false, message: "请先填写 API Key" };

  const url = resolveApiUrl("/models");
  const started = Date.now();
  let lastErr = "";
  for (const style of ["x-api-key", "bearer"]) {
    try {
      const res = await requestUpstream("GET", url, buildModelHeaders(style, key), undefined, PROBE_TIMEOUT_MS);
      const text = await readBody(res.body);
      const ms = Date.now() - started;
      if (res.statusCode === 401 || res.statusCode === 403) {
        lastErr = "HTTP " + res.statusCode + "（认证被拒）";
        continue;
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return { ok: false, status: res.statusCode, ms, message: "HTTP " + res.statusCode + "：" + text.slice(0, 200) };
      }
      let models = [];
      try { models = parseModelList(text); } catch (e) {
        return { ok: false, status: res.statusCode, ms, message: "模型列表无法解析：" + shortErr(e) };
      }
      if (models.length) {
        // Use this result as the cache while we're here, so the model dropdown right after does not have to fetch again.
        _modelCache = models;
        _modelCacheAt = Date.now();
        _modelAuthStyle = style;
        _modelLastError = "";
      }
      const groups = groupModelsByEffort(models);
      return {
        ok: models.length > 0,
        status: res.statusCode,
        ms,
        auth: style,
        total: models.length,
        groups: groups.length,
        names: groups.slice(0, 8).map((g) => g.baseId),
        message: models.length ? "" : "连接成功，但中转站没返回任何模型",
      };
    } catch (e) {
      lastErr = shortErr(e);
    }
  }
  return { ok: false, ms: Date.now() - started, message: lastErr || "连接失败" };
}

// Relay overview for the panel to display.
function relaySnapshot() {
  return {
    configured: relayConfigured(),
    baseUrl: baseUrlRaw(),
    messagesUrl: resolveApiUrl("/messages"),
    models: modelSnapshot(),
    usageSource: _usageSource ? (USAGE_SOURCE_LABEL[_usageSource] || _usageSource) : "",
  };
}

// When the config changes (address / key), invalidate every cache so data from the previous site is not shown.
function invalidateRelayCaches() {
  clearModelCache();
  clearUsageSource();
  _modelAuthStyle = "";
  _effortCache.clear();
}

module.exports = {
  init,
  // Handlers
  makeRelayKrsHandler,
  makeRelayCpsHandler,
  // For the panel
  testRelayConnection,
  fetchRelayUsage,
  fetchRelayModels,
  buildCpsModelList,
  relaySnapshot,
  relayConfigured,
  invalidateRelayCaches,
  // For unit tests / troubleshooting
  buildAnthropicRequest,
  AnthropicStreamConverter,
  encodeEvent,
  encodeException,
  EVENT_STREAM_CONTENT_TYPE,
};
