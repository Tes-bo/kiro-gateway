// ---------------------------------------------------------------------------
// 中转站模式（relay）：把 Kiro 的 CodeWhisperer 请求翻译成 Anthropic Messages
// API 发给任意兼容中转站，再把上游的 SSE 流实时翻回 Kiro 能识别的 AWS
// event-stream 二进制帧。
//
// 官方直连模式（official）是「换凭证透传」，零协议翻译；中转站模式是「协议翻译」，
// 两者共用同一套端点重定向机制，但各自占用独立端口，互不干扰。
//
// 本文件刻意不 require("vscode")：所有配置读取、日志、统计埋点都由 extension.js
// 在启动时通过 init() 注入，这样翻译层保持纯粹，也避免和主文件循环依赖。
// ---------------------------------------------------------------------------
"use strict";

const http = require("http");
const https = require("https");
const { StringDecoder } = require("string_decoder");

// --- 宿主注入 ---------------------------------------------------------------
// extension.js 在 activate 时调用 init() 把这些能力递进来。给一份空实现兜底，
// 万一忘了注入也只是没日志没统计，不会抛异常把请求打断。
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
  // 固定前置/后置提示词：中转站模式同样复用面板上那份配置。
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
// AWS event-stream 帧编码
//
// Kiro 的 runtime 端点回的是 application/vnd.amazon.eventstream：一串二进制帧，
// 每帧 = 总长(4) + 头部长(4) + 前缀CRC(4) + 头部 + 载荷 + 整帧CRC(4)。
// 中转站给的是文本 SSE，所以每个事件都要按这个格式重新打包。
// ---------------------------------------------------------------------------
const EVENT_STREAM_CONTENT_TYPE = "application/vnd.amazon.eventstream";
const HEADER_TYPE_STRING = 7; // 头部值类型：UTF-8 字符串

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
  // 前缀 CRC 只覆盖前 8 字节（两个长度字段）。
  buf.writeUInt32BE(crc32(buf, 0, 8), off); off += 4;
  headers.copy(buf, off); off += headersLen;
  payload.copy(buf, off); off += payload.length;
  // 整帧 CRC 覆盖到载荷结束。
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

// 把一个中间态事件对象写成对应的 CodeWhisperer 帧。返回写出的字节数，便于统计
// 里那个「输出 token 估算」跟官方直连模式对齐。
function writeEvent(res, ev) {
  let buf = null;
  if (ev.assistantResponseEvent) {
    buf = encodeEvent("assistantResponseEvent", ev.assistantResponseEvent);
  } else if (ev.messageMetadataEvent) {
    buf = encodeEvent("messageMetadataEvent", ev.messageMetadataEvent);
  } else if (ev.toolUseEvent) {
    // stop:true 告诉 Kiro 这个工具调用的入参已经完整，可以执行了。
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
// 上游请求：中转站地址可能是自建的 http 服务，所以走原生 http/https 而不是 fetch。
// ---------------------------------------------------------------------------
const UPSTREAM_TIMEOUT_MS = 30 * 60 * 1000; // 生成类请求可以很久，留足余量
const PROBE_TIMEOUT_MS = 15 * 1000;         // 模型列表 / 用量这类小请求

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

// 把响应体读成字符串。上限保护：中转站要是回一个大文件，不能把内存吃穿。
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
// 地址拼装
//
// 用户填的可能是 https://x.com、https://x.com/v1 或 https://x.com/v1/。统一成
// 「基址 + /messages」这种 Anthropic 端点形式，同时保留根地址供用量接口用。
// ---------------------------------------------------------------------------
function baseUrlRaw() {
  return String(prefs().baseUrl || "").trim().replace(/\/+$/, "");
}

// Anthropic 端点：没写 /v1 的自动补上，避免用户少填一段就 404。
function resolveApiUrl(apiPath) {
  const base = baseUrlRaw();
  if (!base) return "";
  const p = apiPath.startsWith("/") ? apiPath : "/" + apiPath;
  if (/\/v\d+$/i.test(base)) return base + p;
  return base + "/v1" + p;
}

// 站点根地址：用量 / 计费这些接口挂在站点根上，不在 /v1 下面。
function resolveRootUrl(urlPath) {
  const base = baseUrlRaw();
  if (!base) return "";
  const root = base.replace(/\/v\d+$/i, "");
  const p = urlPath.startsWith("/") ? urlPath : "/" + urlPath;
  return root + p;
}
// 中转站的网页地址：把 baseUrl 末尾的 /v1 去掉就是站点根。面板上那个「网页面板」
// 按钮跳这里 —— 插件只认接口，账单明细、充值记录这些还是得去人家网站上看。
// 推不出来就返回空串，按钮自己隐藏。
function relaySiteUrl() {
  const base = baseUrlRaw();
  if (!base) return "";
  return base.replace(/\/v\d+$/i, "");
}

function relayApiKey() {
  return String(prefs().apiKey || "").trim();
}

// 中转站配置齐了没有。面板和 KRS 处理器都用它来决定要不要提示用户去填。
function relayConfigured() {
  return !!baseUrlRaw() && !!relayApiKey();
}

// ---------------------------------------------------------------------------
// 模型仓库：从中转站 /v1/models 拉一份清单缓存起来。
//
// Kiro 的模型下拉框来自 CPS 的 ListAvailableModels，所以这份清单直接决定用户在
// 编辑器里能选什么模型。
// ---------------------------------------------------------------------------
const EFFORT_LEVELS = ["low", "medium", "high", "xhigh", "max"];
const DEFAULT_EFFORT_LEVEL = "high";
const EFFORT_SUFFIX_RE = /-(low|medium|high|xhigh|max)$/i;
const MODEL_TTL_MS = 60 * 1000;

let _modelCache = [];
let _modelCacheAt = 0;
let _modelAuthStyle = "";  // 上次成功的认证风格，下次优先用它
let _modelLastError = "";

function parseContextWindow(m) {
  const raw = m.context_window ?? m.context_length ?? m.max_input_tokens
    ?? m.max_context_tokens ?? m.maxInputTokens ?? m.contextWindow;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

// 中转站的认证头有两种流派：Anthropic 原生的 x-api-key，和 OpenAI 风格的
// Authorization: Bearer。两种都试一遍，谁成谁留下。
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
      // 401/403 说明这种认证风格不对路，换另一种再试，不当成硬错误。
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

// 中转站是否单独提供了「基础模型 + 档位后缀」这种变体（如 xxx-high）。
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

// 把 xxx、xxx-high、xxx-max 归并成一个基础模型 + 一组可选档位，这样 Kiro 的下拉
// 框里是「一个模型 + 档位选择」，而不是一堆看着重复的条目。
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
// 思考档位（effort）
//
// Kiro 的模型选择器带 max/xhigh/high/medium/low 档位。中转站不一定认这套，所以
// 按配置翻译成「模型变体」或「思考预算」。
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

// 档位可能藏在请求体好几个位置，取决于 Kiro 的版本，全都翻一遍。
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

// 请求体里没带档位时退回同一会话上一轮记住的值 —— Kiro 只在切换档位的那一轮把
// 它写进请求体，后续轮次会省掉。
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
// 翻译层：CodeWhisperer 请求体 → Anthropic Messages 请求体
//
// Kiro 发来的结构大致是：
//   conversationState: {
//     conversationId, history: [...], currentMessage: {...}
//   }
// history 里交替出现 userInputMessage / assistantResponseMessage，工具调用与
// 工具结果分别挂在两侧。Anthropic 那边是扁平的 messages 数组 + content 块。
// ---------------------------------------------------------------------------
// 请求里一个 modelId 都没有时的最后兜底。只是最后一道 —— 见 fallbackModelId()，
// 优先用中转站自己报上来的模型，写死的名字换一家中转站就可能不认。
const LAST_RESORT_MODEL_ID = "CLAUDE_SONNET_4_20250514_V1_0";

// 兜底模型 ID 取自已拉到的模型列表首项（同 buildCpsModelList 交给 Kiro 的默认项），
// 列表还没拉到时才退回常量。
function fallbackModelId() {
  return _modelCache[0]?.id || LAST_RESORT_MODEL_ID;
}

// 助手历史里的思考块。Anthropic 要求 thinking 块必须带签名才能回传，缺一个就不
// 能带上，否则上游会以为签名被篡改而报错。
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

// 取最后一次用户消息带的 modelId —— 用户中途换模型时，以最新那次为准。
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

// Kiro 内部模型 ID → 中转站模型 ID。先查用户的映射表，再看兜底模型，都没配就原样
// 透传（很多中转站直接认 Kiro 的 ID）。
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

// 工具结果的形态五花八门（字符串、{text}、{json}、数组混排），压成纯文本最稳。
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

// Kiro 把「当前打开的文件」「#File 引用」这些塞在 userInputMessageContext 里，
// Anthropic 没有对应字段，拼成带标记的文本附在用户消息后面。
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
      // 工具结果必须排在这轮用户消息最前面，Anthropic 要求它紧跟对应的 tool_use。
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
        // 只有一个纯文本块时用字符串形式，省掉一层嵌套，兼容性更好。
        messages.push({
          role: "user",
          content: blocks.length === 1 && blocks[0].type === "text" ? blocks[0].text : blocks,
        });
      }
      // 工具规格每轮都会重发一份，取到就覆盖，最后留下的是最新的那份。
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
      // 助手消息不能是空的，占位一下免得上游拒收整条对话。
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

  // 思考模式：模型名里带 thinking 的默认按开启处理，除非用户明确关掉。
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

// 思考预算必须给正文留出余量，否则上游会因为 budget >= max_tokens 直接报错。
function setThinkingBudget(body, budget) {
  if (!budget || budget <= 0) return;
  const b = Math.min(budget, body.max_tokens - 4096);
  if (b >= 1024) body.thinking = { type: "enabled", budget_tokens: b };
}

function isAnthropicModel(model) {
  return /claude|anthropic/i.test(String(model || ""));
}

// 提示词缓存断点：让中转站复用重复的对话前缀。cache_control 是 Anthropic 专有
// 字段，非 Claude 模型默认跳过，免得中转站因为不认识这个字段整条请求报错。
function applyCacheBreakpoints(body) {
  const mode = String(prefs().promptCaching || "auto");
  if (mode === "off") return;
  if (mode === "auto" && !isAnthropicModel(body.model)) return;

  const cc = () => ({ type: "ephemeral" });
  const MAX = 4; // Anthropic 每请求最多 4 个断点
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

  // 第一条用户消息：系统提示词那一段，整场对话都不变，最值得缓存。
  const firstUser = msgs.findIndex((m) => m.role === "user");
  if (firstUser >= 0 && used < MAX && mark(firstUser)) used++;

  // 倒数第二条用户消息：让上一轮的对话前缀也能命中。
  const userIdx = [];
  for (let i = 0; i < msgs.length; i++) if (msgs[i].role === "user") userIdx.push(i);
  if (userIdx.length >= 3 && used < MAX) {
    const target = userIdx[userIdx.length - 2];
    if (target !== firstUser) mark(target);
  }
}

// 把 Kiro 的档位落到请求上。三种落法：中转站自己有档位变体模型就换模型名；
// 否则折算成思考预算；modelVariant 模式下退而求其次用 -thinking 变体。
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
  // auto 模式走到这里说明中转站没有对应的档位变体：只把 output_config 原样带上，
  // 由中转站自己决定怎么处理。不强行改成思考预算 —— 对不支持 thinking 的模型来说
  // 那会直接把请求打回来。想要确定性的行为就把 effortMode 显式设成 thinkingBudget。
  if (mode === "thinkingBudget") {
    setThinkingBudget(body, budgetForEffort(effort));
  }
}

// ---------------------------------------------------------------------------
// 流转换器：Anthropic SSE → CodeWhisperer 事件
//
// 上游一行一个 "data: {...}"，事件序列大致是：
//   message_start → (content_block_start → content_block_delta* →
//   content_block_stop)* → message_delta → message_stop
// 每种 delta 对应 Kiro 的一种事件：正文走 assistantResponseEvent，思考走
// reasoningContentEvent，工具调用要攒齐入参再一次性发 toolUseEvent。
// ---------------------------------------------------------------------------
const FALLBACK_CONTEXT_WINDOW = 200000;

// 上下文窗口：中转站报了就用它的，没报只能按模型名猜。
//
// 猜的时候必须往小猜。这个值是分母，猜大了算出来的占用比例就偏小 —— 比如真实
// 占用 100K/200K（50%），窗口猜成 1000000 就变成 10%，Kiro 以为还很空，不触发
// 压缩，接着往里塞，直到上游直接报超长。宁可高估占用让它早点压缩，代价只是压缩
// 得勤一点；低估的代价是这轮对话直接崩。
// 所以只有中转站明确上报窗口时才敢用大值，"auto"这种根本不知道会路由到哪个模型
// 的一律按保守窗口算。
function contextWindowForModelId(modelId) {
  const fromRelay = contextWindowForModel(modelId);
  if (fromRelay > 0) return fromRelay;
  const m = String(modelId || "").toLowerCase();
  // 只有型号里明确写了大窗口世代，才按大窗口算；auto 不在其中。
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

  // 处理一行 SSE。返回 0 个或多个待写出的事件。
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
        // 缓存读取和缓存写入的 token 也占上下文，得一起算进去。
        const total = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
        this.startInputTokens = total;
        // 立刻下发，不要攒到 flush()。上下文占用讲的是"输入占了多少"，message_start
        // 这会儿这个数字就已经定了，没有等下去的理由；而攒到最后一刻的话，流一旦
        // 被中断（换号重发、上游报错），这一轮的百分比就丢了，Kiro 那个圆圈会一直
        // 停在旧值上，几轮下来越偏越多，等它反应过来上下文已经爆了。
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
        // 签名是分片来的，攒齐了在 block_stop 时一次性发出去。
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
      // 有些中转站会直接把上下文占用比例算好给我们。它知道真实的窗口大小，比我们
      // 按模型名猜的准，所以拿到就立刻下发覆盖掉先前那个估算值。
      const relayPct = ev.usage.contextUsagePercentage;
      if (typeof relayPct === "number" && relayPct >= 0) {
        out.push(...this.emitContextPct(relayPct));
      }
      // 用合并后的累计 usage 来算，而不是只看这一条 message_delta：上游常常在
      // message_start 里报完整的输入构成（含缓存读取/写入），到 message_delta 只
      // 补一个 output_tokens。只认当前这条会把缓存那部分丢掉，输入 token 就偏小了。
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

  // 下发一次上下文占用（Kiro 顶部那个百分比圆圈就是拿它画的）。
  // 值跟上次发的一样就不重发，省掉无意义的帧；不一样就发，后来的更准。
  emitContextPct(pct) {
    if (pct === null || pct === undefined || !Number.isFinite(pct)) return [];
    const v = Math.max(0, Math.min(100, pct));
    if (this.sentContextPct !== null && Math.abs(this.sentContextPct - v) < 0.01) return [];
    this.sentContextPct = v;
    this.pendingContextPct = null;
    return [{ contextUsageEvent: { contextUsagePercentage: v } }];
  }

  // 收尾：补上没闭合的工具调用和上下文占用条。
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
    // 兜底：整轮下来一次都没发出去过（上游压根没报 usage），最后补一发。
    if (this.sentContextPct === null && this.pendingContextPct !== null) {
      out.push(...this.emitContextPct(this.pendingContextPct));
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// 意图分类拦截
//
// Kiro 每轮对话前会先发一条"你是意图分类器，判断这是 chat/do/spec"的请求。这条
// 请求对用户不可见，却要花一次真实调用。本地按关键词判一下直接回，省掉这一次。
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
  // 分类器的提示词很长，真正要判断的用户原话在这个标记之后。
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
// CPS：模型清单
//
// Kiro 的模型下拉框来自 ListAvailableModels。这里把中转站的 /v1/models 结果翻译
// 成 Kiro 认的结构，并按需附上档位选择的 schema。
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

    // 档位来源三选一：中转站原生声明 > 模型变体推断 > 全量给上。
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

// 假的 profile：Kiro 启动时会问一次，不给它会卡在初始化。中转站模式下没有真实
// 的 AWS 账号概念，回一个结构合法的占位就行。
function fakeProfile() {
  return {
    arn: "arn:aws:codewhisperer:us-east-1:000000000000:profile/KIROAPIKEYIDE",
    profileName: "Kiro Gateway",
    identityDetails: { region: "us-east-1" },
  };
}

// 把 x-amz-target 头和 URL 路径揉成一个便于匹配的小写串。
function opProbe(req, urlPath) {
  const target = String(req.headers["x-amz-target"] || req.headers["x-amzn-target"] || "");
  const op = (target.split(".").pop() || "").replace(/[^a-z0-9]/gi, "").toLowerCase();
  const pathKey = String(urlPath || "").replace(/[^a-z0-9]/gi, "").toLowerCase();
  return { probe: op + " " + pathKey, op, pathKey, hasTarget: !!target };
}

// ---------------------------------------------------------------------------
// KRS：生成请求的翻译转发
// ---------------------------------------------------------------------------
function beginEventStream(res) {
  res.writeHead(200, {
    "Content-Type": EVENT_STREAM_CONTENT_TYPE,
    "Transfer-Encoding": "chunked",
  });
  // 关掉 Nagle：不然小的增量帧会被攒着发，用户会觉得回答一顿一顿的。
  try { res.socket?.setNoDelay(true); } catch {}
}

// 把一段话当成助手的正常回答发出去。用来提示"还没配置"这类情况 —— 比抛错好，
// 用户在对话框里直接就能看懂该去做什么。
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

// 本该走 CPS 的管理类调用有时会落到 KRS（不同 Kiro 版本对通用回退端点的解析不
// 一样）。就地应答，别让模型列表变空。
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

// Kiro 会向 runtime 端点发 InvokeMCPCommand 探测「服务端托管的 MCP 工具」。中转站
// 没有这种东西，但回 {} 不是合法 JSON-RPC，会让 Kiro 的工具发现流程失败、看起来
// 像是工具都没了。回一个合法的「没有远程工具」结果，本地工具不受影响。
function handleMcpJsonRpc(res, rawBody) {
  let id = null;
  let rpcMethod = "";
  try {
    const parsed = JSON.parse(rawBody);
    id = parsed?.id ?? null;
    rpcMethod = typeof parsed?.method === "string" ? parsed.method : "";
  } catch {}
  log("[中转站/KRS] MCP: " + (rpcMethod || "(无法解析)"));

  // 没有 id 的是通知（notification），按协议不需要回结果。
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
  // 固定前置/后置提示词在翻译之前注入，这样它跟官方直连模式的行为一致。
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

  // 意图分类：本地判掉，省一次上游调用。
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

  // 统计沿用官方直连那一套：请求数、输入输出量、失败数在面板上是同一组数字。
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
    // 有的中转站只认 OpenAI 风格的 Authorization，两个都带上最省事。
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
    // 用助手回答的形式把错误说清楚，比一个红色的 500 更有用。
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

// 边读上游 SSE 边转边写，全程不落盘不攒整段，用户看到的是逐字输出。
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
      // 输出量按真实回传字节记，跟官方直连模式的口径保持一致。
      if (outBytes) host.stats.addOutBytes(outBytes, "");
      endOnce(true);
      resolve();
    };

    // 用户点了停止 / 重载窗口：上游连接要立刻掐掉，不然中转站还在计费。
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
// CPS：控制面
// ---------------------------------------------------------------------------
function makeRelayCpsHandler() {
  return function handle(req, res) {
    const urlRaw = req.url || "/";
    if (urlRaw === host.healthPath) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(host.healthMarker);
      return;
    }
    req.resume(); // 控制面请求的 body 用不上，读掉免得连接挂住
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
      // 中转站没有 Kiro 的额度概念，回空对象即可，Kiro 会把额度条隐藏掉。
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
// 用量查询
//
// 中转站的用量接口没有统一标准，常见的几种流派逐个探测，命中即用，并把探测结果
// 缓存起来（下次直接问对的那个，不再挨个试）。
// ---------------------------------------------------------------------------
const USAGE_SOURCE_TTL_MS = 30 * 60 * 1000;
const NEWAPI_QUOTA_DIVISOR = 500000; // New-API 的 quota 单位 → 美元
let _usageSource = "";               // 上次命中的流派
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

// KiroTool 风格：/api/pub/quota，带请求明细，能顺手算出缓存命中率。
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
    // 缓存写入的字段名各家不一样，挨着试一遍，没有就算 0。
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

  // 命中率 = 缓存读取 / 总输入。分母怎么取要看上游的 prompt_tokens 有没有把缓存
  // 读取算进去，两种口径都存在，猜错的后果很直观：
  //   已经算进去了却又加一遍 → 命中率被砍掉一半（99% 显示成 50%）
  //   没算进去却不加         → 命中率超过 100%
  // 所以按"缓存读取有没有超过总输入"反推：超过说明是分开记的，那就相加。
  const cacheDenom = totalCacheRead > totalInput ? totalInput + totalCacheRead : totalInput;
  const cache = cacheRecords > 0
    ? {
        records: cacheRecords,
        cacheReadTokens: totalCacheRead,
        cacheWriteTokens: totalCacheWrite,
        // 分母一起带出去，面板要把它显示成「总输入 token」，口径必须跟命中率一致。
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

// New-API / One-API 风格：/api/user/self，注意 Authorization 不带 Bearer 前缀。
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

// kiro2cc-proxy 风格：/api/user/usage，字段名就是驼峰的那一套。
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

// OpenAI 兼容计费接口：订阅额度 + 累计消费，通用兜底。
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
    usedUsd = (Number(usage.total_usage) || 0) / 100; // 这个接口的单位是美分
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

  // 上次命中过就先问它，省掉几次无谓的探测往返。
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
// 连通性测试：面板上那个「测试连接」按钮。只拉模型列表，不发生成请求，不花钱。
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
        // 顺手把这次结果当缓存用上，紧接着的模型下拉框就不用再拉一次。
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

// 面板要展示的中转站概况。
function relaySnapshot() {
  return {
    configured: relayConfigured(),
    baseUrl: baseUrlRaw(),
    messagesUrl: resolveApiUrl("/messages"),
    models: modelSnapshot(),
    usageSource: _usageSource ? (USAGE_SOURCE_LABEL[_usageSource] || _usageSource) : "",
  };
}

// 配置变了（地址 / Key）就把缓存全部作废，免得拿着上一个站点的数据显示。
function invalidateRelayCaches() {
  clearModelCache();
  clearUsageSource();
  _modelAuthStyle = "";
  _effortCache.clear();
}

module.exports = {
  init,
  // 处理器
  makeRelayKrsHandler,
  makeRelayCpsHandler,
  // 面板用
  testRelayConnection,
  fetchRelayUsage,
  fetchRelayModels,
  buildCpsModelList,
  relaySnapshot,
  relayConfigured,
  invalidateRelayCaches,
  // 单测 / 排查用
  buildAnthropicRequest,
  AnthropicStreamConverter,
  encodeEvent,
  encodeException,
  EVENT_STREAM_CONTENT_TYPE,
};
