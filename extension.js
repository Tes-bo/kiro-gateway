"use strict";
// Kiro Gateway
// ---------------------------------------------------------------------------
// Route Kiro's built-in AI calls through a Kiro API key (ksk_...)
// or a JSON OAuth credential (refreshToken / accessToken).
//
// How it works (verified against the live service):
//   * A ksk_ key authenticates generation/control operations directly against
//     Kiro's own gateways using the same wire protocol the IDE already speaks:
//       - runtime.{region}.kiro.dev    (KRS: generateAssistantResponse, ...)
//       - management.{region}.kiro.dev (CPS: List-Available-Models, usage, ...)
//   * Auth is a plain Bearer token PLUS a `tokentype: API_KEY` header, and the
//     request body must NOT carry a profileArn (that belongs to the IDE's own
//     OAuth login and 403s a ksk_ key). The header `x-amzn-kiro-agent-mode`
//     must be present.
//   * Those API-key-compatible operations use a thin reverse proxy: swap the
//     credential, strip profileArn, and forward. Profile-bound operations such
//     as Remote Tools `/mcp` keep the IDE's official bearer auth and body.
//
// Integration with the built-in chat is done exactly like the IDE expects:
// we point `codewhisperer.config.krsEndpoints` / `cpsEndpoints` at two local
// proxy servers, so kiro-agent transparently talks to us instead of AWS.
// ---------------------------------------------------------------------------

const vscode = require("vscode");
const http = require("http");
const https = require("https");
const path = require("path");
const fsMod = require("fs");
const childProcess = require("child_process");
const crypto = require("crypto");
const { URL } = require("url");

// ---------------------------------------------------------------------------
// 上游连接池
//
// 每建一条新连接要付一次完整握手：本机→Clash→节点服务器→目标站，三段的 TCP 与
// TLS 合计 4–6 个 RTT。实测约 1.4s，而复用一条已有连接只要 0.30s —— 一次请求
// 差 1.1 秒，这是整条链路上最大的一笔开销。
//
// Node 的 https.globalAgent 虽然 keepAlive 默认开着，但空闲 socket 只留 5 秒
// （实测：间隔 4s 复用 0.31s，间隔 6s 弹回 1.61s）。一轮对话内 Kiro 连发的几个
// 请求能吃到复用，但跨轮次（用户读回复、打字）几乎必然超过 5 秒，握手就回来了。
// 所以自己管一个池子，把空闲保留拉到 30 秒。
//
// 前提：Kiro 必须设置
//     "http.proxySupport": "off"
//     "http.experimental.systemCertificatesV2": true
// 否则 @vscode/proxy-agent 会把这里传的 agent 整个换掉，而它换上去的那个
// PacProxyAgent 的 keepAlive 是被显式注释掉的（见 vscode#228872），白搭。
const UPSTREAM_AGENT = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 32,
  maxFreeSockets: 8,
  scheduling: "lifo", // 优先复用最近用过的，命中率高于 fifo
  timeout: 310000,    // 与单请求超时对齐，别让 agent 先掐断长生成
  family: 4,          // 坏掉的 IPv6 会在 TLS 握手完成前把连接掐掉
});

// 复用的代价：空闲 socket 可能被上游先关掉，重发时报 ECONNRESET。
// 插件原有的 isTransportFailure 已把 econnreset 列入传输层失败，退避重发这条
// 通路正好接住，所以这里不需要额外容错。
// 中转站模式的协议翻译层。它不 require("vscode")，所有配置/日志/统计都由这边在
// activate 时通过 relay.init() 注入。
const relay = require("./relay.js");

const CONFIG_NS = "kiroGateway";
const HEALTH_PATH = "/__kiro_key_health";
const HEALTH_MARKER = "kiro-key-ok";
const REPO_URL = "https://github.com/Tes-bo/kiro-gateway";
// Current extension version, read from the shipped package.json (extension.js
// sits next to it both in dev and inside the packaged VSIX).
function currentVersion() {
  try { return String(require("./package.json").version || "0.0.0"); } catch { return "0.0.0"; }
}
function cleanVersion(value) {
  return String(value || "").trim().replace(/^v/i, "");
}
// Kiro's product version is NOT vscode.version: e.g. Kiro 0.12.333 is built
// on editor 1.107.1. On macOS the product version lives in the app bundle's
// Info.plist. Other platforms first use Kiro-specific product metadata, then
// the executable's ProductVersion on Windows.
function kiroProductVersion(product) {
  const metadata = [
    product.kiroVersion,
    product.productVersion,
    product.applicationVersion,
    product.releaseVersion,
  ].map(cleanVersion).find(Boolean);
  if (metadata) return metadata;

  if (process.platform === "darwin") {
    const infoFile = path.resolve(vscode.env.appRoot || "", "..", "..", "Info.plist");
    try {
      const xml = fsMod.readFileSync(infoFile, "utf8");
      const match = xml.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/i);
      if (match && cleanVersion(match[1])) return cleanVersion(match[1]);
    } catch {}
    try {
      return cleanVersion(childProcess.execFileSync(
        "/usr/bin/plutil",
        ["-extract", "CFBundleShortVersionString", "raw", "-o", "-", infoFile],
        { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] }
      ));
    } catch {}
  }

  if (process.platform === "win32") {
    try {
      const exe = String(process.execPath || "").replace(/'/g, "''");
      return cleanVersion(childProcess.execFileSync(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", `(Get-Item -LiteralPath '${exe}').VersionInfo.ProductVersion`],
        { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] }
      ));
    } catch {}
  }

  // Some distributions expose their product version directly in product.json.
  // Only accept it when it differs from the underlying editor version, so an
  // editor build such as 1.107.1 is never mislabeled as the Kiro release.
  const generic = cleanVersion(product.version);
  return generic && generic !== cleanVersion(vscode.version) ? generic : "unknown";
}
// Report both version layers plus installed Kiro/CodeWhisperer core extensions.
function kiroHostInfo() {
  let product = {};
  try {
    const productFile = path.join(vscode.env.appRoot || "", "product.json");
    product = JSON.parse(fsMod.readFileSync(productFile, "utf8"));
  } catch {}
  const ownId = String(extContext?.extension?.id || "").toLowerCase();
  const core = [];
  try {
    for (const ext of vscode.extensions.all || []) {
      const p = ext.packageJSON || {};
      const text = [ext.id, p.name, p.displayName, p.publisher].join(" ").toLowerCase();
      const id = String(ext.id || "").toLowerCase();
      if (id === ownId || id.includes("kiro-gateway")) continue;
      if (/kiro|codewhisperer/.test(text)) core.push(ext.id + "@" + String(p.version || "unknown"));
    }
  } catch {}
  return {
    appName: String(vscode.env.appName || product.nameLong || product.nameShort || "Kiro"),
    productVersion: kiroProductVersion(product),
    editorVersion: cleanVersion(vscode.version) || "unknown",
    commit: String(product.commit || product.buildNumber || "unknown"),
    platform: process.platform + "/" + process.arch,
    coreExtensions: core.length ? core.join(", ") : "not-detected",
    pluginVersion: currentVersion(),
  };
}
function logKiroHostInfo() {
  const info = kiroHostInfo();
  log("Kiro version: app=" + info.appName
    + " productVersion=" + info.productVersion
    + " editorVersion=" + info.editorVersion
    + " commit=" + info.commit
    + " platform=" + info.platform
    + " coreExtensions=" + info.coreExtensions
    + " plugin=" + info.pluginVersion);
}
const HOP_BY_HOP = ["connection", "keep-alive", "transfer-encoding", "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade"];

// A ksk_ key is rejected upstream with "Access denied. Please check your
// authentication." whenever the request body carries a profileArn (that field
// belongs to the IDE's OAuth login). Depending on the Kiro build a generation
// request is addressed either REST-style (operation in the URL path) or
// awsJson-style (POST "/" with the operation in the x-amz-target header), so
// gating the strip on the URL alone misses awsJson clients. We instead scrub
// profileArn from ANY JSON body below, which covers both.

// Recursively remove any `profileArn` field from a parsed JSON body. Kiro
// versions have placed it at the top level and, in some builds, nested inside
// the request envelope, so we scrub it everywhere to be safe. Returns true if
// anything was removed.
function scrubProfileArn(node) {
  if (!node || typeof node !== "object") return false;
  let changed = false;
  if (Array.isArray(node)) {
    for (const item of node) if (scrubProfileArn(item)) changed = true;
    return changed;
  }
  if (Object.prototype.hasOwnProperty.call(node, "profileArn")) {
    delete node.profileArn;
    changed = true;
  }
  for (const k of Object.keys(node)) if (scrubProfileArn(node[k])) changed = true;
  return changed;
}

// Strip profileArn from a JSON request body before an operation is sent with a
// ksk_ key. Official-only paths such as `/mcp` are diverted before this helper
// is called. Non-JSON bodies are forwarded untouched.
function stripProfileArnFromBody(bodyBuf) {
  if (!bodyBuf || !bodyBuf.length) return bodyBuf;
  let j;
  try {
    j = JSON.parse(bodyBuf.toString("utf8"));
  } catch {
    return bodyBuf; // not JSON: forward untouched
  }
  if (scrubProfileArn(j)) {
    return Buffer.from(JSON.stringify(j), "utf8");
  }
  return bodyBuf;
}

// Strip profileArn from the QUERY STRING as well.
//
// stripProfileArnFromBody 只能覆盖有请求体的操作。控制面上有一批 REST GET 操作
// （GetUsageLimits / ListAvailableModels 这类）把 profileArn 序列化成查询参数，
// GET 没有 body，那道清理直接空过，profileArn 就跟着 ksk_ 凭证一起发上去了。
// 上游看到「API key 凭证 + OAuth 身份的 profileArn」这种不可能的组合，回
// HTTP 403 {"message":"Invalid token"}。
//
// 症状：Kiro 自带的账户面板显示「Unable to fetch account usage data: Invalid
// token」。实测同一个 URL 去掉这个参数就是 200 + 正常用量数据。
// 所以查询串按同一条规则处理：只要出现 profileArn 就摘掉，其余参数原样保留、
// 顺序不动 —— 转发依然是「除凭证与 profileArn 外一个字节不改」。
function stripProfileArnFromUrl(rawUrl) {
  const url = String(rawUrl || "");
  const q = url.indexOf("?");
  if (q < 0) return url;
  const pathPart = url.slice(0, q);
  // 大小写不敏感地找：不同 SDK 版本的参数名大小写不保证一致。
  const kept = [];
  let removed = false;
  for (const pair of url.slice(q + 1).split("&")) {
    if (!pair) continue;
    const name = pair.split("=")[0];
    if (decodeURIComponent(name).toLowerCase() === "profilearn") { removed = true; continue; }
    kept.push(pair);
  }
  if (!removed) return url; // 没有就原样返回，绝不重新编码
  return kept.length ? pathPart + "?" + kept.join("&") : pathPart;
}

// The upstream authorizes generation requests only when the User-Agent carries
// a KiroIDE signature. kiro-agent sends this naturally; we inject a valid one
// as a fallback so the gateway also works if a client omits it.
const KIRO_VERSION = "0.9.2";
const KIRO_SYSTEM = "darwin#24.6.0";
const KIRO_NODE = "22.21.1";

let extContext = null;
let krsServer = null;
let cpsServer = null;
let statusBarItem = null;
let panelProvider = null;
let output = null;
let _machineId = null;

// ---------------------------------------------------------------------------
// Config accessors
// ---------------------------------------------------------------------------
function cfg() {
  return vscode.workspace.getConfiguration(CONFIG_NS);
}
function get(key, def) {
  return cfg().get(key, def);
}
async function set(key, value) {
  await cfg().update(key, value, vscode.ConfigurationTarget.Global);
  // 远程经常同时开好几个窗口，只有占着端口的那个真正转发。
  // 配置写到另一边的窗口不一定能读到，所以选中项的编号再落一份本机文件。
  // 文件里只有编号，不放 refresh token。
  if (key === "activeApiKey") {
    try { writeSharedActiveId(value); } catch (e) {
      log("!! 记录选中项失败: " + (e && e.message ? e.message : e));
    }
  }
}
function isEnabled() {
  return get("enabled", false);
}
function getApiKeys() {
  const arr = get("apiKeys", []) || [];
  const list = Array.isArray(arr) ? arr.map((s) => String(s || "").trim()).filter(Boolean) : [];
  // de-dupe, preserve order
  return [...new Set(list)];
}
function getActiveApiKey() {
  const list = getApiKeys();
  const configured = String(get("activeApiKey", "") || "").trim();
  let sharedId = "";
  try { sharedId = readSharedActiveId(); } catch { sharedId = ""; }
  if (sharedId && list.includes(sharedId) && sharedId !== configured) {
    if (thisProcessHasCred(sharedId)) {
      if (_loggedSharedId !== sharedId) {
        _loggedSharedId = sharedId;
        log("[auth] 改用另一窗口选中的 " + maskKey(sharedId));
      }
      return sharedId;
    }
    if (_loggedMissingSharedId !== sharedId) {
      _loggedMissingSharedId = sharedId;
      log("[auth] 另一窗口选了 " + maskKey(sharedId) + "，本窗口没有这把号的凭证，继续用当前号");
    }
  }
  const a = configured;
  if (a && list.includes(a)) return a;
  return list[0] || "";
}
function getApiKey() {
  // The selected/active key is the default (control-plane calls, status, etc.).
  return getActiveApiKey();
}
async function setApiKeys(list) {
  const clean = [...new Set((Array.isArray(list) ? list : []).map((s) => String(s || "").trim()).filter(Boolean))];
  await set("apiKeys", clean);
  // Deleted keys must not keep their per-key usage counters around.
  pruneKeyStats(clean);
  // 顺手记下新密钥的添加时间、清掉已删除密钥的那条（面板要显示「添加于」）。
  await syncKeyAddedAt(clean);
  await pruneJsonCreds(clean);
  return clean;
}
// 密钥的添加时间。按指纹存在 globalState 里（不落明文），密钥列表本身是配置里的
// 一个字符串数组，带不了这类元数据。
function keyAddedAll() {
  const m = pref("keyAddedAt", {});
  return m && typeof m === "object" ? m : {};
}
function keyAddedAt(key) {
  const fp = keyFingerprint(key);
  if (!fp) return 0;
  return Number(keyAddedAll()[fp]) || 0;
}
// 给还没有时间戳的密钥补上"现在"，并丢掉已经不存在的密钥。第一次升级到这个版本
// 时，老密钥拿不到真正的添加时刻，只能以看到它的那一刻为准。
async function syncKeyAddedAt(keys) {
  const list = Array.isArray(keys) ? keys : getApiKeys();
  const now = Date.now();
  const prev = keyAddedAll();
  const next = {};
  let changed = false;
  for (const k of list) {
    const fp = keyFingerprint(k);
    if (!fp) continue;
    const at = Number(prev[fp]) || 0;
    next[fp] = at || now;
    if (!at) changed = true;
  }
  if (!changed && Object.keys(next).length === Object.keys(prev).length) return;
  await setPref("keyAddedAt", next);
}
// One-time migration: move legacy single apiKey into the apiKeys array.
async function migrateLegacyKey() {
  const legacy = String(get("apiKey", "") || "").trim();
  if (!legacy) return;
  const list = getApiKeys();
  if (!list.includes(legacy)) await setApiKeys([legacy, ...list]);
  await set("apiKey", "");
}
const DEFAULT_REGION = "us-east-1";
// 自动识别地区的候选。Kiro 目前只在弗吉尼亚（us-east-1）和法兰克福
const REGION_CANDIDATES = ["us-east-1", "eu-central-1"];
// 自动识别的结果按密钥缓存这么久，过期后下一次会重新探一遍（订阅迁移到别的区域
// 时不至于一直用旧结果）。
const REGION_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
function configuredRegion() {
  const r = String(get("region", DEFAULT_REGION) || DEFAULT_REGION).trim();
  return r || DEFAULT_REGION;
}
// JSON 凭证的归属区域。profileArn 里的区域是账号注册地，比「用量接口回了 200」
// 可靠：Get-Usage-Limits 在另一个区域也可能 200，但 List-Available-Models 会给空列表。
function jsonHomeRegion(key) {
  if (!isJsonKey(key)) return "";
  const cred = getJsonCred(key);
  if (!cred) return "";
  return regionFromProfileArn(cred.profileArn) || String(cred.region || "").trim();
}
// 用量探测的缓存。和 profileArn 矛盾时作废，否则会把 BuilderId 这类号钉死在
// 一个「用量能查、模型列表为空」的区域上。
function trustedCachedRegion(key) {
  const cached = cachedRegionFor(key);
  if (!cached) return "";
  const home = jsonHomeRegion(key);
  if (home && cached !== home) return "";
  return cached;
}
function preferredRegionFor(key) {
  if (!isRegionAuto() || !key) return "";
  const cached = trustedCachedRegion(key);
  if (cached) return cached;
  return jsonHomeRegion(key);
}
function getRegion() {
  if (isRegionAuto()) {
    const preferred = preferredRegionFor(getActiveApiKey());
    if (preferred) return preferred;
  }
  return configuredRegion();
}
// 「地区」是否交给自动识别。默认开启：绝大多数用户并不知道自己的密钥属于哪个
// 区域，让插件拿密钥去两个候选端点各问一次即可，比让人猜更可靠。
function isRegionAuto() {
  return pref("regionAuto", true) === true;
}
async function setRegionAutoPref(v) {
  await setPref("regionAuto", !!v);
}
// 参与探测的地区：内置候选 + 当前配置值（可能是用户填的自定义地区）。
function regionCandidates() {
  return [...new Set([...REGION_CANDIDATES, getRegion()]
    .map((r) => String(r || "").trim())
    .filter(Boolean))];
}
// 识别结果按密钥指纹（sha256 前 16 位）缓存，不落密钥明文。
function regionCacheAll() {
  const m = pref("regionByKey", {});
  return m && typeof m === "object" ? m : {};
}
function cachedRegionFor(key) {
  const fp = keyFingerprint(key);
  if (!fp) return "";
  const e = regionCacheAll()[fp];
  if (!e || !e.region) return "";
  if (Date.now() - Number(e.at || 0) > REGION_CACHE_TTL_MS) return "";
  return String(e.region);
}
async function rememberRegionFor(key, region) {
  const fp = keyFingerprint(key);
  if (!fp || !region) return;
  const m = { ...regionCacheAll() };
  m[fp] = { region: String(region), at: Date.now() };
  // 只保留当前还存在的密钥，删掉的密钥不留痕。
  const alive = new Set(getApiKeys().map(keyFingerprint).filter(Boolean));
  for (const k of Object.keys(m)) if (!alive.has(k)) delete m[k];
  await setPref("regionByKey", m);
}
function forgetRegionCache() {
  return setPref("regionByKey", {});
}
function getPorts() {
  const p = get("ports", {}) || {};
  return { krs: Number(p.krs) || 19820, cps: Number(p.cps) || 19821 };
}
// ---------------------------------------------------------------------------
// 工作模式：official（APIKEY 直连）/ relay（中转站）
const MODE_OFFICIAL = "official";
const MODE_RELAY = "relay";
const MODE_LABEL = { official: "APIKEY 直连", relay: "中转站" };

function getMode() {
  return get("mode", MODE_OFFICIAL) === MODE_RELAY ? MODE_RELAY : MODE_OFFICIAL;
}
function isRelayMode() {
  return getMode() === MODE_RELAY;
}
function modeLabel() {
  return MODE_LABEL[getMode()] || getMode();
}
async function setMode(mode) {
  const next = mode === MODE_RELAY ? MODE_RELAY : MODE_OFFICIAL;
  if (next === getMode()) return next;
  await set("mode", next);
  return next;
}
function getRelayPorts() {
  const p = get("relayPorts", {}) || {};
  return { krs: Number(p.krs) || 19830, cps: Number(p.cps) || 19831 };
}
// 当前模式实际使用的端口。端点重定向、健康检查、服务器绑定都以它为准。
function activePorts() {
  return isRelayMode() ? getRelayPorts() : getPorts();
}
// 中转站模式的全部配置，打包成一个对象交给 relay.js（它不认识 vscode 的配置 API）。
function relayPrefs() {
  return {
    baseUrl: get("relayBaseUrl", ""),
    apiKey: get("relayApiKey", ""),
    maxTokens: get("relayMaxTokens", 32000),
    thinking: get("relayThinking", "auto"),
    thinkingBudget: get("relayThinkingBudget", 8192),
    effortMode: get("relayEffortMode", "auto"),
    effortBudgets: get("relayEffortBudgets", {}),
    defaultModel: get("relayDefaultModel", ""),
    modelMapping: get("relayModelMapping", {}),
    interceptIntentClassifier: get("relayInterceptIntentClassifier", true),
    promptCaching: get("relayPromptCaching", "auto"),
  };
}
// 当前模式的凭证齐了没有。官方直连要有 ksk_ 密钥，中转站要有地址 + Key；缺了就
// 不去接管端点，免得 Kiro 的对话框变成一潭死水。
function credentialsReady() {
  return isRelayMode() ? relay.relayConfigured() : !!getApiKey();
}

// ---------------------------------------------------------------------------
// JSON 凭证（OAuth refreshToken / accessToken）
//
// 面板里可以粘贴 kiro-auth-token.json 或同类 JSON。存盘时 apiKeys 只留一个稳定
// 的 json_<指纹> 占位，真正的 token 放在 globalState，刷新时身份不会跟着变。
// Social / Desktop 走 prod.{region}.auth.desktop.kiro.dev/refreshToken；
// 带 clientId+clientSecret 的走 AWS SSO OIDC。
// ---------------------------------------------------------------------------
const JSON_KEY_PREFIX = "json_";
const JSON_REFRESH_SKEW_MS = 5 * 60 * 1000;
const _jsonRefreshInflight = new Map();
const _authMemo = new Map();

function isJsonKey(key) {
  return String(key || "").startsWith(JSON_KEY_PREFIX);
}
function jsonCredsAll() {
  const m = extContext && extContext.globalState.get("kiroGateway.jsonCreds");
  return m && typeof m === "object" ? m : {};
}
async function setJsonCredsAll(m) {
  if (extContext) await extContext.globalState.update("kiroGateway.jsonCreds", m);
}
function getJsonCred(id) {
  const c = jsonCredsAll()[String(id || "")];
  return c && typeof c === "object" ? c : null;
}
// 多窗口时，选中项写到本机文件，占端口的窗口每次转发前读编号。
// 只有本进程已经存着这把号的凭证才跟着换；没有就保持原号，不去刷新，也不判死。
let _loggedSharedId = "";
let _loggedMissingSharedId = "";
function sharedActiveIdPath() {
  return path.join(require("os").homedir(), ".kiro-gateway", "active-key-id");
}
function readSharedActiveId() {
  try {
    return String(fsMod.readFileSync(sharedActiveIdPath(), "utf8") || "").trim().split(/\s/)[0] || "";
  } catch {
    return "";
  }
}
function writeSharedActiveId(id) {
  const key = String(id || "").trim();
  const file = sharedActiveIdPath();
  const dir = path.dirname(file);
  fsMod.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = file + ".tmp";
  fsMod.writeFileSync(tmp, key + "\n", { mode: 0o600 });
  fsMod.renameSync(tmp, file);
  try { fsMod.chmodSync(file, 0o600); } catch {}
}
function thisProcessHasCred(key) {
  if (!key) return false;
  if (!isJsonKey(key)) return true;
  const cred = getJsonCred(key);
  return !!(cred && cred.refreshToken);
}
function pickCredField(obj, names) {
  for (const n of names) {
    if (obj && obj[n] != null && String(obj[n]).trim()) return String(obj[n]).trim();
  }
  return "";
}
function regionFromProfileArn(arn) {
  const m = String(arn || "").match(/arn:aws:codewhisperer:([a-z0-9-]+):/i);
  return m ? m[1] : "";
}
function parseExpiresAt(v) {
  if (v == null || v === "") return 0;
  if (typeof v === "number" && Number.isFinite(v)) {
    return v < 1e12 ? Date.now() + v * 1000 : v;
  }
  const n = Number(v);
  if (Number.isFinite(n) && n > 0) return n < 1e12 ? Date.now() + n * 1000 : n;
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? t : 0;
}
function jsonCredIdFrom(cred) {
  const seed = [cred.refreshToken || "", cred.clientId || ""].join("|");
  return JSON_KEY_PREFIX + crypto.createHash("sha256").update(seed).digest("hex").slice(0, 16);
}
function normalizeJsonCred(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  const refreshToken = pickCredField(obj, ["refreshToken", "refresh_token", "RefreshToken"]);
  if (!refreshToken) return null;
  const accessToken = pickCredField(obj, ["accessToken", "access_token", "AccessToken"]);
  const profileArn = pickCredField(obj, ["profileArn", "profile_arn", "ProfileArn"]);
  const clientId = pickCredField(obj, ["clientId", "client_id"]);
  const clientSecret = pickCredField(obj, ["clientSecret", "client_secret"]);
  const authMethodRaw = pickCredField(obj, ["authMethod", "auth_method", "authType"]);
  const provider = pickCredField(obj, ["provider", "Provider"]);
  const region = pickCredField(obj, ["region", "idcRegion", "idc_region", "ssoRegion", "sso_region"])
    || regionFromProfileArn(profileArn);
  const isIdc = !!(clientId && clientSecret) || /idc|sso|oidc/i.test(authMethodRaw);
  return {
    refreshToken,
    accessToken,
    profileArn,
    clientId,
    clientSecret,
    authMethod: isIdc ? "idc" : (authMethodRaw || "social"),
    provider: provider || (isIdc ? "IdC" : "Social"),
    region: region || "",
    expiresAt: parseExpiresAt(obj.expiresAt || obj.expires_at || obj.expiresIn || obj.expires_in),
  };
}
function pickUsageSnapshot(obj) {
  if (!obj || typeof obj !== "object") return null;
  const u = obj.usage && typeof obj.usage === "object" && !Array.isArray(obj.usage) ? obj.usage : null;
  const s = obj.subscription && typeof obj.subscription === "object" && !Array.isArray(obj.subscription) ? obj.subscription : null;
  const num = (node, names) => {
    if (!node) return null;
    for (const n of names) {
      const v = node[n];
      if (typeof v === "number" && Number.isFinite(v)) return v;
      if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
    }
    return null;
  };
  const used = num(u, ["current", "currentUsage", "used", "baseCurrent", "usedCredits"]);
  const total = num(u, ["limit", "usageLimit", "total", "baseLimit", "totalCredits"]);
  const title = String((s && (s.title || s.subscriptionTitle || s.type)) || obj.subscriptionTitle || "").trim();
  let resetAt = 0;
  const rawReset = u && (u.nextResetDate || u.nextDateReset || u.resetAt || u.resetDate);
  if (rawReset != null && rawReset !== "") {
    const t = typeof rawReset === "number"
      ? (rawReset < 1e12 ? rawReset * 1000 : rawReset)
      : Date.parse(String(rawReset));
    if (Number.isFinite(t) && t > 0) resetAt = t;
  }
  if (used == null && total == null && !title) return null;
  return { used, total, subscriptionTitle: title, resetAt };
}
function extractJsonCreds(value) {
  const out = [];
  const seen = new Set();
  const visit = (node) => {
    if (Array.isArray(node)) { node.forEach(visit); return; }
    if (!node || typeof node !== "object") return;
    // 账号导出包常见形态：accounts[].credentials 是对象而不是数组。
    // 先把外壳字段和内层 credentials 合成一份再认，refreshToken 在哪一层都能吃到。
    const merged = (node.credentials && typeof node.credentials === "object" && !Array.isArray(node.credentials))
      ? { ...node, ...node.credentials }
      : node;
    const one = normalizeJsonCred(merged);
    if (one) {
      const snap = pickUsageSnapshot(merged);
      if (snap) one.importedUsage = snap;
      const id = one.refreshToken + "|" + (one.clientId || "");
      if (!seen.has(id)) { seen.add(id); out.push(one); }
      return;
    }
    for (const v of Object.values(node)) {
      if (v && typeof v === "object") visit(v);
    }
  };
  visit(value);
  return out;
}
function extractApiKeysFromJson(value) {
  const keys = [];
  const walk = (v) => {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (!v || typeof v !== "object") return;
    const k = v.apiKey || v.api_key || v.key;
    if (typeof k === "string" && k.trim().startsWith("ksk_")) keys.push(k.trim());
  };
  walk(value);
  return keys;
}
function tryParseJsonValue(text) {
  const t = String(text || "").trim();
  if (!t) return undefined;
  try { return JSON.parse(t); } catch {}
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    try { return JSON.parse(fence[1].trim()); } catch {}
  }
  return undefined;
}
async function upsertJsonCred(id, cred, opts = {}) {
  const all = { ...jsonCredsAll() };
  const prev = all[id] && typeof all[id] === "object" ? all[id] : {};
  all[id] = {
    ...prev,
    ...cred,
    id,
    accessToken: cred.accessToken || prev.accessToken || "",
    refreshToken: cred.refreshToken || prev.refreshToken || "",
    profileArn: cred.profileArn || prev.profileArn || "",
    clientId: cred.clientId || prev.clientId || "",
    clientSecret: cred.clientSecret || prev.clientSecret || "",
    authMethod: cred.authMethod || prev.authMethod || "social",
    provider: cred.provider || prev.provider || "Social",
    region: cred.region || prev.region || "",
    expiresAt: cred.expiresAt || prev.expiresAt || 0,
    importedUsage: cred.importedUsage || prev.importedUsage || null,
  };
  await setJsonCredsAll(all);
  if (!opts.keepMemo) _authMemo.delete(id);
  return all[id];
}
async function pruneJsonCreds(keys) {
  const alive = new Set((Array.isArray(keys) ? keys : []).filter(isJsonKey));
  const all = jsonCredsAll();
  let changed = false;
  const next = {};
  for (const [id, cred] of Object.entries(all)) {
    if (alive.has(id)) next[id] = cred;
    else changed = true;
  }
  if (changed) await setJsonCredsAll(next);
}
function displayJsonKey(key) {
  const cred = getJsonCred(key);
  const tag = (cred && (cred.provider || cred.authMethod)) || "JSON";
  const tail = String(key || "").slice(-4);
  return "JSON·" + tag + "·" + tail;
}
// 面板按 keys[].full 缓存账户用量。JSON 凭证的 full 是展示名，不是 json_ 内部 id，
// 同步结果必须用同一把钥匙，否则套餐/积分对不上行。
function panelFullKey(key) {
  return isJsonKey(key) ? displayJsonKey(key) : String(key || "");
}
function exportableJsonCred(id) {
  const c = getJsonCred(id);
  if (!c) return null;
  const out = {
    accessToken: c.accessToken || "",
    refreshToken: c.refreshToken || "",
    expiresAt: c.expiresAt ? new Date(c.expiresAt).toISOString() : "",
    authMethod: c.authMethod || "social",
    provider: c.provider || "",
  };
  if (c.profileArn) out.profileArn = c.profileArn;
  if (c.region) out.region = c.region;
  if (c.clientId) out.clientId = c.clientId;
  if (c.clientSecret) out.clientSecret = c.clientSecret;
  return out;
}
function exportKeyText(key) {
  if (isJsonKey(key)) {
    const obj = exportableJsonCred(key);
    return obj ? JSON.stringify(obj, null, 2) : String(key);
  }
  return String(key || "");
}
function tokenTypeForCred(cred) {
  if (!cred) return "";
  if (cred.authMethod === "idc" || (cred.clientId && cred.clientSecret)) return "SSO_OIDC";
  return "";
}
function authFromCred(cred, id) {
  return {
    type: "oauth",
    key: id,
    token: cred.accessToken || "",
    profileArn: cred.profileArn || "",
    region: cred.region || regionFromProfileArn(cred.profileArn) || "",
    tokenType: tokenTypeForCred(cred),
    expiresAt: Number(cred.expiresAt) || 0,
  };
}
function peekFreshAuth(key) {
  const k = String(key || "");
  if (!k) return null;
  if (!isJsonKey(k)) return { type: "apikey", key: k, token: k, profileArn: "", region: "", expiresAt: 0 };
  const memo = _authMemo.get(k);
  if (memo && memo.token && (!memo.expiresAt || memo.expiresAt - Date.now() > JSON_REFRESH_SKEW_MS)) return memo;
  const cred = getJsonCred(k);
  if (cred && cred.accessToken && cred.expiresAt && cred.expiresAt - Date.now() > JSON_REFRESH_SKEW_MS) {
    const auth = authFromCred(cred, k);
    _authMemo.set(k, auth);
    return auth;
  }
  return null;
}
function httpsExchange(method, urlStr, headers, body, timeoutMs, attempt) {
  const n = attempt || 0;
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(urlStr); } catch (e) { return reject(e); }
    const payload = body == null ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body), "utf8");
    const hdrs = { ...(headers || {}) };
    if (payload) hdrs["content-length"] = String(payload.length);
    const req = https.request(
      {
        method,
        hostname: target.hostname,
        port: 443,
        path: target.pathname + target.search,
        headers: hdrs,
        timeout: timeoutMs || 20000,
        family: 4,
        agent: UPSTREAM_AGENT,
      },
      (res) => {
        const c = [];
        res.on("data", (d) => c.push(d));
        res.on("end", () => resolve({ statusCode: res.statusCode || 0, body: Buffer.concat(c).toString("utf8") }));
      }
    );
    // 只有「TLS 还没建立」才重试。这种失败发生在 HTTP 正文写出之前，
    // refreshToken 没有送到服务器，不会被轮换。超时、断线、已有 HTTP 响应都不重发。
    const fail = (e) => {
      const msg = e && e.message ? e.message : String(e || "");
      if (n < 3 && /before secure tls/i.test(msg)) {
        const free = UPSTREAM_AGENT.freeSockets || {};
        for (const name of Object.keys(free)) {
          for (const sock of free[name] || []) {
            try { sock.destroy(); } catch {}
          }
        }
        setTimeout(() => {
          httpsExchange(method, urlStr, headers, body, timeoutMs, n + 1).then(resolve, reject);
        }, 1000 * (n + 1));
        return;
      }
      reject(e instanceof Error ? e : new Error(msg));
    };
    req.on("error", fail);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    if (payload) req.write(payload);
    req.end();
  });
}
async function refreshSocialCred(cred) {
  const regions = [...new Set([
    cred.region,
    regionFromProfileArn(cred.profileArn),
    getRegion(),
    "us-east-1",
    "eu-central-1",
  ].map((r) => String(r || "").trim()).filter(Boolean))];
  let lastErr = new Error("refresh failed");
  for (const region of regions) {
    const url = "https://prod." + region + ".auth.desktop.kiro.dev/refreshToken";
    try {
      const res = await httpsExchange("POST", url, {
        "content-type": "application/json",
        accept: "application/json",
        "user-agent": kiroUserAgent(),
      }, { refreshToken: cred.refreshToken }, 20000);
      if (res.statusCode < 200 || res.statusCode >= 300) {
        lastErr = new Error("HTTP " + res.statusCode + ": " + String(res.body || "").slice(0, 180));
        continue;
      }
      const data = JSON.parse(res.body || "{}");
      const accessToken = data.accessToken || data.access_token;
      if (!accessToken) {
        lastErr = new Error("refresh 响应没有 accessToken");
        continue;
      }
      return {
        accessToken,
        refreshToken: data.refreshToken || data.refresh_token || cred.refreshToken,
        profileArn: data.profileArn || data.profile_arn || cred.profileArn || "",
        expiresAt: parseExpiresAt(data.expiresAt || data.expires_at || data.expiresIn || data.expires_in || 3600),
        region,
      };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}
async function refreshIdcCred(cred) {
  // Kiro 的 BuilderId / IdC 走 SSO OIDC CreateToken：POST /token，JSON，驼峰字段。
  // application/x-www-form-urlencoded 会被这个接口当成非法请求，回
  // 400 invalid_request（location/reason 为空的那条），刷新令牌本身并没有坏。
  const regions = [...new Set([
    cred.region,
    regionFromProfileArn(cred.profileArn),
    "us-east-1",
  ].map((r) => String(r || "").trim()).filter(Boolean))];
  let lastErr = new Error("refresh failed");
  for (const region of regions) {
    const url = "https://oidc." + region + ".amazonaws.com/token";
    try {
      const res = await httpsExchange("POST", url, {
        "content-type": "application/json",
        accept: "application/json",
        "user-agent": kiroUserAgent(),
      }, {
        clientId: cred.clientId,
        clientSecret: cred.clientSecret,
        grantType: "refresh_token",
        refreshToken: cred.refreshToken,
      }, 20000);
      if (res.statusCode < 200 || res.statusCode >= 300) {
        lastErr = new Error("HTTP " + res.statusCode + ": " + String(res.body || "").slice(0, 180));
        if (res.statusCode === 400 && /invalid_grant/i.test(res.body || "")) break;
        continue;
      }
      const data = JSON.parse(res.body || "{}");
      const accessToken = data.accessToken || data.access_token;
      if (!accessToken) {
        lastErr = new Error("OIDC refresh 响应没有 accessToken");
        continue;
      }
      return {
        accessToken,
        refreshToken: data.refreshToken || data.refresh_token || cred.refreshToken,
        profileArn: cred.profileArn || "",
        expiresAt: parseExpiresAt(data.expiresIn || data.expires_in || data.expiresAt || data.expires_at || 3600),
        region,
      };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}
async function resolveAuth(key) {
  const k = String(key || "").trim();
  if (!k) throw new Error("没有可用凭证");
  if (!isJsonKey(k)) {
    const auth = { type: "apikey", key: k, token: k, profileArn: "", region: "", expiresAt: 0 };
    _authMemo.set(k, auth);
    return auth;
  }
  const fresh = peekFreshAuth(k);
  if (fresh && fresh.token) return attachProfileArn(k, fresh);
  if (_jsonRefreshInflight.has(k)) return _jsonRefreshInflight.get(k);
  const job = (async () => {
    const cred = getJsonCred(k);
    if (!cred || !cred.refreshToken) throw new Error("JSON 凭证不存在或缺少 refreshToken");
    const still = peekFreshAuth(k);
    if (still && still.token) return attachProfileArn(k, still);
    log("[JSON] 刷新凭证 " + displayJsonKey(k) + " method=" + (cred.authMethod || "social"));
    const isIdc = cred.authMethod === "idc" || !!(cred.clientId && cred.clientSecret);
    let next;
    try {
      next = isIdc ? await refreshIdcCred(cred) : await refreshSocialCred(cred);
    } catch (e) {
      // 提前 5 分钟就刷新。这一步失败时，原来的 accessToken 往往还没过期，
      // 不该让用量查询整段报「credential refresh failed」。
      if (cred.accessToken && Number(cred.expiresAt) > Date.now()) {
        log("[JSON] 刷新失败，accessToken 尚未过期，先继续用: " + (e && e.message ? e.message : e));
        const auth = authFromCred(cred, k);
        _authMemo.set(k, auth);
        return attachProfileArn(k, auth);
      }
      throw e;
    }
    const saved = await upsertJsonCred(k, { ...cred, ...next });
    const auth = authFromCred(saved, k);
    _authMemo.set(k, auth);
    log("[JSON] 刷新成功 " + displayJsonKey(k)
      + (auth.profileArn ? " profileArn=有" : " profileArn=无")
      + (auth.region ? " region=" + auth.region : ""));
    return attachProfileArn(k, auth);
  })().finally(() => _jsonRefreshInflight.delete(k));
  _jsonRefreshInflight.set(k, job);
  return job;
}
function findProfileArnDeep(node, depth = 0) {
  if (node == null || depth > 8) return "";
  if (typeof node === "string") {
    return /arn:aws:codewhisperer:[a-z0-9-]+:\d+:profile\//i.test(node) ? node : "";
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      const hit = findProfileArnDeep(item, depth + 1);
      if (hit) return hit;
    }
    return "";
  }
  if (typeof node !== "object") return "";
  if (typeof node.profileArn === "string" && node.profileArn.trim()) return node.profileArn.trim();
  for (const v of Object.values(node)) {
    const hit = findProfileArnDeep(v, depth + 1);
    if (hit) return hit;
  }
  return "";
}
async function lookupProfileArn(auth) {
  if (!auth || auth.type === "apikey" || auth.profileArn) return (auth && auth.profileArn) || "";
  const region = auth.region || getRegion();
  const paths = [
    "/List-Available-Profiles?origin=AI_EDITOR",
    "/Get-Profile?origin=AI_EDITOR",
  ];
  for (const p of paths) {
    try {
      const res = await apiGetWithAuth(managementBaseFor(region), p, auth, { timeoutMs: 8000 });
      if (res.statusCode < 200 || res.statusCode >= 300) continue;
      let data;
      try { data = JSON.parse(res.body || "{}"); } catch { continue; }
      const arn = findProfileArnDeep(data);
      if (arn) return arn;
    } catch {}
  }
  return "";
}
async function attachProfileArn(id, auth) {
  if (!auth || auth.type !== "oauth" || auth.profileArn) return auth;
  const cred = getJsonCred(id) || {};
  if (cred.profileLookupTried) return auth;
  const arn = await lookupProfileArn(auth);
  const saved = await upsertJsonCred(id, {
    ...cred,
    profileArn: arn || cred.profileArn || "",
    region: regionFromProfileArn(arn) || cred.region || auth.region || "",
    profileLookupTried: true,
  }, { keepMemo: true });
  if (!arn) return auth;
  const next = authFromCred(saved, id);
  _authMemo.set(id, next);
  log("[JSON] 补到 profileArn " + displayJsonKey(id));
  return next;
}
function applyProfileArnToBody(bodyBuf, profileArn) {
  if (!profileArn || !bodyBuf || !bodyBuf.length) return bodyBuf;
  let j;
  try { j = JSON.parse(bodyBuf.toString("utf8")); } catch { return bodyBuf; }
  if (!j || typeof j !== "object") return bodyBuf;
  const setDeep = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) { node.forEach(setDeep); return; }
    if (Object.prototype.hasOwnProperty.call(node, "profileArn")) node.profileArn = profileArn;
    for (const key of Object.keys(node)) setDeep(node[key]);
  };
  setDeep(j);
  j.profileArn = profileArn;
  return Buffer.from(JSON.stringify(j), "utf8");
}
// addIfMissing=false 时只改写已经存在的那个 profileArn，不会凭空补一个。转发
// Kiro 自己发出的请求时要的就是这个：它把 profileArn 放在哪儿，我们就只换哪儿的
// 值，别的位置一律保持原样。
function applyProfileArnToUrl(rawUrl, profileArn, addIfMissing = true) {
  if (!profileArn) return rawUrl;
  const url = String(rawUrl || "");
  const q = url.indexOf("?");
  const pathPart = q < 0 ? url : url.slice(0, q);
  const pairs = q < 0 ? [] : url.slice(q + 1).split("&").filter(Boolean);
  let found = false;
  const next = pairs.map((pair) => {
    const name = pair.split("=")[0];
    if (decodeURIComponent(name).toLowerCase() === "profilearn") {
      found = true;
      return name + "=" + encodeURIComponent(profileArn);
    }
    return pair;
  });
  if (!found) {
    if (!addIfMissing) return url;
    next.push("profileArn=" + encodeURIComponent(profileArn));
  }
  return next.length ? pathPart + "?" + next.join("&") : pathPart;
}
function prepareOutbound(auth, bodyBuf, rawUrl) {
  const body = Buffer.isBuffer(bodyBuf) ? bodyBuf : Buffer.from(bodyBuf || "");
  if (!auth || auth.type === "apikey") {
    return { body: stripProfileArnFromBody(body), url: stripProfileArnFromUrl(rawUrl) };
  }
  const nextBody = applyProfileArnToBody(body, auth.profileArn);
  // profileArn 只该有一个落点。生成请求（POST awsJson）官方是放在 body 里的，
  // body 已经带上之后再往查询串补一份，就成了官方从不发送的多余参数 —— 转发的
  // 字节必须跟 Kiro 原本要发的一致，所以这时查询串只改写、不新增。没有 body 的
  // REST GET 反过来只能靠查询串带。
  const bodyCarriesArn = nextBody !== body;
  return {
    body: nextBody,
    url: applyProfileArnToUrl(rawUrl, auth.profileArn, !bodyCarriesArn),
  };
}
async function ingestRawCredentials(raws) {
  const incoming = Array.isArray(raws) ? raws : [raws];
  const existing = new Set(getApiKeys());
  const added = [];
  let invalid = 0, dup = 0;
  const considerText = async (text) => {
    const t = String(text || "").trim();
    if (!t) return;
    if (t.startsWith("ksk_")) {
      if (existing.has(t)) { dup++; return; }
      existing.add(t);
      added.push(t);
      return;
    }
    const parsed = tryParseJsonValue(t);
    if (parsed === undefined) { invalid++; return; }
    const jsonCreds = extractJsonCreds(parsed);
    const apiKeys = extractApiKeysFromJson(parsed);
    if (!jsonCreds.length && !apiKeys.length) { invalid++; return; }
    for (const k of apiKeys) {
      if (existing.has(k)) { dup++; continue; }
      existing.add(k);
      added.push(k);
    }
    for (const c of jsonCreds) {
      const id = jsonCredIdFrom(c);
      if (existing.has(id)) { dup++; continue; }
      await upsertJsonCred(id, c);
      existing.add(id);
      added.push(id);
    }
  };
  if (incoming.length === 1) {
    await considerText(incoming[0]);
  } else {
    const joined = incoming.map((s) => String(s || "")).join("\n");
    const parsed = tryParseJsonValue(joined);
    if (parsed !== undefined && (extractJsonCreds(parsed).length || extractApiKeysFromJson(parsed).length)) {
      await considerText(joined);
    } else {
      for (const item of incoming) await considerText(item);
    }
  }
  return { added, invalid, dup };
}
function defaultJsonImportDir() {
  const home = require("os").homedir();
  const cache = path.join(home, ".aws", "sso", "cache");
  try { if (fsMod.existsSync(cache)) return cache; } catch {}
  return home;
}
async function importJsonCredentialFiles() {
  const uris = await vscode.window.showOpenDialog({
    title: "导入 JSON 凭证文件",
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: true,
    defaultUri: vscode.Uri.file(defaultJsonImportDir()),
    filters: {
      "JSON 凭证": ["json"],
      "文本文件": ["txt", "jsonl"],
      "所有文件": ["*"],
    },
    openLabel: "导入",
  });
  if (!uris || !uris.length) return { cancelled: true };
  const texts = [];
  const failed = [];
  for (const uri of uris) {
    try {
      const buf = await vscode.workspace.fs.readFile(uri);
      let text = Buffer.from(buf).toString("utf8");
      if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
      if (!String(text || "").trim()) {
        failed.push(path.basename(uri.fsPath) + " 是空文件");
        continue;
      }
      texts.push(text);
    } catch (e) {
      failed.push(path.basename(uri.fsPath) + ": " + (e && e.message ? e.message : e));
    }
  }
  if (!texts.length) {
    return { cancelled: false, ingested: { added: [], invalid: uris.length, dup: 0 }, failed, message: "没能读到任何文件内容" };
  }
  const ingested = await ingestRawCredentials(texts);
  return { cancelled: false, ingested, failed, files: uris.length };
}
async function applyIngestedCredentials(ingested, failed) {
  const toAdd = (ingested && ingested.added) || [];
  if (!toAdd.length) {
    const message = ingested && ingested.dup
      ? "这些 JSON 凭证已经在列表里了"
      : "文件里没有可识别的凭证（需要 refreshToken 或 ksk_）";
    if (panelProvider) panelProvider.post({ type: "error", message });
    else vscode.window.showWarningMessage("Kiro Gateway: " + message);
    return { ok: false, added: 0 };
  }
  const list = getApiKeys();
  const startIndex = list.length;
  await setApiKeys([...list, ...toAdd]);
  forgetKeyHealth(toAdd);
  await applyState();
  maybeAdoptUsableKey();
  await ensureRegionDetected({ silent: true });
  if (panelProvider) panelProvider.pushState();
  const skipped = (ingested.invalid || 0) + (ingested.dup || 0);
  const extra = failed && failed.length ? "；" + failed.length + " 个文件读失败" : "";
  const message = skipped > 0
    ? `已从文件导入 ${toAdd.length} 个凭证，忽略 ${skipped} 个（无效或重复）` + extra
    : `已从文件导入 ${toAdd.length} 个凭证` + extra;
  if (panelProvider) panelProvider.post({ type: "toast", message });
  else vscode.window.showInformationMessage("Kiro Gateway: " + message);
  if (panelProvider && getAutoRefresh()) {
    await panelProvider.syncAccounts(toAdd.map((_, k) => startIndex + k), { retries: 3, retryDelayMs: 1500 });
  }
  return { ok: true, added: toAdd.length };
}

// UI-only preferences live in globalState (not workspace config), so they work
// without registering configuration keys and never hit "config not registered".
function getHideApiKey() {
  const v = extContext && extContext.globalState.get("kiroGateway.hideApiKey");
  return v !== false; // default true
}
async function setHideApiKeyPref(v) {
  if (extContext) await extContext.globalState.update("kiroGateway.hideApiKey", !!v);
}
function getAutoRefresh() {
  if (!extContext) return true;
  const v = extContext.globalState.get("kiroGateway.autoRefresh");
  // Default to enabled when the preference has never been set.
  return v === undefined ? true : v === true;
}
async function setAutoRefreshPref(v) {
  if (extContext) await extContext.globalState.update("kiroGateway.autoRefresh", !!v);
}
// Generic globalState-backed panel preference (same rationale as the two
// above: no configuration schema entry needed).
function pref(name, def) {
  if (!extContext) return def;
  const v = extContext.globalState.get("kiroGateway." + name);
  return v === undefined ? def : v;
}
async function setPref(name, value) {
  if (extContext) await extContext.globalState.update("kiroGateway." + name, value);
}
// Fixed text injected before / after the user's message on every chat turn.
function getPromptPrefs() {
  return {
    prefixEnabled: pref("prefixEnabled", false) === true,
    prefixText: String(pref("prefixText", "") || ""),
    suffixEnabled: pref("suffixEnabled", false) === true,
    suffixText: String(pref("suffixText", "") || ""),
  };
}
const DEFAULT_RETRY_RULES = [
  { enabled: true, match: "Too many", reply: "" },
  { enabled: true, match: "Access denied", reply: "" },
];
const RETRY_MAX_CAP = 50;
const RETRY_REPLY_MAX = 500;
function normalizeRetryRules(raw) {
  if (!Array.isArray(raw)) return DEFAULT_RETRY_RULES.map((r) => ({ ...r }));
  return raw
    .filter((r) => r && typeof r === "object")
    .map((r) => ({
      enabled: r.enabled !== false,
      match: String(r.match || "").trim(),
      reply: String(r.reply || "").trim().slice(0, RETRY_REPLY_MAX),
    }))
    .filter((r) => r.match)
    .slice(0, 50);
}
function getRetryPrefs() {
  const max = Math.round(Number(pref("retryMax", 2)));
  const delay = Math.round(Number(pref("retryDelayMs", 2000)));
  return {
    enabled: pref("retryEnabled", false) === true,
    rules: normalizeRetryRules(pref("retryRules", undefined)),
    max: Number.isFinite(max) ? Math.min(Math.max(max, 1), RETRY_MAX_CAP) : 2,
    delayMs: Number.isFinite(delay) ? Math.min(Math.max(delay, 0), 60000) : 2000,
  };
}
// 无感自动切换密钥。
const SWITCH_DEFAULT_COOLDOWN_MS = 5 * 60 * 1000;
function getSwitchPrefs() {
  const cd = Math.round(Number(pref("switchCooldownMs", SWITCH_DEFAULT_COOLDOWN_MS)));
  return {
    enabled: pref("autoSwitch", true) !== false,
    cooldownMs: Number.isFinite(cd) ? Math.min(Math.max(cd, 0), 24 * 60 * 60 * 1000) : SWITCH_DEFAULT_COOLDOWN_MS,
    // 均衡路由
    loadBalance: pref("loadBalance", true) !== false,
  };
}
function runtimeBaseFor(region) {
  return "https://runtime." + (String(region || "").trim() || DEFAULT_REGION) + ".kiro.dev";
}
function managementBaseFor(region) {
  return "https://management." + (String(region || "").trim() || DEFAULT_REGION) + ".kiro.dev";
}
function runtimeBase() {
  return runtimeBaseFor(getRegion());
}
function managementBase() {
  return managementBaseFor(getRegion());
}

// ---------------------------------------------------------------------------
// 生成平面端点表
const GEN_ENDPOINTS = [
  { id: "q", label: "AmazonQ", base: (r) => "https://q." + r + ".amazonaws.com" },
  { id: "krs", label: "KiroKRS", base: (r) => runtimeBaseFor(r) },
];
// 注意：不要给转发的请求补 x-amz-target。
function genEndpointById(id) {
  return GEN_ENDPOINTS.find((e) => e.id === id) || GEN_ENDPOINTS[0];
}
// IDE 原生的生成平面。非生成类操作一律只走它。
function krsOnlyChain() {
  return [genEndpointById("krs")];
}
// 默认首选 krs。
function getPreferredEndpointId() {
  const v = String(get("preferredEndpoint", "krs") || "krs").toLowerCase();
  return GEN_ENDPOINTS.some((e) => e.id === v) ? v : "krs";
}
function getEndpointFallback() {
  return get("endpointFallback", true) !== false;
}
// 端点冷却默认 5 秒。
function getEndpointCooldownMs() {
  const v = Math.round(Number(get("endpointCooldownMs", 5000)));
  return Number.isFinite(v) ? Math.min(Math.max(v, 0), 30 * 60 * 1000) : 5000;
}
// 端点链允许走几轮，轮次之间退避多久。
function getEndpointRoundPrefs() {
  const rounds = Math.round(Number(get("endpointRounds", 2)));
  const delay = Math.round(Number(get("endpointRoundDelayMs", 1500)));
  return {
    rounds: Number.isFinite(rounds) ? Math.min(Math.max(rounds, 1), 5) : 2,
    delayMs: Number.isFinite(delay) ? Math.min(Math.max(delay, 0), 30000) : 1500,
  };
}
// 限流耐心模式。
function getThrottlePatience() {
  const cap = Math.round(Number(get("throttleBackoffCapMs", 30000)));
  return {
    forever: get("throttleRetryForever", true) !== false,
    capMs: Number.isFinite(cap) ? Math.min(Math.max(cap, 1000), 300000) : 30000,
  };
}
// 指数退避的下一步等待时间：翻倍但不超过 cap。cur=0 时取 base。
function nextBackoffMs(cur, base, cap) {
  const next = cur > 0 ? cur * 2 : Math.max(base, 1);
  return Math.min(next, cap);
}
// 这次失败是不是"端点级限流"。
function isThrottleFailure(status, text) {
  if (status === 429) return true;
  // 传输层错误没有状态码；2xx 里也可能藏着限流错误帧（HTTP 200 + ThrottlingException）。
  if (!status || (status >= 200 && status < 300)) return THROTTLE_RE.test(String(text || ""));
  return false;
}
// 这次失败是不是"这个端点不认这个操作"（端点能力缺失，跟限流是两件事）。
const UNSUPPORTED_OP_RE = /unknownoperation|operation is not recognized/i;
function isUnsupportedOperationFailure(status, text) {
  // 只测文本、不卡状态码：上游有时先回 200 再在事件流里发错误帧。调用点传进来的
  return UNSUPPORTED_OP_RE.test(String(text || ""));
}
// 这次失败是不是"上游临时故障"（可重试的 5xx）。
const TRANSIENT_SERVER_RE = /internalserver|internalfailure|serviceunavailable|badgateway|gatewaytimeout|502 bad gateway|503 service/i;
// 传输层故障：请求根本没到达上游，或者连接在中途断了。
const TRANSPORT_FAILURE_RE = new RegExp([
  "socket disconnected",            // TLS 握手前被掐（代理抖动的典型表现）
  "before secure tls",
  "econnreset", "econnrefused", "econnaborted",
  "epipe", "etimedout", "ehostunreach", "enetunreach", "enetreset",
  "eai_again",                      // DNS 临时失败
  "socket hang up",
  "upstream timeout",               // 我们自己在 on("timeout") 里造的
  "request timeout",
  "tunneling socket could not be established", // 代理隧道建立失败
].join("|"), "i");
function isTransportFailure(text) {
  return TRANSPORT_FAILURE_RE.test(String(text || ""));
}
function isTransientServerFailure(status, text) {
  const s = Number(status) || 0;
  // 明确的 5xx 状态码即可判定，不必看正文。
  if (s >= 500 && s < 600) return true;
  // 传输层故障没有状态码，只能靠错误文本认。
  if (isTransportFailure(text)) return true;
  // 上游有时先回 200 再在事件流里发错误帧，这时只能靠正文特征。
  return TRANSIENT_SERVER_RE.test(String(text || ""));
}
function getServerErrorRetryPrefs() {
  const max = Math.round(Number(get("serverErrorRetryMax", 5)));
  return {
    enabled: get("serverErrorRetry", true) !== false,
    max: Number.isFinite(max) ? Math.min(Math.max(max, 1), 20) : 5,
  };
}

// 已知的端点能力缺失。键是「端点 + 区域 + 操作」，因为同一端点在不同区能力不同。
// 只放内存：重载窗口后重新探测，万一上游哪天补上了这个操作也能自动恢复。
const _endpointUnsupported = new Set();
function unsupportedKey(id, region, op) {
  return String(id) + "|" + String(region || "") + "|" + String(op || "").toLowerCase();
}
function markEndpointUnsupported(id, region, op) {
  _endpointUnsupported.add(unsupportedKey(id, region, op));
}
function isEndpointUnsupported(id, region, op) {
  return _endpointUnsupported.has(unsupportedKey(id, region, op));
}
function unsupportedSnapshot() {
  return [..._endpointUnsupported];
}
function resetEndpointUnsupported() {
  _endpointUnsupported.clear();
}
// 把已知不认这个操作的端点从链里剔掉，省掉一次注定失败的往返。
// 绝不返回空链：全被剔掉时退回原链 —— 发出去拿到错误，也好过根本不发。
function filterUnsupportedEndpoints(chain, region, op) {
  const keep = chain.filter((e) => !isEndpointUnsupported(e.id, region, op));
  return keep.length > 0 ? keep : chain;
}
// 端点回退的下一步决策。抽成纯函数是为了可测 —— 调度逻辑本身在闭包里，状态多，
// 靠端到端复现代价太高。
//   { action: "switch", index }              本轮还有没试过的端点，立刻换
//   { action: "round", nextRound, delayMs }  本轮全撞上，退避后重走一轮
//   { action: "giveup" }                     轮次用尽，交回调用方
// skipIds：本次请求里已经探明"不支持当前操作"的端点，一律跳过。
//
// 能力缺失表是在请求开始时用来过滤 epChain 的，但请求进行中才探明的缺失只写进了
// 表，epChain 已经定型。而"换轮"会清空 triedEndpoints，于是同一个请求里，已知不认
// 这个操作的端点会被反复重选，每次都是注定的 400，纯浪费往返，限流场景下还在给
// 速率桶添乱。所以换轮时也要落在"可用"的端点上，round 分支一并返回 index。
function planEndpointFallback(chain, triedIds, round, prefs, skipIds) {
  const skip = skipIds || new Set();
  const usable = [];
  for (let i = 0; i < chain.length; i++) {
    if (!skip.has(chain[i].id)) usable.push(i);
  }
  // 链里每个端点都不支持这个操作：换端点这条路已经走不通了，别再空转。
  if (usable.length === 0) return { action: "giveup" };
  for (const i of usable) {
    if (!triedIds.has(chain[i].id)) return { action: "switch", index: i };
  }
  if (round >= prefs.rounds) return { action: "giveup" };
  return { action: "round", nextRound: round + 1, delayMs: prefs.delayMs, index: usable[0] };
}
// 端点冷却：某个端点刚因 429 失败过，后续请求直接从下一个端点起步，别再撞它。
// 只放内存，重载窗口后重新探测。
const _endpointCooldown = new Map(); // id -> untilMs
function endpointCoolDown(id) {
  const ms = getEndpointCooldownMs();
  if (ms > 0) _endpointCooldown.set(id, Date.now() + ms);
}
function endpointCooldownLeft(id) {
  const until = _endpointCooldown.get(id);
  if (!until) return 0;
  const left = until - Date.now();
  if (left <= 0) { _endpointCooldown.delete(id); return 0; }
  return left;
}
function endpointClearCooldown(id) {
  _endpointCooldown.delete(id);
}
// 本次请求要走的端点顺序：首选在前，其余按表序补齐。关掉回退时只留首选。
function genEndpointChain() {
  const preferred = getPreferredEndpointId();
  const head = GEN_ENDPOINTS.filter((e) => e.id === preferred);
  if (!getEndpointFallback()) return head;
  return [...head, ...GEN_ENDPOINTS.filter((e) => e.id !== preferred)];
}
// 起步端点下标：跳过还在冷却里的，全都在冷却就仍从 0 起（总比不发好）。
function pickStartEndpointIndex(chain) {
  for (let i = 0; i < chain.length; i++) {
    if (endpointCooldownLeft(chain[i].id) === 0) return i;
  }
  return 0;
}
function endpointStatusSnapshot() {
  const out = {};
  for (const e of GEN_ENDPOINTS) {
    out[e.id] = { label: e.label, cooldownLeftMs: endpointCooldownLeft(e.id) };
  }
  return out;
}
// 把当前生效的端点链打进日志，方便确认"现在到底走哪个端点"。
function logEndpointChain() {
  const chain = genEndpointChain();
  const region = getRegion();
  const rp = getEndpointRoundPrefs();
  log("生成端点链: " + chain.map((e, i) => (i + 1) + ") " + e.label + " " + e.base(region)).join("  |  ")
    + "  · 回退=" + (getEndpointFallback() ? "开" : "关")
    + " · 最多 " + rp.rounds + " 轮 / 轮间退避 " + rp.delayMs + "ms"
    + " · 端点冷却=" + Math.round(getEndpointCooldownMs() / 1000) + "s");
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
// In-memory ring buffer so the control panel can show recent logs in a drawer
// without the user hunting for the "Kiro Gateway" output channel. We keep
// only the last hour (and hard-cap the count) so it never grows unbounded.
const LOG_RETENTION_MS = 60 * 60 * 1000; // keep the last hour
const LOG_MAX_ENTRIES = 5000;            // hard cap regardless of time window
const _logBuffer = [];                   // [{ t: epochMs, line: string }]
function pruneLogs() {
  const cutoff = Date.now() - LOG_RETENTION_MS;
  while (_logBuffer.length && _logBuffer[0].t < cutoff) _logBuffer.shift();
  if (_logBuffer.length > LOG_MAX_ENTRIES) _logBuffer.splice(0, _logBuffer.length - LOG_MAX_ENTRIES);
}
function getRecentLogs() {
  pruneLogs();
  return _logBuffer.map((e) => e.line);
}
function log(...args) {
  const msg = args
    .map((a) => (typeof a === "string" ? a : a instanceof Error ? a.message : (() => { try { return JSON.stringify(a); } catch { return String(a); } })()))
    .join(" ");
  const t = Date.now();
  const d = new Date(t);
  const p = (n) => String(n).padStart(2, "0");
  const line = "[" + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()) + "] " + msg;
  if (!output) output = vscode.window.createOutputChannel("Kiro Gateway");
  output.appendLine(line);
  _logBuffer.push({ t, line });
  pruneLogs();
}

// One-time, prominent marker the first time kiro-agent actually reaches each
// local proxy plane. Both logs a user sent looked "healthy" (ports bound,
// endpoints written) yet contained ZERO proxy traffic — meaning kiro-agent was
// never routed through us. This marker makes "链路真的打通了" unmistakable in
// the log, so "没走代理" vs "走了但上游报错" is obvious at a glance.
let _proxyHit = { KRS: false, CPS: false };
function resetProxyHitMarkers() { _proxyHit = { KRS: false, CPS: false }; }
function markProxyHit(label, req) {
  if (_proxyHit[label]) return;
  _proxyHit[label] = true;
  const op = String((req && req.url) || "").split("?")[0];
  log("========== [" + label + "] 首次收到 kiro-agent 代理请求 → 链路已打通 (" + (req && req.method) + " " + op + ") ==========");
}

// ---------------------------------------------------------------------------
// Usage statistics
// ---------------------------------------------------------------------------
// Counters for traffic that really went through the local generation proxy
// (KRS). Control-plane polls (model list / usage limits) are deliberately NOT
// counted: kiro-agent fires those on a timer and they cost no credits.
//
// Every counter updates LIVE, as it happens — nothing waits for the call to
// finish:
//   requests : incremented the moment a generation request is accepted.
//   errors   : 只记「最终交回给 Kiro 的失败」。一次上游失败如果被自动切号
//              （换下一把 key 重发）或自动重试接住了，Kiro 看到的仍是成功的
//              回答，那次失败就不计入错误数 —— 否则无感切号会把错误数刷高，
//              看起来像出了问题。没号可换的 429、上游 5xx、网络错误这些真的
//              退回给 Kiro 的失败才计数。
//   credits  : added as soon as the upstream answers 2xx, using the model's
//              rateMultiplier (the same number Kiro bills with) learned from
//              the control plane's model list.
//   tokens   : ESTIMATE that grows with every relayed chunk (~4 chars per
//              token). The upstream never reports token usage, so the UI labels
//              this value as an estimate.
//   inflight : generation calls currently open (live only, never persisted).
//
// Persisted in globalState (debounced) so the panel keeps its numbers across
// window reloads.
const STATS_STATE_KEY = "kiroGateway.stats";
const KEY_STATS_STATE_KEY = "kiroGateway.keyStats";
const MODEL_RATES_STATE_KEY = "kiroGateway.modelRates";
const STATS_FLUSH_MS = 3000;   // debounce for globalState writes
const STATS_PUSH_MS = 250;     // throttle for the streaming byte counter
const CHARS_PER_TOKEN = 4;     // rough tokenizer ratio for the estimate

// 统计只统计"今天"：day 记录这批计数属于哪一天（本地日期），跨天后自动归零。
let _stats = { requests: 0, errors: 0, tokens: 0, credits: 0, since: 0, day: "" };
let _statsInflight = 0; // open generation calls right now
// Per-key breakdown ("个人消耗" in the panel): the same live counters, but
// attributed to the key that actually served the request. Stored under a short
// fingerprint of the key instead of the key itself, so globalState never holds
// another plaintext copy of the secret.
let _keyStats = {}; // fingerprint -> { requests, errors, tokens, credits, since }
const _keyFpCache = new Map(); // key -> fingerprint (hashing runs per chunk)
let _modelRates = {}; // modelId -> credit rate multiplier
let _statsFlushTimer = null;
let _statsPushTimer = null;

function posNum(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
function keyFingerprint(key) {
  const k = String(key || "").trim();
  if (!k) return "";
  let fp = _keyFpCache.get(k);
  if (!fp) {
    fp = crypto.createHash("sha256").update(k).digest("hex").slice(0, 16);
    _keyFpCache.set(k, fp);
  }
  return fp;
}
function emptyKeyStats() {
  return { requests: 0, errors: 0, tokens: 0, credits: 0, since: 0 };
}
// The mutable counter bucket for a key, created on first use.
function keyBucket(key) {
  const fp = keyFingerprint(key);
  if (!fp) return null;
  let b = _keyStats[fp];
  if (!b) {
    b = emptyKeyStats();
    b.since = Date.now();
    _keyStats[fp] = b;
  }
  return b;
}
// Drop buckets whose key no longer exists, so deleted keys stop taking up
// space (and a re-added key starts from zero).
function pruneKeyStats(keys) {
  const alive = new Set((Array.isArray(keys) ? keys : []).map(keyFingerprint).filter(Boolean));
  let changed = false;
  for (const fp of Object.keys(_keyStats)) {
    if (!alive.has(fp)) { delete _keyStats[fp]; changed = true; }
  }
  if (changed) flushStatsSoon();
}
// 本地日期键，用来判断"是不是还在同一天"。
function todayKey(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
}
// 今天 0 点的时间戳，作为当日统计的起点。
function startOfToday() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}
// 跨天就把总计数和每把密钥的计数一起归零。所有读取与写入统计的入口都会先调用
// 它，因此无论是有流量、面板来拉取，还是定时器到点，都能保证看到的是当天数据。
// 这里只改数据、不推送，避免和 pushStats 相互递归。
function ensureToday() {
  const today = todayKey();
  if (_stats.day === today) return false;
  _stats = { requests: 0, errors: 0, tokens: 0, credits: 0, since: startOfToday(), day: today };
  _keyStats = {};
  if (_statsFlushTimer) { clearTimeout(_statsFlushTimer); _statsFlushTimer = null; }
  persistStatsNow();
  return true;
}
// 到了本地时间 0 点主动归零一次：没有流量、面板也没拉取时，显示同样会跟着翻页。
let _dayRolloverTimer = null;
function scheduleDailyReset() {
  if (_dayRolloverTimer) clearTimeout(_dayRolloverTimer);
  // 明天 0 点过 2 秒，留一点余量避开边界抖动。
  const delay = Math.max(startOfToday() + 24 * 60 * 60 * 1000 + 2000 - Date.now(), 1000);
  _dayRolloverTimer = setTimeout(() => {
    _dayRolloverTimer = null;
    if (ensureToday()) {
      log("统计已按日自动清零（" + _stats.day + "）");
      pushStatsNow();
    }
    scheduleDailyReset();
  }, delay);
}
function stopDailyReset() {
  if (_dayRolloverTimer) { clearTimeout(_dayRolloverTimer); _dayRolloverTimer = null; }
}
function loadStats() {
  const s = (extContext && extContext.globalState.get(STATS_STATE_KEY)) || null;
  _stats = {
    requests: posNum(s && s.requests),
    errors: posNum(s && s.errors),
    tokens: posNum(s && s.tokens),
    credits: posNum(s && s.credits),
    since: posNum(s && s.since) || startOfToday(),
    // 旧版本存下来的数据没有 day 字段，视为"不是今天"，加载后会被清零。
    day: String((s && s.day) || ""),
  };
  const per = (extContext && extContext.globalState.get(KEY_STATS_STATE_KEY)) || null;
  if (per && typeof per === "object") {
    const clean = {};
    for (const [fp, b] of Object.entries(per)) {
      if (!fp || !b || typeof b !== "object") continue;
      clean[fp] = {
        requests: posNum(b.requests),
        errors: posNum(b.errors),
        tokens: posNum(b.tokens),
        credits: posNum(b.credits),
        since: posNum(b.since),
      };
    }
    _keyStats = clean;
  }
  const rates = (extContext && extContext.globalState.get(MODEL_RATES_STATE_KEY)) || null;
  if (rates && typeof rates === "object") {
    const clean = {};
    for (const [id, r] of Object.entries(rates)) {
      const n = Number(r);
      if (id && Number.isFinite(n) && n >= 0) clean[id] = n;
    }
    _modelRates = clean;
  }
}
function statsSnapshot() {
  ensureToday();
  return {
    requests: Math.round(_stats.requests),
    errors: Math.round(_stats.errors),
    tokens: Math.round(_stats.tokens),
    credits: Math.round(_stats.credits * 100) / 100,
    since: _stats.since,
    inflight: _statsInflight,
  };
}
// Per-key counters for the panel, keyed by the API key string (the webview
// already knows the keys, so it can look its rows up directly). Only the
// currently configured keys are reported.
function keyStatsSnapshot() {
  ensureToday();
  const out = {};
  for (const k of getApiKeys()) {
    const b = _keyStats[keyFingerprint(k)];
    out[k] = b
      ? {
          requests: Math.round(b.requests),
          errors: Math.round(b.errors),
          tokens: Math.round(b.tokens),
          credits: Math.round(b.credits * 100) / 100,
          since: b.since,
        }
      : emptyKeyStats();
  }
  return out;
}
function persistStatsNow() {
  if (!extContext) return;
  try { extContext.globalState.update(STATS_STATE_KEY, _stats); } catch {}
  try { extContext.globalState.update(KEY_STATS_STATE_KEY, _keyStats); } catch {}
}
function flushStatsSoon() {
  if (_statsFlushTimer || !extContext) return;
  _statsFlushTimer = setTimeout(() => {
    _statsFlushTimer = null;
    persistStatsNow();
  }, STATS_FLUSH_MS);
}
// A streaming answer emits many chunks; throttle so the token counter ticks up
// smoothly instead of posting a webview message per chunk.
function pushStatsSoon() {
  if (_statsPushTimer) return;
  _statsPushTimer = setTimeout(() => {
    _statsPushTimer = null;
    if (panelProvider) panelProvider.pushStats();
  }, STATS_PUSH_MS);
}
// Discrete events (request accepted / failed / billed) are pushed immediately.
function pushStatsNow() {
  if (_statsPushTimer) { clearTimeout(_statsPushTimer); _statsPushTimer = null; }
  if (panelProvider) panelProvider.pushStats();
}
// Remember the credit rate of every model the control plane advertises, so a
// request's credit cost is the real billed multiplier instead of a guess.
function rememberModelRates(bodyText) {
  let models;
  try { models = JSON.parse(bodyText).models; } catch { return; }
  if (!Array.isArray(models)) return;
  const next = { ..._modelRates };
  let changed = false;
  for (const m of models) {
    const id = String((m && m.modelId) || "").trim();
    const rate = Number(m && m.rateMultiplier);
    if (!id || !Number.isFinite(rate) || rate < 0) continue;
    if (next[id] !== rate) { next[id] = rate; changed = true; }
  }
  if (!changed) return;
  _modelRates = next;
  if (extContext) { try { extContext.globalState.update(MODEL_RATES_STATE_KEY, next); } catch {} }
}
function creditRateFor(modelId) {
  const r = _modelRates[String(modelId || "").trim()];
  // Unknown model: bill it as a standard 1x agentic request.
  return Number.isFinite(r) ? r : 1;
}
// The operation name, however the client addressed it (REST path vs awsJson
// x-amz-target header).
function operationName(req) {
  const target = String((req.headers && (req.headers["x-amz-target"] || req.headers["x-amzn-target"])) || "");
  const fromTarget = target.split(/[.#]/).pop();
  if (fromTarget) return fromTarget;
  const p = String(req.url || "").split("?")[0].replace(/\/+$/, "");
  return p.split("/").pop() || "/";
}
// Only agentic chat/generation calls consume credits. Inline completions and
// other KRS chatter are counted as requests but cost nothing.
const BILLED_OP_RE = /generateassistantresponse|sendmessage|converse/i;
// 允许在端点之间轮换的操作。
//
// 端点回退只对"两个平面都认的操作"成立。不可轮换的操作被改道过去只会白烧两次
// 往返，最后把一个注定失败的错误交回 Kiro。实测矩阵（见 GEN_ENDPOINTS 上方）里
// GenerateAssistantResponse 是唯一在 q. 和 krs、us-east-1 和 eu-central-1 四个组合
// 上都可用的操作，所以只有它有资格轮换。converse 从未在日志里出现过，也没有实测
// 数据，不放进来 —— 有需要时先测再加。
const ROTATABLE_OP_RE = /generateassistantresponse/i;
// Find the requested modelId anywhere in the (already parsed) request body.
function findModelId(node, depth = 0) {
  if (!node || typeof node !== "object" || depth > 8) return "";
  if (Array.isArray(node)) {
    for (const item of node) {
      const v = findModelId(item, depth + 1);
      if (v) return v;
    }
    return "";
  }
  for (const k of ["modelId", "model"]) {
    const v = node[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  for (const k of Object.keys(node)) {
    const v = findModelId(node[k], depth + 1);
    if (v) return v;
  }
  return "";
}
function modelIdFromBody(bodyBuf) {
  if (!bodyBuf || !bodyBuf.length) return "";
  let j;
  try { j = JSON.parse(bodyBuf.toString("utf8")); } catch { return ""; }
  // Prefer the CURRENT turn's model. A plain depth-first scan hits the first
  // history entry instead and would bill this request at an older model's rate.
  const cur = findCurrentUserInputMessage(j);
  for (const k of ["modelId", "model"]) {
    const v = cur && cur[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return findModelId(j);
}
// --- Live counter updates -------------------------------------------------
// A generation request was accepted and is on its way upstream.
// `key` is the API key that serves the call, so the same event also lands in
// that key's own bucket (个人消耗).
function statsRequestStarted(inBytes, key) {
  ensureToday(); // 跨天的第一笔请求不该累加到昨天的数字上
  const add = posNum(inBytes) / CHARS_PER_TOKEN;
  _stats.requests += 1;
  _stats.tokens += add;
  _statsInflight += 1;
  if (!_stats.since) _stats.since = Date.now();
  const b = keyBucket(key);
  if (b) {
    b.requests += 1;
    b.tokens += add;
    if (!b.since) b.since = Date.now();
  }
  flushStatsSoon();
  pushStatsNow();
}
// Relayed response bytes, chunk by chunk, while the answer streams.
function statsAddOutBytes(n, key) {
  const bytes = posNum(n);
  if (!bytes) return;
  const add = bytes / CHARS_PER_TOKEN;
  _stats.tokens += add;
  const b = keyBucket(key);
  if (b) b.tokens += add;
  flushStatsSoon();
  pushStatsSoon();
}
function statsRequestFailed(key) {
  _stats.errors += 1;
  const b = keyBucket(key);
  if (b) b.errors += 1;
  flushStatsSoon();
  pushStatsNow();
}
// Charged as soon as the upstream accepts the call, not when the stream ends.
function statsAddCredits(op, modelId, key) {
  if (!BILLED_OP_RE.test(String(op || ""))) return;
  const rate = creditRateFor(modelId);
  _stats.credits += rate;
  const b = keyBucket(key);
  if (b) b.credits += rate;
  flushStatsSoon();
  pushStatsNow();
}
function statsRequestFinished() {
  if (_statsInflight > 0) _statsInflight -= 1;
  pushStatsNow();
}
// 手动清零：把当天的计数清空，归属日期仍是今天。
async function resetStats() {
  _stats = { requests: 0, errors: 0, tokens: 0, credits: 0, since: Date.now(), day: todayKey() };
  _keyStats = {};
  if (_statsFlushTimer) { clearTimeout(_statsFlushTimer); _statsFlushTimer = null; }
  if (extContext) {
    try { await extContext.globalState.update(STATS_STATE_KEY, _stats); } catch {}
    try { await extContext.globalState.update(KEY_STATS_STATE_KEY, _keyStats); } catch {}
  }
  pushStatsNow();
}

// ---------------------------------------------------------------------------
// 无感自动切换密钥
// ---------------------------------------------------------------------------
// 只有"这把 key 现在用不了"这类错误才触发切换：限流、鉴权失效、额度用尽。
// 其它错误（网络抖动、上游 5xx）属于自动重试的范畴，不该浪费一把 key。
// 限流文案。throttl 一条就覆盖了 ThrottlingException / throttled / throttling
// 这一串写法；rate exceeded 是上游另一种回法，官方那套探测也认它。
const THROTTLE_RE = /too many requests|throttl|rate ?limit|rate exceeded|slow down/i;
const INVALID_RE = /access denied|unauthorized|invalid.{0,12}(api ?key|token)|token.{0,12}expired|forbidden/i;
const QUOTA_RE = /quota|usage ?limit|limit ?(reached|exceeded)|exhaust|insufficient|out of credit|no credit/i;
// 溢出上限（OVERAGE_EXCEEDED_RE）定义在探活那一节，跟 DEAD_KINDS 放在一起。
// 下面的 keyFailureKind 会用到它 —— 都是运行时调用，取值时它早就初始化好了。
// 账号被上游风控禁用。原文是「Your User ID is temporarily suspended. We detected
// unusual user activity and locked it as a security precaution. To restore
// access, please contact our support team…」这种账号不会自己恢复，必须换号。
//
// 这里只认足够特异的短语。早先把 restore access / security precaution / locked
// 之类各自单列成一条，任何报错正文里偶然出现一句就会把正常账号判成禁用，所以
// 那些弱信号改成"必须成对出现"才算。
const SUSPENDED_RE = /temporarily suspended|(?:user id|account)[^.\n]{0,40}\bsuspended\b/i;
function looksSuspended(text) {
  const t = String(text || "");
  if (SUSPENDED_RE.test(t)) return true;
  // 单独一句都可能出现在别的提示里，两个信号同时出现才下结论。
  return /unusual (?:user )?activity/i.test(t) && /security precaution/i.test(t);
}
// 禁用文案的「早期信号」。
//
// 禁用提示是逐 token 流下来的，开头那几帧往往只够拼出「Your User ID is」这么
// 几个词，真正的判定关键词（temporarily suspended）还在后面。命中这些前缀信号
// 说明"这可能是一段禁用提示"，值得把判定窗口放宽几帧再决定 —— 一旦放行就再也
// 没有透明换号的机会了。正常回答不含这些词，不受影响。
const SUSPENDED_HINT_RE = /your user id|\bsuspend|unusual (?:user )?activity|security precaution/i;
function maybeSuspendedPrefix(text) {
  return SUSPENDED_HINT_RE.test(String(text || ""));
}
// 从流式回答里把正文拼回来。
//
// 上游有时不用错误码，而是拿 HTTP 200 把「账号被禁用」当成一段普通回答流回来
// （Kiro 聊天窗里直接显示那段 temporarily suspended 提示）。这种响应是 AWS 的
// event stream，正文被切成很多小帧逐 token 下发，关键词会跨帧断开，直接拿原始
// 字节去匹配是匹配不到的 —— 所以先把各帧里的文本字段抽出来接成一整段再判断。
function extractStreamText(raw) {
  const text = String(raw || "");
  let out = "";
  const re = /"(?:content|text|message|errorMessage)"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(text)) !== null) out += m[1];
  return out;
}
// 判定账号状态用的证据文本：原始字节 + 从各帧里抽出来接好的正文。
//
// 两者缺一不可 —— 原始字节对付普通 JSON 错误体，拼回来的正文对付被切成小帧、
// 关键词跨帧断开的流式回答。缓冲错误体那条分支如果只传原始字节，分帧的
// 「temporarily suspended」就匹配不到，账号状态永远不被标记，面板一直显示「正常」。
function failureEvidence(raw) {
  const text = String(raw || "");
  return text + "\n" + extractStreamText(text);
}
// 判定前先攒够这么多字节：一帧 event stream 带着帧头和 payload，通常一个 chunk
// 就够判了；万一 TCP 把开头切得很碎，就多等一个 chunk。
const HEAD_MIN_BYTES = 256;
// 攒不够也不能一直等：上游在模型思考期间可能只发很小的心跳帧，超过这个时间就
// 直接放行，最坏情况只给正常回答的首字节加这么点延迟。
const HEAD_WAIT_MS = 300;
// 开头已经出现禁用文案的早期信号时改用这一组更宽的窗口，把关键词等齐。
// 默认的 256 字节 / 300ms 只够收下帧头和头几个 token，禁用文案的
// 「temporarily suspended」通常还没到 —— 窗口一关就直接放行，这把号从此
// 不会被判成已禁用，也就永远不会自动换掉。
const SUSPECT_MIN_BYTES = 4 * 1024;
const SUSPECT_WAIT_MS = 2000;
// 放行之后继续扫描正文的字节上限：攒到这么多还没命中就不再攒，避免长回答一直
// 往内存里堆字符串。
const TAIL_SCAN_CAP = 64 * 1024;
// 流里塞的错误帧。上游有时先回 200，再在 event stream 里发一个异常帧，Kiro 把它
// 显示成「Something went wrong: [InternalServerException] …」。状态码是 200，所以
// 光看状态码的话自动重试和自动切号都够不着这种失败。
//
// 只认未转义的帧结构（":exception-type"、"__type"、"errorMessage"）：回答正文里
// 的引号在 JSON 里是 \" 形态，所以哪怕用户正好在跟 AI 讨论
// InternalServerException，也不会被当成错误帧。
const STREAM_ERROR_RE = /:exception-type|"__type"\s*:\s*"[^"]*(?:Exception|Error|Fault)|"errorMessage"\s*:\s*"/;
// 流内错误帧对应的可匹配文本：没有错误帧就返回空串。
// 返回的内容会交给重试规则和切号判定去匹配，所以要带上异常类型和错误消息。
function streamErrorText(raw) {
  const text = String(raw || "");
  if (!STREAM_ERROR_RE.test(text)) return "";
  const type = exceptionName(text);
  // 错误消息可能在 message / errorMessage 字段里，extractStreamText 会一并抽出。
  const detail = extractStreamText(text);
  const joined = (type + " " + detail).trim();
  return joined || text.slice(0, 500);
}
// 冷却时长按原因区分：限流是暂时的，失效/额度用尽/被禁用要压得更久。
const COOLDOWN_FACTOR = { throttle: 1, denied: 0.4, quota: 6, overage: 12, invalid: 12, suspended: 12 };
const KIND_LABEL = {
  throttle: "被限流",
  denied: "被拒绝(403)",
  upstream: "上游故障",
  quota: "额度用尽",
  overage: "溢出上限用尽",
  invalid: "鉴权失效",
  suspended: "账号被禁用",
};
// 每种原因最终落到哪个账号状态上。被禁用是独立状态，面板单独显示「已禁用」，
// 跟"密钥本身鉴权失效"不是一回事。
// upstream 故意不映射状态：5xx 是上游自己的问题，跟这把号的好坏无关，不能因此
// 给账号扣帽子。
// overage 归到 quota 状态：对用户来说都是「额度用尽」，面板不必分两个词。内部保留
// 独立的 kind 只是为了日志和删除原因能说清是 base 用完还是连 overage 都烧光了。
const KIND_TO_STATE = {
  denied: "denied", quota: "quota", overage: "quota", invalid: "invalid", suspended: "suspended",
};
// 软失败：换号重发值得试（不同号可能落到不同后端），但既不判死账号、也不按用户
// 配置的冷却时长压 —— 那个时长是给"账号有问题"准备的，动辄几分钟，用在上游抖动
// 上会把所有号一次性排除干净。
const SOFT_KINDS = new Set(["upstream"]);
const SOFT_COOLDOWN_MS = 20 * 1000;
// 宿主端日志用的状态中文名。内部仍然细分（冷却时长、切号决策要用到），只是
// 对外呈现时会折叠成三种，见 publicState。
const STATE_LABEL_HOST = {
  ok: "正常",
  denied: "被拒绝",
  quota: "额度用尽",
  invalid: "已失效",
  suspended: "已禁用",
  unknown: "未检测",
};
// 判断上游的失败是否说明"这把 key 该换了"，返回原因或 null。
//
// 顺序上先看状态码这类硬证据，正文关键词只用来给状态码补充细节：光凭正文里
// 出现 forbidden / quota 就换号并把账号判死，太容易冤枉正常账号（上游的 5xx
// 错误页、回显的请求内容里都可能带上这些词）。
function keyFailureKind(status, bodyText) {
  const text = String(bodyText || "");
  // 禁用文案很特异，命中就可以直接认定，不用等状态码。
  if (looksSuspended(text)) return "suspended";
  // 溢出上限同理，而且比状态码可靠：上游是用 HTTP 400 回它的，而 400 在下面会落到
  // 关键词兜底，很容易被读成别的原因。这两个特征串一出现就说明号真废了，先认下来。
  if (OVERAGE_EXCEEDED_RE.test(text)) return "overage";
  if (status === 402) return "quota";
  // 429 要分两种情况，不能一律当限流。
  //
  // 上游额度耗尽时也会回 429，光认状态码就会把"这个月配额用完了"判成"请求发太快
  // 了"—— 前者得换号或者等重置，后者歇几分钟就好，结论正好相反，等错了就是白等。
  // 所以先看正文里有没有额度字样，有就按额度用尽算。官方那套账号探测同样是把额度
  // 判定排在限流前面的。
  if (status === 429) return QUOTA_RE.test(text) ? "quota" : "throttle";
  if (status === 401) return "invalid";
  if (status === 403) {
    // 403 既可能是密钥无效，也可能是额度用尽的另一种回法。
    if (QUOTA_RE.test(text)) return "quota";
    if (INVALID_RE.test(text)) return "invalid";
    // 原因不明的 403 不再当成"跟密钥无关"直接放过去 —— 上游在额度耗尽、风控
    // 限流、区域不匹配时都可能回一个不带任何线索的 403，把它原样交回 Kiro 只会
    // 让这轮对话直接失败。按"这把号暂时用不了"处理：换号重发 + 短冷却，但不判死
    // （denied 不是终态，冷却过去自己就恢复），所以误判的代价只是几分钟不被选中。
    return "denied";
  }
  // 传输层错误（status=0）：网线断了、DNS 挂了，换号也一样不通，只有正文明确
  // 说限流才换。
  if (!status) {
    if (THROTTLE_RE.test(text)) return "throttle";
    return null;
  }
  // 上游 5xx（500 / 502 / 503 / 504）：先看是不是被限流包装成了 5xx，否则按软
  // 失败处理 —— 换一把号重发往往就通了，同时只压 20 秒的短冷却，不改账号状态。
  if (status >= 500) {
    if (THROTTLE_RE.test(text)) return "throttle";
    return "upstream";
  }
  // 2xx 一律不得推出「鉴权失效」。
  //
  // 上游回了 2xx 就说明这次请求的凭证是通过鉴权的 —— 从这种响应里读出"密钥失效"
  // 在逻辑上自相矛盾。而下面那段纯关键词兜底会命中 INVALID_RE 里的 forbidden /
  // unauthorized / access denied，于是 HTTP 200 + 错误帧（或者用户正好在跟 AI
  // 讨论 403）就能把一把健康的密钥判成已失效，而且这是终态、会被冻结、不再探测。
  // 2xx 下只保留两种结论：禁用文案（上面已经判过）和明确的限流。
  if (status >= 200 && status < 300) {
    if (THROTTLE_RE.test(text)) return "throttle";
    return null;
  }
  if (THROTTLE_RE.test(text)) return "throttle";
  if (QUOTA_RE.test(text)) return "quota";
  if (INVALID_RE.test(text)) return "invalid";
  return null;
}
// key -> { until, kind }。只放在内存里：重载窗口后重新探测比记着一份可能过期的
// 黑名单更安全。
const _keyCooldown = new Map();
// 账号健康状态。key -> { state, at }，state 取值：
//   ok        正常，可以用
//   quota     额度用尽（积分已跑满，或上游明确这么说）
//   invalid   已失效（鉴权被拒）
//   suspended 账号被上游禁用
//   unknown   还没探测过，或只是网络问题导致探测失败
// 来源有两处：账户信息同步的结果，以及真实请求的成败。
const _keyHealth = new Map();
// 终态：这三种都是"账号本身有问题"，不会自己好转。一旦判定就冻结下来 ——
// 不再重复探测，也不被后续的网络抖动改写，一直保持到密钥被删除或用户手动重置。
const TERMINAL_STATES = new Set(["invalid", "quota", "suspended"]);
function isTerminalState(state) {
  return TERMINAL_STATES.has(String(state || ""));
}
// 终态的复检窗口：到点之后自动解冻，让这把号重新参与挑号和探测。
//
// 早先终态是"永久"的，结果 quota 变成了一个死锁：额度用尽 → 冻结 → 挑号跳过它、
// 账户同步也跳过它（省一次往返）→ 于是永远拿不到"额度已经恢复"的新数据 → 永远
// 解不了冻。可 Kiro 的额度本来就是按周期重置的，这是个暂时状态，不该判死。
//   quota     3 小时后复检一次。重置周期通常比这更长，多探几次的代价只是一次
//             很轻的 GET，换来的是额度一恢复就能自动接着用。
//   invalid   密钥真被吊销确实不会自己好，但"跨区拒绝、上游鉴权抖动"长得一模
//             一样，留一个 12 小时后复核的机会，避免一次误判就把号永久废掉。
//   suspended 风控锁号要人工申诉，自动复检没有意义，保持永久冻结。
const FREEZE_TTL_MS = { quota: 3 * 60 * 60 * 1000, invalid: 12 * 60 * 60 * 1000 };
// 这个终态什么时候到期。返回 0 表示永久冻结。hint 是调用方给的确切到期时间
// （比如从用量接口解析出的额度重置时间），比默认 TTL 更准就用它。
function freezeExpiresAt(state, hint) {
  const ttl = FREEZE_TTL_MS[state];
  if (!ttl) return 0;
  const at = Number(hint) || 0;
  return at > Date.now() ? at : Date.now() + ttl;
}
// 这把 key 的状态是否还处于冻结中（终态且没到复检时间）。
// 顺手做到期解冻：这个函数在挑号热路径上被反复调用，把解冻放在这里，任何一条
// 用到"这把号能不能用"的路径都会自动获得复检能力，不用各处再判一次。
// opts.silent: 解冻后不要回推面板。给 keyStatusSnapshot / setKeyHealth 用 ——
// 它们本来就在生成快照或紧接着自己会推一次，这里再推一次就成了嵌套调用
// （pushStats → keyStatusSnapshot → keyHealthFrozen → pushStats …）。
function keyHealthFrozen(key, opts = {}) {
  const h = _keyHealth.get(key);
  if (!h || !isTerminalState(h.state)) return false;
  if (!h.until || h.until > Date.now()) return true;
  // 复检窗口到了：清掉旧结论。真的还是坏的，下一次探测或请求会把它重新判回来，
  // 代价只是一次往返。
  _keyHealth.delete(key);
  saveKeyHealthSoon();
  log("账号状态复检: " + maskKey(key) + " 的「" + (STATE_LABEL_HOST[h.state] || h.state)
    + "」判定已到期，恢复参与挑号");
  if (!opts.silent && panelProvider) panelProvider.pushStats();
  return false;
}
// opts.force: 允许改写终态。只有两种情况给 force —— 这把 key 真的跑成功了
// （最硬的证据，用来自我纠正误判），以及用户手动重置状态。
// opts.until: 终态的确切到期时间，没给就按 FREEZE_TTL_MS 算。
function setKeyHealth(key, state, opts = {}) {
  if (!key || !state) return;
  // 先给过期的终态一次解冻机会：否则一把已经过了复检窗口的号会被旧结论挡在
  // 门外，新探测到的结果根本写不进来。这里不用它回推面板，下面自己会推。
  keyHealthFrozen(key, { silent: true });
  const prev = _keyHealth.get(key);
  // 这里只负责记状态，不负责删号。删除统一走探活那一节（runLivenessScan →
  // deleteKeyAutomatic）：那条路径的依据是真发一次请求拿回来的响应，比在这里凭
  // 用量接口的 used >= total 推断可靠得多 —— POWER 这类号 base 用超之后还有
  // overage 余量，照样能跑，用量却已经显示 10508/10000 了，照它删就是丢好号。
  if (prev && isTerminalState(prev.state) && !opts.force) return;
  if (prev && prev.state === state) return;
  const entry = { state, at: Date.now() };
  if (isTerminalState(state)) {
    const until = freezeExpiresAt(state, opts.until);
    if (until) entry.until = until;
  }
  _keyHealth.set(key, entry);
  saveKeyHealthSoon();
  if (panelProvider) panelProvider.pushStats();
}
// 账户同步的结果换算成健康状态。
//
// 这里只在证据够硬的时候才下结论：状态码是主依据，正文关键词只用来区分同一个
// 状态码背后的不同原因。早先的做法是拿错误信息整段去套 /\b(401|403)\b/ 这类
// 正则，正文里随便出现一个 403 数字、一句 forbidden，正常账号就被判成已失效，
// 而且一判就再也不会翻案。
function noteAccountHealth(key, ok, info, err) {
  if (ok) {
    const used = Number(info && info.used);
    const total = Number(info && info.total);
    const exhausted = Number.isFinite(used) && Number.isFinite(total) && total > 0 && used >= total;
    // 用量先存下来：挑号时要靠它把请求优先分给额度富裕的号。
    noteKeyUsage(key, info);
    const prev = _keyHealth.get(key);
    // 唯一不能靠"查得到用量"翻案的是被禁用：账号被风控锁掉往往只挡推理接口，
    // 用量查询照样回 200。要给禁用翻案，得靠这把号真跑通一次请求
    // （clearCooldown），或者用户手动重置状态。
    if (prev && prev.state === "suspended") {
      maybeAdoptUsableKey();
      return;
    }
    // 其余情况下拿到真实账户数据是最可靠的一手信息，允许推翻之前的终态判定
    // （之前误判成已失效的号就是靠这里自己纠正回来的）。
    // 额度用尽时，若用量接口给了确切的重置时间就拿它当复检时间，比默认 TTL 准。
    setKeyHealth(key, exhausted ? "quota" : "ok", { force: true, until: info && info.resetAt });
    maybeAdoptUsableKey();
    return;
  }
  const status = Number(err && err.status) || 0;
  // 正文优先用响应体，退化到 Error.message（里面也带了截断的响应体）。
  const text = String((err && (err.body || err.message)) || err || "");
  // 禁用文案很特异，命中就直接认定。
  if (looksSuspended(text)) { setKeyHealth(key, "suspended"); scheduleDeadDrop(key, "suspended"); }
  // 溢出上限的 reason 常量比状态码可靠，先认它（上游用 400 回它，会落到后面的兜底里
  // 被读成别的原因）。base + overage 都烧光了，跟额度用尽归一个状态。
  else if (OVERAGE_EXCEEDED_RE.test(text)) { setKeyHealth(key, "quota"); scheduleDeadDrop(key, "overage"); }
  // 429 也要先过一遍额度文案：额度耗尽时上游同样回 429，先认状态码会把"配额用完"
  // 判成"发太快了"。跟 keyFailureKind 里的顺序保持一致。
  else if (status === 402 || ((status === 403 || status === 429) && QUOTA_RE.test(text))) {
    setKeyHealth(key, "quota");
    // 402 / 403 是明确拒绝，可以据此清号。429 只标状态不删 —— 它本质是限流，而巡检
    // 是并发打管理端点的，本身最容易撞 429，正文里带一句 quota 不足以断定额度真用完。
    if (status !== 429) scheduleDeadDrop(key, "quota");
  }
  else if (status === 401) setKeyHealth(key, "invalid");
  else if (status === 403) {
    // 403 不一定代表密钥坏了：正文明确说鉴权被拒才判失效。看不出原因就保留原
    // 结论 —— 这个接口不给用说明不了账号状态，把本来判定正常的号降级成「未检测」
    // 只会让人以为出了问题。
    if (INVALID_RE.test(text)) setKeyHealth(key, "invalid");
  }
  // 限流是一个真结论，不是"没查出来"，所以要记下来让面板显示「限流中」；但只记，
  // 不排除 —— 不压 key 冷却、不改账号状态。
  //
  // 早先这里压的是 coolDownKey(key, "throttle")，那会让 keyIsUsable 返回 false，把
  // 一把其实健康的号从挑号里踢出去 5 分钟。而巡检是并发打管理端点的，本身最容易撞
  // 429，一撞就排除的话可能一次性废掉大半号池。项目其余三条路径（端点回退、流内
  // 错误、推理探活）也都刻意不把 429 当账号问题，这里保持一致。
  else if (status === 429) {
    noteKeyThrottled(key);
    return;
  }
  // 上游 5xx、超时、网络错误说明不了账号本身的状态：保留原结论。
  else if (status >= 500 || !status) return;
  else setKeyHealth(key, "unknown");
  maybeAdoptUsableKey();
}
// 当前选中的密钥已经不可用时，主动换一把可用的，不必等下一次请求撞墙才切。
// 账户同步刚给出结论、或用户新增/删除密钥后都会走一次，新加进来的密钥因此能
// 立刻接手。
function maybeAdoptUsableKey() {
  if (!getSwitchPrefs().enabled) return;
  const active = getActiveApiKey();
  if (!active || keyIsUsable(active)) return;
  const next = rankUsableKeys([active])[0];
  if (!next) return;
  const h = _keyHealth.get(active);
  // 状态名（quota / invalid / …）用宿主端那份映射翻译，别再借 KIND_LABEL：两者
  // 只是恰好有几个同名键，加一个新状态就会显示成 undefined。
  log("自动切换密钥: 当前 " + maskKey(active) + " "
    + (STATE_LABEL_HOST[h && h.state] || "不可用") + " → 换用 " + maskKey(next));
  adoptKey(next);
}
// 密钥被删除或重新添加时，清掉它残留的状态。否则删掉再加回同一把 key，会继承
// 之前的"已失效 / 额度用尽 / 已禁用"结论，从此再也不会被自动切号选中。
function forgetKeyHealth(keys) {
  const list = Array.isArray(keys) ? keys : [keys];
  let changed = false;
  for (const k of list) {
    if (!k) continue;
    if (_keyHealth.delete(k)) changed = true;
    if (_keyCooldown.delete(k)) changed = true;
    // 挑号用的那几份缓存一起清掉：密钥都删了还留着用量和探测时间，既没意义也是
    // 一份长不掉的内存。
    _keyUsage.delete(k);
    _keyLastUsedAt.delete(k);
    _keyProbeAt.delete(k);
    _keyThrottledAt.delete(k);
  }
  if (!changed) return;
  saveKeyHealthSoon();
  if (panelProvider) panelProvider.pushStats();
}
// 终态要跨窗口保留，否则重载一次就又从"未检测"开始，已经确认坏掉的号会被重新
// 探测一遍。落盘的是密钥指纹，globalState 里不会多存一份明文密钥。
const KEY_HEALTH_STATE_KEY = "kiroGateway.keyHealth";
let _keyHealthSaveTimer = null;
function saveKeyHealthSoon() {
  if (_keyHealthSaveTimer) return;
  _keyHealthSaveTimer = setTimeout(() => {
    _keyHealthSaveTimer = null;
    saveKeyHealth();
  }, 500);
}
async function saveKeyHealth() {
  if (!extContext) return;
  const out = {};
  for (const [key, h] of _keyHealth) {
    if (!h || !isTerminalState(h.state)) continue;
    // 复检时间一起存：不然重载窗口就等于把复检窗口重新计时，一把快到期的号会
    // 被又冻上一整轮。
    out[keyFingerprint(key)] = { state: h.state, at: h.at || Date.now(), until: h.until || 0 };
  }
  try { await extContext.globalState.update(KEY_HEALTH_STATE_KEY, out); } catch {}
}
// 启动时恢复终态。只认现存密钥的指纹，已删除的条目顺手丢掉。
function loadKeyHealth() {
  if (!extContext) return;
  let saved = null;
  try { saved = extContext.globalState.get(KEY_HEALTH_STATE_KEY); } catch {}
  if (!saved || typeof saved !== "object") return;
  let restored = 0;
  let expired = 0;
  for (const key of getApiKeys()) {
    const e = saved[keyFingerprint(key)];
    if (!e || !isTerminalState(e.state)) continue;
    const state = String(e.state);
    // until 缺失的是旧版本存下来的永久终态。quota / invalid 现在都带复检窗口，
    // 给它们补一个：否则升级前被判死的号永远翻不了案。
    let until = Number(e.until) || 0;
    if (!until) until = freezeExpiresAt(state, 0);
    if (until && until <= Date.now()) { expired++; continue; }
    const entry = { state, at: Number(e.at) || Date.now() };
    if (until) entry.until = until;
    _keyHealth.set(key, entry);
    restored++;
  }
  if (expired) log("已跳过 " + expired + " 个账号的过期终态判定，它们重新参与挑号");
  if (restored) log("已恢复 " + restored + " 个账号的终态（已失效 / 额度用尽 / 已禁用）");
  // 落盘一次，把已删除密钥的残留条目清出去。
  saveKeyHealthSoon();
}
// 用户手动重置：连冷却带健康状态一起清空，所有密钥回到"未检测"，下一次同步或
// 请求重新给结论。终态就是靠这个出口翻案的。
function resetKeyHealth() {
  _keyCooldown.clear();
  _keyHealth.clear();
  // 探测时间也清掉：用户点了重置就是要立刻重新判定，不该被"4 分钟内不重复探测"
  // 的节流挡住。用量数据留着无害，它只影响挑号顺序，下一轮探测会覆盖。
  _keyProbeAt.clear();
  // 限流标记属于状态判定，重置一起清。
  _keyThrottledAt.clear();
  // 「刚删过的坏号」记忆一起清掉。重置的语义就是全部翻案，这个记忆不清的话，用户
  // 想把那把号重新收回来会被号池当成重复号挡掉。
  _deadKeyAt.clear();
  saveKeyHealthSoon();
  // 重置后马上跑一轮巡检，面板上的「未检测」很快就会有结论。
  healthSweepOnce().catch(() => {});
}
// 一把 key 现在能不能用：冷却中不能用，已失效 / 额度用尽 / 已禁用也不能用。
// "未知"仍然算可用 —— 没探测过不等于坏了。
function keyIsUsable(key) {
  if (!key) return false;
  if (cooldownLeft(key)) return false;
  return !keyHealthFrozen(key);
}
// 每把 key 最近一次拿到的用量，挑号时用来优先选剩余额度多的那把。
const _keyUsage = new Map(); // key -> { used, total, at }
// 每把 key 最近一次被真实请求用过的时间，用于同档位内轮转。
const _keyLastUsedAt = new Map();
function noteKeyUsage(key, info) {
  if (!key || !info) return;
  const used = Number(info.used);
  const total = Number(info.total);
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return;
  _keyUsage.set(key, { used, total, at: Date.now() });
}
function noteKeyUsed(key) {
  if (key) _keyLastUsedAt.set(key, Date.now());
}
// 剩余额度比例（0~1）。没有用量数据时返回 null，排序里当"未知"处理。
function keyHeadroom(key) {
  const u = _keyUsage.get(key);
  if (!u) return null;
  return Math.max(0, Math.min(1, (u.total - u.used) / u.total));
}
// 可用密钥按"现在最该用哪把"排序。
//
// 早先所有挑号入口都是 getApiKeys().find(keyIsUsable) —— 永远取列表里第一把可用
// 的。号多的时候这会把负载全压在前几把上：第一把被打满限流 → 切到第二把 → 第二把
// 也满 → 逐个打死，而列表后面那些额度富裕的号一次都没被用到。冷却一结束又立刻
// 回到第一把，循环往复。
//
// 排序规则：
//   1. 状态确认正常的排在"未检测"前面（未检测不等于坏，但正常是确定的）
//   2. 剩余额度多的优先，把负载摊到额度富裕的号上（差距小于 2% 视为同档）
//   3. 都一样就选最久没用过的，天然形成轮转
function rankUsableKeys(exclude) {
  const skip = exclude instanceof Set ? exclude : new Set(exclude || []);
  return getApiKeys()
    .filter((k) => !skip.has(k) && keyIsUsable(k))
    .map((k) => ({
      key: k,
      ok: (_keyHealth.get(k) || {}).state === "ok" ? 0 : 1,
      headroom: keyHeadroom(k),
      last: Number(_keyLastUsedAt.get(k) || 0),
    }))
    .sort((a, b) => {
      if (a.ok !== b.ok) return a.ok - b.ok;
      if (a.headroom != null && b.headroom != null) {
        if (Math.abs(a.headroom - b.headroom) > 0.02) return b.headroom - a.headroom;
      } else if (a.headroom != null) return -1;
      else if (b.headroom != null) return 1;
      return a.last - b.last;
    })
    .map((e) => e.key);
}
// 均衡路由用的额度档位：剩余额度按 25% 一档粗分桶，只有跨档才算「更富裕」。
//
// 为什么不像 rankUsableKeys 那样直接比精确值：_keyUsage 只在账户信息同步时更新，
// 请求打出去消耗掉的额度不会立刻反映回来。按精确值比大小的话，剩 90% 和剩 88% 也
// 算「更富裕」，于是每个请求都挑同一把，要等下一次同步才发现它降下来了 —— 均衡就
// 退化成「一直用额度最多的那把」。分桶把这点噪音抹平，同档内交给「最久没用过」轮转。
// 那个 2% 的判定对 failover 够用（低频、撞墙才走一次），对每请求挑号不够。
//
// 数据太旧的一律当未知（返回 null）：陈旧额度不该主导挑号，宁可退回纯轮转。
const USAGE_FRESH_MS = 10 * 60 * 1000;
const HEADROOM_BUCKET = 0.25;
function keyHeadroomBucket(key) {
  const u = _keyUsage.get(key);
  if (!u || Date.now() - Number(u.at || 0) > USAGE_FRESH_MS) return null;
  const h = Math.max(0, Math.min(1, (u.total - u.used) / u.total));
  return Math.floor(h / HEADROOM_BUCKET);
}
// 均衡路由的号池和顺位。跟 rankUsableKeys 有两处刻意的不同：
//
//   * 只收状态确认正常的号。rankUsableKeys 把「未检测」也算可用，那是给 failover
//     用的 —— 撞墙之后有一把没试过的总比没有好。但常态下的负载分摊不该拉未检测的
//     号进来：它可能本来就是坏的，只是还没被发现，轮到它就白费一次往返。
//     冷却中和已判死的号在 keyIsUsable 那层就已经挡掉了。
//   * 额度按档位比，同档内按「最久没用过」轮转（noteKeyUsed 每次转发都记时间），
//     于是连续请求会在正常号之间自然摊开。
function rankHealthyKeys(exclude) {
  const skip = exclude instanceof Set ? exclude : new Set(exclude || []);
  return getApiKeys()
    .filter((k) => !skip.has(k) && keyIsUsable(k) && (_keyHealth.get(k) || {}).state === "ok")
    .map((k) => ({
      key: k,
      bucket: keyHeadroomBucket(k),
      last: Number(_keyLastUsedAt.get(k) || 0),
    }))
    .sort((a, b) => {
      // 额度档位高的先用；有一方没有新鲜数据就跳过这轮比较，直接看轮转。
      if (a.bucket != null && b.bucket != null && a.bucket !== b.bucket) return b.bucket - a.bucket;
      return a.last - b.last;
    })
    .map((e) => e.key);
}
// 对外呈现四种账号状态：正常 / 限流中 / 额度用尽 / 已禁用。
//
// 剩下那些细分（403 被拒、上游故障、未检测）都是过程态 —— 插件自己换号、自己等
// 冷却就消化掉了，用户不需要跟着操心，一律折叠成"正常"。
// 鉴权失效并进"已禁用"：对用户来说这两种的含义完全一样 —— 这把号不能用了，
// 去换一把或删掉，没必要用两个词表达同一个动作。
//
// 限流单独露出来，是因为它跟另外三种的处置办法都不一样：号没毛病，只是这会儿发得
// 太快，等几分钟自己就好。折进"正常"会让用户看着一切正常却发现请求在换号；折进
// "额度用尽"又会让人以为得去充钱或者换号。
const PUBLIC_STATE = { quota: "quota", suspended: "suspended", invalid: "suspended" };
function publicState(state) {
  return PUBLIC_STATE[String(state || "")] || "ok";
}
// 曾被限流的记录，只为了在面板上显示「限流中」。
//
// 关键在于它不参与挑号。本项目其余三条路径（转发的端点回退、流内错误、推理探活）
// 都刻意不把 429 记成账号状态 —— 限流通常是端点/区域级的并发配额，不是这把号坏了，
// 把它从挑号里排除只会让一把健康的号白闲着。尤其账号巡检是并发打管理端点的，本身
// 就容易撞 429，一排除就可能一次性废掉大半号池，反而没号可用。
// 所以这里只记不排除：keyIsUsable 完全不看它。
// TTL 跟官方那套探测的 passiveStatus 一致 —— 10 分钟内没有新的限流迹象就自动消失。
const THROTTLE_SEEN_TTL_MS = 10 * 60 * 1000;
const _keyThrottledAt = new Map();
function noteKeyThrottled(key) {
  if (!key) return;
  _keyThrottledAt.set(key, Date.now());
  if (panelProvider) panelProvider.pushStats();
}
function clearKeyThrottled(key) {
  if (key) _keyThrottledAt.delete(key);
}
function keyThrottled(key) {
  const at = _keyThrottledAt.get(key);
  if (!at) return false;
  if (Date.now() - at > THROTTLE_SEEN_TTL_MS) { _keyThrottledAt.delete(key); return false; }
  return true;
}
// 面板用：每把 key 的展示状态。
// 只给状态词，不给冷却剩余时间也不给复检时刻 —— 那些是内部节奏，面板不展示。
function keyStatusSnapshot() {
  const out = {};
  for (const key of getApiKeys()) {
    // 先走一次冻结检查，顺带把到期的终态解掉，面板拉一次状态就能看到复检结果。
    // 这里必须静默：本函数就是 pushStats 的数据源，解冻再回推会变成嵌套调用。
    keyHealthFrozen(key, { silent: true });
    const h = _keyHealth.get(key);
    const pub = publicState(h && h.state);
    // 终态优先于限流：一把号既额度用尽又在限流冷却里时，该报的是前者 —— 等限流
    // 过去它照样不能用。
    out[key] = { state: pub !== "ok" ? pub : (keyThrottled(key) ? "throttled" : "ok") };
  }
  return out;
}
function coolDownKey(key, kind) {
  if (!key) return;
  // 账号状态先记，跟冷却时长没关系。
  // 额度用尽、鉴权失效、被禁用都是"这把号本身有问题"，属于终态；限流只是暂时的，
  // 冷却过去还能用，不给它扣坏账号的帽子。
  // 这一步必须在冷却之前做：冷却分钟数可以设成 0，早先的写法在 ms<=0 时直接
  // 返回，于是把状态判定一起跳过了 —— 号明明已经用不了，面板还一直显示正常，
  // 切号也不会跳过它。
  if (KIND_TO_STATE[kind]) setKeyHealth(key, KIND_TO_STATE[kind], { reason: KIND_LABEL[kind] });
  // 转发时撞出来的结论，是上游对着一发真实请求给的答复 —— 额度用尽 / 溢出上限 /
  // 账号被禁用这三类直接把号清出列表，不用等探活（它默认还关着）。
  // 这一行原先被合并错插进了 cooldownLeft，而那里没有 kind 变量，于是每次读冷却
  // 都抛 ReferenceError，把面板的状态推送整条打断。
  scheduleDeadDrop(key, kind);
  const { cooldownMs } = getSwitchPrefs();
  // 软失败（上游 5xx）跟账号本身无关，压一个固定的 20 秒短冷却就够：让同一轮里
  // 的其他号先顶上，很快自己恢复。用用户配置的冷却时长（默认 5 分钟）会在上游
  // 抖一下的时候把所有号一次性排除干净，反而没号可用。
  const ms = SOFT_KINDS.has(kind) ? SOFT_COOLDOWN_MS : cooldownMs * (COOLDOWN_FACTOR[kind] || 1);
  if (ms <= 0) {
    log("[KRS] 密钥 " + maskKey(key) + " " + (KIND_LABEL[kind] || kind) + "（冷却已关闭）");
    return;
  }
  _keyCooldown.set(key, { until: Date.now() + ms, kind });
  log("[KRS] 密钥 " + maskKey(key) + " " + (KIND_LABEL[kind] || kind)
    + "，冷却 " + Math.round(ms / 1000) + "s");
  // 限流现在是面板上看得见的状态了，写完就推一次，别让用户等下一轮 5 秒轮询才
  // 看到「限流中」。冷却结束后的恢复仍然靠轮询，那个延迟无所谓。
  if (panelProvider) panelProvider.pushStats();
}
// 冷却剩余毫秒（0 = 可用）。顺手清掉已过期的条目。
function cooldownLeft(key) {
  const entry = _keyCooldown.get(key);
  if (!entry) return 0;
  const left = entry.until - Date.now();
  if (left <= 0) { _keyCooldown.delete(key); return 0; }
  return left;
}
// 成功用过就说明这把 key 是好的，立刻解除冷却并标回正常。
// 真跑通一次是最硬的证据，所以给 force：万一之前误判成了终态，这里能自己翻案。
function clearCooldown(key) {
  if (_keyCooldown.has(key)) {
    _keyCooldown.delete(key);
    if (panelProvider) panelProvider.pushStats();
  }
  // 跑通了就说明限流已经过去，不用等那 10 分钟 TTL 自己到期。
  clearKeyThrottled(key);
  setKeyHealth(key, "ok", { force: true });
}
// 面板用：当前处于冷却中的密钥。
function cooldownSnapshot() {
  const out = [];
  for (const key of [..._keyCooldown.keys()]) {
    const left = cooldownLeft(key);
    if (left > 0) out.push({ key, leftMs: left, kind: _keyCooldown.get(key).kind });
  }
  return out;
}
// 本次请求要用哪把 key 起步。
//
// 均衡路由关着（或没有一把确认正常的号）时是老行为：优先用户选中的那把，它状态不
// 正常（冷却中、已失效、额度用尽）才顺位换一把。
// 开着时不再粘着选中的那把，每个请求都重新问一遍「现在最该用哪把」——
// rankHealthyKeys 里同档位按「最久没用过」排前面，而每次转发都会 noteKeyUsed，
// 于是连续请求在正常号之间自然轮转，负载摊开而不是全压在第一把上。
function pickStartKey() {
  const active = getActiveApiKey();
  const prefs = getSwitchPrefs();
  if (!prefs.enabled) return active;
  if (prefs.loadBalance) {
    const picked = rankHealthyKeys()[0];
    if (picked) return picked;
    // 一把「确认正常」的都没有（常见于刚加完号、还没同步过账户信息，全是未检测）。
    // 这时候不能干等，落回下面的老逻辑，先把请求发出去再说。
  }
  if (!active || keyIsUsable(active)) return active;
  return rankUsableKeys([active])[0] || active;
}
// 下一把没试过、且状态正常的 key。已失效和额度用尽的直接跳过，不浪费一次往返。
// 顺位由 rankUsableKeys 决定（正常优先、额度多优先、最久没用优先）。
function nextUsableKey(tried) {
  return rankUsableKeys(tried)[0] || null;
}
// 把切换结果落盘，这样后续请求、状态栏和面板都跟着走。
async function adoptKey(key) {
  try {
    await set("activeApiKey", key);
    // 自动模式下顺手把地区切成这把密钥自己的区域。这里只读缓存、不发探测请求：
    // 转发是热路径，不能为了识别地区多等一次往返。缓存没有就维持现状，稍后的
    // 账户同步或面板操作会把它补上。
    if (isRegionAuto()) {
      const r = trustedCachedRegion(key) || jsonHomeRegion(key);
      if (r && r !== configuredRegion()) await applyDetectedRegion(r, { silent: true });
      // 这把号还没探过区：后台补探一次，别等第一次请求撞了跨区 403 再纠正。
      else if (!trustedCachedRegion(key) && !jsonHomeRegion(key)) ensureRegionForKeySoon(key);
    }
    updateStatusBar();
    if (panelProvider) panelProvider.pushState();
  } catch (e) {
    log("!! 切换密钥失败: " + (e?.message || e));
  }
}
// 均衡路由实际用上的那把号要让用户看见：面板的选中态和状态栏都跟着走，否则界面
// 显示的还是上一把，跟真正在跑的对不上。
//
// 但转发是热路径 —— 一轮对话里 Kiro 会连发好几个请求（意图分类、生成…），每个都
// 写一遍 VSCode 配置太重。所以这里节流：
//   * key 没变就什么都不做（命中最多的一条）
//   * 变了也不立刻写，攒一个短窗口再落盘；窗口里又换了就只落最后那一把
const ACTIVE_SYNC_DEBOUNCE_MS = 1200;
let _activeSyncTimer = null;
let _activeSyncWant = "";
function syncActiveKeySoon(key) {
  if (!key) return;
  const prefs = getSwitchPrefs();
  if (!prefs.enabled || !prefs.loadBalance) return;
  if (key === getActiveApiKey()) return;
  _activeSyncWant = key;
  if (_activeSyncTimer) return;
  _activeSyncTimer = setTimeout(() => {
    _activeSyncTimer = null;
    const want = _activeSyncWant;
    _activeSyncWant = "";
    // 攒的这一小段时间里，这把号可能已经被删掉、或者刚被判死了，落盘前再确认一遍。
    if (!want || want === getActiveApiKey()) return;
    if (!getApiKeys().includes(want) || !keyIsUsable(want)) return;
    adoptKey(want);
  }, ACTIVE_SYNC_DEBOUNCE_MS);
}

// ---------------------------------------------------------------------------
// 刚删掉的坏号记忆
// ---------------------------------------------------------------------------
// 真正的删除动作在探活那一节（runLivenessScan → deleteKeyAutomatic）：判废的依据是
// 真发一次请求拿到的响应，比用量接口推算硬得多。这里只补一件探活没管的事 ——
//
// 刚被删掉的坏号记一段时间。号池（尤其是拼车那种共享池）很可能马上又把同一把号发
// 下来，而它刚刚才被判成额度用尽 / 已禁用 —— 再收一次只会重走「导入 → 撞墙 → 判死
// → 删除」，白烧往返。这段时间内当重复号跳过；过了这个期限还给同一把，那就再收，
// 因为那时候额度可能真的到新周期了。
const DEAD_KEY_MEMORY_MS = 6 * 60 * 60 * 1000;
const _deadKeyAt = new Map(); // key -> 被自动删掉的时间
function rememberDeadKey(key) {
  if (key) _deadKeyAt.set(key, Date.now());
}
function isRecentlyDeadKey(key) {
  const at = Number(_deadKeyAt.get(key) || 0);
  if (!at) return false;
  if (Date.now() - at > DEAD_KEY_MEMORY_MS) { _deadKeyAt.delete(key); return false; }
  return true;
}
// 探活之外的删除入口。
//
// 真探活（runLivenessScan）默认是关着的 —— 它每探一把号就烧一个生成请求。要是只让它
// 触发删除，绝大多数人的坏号永远清不掉。而下面这两条路径零额外成本：转发那一发本来
// 就要发，免费巡检走的是控制面用量 GET。
//
// 只认「上游亲口拒绝服务」的这三类。用量接口拿 used >= total 推出来的额度用尽不算：
// POWER 这类号 base 用超之后还有 overage 余量，照样能跑，用量却已经显示 10508/10000,
// 按那个删就是把一把还能用的号弄丢，而且不可逆。
const HARD_DEAD_KINDS = new Set(["suspended", "overage", "quota"]);
const HARD_DROP_DELAY_MS = 800;
const _dropQueue = new Map(); // key -> 删除原因
let _dropTimer = null;
function scheduleDeadDrop(key, kind) {
  if (!key || !HARD_DEAD_KINDS.has(kind) || !getAutoDeleteOnDead()) return;
  _dropQueue.set(key, KIND_LABEL[kind] || kind);
  if (_dropTimer) return;
  // 判定发生在同步路径上（coolDownKey / noteAccountHealth 都会顺手回推面板），在那里
  // 直接 await 删除会套娃，所以攒一个短窗口再做。
  _dropTimer = setTimeout(async () => {
    _dropTimer = null;
    // 一把一把删：每次都要重新读列表（上一次删除已经改过配置），批量算下标会串位。
    while (_dropQueue.size) {
      const [k, why] = _dropQueue.entries().next().value;
      _dropQueue.delete(k);
      try {
        await deleteKeyAutomatic(k, why);
      } catch (e) {
        log("!! 自动删除 " + maskKey(k) + " 失败: " + (e?.message || e));
      }
    }
  }, HARD_DROP_DELAY_MS);
}

// ---------------------------------------------------------------------------
// Prompt injection (前置 / 后置提示词)
// ---------------------------------------------------------------------------
// The fixed prompts are added to the CURRENT user message only, never to the
// conversation history kiro-agent replays on every turn, and never to the
// automatic tool-result turns of an agent loop (those carry no user text).
function findCurrentUserInputMessage(node, depth = 0) {
  if (!node || typeof node !== "object" || depth > 8) return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const v = findCurrentUserInputMessage(item, depth + 1);
      if (v) return v;
    }
    return null;
  }
  const cur = node.currentMessage;
  if (cur && typeof cur === "object" && cur.userInputMessage && typeof cur.userInputMessage === "object") {
    return cur.userInputMessage;
  }
  for (const k of Object.keys(node)) {
    const v = findCurrentUserInputMessage(node[k], depth + 1);
    if (v) return v;
  }
  return null;
}
function isToolLoopTurn(msg) {
  const ctx = msg && msg.userInputMessageContext;
  if (!ctx || typeof ctx !== "object") return false;
  const results = ctx.toolResults;
  return Array.isArray(results) && results.length > 0;
}
// Returns the (possibly rewritten) body plus a flag for logging.
function applyPromptPrefs(bodyBuf) {
  const p = getPromptPrefs();
  const pre = p.prefixEnabled ? p.prefixText.trim() : "";
  const suf = p.suffixEnabled ? p.suffixText.trim() : "";
  if ((!pre && !suf) || !bodyBuf || !bodyBuf.length) return { buf: bodyBuf, applied: "" };
  let j;
  try { j = JSON.parse(bodyBuf.toString("utf8")); } catch { return { buf: bodyBuf, applied: "" }; }
  const msg = findCurrentUserInputMessage(j);
  if (!msg || typeof msg.content !== "string") return { buf: bodyBuf, applied: "" };
  const original = msg.content;
  if (!original.trim() || isToolLoopTurn(msg)) return { buf: bodyBuf, applied: "" };
  let next = original;
  const tags = [];
  // Skip when the text is already there (e.g. a client-side resend).
  if (pre && !next.startsWith(pre)) { next = pre + "\n\n" + next; tags.push("前置"); }
  if (suf && !next.endsWith(suf)) { next = next + "\n\n" + suf; tags.push("后置"); }
  if (!tags.length) return { buf: bodyBuf, applied: "" };
  msg.content = next;
  return { buf: Buffer.from(JSON.stringify(j), "utf8"), applied: tags.join("+") };
}
// Replace the current user message with the rule's 自动回复词 before a re-send,
// keeping the conversation history intact so the upstream still sees the full
// context — only the last thing "the user said" changes.
function applyRetryReply(bodyBuf, replyText) {
  const text = String(replyText || "").trim();
  if (!text || !bodyBuf || !bodyBuf.length) return { buf: bodyBuf, applied: false };
  let j;
  try { j = JSON.parse(bodyBuf.toString("utf8")); } catch { return { buf: bodyBuf, applied: false }; }
  const msg = findCurrentUserInputMessage(j);
  if (!msg || typeof msg.content !== "string") return { buf: bodyBuf, applied: false };
  const p = getPromptPrefs();
  const pre = p.prefixEnabled ? p.prefixText.trim() : "";
  const suf = p.suffixEnabled ? p.suffixText.trim() : "";
  // The fixed prompts apply to this message too — it is a user turn like any other.
  msg.content = (pre ? pre + "\n\n" : "") + text + (suf ? "\n\n" + suf : "");
  return { buf: Buffer.from(JSON.stringify(j), "utf8"), applied: true };
}

// ---------------------------------------------------------------------------
// Auto retry (自动重试)
// ---------------------------------------------------------------------------
// Off by default: this gateway's contract is to surface the selected key's real
// error instead of silently papering over it. When enabled, an upstream failure
// whose status or body matches a rule is re-sent (same key) up to `max` times
// before the error reaches Kiro.
// Kiro 展示任何上游错误时都会套上这句前缀，例如聊天窗里看到的
// 「Something went wrong: [InternalServerException] Encountered an unexpected
// error…」。这句是 Kiro 自己加的，上游原文里并没有 —— 而用户能看到的只有它，
// 照着它写规则是最自然的做法。所以匹配时把这句也算进去，否则照 UI 文案写的
// 规则永远命中不了。
const KIRO_ERROR_PREFIX = "Something went wrong";
// 异常类型短名。event stream 里的 __type 常带包名前缀
// （com.amazon.coral.service#InternalServerException），写规则的人一般只记得
// 后面那截，所以单独再拼一份短名进去。
function exceptionName(text) {
  const m = String(text || "").match(/([A-Za-z][A-Za-z0-9_]*(?:Exception|Error|Fault))\b/);
  return m ? m[1] : "";
}
// 规则要匹配的那段文本：状态码 + Kiro 的固定前缀 + 上游原文 + 异常类型短名。
function retryHaystack(status, bodyText) {
  const body = String(bodyText || "");
  const parts = ["HTTP " + status, KIRO_ERROR_PREFIX, body];
  const type = exceptionName(body);
  if (type) parts.push(type);
  return parts.join(" ").toLowerCase();
}
// opts.replyOnly: 只看带自动回复词的规则。
//
// 带回复词的规则表达的意图是「用这句话把对话续下去」，跟自动切号（换一把 key
// 重发同样的内容）是互斥的两件事，所以转发路径里让它优先于切号。典型场景就是
// 「命中 Access denied → 回复 继续」：Access denied 同时是切号判定密钥失效的
// 关键词，不给回复词插队的机会，这条规则永远拿不到执行。
// reply 为空的规则仍然让切号先走 —— 原样重发和换号重发没有区别，换号更有意义。
function matchedRetryRule(status, bodyText, opts = {}) {
  const p = getRetryPrefs();
  if (!p.enabled) return null;
  const haystack = retryHaystack(status, bodyText);
  for (const rule of p.rules) {
    if (!rule.enabled) continue;
    if (opts.replyOnly && !rule.reply) continue;
    if (haystack.includes(rule.match.toLowerCase())) return rule;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function stripHopByHop(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (HOP_BY_HOP.includes(k.toLowerCase())) continue;
    out[k] = v;
  }
  return out;
}
// A generic retry can help only when the failure may change without changing
// the request. Unknown 4xx responses are request/auth/protocol failures and
// must be surfaced once; 408/425/429 are the explicit transient exceptions.
function isDeterministicClientError(status) {
  return status >= 400 && status < 500
    && status !== 408 && status !== 425 && status !== 429;
}
// 把一段已经缓存下来的响应体交回给 Kiro。
//
// content-length 不是 hop-by-hop 头，会被原样转发，所以必须按真正写出的字节数
// 改写：错误体超过 ERR_BODY_CAP 时只转发了前一截，读响应流出错时更是一个字节
// 都没有 —— 头里却写着完整长度，Kiro 就会一直等那些永远不会来的字节，直到超时。
function sendBufferedBody(res, status, upHeaders, buf) {
  const body = Buffer.isBuffer(buf) ? buf : Buffer.alloc(0);
  const headers = stripHopByHop(upHeaders);
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === "content-length") delete headers[k];
  }
  headers["content-length"] = String(body.length);
  try {
    if (!res.headersSent) res.writeHead(status || 502, headers);
    res.end(body);
  } catch {}
}
function maskKey(k) {
  if (!k) return "(empty)";
  if (isJsonKey(k)) return displayJsonKey(k);
  if (k.length <= 12) return k.slice(0, 4) + "***";
  return k.slice(0, 8) + "…" + k.slice(-4);
}
// Show first 8 + last 8 chars, middle replaced with '*' (capped for display).
function maskKeyLong(k) {
  if (isJsonKey(k)) return displayJsonKey(k);
  const s = String(k || "");
  if (s.length <= 16) return s.slice(0, 4) + "*".repeat(Math.max(3, s.length - 4));
  const stars = "*".repeat(Math.min(Math.max(s.length - 16, 4), 16));
  return s.slice(0, 8) + stars + s.slice(-8);
}
// Stable 64-hex machine id (persisted across reloads).
function machineId() {
  if (_machineId) return _machineId;
  let id = extContext && extContext.globalState.get("kiroGateway.machineId");
  if (!id) {
    id = require("crypto").randomBytes(32).toString("hex");
    extContext && extContext.globalState.update("kiroGateway.machineId", id);
  }
  _machineId = id;
  return id;
}
function kiroUserAgent() {
  const mid = machineId();
  return `aws-sdk-js/1.0.34 ua/2.1 os/${KIRO_SYSTEM} lang/js md/nodejs#${KIRO_NODE} api/codewhispererstreaming#1.0.34 m/E KiroIDE-${KIRO_VERSION}-${mid}`;
}
function kiroXAmzUserAgent() {
  return `aws-sdk-js/1.0.34 KiroIDE-${KIRO_VERSION}-${machineId()}`;
}

// Build the upstream headers for a ksk_ request: keep whatever the IDE sent,
// but force the credential + API-key markers.
const PROFILE_HEADER_NAMES = ["x-amzn-kiro-profile", "x-amzn-kiro-profile-arn", "x-kiro-profile-arn"];
function alignProfileHeaders(headers, auth) {
  const arn = auth && auth.type !== "apikey" ? String(auth.profileArn || "") : "";
  let changed = false;
  for (const k of Object.keys(headers)) {
    if (!PROFILE_HEADER_NAMES.includes(k.toLowerCase())) continue;
    if (!arn) {
      delete headers[k];
      changed = true;
      continue;
    }
    if (headers[k] !== arn) {
      headers[k] = arn;
      changed = true;
    }
  }
  return changed;
}
function injectAuthHeaders(incoming, targetHost, keyOrAuth) {
  const auth = keyOrAuth && typeof keyOrAuth === "object" && keyOrAuth.token
    ? keyOrAuth
    : (peekFreshAuth(keyOrAuth) || { type: isJsonKey(keyOrAuth) ? "oauth" : "apikey", token: keyOrAuth || getApiKey(), profileArn: "" });
  const headers = {};
  for (const [k, v] of Object.entries(incoming || {})) {
    const lk = k.toLowerCase();
    if (lk === "host" || lk === "authorization" || lk === "content-length" || lk === "tokentype") continue;
    if (HOP_BY_HOP.includes(lk)) continue;
    headers[k] = v;
  }
  headers["host"] = targetHost;
  headers["authorization"] = "Bearer " + auth.token;
  if (auth.type === "apikey") headers["tokentype"] = "API_KEY";
  else if (auth.tokenType) headers["tokentype"] = auth.tokenType;
  // 插件关闭时，Kiro 的 bearer 和 x-amzn-kiro-profile 属于同一个号。
  // 这里只换 token 的话，头还是 IDE 当前登录号，对话会被判 access_denied。
  // JSON 号改成它自己的 profileArn；没有就去掉，避免留下别人的身份。ksk_ 不带这些头。
  if (alignProfileHeaders(headers, auth)) log("[auth] profile 头已改成当前账号");
  const has = (name) => Object.keys(headers).some((h) => h.toLowerCase() === name);
  if (!has("x-amzn-kiro-agent-mode")) headers["x-amzn-kiro-agent-mode"] = "vibe";
  // The upstream authorizes only when User-Agent carries a KiroIDE signature.
  const uaKey = Object.keys(headers).find((h) => h.toLowerCase() === "user-agent");
  if (!uaKey || !/KiroIDE/i.test(String(headers[uaKey] || ""))) headers[uaKey || "user-agent"] = kiroUserAgent();
  if (!has("x-amz-user-agent")) headers["x-amz-user-agent"] = kiroXAmzUserAgent();
  if (!has("x-amzn-codewhisperer-optout")) headers["x-amzn-codewhisperer-optout"] = "true";
  return headers;
}

// `/mcp` and `/mcp/stream` are not API-key generation operations. Current
// Kiro builds use them for the built-in Remote Tools service and put the
// signed-in user's required profileArn in the JSON body. Replacing the
// official bearer token with a ksk_ token and stripping profileArn turns that
// valid request into a deterministic HTTP 400.
//
// The endpoint override is base-URL-wide, so these paths still arrive at the
// local KRS listener. Route just these operations back to the official runtime
// with the IDE's original bearer auth and body; all actual generation calls
// continue through the ksk_ path below.
function isOfficialKrsPassthrough(req) {
  try {
    const pathname = new URL(String((req && req.url) || "/"), "http://127.0.0.1").pathname.toLowerCase();
    return pathname === "/mcp" || pathname === "/mcp/stream";
  } catch {
    return false;
  }
}
function officialPassthroughHeaders(incoming, targetHost, bodyLength) {
  const headers = stripHopByHop(incoming);
  for (const k of Object.keys(headers)) {
    const lk = k.toLowerCase();
    if (lk === "host" || lk === "content-length") delete headers[k];
  }
  headers["host"] = targetHost;
  headers["content-length"] = String(bodyLength);
  return headers;
}
function forwardOfficialKrsRequest(req, res, bodyBuf) {
  const body = Buffer.isBuffer(bodyBuf) ? bodyBuf : Buffer.alloc(0);
  let target;
  try {
    target = new URL(runtimeBase() + req.url);
  } catch {
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "bad official KRS passthrough target" }));
    return;
  }
  const headers = officialPassthroughHeaders(req.headers, target.host, body.length);
  const hasAuth = Object.keys(headers).some((k) => k.toLowerCase() === "authorization" && !!headers[k]);
  let hasProfileArn = false;
  try {
    const parsed = body.length ? JSON.parse(body.toString("utf8")) : null;
    hasProfileArn = !!(parsed && typeof parsed.profileArn === "string" && parsed.profileArn);
  } catch {}
  log("-> [KRS/OFFICIAL] " + req.method + " " + target.pathname
    + " auth=" + (hasAuth ? "preserved" : "missing")
    + " profileArn=" + (hasProfileArn ? "preserved" : "missing")
    + " body=" + body.length + "B"
    + " -> " + target.host + target.pathname + " region=" + getRegion());

  const upReq = https.request(
    {
      method: req.method,
      hostname: target.hostname,
      port: 443,
      path: target.pathname + target.search,
      headers,
      timeout: 300000,
      agent: UPSTREAM_AGENT,
    },
    (upRes) => {
      const status = upRes.statusCode || 0;
      log((status >= 200 && status < 300 ? "<- " : "!! ")
        + "[KRS/OFFICIAL] " + target.pathname + " -> HTTP " + status);
      try {
        if (!res.headersSent) res.writeHead(status || 502, stripHopByHop(upRes.headers));
        upRes.pipe(res);
      } catch (e) {
        try { res.destroy(e); } catch {}
      }
      upRes.on("error", (e) => {
        log("!! [KRS/OFFICIAL] response error: " + e.message);
        try { res.destroy(e); } catch {}
      });
    }
  );
  upReq.on("error", (e) => {
    log("!! [KRS/OFFICIAL] upstream error: " + e.message);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      try { res.end(JSON.stringify({ message: "official KRS passthrough error: " + e.message })); } catch {}
    } else {
      try { res.destroy(e); } catch {}
    }
  });
  upReq.on("timeout", () => upReq.destroy(new Error("official KRS passthrough timeout")));
  res.on("close", () => {
    if (!res.writableEnded) {
      try { upReq.destroy(new Error("client closed")); } catch {}
    }
  });
  upReq.end(body);
}

// ---------------------------------------------------------------------------
// Reverse proxy: swap credential, strip profileArn, forward to Kiro gateway.
// ---------------------------------------------------------------------------
// opts.sniff(bodyText, status, req): 旁路嗅探响应体。
//
// 插件自己要用上游的一些数据（模型计费倍率、账号用量），但又必须保证转发给 Kiro
// 的字节跟官方原样一致。所以嗅探是"旁路"的：一边把 chunk 原样写给 Kiro，一边攒
// 一份副本给自己看，攒够上限就不再攒，绝不因为嗅探改动或延迟转发的内容。
// 只对确定很小的 JSON 响应开启，其余一律走 pipe。
const SNIFF_CAP = 64 * 1024;
function makeProxyHandler(label, baseFn, opts = {}) {
  return function handle(req, res) {
    if (req.url === HEALTH_PATH) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(HEALTH_MARKER);
      return;
    }
    const apiKey = getApiKey();
    if (!apiKey) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Kiro Gateway: no API key configured." }));
      return;
    }

    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("error", () => {});
    req.on("end", () => {
      const incomingBody = Buffer.concat(chunks);
      const finish = (auth) => {
      const prepared = prepareOutbound(auth, incomingBody, req.url);
      let bodyBuf = prepared.body;
      const cleanUrl = prepared.url;
      if (auth.type === "apikey" && cleanUrl !== req.url) {
        log("[" + label + "] 已从查询串摘掉 profileArn（ksk_ 凭证不能带它，否则上游回 403 Invalid token）");
      }

      let target;
      try {
        target = new URL(baseFn() + cleanUrl);
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "bad target url: " + e.message }));
        return;
      }

      const activeKey = auth.key || getApiKey();
      const keyTag = "key (" + maskKey(activeKey) + ")";
      const headers = injectAuthHeaders(req.headers, target.host, auth);
      if (bodyBuf.length) headers["content-length"] = Buffer.byteLength(bodyBuf);

      log("-> [" + label + "] " + keyTag + " " + req.method + " " + req.url.split("?")[0] + " region=" + getRegion());

      // 传输层故障的退避重发状态。只有请求发不出去 / 连接中途断了才重发；一旦上游
      // 给了响应头（res.headersSent）就绝不重发 —— 那时字节已经在往 Kiro 流了，
      // 重发会造成两份响应交叉。
      let transportRetries = 0;
      let transportBackoffMs = 0;
      const send = () => {
      const upReq = https.request(
        {
          method: req.method,
          hostname: target.hostname,
          port: 443,
          path: target.pathname + target.search,
          headers,
          timeout: 300000,
          agent: UPSTREAM_AGENT,
        },
        (upRes) => {
          const status = upRes.statusCode || 0;
          const ok = status >= 200 && status < 300;
          log((ok ? "<- [" : "!! [") + label + "] " + keyTag + " -> HTTP " + status);
          const outHeaders = stripHopByHop(upRes.headers);
          res.writeHead(status || 502, outHeaders);
          if (typeof opts.sniff !== "function") {
            upRes.pipe(res);
            upRes.on("error", () => { try { res.end(); } catch {} });
            return;
          }
          // 旁路嗅探：转发照旧一个 chunk 一个 chunk 原样写出，副本只是顺手攒的。
          const seen = [];
          let seenLen = 0;
          upRes.on("data", (c) => {
            const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
            if (seenLen < SNIFF_CAP) {
              seen.push(buf);
              seenLen += buf.length;
            }
            // 背压得自己接上。pipe 本来替我们做这件事，改成手动转发就漏掉了：下游
            // 写不动时 write 返回 false，此时不停上游的话数据会全积在内存里。
            // 当前只嗅探用量/模型这类小 JSON，看不出差别，但别给以后埋坑。
            let flushed = true;
            try { flushed = res.write(buf); } catch { return; }
            if (!flushed) {
              upRes.pause();
              res.once("drain", () => upRes.resume());
            }
          });
          upRes.on("end", () => {
            try { res.end(); } catch {}
            // 嗅探失败绝不能影响这次转发 —— 字节早就发出去了，这里只是自己看一眼。
            try { opts.sniff(Buffer.concat(seen).toString("utf8"), status, req); } catch {}
          });
          upRes.on("error", () => { try { res.end(); } catch {} });
        }
      );
      upReq.on("error", (e) => {
        log("!! [" + label + "] " + keyTag + " upstream error: " + e.message);
        const prefs = getServerErrorRetryPrefs();
        if (!res.headersSent && prefs.enabled && isTransportFailure(e.message)
          && transportRetries < prefs.max) {
          transportRetries += 1;
          transportBackoffMs = nextBackoffMs(
            transportBackoffMs, getEndpointRoundPrefs().delayMs, getThrottlePatience().capMs);
          log("[" + label + "] 传输层故障: " + transportBackoffMs + "ms 后重发"
            + "（第 " + transportRetries + "/" + prefs.max + " 次）");
          setTimeout(send, transportBackoffMs);
          return;
        }
        if (!res.headersSent) res.writeHead(502, { "Content-Type": "application/json" });
        try { res.end(JSON.stringify({ message: "upstream error: " + e.message })); } catch {}
      });
      upReq.on("timeout", () => upReq.destroy(new Error("upstream timeout")));
      if (bodyBuf.length) upReq.write(bodyBuf);
      upReq.end();
      };
      send();
      };
      const cached = peekFreshAuth(apiKey);
      if (cached && cached.token) {
        finish(cached);
        return;
      }
      resolveAuth(apiKey).then(finish).catch((e) => {
        log("!! [" + label + "] 凭证刷新失败: " + (e && e.message ? e.message : e));
        if (!res.headersSent) {
          res.writeHead(401, { "Content-Type": "application/json" });
          try { res.end(JSON.stringify({ message: "Kiro Gateway: credential refresh failed: " + (e && e.message ? e.message : e) })); } catch {}
        }
      });
    });
  };
}

// ---------------------------------------------------------------------------
// 不中断重试
// ---------------------------------------------------------------------------
// 原则：一轮对话不能因为换号、状态检测、冷却这些内部动作而失败。上游怎么拒都行，
// 网关自己想办法把它变成一次成功的回答 —— 换号、等冷却、再换回来，全在同一个
// HTTP 请求里做完，Kiro 只看到最终结果。
//
// 兜住这件事的只有两条边界：
//   1. Kiro 自己取消了（用户点停止、窗口重载）—— 没人等答案了，立刻收手
//   2. 时间预算用完 —— 再耗下去客户端自己也会超时，这时才把最后一次失败如实交回
const NO_INTERRUPT_BUDGET_MS = 15 * 60 * 1000;
// 所有号都在冷却时的轮询间隔：等最快到期的那把，但至少隔这么久再试一次，
// 免得空转。
const NO_INTERRUPT_WAIT_MS = 2500;

// KRS（生成平面）处理器。默认从用户选中的那把 key 出发；上游一旦表示这把 key
// 现在用不了（限流 / 403 / 额度用尽 / 鉴权失效 / 上游 5xx），就在同一个请求内换
// 下一把可用的 key 重发 —— 这就是"无感切号"，Kiro 只会看到最终结果，也不需要
// 重新加载窗口。号都在冷却时不认输，等到期再来一轮，直到预算耗尽。
// 自动切号可以在设置里关掉，关掉后就是严格的"只用选中的那把"。
function makeKrsHandler() {
  return function handle(req, res) {
    if (req.url === HEALTH_PATH) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(HEALTH_MARKER);
      return;
    }
    markProxyHit("KRS", req);
    // 起步用哪把 key 交给 pickStartKey 决定（当前选中的那把优先，它不可用就顺位
    // 挑一把正常的），这里只确认"至少配了一把"。
    // 早先这里写的是"只用选中的那把、没有 failover"，那是自动切号之前的行为，
    // 留着只会误导 —— 真正的切号逻辑在下面的 trySwitchKey。
    if (!getApiKeys().length) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Kiro Gateway: no API key configured." }));
      return;
    }

    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("error", () => {});
    req.on("end", () => {
      const incomingBody = Buffer.concat(chunks);
      // Remote Tools uses the official profile-bound MCP API. It must bypass
      // every ksk_-specific mutation, including profileArn stripping, prompt
      // injection, key rotation and the no-interrupt retry loop.
      if (isOfficialKrsPassthrough(req)) {
        forwardOfficialKrsRequest(req, res, incomingBody);
        return;
      }
      let bodyBuf = incomingBody;
      // profileArn 按当前凭证类型在 attempt 里处理：ksk_ 必须摘掉，JSON/OAuth 必须带上。
      // 这里先不动，否则混用号池时切到 JSON 号会丢掉它自己的 profileArn。

      const statOp = operationName(req);
      const isChat = BILLED_OP_RE.test(statOp);
      // 只有两个平面都认的操作才参与端点轮换，其余一律只走 KRS。
      const isRotatable = ROTATABLE_OP_RE.test(statOp);
      const epChain = isRotatable
        ? filterUnsupportedEndpoints(genEndpointChain(), getRegion(), statOp)
        : krsOnlyChain();
      // 不可轮换的操作不参与端点回退，行为严格等同只走 KRS 的老路径。
      // 必须用 isRotatable 而不是 isChat：epChain 上面已经按 isRotatable 定型，这里
      // 再用 isChat 会出现"链只有 krs 一个、却允许回退"的错配（SendMessage 正是
      // 这种情况）。
      const epFallbackAllowed = isRotatable && getEndpointFallback();
      // 路径、查询串、请求体、除凭证外的全部请求头都原样透传 —— 跟只走 KRS 的老
      // 路径唯一的差别就是这里的主机名，不按端点分叉。
      const buildTarget = (epIdx, urlPath) => {
        try {
          return new URL(epChain[epIdx].base(getRegion()) + (urlPath || req.url));
        } catch (e) {
          return null;
        }
      };
      if (!buildTarget(0)) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "bad target url for endpoint " + epChain[0].id }));
        return;
      }
      // Fixed 前置/后置提示词 go only on real chat turns.
      if (isChat) {
        const injected = applyPromptPrefs(bodyBuf);
        if (injected.applied) {
          bodyBuf = injected.buf;
          log("[KRS] 已注入" + injected.applied + "提示词");
        }
      }
      const statModel = modelIdFromBody(bodyBuf);
      const retryCfg = getRetryPrefs();
      const maxAttempts = retryCfg.enabled ? retryCfg.max + 1 : 1;
      // 自动切号：从用户选中的那把开始（它在冷却中就先跳过）。
      //
      // 这里不再限制"每把只试一次、切完就认输"。目标是不中断 Kiro 这轮对话：只要
      // 客户端还在等、时间预算还没用完，就一直换号 / 等冷却 / 重发，把失败全部在
      // 网关内部消化掉。轮完一圈没成功就清空"已试过"再来一圈，靠 deadline 收口，
      // 不会无限打下去。
      const switchCfg = getSwitchPrefs();
      const triedKeys = new Set();
      const deadline = Date.now() + NO_INTERRUPT_BUDGET_MS;
      const startKey = pickStartKey() || getApiKey();
      // 本次请求已经试过的端点。429 只在还有没试过的端点时才切，切一轮就够 ——
      // 两个端点都限流说明是真的发太快了，这时候继续换只是把请求灌进同样的窗口。
      const triedEndpoints = new Set();
      const startEpIdx = pickStartEndpointIndex(epChain);
      // 端点链走到第几轮。本轮所有端点都撞上限流时退避一次再重走，轮数用尽才放弃。
      let epRound = 1;
      // 耐心模式下的指数退避状态。跨 attempt() 累加，只有换 key 时重置：换成另一把
      // 号意味着"限流跟这把 key 无关"这个前提失效了，新号有独立的并发余量，退避
      // 应该从头算。
      let endlessBackoffMs = 0;
      let endlessWaitedMs = 0;
      // 上游临时故障（5xx）的重试计数与退避。跟限流的退避分开算：两者的成因和收敛
      // 条件都不同，混在一起会互相干扰次数统计。
      let serverRetries = 0;
      let serverBackoffMs = 0;
      // If Kiro cancels the request (user hits stop, window reload…) there is
      // nobody left to answer, so a pending retry must not fire.
      let clientGone = false;
      res.on("close", () => { if (!res.writableEnded) clientGone = true; });
      req.on("aborted", () => { clientGone = true; });
      // Error bodies are small; cap the buffer so a rogue response can't grow
      // memory while we decide whether the rule matched.
      const ERR_BODY_CAP = 64 * 1024;

      // 每次尝试都自带 body 和 key：自动回复词会改写当前用户消息，自动切号会换
      // 掉凭证，两者都让下一次发出的内容与上一次不同。
      const attempt = (n, body, key, epIdx = startEpIdx) => {
        const begin = (auth) => attemptReady(n, body, key, epIdx, auth);
        const cached = peekFreshAuth(key);
        if (cached && cached.token) return begin(cached);
        resolveAuth(key).then(begin).catch((e) => {
          log("!! [KRS] 凭证刷新失败: " + maskKey(key) + " " + (e && e.message ? e.message : e));
          try { coolDownKey(key, "invalid"); } catch {}
          try { maybeAdoptUsableKey(); } catch {}
          const next = nextUsableKey(new Set([key, ...triedKeys]));
          if (next && !clientGone) {
            adoptKey(next).then(() => { if (!clientGone) attempt(n, body, next, startEpIdx); });
            return;
          }
          if (!res.headersSent) {
            res.writeHead(401, { "Content-Type": "application/json" });
            try { res.end(JSON.stringify({ message: "Kiro Gateway: JSON 凭证刷新失败: " + (e && e.message ? e.message : e) })); } catch {}
          }
        });
      };
      const attemptReady = (n, body, key, epIdx, auth) => {
        const prepared = prepareOutbound(auth, body, req.url);
        const sendBody = prepared.body;
        const ep = epChain[epIdx];
        const target = buildTarget(epIdx, prepared.url);
        const keyTag = "key (" + maskKey(key) + ") [" + ep.label + "]";
        const statIn = sendBody.length;
        const headers = injectAuthHeaders(req.headers, target.host, auth);
        if (sendBody.length) headers["content-length"] = Buffer.byteLength(sendBody);
        triedKeys.add(key);
        triedEndpoints.add(ep.id);
        // 记一次"这把号刚被用过"：同档位的号靠它轮转，不会永远压在列表第一把上。
        noteKeyUsed(key);
        // 均衡路由挑到了别的号时，把面板选中态和状态栏也带过去（内部节流，
        // 没换号就是一次空调用）。
        syncActiveKeySoon(key);
        // 诊断信息一次打全：操作名、入站 content-type、实际转发的主机 + 路径。
        // 路径永远是 "/"（操作在 x-amz-target 里），不打出来就看不出这条请求是生成、
        // 会话还是行内补全；content-type 决定上游用哪套协议解析。缺一个都得靠猜。
        const inCt = String((req.headers && (req.headers["content-type"] || req.headers["Content-Type"])) || "-");
        // body 大小也打出来：连接复用之后，剩下的耗时大头是请求体上传（会话历史 +
        // 文件正文每轮全量重传）。没有这个数就没法判断该继续抠代码还是该收敛上下文。
        log("-> [KRS] " + keyTag + " " + req.method + " " + req.url.split("?")[0]
          + " op=" + statOp + (isRotatable ? "" : " (不可轮换，只走 KRS)")
          + " ct=" + inCt
          + " body=" + (bodyBuf.length / 1024).toFixed(0) + "KB"
          + " -> " + target.host + target.pathname
          + " region=" + getRegion() + (n > 1 ? " (重试 " + (n - 1) + "/" + retryCfg.max + ")" : ""));

        // Live statistics for this attempt: the request is counted right now,
        // the token estimate grows while the answer streams, and the outcome is
        // recorded the moment it is known. A streamed answer ends with "end" or,
        // if the client walks away mid-stream, "close" — endOnce() makes sure
        // exactly one of those (or a transport error) closes the attempt.
        statsRequestStarted(statIn, key);
        let statEnded = false;
        // counted=false：这次失败被自动切号或自动重试内部消化掉了，Kiro 那边
        // 根本没看到失败，所以不该记进「错误数」。只有最终真的把失败交回给
        // Kiro（没号可换的 429、上游 5xx、网络错误等）才算一次错误。
        const endOnce = (ok, counted = true) => {
          if (statEnded) return;
          statEnded = true;
          if (!ok && counted) statsRequestFailed(key);
          statsRequestFinished();
        };
        // Re-send after the configured pause, keeping the client waiting. A rule
        // with a 自动回复词 re-sends that text as the user's message instead of
        // repeating the original one.
        const scheduleRetry = (rule, opts = {}) => {
          if (clientGone) return;
          let nextBody = body;
          let how = "原样重发";
          if (isChat && rule.reply) {
            const rewritten = applyRetryReply(body, rule.reply);
            if (rewritten.applied) { nextBody = rewritten.buf; how = "以「" + rule.reply + "」回复"; }
          }
          log("[KRS] 自动重试: 命中「" + rule.match + "」，" + retryCfg.delayMs + "ms 后" + how
            + "（第 " + n + "/" + maxAttempts + " 次已失败）"
            + (opts.beforeSwitch ? "，带回复词的规则优先于自动切号" : ""));
          setTimeout(() => { if (!clientGone) attempt(n + 1, nextBody, key, epIdx); }, retryCfg.delayMs);
        };
        // 带自动回复词的规则先于切号试一次。重试次数用尽后仍然会落到
        // trySwitchKey，所以「这把 key 真的失效了」的兜底没有丢：不是不换号，
        // 只是先把回复词试完。
        // 只对聊天请求成立 —— 工具回合改写不了用户消息（applyRetryReply 拿不到
        // currentMessage），那时回复词无从应用，让它插队只会白等一轮再换号。
        const replyRuleFirst = (status, text) => {
          if (!isChat || n >= maxAttempts) return null;
          return matchedRetryRule(status, text, { replyOnly: true });
        };
        // 冷却最快到期还差多久（没有号在冷却时返回 0）。只服务下面的等待时长计算。
        const soonestCooldownMs = () => {
          const list = cooldownSnapshot();
          if (!list.length) return 0;
          return Math.max(0, Math.min(...list.map((c) => c.leftMs)));
        };
        // 不中断兜底：任何一次失败在真正交回 Kiro 之前都先问它一句「还能不能接着救」。
        //   Kiro 自己取消了 / 预算用完了 → false，把失败如实交回去
        //   还有没试过的可用号         → 立刻换号重发
        //   号都试过或都在冷却         → 清空"已试过"，等最快到期的那把，再来一轮
        // 返回 true 表示这轮失败已经被接走，调用方不许再往 res 写任何东西。
        const keepTrying = (why) => {
          if (clientGone) return false;
          if (!switchCfg.enabled) return false;
          const leftMs = deadline - Date.now();
          if (leftMs <= 0) {
            log("!! [KRS] 不中断重试已达 " + Math.round(NO_INTERRUPT_BUDGET_MS / 60000)
              + " 分钟上限，把失败交回 Kiro（" + why + "）");
            return false;
          }
          let next = nextUsableKey(triedKeys);
          let waitMs = 0;
          if (!next) {
            // 一圈轮完了。不认输：忘掉"这轮试过谁"，等最快解冻的那把号再来一圈。
            triedKeys.clear();
            next = nextUsableKey(triedKeys);
            if (!next) {
              // 连一把没冷却的号都没有：按最近的解冻时间等，至少等 NO_INTERRUPT_WAIT_MS。
              waitMs = Math.min(Math.max(soonestCooldownMs(), NO_INTERRUPT_WAIT_MS), leftMs);
              next = pickStartKey() || key;
            }
          }
          log("[KRS] 不中断重试: " + why + "，" + (waitMs ? Math.round(waitMs / 1000) + "s 后" : "立即")
            + "用 " + maskKey(next) + " 重发（剩余预算 " + Math.round(leftMs / 1000) + "s）");
          const go = () => {
            if (clientGone) return;
            // 换号后端点链重新开一轮：新号的并发余量是独立的，原号身上累计的端点
            // 冷却与退避对它不成立。
            triedEndpoints.clear();
            epRound = 1;
            endlessBackoffMs = 0;
            endlessWaitedMs = 0;
            adoptKey(next).then(() => { if (!clientGone) attempt(n, body, next, startEpIdx); });
          };
          if (waitMs > 0) setTimeout(go, waitMs); else go();
          return true;
        };
        // 端点能力缺失。跟限流是两件事，所以单独一条通路。
        //
        // 场景：KRS 限流 → 改道 q.{region} → 那个平面不认这个操作 → 400
        // UnknownOperationException。这个 400 完全是我们改道造成的，绝不能交回
        // Kiro —— 用户看到的就是聊天窗里的红字报错，而它跟账号、跟限流都无关。
        //
        // 处理：把「端点 + 区域 + 操作」记进能力缺失表（后续请求直接跳过，不再浪费
        // 往返），然后换到链里还支持这个操作的端点重发。要退避一下再发，因为我们
        // 本来就是因为原端点限流才改道过来的，立刻打回去大概率再吃一次 429。
        const trySwitchEndpointUnsupported = (status, bodyText) => {
          if (clientGone || !epFallbackAllowed) return false;
          if (!isUnsupportedOperationFailure(status, bodyText)) return false;
          const region = getRegion();
          if (!isEndpointUnsupported(ep.id, region, statOp)) {
            markEndpointUnsupported(ep.id, region, statOp);
            log("[KRS] 端点能力缺失: " + ep.label + " 在 " + region + " 不认 " + statOp
              + " → 本会话内不再把该操作发往此端点");
          }
          const alt = epChain.findIndex((e) =>
            e.id !== ep.id && !isEndpointUnsupported(e.id, region, statOp));
          if (alt < 0) {
            log("!! [KRS] 端点能力缺失: 没有别的端点支持 " + statOp + "，错误只能交回 Kiro");
            return false;
          }
          const delayMs = getEndpointRoundPrefs().delayMs;
          // 允许再走一次那个端点：它是被限流挡下的，不是不支持。
          triedEndpoints.delete(epChain[alt].id);
          log("[KRS] 端点能力缺失: " + delayMs + "ms 后改用 " + epChain[alt].label + " 重发");
          setTimeout(() => { if (!clientGone) attempt(n, body, key, alt); }, delayMs);
          return true;
        };
        // 上游临时故障重试。
        //
        // 上游回 5xx / InternalServerException 时，错误文案自己就写着 "please try
        // again"，而实测下一次同样的请求就成功。这属于瞬时错误，内部消化掉就行，
        // 不该让用户看到红字。
        //
        // 跟限流退避共用同一套指数增长和上限配置，但次数有限：限流是"等等就好"、
        // 等下去必然能通，而 5xx 连续不断更可能是真出问题（典型如账号超额后上游
        // 行为不稳定，会持续吐 500），无限重试只会让对话一直转着却拿不到结果。
        const tryRetryServerError = (status, bodyText) => {
          if (clientGone) return false;
          if (!isTransientServerFailure(status, bodyText)) return false;
          const prefs = getServerErrorRetryPrefs();
          if (!prefs.enabled) return false;
          if (serverRetries >= prefs.max) {
            log("!! [KRS] 上游临时故障: 已重试 " + serverRetries + "/" + prefs.max
              + " 次仍未成功，交回上层处理（连续 5xx 通常不是瞬时问题，"
              + "先看看账号额度是不是用尽了）");
            return false;
          }
          serverRetries += 1;
          const cap = getThrottlePatience().capMs;
          serverBackoffMs = nextBackoffMs(serverBackoffMs, getEndpointRoundPrefs().delayMs, cap);
          log("[KRS] 上游临时故障 (HTTP " + status + "): " + serverBackoffMs + "ms 后重发"
            + "（第 " + serverRetries + "/" + prefs.max + " 次，不换 key、不换端点）");
          setTimeout(() => { if (!clientGone) attempt(n, body, key, epIdx); }, serverBackoffMs);
          return true;
        };
        // 429 优先换端点，不换 key、不计重试次数。
        //
        // 实测证明 429 USER_REQUEST_RATE_EXCEEDED 是「端点级速率」，不是这把 key 的
        // 问题：KRS 打爆的同一秒 q. 满速连打全成。把 429 当成 key 的问题去换号 +
        // 冷却 key，切了也无效（同机器同 machineId），还会把好号标成限流。所以这里
        // 在 trySwitchKey 之前先拦一道：换端点成功就完全不动 key 状态。
        const trySwitchEndpoint = (status, bodyText) => {
          if (!isThrottleFailure(status, bodyText)) return false;
          if (clientGone || !epFallbackAllowed) return false;
          // 刚撞过的端点压一小段冷却，后续请求别再从它起步。
          endpointCoolDown(ep.id);
          const prefs = getEndpointRoundPrefs();
          // 本次请求进行中探明的能力缺失也要跳过。epChain 在请求开始时就定型了，
          // 光靠构造期过滤挡不住"跑到一半才发现某端点不支持"的情况。
          const skipIds = new Set(
            epChain.filter((e) => isEndpointUnsupported(e.id, getRegion(), statOp)).map((e) => e.id)
          );
          const plan = planEndpointFallback(epChain, triedEndpoints, epRound, prefs, skipIds);
          if (plan.action === "switch") {
            log("[KRS] 端点回退: " + ep.label + " 限流 → 换 " + epChain[plan.index].label
              + " 重发（第 " + epRound + "/" + prefs.rounds + " 轮，不换 key，不计重试）");
            attempt(n, body, key, plan.index);
            return true;
          }
          if (plan.action === "round") {
            epRound = plan.nextRound;
            triedEndpoints.clear();
            log("[KRS] 端点回退: 所有端点本轮都限流，" + plan.delayMs + "ms 后开始第 "
              + epRound + "/" + prefs.rounds + " 轮");
            // 落在可用端点上，不能写死 0 —— 0 号可能正是刚探明不支持的那个。
            const restartIdx = typeof plan.index === "number" ? plan.index : 0;
            setTimeout(() => { if (!clientGone) attempt(n, body, key, restartIdx); }, plan.delayMs);
            return true;
          }
          // 轮次用尽：换端点这条路走完了，把决定权交回 handleThrottle 去试换号。
          //
          // 这里绝不能就地退避。早先的写法是在这个分支里直接进入耐心退避并
          // return true，而耐心模式默认是开的，于是 handleThrottle 里排在后面的
          // trySwitchKeyForThrottle 永远拿不到执行机会 —— 限流时全程死磕同一把号，
          // 号池里其它号的并发余量一次也没用上，面板上「自动切换密钥」写的
          // 「被限流时自动换下一把」也就成了空话。
          log("[KRS] 端点回退: " + prefs.rounds + " 轮内所有端点都被限流，改试换号");
          return false;
        };
        // 限流的最后一手：端点和号都试过一圈了，退避一段再从头来。
        //
        // 默认开耐心模式（throttleRetryForever）：不把 429 交回 Kiro，用指数退避一直
        // 重试，只有 Kiro 侧取消（clientGone）才停。关掉它就恢复「都试过即报错」。
        const throttleBackoffWait = () => {
          if (clientGone) return false;
          const patience = getThrottlePatience();
          if (!patience.forever) {
            log("[KRS] 限流: 端点与号都试过了，throttleRetryForever 关着，把 429 交回 Kiro");
            return false;
          }
          const prefs = getEndpointRoundPrefs();
          endlessBackoffMs = nextBackoffMs(endlessBackoffMs, prefs.delayMs, patience.capMs);
          endlessWaitedMs += endlessBackoffMs;
          // 退避的语义是「等限流窗口过去，再完整来一圈」，所以这一圈的「已试过」记录
          // 要一起清掉。不清的话醒来后端点和号都还挂着「试过」，只能在最后那把号上
          // 反复死磕，退避就白等了。
          triedEndpoints.clear();
          triedKeys.clear();
          epRound = 1;
          log("[KRS] 限流退避: " + endlessBackoffMs + "ms 后再来一圈（端点 + 号）"
            + "（已累计等 " + Math.round(endlessWaitedMs / 1000) + "s，稳态上限 "
            + Math.round(patience.capMs / 1000) + "s；关 throttleRetryForever 可恢复旧行为）");
          // 落在可用端点上：写死 0 的话每一轮都白打一次已知不支持的那个端点。
          const idx0 = epChain.findIndex(
            (e) => !isEndpointUnsupported(e.id, getRegion(), statOp));
          setTimeout(() => {
            if (!clientGone) attempt(n, body, key, idx0 >= 0 ? idx0 : 0);
          }, endlessBackoffMs);
          return true;
        };
        // 限流时的换号。端点全试过之后走这里 —— 不同账号有各自独立的并发余量，
        // 换一把号往往立刻就通，比干等一轮退避划算得多。
        //
        // 但绝不给当前 key 记账号状态：429 说明不了这把 key 的好坏，标成「限流中」
        // 只会让面板误导人，还让自动挑号跳过一把其实健康的号。
        //
        // 返回 false 的两种情况（自动切号关着 / 号都试过一圈了）都由调用方接手去做
        // 耐心退避，不会把 429 直接甩回 Kiro。
        const trySwitchKeyForThrottle = () => {
          if (clientGone || !switchCfg.enabled) return false;
          const next = nextUsableKey(triedKeys);
          if (!next) return false;
          log("[KRS] 限流换号: " + maskKey(key) + " → " + maskKey(next)
            + "（端点已全部试过；不标记账号状态）");
          // 换号后端点链重新开一轮：新号的并发余量是独立的。
          triedEndpoints.clear();
          epRound = 1;
          // 换号即"限流跟原号无关"的假设失效，耐心退避从头算。
          endlessBackoffMs = 0;
          endlessWaitedMs = 0;
          adoptKey(next).then(() => { if (!clientGone) attempt(n, body, next, startEpIdx); });
          return true;
        };
        // 限流的完整处置链：换端点（本轮内换 → 多轮退避）→ 换号 → 耐心退避再来一圈。
        // 全程不动 key 状态，只打一个「正在被限流」的显示标记。
        // 三步的先后是有讲究的：端点最便宜（同一把号，两个端点限流桶独立），换号次之
        // （另一个账号有独立的并发余量），干等最贵，所以放最后。
        // 返回 true 表示这轮失败已经被接走，调用方不许再往 res 写任何东西。
        const handleThrottle = (status, bodyText) => {
          if (!isThrottleFailure(status, bodyText)) return false;
          // 标记必须打在这里 —— 这是限流的唯一入口。
          //
          // 先前打在 trySwitchKey 的 throttle 分支里，可是 handleThrottle 一旦接手
          // （换端点或换号成功）调用方就直接 return 了，压根走不到那儿，于是真实限流
          // 全程无标记，面板一直显示「正常」。
          // 只标记、不动状态：不压冷却、不写 _keyHealth，keyIsUsable 完全不看它，
          // 所以挑号照旧能用这把号，单 key 场景也不会被判成不可用。
          noteKeyThrottled(key);
          if (trySwitchEndpoint(status, bodyText)) return true;
          if (trySwitchKeyForThrottle()) return true;
          return throttleBackoffWait();
        };
        // 这把 key 用不了就换下一把，同一个请求内立刻重发；成功与否 Kiro 都只看到
        // 最终结果，所以整个过程对用户是无感的。重试次数不受影响：换 key 不算重试。
        const trySwitchKey = (status, bodyText) => {
          // 先判定并记状态，再看能不能换号。两件事必须分开：换不了号（开关关着、
          // 客户端已经走了）不代表这把号还是好的 —— 早先的写法在那几种情况下直接
          // 返回，连账号状态都不记，于是一把已经被封的号在面板上仍显示正常，后续
          // 每次请求还会继续挑中它。
          const kind = keyFailureKind(status, bodyText);
          if (!kind) return false;
          // 限流不记账号状态：429 是端点级速率问题，跟这把 key 的好坏无关。给它记
          // 「限流中」+ 冷却只会让面板误导人，单 key 场景下更是每隔一两分钟就把唯一
          // 一把好号标成不可用。限流该走的是 handleThrottle（换端点 → 多轮退避 →
          // 换号 → 耐心退避）；那条路都走不通时（比如耐心模式被关掉），这里仍然按
          // 不中断语义继续救，只是不动状态。
          if (kind === "throttle") {
            // 记一笔，但只用于面板显示「限流中」：不压冷却、不改账号状态，
            // keyIsUsable 完全不看它。用户需要看出"此刻正在被限流"，而挑号照旧可以
            // 用这把号 —— 单 key 场景下唯一那把更不能因为限流就被判成不可用。
            noteKeyThrottled(key);
            return keepTrying(maskKey(key) + " 限流（不标记账号状态）");
          }
          coolDownKey(key, kind);
          // 地区填错的表现和密钥失效一模一样，这里顺手在后台复核一次地区。
          recheckRegionOnAuthFailure(key, kind);
          // 当前选中的号已经判死，先让可用的那把接手，下一次请求不必再撞同一面墙。
          // 自动切号关着时 maybeAdoptUsableKey 内部会自己跳过。
          maybeAdoptUsableKey();
          return keepTrying(maskKey(key) + " " + (KIND_LABEL[kind] || kind));
        };

        const upReq = https.request(
          { method: req.method, hostname: target.hostname, port: 443, path: target.pathname + target.search, headers, timeout: 300000, agent: UPSTREAM_AGENT },
          (upRes) => {
            const status = upRes.statusCode || 0;
            const ok = status >= 200 && status < 300;
            log((ok ? "<- [KRS] " : "!! [KRS] ") + keyTag + " -> HTTP " + status + (ok ? " (serving)" : ""));

            // 失败：先把（很小的）错误体缓存下来，在任何字节到达 Kiro 之前判断，
            // 这样重发才能做到透明。
            // 这里不再判断"还有没有牌可打" —— 不中断模式下永远还有牌（换号、等冷却
            // 再来一轮），只有 keepTrying 说不行了才真的把这份错误体发出去。
            if (!ok) {
              const parts = [];
              let size = 0;
              upRes.on("data", (d) => {
                statsAddOutBytes(d.length, key);
                if (size < ERR_BODY_CAP) { parts.push(d); size += d.length; }
              });
              upRes.on("end", () => {
                // 证据要带上抽帧后的正文：分帧的禁用文案只看原始字节匹配不到，
                // 账号状态就永远不会被标记。
                const bodyText = failureEvidence(Buffer.concat(parts).toString("utf8"));
                // 端点能力缺失最先判：这个 400 是我们改道造成的，跟账号无关，
                // 交回 Kiro 就是聊天窗里的红字。
                if (trySwitchEndpointUnsupported(status, bodyText)) { endOnce(false, false); return; }
                // 限流：换端点 → 多轮退避 → 换号 → 退避再来一圈，全程不动 key 状态。
                if (handleThrottle(status, bodyText)) { endOnce(false, false); return; }
                // 上游临时故障：原端点退避重发，不换 key、不换端点。
                if (tryRetryServerError(status, bodyText)) { endOnce(false, false); return; }
                // 带自动回复词的规则再试：它要的是用那句话续接对话，不是换号。
                const replyRule = replyRuleFirst(status, bodyText);
                if (replyRule) { endOnce(false, false); scheduleRetry(replyRule, { beforeSwitch: true }); return; }
                // 其次换 key：这把已经明确不可用，用别的 key 重试才有意义。
                // 换号成功就是一次无感切换，不记错误数。
                if (trySwitchKey(status, bodyText)) { endOnce(false, false); return; }
                if (n < maxAttempts) {
                  const rule = matchedRetryRule(status, bodyText);
                  // 自动重试同样是内部消化，等真的重试不动了才计错误。
                  if (rule) { endOnce(false, false); scheduleRetry(rule); return; }
                }
                // 未命中任何明确规则的 4xx 是确定性的请求错误。换 key、换端点或立即
                // 原样重发都不会改变请求，尤其不能让 400 在 15 分钟预算内形成热循环。
                // 408/425/429 仍属于可恢复失败，429 已在上面的限流链处理；其余未知
                // 失败继续保留不中断兜底。
                if (isDeterministicClientError(status)) {
                  log("!! [KRS] HTTP " + status + " 是不可重试的客户端错误，立即交回 Kiro");
                } else if (keepTrying("HTTP " + status)) {
                  endOnce(false, false);
                  return;
                }
                endOnce(false);
                sendBufferedBody(res, status, upRes.headers, Buffer.concat(parts));
              });
              upRes.on("error", () => {
                if (keepTrying("读取上游响应出错")) { endOnce(false, false); return; }
                endOnce(false);
                sendBufferedBody(res, status, upRes.headers, Buffer.concat(parts));
              });
              return;
            }

            // Accepted upstream: bill the credits now instead of waiting for the
            // stream to finish, so the card moves the moment the answer starts.
            if (ok) statsAddCredits(statOp, statModel, key);

            // 响应头先攥在手里，等开头这批字节到手再决定怎么处理：
            //   开头是错误帧（200 + InternalServerException 之类）或账号禁用提示
            //     → 当成失败走换号 / 自动重试。此时还没往 Kiro 写过一个字节，重发
            //       是透明的，Kiro 只会看到最终结果。
            //   是正常回答 → 立刻放行。
            // 状态码看不出问题的失败就是靠这一步接住的：光看 HTTP 200，自动重试和
            // 自动切号都够不着它。回答中途才出错的没办法，前半段已经交给 Kiro 了。
            let head = [];
            let headSize = 0;
            let decided = false;
            let opened = false;
            let handled = false;      // 已被换号 / 重试接走，这个响应不再转发
            let failedContent = false; // 内容其实是失败（错误帧 / 禁用提示）
            let headTimer = null;
            // 开头已经出现禁用文案的早期信号：判定窗口临时放宽，等关键词到齐。
            let suspectMode = false;
            const dropHeadTimer = () => {
              if (headTimer) { clearTimeout(headTimer); headTimer = null; }
            };
            // 判定用的文本：原始字节对付普通 JSON 错误体，拼回来的正文对付被切成
            // 小帧、关键词跨帧断开的流式回答。两者接在一起当证据。
            const headText = () => {
              const raw = Buffer.concat(head || []).toString("utf8");
              return raw + "\n" + extractStreamText(raw);
            };
            // 放行之后仍然要盯着后续内容。
            //
            // 禁用提示是逐 token 流下来的，关键词完全可能落在判定窗口之外 —— 这种
            // 情况下这一轮的内容已经交给 Kiro 了（聊天窗里能看到那段 suspended
            // 提示），救不回来；但把状态记成「已禁用」能让下一次请求自动换号。
            // 少了这一步，一把已经被封的号会被无限次重复挑中，表现就是"账号禁用后
            // 不会自动切换"。
            let tailScan = "";
            const scanTail = (chunk) => {
              if (tailScan === null) return;
              tailScan += chunk.toString("utf8");
              if (!looksSuspended(tailScan + "\n" + extractStreamText(tailScan))) {
                // 攒到上限还没命中就不再攒，避免长回答一直堆内存。
                if (tailScan.length > TAIL_SCAN_CAP) tailScan = null;
                return;
              }
              tailScan = null;
              failedContent = true;
              log("!! [KRS] " + keyTag + " 回答正文里出现账号被禁用的提示，判为已禁用"
                + "（本轮已转发给 Kiro，下一次请求会自动换号）");
              coolDownKey(key, "suspended");
              maybeAdoptUsableKey();
            };
            // 把攒下的开头连同响应头一起放出去，之后的字节交给 pipe。
            // finalize=true 表示上游已经结束了，直接一次写完收尾（此时不能再
            // pipe：流已经结束，pipe 不会再触发 end，res 会一直挂着）。
            const openStream = (finalize) => {
              if (opened || handled) return;
              opened = true;
              dropHeadTimer();
              res.writeHead(status || 502, stripHopByHop(upRes.headers));
              const buf = head && head.length ? Buffer.concat(head) : null;
              head = null;
              if (finalize) {
                try { res.end(buf || undefined); } catch {}
                return;
              }
              // 已攒的开头接到尾部扫描的起点上：禁用文案的关键词可能正好跨在
              // "放行的这一批"和"后面那一批"之间，不接上就又漏判了。
              if (buf) {
                tailScan = buf.toString("utf8");
                try { res.write(buf); } catch {}
              }
              upRes.pipe(res);
            };
            // 只判一次。返回 true 表示已经被换号 / 重试接走，调用方不要再转发。
            const decide = () => {
              if (decided) return handled;
              decided = true;
              dropHeadTimer();
              const raw = Buffer.concat(head || []).toString("utf8");
              // 证据用 headText()：原始字节对付普通 JSON 错误体，拼回来的正文对付
              // 被切成小帧、关键词跨帧断开的流式回答。后面所有判定都用这一份 ——
              // 只传原始字节的话，分片的禁用文案能进这个分支，却在 keyFailureKind
              // 里又匹配不上，结果判了状态却切不了号。
              const evidence = headText();
              if (looksSuspended(evidence)) {
                failedContent = true;
                log("!! [KRS] " + keyTag + " 上游返回账号被禁用的提示（HTTP " + status + "），判为已禁用");
                if (trySwitchKey(status, evidence)) { handled = true; endOnce(false, false); return true; }
                // 换不了号（自动切号关着 / 没有别的可用号）：trySwitchKey 已经把
                // 状态记成已禁用并试过接管，这里不用再记一遍。
                return false;
              }
              const streamErr = streamErrorText(raw);
              if (streamErr) {
                failedContent = true;
                log("!! [KRS] " + keyTag + " HTTP " + status + " 但内容是错误帧: " + streamErr.slice(0, 160));
                // 错误帧里同样会藏着能力缺失、限流和上游临时故障 —— 状态码是 200，
                // 只看状态码这三条通路都够不着。
                if (trySwitchEndpointUnsupported(status, streamErr)) { handled = true; endOnce(false, false); return true; }
                if (handleThrottle(status, streamErr)) { handled = true; endOnce(false, false); return true; }
                if (tryRetryServerError(status, streamErr)) { handled = true; endOnce(false, false); return true; }
                const replyRule = replyRuleFirst(status, streamErr);
                if (replyRule) {
                  handled = true; endOnce(false, false);
                  scheduleRetry(replyRule, { beforeSwitch: true });
                  return true;
                }
                if (trySwitchKey(status, streamErr)) { handled = true; endOnce(false, false); return true; }
                if (n < maxAttempts) {
                  const rule = matchedRetryRule(status, streamErr);
                  if (rule) { handled = true; endOnce(false, false); scheduleRetry(rule); return true; }
                }
                // 错误帧但说不上是哪把号的问题（比如上游内部异常）：不中断模式下
                // 换个号再试，别把这个错误帧交给 Kiro 显示成"Something went wrong"。
                if (keepTrying("流内错误帧")) { handled = true; endOnce(false, false); return true; }
                return false;
              }
              if (ok) {
                clearCooldown(key); // 拿到了正常回答，这把 key 确实是好的
                return false;
              }
              // 失败响应走到这里：先按端点级问题处理（这些都跟 key 的好坏无关），
              // 再记账号状态，最后交给不中断兜底 —— 能换号 / 能等冷却就绝不把失败
              // 交回 Kiro。
              if (trySwitchEndpointUnsupported(status, evidence)) { handled = true; endOnce(false, false); return true; }
              if (handleThrottle(status, evidence)) { handled = true; endOnce(false, false); return true; }
              if (tryRetryServerError(status, evidence)) { handled = true; endOnce(false, false); return true; }
              const kind = keyFailureKind(status, evidence);
              // 限流除外：429 是端点级并发问题，跟这把 key 的好坏无关，不压冷却也
              // 不改账号状态。但要记一笔用于面板显示 —— 让用户看出此刻在被限流，
              // 跟"号坏了"是两回事（这个标记不参与挑号）。
              if (kind === "throttle") noteKeyThrottled(key);
              if (kind && kind !== "throttle") {
                coolDownKey(key, kind);
                recheckRegionOnAuthFailure(key, kind);
                maybeAdoptUsableKey();
              }
              if (keepTrying(kind ? maskKey(key) + " " + (KIND_LABEL[kind] || kind) : "HTTP " + status)) {
                handled = true;
                endOnce(false, false);
                return true;
              }
              return false;
            };
            upRes.on("data", (d) => {
              statsAddOutBytes(d.length, key);
              if (handled) return;
              // 已经放行了：内容照旧由 pipe 转发，这里只继续扫描禁用文案，好让
              // 下一次请求能换号。
              if (opened) { scanTail(d); return; }
              head.push(d);
              headSize += d.length;
              // 开头出现禁用文案的早期信号就切到更宽的判定窗口，把关键词等齐。
              // 已经设好的短定时器必须撤掉重设，否则 300ms 一到照样提前放行。
              if (!suspectMode && !decided && maybeSuspendedPrefix(headText())) {
                suspectMode = true;
                dropHeadTimer();
                log("[KRS] " + keyTag + " 开头出现账号异常的迹象，延长判定窗口后再决定是否换号");
              }
              const minBytes = suspectMode ? SUSPECT_MIN_BYTES : HEAD_MIN_BYTES;
              const waitMs = suspectMode ? SUSPECT_WAIT_MS : HEAD_WAIT_MS;
              if (headSize < minBytes && !decided) {
                // 开头太碎，等下一个 chunk；上游要是迟迟不发，定时器兜底放行。
                if (!headTimer) {
                  headTimer = setTimeout(() => {
                    headTimer = null;
                    if (opened || handled) return;
                    if (decide()) { try { upRes.destroy(); } catch {} return; }
                    openStream(false);
                  }, waitMs);
                }
                return;
              }
              // 被接走就把上游这条响应丢掉，别再收它的数据。
              if (decide()) { try { upRes.destroy(); } catch {} return; }
              openStream(false);
            });
            upRes.on("end", () => {
              dropHeadTimer();
              if (handled) return;
              if (!opened) {
                if (decide()) { try { upRes.destroy(); } catch {} return; }
                openStream(true);
              }
              // 内容其实是失败的话，这轮对话对 Kiro 来说等于没成，计进错误数。
              endOnce(ok && !failedContent);
            });
            upRes.on("close", () => {
              dropHeadTimer();
              if (handled) return;
              if (!opened) {
                if (decide()) { try { upRes.destroy(); } catch {} return; }
                openStream(true);
              }
              endOnce(ok && !failedContent);
            });
            upRes.on("error", () => {
              dropHeadTimer();
              if (handled) return;
              // 还没放行的话可以完全透明地重来一次；已经放行的救不回来（前半段
              // 回答早就到 Kiro 那边了），只能把流收掉。
              if (!opened && keepTrying("上游响应中断")) {
                handled = true;
                endOnce(false, false);
                return;
              }
              endOnce(false);
              if (!opened) {
                // 响应头还攥在手里：把攒下的那点内容按实际长度交回去，不能带着
                // 上游那个对不上的 content-length 发一个空 body。
                opened = true;
                const buf = head && head.length ? Buffer.concat(head) : null;
                head = null;
                sendBufferedBody(res, status, upRes.headers, buf);
                return;
              }
              try { res.end(); } catch {}
            });
          }
        );
        upReq.on("error", (e) => {
          log("!! [KRS] " + keyTag + " upstream error: " + e.message);
          if (!res.headersSent) {
            // 传输层故障先原地退避重发：请求根本没到达上游（TLS 握手被本机代理掐断、
            // DNS 临时失败、连接被重置），重发不会重复计费也不会产生两份回答，比换号
            // 更安全也更可能成功 —— 换号对"网络本身不通"毫无帮助。
            if (tryRetryServerError(0, e.message)) { endOnce(false, false); return; }
            // 传输层错误一般跟 key 无关，keyFailureKind 只在文本里真出现限流 /
            // 失效字样时才会命中。换号或重试接住了就不记错误数。
            const replyRule = replyRuleFirst(0, e.message);
            if (replyRule) { endOnce(false, false); scheduleRetry(replyRule, { beforeSwitch: true }); return; }
            if (trySwitchKey(0, e.message)) { endOnce(false, false); return; }
            if (n < maxAttempts) {
              const rule = matchedRetryRule(0, e.message);
              if (rule) { endOnce(false, false); scheduleRetry(rule); return; }
            }
            // 网络抖动、DNS 失败、连接被重置：还没往 Kiro 写过一个字节，换个号
            // 重发对它完全透明，不该让这轮对话就这么断掉。
            if (keepTrying("传输层错误 " + e.message)) { endOnce(false, false); return; }
          }
          endOnce(false);
          if (!res.headersSent) res.writeHead(502, { "Content-Type": "application/json" });
          try { res.end(JSON.stringify({ message: "upstream error: " + e.message })); } catch {}
        });
        upReq.on("timeout", () => upReq.destroy(new Error("upstream timeout")));
        if (sendBody.length) upReq.write(sendBody);
        upReq.end();
      };

      attempt(1, bodyBuf, startKey);
    });
  };
}

// CPS (control plane) handler. kiro-agent may ask for the model list / usage
// via an awsJson call (POST / with x-amz-target) rather than the REST GET path,
// so blind passthrough can hit UnknownOperation and yield an EMPTY model list
// (the "cannot select model" symptom). We DETECT the operation and answer it
// with the known-good management GET call, returning the raw JSON verbatim so
// the format Kiro expects is preserved.
// 识别这次 CPS 请求是哪个操作。路径寻址和 x-amz-target 寻址两种都要认。
function cpsOpOf(req) {
  const clean = (req.url || "/").split("?")[0];
  const amzTarget = String(req.headers["x-amz-target"] || req.headers["x-amzn-target"] || "");
  const norm = (s) => String(s).replace(/[^a-z0-9]/gi, "").toLowerCase();
  const k = norm(clean) + "|" + norm(amzTarget);
  if (k.includes("availablemodels")) return "models";
  if (k.includes("usagelimit")) return "usage";
  return "";
}
function makeCpsHandler() {
  // 控制平面一律原样透传，额外挂一个旁路嗅探，把插件自己要的那点数据（模型计费
  // 倍率、账号用量）顺手记下来 —— 转发给 Kiro 的字节不受任何影响。
  //
  // 早先"用量"和"模型列表"这两个操作是截下来自己重发一遍的，那样做丢了四样东西：
  //   1. Kiro 的原始查询参数被硬编码顶替（resourceType 永远是 AGENTIC_REQUEST），
  //      IDE 要哪份数据都只能拿到这一份
  //   2. 请求体被 req.resume() 直接丢弃
  //   3. 官方响应头全部丢掉，只补一个 Content-Type
  //   4. 请求失败时回一个 HTTP 200 + {} 假装成功
  // 结果就是 IDE 里那个百分比圆圈拿不到它真正请求的数据 —— 要么是别的资源类型的
  // 数字，要么干脆是空对象。而 Kiro 又要靠这个百分比判断该不该压缩上下文，圆圈
  // 不准，压缩就不触发，上下文一路堆到爆。
  // 现在官方下发什么，IDE 就收到什么，原封不动。
  const passthrough = makeProxyHandler("CPS", managementBase, {
    sniff: (bodyText, status, req) => {
      if (status < 200 || status >= 300 || !bodyText) return;
      const op = cpsOpOf(req);
      if (op === "models") {
        // 缓存每个模型的计费倍率，用于按真实费率归集每次请求的积分消耗。
        rememberModelRates(bodyText);
        return;
      }
      if (op === "usage") noteUsageFromBody(getApiKey(), bodyText);
    },
  });
  return function handle(req, res) {
    if (req.url === HEALTH_PATH) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(HEALTH_MARKER);
      return;
    }
    if (!getApiKey()) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Kiro Gateway: no API key configured." }));
      return;
    }
    markProxyHit("CPS", req);
    // 所有控制平面操作走同一条路：换凭证 + 原样转发 + 原样回传。
    passthrough(req, res);
  };
}

// ---------------------------------------------------------------------------
// Port binder: bind locally, reuse if a sibling instance already holds it.
// ---------------------------------------------------------------------------
class ProxyServer {
  constructor(port, handler, label) {
    this.port = port;
    this.handler = handler;
    this.label = label;
    this.server = null;
    this.pending = null;
    this.stopped = false;
    this.retryTimer = null;
    // 端口到底归谁，面板顶栏靠它区分四种情况：
    //   listening 自己绑上了，请求由本窗口转发
    //   standby   端口被另一个 Kiro 窗口的同类网关占着 —— 这是正常的多窗口共享，
    //             请求由那个窗口代转，它退出后本窗口会自动接管，不是错误
    //   conflict  端口被无关程序占着，得换端口或者关掉那个程序
    //   idle      没启动
    // 早先这两种占用都只在日志里写一行，面板上看不出区别，用户只能看到"端口被占"
    // 然后无从下手。
    this.state = "idle";
  }
  start() {
    this.stopped = false;
    this._tryBind();
  }
  _tryBind() {
    if (this.stopped) return;
    const srv = http.createServer(this.handler);
    this.pending = srv;
    srv.on("error", (e) => {
      if (this.pending === srv) this.pending = null;
      try { srv.close(); } catch {}
      if (e.code === "EADDRINUSE") {
        log("!! [" + this.label + "] port " + this.port + " is in use; checking whether it is another healthy gateway");
        // 占用者是不是自己的同类？是就说明另一个 Kiro 窗口已经把网关起好了，本窗口
        // 待命就行，不该当成故障报给用户；不是才是真冲突。
        this.isReachable().then((sameKind) => {
          if (this.stopped || this.server) return;
          this.state = sameKind ? "standby" : "conflict";
          log("[" + this.label + "] 端口 " + this.port
            + (sameKind ? " 由另一个窗口的网关持有，本窗口待命" : " 被无关程序占用"));
          if (panelProvider) panelProvider.pushState();
        }).catch(() => {});
      } else {
        this.state = "conflict";
        log("!! [" + this.label + "] listen error: " + e.message);
        if (panelProvider) panelProvider.pushState();
      }
      this._scheduleRetry();
    });
    srv.listen(this.port, "127.0.0.1", () => {
      if (this.stopped) {
        try { srv.close(); } catch {}
        if (this.pending === srv) this.pending = null;
        return;
      }
      this.server = srv;
      this.pending = null;
      // 抢到端口了（可能是首次，也可能是原持有者退出后本窗口接管）。
      const wasStandby = this.state === "standby";
      this.state = "listening";
      log("[" + this.label + "] listening on 127.0.0.1:" + this.port
        + (wasStandby ? "（已从另一个窗口接管）" : ""));
      if (panelProvider) panelProvider.pushState();
    });
  }
  _scheduleRetry() {
    if (this.stopped || this.retryTimer) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this._tryBind();
    }, 3000);
  }
  async isReachable() {
    if (this.server) return true;
    return new Promise((resolve) => {
      const req = http.request(
        { host: "127.0.0.1", port: this.port, path: HEALTH_PATH, method: "GET", timeout: 1000 },
        (r) => {
          const c = [];
          r.on("data", (d) => c.push(d));
          r.on("end", () => resolve(Buffer.concat(c).toString("utf8").includes(HEALTH_MARKER)));
        }
      );
      req.on("error", () => resolve(false));
      req.on("timeout", () => { req.destroy(); resolve(false); });
      req.end();
    });
  }
  async waitUntilReachable(timeoutMs = 6000) {
    const deadline = Date.now() + timeoutMs;
    do {
      if (await this.isReachable()) return true;
      await sleep(150);
    } while (!this.stopped && Date.now() < deadline);
    log("!! [" + this.label + "] health check failed on 127.0.0.1:" + this.port);
    return false;
  }
  stop() {
    this.stopped = true;
    this.state = "idle";
    if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
    if (this.server) { try { this.server.close(); } catch {} this.server = null; }
    if (this.pending) { try { this.pending.close(); } catch {} this.pending = null; }
  }
}

// 把两个平面的端口状态汇总成顶栏那一个词。
//   off      网关开关是关的，Kiro 走自己的端点
//   conflict 至少一个端口被无关程序占着 —— 最需要用户动手，优先暴露
//   standby  端口由另一个 Kiro 窗口的网关持有，本窗口待命（多窗口共享的正常态）
//   running  两个平面都归本窗口
//   starting 还在绑定
function gatewayRuntimeState() {
  if (!isEnabled()) return "off";
  const states = [krsServer, cpsServer].filter(Boolean).map((s) => s.state);
  if (!states.length) return "starting";
  if (states.includes("conflict")) return "conflict";
  if (states.every((s) => s === "listening")) return "running";
  if (states.includes("standby")) return "standby";
  return "starting";
}
// 面板要显示是哪个端口出的问题，所以按平面分开报一份。
function gatewayPlaneStates() {
  return {
    krs: (krsServer && krsServer.state) || "idle",
    cps: (cpsServer && cpsServer.state) || "idle",
  };
}

// ---------------------------------------------------------------------------
// codewhisperer.config endpoint override (redirect kiro-agent to our proxy)
// ---------------------------------------------------------------------------
// Regions we advertise as redirected. Our single local proxy handles all of
// them and forwards to the user's configured region, so kiro-agent hits us no
// matter which region it thinks it is using. This is a STATIC baseline; the
// user's currently-selected region is always merged in at write time (see
// redirectRegions) so a key issued in, say, ap-southeast-2 still gets its
// endpoint rewritten — otherwise kiro-agent would silently bypass the proxy
// and talk to AWS directly for that region.
const REDIRECT_REGIONS = ["us-east-1", "eu-central-1"];
// The regions to actually write, always including the active region so the
// redirect can never miss the plane kiro-agent is really using. 自动识别的候选
// 区域也一起写进去：识别结果随时可能从一个候选切到另一个，端点表提前覆盖全部
// 候选，切换时就不必再等一次重载。
function redirectRegions() {
  return [...new Set([getRegion(), ...REGION_CANDIDATES, ...REDIRECT_REGIONS]
    .map((r) => String(r || "").trim())
    .filter(Boolean))];
}

// Locate the active profile's settings.json. In profile-enabled Kiro builds,
// globalStorageUri itself is profile-scoped, so walking up from
// <profile>/globalStorage/<extension-id> lands in the correct profile rather
// than always writing the default User/settings.json.
function userSettingsPath() {
  try {
    const gs = extContext.globalStorageUri.fsPath;
    return path.join(path.resolve(gs, "..", ".."), "settings.json");
  } catch {
    return "";
  }
}
function parseSettingsJson(raw) {
  const text = String(raw || "").replace(/^\uFEFF/, "");
  const stripped = text
    .replace(/\\"|"(?:\\"|[^"])*"|(\/\/[^\n\r]*|\/\*[\s\S]*?\*\/)/g, (m, c) => (c ? "" : m))
    .replace(/,(\s*[}\]])/g, "$1");
  return JSON.parse(stripped || "{}");
}
function fullEndpointKey(key) {
  return "codewhisperer.config." + key;
}
function normalizeEndpointList(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((e) => e && typeof e === "object")
    .map((e) => ({
      region: String(e.region || "").trim(),
      endpoint: String(e.endpoint || "").trim().replace(/\/$/, ""),
    }))
    .filter((e) => e.region && e.endpoint)
    .sort((a, b) => a.region.localeCompare(b.region) || a.endpoint.localeCompare(b.endpoint));
}
function endpointListsEqual(a, b) {
  return JSON.stringify(normalizeEndpointList(a)) === JSON.stringify(normalizeEndpointList(b));
}
function endpointOverride(port) {
  return redirectRegions().map((region) => ({ region, endpoint: "http://127.0.0.1:" + port }));
}
function readEndpointFromSettingsFile(key) {
  const file = userSettingsPath();
  if (!file || !fsMod.existsSync(file)) return undefined;
  try {
    return parseSettingsJson(fsMod.readFileSync(file, "utf8"))[fullEndpointKey(key)];
  } catch (e) {
    log("!! settings.json read failed (" + file + "): " + (e?.message || e));
    return undefined;
  }
}
// Fallback for Kiro builds that consume these hidden settings but do not
// register them with VS Code's configuration schema. The write is verified by
// reading the exact active-profile file back; "write succeeded" alone is not
// treated as proof anymore.
function writeEndpointToSettingsFile(key, value) {
  const file = userSettingsPath();
  if (!file) return { ok: false, file: "" };
  try {
    fsMod.mkdirSync(path.dirname(file), { recursive: true });
    const raw = fsMod.existsSync(file) ? fsMod.readFileSync(file, "utf8") : "{}";
    const obj = parseSettingsJson(raw);
    obj[fullEndpointKey(key)] = value;
    const backup = file + ".kiro-gateway.bak";
    if (fsMod.existsSync(file) && !fsMod.existsSync(backup)) {
      try { fsMod.copyFileSync(file, backup); } catch {}
    }
    const tmp = file + ".kiro-gateway.tmp";
    fsMod.writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n", "utf8");
    try {
      fsMod.renameSync(tmp, file);
    } catch {
      fsMod.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n", "utf8");
      try { fsMod.unlinkSync(tmp); } catch {}
    }
    const readBack = readEndpointFromSettingsFile(key);
    const ok = endpointListsEqual(readBack, value);
    log((ok ? "endpoint disk verification OK" : "!! endpoint disk verification FAILED")
      + " for " + fullEndpointKey(key) + " file=" + file);
    return { ok, file };
  } catch (e) {
    log("!! settings.json fallback failed (" + file + "): " + (e?.message || e));
    return { ok: false, file };
  }
}
async function waitForEndpointReadback(cw, key, expected, timeoutMs = 2500) {
  const deadline = Date.now() + timeoutMs;
  do {
    if (endpointListsEqual(cw.get(key), expected)) return true;
    await sleep(100);
  } while (Date.now() < deadline);
  return endpointListsEqual(cw.get(key), expected);
}
function logEndpointScopes(cw, key) {
  const i = cw.inspect(key);
  if (!i) {
    log("endpoint config inspect: " + fullEndpointKey(key) + " is not registered/visible through Configuration API");
    return;
  }
  const scopes = ["globalValue", "workspaceValue", "workspaceFolderValue"]
    .filter((name) => i[name] !== undefined)
    .join(",") || "default-only";
  log("endpoint config inspect: " + fullEndpointKey(key) + " scopes=" + scopes);
}
function hasHigherScopeConflict(cw, key, expected) {
  const i = cw.inspect(key);
  if (!i) return false;
  const higher = i.workspaceFolderValue !== undefined ? i.workspaceFolderValue : i.workspaceValue;
  return higher !== undefined && !endpointListsEqual(higher, expected);
}
async function updateWithRetry(cw, key, value, attempts = 4) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      await cw.update(key, value, vscode.ConfigurationTarget.Global);
      return true;
    } catch (e) {
      lastErr = e;
      const msg = String(e?.message || e);
      if (/not (?:a )?registered configuration|没有注册配置|未注册/i.test(msg)) break;
      await sleep(250 * (i + 1));
    }
  }
  throw lastErr;
}
async function overrideEndpoint(key, port, backupKey) {
  const cw = vscode.workspace.getConfiguration("codewhisperer.config");
  const expected = endpointOverride(port);
  const effective = cw.get(key) ?? [];
  const disk = readEndpointFromSettingsFile(key);
  if (!globalThis[backupKey]) {
    const current = effective.length ? effective : (disk ?? []);
    const isLocal = Array.isArray(current) && current.some((e) => /127\.0\.0\.1|localhost/.test(e?.endpoint ?? ""));
    globalThis[backupKey] = isLocal ? [] : current;
  }
  // Exact, region-complete comparison. The old `.some(localhost)` check
  // incorrectly skipped rewrites when only one of several regions matched.
  const effectiveMatches = endpointListsEqual(effective, expected);
  const diskMatches = endpointListsEqual(disk, expected);
  if (effectiveMatches) {
    log("endpoint verification OK: " + fullEndpointKey(key)
      + " regions=" + redirectRegions().join(",")
      + " source=effective-config");
    return { changed: false, ok: true };
  }
  // 磁盘上已经是 127.0.0.1，但 Kiro 实际调用的是 get()。键没注册时 get() 一直是空的，
  // 插件却把「磁盘对了」当成成功，模型列表和对话都继续走官方地址。
  if (diskMatches && hasHigherScopeConflict(cw, key, expected)) {
    log("!! active-profile endpoint is correct on disk but blocked by workspace/folder settings: " + fullEndpointKey(key));
    return { changed: false, ok: false };
  }
  if (diskMatches) {
    log("!! " + fullEndpointKey(key) + " 磁盘已指向本机代理，Kiro 的生效配置不是。改为写入 Configuration API。 file=" + userSettingsPath());
  }
  logEndpointScopes(cw, key);
  try {
    await updateWithRetry(cw, key, expected);
    if (await waitForEndpointReadback(cw, key, expected)) {
      log("endpoint effective-config verification OK: " + fullEndpointKey(key) + " -> 127.0.0.1:" + port);
      return { changed: true, ok: true };
    }
    log("!! Configuration API returned success but readback mismatched for " + fullEndpointKey(key));
  } catch (e) {
    log("config API write unavailable for " + key + "; using active-profile settings.json: " + (e?.message || e));
  }
  const written = writeEndpointToSettingsFile(key, expected);
  if (written.ok) {
    const effectiveOk = await waitForEndpointReadback(cw, key, expected);
    if (!effectiveOk && hasHigherScopeConflict(cw, key, expected)) {
      log("!! endpoint override blocked by workspace/folder settings: " + fullEndpointKey(key));
      vscode.window.showErrorMessage(
        "Kiro Gateway: 工作区设置覆盖了 " + fullEndpointKey(key)
        + "，请删除工作区中的同名配置后重新加载窗口。"
      );
      return { changed: true, ok: false };
    }
    log("endpoint override verified via settings.json -> 127.0.0.1:" + port
      + (effectiveOk ? " (effective config updated)" : " (disk verified; reload required)"));
    return { changed: true, ok: true };
  }
  vscode.window.showErrorMessage(
    "Kiro Gateway: 无法写入或验证 " + fullEndpointKey(key)
    + "。请打开日志查看实际 settings.json 路径。"
  );
  return { changed: false, ok: false };
}
async function restoreEndpoint(key, backupKey) {
  const cw = vscode.workspace.getConfiguration("codewhisperer.config");
  let restore = globalThis[backupKey] ?? [];
  if (Array.isArray(restore) && restore.some((e) => /127\.0\.0\.1|localhost/.test(e?.endpoint ?? ""))) restore = [];
  const effective = cw.get(key);
  const disk = readEndpointFromSettingsFile(key);
  if (endpointListsEqual(effective, restore) && endpointListsEqual(disk ?? restore, restore)) return false;
  try {
    await updateWithRetry(cw, key, restore);
    if (await waitForEndpointReadback(cw, key, restore)) {
      log(key + " restored -> Kiro official (verified)");
      return true;
    }
  } catch (e) {
    log("config API restore unavailable for " + key + "; using settings.json: " + (e?.message || e));
  }
  const written = writeEndpointToSettingsFile(key, restore);
  if (written.ok) log(key + " restored via settings.json -> Kiro official (disk verified)");
  return written.ok;
}

// Bind only after both listeners pass their health checks, then persist and
// verify both endpoint overrides. This avoids the old fixed-400ms startup race.
async function syncEndpoints() {
  const { krs, cps } = activePorts();
  const [krsOk, cpsOk] = await Promise.all([
    krsServer ? krsServer.waitUntilReachable() : false,
    cpsServer ? cpsServer.waitUntilReachable() : false,
  ]);
  if (isEnabled() && credentialsReady() && krsOk && cpsOk) {
    const a = await overrideEndpoint("krsEndpoints", krs, "__kiroKeyOrigKrs");
    const b = await overrideEndpoint("cpsEndpoints", cps, "__kiroKeyOrigCps");
    const ok = a.ok && b.ok;
    log(ok
      ? "gateway endpoint verification complete: KRS/CPS ready; reload Kiro if no proxy request appears"
      : "!! gateway endpoint verification incomplete: KRS/CPS override is partial");
    return { bound: ok, changed: a.changed || b.changed };
  }
  const a = await restoreEndpoint("krsEndpoints", "__kiroKeyOrigKrs");
  const b = await restoreEndpoint("cpsEndpoints", "__kiroKeyOrigCps");
  return { bound: false, changed: a || b };
}

// ---------------------------------------------------------------------------
// Registry self-heal: survive window reloads (Kiro tends to mark sideloaded
// extensions .obsolete / drop them from extensions.json). Only ever touches
// THIS extension's own entries.
// ---------------------------------------------------------------------------
function myExtId() {
  return extContext?.extension?.id || "local.kiro-gateway";
}
function myExtDirName() {
  try { return path.basename(extContext.extensionPath); } catch { return ""; }
}
function extensionsRootDir() {
  try { return path.resolve(extContext.extensionPath, ".."); } catch { return ""; }
}
function readJsonSafe(file, fallback) {
  try {
    const raw = fsMod.readFileSync(file, "utf8").trim();
    return raw ? JSON.parse(raw) : fallback;
  } catch { return fallback; }
}
function writeJsonSafe(file, data) {
  const text = JSON.stringify(data);
  try {
    if (fsMod.existsSync(file) && !fsMod.existsSync(file + ".kkbak")) fsMod.copyFileSync(file, file + ".kkbak");
  } catch {}
  const tmp = file + ".kktmp";
  fsMod.writeFileSync(tmp, text, "utf8");
  fsMod.renameSync(tmp, file);
}
function cleanObsoleteSelf() {
  const root = extensionsRootDir();
  if (!root) return false;
  const obsPath = path.join(root, ".obsolete");
  if (!fsMod.existsSync(obsPath)) return false;
  const obs = readJsonSafe(obsPath, null);
  if (!obs || typeof obs !== "object") return false;
  const dirName = myExtDirName();
  let changed = false;
  for (const k of Object.keys(obs)) {
    if (k === dirName || k.startsWith(myExtId())) { delete obs[k]; changed = true; }
  }
  if (changed) { writeJsonSafe(obsPath, obs); log("self-heal: removed self from .obsolete"); }
  return changed;
}
function ensureRegistered() {
  const root = extensionsRootDir();
  if (!root) return false;
  const file = path.join(root, "extensions.json");
  const list = readJsonSafe(file, null);
  if (!Array.isArray(list)) return false;
  const id = myExtId();
  if (list.some((e) => e?.identifier?.id === id)) return false;
  const version = extContext?.extension?.packageJSON?.version || "1.0.0";
  const dirName = myExtDirName();
  list.push({
    identifier: { id },
    version,
    location: { $mid: 1, path: extContext.extensionPath, scheme: "file" },
    relativeLocation: dirName,
    metadata: {
      isApplicationScoped: false, isMachineScoped: false, isBuiltin: false,
      installedTimestamp: Date.now(), pinned: false, source: "vsix",
      updated: false, private: false, isPreReleaseVersion: false,
      hasPreReleaseVersion: false, preRelease: false,
    },
  });
  writeJsonSafe(file, list);
  log("self-heal: registered self in extensions.json");
  return true;
}
function selfHeal() {
  try { cleanObsoleteSelf(); } catch (e) { log("cleanObsoleteSelf failed: " + (e?.message || e)); }
  try { ensureRegistered(); } catch (e) { log("ensureRegistered failed: " + (e?.message || e)); }
}
function registryHealth() {
  const root = extensionsRootDir();
  const out = { registered: false, obsolete: false };
  if (!root) return out;
  const list = readJsonSafe(path.join(root, "extensions.json"), null);
  if (Array.isArray(list)) out.registered = list.some((e) => e?.identifier?.id === myExtId());
  const obs = readJsonSafe(path.join(root, ".obsolete"), null);
  if (obs && typeof obs === "object") {
    const dirName = myExtDirName();
    out.obsolete = Object.keys(obs).some((k) => k === dirName || k.startsWith(myExtId()));
  }
  return out;
}

// ---------------------------------------------------------------------------
// 装了新包但还没重载的检测
// ---------------------------------------------------------------------------
// 侧载 VSIX 时 Kiro 不一定会弹「需要重新加载」，于是新代码明明已经躺在磁盘上，
// 跑着的却还是旧实例，只能靠重启整个 Kiro。这里由旧实例自己发现这件事并提示：
//   1) 扩展目录里出现了同 id 的更高版本 → 正常升级
//   2) 自己目录里的文件被覆盖（版本号没变的重复打包）→ 指纹变了
// 两种都只需要重新加载窗口，不必重启 Kiro。
const UPDATE_POLL_MS = 10000;
let _selfStamp = "";          // 启动时自身文件的指纹
let _pendingUpdate = null;    // { version, reason }
let _updateTimer = null;
let _updateNotified = false;  // 弹窗只弹一次，横幅和状态栏则一直留着

function fileStamp(file) {
  try {
    const st = fsMod.statSync(file);
    return st.size + ":" + Math.round(st.mtimeMs);
  } catch { return "-"; }
}
// 自身关键文件的指纹。覆盖安装同一个版本号时，目录名不变但文件会被换掉。
function computeSelfStamp() {
  const dir = extContext?.extensionPath || "";
  if (!dir) return "";
  return ["extension.js", "package.json", path.join("webview-ui", "dist", "index.html")]
    .map((f) => fileStamp(path.join(dir, f)))
    .join("|");
}
function cmpVersion(a, b) {
  const pa = String(a).split(/[.\-+]/);
  const pb = String(b).split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = parseInt(pa[i], 10) || 0;
    const nb = parseInt(pb[i], 10) || 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}
// 磁盘上这个扩展的最高版本：先看注册表，再扫 <id>-<version> 目录名兜底。
function newestInstalledVersion() {
  const root = extensionsRootDir();
  const id = myExtId().toLowerCase();
  let best = currentVersion();
  const consider = (v) => {
    const clean = cleanVersion(v);
    if (clean && cmpVersion(clean, best) > 0) best = clean;
  };
  const list = readJsonSafe(path.join(root, "extensions.json"), null);
  if (Array.isArray(list)) {
    for (const e of list) {
      if (String(e?.identifier?.id || "").toLowerCase() === id) consider(e?.version);
    }
  }
  try {
    for (const name of fsMod.readdirSync(root)) {
      const lower = name.toLowerCase();
      if (!lower.startsWith(id + "-")) continue;
      consider(name.slice(id.length + 1));
    }
  } catch {}
  return best;
}
// 检查一次，返回待生效的更新（没有则 null）。
function detectPendingUpdate() {
  if (!extContext) return null;
  const newest = newestInstalledVersion();
  if (cmpVersion(newest, currentVersion()) > 0) {
    return { version: newest, reason: "newer-version" };
  }
  const stamp = computeSelfStamp();
  if (_selfStamp && stamp && stamp !== _selfStamp) {
    return { version: currentVersion(), reason: "reinstalled" };
  }
  return null;
}
function pendingUpdateInfo() {
  if (!_pendingUpdate) return null;
  return {
    version: _pendingUpdate.version,
    running: currentVersion(),
    reason: _pendingUpdate.reason,
  };
}
async function announcePendingUpdate(found) {
  _pendingUpdate = found;
  const isNewer = found.reason === "newer-version";
  const text = isNewer
    ? "Kiro Gateway 已安装新版本 v" + found.version + "（当前运行 v" + currentVersion() + "）"
    : "Kiro Gateway 的插件文件已更新（v" + found.version + "）";
  log("检测到待生效的插件更新: " + found.reason + " -> v" + found.version
    + "（运行中 v" + currentVersion() + "），重新加载窗口即可生效");
  updateStatusBar();
  if (panelProvider) panelProvider.pushState();
  if (_updateNotified) return;
  _updateNotified = true;
  // 打开了自动重载就直接重载，留一点时间把日志和面板状态刷出去。
  if (pref("autoReloadOnUpdate", false) === true) {
    log("自动重载已开启，1.5 秒后重新加载窗口");
    vscode.window.setStatusBarMessage("Kiro Gateway：检测到更新，正在重新加载窗口…", 3000);
    setTimeout(() => { vscode.commands.executeCommand("workbench.action.reloadWindow"); }, 1500);
    return;
  }
  const pick = await vscode.window.showInformationMessage(
    text + "，重新加载窗口即可生效（不用重启 Kiro）。",
    "重新加载窗口",
    "稍后"
  );
  if (pick === "重新加载窗口") await vscode.commands.executeCommand("workbench.action.reloadWindow");
}
function checkForPendingUpdate() {
  if (_pendingUpdate) return; // 已经在提示了
  let found = null;
  try { found = detectPendingUpdate(); } catch (e) { log("!! 更新检测失败: " + (e?.message || e)); }
  if (found) announcePendingUpdate(found);
}
// 事件 + 轮询双保险：onDidChange 在部分 Kiro 构建里不触发，而扫目录很轻。
function startUpdateWatch() {
  _selfStamp = computeSelfStamp();
  checkForPendingUpdate();
  if (_updateTimer) clearInterval(_updateTimer);
  _updateTimer = setInterval(checkForPendingUpdate, UPDATE_POLL_MS);
  try {
    return vscode.extensions.onDidChange(() => checkForPendingUpdate());
  } catch {
    return { dispose() {} };
  }
}
function stopUpdateWatch() {
  if (_updateTimer) { clearInterval(_updateTimer); _updateTimer = null; }
}

// ---------------------------------------------------------------------------
// Direct API calls (used by the Test button and the panel's model/usage view)
// ---------------------------------------------------------------------------
function apiGet(base, urlPath, key, opts = {}) {
  const k = String(key || getApiKey() || "").trim();
  return Promise.resolve(resolveAuth(k)).then((auth) => apiGetWithAuth(base, urlPath, auth, opts));
}
function apiGetWithAuth(base, urlPath, auth, opts = {}) {
  const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs) : 30000;
  const path = auth.type === "apikey"
    ? stripProfileArnFromUrl(urlPath)
    : applyProfileArnToUrl(urlPath, auth.profileArn);
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(base + path); } catch (e) { return reject(e); }
    const headers = {
      Accept: "application/json",
      Authorization: "Bearer " + auth.token,
      "x-amzn-kiro-agent-mode": "vibe",
      "user-agent": kiroUserAgent(),
    };
    if (auth.type === "apikey") headers.tokentype = "API_KEY";
    else if (auth.tokenType) headers.tokentype = auth.tokenType;
    const req = https.request(
      {
        method: "GET",
        hostname: target.hostname,
        port: 443,
        path: target.pathname + target.search,
        headers,
        timeout: timeoutMs,
        agent: UPSTREAM_AGENT,
      },
      (res) => {
        const c = [];
        res.on("data", (d) => c.push(d));
        res.on("end", () => resolve({ statusCode: res.statusCode || 0, body: Buffer.concat(c).toString("utf8") }));
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.end();
  });
}
// 带上状态码和响应体的错误：账号状态判定要靠状态码，不能从错误文本里正则捞
// 数字（正文里随便一个 403 就会把正常账号判成失效）。
function httpError(status, body) {
  const text = String(body || "");
  const e = new Error("HTTP " + status + ": " + text.slice(0, 200));
  e.status = Number(status) || 0;
  e.body = text;
  return e;
}
// 单把密钥用哪个区域。自动模式下，和 profileArn 一致的缓存优先；缓存和
// profile 矛盾（用量 200 误判）时直接用 profile 区域，不再听那个缓存。
function regionForKey(key) {
  const preferred = preferredRegionFor(key);
  if (preferred) return preferred;
  const home = jsonHomeRegion(key);
  if (home) return home;
  return configuredRegion();
}
// 针对某把密钥的控制面 GET。跨区拒绝（401/403/404）时，自动模式会现场识别一次
// 再重试，省得把「区域填错」误判成「密钥失效」。
async function cpsGetForKey(key, urlPath) {
  const k = String(key || getApiKey() || "").trim();
  const region = regionForKey(k);
  const res = await apiGet(managementBaseFor(region), urlPath, k);
  const crossRegion = res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 404;
  if (!crossRegion || !isRegionAuto() || !k) return res;
  let detected = "";
  try { detected = (await detectRegionForKey(k)).region; } catch {}
  if (!detected || detected === region) return res;
  await rememberRegionFor(k, detected);
  // 正在使用的那把密钥，识别结果同时落到全局配置，代理转发一起跟着切。
  if (k === getApiKey()) await applyDetectedRegion(detected, { silent: true });
  return apiGet(managementBaseFor(detected), urlPath, k);
}
async function fetchModels(key) {
  const path = "/List-Available-Models?origin=AI_EDITOR&maxResults=200";
  const order = [];
  const pushRegion = (region) => {
    const v = String(region || "").trim();
    if (v && !order.includes(v)) order.push(v);
  };
  pushRegion(regionForKey(key));
  pushRegion(jsonHomeRegion(key));
  for (const region of REGION_CANDIDATES) pushRegion(region);
  let lastErr = null;
  let empty = null;
  for (const region of order) {
    let res;
    try {
      res = await apiGet(managementBaseFor(region), path, key);
    } catch (e) {
      lastErr = e;
      continue;
    }
    if (res.statusCode < 200 || res.statusCode >= 300) {
      lastErr = httpError(res.statusCode, res.body);
      continue;
    }
    let data = {};
    try { data = JSON.parse(res.body || "{}"); } catch {}
    const models = Array.isArray(data.models) ? data.models : [];
    if (!models.length) {
      empty = { region, data, models };
      continue;
    }
    if (region !== order[0]) {
      log("模型列表在 " + order[0] + " 为空或失败，改用 " + region + "（" + models.length + " 个模型）");
    }
    await rememberRegionFor(key, region);
    if (isRegionAuto() && String(key || "") === getApiKey()) await applyDetectedRegion(region, { silent: true });
    rememberModelRates(JSON.stringify({ models }));
    return {
      defaultModel: data?.defaultModel?.modelId || "",
      models: models.map((m) => ({ id: m.modelId, name: m.modelName, rate: m.rateMultiplier })),
    };
  }
  if (empty) {
    rememberModelRates(JSON.stringify({ models: [] }));
    return {
      defaultModel: empty.data?.defaultModel?.modelId || "",
      models: [],
    };
  }
  throw lastErr || new Error("无法获取模型列表");
}
async function fetchUsage(key) {
  const res = await cpsGetForKey(key, "/Get-Usage-Limits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST");
  if (res.statusCode < 200 || res.statusCode >= 300) throw httpError(res.statusCode, res.body);
  return JSON.parse(res.body);
}
async function testKey(key) {
  const k = (key || getApiKey() || "").trim();
  if (!k) throw new Error("请先填写 API Key");
  const m = await fetchModels(k);
  let subscription = "";
  let used = null, total = null;
  try {
    const info = await fetchAccountInfo(k);
    subscription = info?.subscriptionTitle || "";
    used = info?.used;
    total = info?.total;
  } catch {}
  return { modelCount: m.models.length, defaultModel: m.defaultModel, subscription, used, total, models: m.models };
}

// ---------------------------------------------------------------------------
// 地区自动识别
// ---------------------------------------------------------------------------
// 密钥属于哪个区域，用它去各候选区域的 management 端点问一次最省事：
//   2xx  → 这个区域认这把密钥，命中；
//   429  → 认得但正被限流，作为备选（没有 2xx 时才用）；
//   其它 → 不属于这个区域（403 就是典型的跨区拒绝）。
// 探测走的是最轻的那个 GET（Get-Usage-Limits），不产生额度消耗。
const REGION_PROBE_PATH = "/Get-Usage-Limits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST";
const REGION_PROBE_TIMEOUT_MS = 8000;
let _regionDetecting = null; // 进行中的探测 Promise，避免并发重复探测
let _regionDetectBusy = false; // 面板要显示「探测中」，标志必须先于探测同步置起
function isRegionDetecting() {
  return _regionDetectBusy;
}
async function probeRegion(region, key) {
  const started = Date.now();
  try {
    const res = await apiGet(managementBaseFor(region), REGION_PROBE_PATH, key, { timeoutMs: REGION_PROBE_TIMEOUT_MS });
    const status = Number(res.statusCode) || 0;
    return {
      region,
      status,
      ms: Date.now() - started,
      hit: status >= 200 && status < 300,
      soft: status === 429,
    };
  } catch (e) {
    // 域名不存在（ENOTFOUND）/ 超时都归到这里：这个区域不可用。
    return { region, status: 0, ms: Date.now() - started, hit: false, soft: false, error: e?.message || String(e) };
  }
}
// 用量接口在两个区域都可能 200。JSON 号有 profileArn 时以那个区域为准；
// 没有 profile、又有多个 200 时，用「模型列表非空」把空区域排除掉。
async function detectRegionForKey(key) {
  const k = String(key || "").trim();
  if (!k) throw new Error("请先添加 API Key");
  const home = jsonHomeRegion(k);
  const cands = regionCandidates();
  const ordered = home && cands.includes(home)
    ? [home, ...cands.filter((r) => r !== home)]
    : cands;
  const results = await Promise.all(ordered.map((r) => probeRegion(r, k)));
  log("region 探测: " + results.map((r) => r.region + "=" + (r.status || (r.error || "err")) + "/" + r.ms + "ms").join(" "));
  const hits = results.filter((r) => r.hit);
  // profileArn 区域只要用量接口认，就用它。另一个区域的 200 不能把号带走：
  // 那边经常能查出套餐，但模型列表是空的。
  if (home && hits.some((r) => r.region === home)) return { region: home, results };
  if (home) {
    const homeResult = results.find((r) => r.region === home);
    const transportFailed = homeResult && !homeResult.hit && !homeResult.soft && !homeResult.status;
    if (transportFailed) {
      for (const hit of hits) {
        if (await regionServesModels(k, hit.region)) return { region: hit.region, results };
      }
      return { region: home, results };
    }
  }
  if (hits.length > 1) {
    for (const hit of hits) {
      if (await regionServesModels(k, hit.region)) return { region: hit.region, results };
    }
  }
  const hit = hits[0] || results.find((r) => r.soft);
  return { region: hit ? hit.region : "", results };
}
async function regionServesModels(key, region) {
  try {
    const res = await apiGet(
      managementBaseFor(region),
      "/List-Available-Models?origin=AI_EDITOR&maxResults=50",
      key,
      { timeoutMs: REGION_PROBE_TIMEOUT_MS }
    );
    if (res.statusCode < 200 || res.statusCode >= 300) return false;
    const data = JSON.parse(res.body || "{}");
    return Array.isArray(data.models) && data.models.length > 0;
  } catch {
    return false;
  }
}
// 自动模式下确保当前密钥的地区已识别。
//   force = true  → 忽略缓存，重新探测（面板上的「重新识别」走这里）
//   silent = true → 不弹 toast，只写日志（启动 / 切换密钥时的后台识别）
// 识别结果写回 region 配置项，这样端点重定向、代理转发、状态栏全都自动跟着走，
// 不需要在别处再判断一次自动模式。
async function ensureRegionDetected(opts = {}) {
  const { force = false, silent = true } = opts;
  if (!isRegionAuto() && !force) return null;
  const key = getApiKey();
  if (!key) return null;
  if (!force) {
    const trusted = trustedCachedRegion(key);
    if (trusted) {
      if (trusted !== configuredRegion()) await applyDetectedRegion(trusted, { silent });
      return trusted;
    }
  }
  if (_regionDetecting) return _regionDetecting;
  // 先把「探测中」置起来再发请求，pushState 推出去的状态才是真的进行中。
  _regionDetectBusy = true;
  if (panelProvider) panelProvider.pushState();
  _regionDetecting = (async () => {
    try {
      const { region } = await detectRegionForKey(key);
      if (!region) {
        log("region 自动识别失败，保持当前地区 " + getRegion());
        if (!silent && panelProvider) {
          panelProvider.post({ type: "error", message: "自动识别失败：候选地区都没有响应，已保持 " + getRegion() });
        }
        return "";
      }
      await rememberRegionFor(key, region);
      await applyDetectedRegion(region, { silent });
      return region;
    } catch (e) {
      log("!! region 自动识别出错: " + (e?.message || e));
      if (!silent && panelProvider) {
        panelProvider.post({ type: "error", message: "自动识别失败: " + (e?.message || e) });
      }
      return "";
    } finally {
      _regionDetecting = null;
      _regionDetectBusy = false;
      if (panelProvider) panelProvider.pushState();
    }
  })();
  return _regionDetecting;
}
// 把识别到的地区落到配置里。值没变就什么都不做，免得白写一次配置、白触发一次
// applyState。
async function applyDetectedRegion(region, opts = {}) {
  const r = String(region || "").trim();
  if (!r || r === configuredRegion()) return false;
  const before = getRegion();
  await set("region", r);
  log("region 自动识别: " + before + " -> " + r);
  await applyState({ silent: true });
  if (panelProvider) {
    panelProvider.pushState();
    if (!opts.silent) panelProvider.post({ type: "toast", message: "已自动识别地区: " + r });
  }
  return true;
}
// 生成请求撞到「鉴权失效」时，先怀疑是地区不对而不是密钥坏了：跨区拒绝和真失效
// 的响应长得一样（都是 403 + access denied），只有换个区域再问一次才能区分。
// 自动模式下后台复核一次，地区真的变了就把刚才那条失效判定撤掉，让这把密钥在新
// 区域重新参与挑号。同一把密钥 60 秒内只复核一次，避免连续失败时反复探测。
const REGION_RECHECK_MIN_GAP_MS = 60 * 1000;
const _regionRecheckAt = new Map(); // key -> 上次复核时间
// 切到一把还没探过区的号时补一次探测。
//
// 不补的话，regionForKey 会回退到全局值（也就是上一把号的区）。多把号分属不同区时
// 这一发就打错了区，上游回的是 403 + 一句跟「凭证真坏了」一模一样的正文，号很容易
// 被误标成已失效。转发路径有 cpsGetForKey 的跨区重试兜底，但那要先撞一次墙；这里
// 提前把区探出来写进缓存，之后 regionForKey 直接命中，那一次墙就不用撞了。
// 跟失败复核共用 _regionRecheckAt 的节流：两者要问的是同一件事，60 秒内只问一次。
function ensureRegionForKeySoon(key) {
  if (!key || !isRegionAuto() || cachedRegionFor(key)) return;
  const last = Number(_regionRecheckAt.get(key) || 0);
  if (Date.now() - last < REGION_RECHECK_MIN_GAP_MS) return;
  _regionRecheckAt.set(key, Date.now());
  detectRegionForKey(key)
    .then(async ({ region }) => {
      if (!region) return;
      await rememberRegionFor(key, region);
      if (key === getApiKey()) await applyDetectedRegion(region, { silent: true });
      log("已识别 " + maskKey(key) + " 所属区域: " + region);
    })
    .catch(() => {});
}
function recheckRegionOnAuthFailure(key, kind) {
  // denied 也要复核：原因不明的 403 里，"区域不匹配"占了很大一块，跟真失效的
  // 响应长得一模一样。
  if ((kind !== "invalid" && kind !== "denied") || !isRegionAuto() || !key) return;
  const last = Number(_regionRecheckAt.get(key) || 0);
  if (Date.now() - last < REGION_RECHECK_MIN_GAP_MS) return;
  _regionRecheckAt.set(key, Date.now());
  const before = regionForKey(key);
  detectRegionForKey(key)
    .then(async ({ region }) => {
      if (!region || region === before) return;
      await rememberRegionFor(key, region);
      if (key === getApiKey()) await applyDetectedRegion(region, { silent: true });
      log("region 由 " + before + " 纠正为 " + region + "，撤销 " + maskKey(key) + " 的失效判定");
      forgetKeyHealth(key);
    })
    .catch(() => {});
}

// First numeric value among the given keys of an object (NaN-safe).
function pickNum(obj, keys) {
  if (!obj || typeof obj !== "object") return null;
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "number" && !Number.isNaN(v)) return v;
    if (typeof v === "string" && v.trim() !== "" && !Number.isNaN(Number(v))) return Number(v);
  }
  return null;
}
// Recursively collect any { currentUsage*, usageLimit* } pairs from the usage
// response. Field names have shifted across Kiro builds (…WithPrecision vs
// plain, top-level vs nested in breakdown lists), so we scan defensively rather
// than assume one shape.
function collectUsagePairs(node, out) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) collectUsagePairs(item, out);
    return;
  }
  const used = pickNum(node, ["currentUsageWithPrecision", "currentUsage", "usedCredits", "used"]);
  const limit = pickNum(node, ["usageLimitWithPrecision", "usageLimit", "totalCredits", "limit"]);
  if (used != null || limit != null) out.push({ used, limit });
  for (const k of Object.keys(node)) collectUsagePairs(node[k], out);
}
// 额度重置时间。字段名在不同 Kiro 版本里换过好几轮，所以递归扫一遍，认到哪个
// 算哪个；拿到的可能是 ISO 字符串、秒级或毫秒级时间戳，统一折成毫秒时间戳。
// 有了这个值，"额度用尽"的冻结就能压到真正的重置时刻，而不是拍一个默认 TTL。
const RESET_AT_FIELDS = [
  "nextDateReset", "nextResetDate", "resetDate", "resetAt", "resetTime",
  "usageLimitResetDate", "nextUsageResetDate", "renewalDate", "periodEnd",
];
function normalizeResetAt(v) {
  if (v == null) return 0;
  if (typeof v === "number" && Number.isFinite(v)) {
    // 10 位是秒、13 位是毫秒。小于 1e12 的一律按秒处理。
    const ms = v < 1e12 ? v * 1000 : v;
    return ms > Date.now() ? Math.round(ms) : 0;
  }
  const s = String(v).trim();
  if (!s) return 0;
  if (/^\d+$/.test(s)) return normalizeResetAt(Number(s));
  const t = Date.parse(s);
  return Number.isFinite(t) && t > Date.now() ? t : 0;
}
function findResetAt(node, depth = 0) {
  if (!node || typeof node !== "object" || depth > 8) return 0;
  if (Array.isArray(node)) {
    for (const item of node) {
      const hit = findResetAt(item, depth + 1);
      if (hit) return hit;
    }
    return 0;
  }
  for (const f of RESET_AT_FIELDS) {
    const hit = normalizeResetAt(node[f]);
    if (hit) return hit;
  }
  for (const k of Object.keys(node)) {
    const hit = findResetAt(node[k], depth + 1);
    if (hit) return hit;
  }
  return 0;
}
// Map a subscription title to a coarse tier for consistent tag coloring.
function tierFromTitle(title) {
  const t = String(title || "").toLowerCase();
  if (!t) return "";
  if (t.includes("power")) return "power";
  if (t.includes("pro+") || t.includes("pro plus") || t.includes("promax") || t.includes("pro max")) return "pro+";
  if (t.includes("pro")) return "pro";
  if (t.includes("free")) return "free";
  return "other";
}
// 把用量响应解析成 { subscriptionTitle, tier, used, total, resetAt }。
// 两条路共用这一份解析：插件主动探测（fetchAccountInfo），以及 Kiro 自己请求用量
// 时的旁路嗅探（noteUsageFromBody）。认字段的方式必须一致，否则面板和 IDE 会各
// 说一套数字。
function parseUsagePayload(data) {
  const title = data?.subscriptionInfo?.subscriptionTitle || data?.subscriptionInfo?.subscriptionType || "";
  const pairs = [];
  collectUsagePairs(data, pairs);
  let used = null, total = null;
  for (const p of pairs) {
    if (p.used != null) used = (used || 0) + p.used;
    if (p.limit != null) total = (total || 0) + p.limit;
  }
  // 额度重置时间：有就带回去，"额度用尽"的冻结会压到这个时刻自动复检。
  return { subscriptionTitle: title, tier: tierFromTitle(title), used, total, resetAt: findResetAt(data) };
}
// Fetch subscription tier + aggregate credit usage for a single key.
async function fetchAccountInfo(key) {
  try {
    const info = parseUsagePayload(await fetchUsage(key));
    log("account info: title=" + info.subscriptionTitle + " used=" + info.used + " total=" + info.total
      + (info.resetAt ? " reset=" + new Date(info.resetAt).toISOString() : ""));
    if (isJsonKey(key) && (info.used != null || info.total != null || info.subscriptionTitle)) {
      try {
        await upsertJsonCred(key, {
          importedUsage: {
            used: info.used,
            total: info.total,
            subscriptionTitle: info.subscriptionTitle || "",
            resetAt: info.resetAt || 0,
          },
        }, { keepMemo: true });
      } catch {}
    }
    return info;
  } catch (e) {
    if (isJsonKey(key)) {
      const cred = getJsonCred(key);
      const seed = cred && cred.importedUsage;
      if (seed && (seed.used != null || seed.total != null || seed.subscriptionTitle)) {
        const title = seed.subscriptionTitle || "";
        log("account info: 导入快照 " + displayJsonKey(key) + " title=" + title
          + " used=" + seed.used + " total=" + seed.total);
        return {
          subscriptionTitle: title,
          tier: tierFromTitle(title),
          used: seed.used,
          total: seed.total,
          resetAt: seed.resetAt || 0,
        };
      }
    }
    throw e;
  }
}
// Kiro 自己请求用量时顺手记一笔。这是最新鲜的一手数据 —— IDE 那个百分比圆圈就是
// 拿它画的 —— 用来更新账号状态和挑号要看的剩余额度，还能省掉插件自己再探一次。
function noteUsageFromBody(key, bodyText) {
  if (!key || !bodyText) return;
  let data;
  try { data = JSON.parse(bodyText); } catch { return; }
  const info = parseUsagePayload(data);
  if (info.used == null && info.total == null) return;
  noteKeyProbed(key);
  noteAccountHealth(key, true, info);
}

// ---------------------------------------------------------------------------
// 后台账号巡检
// ---------------------------------------------------------------------------
// 面板里那个 30 秒的账户同步跑在 webview 里，而 webview 一被隐藏就整个销毁 ——
// 面板没开着的时候，账号状态只能靠"真实请求撞墙"被动更新：额度已经重置了看不
// 出来、限流早就解了也不知道、当前这把号在别处被打满了照样一直用，撞一次墙才切。
//
// 所以宿主端自己也要巡检，只是节奏放得很慢，并且跟面板共用一份"上次探测时间"，
// 两边不会重复打同一把号。走的是最轻的那个用量 GET，不消耗额度。
const HEALTH_SWEEP_MS = 5 * 60 * 1000;
const HEALTH_PROBE_MIN_GAP_MS = 4 * 60 * 1000; // 同一把号至少隔这么久才再探一次
const HEALTH_SWEEP_MAX_KEYS = 6;               // 单轮最多探几把，号多时自然分摊到多轮
const HEALTH_SWEEP_CONCURRENCY = 3;
const _keyProbeAt = new Map(); // key -> 上次探测时间（面板同步也会写这里）
let _healthTimer = null;
let _healthSweeping = false;
function noteKeyProbed(key) {
  if (key) _keyProbeAt.set(key, Date.now());
}
// 这一轮该探哪些号：当前在用的那把最优先（它的状态最要紧），其余按"最久没探过"
// 排。冻结中的跳过 —— keyHealthFrozen 顺手会把到期的终态解掉，所以刚过复检窗口
// 的号会在这里自动重新进入探测队列。
function keysDueForProbe() {
  const now = Date.now();
  const active = getApiKey();
  return getApiKeys()
    .filter((k) => {
      const st = (_keyHealth.get(k) || {}).state;
      // 额度用尽 / 已禁用的照常探，不看冻结窗口。这两种正常会被自动删掉，还能出现在
      // 列表里说明删除没落地（刚从落盘恢复的终态，或者上一次删失败了）。探一次有两
      // 头好处：真探到 200 就当场翻案救回来（额度过了周期会自己恢复），仍然是坏的就
      // 再触发一次删除。走的是免费的用量 GET，不烧额度。
      if (st === "quota" || st === "suspended") return true;
      // 其余按老规矩：冻结中的跳过。keyHealthFrozen 顺手会把到期的终态解掉，所以刚
      // 过复检窗口的号（比如被跨区误判成鉴权失效的）会在这里自动重新进入探测队列。
      return !keyHealthFrozen(k);
    })
    .filter((k) => k === active || now - Number(_keyProbeAt.get(k) || 0) >= HEALTH_PROBE_MIN_GAP_MS)
    .sort((a, b) => {
      if (a === active) return -1;
      if (b === active) return 1;
      return Number(_keyProbeAt.get(a) || 0) - Number(_keyProbeAt.get(b) || 0);
    })
    .slice(0, HEALTH_SWEEP_MAX_KEYS);
}
async function healthSweepOnce() {
  // 中转站模式没有多号概念；网关关着时也不用替 Kiro 官方服务操心。
  if (_healthSweeping || isRelayMode() || !isEnabled()) return;
  if (getApiKeys().length < 1) return;
  _healthSweeping = true;
  try {
    const targets = keysDueForProbe();
    if (!targets.length) return;
    for (let i = 0; i < targets.length; i += HEALTH_SWEEP_CONCURRENCY) {
      const batch = targets.slice(i, i + HEALTH_SWEEP_CONCURRENCY);
      await Promise.all(batch.map(async (key) => {
        noteKeyProbed(key);
        try {
          noteAccountHealth(key, true, await fetchAccountInfo(key));
        } catch (e) {
          noteAccountHealth(key, false, null, e);
        }
      }));
    }
    // 探测结果可能让当前这把号变成不可用，顺手换一把，别等下一次请求撞墙。
    maybeAdoptUsableKey();
    if (panelProvider) panelProvider.pushStats();
  } finally {
    _healthSweeping = false;
  }
}
function startHealthSweep() {
  stopHealthSweep();
  if (isRelayMode()) return;
  _healthTimer = setInterval(() => { healthSweepOnce().catch(() => {}); }, HEALTH_SWEEP_MS);
}
function stopHealthSweep() {
  if (_healthTimer) { clearInterval(_healthTimer); _healthTimer = null; }
}
// 模式 / 开关 / 密钥变化后重新决定巡检要不要跑。
function syncHealthSweep() {
  if (!isRelayMode() && isEnabled() && getApiKeys().length) startHealthSweep();
  else stopHealthSweep();
}

// ---------------------------------------------------------------------------
// 存活探测 + 号变废自动删除
// ---------------------------------------------------------------------------
// 上面那套巡检走的是控制平面（用量 GET），不消耗额度，但有个盲区：账号被后端风控
// 锁掉时往往只挡推理接口，用量查询照样回 200。表现就是号早就不能对话了，面板还
// 显示「正常」，直到用户自己发一条消息撞上墙。
//
// 所以这里再补一条走推理平面的真探活：POST runtime.{region}.kiro.dev 发一个最小的
// GenerateAssistantResponse。代价是每次真探消耗一次生成请求，因此有两道闸：
//   * 每把号最短 livenessRealCheckPerKeyIntervalSec 秒才被真探一次（默认 60 秒）
//   * 已经冻结成终态的号不再探（终态不会自己翻案）
//
// 探到号已经废了（被禁用 / 溢出上限打满 / 月配额用尽）就按配置直接从密钥列表删掉，
// 省得用户回来一个个手工清。
function getLivenessCheckEnabled() {
  return get("livenessCheckEnabled", false) === true;
}
function getLivenessCheckIntervalSec() {
  const v = Math.round(Number(get("livenessCheckIntervalSec", 60)));
  return Number.isFinite(v) ? Math.min(Math.max(v, 10), 3600) : 60;
}
// 每号真探最短间隔。防止扫描过密时反复真探同一把号，把额度烧在探活上。
function getLivenessRealCheckPerKeyIntervalSec() {
  const v = Math.round(Number(get("livenessRealCheckPerKeyIntervalSec", 60)));
  return Number.isFinite(v) ? Math.min(Math.max(v, 10), 3600) : 60;
}
// 默认开：号废了就自动清出列表。留着一把已禁用 / 额度用尽的号没有任何用处 —— 它不
// 参与挑号，只在面板上占一行红标，还要在每轮探活里被反复确认。要删的只有这三类
// （见 DEAD_KINDS），鉴权失效刻意不在其中，那可能只是凭证输错或者跨区误判。
function getAutoDeleteOnDead() {
  return get("autoDeleteOnDead", true) !== false;
}
// 溢出上限特征。POWER 号打满 base + overage 之后，推理平面直接回 HTTP 400 +
// __type=ServiceQuotaExceededException + reason=OVERAGE_REQUEST_LIMIT_EXCEEDED。
// keyFailureKind 会把它归成通用 quota，但从用户视角这号已经彻底没救（只能等下个
// 计费周期），单独一类方便面板计数和日志区分。
const OVERAGE_EXCEEDED_RE = /OVERAGE_REQUEST_LIMIT_EXCEEDED|reached the limit for overages/i;
// 该被自动删的类别：
//   suspended        账号被后端主动禁用
//   overage_exceeded 溢出上限打满
//   quota            月配额用尽
// invalid 不进这个集合 —— 那可能只是凭证输错，删掉反而让用户丢了改正的机会。
// network / unknown 也不进：网络抖动不算数。
const DEAD_KINDS = new Set(["suspended", "overage_exceeded", "quota"]);
// 每号上次真探的时间戳。只放内存，重载后立刻能重新真探一轮。
const _keyLastRealCheck = new Map();
function forgetKeyLastRealCheck() {
  const alive = new Set(getApiKeys());
  for (const k of _keyLastRealCheck.keys()) if (!alive.has(k)) _keyLastRealCheck.delete(k);
}

// 单把号的真探活。请求形态沿用转发时那套通过实测的组合，别另起一套 headers。
async function livenessCheckOne(key) {
  const region = cachedRegionFor(key) || getRegion();
  let hostname;
  try {
    hostname = new URL(runtimeBaseFor(region)).hostname;
  } catch {
    return { kind: "network", detail: "bad region " + region };
  }
  // conversationId 每次都换，避免上游把探活当成延续对话累积到某个会话上，也避免
  // 探活污染真正对话的历史。
  const rawBody = {
    conversationState: {
      chatTriggerType: "MANUAL",
      conversationId: crypto.randomUUID(),
      currentMessage: {
        userInputMessage: { content: "1", modelId: "auto", origin: "AI_EDITOR" },
      },
      history: [],
    },
  };
  return Promise.resolve(resolveAuth(key)).then((auth) => new Promise((resolve) => {
  const bodyBuf = prepareOutbound(auth, Buffer.from(JSON.stringify(rawBody), "utf8"), "/").body;
    let done = false;
    let statusCode = 0;
    const bufs = [];
    let total = 0;
    // 只读前 16KB 判定。生成响应是流式的，但判断"号通不通"最多看头部就够：
    // 2xx + 早期正常帧 = ok；4xx = 立即错误；2xx + 早期错误帧 = 被禁用。
    // 额度已经花了，多读只是浪费时间和内存。
    const READ_CAP = 16 * 1024;
    const finalize = () => {
      if (done) return;
      done = true;
      const raw = Buffer.concat(bufs).toString("utf8");
      // 溢出上限优先识别：这是最硬的证据（__type 硬字段 + 特定 reason 常量），
      // 无论状态码是什么，只要正文里出现就能确认这号废了。
      if (OVERAGE_EXCEEDED_RE.test(raw)) {
        resolve({ kind: "overage_exceeded", detail: "HTTP " + statusCode + " overage" });
        return;
      }
      if (statusCode >= 200 && statusCode < 300) {
        // 2xx 也可能带流内错误帧：上游有时用 200 + 错误帧返回「已禁用」。
        if (looksSuspended(failureEvidence(raw))) {
          resolve({ kind: "suspended", detail: "200+stream" });
          return;
        }
        resolve({ kind: "ok" });
        return;
      }
      // 4xx / 5xx 沿用 keyFailureKind 的分类，跟转发失败、账户同步的口径完全一致。
      const kind = keyFailureKind(statusCode, raw);
      if (kind === "suspended") { resolve({ kind: "suspended", detail: "HTTP " + statusCode }); return; }
      if (kind === "invalid") { resolve({ kind: "invalid", detail: "HTTP " + statusCode }); return; }
      if (kind === "quota") { resolve({ kind: "quota", detail: "HTTP " + statusCode }); return; }
      // 限流说明号是活的，只是这一刻挤，不作结论。
      if (kind === "throttle") { resolve({ kind: "unknown", detail: "HTTP " + statusCode + " throttle" }); return; }
      resolve({ kind: "unknown", detail: "HTTP " + statusCode });
    };
    const req = https.request(
      {
        hostname, port: 443, path: "/", method: "POST",
        headers: {
          "content-type": "application/x-amz-json-1.0",
          "x-amz-target": "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
          "x-amzn-kiro-agent-mode": "vibe",
          accept: "*/*",
          authorization: "Bearer " + auth.token,
          ...(auth.type === "apikey" ? { tokentype: "API_KEY" } : {}),
          ...(auth.tokenType ? { tokentype: auth.tokenType } : {}),
          "user-agent": kiroUserAgent(),
          "x-amz-user-agent": kiroXAmzUserAgent(),
          "x-amzn-codewhisperer-optout": "true",
          "content-length": bodyBuf.length,
        },
        // 生成请求本来就慢，但真挂了也别耗太久。
        timeout: 25000,
        // 探活刻意不进连接池：它会 req.destroy() 提前断流（收够头部就够判断了），
        // 半途掐断的 socket 不该回到池子里污染正常请求。
        agent: false,
      },
      (res) => {
        statusCode = res.statusCode || 0;
        res.on("data", (c) => {
          total += c.length;
          if (total <= READ_CAP) bufs.push(c);
          // 收够头部就断连。destroy 会走 close 分支，done 标记保证不重复 resolve。
          if (total >= READ_CAP) { try { req.destroy(); } catch {} }
        });
        res.on("end", finalize);
        res.on("close", finalize);
      }
    );
    req.on("timeout", () => {
      try { req.destroy(); } catch {}
      if (!done) { done = true; resolve({ kind: "network", detail: "timeout" }); }
    });
    req.on("error", (e) => {
      if (!done) { done = true; resolve({ kind: "network", detail: e && e.message ? e.message : String(e) }); }
    });
    req.write(bodyBuf);
    req.end();
  })).catch((e) => ({ kind: "invalid", detail: e && e.message ? e.message : String(e) }));
}

// 探活扫描状态，面板显示用。
const _livenessState = {
  lastRunAt: 0,
  lastCounts: { ok: 0, suspended: 0, overage_exceeded: 0, invalid: 0, quota: 0, network: 0, unknown: 0, skipped: 0 },
  lastDeleted: 0,   // 本次扫描删了几把
  totalDeleted: 0,  // 本次会话累计删了几把
  running: false,
};
function livenessStateSnapshot() {
  return {
    enabled: getLivenessCheckEnabled(),
    intervalSec: getLivenessCheckIntervalSec(),
    perKeyIntervalSec: getLivenessRealCheckPerKeyIntervalSec(),
    autoDelete: getAutoDeleteOnDead(),
    ...(_livenessState),
  };
}

// 自动删掉一把号，走跟面板删除同一套清理。
// 激活的号被删且网关开着时要顺手关网关并提示重载：直接删不关，kiro-agent 那边看到
// 的端点已经没有凭证可用，会连续报错。
async function deleteKeyAutomatic(key, reason) {
  const list = getApiKeys();
  const idx = list.indexOf(key);
  if (idx < 0) return { deleted: false, activeAffected: false };
  const removingActive = getActiveApiKey() === key;
  list.splice(idx, 1);
  // 记一笔「刚删过这把」：号池（尤其拼车那种共享池）很可能立刻又把同一把发下来，
  // 收它只是重走一遍导入 → 撞墙 → 判废 → 删除，白烧往返。
  rememberDeadKey(key);
  await setApiKeys(list);
  // forgetKeyHealth 已经把状态、冷却、用量、探测时间一并清掉了。原来这里还调了
  // clearCooldown，那个会顺手写回一条 "ok"，等于给一把已经不在列表里的号留条脏记录。
  forgetKeyHealth([key]);
  _keyLastRealCheck.delete(key);
  try { await syncKeyAddedAt(list); } catch {}
  // silent：这条路径是后台探活触发的，不该弹原生对话框打断用户。
  await applyState({ silent: true });
  maybeAdoptUsableKey();
  if (removingActive) {
    // 删到正在用的那把也不关网关。
    //
    // 原来这里是 set("enabled", false) 再提示重载。但号池自动续号随时会补新号进来，
    // 网关一关，补回来的号就没地方落，用户还得手动再开一次 —— 而这条路径恰恰是全自动
    // 补号最常撞上的：正在用的号烧完被删，紧接着续号就拉回来一把新的。
    // 池子里还有号就切下一把；一把不剩就让它空转等续号 —— 反正号都废了，关不关网关都
    // 发不出请求，开着反而能让补回来的号立刻接上。
    const tail = list.length
      ? "，网关保持开启并切到剩余可用号"
      : "，池子已空，网关保持开启等号池补号";
    log("[探活] 已自动删除正在使用的密钥 " + maskKey(key) + "（" + reason + "）" + tail);
  } else {
    log("[探活] 自动删除 " + maskKey(key) + "（" + reason + "）");
  }
  // 不弹通知。删号本来就是全自动的，号池一补一删可能连着好几次，每次都弹一个框太吵，
  // 而且这事不需要用户当场做任何决定。要追溯就去运行日志里看上面那两行。
  if (panelProvider) panelProvider.pushState();
  return { deleted: true, activeAffected: removingActive };
}

const LIVENESS_CONCURRENCY = 4;
const DEAD_KIND_LABEL = {
  suspended: "账号已被禁用",
  overage_exceeded: "溢出额度已打满",
  quota: "额度已用尽",
};
// 一轮扫描：挑出该真探的号逐个探活，结果落到账号状态上，废号按配置删掉。
// manual=true 时忽略每号最短间隔（用户自己点的按钮，代价他知道）。
async function runLivenessScan({ manual = false } = {}) {
  if (_livenessState.running) {
    if (manual) log("[探活] 上一轮还没跑完，本轮跳过");
    return { skipped: true };
  }
  // 中转站模式没有多号概念；网关关着时也不必替 Kiro 官方服务操心。
  if (!manual && (isRelayMode() || !isEnabled())) return { skipped: true };
  _livenessState.running = true;
  const counts = { ok: 0, suspended: 0, overage_exceeded: 0, invalid: 0, quota: 0, network: 0, unknown: 0, skipped: 0 };
  const okKeys = [];
  let deleted = 0;
  try {
    const now = Date.now();
    const perKeyMin = getLivenessRealCheckPerKeyIntervalSec() * 1000;
    const targets = [];
    for (const k of getApiKeys()) {
      // 冻结成终态的号不再真探。但如果开着自动删号，终态里属于"废号"的那几种要放进来
      // 探一次 —— 否则被巡检判成 quota 冻结的号永远等不到删除，一直躺在列表里。
      if (keyHealthFrozen(k, { silent: true })) {
        const st = (_keyHealth.get(k) || {}).state;
        if (!(getAutoDeleteOnDead() && DEAD_KINDS.has(st))) { counts.skipped++; continue; }
      }
      if (!manual && now - Number(_keyLastRealCheck.get(k) || 0) < perKeyMin) { counts.skipped++; continue; }
      targets.push(k);
    }
    for (let i = 0; i < targets.length; i += LIVENESS_CONCURRENCY) {
      const batch = targets.slice(i, i + LIVENESS_CONCURRENCY);
      const results = await Promise.all(batch.map(async (key) => {
        _keyLastRealCheck.set(key, Date.now());
        const r = await livenessCheckOne(key).catch((e) => ({
          kind: "network", detail: e && e.message ? e.message : String(e),
        }));
        return { key, r };
      }));
      for (const { key, r } of results) {
        counts[r.kind] = (counts[r.kind] || 0) + 1;
        if (r.kind === "ok") {
          // 真探通了就是最硬的"这号能用"：连终态都可以靠它翻案，所以带 force。
          // 额度用尽的号在计费周期重置后就是靠这一步自动救回来的。
          clearCooldown(key);
          setKeyHealth(key, "ok", { force: true });
          okKeys.push(key);
          continue;
        }
        if (r.kind === "network" || r.kind === "unknown") continue; // 抖动不作结论
        // 有结论的失败：记状态，让面板和挑号逻辑立刻知道。overage 归到 quota，
        // 因为面板只认那几个状态名。
        setKeyHealth(key, r.kind === "overage_exceeded" ? "quota" : r.kind);
        if (!getAutoDeleteOnDead() || !DEAD_KINDS.has(r.kind)) continue;
        const reason = (DEAD_KIND_LABEL[r.kind] || r.kind) + " · " + (r.detail || "");
        const out = await deleteKeyAutomatic(key, reason).catch(() => ({ deleted: false }));
        if (out.deleted) deleted++;
        // 删到正在用的那把也不再关网关（见 deleteKeyAutomatic），所以这一轮不用中断。
        // 剩下的号继续探完，一次扫描把废号一起清掉，比留到下一轮更省事。
      }
    }
    // 探到活的号顺手刷一次用量：走控制平面 GET，不消耗生成额度，面板顶部的
    // 已用 / 总量就不必等用户点「立即同步」。不 await，别拖住这一轮。
    if (okKeys.length) {
      Promise.all(okKeys.map(async (k) => {
        try { noteAccountHealth(k, true, await fetchAccountInfo(k)); } catch {}
      })).then(() => { if (panelProvider) panelProvider.pushStats(); }).catch(() => {});
    }
    // 正在用的那把可能刚被判成终态（标了但没删）：让可用的号接手，下一次请求
    // 不必再撞同一面墙。自动切号关着时这个调用内部会自己跳过。
    maybeAdoptUsableKey();
  } finally {
    _livenessState.running = false;
    _livenessState.lastRunAt = Date.now();
    _livenessState.lastCounts = counts;
    _livenessState.lastDeleted = deleted;
    _livenessState.totalDeleted += deleted;
    forgetKeyLastRealCheck();
    if (panelProvider) panelProvider.pushStats();
  }
  const summary = Object.entries(counts).filter(([, v]) => v > 0)
    .map(([k, v]) => k + "=" + v).join(" ");
  if (summary || deleted) {
    log("[探活] 一轮完成: " + (summary || "无可探的号") + (deleted ? " · 已删 " + deleted + " 把" : ""));
  }
  return { counts, deleted };
}

let _livenessTimer = null;
function stopLivenessScheduler() {
  if (_livenessTimer) { clearInterval(_livenessTimer); _livenessTimer = null; }
}
function startLivenessScheduler() {
  stopLivenessScheduler();
  _livenessTimer = setInterval(() => {
    runLivenessScan().catch(() => {});
  }, getLivenessCheckIntervalSec() * 1000);
}
// 开关 / 间隔 / 模式 / 密钥变化后重新决定探活要不要跑。
function syncLivenessScheduler() {
  if (getLivenessCheckEnabled() && !isRelayMode() && isEnabled() && getApiKeys().length) {
    startLivenessScheduler();
  } else {
    stopLivenessScheduler();
  }
}

// ---------------------------------------------------------------------------
// 自动续号（号池自动补号）
// ---------------------------------------------------------------------------
// 可用密钥（没在冷却、也没被判成终态）掉到阈值以下时，后台按节奏轮询用户配置的
// 号池 API，把拉回来的 ksk_ 新号先验证一遍再导入。
//
// 几条关键约定：
//   * 重复的 key 直接跳过、不计入成功次数。全是重复说明号池还没出新号，继续猛拉
//     没有意义，所以这种情况进「重复 Key 冷却」，比普通轮询间隔压得更久。
//   * 请求失败按指数退避（基础退避 × 2^n，夹到最大退避，再叠一个随机抖动），
//     连续失败到阈值就熔断一段时间 —— 对面已经挂了还在死循环只会被拉黑。
//   * 「最大轮询次数」是一次触发（掉到阈值以下）之内的上限，用完就停手；可用密钥
//     恢复到阈值以上会自动复位，也可以在面板上点「立即续号」手动复位。
//   * 号池接口五花八门，所以解析分两层：先按结构认（拼车队那种带 code / msg /
//     data[].account 的 JSON，顺带能拿到区域和状态），认不出来再用正则把 ksk_
//     开头的串捞出来，纯文本、一行一个的照样能吃。
//   * 对面明确说「暂无可用号，正在补货」时按排队处理：既不算失败（不喂熔断）也不
//     算重复（不进长冷却），按普通间隔继续等发车。
const RENEW_DEFAULTS = {
  enabled: false,
  apiUrl: "",
  // 验证通过的新号是否直接写进密钥列表。关掉则先进「待导入」等用户确认。
  autoImport: true,
  // 持续囤号：开了就不看阈值，按轮询间隔一直去号池捞新号（号池出新号就收下）。
  // 默认关 —— 只在号不够用时才补，对号池最客气。
  alwaysPoll: false,
  threshold: 2,             // 触发阈值：可用密钥少于这个数就开始补
  intervalSec: 60,          // 轮询间隔
  maxRounds: 3,             // 最大轮询次数，用完停手
  batchSize: 1,             // 单次批量数：一轮里发几次请求
  requestGapSec: 5,         // 同轮请求间隔
  backoffBaseSec: 30,       // 基础退避
  backoffMaxSec: 300,       // 最大退避
  breakerThreshold: 5,      // 连续失败熔断阈值
  breakerCooldownSec: 300,  // 熔断冷却
  dupCooldownSec: 600,      // 重复 Key 冷却
  jitterPct: 10,            // 退避随机抖动
};
// 每个数值参数的取值区间。面板会夹一次，宿主这边再夹一次 —— 配置也可能是用户
// 直接改 globalState 塞进来的。
const RENEW_LIMITS = {
  threshold: [1, 100],
  intervalSec: [5, 3600],
  maxRounds: [1, 1000],
  batchSize: [1, 20],
  requestGapSec: [0, 300],
  backoffBaseSec: [1, 3600],
  backoffMaxSec: [1, 86400],
  breakerThreshold: [1, 100],
  breakerCooldownSec: [0, 86400],
  dupCooldownSec: [0, 86400],
  jitterPct: [0, 100],
};
const RENEW_TICK_MS = 2000;              // 调度器心跳，只做时间比较，很便宜
const RENEW_FETCH_TIMEOUT_MS = 20000;    // 单次号池请求超时
const RENEW_BODY_CAP = 512 * 1024;       // 响应体读取上限，防止对面吐一个大文件
// 号池返回什么格式都行，统一用这个正则捞 key。不含 base64 的 + / = ：那几个字符
// 在 JSON / URL 里都可能是分隔符，宁可少捞也不要把结尾的标点吃进来。
const RENEW_KEY_RE = /ksk_[A-Za-z0-9_-]{8,}/g;
// 结构化响应里的 account.key 是单独一个字段，要整串匹配，不能用上面那个全局正则
// （带 g 的正则有 lastIndex，反复 test 同一个会跳字符）。
const RENEW_KEY_ONE_RE = /^ksk_[A-Za-z0-9_-]{8,}$/;
// zone 是区域缩写，只在没给完整 aws_region 时用得上。
const RENEW_ZONE_REGION = { us: "us-east-1", eu: "eu-central-1" };
// 业务码：0 和 200 都是常见的「成功」写法，其余当失败看待。没给 code 的号池
// （纯文本、一行一个）不参与这个判断。
const RENEW_OK_CODES = new Set([0, 200]);
function renewCodeOk(code) {
  return code == null || RENEW_OK_CODES.has(Number(code));
}

// 有的号池（拼车队 / 发车那一类）返回的是带座位信息的结构化 JSON：
//   { code: 0, msg: "已进「US Power 拼车队」拼车队列，但暂无可用号…",
//     data: [ { claimId, channelId, channelName, seatNo, seatsTotal, claimType,
//               claimTime, warrantyUntil,
//               account: { key, zone, aws_region, status } } ] }
// 比一串裸 key 多给了三样有用的东西：
//   * account.aws_region —— 号属于哪个区直接写着，验号时不必再拿它去各候选区探
//     一遍（那是一轮并发请求，能省就省）；
//   * account.status —— 不是 active 的号连验都不用验，省一次往返；
//   * code / msg —— 「正在补货，补到后自动为你发车」是排队而不是故障，只看 HTTP
//     状态码会把它当失败往熔断上累，反而错过发车。
// 认不出这个结构就返回 null，让调用方退回正则，谁的格式都还能吃。
// status 的摆法不统一：有的号池写在 account 里，有的写在外层那一条上，字段名也
// 可能是 state / accountStatus。两层都看一眼 —— 只从 account 里读的话，写在外层的
// 状态会被读成空串，过滤时当成「号池没给状态」放行，不是 active 的号就漏进来了。
function renewStatusOf(row, acc) {
  const pick = (o) => {
    if (!o || typeof o !== "object") return "";
    const v = o.status ?? o.state ?? o.accountStatus ?? o.account_status;
    return v == null ? "" : String(v).trim().toLowerCase();
  };
  return pick(acc) || pick(row);
}
function renewRegionOf(account) {
  const full = String(account?.aws_region || account?.awsRegion || account?.region || "").trim();
  // 完整区域名（us-east-1 / eu-central-1）直接可用。
  if (/^[a-z]{2}-[a-z]+-\d+$/.test(full)) return full;
  const zone = String(account?.zone || "").trim().toLowerCase();
  return RENEW_ZONE_REGION[zone] || "";
}
function parseRenewPayload(body) {
  let j;
  try { j = JSON.parse(String(body || "")); } catch { return null; }
  if (!j || typeof j !== "object") return null;
  const code = j.code == null ? null : Number(j.code);
  const msg = String(j.msg || j.message || "").trim();
  // data 是常见写法，顶层直接是数组的也认。
  const rows = Array.isArray(j.data) ? j.data : Array.isArray(j) ? j : null;
  // 三样都没有：不是这类响应，交给正则。
  if (rows == null && code == null && !msg) return null;
  const items = [];
  const seen = new Set();
  for (const row of rows || []) {
    if (!row || typeof row !== "object") continue;
    // 有 account 就从里面取，没有就当这一层自己带着 key（有的号池把号平铺在 data 里）。
    const acc = row.account && typeof row.account === "object" ? row.account : row;
    const key = String(acc.key || acc.apiKey || "").trim();
    // 补货中的条目 account 可能是 null，安全跳过。
    if (!RENEW_KEY_ONE_RE.test(key) || seen.has(key)) continue;
    seen.add(key);
    items.push({
      key,
      region: renewRegionOf(acc),
      status: renewStatusOf(row, acc),
      claimId: posNum(row.claimId),
      channelName: String(row.channelName || "").trim(),
      seatNo: posNum(row.seatNo),
      seatsTotal: posNum(row.seatsTotal),
      claimTime: posNum(row.claimTime),
      warrantyUntil: posNum(row.warrantyUntil),
    });
  }
  // 最新领到的座位排前面：同一份响应里既有历史座位又有刚发车的新号时，先验新的。
  items.sort((a, b) => b.claimTime - a.claimTime);
  return { code, msg, items, rows: rows ? rows.length : 0, structured: true };
}
// 统一入口：结构化优先（能带上地区和状态），认不出结构或结构里一个号都没有就退回
// 正则。不管走哪条路，出来的都是同一种条目形状。
function renewItemsFrom(body) {
  const parsed = parseRenewPayload(body);
  if (parsed && parsed.items.length) return parsed;
  const items = extractRenewKeys(body).map((key) => ({
    key, region: "", status: "",
    claimId: 0, channelName: "", seatNo: 0, seatsTotal: 0, claimTime: 0, warrantyUntil: 0,
  }));
  if (!parsed) return { code: null, msg: "", items, rows: 0, structured: false };
  // 结构认出来了但没号（正在补货）：保留 code / msg，调度那边要靠它区分排队和故障。
  return { ...parsed, items };
}
// 座位信息压成一行，面板测试结果和日志共用。
function renewItemNote(it) {
  const parts = [];
  if (it.channelName) parts.push(it.channelName);
  if (it.seatNo) parts.push("座位 " + it.seatNo + (it.seatsTotal ? "/" + it.seatsTotal : ""));
  if (it.status && it.status !== "active") parts.push("状态 " + it.status);
  if (it.warrantyUntil) {
    const left = it.warrantyUntil - Date.now();
    parts.push(left > 0 ? "质保剩 " + Math.max(1, Math.round(left / 60000)) + " 分钟" : "质保已过");
  }
  return parts.join(" · ");
}

function clampInt(value, range, def) {
  const n = Math.round(Number(value));
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(n, range[0]), range[1]);
}
function getRenewPrefs() {
  const out = {
    enabled: pref("renewEnabled", RENEW_DEFAULTS.enabled) === true,
    apiUrl: String(pref("renewApiUrl", RENEW_DEFAULTS.apiUrl) || "").trim(),
    autoImport: pref("renewAutoImport", RENEW_DEFAULTS.autoImport) !== false,
    alwaysPoll: pref("renewAlwaysPoll", RENEW_DEFAULTS.alwaysPoll) === true,
  };
  for (const name of Object.keys(RENEW_LIMITS)) {
    out[name] = clampInt(pref("renew_" + name, RENEW_DEFAULTS[name]), RENEW_LIMITS[name], RENEW_DEFAULTS[name]);
  }
  return out;
}
async function setRenewPrefs(patch) {
  const p = patch && typeof patch === "object" ? patch : {};
  if (typeof p.enabled === "boolean") await setPref("renewEnabled", p.enabled);
  if (typeof p.apiUrl === "string") await setPref("renewApiUrl", p.apiUrl.trim().slice(0, 2000));
  if (typeof p.autoImport === "boolean") await setPref("renewAutoImport", p.autoImport);
  if (typeof p.alwaysPoll === "boolean") await setPref("renewAlwaysPoll", p.alwaysPoll);
  for (const name of Object.keys(RENEW_LIMITS)) {
    if (p[name] == null) continue;
    await setPref("renew_" + name, clampInt(p[name], RENEW_LIMITS[name], RENEW_DEFAULTS[name]));
  }
}
// 现在有几把能用的密钥。这就是「触发阈值」对着看的那个数：冷却中的、已失效 /
// 额度用尽 / 已禁用的都不算。
function usableKeyCount() {
  return getApiKeys().filter((k) => keyIsUsable(k)).length;
}
// 号池测试列表里只要「认得出是哪一把」，所以只留前缀和后 4 位。
function maskRenewKey(k) {
  const s = String(k || "");
  if (s.length <= 8) return s;
  return s.slice(0, 4) + "…" + s.slice(-4);
}
function renewSleep(ms) {
  return new Promise((r) => setTimeout(r, Math.max(0, Number(ms) || 0)));
}
// 拉一次号池 API。走原生 http/https，因为号池地址可能是自建的 http 服务。
function renewFetch(url) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = new URL(String(url || "").trim()); }
    catch { return reject(new Error("号池 API 不是合法的 URL")); }
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      return reject(new Error("号池 API 只支持 http / https"));
    }
    const mod = target.protocol === "https:" ? https : http;
    const started = Date.now();
    const req = mod.request(
      {
        method: "GET",
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: target.pathname + target.search,
        headers: {
          Accept: "application/json, text/plain, */*",
          "user-agent": "kiro-gateway/" + currentVersion(),
        },
        timeout: RENEW_FETCH_TIMEOUT_MS,
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (d) => {
          size += d.length;
          if (size <= RENEW_BODY_CAP) chunks.push(d);
        });
        res.on("end", () => resolve({
          status: Number(res.statusCode) || 0,
          body: Buffer.concat(chunks).toString("utf8"),
          ms: Date.now() - started,
        }));
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("请求超时")));
    req.end();
  });
}
// 从响应正文里捞出去重后的 key，保持出现顺序。
function extractRenewKeys(body) {
  const out = [];
  const seen = new Set();
  const re = new RegExp(RENEW_KEY_RE.source, "g");
  let m;
  while ((m = re.exec(String(body || ""))) !== null) {
    if (seen.has(m[0])) continue;
    seen.add(m[0]);
    out.push(m[0]);
  }
  return out;
}
// 拉一次并把号整理出来，测试按钮和真正的轮询都走这里。
// keys 保留是为了让只关心「有几把号」的调用方不用改写法。
async function renewProbe(url) {
  const target = String(url || "").trim() || getRenewPrefs().apiUrl;
  if (!target) throw new Error("请先填写号池 API");
  const res = await renewFetch(target);
  const parsed = renewItemsFrom(res.body);
  return {
    status: res.status,
    ms: res.ms,
    body: res.body,
    code: parsed.code,
    msg: parsed.msg,
    structured: parsed.structured,
    items: parsed.items,
    keys: parsed.items.map((it) => it.key),
  };
}
// 验证一把新号：拿它去各候选地区问一次用量接口，2xx（或被限流的 429）说明这把号
// 是真的，同时也就知道了它属于哪个地区。额度已经跑满的号不收 —— 补进来也用不了。
// 这里刻意不写地区缓存：测试按钮也会走这个函数，不该污染缓存，落缓存放到导入之后。
// hint.region：号池自己写明的区域（结构化响应里的 aws_region / zone）。先只探这
// 一个，命中就省掉一整轮多区并发探测；没命中再退回全量探测 —— 号池写错区域的情况
// 也得兜住。
async function verifyRenewKey(key, hint) {
  const hinted = String(hint?.region || "").trim();
  let region = "";
  if (hinted) {
    try {
      const p = await probeRegion(hinted, key);
      if (p.hit || p.soft) region = hinted;
    } catch {}
  }
  if (!region) {
    try {
      region = (await detectRegionForKey(key)).region || "";
    } catch (e) {
      return { ok: false, region: "", info: null, message: e?.message || String(e) };
    }
  }
  if (!region) return { ok: false, region: "", info: null, message: "候选地区都不认这把 key" };
  let info = null;
  // 拿不到套餐信息不影响判定（这个接口偶尔不给用），只是列表里少显示点东西。
  try { info = await fetchAccountInfo(key); } catch {}
  const used = Number(info && info.used);
  const total = Number(info && info.total);
  if (Number.isFinite(used) && Number.isFinite(total) && total > 0 && used >= total) {
    return { ok: false, region, info, message: "额度已用尽" };
  }
  return { ok: true, region, info, message: "" };
}
// 把验证通过的新号并进密钥列表。entries: [{ key, region }]
async function importRenewKeys(entries) {
  const list = getApiKeys();
  const existing = new Set(list);
  const fresh = entries.filter((e) => e && e.key && !existing.has(e.key));
  if (!fresh.length) return 0;
  await setApiKeys([...list, ...fresh.map((e) => e.key)]);
  // 新号从干净状态开始，别继承同一把 key 以前留下的终态。
  forgetKeyHealth(fresh.map((e) => e.key));
  // 验证时已经探到地区了，顺手记下来，导入后第一次用就不必再探一遍。
  for (const e of fresh) {
    if (e.region) { try { await rememberRegionFor(e.key, e.region); } catch {} }
  }
  await applyState({ silent: true });
  // 当前那把已经不可用时，让新号立刻接手。
  maybeAdoptUsableKey();
  if (panelProvider) panelProvider.pushState();
  return fresh.length;
}

// --- 待导入暂存区 -----------------------------------------------------------
// 「自动导入」关掉时，验证通过的新号先落在这里，由用户在面板上点确认才进密钥
// 列表。有人不愿意让插件自己往列表里塞号（比如想先看看是哪个区、什么套餐），
// 这块暂存区就是给这种用法的。
//
// 落盘而不是只放内存：拉到的号重载窗口后还在，否则等于白拉一趟。存的是明文
// key —— 和 apiKeys 本身一样（那也是明文配置项），没有引入新的暴露面。
const RENEW_PENDING_STATE_KEY = "kiroGateway.renewPending";
const RENEW_PENDING_CAP = 50; // 上限：没人来确认时也不会无限堆下去
let _renewPending = []; // [{ key, region, title, used, total, note, at }]
function loadRenewPending() {
  if (!extContext) return;
  let saved = null;
  try { saved = extContext.globalState.get(RENEW_PENDING_STATE_KEY); } catch {}
  if (!Array.isArray(saved)) return;
  // 已经手动加进密钥列表的、以及重复条目，加载时顺手清掉。
  const skip = new Set(getApiKeys());
  const out = [];
  for (const e of saved) {
    if (!e || typeof e !== "object" || typeof e.key !== "string") continue;
    if (skip.has(e.key)) continue;
    skip.add(e.key);
    out.push({
      key: e.key,
      region: String(e.region || ""),
      title: String(e.title || ""),
      used: Number(e.used),
      total: Number(e.total),
      note: String(e.note || ""),
      at: posNum(e.at) || Date.now(),
    });
    if (out.length >= RENEW_PENDING_CAP) break;
  }
  _renewPending = out;
  if (_renewPending.length) log("待导入暂存区恢复了 " + _renewPending.length + " 个新号");
}
async function saveRenewPending() {
  if (!extContext) return;
  try { await extContext.globalState.update(RENEW_PENDING_STATE_KEY, _renewPending); } catch {}
}
// 面板要显示的形状。带上完整 key：面板据它来点「导入这一个」，跟密钥列表的做法一致。
function renewPendingSnapshot() {
  return _renewPending.map((e) => ({
    key: e.key,
    masked: maskRenewKey(e.key),
    region: e.region,
    title: e.title,
    used: Number.isFinite(e.used) ? e.used : null,
    total: Number.isFinite(e.total) ? e.total : null,
    note: e.note,
    at: e.at,
  }));
}
// 重复判定要连暂存区一起看，否则已经暂存、还没确认的号会在下一轮被当成新号，
// 白验一次往返。
function renewKnownKeys() {
  // 刚被自动删掉的坏号也算「已知」：号池很可能立刻又把同一把发下来，收它只是再走一
  // 遍导入 → 撞墙 → 判死 → 删除。过了记忆期还给同一把就再收，那时额度可能真重置了。
  const dead = [];
  for (const k of [..._deadKeyAt.keys()]) if (isRecentlyDeadKey(k)) dead.push(k);
  return new Set([...getApiKeys(), ..._renewPending.map((e) => e.key), ...dead]);
}
// 验证通过的号进暂存区。entries: [{ key, region, info }]
async function stashRenewKeys(entries) {
  const known = renewKnownKeys();
  const add = [];
  for (const e of entries) {
    if (!e || !e.key || known.has(e.key)) continue;
    known.add(e.key);
    const info = e.info || null;
    add.push({
      key: e.key,
      region: String(e.region || ""),
      title: String((info && info.subscriptionTitle) || ""),
      used: Number(info && info.used),
      total: Number(info && info.total),
      note: String(e.note || ""),
      at: Date.now(),
    });
  }
  if (!add.length) return 0;
  // 新的排前面，超出上限时丢最旧的那些。
  _renewPending = [...add, ..._renewPending].slice(0, RENEW_PENDING_CAP);
  await saveRenewPending();
  if (panelProvider) panelProvider.pushState();
  return add.length;
}
// 从暂存区导入。keys 为空 = 全部导入。
async function importPendingKeys(keys) {
  const want = Array.isArray(keys) && keys.length ? new Set(keys.map(String)) : null;
  const picked = _renewPending.filter((e) => !want || want.has(e.key));
  if (!picked.length) return 0;
  const n = await importRenewKeys(picked.map((e) => ({ key: e.key, region: e.region })));
  const gone = new Set(picked.map((e) => e.key));
  _renewPending = _renewPending.filter((e) => !gone.has(e.key));
  await saveRenewPending();
  if (panelProvider) panelProvider.pushState();
  return n;
}
// 丢弃暂存区里的号。keys 为空 = 全部丢弃。
async function dropPendingKeys(keys) {
  const want = Array.isArray(keys) && keys.length ? new Set(keys.map(String)) : null;
  const before = _renewPending.length;
  _renewPending = want ? _renewPending.filter((e) => !want.has(e.key)) : [];
  if (_renewPending.length === before) return 0;
  await saveRenewPending();
  if (panelProvider) panelProvider.pushState();
  return before - _renewPending.length;
}
// 验证通过的新号该去哪：自动导入就直接进密钥列表，否则进暂存区等确认。
// 返回 { imported, stashed }，调用方据此写日志和决定下一轮的节奏。
async function deliverRenewKeys(entries) {
  if (getRenewPrefs().autoImport) {
    return { imported: await importRenewKeys(entries), stashed: 0 };
  }
  return { imported: 0, stashed: await stashRenewKeys(entries) };
}

// --- 调度 -------------------------------------------------------------------
// phase 就是面板上那行状态：
//   off      没启用，或者号池 API 还没填
//   idle     可用密钥够用，待命
//   waiting  低于阈值，等下一次轮询
//   polling  正在拉号
//   backoff  上一轮失败，退避中
//   dup      拉到的全是重复，重复 Key 冷却中
//   pending  自动导入关着，暂存区已有号在等用户确认，先不拉了
//   breaker  连续失败触发熔断，冷却中
//   stopped  最大轮询次数用完，停手
let _renewTimer = null;
let _renewBusy = false;   // 一轮正在跑，心跳不要叠上去
let _renewForce = false;  // 面板点了「立即续号」：忽略阈值和停手状态，跑一轮
let _renew = {
  phase: "off",
  rounds: 0,          // 本次触发已经跑了几轮
  fails: 0,           // 连续失败次数（熔断用）
  nextAt: 0,          // 下一轮的时间点
  breakerUntil: 0,
  dupUntil: 0,
  imported: 0,        // 本次触发累计导入了几把
  stashed: 0,         // 本次触发累计暂存了几把（自动导入关着时）
  lastAt: 0,          // 上一轮结束时间
  lastMessage: "",    // 上一轮结果，面板直接显示
};
function resetRenewCounters() {
  _renew.rounds = 0;
  _renew.fails = 0;
  _renew.nextAt = 0;
  _renew.breakerUntil = 0;
  _renew.dupUntil = 0;
  _renew.imported = 0;
  _renew.stashed = 0;
}
function renewStatusSnapshot() {
  const p = getRenewPrefs();
  const now = Date.now();
  return {
    phase: _renew.phase,
    rounds: _renew.rounds,
    maxRounds: p.maxRounds,
    fails: _renew.fails,
    breakerThreshold: p.breakerThreshold,
    usable: usableKeyCount(),
    threshold: p.threshold,
    imported: _renew.imported,
    stashed: _renew.stashed,
    pendingCount: _renewPending.length,
    autoImport: p.autoImport,
    alwaysPoll: p.alwaysPoll,
    waitMs: Math.max(0, _renew.nextAt - now),
    breakerMs: Math.max(0, _renew.breakerUntil - now),
    dupMs: Math.max(0, _renew.dupUntil - now),
    lastAt: _renew.lastAt,
    lastMessage: _renew.lastMessage,
  };
}
function setRenewPhase(phase) {
  if (_renew.phase === phase) return;
  _renew.phase = phase;
  // 状态跟着统计一起推：面板每几秒拉一次 stats，倒计时因此能自己走。
  if (panelProvider) panelProvider.pushStats();
}
// 指数退避：基础退避 × 2^(连续失败-1)，夹到最大退避，再叠一个 ±抖动%。
// 抖动是为了让多个客户端不齐刷刷地在同一秒重试。
function renewBackoffMs(p, fails) {
  const base = Math.max(1000, p.backoffBaseSec * 1000);
  const max = Math.max(base, p.backoffMaxSec * 1000);
  const grown = Math.min(base * Math.pow(2, Math.max(0, fails - 1)), max);
  const jitter = p.jitterPct / 100;
  if (jitter <= 0) return Math.round(grown);
  return Math.max(1000, Math.round(grown + grown * jitter * (Math.random() * 2 - 1)));
}
// 现在该显示哪个 phase。心跳的判断和一轮跑完后的即时刷新共用这一套规则，
// 两处的措辞才不会打架。"due" 表示到点了该拉，只有心跳会用到它。
function computeRenewPhase(p, now = Date.now()) {
  if (!p.apiUrl || !p.enabled) return "off";
  // 持续囤号不看阈值：号池出了新号就收下，跟当前够不够用无关。
  if (!p.alwaysPoll && usableKeyCount() >= p.threshold) return "idle";
  // 自动导入关着、暂存区里已经躺着号：活儿干完了，就差确认，别接着拉号池。
  if (!p.autoImport && _renewPending.length > 0) return "pending";
  if (now < _renew.breakerUntil) return "breaker";
  if (now < _renew.dupUntil) return "dup";
  // 「最大轮询次数」是补到够用就停手的保险，持续囤号本来就没有终点，不受它限制。
  // 熔断和退避照旧生效 —— 那两个护的是号池，任何模式都不能省。
  if (!p.alwaysPoll && _renew.rounds >= p.maxRounds) return "stopped";
  if (now < _renew.nextAt) return _renew.fails > 0 ? "backoff" : "waiting";
  return "due";
}
// 跑一轮：按「单次批量数」发若干次请求，每次之间隔「同轮请求间隔」。
// 只负责拉 + 验 + 导入，节奏决策交给 runRenewRound。
// force：来自面板的「立即续号」，这一轮不受启用开关约束。
async function pollRenewOnce(p, force) {
  const r = { found: 0, dup: 0, invalid: 0, errors: 0, imported: 0, stashed: 0, queued: 0, notes: [] };
  for (let i = 0; i < p.batchSize; i++) {
    if (i > 0 && p.requestGapSec > 0) await renewSleep(p.requestGapSec * 1000);
    // 等待期间用户可能把开关关掉了，别接着打。
    if (!force && !getRenewPrefs().enabled) break;
    let probe;
    try {
      probe = await renewProbe(p.apiUrl);
    } catch (e) {
      r.errors++;
      r.notes.push("请求失败: " + (e?.message || e));
      continue;
    }
    if (probe.status < 200 || probe.status >= 300) {
      r.errors++;
      r.notes.push("HTTP " + probe.status);
      continue;
    }
    // 业务码失败而且一个号都没给：HTTP 是 200，但对面明确说不行（队列满、令牌
    // 过期之类），拿 msg 当原因比「响应里没有 key」有用得多。
    if (!renewCodeOk(probe.code) && !probe.items.length) {
      r.errors++;
      r.notes.push(probe.msg || "号池返回业务码 " + probe.code);
      continue;
    }
    if (!probe.items.length) {
      // 「已进拼车队列，暂无可用号，正在补货，补到后自动为你发车」是正常排队：
      // 按等号处理，不往熔断上累 —— 否则几轮就停手，反而错过发车。
      if (probe.structured) {
        r.queued++;
        r.notes.push(probe.msg || "号池暂无可用号");
      } else {
        r.errors++;
        r.notes.push("响应里没有 ksk_ 开头的 key");
      }
      continue;
    }
    // 只收 status 是 active 的号：号池标了状态而不是 active 的，连验都不用验。
    // 完全没给 status 的（纯文本号池、一行一个 ksk_）没法判断，照旧放行 —— 那种
    // 号池要是也拦掉，就一个号都收不到了。
    const alive = probe.items.filter((it) => !it.status || it.status === "active");
    const skipped = probe.items.filter((it) => it.status && it.status !== "active");
    if (skipped.length) {
      // 把具体状态列出来，方便对着号池的文档确认过滤是不是拦对了。
      const kinds = [...new Set(skipped.map((it) => it.status))];
      r.notes.push(skipped.length + " 个号状态不是 active（" + kinds.join(" / ") + "），已跳过");
      log("自动续号: 跳过 " + skipped.length + " 个非 active 的号（" + kinds.join(" / ") + "）");
    }
    if (!alive.length) {
      r.queued++;
      continue;
    }
    r.found += alive.length;
    // 重复的直接跳过，一次往返都不浪费。已经在待导入暂存区里的也算重复 ——
    // 不然没确认导入的那些号每轮都会被重新验一遍。
    const known = renewKnownKeys();
    const fresh = alive.filter((it) => !known.has(it.key));
    r.dup += alive.length - fresh.length;
    if (!fresh.length) continue;
    const good = [];
    for (const it of fresh) {
      // 条目本身就带着号池写明的区域，验号时直接用，省掉一轮多区探测。
      const v = await verifyRenewKey(it.key, it);
      if (v.ok) {
        good.push({ key: it.key, region: v.region, info: v.info, note: renewItemNote(it) });
        const note = renewItemNote(it);
        if (note) log("自动续号: " + maskRenewKey(it.key) + " " + note);
      } else {
        r.invalid++;
        r.notes.push(maskRenewKey(it.key) + " 验证不通过: " + v.message);
      }
    }
    if (good.length) {
      const d = await deliverRenewKeys(good);
      r.imported += d.imported;
      r.stashed += d.stashed;
    }
  }
  return r;
}
// 一轮的完整流程：跑 + 根据结果决定下一次什么时候来。
async function runRenewRound(p, force) {
  _renew.rounds++;
  const r = await pollRenewOnce(p, force);
  const now = Date.now();
  // 有号进来就算这一轮有收获。「自动导入」关着时号落在待导入暂存区，同样算收获：
  // 该做的活儿都干完了，只差用户点一下确认。
  if (r.imported > 0 || r.stashed > 0) {
    _renew.imported += r.imported;
    _renew.stashed += r.stashed;
    _renew.fails = 0;
    _renew.nextAt = now + p.intervalSec * 1000;
    const got = [];
    if (r.imported) got.push("导入 " + r.imported + " 个新 key");
    if (r.stashed) got.push("暂存 " + r.stashed + " 个新 key，等你确认导入");
    _renew.lastMessage = got.join("，")
      + (r.dup ? "，跳过 " + r.dup + " 个重复" : "")
      + (r.invalid ? "，" + r.invalid + " 个验证不通过" : "");
    log("自动续号: 第 " + _renew.rounds + " 轮 " + _renew.lastMessage);
    return;
  }
  // 号池明确说了在排队 / 补货（结构化响应里 data 是空的）：这既不是失败也不是
  // 重复，按普通轮询间隔继续等就行 —— 发车是对面推的，等的就是那一下，压太久
  // 反而白等。连续失败计数保持清零，不让排队把熔断喂饱。
  if (r.queued > 0 && r.errors === 0 && r.invalid === 0 && r.dup === 0) {
    _renew.fails = 0;
    _renew.nextAt = now + p.intervalSec * 1000;
    _renew.lastMessage = (r.notes[0] || "号池暂无可用号")
      + "，" + p.intervalSec + " 秒后再看一次";
    log("自动续号: 第 " + _renew.rounds + " 轮 " + _renew.lastMessage);
    return;
  }
  // 一把都没进来。全是重复说明号池还没出新号：这不算失败，不该触发熔断。
  if (r.dup > 0 && r.errors === 0 && r.invalid === 0) {
    _renew.fails = 0;
    if (p.alwaysPoll) {
      // 持续囤号模式下重复是常态（号池就守着那几个号），不该按十分钟压住 ——
      // 「守在号池边上等新号」本来就是这个模式的用途，按普通间隔继续看就行。
      _renew.nextAt = now + p.intervalSec * 1000;
      _renew.lastMessage = "拉到的 " + r.dup + " 个 key 全是重复，"
        + p.intervalSec + " 秒后再看一次";
    } else {
      // 只在缺号时才补的模式下，全是重复意味着这一趟白跑，压久一点再来。
      _renew.dupUntil = now + p.dupCooldownSec * 1000;
      _renew.nextAt = _renew.dupUntil;
      _renew.lastMessage = "拉到的 " + r.dup + " 个 key 全是重复，冷却 " + p.dupCooldownSec + " 秒";
    }
    log("自动续号: 第 " + _renew.rounds + " 轮 " + _renew.lastMessage);
    return;
  }
  // 真失败：退避，并累计连续失败次数。
  _renew.fails++;
  const note = r.notes.slice(0, 3).join("；") || "没拿到可用的新 key";
  if (_renew.fails >= p.breakerThreshold) {
    _renew.breakerUntil = now + p.breakerCooldownSec * 1000;
    _renew.nextAt = _renew.breakerUntil;
    _renew.fails = 0;
    _renew.lastMessage = "连续失败 " + p.breakerThreshold + " 次触发熔断，冷却 "
      + p.breakerCooldownSec + " 秒（" + note + "）";
  } else {
    const wait = renewBackoffMs(p, _renew.fails);
    _renew.nextAt = now + wait;
    _renew.lastMessage = note + "，退避 " + Math.round(wait / 1000) + " 秒后重试";
  }
  log("自动续号: 第 " + _renew.rounds + " 轮失败 — " + _renew.lastMessage);
}
// 心跳：绝大多数时候只做几次时间比较就返回。
async function renewTick() {
  if (_renewBusy) return;
  const p = getRenewPrefs();
  const force = _renewForce;
  if (!p.apiUrl || (!p.enabled && !force)) {
    _renewForce = false;
    setRenewPhase("off");
    return;
  }
  if (!force) {
    const phase = computeRenewPhase(p);
    if (phase === "idle") {
      // 补够了：把这次触发的计数全部复位，等下次掉下去重新开始。
      if (_renew.rounds || _renew.fails || _renew.nextAt || _renew.breakerUntil || _renew.dupUntil) {
        resetRenewCounters();
      }
      setRenewPhase("idle");
      return;
    }
    // 只有「到点了该拉」才往下走，其余几种都是在等。
    if (phase !== "due") { setRenewPhase(phase); return; }
  }
  _renewForce = false;
  _renewBusy = true;
  setRenewPhase("polling");
  try {
    await runRenewRound(p, force);
  } catch (e) {
    _renew.lastMessage = "出错: " + (e?.message || e);
    log("!! 自动续号出错: " + (e?.message || e));
  } finally {
    _renewBusy = false;
    _renew.lastAt = Date.now();
    // 立刻按新的计数算出该显示什么，别让面板等到下一次心跳。这里一定不会是
    // "due"：不管成功、重复还是失败，上面都把 nextAt 推到了将来。
    const next = computeRenewPhase(getRenewPrefs());
    _renew.phase = next === "due" ? "waiting" : next;
    if (panelProvider) panelProvider.pushStats();
  }
}
function startRenewLoop() {
  if (_renewTimer) return;
  _renewTimer = setInterval(() => { renewTick().catch(() => {}); }, RENEW_TICK_MS);
  renewTick().catch(() => {});
}
function stopRenewLoop() {
  if (_renewTimer) { clearInterval(_renewTimer); _renewTimer = null; }
}
// 开关或参数变动后调用：开着就确保心跳在跑，关了就停下来。
function syncRenewLoop() {
  const p = getRenewPrefs();
  if (p.enabled && p.apiUrl) {
    startRenewLoop();
  } else {
    stopRenewLoop();
    setRenewPhase("off");
  }
}
// 面板上的「立即续号」：清掉退避 / 熔断 / 停手状态，忽略阈值立刻跑一轮。
async function renewKickNow() {
  const p = getRenewPrefs();
  if (!p.apiUrl) throw new Error("请先填写号池 API");
  resetRenewCounters();
  _renewForce = true;
  _renew.lastMessage = "已手动触发";
  // 启用状态下顺手把心跳挂起来，这样手动跑完还能自动接着补。
  if (p.enabled) startRenewLoop();
  await renewTick();
  return renewStatusSnapshot();
}
// 面板「测试」：拉一次之后把每把 key 真验一遍（地区 + 用量接口），一个都不导入。
// 早先这里还有一个只测链接、不验号的 testRenewLink，但它的结论（通不通、有几个
// key）已经全在这份结果里，面板上分成两个按钮只是让人多点一次，合并掉了。
async function testRenewAvailability(url) {
  const probe = await renewProbe(url);
  rememberRenewTest(probe.items);
  // 面板上只显示一行结论，诊断细节落到运行日志里 —— 要对格式、看状态码和耗时的
  // 时候去那儿查，界面不为这点信息多占一行。
  log("号池测试: HTTP " + probe.status
    + (probe.code != null ? " · code " + probe.code : "")
    + " · " + probe.ms + "ms · 提取 " + probe.items.length + " 个 key"
    + (probe.msg ? " · " + probe.msg.slice(0, 120) : ""));
  const existing = renewKnownKeys();
  const rows = [];
  let usable = 0;
  // 带下标遍历：面板要把「状态正常且可用」的号单独列出来、并且逐个导入，光有掩码
  // 认不出该收哪一把 —— idx 指向 _renewLastTest.items，导入时凭它取回真实 key。
  for (let idx = 0; idx < probe.items.length; idx++) {
    const it = probe.items[idx];
    const seat = renewItemNote(it);
    if (existing.has(it.key)) {
      rows.push({
        idx, masked: maskRenewKey(it.key), dup: true, ok: false, region: it.region || "",
        seat, note: ["已存在", seat].filter(Boolean).join(" · "),
      });
      continue;
    }
    // 号池已经标了状态的，不是 active 的直接判掉，不浪费一次验证往返。
    if (it.status && it.status !== "active") {
      rows.push({
        idx, masked: maskRenewKey(it.key), dup: false, ok: false, region: it.region || "",
        seat, note: ["号池状态 " + it.status, seat].filter(Boolean).join(" · "),
      });
      continue;
    }
    const v = await verifyRenewKey(it.key, it);
    if (v.ok) usable++;
    const info = v.ok ? v.info : null;
    const hasQuota = !!(info && info.total != null);
    rows.push({
      idx,
      masked: maskRenewKey(it.key),
      dup: false,
      ok: v.ok,
      region: v.region || it.region || "",
      // 额度拆成结构化字段：面板列表照「待导入」那套排版（套餐 · 已用/总量），
      // 不必再从 note 那串拼好的文本里反解。
      title: (info && info.subscriptionTitle) || "",
      used: hasQuota ? Math.round(info.used || 0) : null,
      total: hasQuota ? Math.round(info.total) : null,
      seat,
      // 没通过时把原因留在这儿，失败的行仍然要能说清为什么。
      reason: v.ok ? "" : (v.message || ""),
      note: [
        v.ok
          ? [info && info.subscriptionTitle, hasQuota
              ? Math.round(info.used || 0) + "/" + Math.round(info.total)
              : ""].filter(Boolean).join(" · ")
          : v.message,
        seat,
      ].filter(Boolean).join(" · "),
    });
  }
  return {
    ok: usable > 0,
    status: probe.status,
    ms: probe.ms,
    code: probe.code,
    msg: probe.msg,
    total: probe.items.length,
    dup: rows.filter((r) => r.dup).length,
    usable,
    keys: rows,
    preview: probe.items.length || probe.msg ? "" : String(probe.body || "").trim().slice(0, 200),
  };
}
// 最近一次测试提取到的号，供面板上的「导入这些 Key」用。测试本身从不导入，但看完
// 结果往往就想直接收下 —— 面板那边只有掩码，没有这份缓存就没法告诉宿主要收哪几把。
let _renewLastTest = { items: [], at: 0 };
function rememberRenewTest(items) {
  _renewLastTest = { items: (items || []).map((it) => ({ ...it })), at: Date.now() };
}
// 把最近一次测试里能收的号验一遍再交付（自动导入开着就进密钥列表，关着就进暂存区）。
// 已存在的、以及号池标了非 active 的直接跳过。
async function importRenewTestKeys(indices) {
  if (!_renewLastTest.items.length) {
    throw new Error("请先点「测试」拉一次号");
  }
  // indices 省略 = 把这一轮能收的全收下（面板上的「全部导入」）；带下标 = 只收
  // 列表里点的那一行。下标对应 _renewLastTest.items，掩码认不出是哪一把。
  const picked = Array.isArray(indices) && indices.length
    ? indices
        .map((i) => ({ it: _renewLastTest.items[Number(i)], idx: Number(i) }))
        .filter((x) => x.it)
    : _renewLastTest.items.map((it, idx) => ({ it, idx }));
  if (!picked.length) {
    throw new Error("选中的号已经不在最近一次测试结果里，请重新测试");
  }
  const known = renewKnownKeys();
  const todo = [];
  // 已经收不了的下标也回报给面板：这一轮后台轮询可能已经把某把号收走了，
  // 那它就该从「可用号」清单里消失，而不是留着让人反复点、每次都被跳过。
  const skippedIdx = [];
  for (const one of picked) {
    const { it, idx } = one;
    if (!known.has(it.key) && (!it.status || it.status === "active")) todo.push(one);
    else skippedIdx.push(idx);
  }
  const skipped = skippedIdx.length;
  if (!todo.length) {
    return { imported: 0, stashed: 0, skipped, invalid: 0, doneIdx: [], skippedIdx };
  }
  const good = [];
  // 真正交付出去的下标回报给面板，收下的行就从可用列表里划掉，剩下的还能接着点。
  const doneIdx = [];
  let invalid = 0;
  for (const { it, idx } of todo) {
    const v = await verifyRenewKey(it.key, it);
    if (v.ok) {
      good.push({ key: it.key, region: v.region, info: v.info, note: renewItemNote(it) });
      doneIdx.push(idx);
    } else invalid++;
  }
  const d = good.length ? await deliverRenewKeys(good) : { imported: 0, stashed: 0 };
  // 验证不通过的（invalid）故意不回报下标 —— 有可能只是这一次网络抖动，
  // 留在清单里还能再点一次，收不上才是真坏。
  return { ...d, skipped, invalid, doneIdx, skippedIdx };
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------
function updateStatusBar() {
  if (!statusBarItem) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = "kiroGateway.openPanel";
  }
  // 有待生效的更新时，状态栏优先说这件事，并且点一下就直接重载。
  if (_pendingUpdate) {
    statusBarItem.text = "$(sync) Kiro Gateway: 待重载生效";
    statusBarItem.tooltip = "已安装 v" + _pendingUpdate.version + "（运行中 v" + currentVersion()
      + "）· 点击重新加载窗口生效";
    statusBarItem.command = "kiroGateway.reloadWindow";
    statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    statusBarItem.show();
    return;
  }
  const relayMode = isRelayMode();
  const on = isEnabled() && credentialsReady();
  const icon = relayMode ? "$(arrow-swap)" : "$(key)";
  statusBarItem.command = "kiroGateway.openPanel";
  statusBarItem.backgroundColor = undefined;
  // 状态栏带上模式，双模式共存时一眼能看出现在走的是哪条路。
  statusBarItem.text = icon + " Kiro Gateway: " + (on ? modeLabel() : "未开启");
  if (!on) {
    statusBarItem.tooltip = "Kiro Gateway 未启用（点击打开面板）"
      + (isEnabled() && !credentialsReady()
        ? relayMode ? " · 中转站地址或 Key 还没填" : " · 还没有可用的 API Key"
        : "");
  } else if (relayMode) {
    const snap = relay.relaySnapshot();
    statusBarItem.tooltip = "中转站模式 · " + snap.baseUrl
      + (snap.models.count ? " · " + snap.models.count + " 个模型" : "");
  } else {
    statusBarItem.tooltip = "APIKEY 直连 · region=" + getRegion()
      + (isRegionAuto() ? "（自动识别）" : "") + " · " + maskKey(getApiKey());
  }
  statusBarItem.show();
}

// ---------------------------------------------------------------------------
// Apply current state: (re)bind servers + sync endpoint override.
// Serialized so overlapping calls (toggle + config-change listener) don't write
// codewhisperer.config concurrently, which triggers write conflicts.
// ---------------------------------------------------------------------------
let _applyChain = Promise.resolve();
function applyState(opts = {}) {
  const run = () => _applyStateImpl(opts);
  _applyChain = _applyChain.then(run, run);
  return _applyChain;
}
// 上一次绑定服务器时用的模式。模式一变就必须重建监听器 —— 端口和处理器都换了。
let _boundMode = "";
async function _applyStateImpl(opts = {}) {
  const mode = getMode();
  const { krs, cps } = activePorts();
  if (isEnabled() && credentialsReady()) {
    // A port change must recreate the listener. Previously the old server was
    // kept alive while settings were rewritten to the new (unbound) port.
    const modeChanged = _boundMode !== mode;
    if (krsServer && (modeChanged || krsServer.port !== krs)) { krsServer.stop(); krsServer = null; }
    if (cpsServer && (modeChanged || cpsServer.port !== cps)) { cpsServer.stop(); cpsServer = null; }
    if (modeChanged && _boundMode) log("模式切换: " + (MODE_LABEL[_boundMode] || _boundMode) + " -> " + MODE_LABEL[mode]);
    if (!krsServer) {
      resetProxyHitMarkers();
      krsServer = new ProxyServer(krs, mode === MODE_RELAY ? relay.makeRelayKrsHandler() : makeKrsHandler(), "KRS");
      krsServer.start();
    }
    if (!cpsServer) {
      cpsServer = new ProxyServer(cps, mode === MODE_RELAY ? relay.makeRelayCpsHandler() : makeCpsHandler(), "CPS");
      cpsServer.start();
    }
    _boundMode = mode;
  } else {
    // Disabled (or no credentials): tear the proxies down so the local ports
    // are freed instead of lingering and holding them.
    if (krsServer) { krsServer.stop(); krsServer = null; log("[KRS] stopped (disabled)"); }
    if (cpsServer) { cpsServer.stop(); cpsServer = null; log("[CPS] stopped (disabled)"); }
    _boundMode = "";
    // Nothing can still be in flight once the listener is gone; make sure the
    // live "进行中" indicator can't stay stuck.
    if (_statsInflight !== 0) { _statsInflight = 0; pushStatsNow(); }
  }
  const { bound, changed } = await syncEndpoints();
  // 后台账号巡检跟着开关 / 模式 / 密钥数量走：网关没开或切到中转站就停掉，不做
  // 无意义的探测。
  syncHealthSweep();
  // 推理平面真探活也跟着走。它比巡检重（每次消耗一次生成请求），所以默认关闭，
  // 只有用户显式打开 livenessCheckEnabled 才跑。
  syncLivenessScheduler();
  updateStatusBar();
  if (changed && !opts.silent) {
    const pick = await vscode.window.showInformationMessage(
      "Kiro Gateway 已接管内置对话。需要重新加载窗口后 Kiro 才会走新端点。",
      "重新加载窗口"
    );
    if (pick === "重新加载窗口") await vscode.commands.executeCommand("workbench.action.reloadWindow");
  }
  return { bound, changed };
}

// 切换工作模式。两种模式端口不同，端点重定向必须跟着改，所以切完要重载窗口才
// 真正生效 —— Kiro 只在启动时读一次端点配置。
async function switchModeTo(mode) {
  const next = await setMode(mode);
  // 上一个站点的模型列表 / 用量缓存作废，免得切回来看到的是旧数据。
  relay.invalidateRelayCaches();
  await applyState({ silent: true });
  panelProvider && panelProvider.pushState();
  const pick = await vscode.window.showInformationMessage(
    "已切换到「" + (MODE_LABEL[next] || next) + "」。需要重新加载窗口后 Kiro 才会走新端点。",
    "重新加载窗口"
  );
  if (pick === "重新加载窗口") await vscode.commands.executeCommand("workbench.action.reloadWindow");
  return next;
}

// ---------------------------------------------------------------------------
// Webview control panel
// ---------------------------------------------------------------------------
class ControlPanelProvider {
  constructor() { this.view = null; }
  resolveWebviewView(webviewView) {
    this.view = webviewView;
    const distRoot = vscode.Uri.joinPath(extContext.extensionUri, "webview-ui", "dist");
    webviewView.webview.options = { enableScripts: true, localResourceRoots: [distRoot] };
    webviewView.webview.html = this.getHtml(webviewView.webview, distRoot);
    webviewView.webview.onDidReceiveMessage(async (msg) => {
      try { await this.onMessage(msg); } catch (e) { this.post({ type: "error", message: e?.message || String(e) }); }
    });
    this.pushState();
  }
  post(m) {
    if (!this.view) return;
    // The webview is disposed whenever the panel is hidden, and stats pushes
    // fire from background traffic, so posting can hit a dead view. Swallow it
    // instead of throwing out of a timer.
    try { this.view.webview.postMessage(m); } catch {}
  }
  pushState() {
    const rh = registryHealth();
    const keys = getApiKeys();
    const active = getActiveApiKey();
    this.post({
      type: "state",
      enabled: isEnabled(),
      // region 是这把号实际会走的区域：自动模式下用它自己探测到的那个，探过才有
      // 值，没探过就落到全局配置。面板按号显示，不再让用户手选。
      keys: keys.map((k, i) => ({
        index: i,
        masked: maskKeyLong(k),
        full: panelFullKey(k),
        kind: isJsonKey(k) ? "json" : "apikey",
        addedAt: keyAddedAt(k),
        region: regionForKey(k),
      })),
      keyCount: keys.length,
      activeIndex: active ? keys.indexOf(active) : -1,
      region: getRegion(),
      regionAuto: isRegionAuto(),
      regionDetecting: isRegionDetecting(),
      regionCandidates: REGION_CANDIDATES,
      ports: getPorts(),
      // 双模式：mode 决定面板显示哪一套配置，relay* 是中转站那一侧的全部状态。
      mode: getMode(),
      relayPorts: getRelayPorts(),
      relay: { ...relayPrefs(), ...relay.relaySnapshot() },
      registered: rh.registered,
      obsolete: rh.obsolete,
      hideApiKey: getHideApiKey(),
      autoRefresh: getAutoRefresh(),
      pendingUpdate: pendingUpdateInfo(),
      autoReloadOnUpdate: pref("autoReloadOnUpdate", false) === true,
      prompts: getPromptPrefs(),
      autoSwitch: getSwitchPrefs(),
      retry: getRetryPrefs(),
      // 生成端点链与限流处置策略。面板只读展示，改动走 settings.json 或命令面板。
      endpoints: {
        list: GEN_ENDPOINTS.map((e) => ({ id: e.id, label: e.label, base: e.base(getRegion()) })),
        preferred: getPreferredEndpointId(),
        fallback: getEndpointFallback(),
        cooldownMs: getEndpointCooldownMs(),
        ...getEndpointRoundPrefs(),
        patience: getThrottlePatience(),
        serverErrorRetry: getServerErrorRetryPrefs(),
      },
      // 探活 + 号变废自动删的开关与上一轮结果。
      liveness: livenessStateSnapshot(),
      // Agent 命令确认弹窗自动放行。
      autoAllow: autoAllowEnabled(),
      autoRenew: getRenewPrefs(),
      // 待导入暂存区：「自动导入」关掉时新号先落这里，等用户在面板上确认。
      renewPending: renewPendingSnapshot(),
      // 网关实际跑没跑起来。开关开着不等于端口就是自己的 —— 多窗口时很可能是
      // 隔壁窗口在转发，顶栏要把这件事说清楚。
      gateway: gatewayRuntimeState(),
      gatewayPlanes: gatewayPlaneStates(),
      version: currentVersion(),
      repoUrl: REPO_URL,
    });
    this.pushStats();
  }
  // 面板「统计」卡片用的实时计数。顺带把处于冷却中的密钥一起送过去：面板每几秒
  // 拉一次，冷却剩余时间因此能自己走。
  pushStats() {
    this.post({
      type: "stats",
      stats: statsSnapshot(),
      keyStats: keyStatsSnapshot(),
      cooldowns: cooldownSnapshot(),
      keyStatus: keyStatusSnapshot(),
      // 自动续号的运行状态跟着统计一起走：面板每几秒拉一次，倒计时自己会动。
      renew: renewStatusSnapshot(),
      // 端点冷却剩余时间、探活上一轮结果、已探明的能力缺失，都是会动的量，跟着
      // 统计一起推，面板不用自己算。
      endpointStatus: endpointStatusSnapshot(),
      liveness: livenessStateSnapshot(),
      endpointUnsupported: unsupportedSnapshot(),
      at: Date.now(),
    });
  }
  // Sync account info (subscription tier + credits) for the given key indices.
  // Results stream back per-key as they resolve; a final accountDone stamps the
  // sync time. Shared by the manual "fetchAccount" flow and post-add sync.
  //
  // opts.retries / opts.retryDelayMs: a freshly-created ksk_ key often isn't
  // queryable on the backend for the first second or two, so the immediate
  // post-add sync can fail even though the key is valid (a manual "立即同步"
  // a moment later succeeds). Retrying a few times papers over that window so
  // the new key doesn't render a stale "同步失败".
  async syncAccounts(targets, opts = {}) {
    const { retries = 0, retryDelayMs = 1500, force = false } = opts;
    const keys = getApiKeys();
    let valid = targets.filter((idx) => idx >= 0 && idx < keys.length);
    // 已失效 / 已禁用 / 额度用尽是终态：不再重复探测，省掉一次往返，状态也不会
    // 被网络抖动改写。这些行继续显示上一次拿到的套餐和积分。只有用户在某一行
    // 手动点「同步账户信息」（force）才会再查一次，作为人工复核的出口。
    if (!force) valid = valid.filter((idx) => !keyHealthFrozen(keys[idx]));
    // 过滤后可能一个都不剩，这时也要补一条 accountDone，否则面板的「同步中…」
    // 会一直转。
    if (!valid.length) { this.post({ type: "accountDone", at: Date.now() }); return; }
    // Query keys in small concurrent batches instead of all at once: syncing
    // dozens/hundreds of keys with a single Promise.all would fire that many
    // simultaneous backend requests. Running BATCH_SIZE at a time (and waiting
    // for each batch before starting the next) keeps it fast while capping the
    // burst. We also don't emit "accountLoading" — the UI keeps showing the
    // previous value and silently swaps in the fresh result when each resolves.
    const BATCH_SIZE = 5;
    const syncOne = async (idx) => {
      let lastErr;
      // 面板这一次探测也记进"上次探测时间"，宿主端的后台巡检就不会紧接着再打
      // 同一把号一遍。
      noteKeyProbed(keys[idx]);
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const info = await fetchAccountInfo(keys[idx]);
          // 同步结果同时用来判定账号状态（正常 / 额度用尽 / 已失效）。
          noteAccountHealth(keys[idx], true, info);
          // Include the key string so the webview can cache by key identity
          // (stable across reorders) instead of a volatile array index.
          this.post({ type: "accountResult", index: idx, key: panelFullKey(keys[idx]), ok: true, info });
          return;
        } catch (e) {
          lastErr = e;
          if (attempt < retries) await new Promise((r) => setTimeout(r, retryDelayMs));
        }
      }
      const failMsg = lastErr?.message || String(lastErr);
      // 整个错误对象交过去：里面带着 HTTP 状态码和响应体，判定才有硬依据。
      noteAccountHealth(keys[idx], false, null, lastErr);
      this.post({ type: "accountResult", index: idx, key: panelFullKey(keys[idx]), ok: false, message: failMsg });
    };
    for (let i = 0; i < valid.length; i += BATCH_SIZE) {
      const batch = valid.slice(i, i + BATCH_SIZE);
      await Promise.all(batch.map(syncOne));
    }
    this.post({ type: "accountDone", at: Date.now() });
  }
  async onMessage(msg) {
    switch (msg.type) {
      case "ready":
        this.pushState();
        break;
      // --- 生成端点 / 探活 / 自动放行 -------------------------------------
      // 端点参数改动会影响下一次转发走哪个主机，改完顺手把生效的链打进日志。
      case "setEndpointPrefs": {
        const p = msg.prefs || {};
        if (typeof p.preferred === "string" && GEN_ENDPOINTS.some((e) => e.id === p.preferred)) {
          await set("preferredEndpoint", p.preferred);
        }
        if (typeof p.fallback === "boolean") await set("endpointFallback", p.fallback);
        if (Number.isFinite(Number(p.cooldownMs))) await set("endpointCooldownMs", Math.round(Number(p.cooldownMs)));
        if (Number.isFinite(Number(p.rounds))) await set("endpointRounds", Math.round(Number(p.rounds)));
        if (Number.isFinite(Number(p.delayMs))) await set("endpointRoundDelayMs", Math.round(Number(p.delayMs)));
        if (typeof p.throttleRetryForever === "boolean") await set("throttleRetryForever", p.throttleRetryForever);
        if (Number.isFinite(Number(p.throttleBackoffCapMs))) await set("throttleBackoffCapMs", Math.round(Number(p.throttleBackoffCapMs)));
        if (typeof p.serverErrorRetry === "boolean") await set("serverErrorRetry", p.serverErrorRetry);
        if (Number.isFinite(Number(p.serverErrorRetryMax))) await set("serverErrorRetryMax", Math.round(Number(p.serverErrorRetryMax)));
        logEndpointChain();
        this.pushState();
        break;
      }
      // 端点冷却和能力缺失都只在内存里，清掉相当于"忘掉刚才那几次失败"，
      // 下一次请求重新从首选端点起步。
      case "resetEndpointState": {
        for (const e of GEN_ENDPOINTS) endpointClearCooldown(e.id);
        resetEndpointUnsupported();
        log("端点状态已重置：冷却与能力缺失记录全部清空");
        this.pushStats();
        break;
      }
      case "setLivenessPrefs": {
        const p = msg.prefs || {};
        if (typeof p.enabled === "boolean") await set("livenessCheckEnabled", p.enabled);
        if (Number.isFinite(Number(p.intervalSec))) await set("livenessCheckIntervalSec", Math.round(Number(p.intervalSec)));
        if (Number.isFinite(Number(p.perKeyIntervalSec))) await set("livenessRealCheckPerKeyIntervalSec", Math.round(Number(p.perKeyIntervalSec)));
        if (typeof p.autoDelete === "boolean") await set("autoDeleteOnDead", p.autoDelete);
        syncLivenessScheduler();
        this.pushState();
        break;
      }
      case "livenessCheckNow": {
        const r = await runLivenessScan({ manual: true });
        if (r && r.skipped) this.post({ type: "toast", message: "上一轮探活还没跑完，稍后再试" });
        this.pushStats();
        break;
      }
      case "setAutoAllow": {
        await set("autoAllow.enabled", !!msg.value);
        // 配置监听里也会同步一次，这里显式调用是为了面板点完立刻生效，不等事件。
        syncAutoAllow("面板");
        this.pushState();
        break;
      }
      // --- 双模式与中转站 -----------------------------------------------
      case "setMode": {
        const next = msg.mode === MODE_RELAY ? MODE_RELAY : MODE_OFFICIAL;
        if (next === getMode()) break;
        await switchModeTo(next);
        break;
      }
      case "setRelay": {
        // 面板一次提交整份草稿：地址、Key 和各项翻译参数一起落盘，避免逐项写配置
        // 时被中间态触发多次 applyState。
        const patch = msg.patch && typeof msg.patch === "object" ? msg.patch : {};
        const FIELDS = {
          baseUrl: "relayBaseUrl",
          apiKey: "relayApiKey",
          maxTokens: "relayMaxTokens",
          thinking: "relayThinking",
          thinkingBudget: "relayThinkingBudget",
          effortMode: "relayEffortMode",
          effortBudgets: "relayEffortBudgets",
          defaultModel: "relayDefaultModel",
          modelMapping: "relayModelMapping",
          interceptIntentClassifier: "relayInterceptIntentClassifier",
          promptCaching: "relayPromptCaching",
        };
        let credsChanged = false;
        for (const [field, confKey] of Object.entries(FIELDS)) {
          if (!(field in patch)) continue;
          let v = patch[field];
          if (field === "baseUrl" || field === "apiKey" || field === "defaultModel") v = String(v || "").trim();
          if (field === "maxTokens" || field === "thinkingBudget") v = Number(v) || 0;
          if (field === "interceptIntentClassifier") v = !!v;
          if ((field === "baseUrl" || field === "apiKey") && v !== get(confKey, "")) credsChanged = true;
          await set(confKey, v);
        }
        if (credsChanged) relay.invalidateRelayCaches();
        // 中转站模式下改地址/Key 会让「凭证齐了没有」的结论变化，要重新接管端点。
        if (isRelayMode()) await applyState({ silent: true });
        this.pushState();
        this.post({ type: "toast", message: "中转站配置已保存" });
        break;
      }
      case "testRelay": {
        this.post({ type: "relayTesting" });
        try {
          const r = await relay.testRelayConnection();
          this.post({ type: "relayTestResult", ...r });
        } catch (e) {
          this.post({ type: "relayTestResult", ok: false, message: e?.message || String(e) });
        }
        this.pushState();
        break;
      }
      case "refreshRelayModels": {
        this.post({ type: "relayModelsLoading" });
        try {
          await relay.fetchRelayModels(true);
          this.post({ type: "relayModels", ...relay.relaySnapshot().models });
        } catch (e) {
          this.post({ type: "relayModels", error: e?.message || String(e), count: 0, ids: [] });
        }
        this.pushState();
        break;
      }
      case "fetchRelayUsage": {
        this.post({ type: "relayUsageLoading" });
        try {
          this.post({ type: "relayUsage", ...(await relay.fetchRelayUsage(!!msg.force)) });
        } catch (e) {
          this.post({ type: "relayUsage", ok: false, message: e?.message || String(e) });
        }
        break;
      }
      case "importJsonFiles": {
        const result = await importJsonCredentialFiles();
        if (result.cancelled) break;
        if (result.message && (!result.ingested || !result.ingested.added.length)) {
          this.post({ type: "error", message: result.message });
          break;
        }
        await applyIngestedCredentials(result.ingested, result.failed);
        break;
      }
      case "addKey": {
        const v = String(msg.value || "").trim();
        if (!v) { this.post({ type: "error", message: "密钥不能为空" }); break; }
        const ingested = await ingestRawCredentials([v]);
        if (!ingested.added.length) {
          this.post({ type: "error", message: ingested.dup ? "该密钥或 JSON 凭证已存在" : "无法识别：请粘贴 ksk_ 密钥或 JSON 凭证（需含 refreshToken）" });
          break;
        }
        const list = getApiKeys();
        const newIndex = list.length;
        await setApiKeys([...list, ...ingested.added]);
        forgetKeyHealth(ingested.added);
        await applyState();
        maybeAdoptUsableKey();
        await ensureRegionDetected({ silent: true });
        this.pushState();
        this.post({ type: "toast", message: ingested.added.length > 1 ? "已添加 " + ingested.added.length + " 个凭证" : "已添加密钥" });
        if (getAutoRefresh()) await this.syncAccounts(ingested.added.map((_, i) => newIndex + i), { retries: 3, retryDelayMs: 1500 });
        break;
      }
      case "addKeys": {
        // Batch add: validate + de-dupe and persist in ONE write. Adding keys
        // one-by-one races here because each webview message is handled
        // concurrently and reads the same pre-write list, so only the last
        // write would survive.
        const incoming = Array.isArray(msg.values) ? msg.values : [];
        const list = getApiKeys();
        const ingested = await ingestRawCredentials(incoming);
        const toAdd = ingested.added;
        const invalid = ingested.invalid, dup = ingested.dup;
        if (toAdd.length === 0) {
          this.post({ type: "error", message: "没有可添加的密钥（无效或重复）。支持 ksk_ 或含 refreshToken 的 JSON。" });
          break;
        }
        const startIndex = list.length;
        await setApiKeys([...list, ...toAdd]);
        forgetKeyHealth(toAdd);
        await applyState();
        maybeAdoptUsableKey();
        await ensureRegionDetected({ silent: true });
        this.pushState();
        const skipped = invalid + dup;
        this.post({
          type: "toast",
          message: skipped > 0
            ? `已添加 ${toAdd.length} 个密钥，忽略 ${skipped} 个（无效或重复）`
            : `已添加 ${toAdd.length} 个密钥`,
        });
        if (getAutoRefresh()) {
          await this.syncAccounts(
            toAdd.map((_, k) => startIndex + k),
            { retries: 3, retryDelayMs: 1500 }
          );
        }
        break;
      }
      case "deleteKey": {
        const list = getApiKeys();
        const i = Number(msg.index);
        if (i >= 0 && i < list.length) {
          const [gone] = list.splice(i, 1);
          await setApiKeys(list);
          forgetKeyHealth(gone);
          await applyState();
          maybeAdoptUsableKey();
          this.pushState();
          this.post({ type: "toast", message: "已删除密钥" });
        }
        break;
      }
      case "deleteKeys": {
        // Batch delete by index in ONE write. If the currently in-use key is
        // among them and the gateway is on, also turn the gateway off and
        // require a reload (mirroring the single delete-of-active flow).
        const list = getApiKeys();
        const valid = (Array.isArray(msg.indices) ? msg.indices : [])
          .map((n) => Number(n))
          .filter((i) => Number.isInteger(i) && i >= 0 && i < list.length);
        if (valid.length === 0) {
          this.post({ type: "error", message: "删除失败: 没有选中的密钥" });
          break;
        }
        const remove = new Set(valid);
        const activeKey = getActiveApiKey();
        const removingActive = !!activeKey && remove.has(list.indexOf(activeKey));
        const remaining = list.filter((_, i) => !remove.has(i));
        await setApiKeys(remaining);
        forgetKeyHealth(list.filter((_, i) => remove.has(i)));
        if (removingActive && isEnabled()) {
          await set("enabled", false);
          await applyState({ silent: true });
          this.pushState();
          this.post({
            type: "needReload",
            text: `已删除 ${valid.length} 个密钥（含当前使用的密钥）并关闭网关。重新加载窗口后恢复 Kiro 默认服务。`,
          });
        } else {
          await applyState();
          this.pushState();
          this.post({ type: "toast", message: `已删除 ${valid.length} 个密钥` });
        }
        break;
      }
      case "deleteKeyDisableGateway": {
        // Delete the key that's currently in use AND turn the gateway off in one
        // atomic host-side step, then require a reload. The webview shows its own
        // a-modal spinner + reload prompt, so applyState runs silent to avoid a
        // duplicate native VS Code dialog.
        const list = getApiKeys();
        const i = Number(msg.index);
        if (i >= 0 && i < list.length) {
          const [gone] = list.splice(i, 1);
          await setApiKeys(list);
          // 删掉就把它的状态判定一起丢掉，别让终态留在落盘里。
          forgetKeyHealth(gone);
          await set("enabled", false);
          await applyState({ silent: true });
          this.pushState();
          this.post({
            type: "needReload",
            text: "已删除当前使用的密钥并关闭网关。重新加载窗口后恢复 Kiro 默认服务。",
          });
        } else {
          this.post({ type: "error", message: "删除失败: 未找到该密钥" });
        }
        break;
      }
      case "selectKey": {
        const list = getApiKeys();
        const i = Number(msg.index);
        if (i >= 0 && i < list.length) {
          await set("activeApiKey", list[i]);
          // silent: 切换密钥不动端口也不动启用状态，本地端点不会变，用不着催重载。
          await applyState({ silent: true });
          // 换了密钥就顺带把地区对齐到这把密钥所属的区域：缓存命中是零开销，
          // 没缓存才探一次（两个候选并发，通常不到一秒）。
          await ensureRegionDetected({ silent: true });
          this.pushState();
          // 代理每次转发都实时读取当前密钥，所以手动切换和自动切号一样立即生效 ——
          // 后者走的就是同一条路径（adoptKey），从来不提示重载。早先这里弹「需要
          // 重新加载窗口」是历史遗留，白让用户多点一次，改成一个 toast 就够了。
          this.post({ type: "toast", message: "已切换密钥，立即生效" });
        }
        break;
      }
      case "copyKey": {
        const list = getApiKeys();
        const i = Number(msg.index);
        if (i >= 0 && i < list.length) {
          try {
            await vscode.env.clipboard.writeText(exportKeyText(list[i]));
            this.post({ type: "toast", message: isJsonKey(list[i]) ? "已复制 JSON 凭证到剪贴板" : "已复制完整密钥到剪贴板" });
          } catch (e) {
            this.post({ type: "error", message: "复制失败: " + (e?.message || e) });
          }
        } else {
          this.post({ type: "error", message: "复制失败: 未找到该密钥" });
        }
        break;
      }
      case "exportKeys": {
        // Export selected keys (by index) to a .txt file the user picks via a
        // native save dialog, one key per line.
        const list = getApiKeys();
        const picked = (Array.isArray(msg.indices) ? msg.indices : [])
          .map((n) => Number(n))
          .filter((i) => Number.isInteger(i) && i >= 0 && i < list.length)
          .map((i) => list[i]);
        if (picked.length === 0) {
          this.post({ type: "error", message: "导出失败: 没有可导出的密钥" });
          break;
        }
        try {
          const d = new Date();
          const p = (n) => String(n).padStart(2, "0");
          const name = `kiro-api-keys-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.txt`;
          const baseDir =
            (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0]?.uri.fsPath) ||
            require("os").homedir();
          const uri = await vscode.window.showSaveDialog({
            title: "导出 API Key",
            saveLabel: "导出",
            defaultUri: vscode.Uri.file(path.join(baseDir, name)),
            filters: { "文本文件": ["txt"], "所有文件": ["*"] },
          });
          if (!uri) break; // user cancelled
          const hasJson = picked.some(isJsonKey);
          const payload = hasJson
            ? JSON.stringify(picked.map((k) => isJsonKey(k) ? exportableJsonCred(k) : { apiKey: k }), null, 2) + "\n"
            : picked.join("\n") + "\n";
          fsMod.writeFileSync(uri.fsPath, payload, "utf8");
          this.post({ type: "toast", message: `已导出 ${picked.length} 个密钥` });
        } catch (e) {
          this.post({ type: "error", message: "导出失败: " + (e?.message || e) });
        }
        break;
      }
      case "saveRegion": {
        // value === "__auto" → 交给自动识别；其余值 → 固定用户选的地区。
        const raw = String(msg.value || "").trim();
        if (raw === "__auto") {
          await setRegionAutoPref(true);
          this.pushState();
          this.post({ type: "toast", message: "已开启地区自动识别，正在探测…" });
          const r = await ensureRegionDetected({ force: true, silent: false });
          if (r) this.post({ type: "toast", message: "地区已自动识别: " + r });
          break;
        }
        await setRegionAutoPref(false);
        await set("region", raw || DEFAULT_REGION);
        await applyState();
        this.pushState();
        this.post({ type: "toast", message: "Region 已保存: " + getRegion() });
        break;
      }
      case "detectRegion": {
        // 面板上的「重新识别」：忽略缓存重新探测，并把结果反馈给用户。
        if (!getApiKey()) {
          this.post({ type: "error", message: "请先添加 API Key 再识别地区" });
          break;
        }
        const r = await ensureRegionDetected({ force: true, silent: false });
        if (r) this.post({ type: "toast", message: "地区已自动识别: " + r });
        this.pushState();
        break;
      }
      case "toggle":
        await set("enabled", !!msg.value);
        // silent: 面板顶部会自己点亮一条重载提示（不是模态框，不打断操作），
        // 这里压掉 VS Code 原生对话框，免得同一件事提示两遍。
        await applyState({ silent: true });
        this.pushState();
        // 文案要说清「开关本身已经生效了」：端口、状态栏、面板当场就跟着变，
        // 重载只是让 Kiro 自带对话换端点。不然用户看到「需要重新加载」会以为
        // 刚才那一下没生效，白等在那儿。
        this.post({
          type: "needReload",
          text: msg.value
            ? "网关已开启，面板和状态栏已经生效，可以接着用。Kiro 自带对话要重新加载窗口后才走你的 API Key。"
            : "网关已关闭，可以接着用。Kiro 自带对话要重新加载窗口后才恢复默认端点。",
        });
        break;
      case "test": {
        const i = Number(msg.index);
        const keys = getApiKeys();
        const key = i >= 0 && i < keys.length ? keys[i] : getApiKey();
        this.post({ type: "testing", index: i });
        try {
          const r = await testKey(key);
          // 测试通过也是一次真实探测，用来刷新账号状态。
          noteAccountHealth(key, true, { used: r.used, total: r.total });
          this.post({ type: "testResult", index: i, ok: true, result: r });
        } catch (e) {
          const msg = e?.message || String(e);
          // 传错误对象而不是字符串：状态码在对象上，判定要靠它。
          noteAccountHealth(key, false, null, e);
          this.post({ type: "testResult", index: i, ok: false, message: msg });
        }
        break;
      }
      case "setHideApiKey":
        await setHideApiKeyPref(msg.value);
        this.pushState();
        break;
      case "setAutoRefresh":
        await setAutoRefreshPref(msg.value);
        this.pushState();
        break;
      case "setPrompt": {
        // which: "prefix" | "suffix"
        const which = msg.which === "suffix" ? "suffix" : "prefix";
        if (typeof msg.enabled === "boolean") await setPref(which + "Enabled", msg.enabled);
        if (typeof msg.text === "string") await setPref(which + "Text", msg.text.slice(0, 4000));
        this.pushState();
        break;
      }
      case "setAutoSwitch": {
        if (typeof msg.enabled === "boolean") await setPref("autoSwitch", msg.enabled);
        if (typeof msg.loadBalance === "boolean") {
          await setPref("loadBalance", msg.loadBalance);
          // 刚关掉均衡的话，当前选中的那把可能是上一轮轮转留下的。它自己还正常就
          // 继续用（用户看到的就是它），不正常才让 maybeAdoptUsableKey 换一把。
          if (!msg.loadBalance) maybeAdoptUsableKey();
        }
        if (msg.cooldownMs != null) {
          const ms = Math.round(Number(msg.cooldownMs));
          await setPref("switchCooldownMs", Number.isFinite(ms)
            ? Math.min(Math.max(ms, 0), 24 * 60 * 60 * 1000)
            : SWITCH_DEFAULT_COOLDOWN_MS);
        }
        this.pushState();
        break;
      }
      case "setAutoReload":
        await setPref("autoReloadOnUpdate", !!msg.value);
        this.pushState();
        break;
      case "setRenew": {
        // 面板「保存配置」一次性提交整份配置，宿主再夹一遍取值区间。
        await setRenewPrefs(msg.patch || {});
        // 参数变了就把这次触发的节奏计数复位：新的间隔 / 阈值应该立刻生效，
        // 而不是等旧的退避走完。
        resetRenewCounters();
        syncRenewLoop();
        this.pushState();
        this.post({ type: "toast", message: "自动续号配置已保存" });
        break;
      }
      case "testRenewKeys": {
        // 面板上就一个「测试」按钮：拉一次链接，再把拿到的号逐个验一遍。
        this.post({ type: "renewTesting", mode: "keys" });
        try {
          const result = await testRenewAvailability(msg.url);
          this.post({ type: "renewTestResult", mode: "keys", ...result });
        } catch (e) {
          this.post({ type: "renewTestResult", mode: "keys", ok: false, message: e?.message || String(e) });
        }
        break;
      }
      case "renewNow": {
        try {
          await renewKickNow();
          this.post({ type: "toast", message: _renew.lastMessage || "已触发一次续号" });
        } catch (e) {
          this.post({ type: "error", message: "续号失败: " + (e?.message || e) });
        }
        this.pushStats();
        break;
      }
      case "renewReset":
        // 停手 / 熔断之后的翻案出口：计数清零，心跳会立刻重新判断要不要补号。
        resetRenewCounters();
        _renew.lastMessage = "已重置续号计数";
        syncRenewLoop();
        this.pushStats();
        this.post({ type: "toast", message: "已重置续号计数" });
        break;
      case "importPending": {
        // keys 为空 = 全部导入。
        const n = await importPendingKeys(msg.keys);
        this.pushStats();
        if (n > 0) this.post({ type: "toast", message: "已导入 " + n + " 个新 key" });
        else this.post({ type: "error", message: "没有可导入的新 key" });
        break;
      }
      case "dropPending": {
        const n = await dropPendingKeys(msg.keys);
        this.pushStats();
        if (n > 0) this.post({ type: "toast", message: "已丢弃 " + n + " 个待导入的 key" });
        break;
      }
      case "importTestKeys": {
        // 可用号列表上的导入：indices 省略 = 全部导入，带下标 = 只收那一行。
        // 验一遍再按「自动导入」的设置交付。
        this.post({ type: "renewTesting", mode: "import", indices: msg.indices });
        try {
          const r = await importRenewTestKeys(msg.indices);
          const parts = [];
          if (r.imported) parts.push("导入 " + r.imported + " 个");
          if (r.stashed) parts.push("暂存 " + r.stashed + " 个待确认");
          if (r.skipped) parts.push("跳过 " + r.skipped + " 个已有/不可收");
          if (r.invalid) parts.push(r.invalid + " 个验证不通过");
          this.post({
            type: "renewTestResult",
            mode: "import",
            ok: r.imported > 0 || r.stashed > 0,
            // 收下的下标带回去，面板把对应行从可用列表里划掉，剩下的还能接着点。
            doneIdx: r.doneIdx || [],
            message: parts.length ? parts.join("，") : "没有可导入的新 key",
          });
          this.pushState();
        } catch (e) {
          this.post({ type: "renewTestResult", mode: "import", ok: false, message: e?.message || String(e) });
        }
        break;
      }
      case "clearCooldowns":
        // 连同"失效 / 额度用尽 / 已禁用"的判定一起清掉（含落盘的那份），让所有
        // 密钥重新回到未检测状态，下一次请求或同步会重新给出结论。额度用尽的号
        // 到了新周期要恢复，就从这里翻案。
        resetKeyHealth();
        // 地区识别缓存跟着一起清：下一次同步或转发会重新识别，订阅换了区域也能
        // 从这里翻案。
        await forgetRegionCache();
        this.pushStats();
        this.post({ type: "toast", message: "已重置全部账号状态" });
        break;
      case "setRetry": {
        if (typeof msg.enabled === "boolean") await setPref("retryEnabled", msg.enabled);
        if (Array.isArray(msg.rules)) await setPref("retryRules", normalizeRetryRules(msg.rules));
        if (msg.max != null) {
          const m = Math.round(Number(msg.max));
          await setPref("retryMax", Number.isFinite(m) ? Math.min(Math.max(m, 1), RETRY_MAX_CAP) : 2);
        }
        if (msg.delayMs != null) {
          const d = Math.round(Number(msg.delayMs));
          await setPref("retryDelayMs", Number.isFinite(d) ? Math.min(Math.max(d, 0), 60000) : 2000);
        }
        this.pushState();
        break;
      }
      case "fetchAccount": {
        // Sync account info. The webview may send an explicit ordered `indices`
        // array (top-of-list first); otherwise a single index, or all keys.
        const keys = getApiKeys();
        let targets;
        if (Array.isArray(msg.indices)) {
          targets = msg.indices.map(Number).filter((i) => Number.isInteger(i) && i >= 0 && i < keys.length);
        } else {
          const i = Number(msg.index);
          targets = i >= 0 && i < keys.length ? [i] : keys.map((_, idx) => idx);
        }
        // force 只由某一行右键的「同步账户信息」带上：那是用户点着某个号要复核，
        // 连已经冻结的终态也重查一次。定时刷新和「立即同步」都不 force，终态
        // 因此不会被反复探测。
        await this.syncAccounts(targets, { force: msg.force === true });
        break;
      }
      case "reload":
        await vscode.commands.executeCommand("workbench.action.reloadWindow");
        break;
      case "openExternal": {
        try { await vscode.env.openExternal(vscode.Uri.parse(String(msg.url || REPO_URL))); }
        catch (e) { this.post({ type: "error", message: "打开链接失败: " + (e?.message || e) }); }
        break;
      }
      case "getStats":
        this.pushStats();
        break;
      case "resetStats":
        await resetStats();
        this.post({ type: "toast", message: "统计已清零" });
        break;
      case "getLogs": {
        // Serve the in-memory ring buffer (last hour) so the panel's log drawer
        // shows recent activity without opening the output channel.
        this.post({ type: "logs", entries: getRecentLogs(), at: Date.now() });
        break;
      }
      case "copyLogs": {
        try {
          await vscode.env.clipboard.writeText(getRecentLogs().join("\n"));
          this.post({ type: "toast", message: "已复制日志到剪贴板" });
        } catch (e) {
          this.post({ type: "error", message: "复制失败: " + (e?.message || e) });
        }
        break;
      }
    }
  }
  getHtml(webview, distRoot) {
    const indexPath = vscode.Uri.joinPath(distRoot, "index.html").fsPath;
    let html;
    try {
      html = fsMod.readFileSync(indexPath, "utf8");
    } catch {
      return '<!DOCTYPE html><html><body style="font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground)">'
        + '<h3>Kiro Gateway</h3><p>Webview 尚未构建。请在 <code>webview-ui</code> 目录执行:</p>'
        + '<pre>npm install &amp;&amp; npm run build</pre></body></html>';
    }
    // Drop crossorigin (blocked in webviews) and rewrite ./assets/* to webview URIs.
    html = html.replace(/\s*crossorigin/g, "");
    html = html.replace(/(src|href)="\.?\/?(assets\/[^"]+)"/g, (_m, attr, rel) => {
      const uri = webview.asWebviewUri(vscode.Uri.joinPath(distRoot, rel));
      return attr + '="' + uri.toString() + '"';
    });
    const csp =
      '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
      + "img-src " + webview.cspSource + " https: data:; "
      + "style-src " + webview.cspSource + " 'unsafe-inline'; "
      + "font-src " + webview.cspSource + " data:; "
      + "script-src " + webview.cspSource + " 'unsafe-inline' 'unsafe-eval';\">";
    html = html.replace(/<head>/i, "<head>\n    " + csp);
    return html;
  }
}

// ---------------------------------------------------------------------------
// Agent 命令确认弹窗（Allow）自动放行
// ---------------------------------------------------------------------------
// Kiro 的 Trust v2 从 ~/.kiro/settings/permissions.yaml 读规则，PolicySession
// 监听该文件，改动后自动重建，不需要重载窗口。
//
// 写进去的规则就是 Kiro 内置 "allow-all" 预设的规则体本身：
//   { capability: "all", effect: "allow" }
// capability 的合法取值是分组 all / builtin / filesystem / sandbox_network 加十来个
// 单项；all = builtin + mcp，所以一条就覆盖 shell、文件读写、MCP、web 全部。
//
// 有六个内置强制询问项【改这个文件无效】，因为 Trust v2 的裁决顺序是
// deny > ask > allow，而这些规则由 kiro-agent 无条件注入（source: "kiro-scope"）：
//   .git  .vscode  .kiro/agents/**  .kiro/hooks/**  **/*.code-workspace  **/mcp.json
// 另有一条硬 deny：Agent 工具不允许写 ~/.kiro/settings/ 与 .kiro/settings/。
// 注意那条 deny 管的是 Agent 的 fs_write 工具，插件自己用 Node fs 直接写不经过
// 策略引擎，所以下面的写入是可行的。
const AUTO_ALLOW_MARKER = "# kiro-gateway:auto-allow";
const AUTO_ALLOW_MARKER_LINE =
  AUTO_ALLOW_MARKER + "  由插件维护：关掉 autoAllow.enabled 会自动删除下面这条规则";
const AUTO_ALLOW_HEADER = [
  "# Kiro Trust v2 权限规则",
  "# 本文件由 Kiro Gateway 创建。删掉整个文件即可恢复 Kiro 默认的逐项确认。",
];

// 极简 YAML 扫描器。只认「顶层 rules: 下面一层的列表项」这一种结构，够用来判断
// 有没有 all/allow 规则以及定位插件自己写的那一段。故意不引第三方 YAML 依赖：
// vsix 必须自包含，加依赖就得打包 node_modules。
function parseRuleItems(text) {
  const lines = String(text == null ? "" : text).split(/\r?\n/);
  const items = [];
  let inRules = false;
  let cur = null;
  let dashIndent = -1;
  const push = () => { if (cur) { items.push(cur); cur = null; } };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\t/g, "  ");
    if (line.trim() === "" || /^\s*#/.test(line)) continue;
    const indent = line.length - line.replace(/^\s*/, "").length;
    if (!inRules) {
      if (/^rules\s*:\s*$/.test(line)) inRules = true;
      continue;
    }
    // 回到顶层的另一个键，说明 rules 段结束了
    if (indent === 0) { push(); break; }
    const dash = line.match(/^(\s*)-\s*(.*)$/);
    if (dash && (dashIndent < 0 || dash[1].length === dashIndent)) {
      push();
      dashIndent = dash[1].length;
      cur = { start: i, end: i, indent: dashIndent, keys: {} };
      const kv = dash[2].trim().match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/);
      if (kv) cur.keys[kv[1]] = kv[2].trim();
      continue;
    }
    if (cur && indent > dashIndent) {
      cur.end = i;
      const kv = line.trim().match(/^([A-Za-z_][\w-]*)\s*:\s*(.*)$/);
      if (kv && cur.keys[kv[1]] === undefined) cur.keys[kv[1]] = kv[2].trim();
    }
  }
  push();
  return items;
}

function unquote(v) {
  return String(v == null ? "" : v).trim().replace(/^["']|["']$/g, "");
}

// 已经有等价的全放行规则了吗（不管是谁写的）。
function hasAllowAllRule(text) {
  return parseRuleItems(text).some(
    (it) => unquote(it.keys.capability) === "all" && unquote(it.keys.effect) === "allow"
  );
}

function findRulesKeyLine(text) {
  const lines = String(text == null ? "" : text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) if (/^rules\s*:\s*$/.test(lines[i])) return i;
  return -1;
}

// 沿用文件里已有列表项的缩进，避免混用两种缩进把 YAML 弄坏。
function ruleItemIndent(text) {
  const items = parseRuleItems(text);
  return items.length > 0 ? items[0].indent : 2;
}

function buildAutoAllowLines(indent) {
  const pad = " ".repeat(Math.max(0, indent));
  return [
    pad + AUTO_ALLOW_MARKER_LINE,
    pad + "- capability: all",
    pad + "  effect: allow",
  ];
}

function freshPermissionsText() {
  return AUTO_ALLOW_HEADER.concat(["", "rules:"], buildAutoAllowLines(2), [""]).join("\n");
}

// text -> { text, changed, reason }。纯函数，不碰磁盘。
// reason 取值：created / inserted / already-allowed / no-rules-key
function addAutoAllowRule(text) {
  const raw = String(text == null ? "" : text);
  const meaningful = raw.split(/\r?\n/).some((l) => l.trim() !== "" && !/^\s*#/.test(l));
  if (!meaningful) return { text: freshPermissionsText(), changed: true, reason: "created" };
  if (hasAllowAllRule(raw)) return { text: raw, changed: false, reason: "already-allowed" };
  const at = findRulesKeyLine(raw);
  // 没有 rules: 顶层键就不猜结构 —— 宁可什么都不做，也不要写坏用户的文件。
  if (at < 0) return { text: raw, changed: false, reason: "no-rules-key" };
  const lines = raw.split(/\r?\n/);
  lines.splice(at + 1, 0, ...buildAutoAllowLines(ruleItemIndent(raw)));
  return { text: lines.join("\n"), changed: true, reason: "inserted" };
}

// 只删插件自己写的那一段（靠标记行定位），用户手写的同类规则一律不动。
// reason 取值：removed / absent
function removeAutoAllowRule(text) {
  const raw = String(text == null ? "" : text);
  const lines = raw.split(/\r?\n/);
  const at = lines.findIndex((l) => l.includes(AUTO_ALLOW_MARKER));
  if (at < 0) return { text: raw, changed: false, reason: "absent" };
  let end = at; // 含标记行
  let i = at + 1;
  while (i < lines.length && lines[i].trim() === "") i++;
  const dash = i < lines.length ? lines[i].match(/^(\s*)-\s*(.*)$/) : null;
  if (dash) {
    const dashIndent = dash[1].length;
    end = i;
    // 跟着的、缩进更深的行属于同一个列表项
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j];
      if (l.trim() === "") break;
      const ind = l.length - l.replace(/^\s*/, "").length;
      if (ind <= dashIndent) break;
      end = j;
    }
  }
  lines.splice(at, end - at + 1);
  return { text: lines.join("\n"), changed: true, reason: "removed" };
}

function autoAllowEnabled() {
  return get("autoAllow.enabled", false) === true;
}
function kiroSettingsDir() {
  return path.join(require("os").homedir(), ".kiro", "settings");
}
function permissionsYamlPath() {
  return path.join(kiroSettingsDir(), "permissions.yaml");
}
function permissionsJsonPath() {
  return path.join(kiroSettingsDir(), "permissions.json");
}

// 原子写 + 首次备份，与 writeEndpointToSettingsFile 的做法保持一致。
// 编码固定 UTF-8 无 BOM：Node 的 "utf8" 不写 BOM，中文注释才不会被解析器拒掉。
function writePermissionsFile(file, text) {
  fsMod.mkdirSync(path.dirname(file), { recursive: true });
  const backup = file + ".kiro-gateway.bak";
  if (fsMod.existsSync(file) && !fsMod.existsSync(backup)) {
    try { fsMod.copyFileSync(file, backup); log("permissions 首次备份 -> " + backup); } catch {}
  }
  const tmp = file + ".kiro-gateway.tmp";
  fsMod.writeFileSync(tmp, text, "utf8");
  try {
    fsMod.renameSync(tmp, file);
  } catch {
    fsMod.writeFileSync(file, text, "utf8");
    try { fsMod.unlinkSync(tmp); } catch {}
  }
}

// 幂等：已经放行就什么都不写。开关关掉时只回收插件自己加的那一段。
function syncAutoAllow(why) {
  const on = autoAllowEnabled();
  const file = permissionsYamlPath();
  const tag = "auto-allow" + (why ? " (" + why + ")" : "");
  try {
    const exists = fsMod.existsSync(file);
    // Trust v2 认 permissions.yaml 和 permissions.json 两种格式，YAML 优先。
    // 只有 json 时新建 yaml 会让用户原有的 json 规则被整份忽略，这种情况不动手。
    if (on && !exists && fsMod.existsSync(permissionsJsonPath())) {
      log("!! " + tag + ": 检测到 permissions.json 而没有 permissions.yaml。"
        + "新建 yaml 会让 json 里的规则全部失效（Trust v2 优先读 yaml），已跳过。"
        + "请手工把规则并到 permissions.yaml，或删掉 json。");
      return;
    }
    if (!on && !exists) return;
    const before = exists ? fsMod.readFileSync(file, "utf8") : "";
    const r = on ? addAutoAllowRule(before) : removeAutoAllowRule(before);
    if (!r.changed) {
      if (r.reason === "no-rules-key") {
        log("!! " + tag + ": " + file + " 里没有顶层 rules: 键，结构不明所以没动。"
          + "手工加一条 `- capability: all` / `  effect: allow` 即可。");
      } else {
        log(tag + ": 无需改动（" + r.reason + "）");
      }
      return;
    }
    writePermissionsFile(file, r.text);
    log(tag + ": " + r.reason + " -> " + file
      + (on ? " · capability all/allow 已生效，Agent 命令与文件写入不再逐条询问"
            : " · 已移除插件写入的放行规则，恢复逐项确认"));
    if (on) {
      log(tag + ": 以下内置强制询问项无法通过本文件关闭 —— "
        + ".git / .vscode / .kiro/agents/** / .kiro/hooks/** / *.code-workspace / mcp.json");
    }
  } catch (e) {
    log("!! " + tag + " 失败 (" + file + "): " + (e && e.message ? e.message : e));
  }
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------
async function activate(context) {
  extContext = context;
  loadStats();
  // 恢复已失效 / 额度用尽 / 已禁用的判定：这些号重载窗口后也不该被重新探测。
  loadKeyHealth();
  // 上次拉到但还没确认导入的新号，重载窗口后接着等确认。
  loadRenewPending();
  // 只保留当天数据：加载时先按日期滚动一次，再挂上 0 点自动清零的定时器。
  ensureToday();
  scheduleDailyReset();
  log("activate · 模式=" + modeLabel());
  logKiroHostInfo();
  selfHeal();
  // 把配置读取、日志、统计埋点递给中转站翻译层。统计走同一套计数器，面板上的
  // 请求数 / 用量在两种模式下是同一组数字。
  relay.init({
    prefs: relayPrefs,
    isEnabled,
    log,
    version: currentVersion,
    healthPath: HEALTH_PATH,
    healthMarker: HEALTH_MARKER,
    markProxyHit,
    applyPromptPrefs,
    stats: {
      requestStarted: statsRequestStarted,
      addOutBytes: statsAddOutBytes,
      requestFailed: statsRequestFailed,
      requestFinished: statsRequestFinished,
    },
  });
  try { await migrateLegacyKey(); } catch (e) { log("migrateLegacyKey failed: " + (e?.message || e)); }
  // 已有密钥补一次添加时间：升级到这个版本之前加的密钥、以及用户直接改配置塞进
  // 去的密钥，都是在这里第一次拿到时间戳。
  try { await syncKeyAddedAt(); } catch (e) { log("syncKeyAddedAt failed: " + (e?.message || e)); }

  panelProvider = new ControlPanelProvider();
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("kiroGateway.controlPanel", panelProvider)
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("kiroGateway.openPanel", async () => {
      await vscode.commands.executeCommand("workbench.view.extension.kiroGateway");
    }),
    // 状态栏的「待重载生效」点击后走这里，也可以从命令面板手动触发。
    vscode.commands.registerCommand("kiroGateway.reloadWindow", async () => {
      await vscode.commands.executeCommand("workbench.action.reloadWindow");
    }),
    vscode.commands.registerCommand("kiroGateway.checkUpdate", async () => {
      checkForPendingUpdate();
      if (!_pendingUpdate) vscode.window.showInformationMessage("Kiro Gateway 已是磁盘上的最新版本 v" + currentVersion());
    }),
    vscode.commands.registerCommand("kiroGateway.toggle", async () => {
      await set("enabled", !isEnabled());
      await applyState();
      panelProvider && panelProvider.pushState();
    }),
    // 命令面板里切模式。端点要换端口，所以切完照例提示重载窗口。
    vscode.commands.registerCommand("kiroGateway.importJsonFiles", async () => {
      const result = await importJsonCredentialFiles();
      if (result.cancelled) return;
      if (result.message && (!result.ingested || !result.ingested.added.length)) {
        vscode.window.showWarningMessage("Kiro Gateway: " + result.message);
        return;
      }
      await applyIngestedCredentials(result.ingested, result.failed);
    }),
    vscode.commands.registerCommand("kiroGateway.switchMode", async () => {
      const pick = await vscode.window.showQuickPick(
        [
          { label: MODE_LABEL.official, description: "官方 ksk_ 密钥直连 Kiro 服务", mode: MODE_OFFICIAL },
          { label: MODE_LABEL.relay, description: "转发到 Anthropic 格式的第三方中转站", mode: MODE_RELAY },
        ],
        { title: "选择工作模式", placeHolder: "当前：" + modeLabel() }
      );
      if (!pick || pick.mode === getMode()) return;
      await switchModeTo(pick.mode);
    }),
    // 立即跑一轮真探活。手动触发忽略"每号最短间隔"那道闸 —— 用户自己按的按钮，
    // 消耗一次生成请求的代价他知道。
    vscode.commands.registerCommand("kiroGateway.livenessCheckNow", async () => {
      if (!getApiKeys().length) {
        vscode.window.showWarningMessage("Kiro Gateway: 还没有配置密钥，无法探活。");
        return;
      }
      vscode.window.showInformationMessage("Kiro Gateway: 开始探活（每把密钥消耗一次生成请求）…");
      const r = await runLivenessScan({ manual: true });
      if (r && r.skipped) {
        vscode.window.showInformationMessage("Kiro Gateway: 上一轮探活还没跑完，稍后再试。");
        return;
      }
      const c = (r && r.counts) || {};
      vscode.window.showInformationMessage(
        "Kiro Gateway 探活完成：可用 " + (c.ok || 0)
        + " · 禁用 " + (c.suspended || 0)
        + " · 溢出 " + (c.overage_exceeded || 0)
        + " · 额度用尽 " + (c.quota || 0)
        + " · 失效 " + (c.invalid || 0)
        + ((r && r.deleted) ? " · 已删 " + r.deleted + " 把" : "")
      );
    }),
    // 命令面板里开关 Agent 命令自动放行，省得去设置里翻。
    vscode.commands.registerCommand("kiroGateway.toggleAutoAllow", async () => {
      const next = !autoAllowEnabled();
      await set("autoAllow.enabled", next);
      // 配置变更监听会顺手同步 permissions.yaml，这里只管提示。
      vscode.window.showInformationMessage(
        "Kiro Gateway: Agent 命令自动放行已" + (next ? "开启" : "关闭")
        + (next ? "（.git / .vscode / .kiro/agents / .kiro/hooks / *.code-workspace / mcp.json 仍会逐项询问）" : "")
      );
    }),
    vscode.commands.registerCommand("kiroGateway.test", async () => {
      try {
        const r = await testKey();
        vscode.window.showInformationMessage("Kiro Key 有效 · " + (r.subscription || "") + " · " + r.modelCount + " 个模型");
      } catch (e) {
        vscode.window.showErrorMessage("Kiro Key 测试失败: " + (e?.message || e));
      }
    })
  );

  // React to relevant config changes.
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      const hit = (k) => e.affectsConfiguration("kiroGateway." + k);
      // 权限自动放行：开关一变就立刻同步 permissions.yaml。Kiro 的 PolicySession
      // 监听这个文件，改完就生效，不用重载窗口。
      if (hit("autoAllow.enabled")) syncAutoAllow("配置变更");
      // 探活开关 / 间隔变了就重挂定时器。
      if (["livenessCheckEnabled", "livenessCheckIntervalSec"].some(hit)) syncLivenessScheduler();
      // 端点相关配置改了就把当前生效的链打进日志，省得靠猜。
      if (["preferredEndpoint", "endpointFallback", "endpointCooldownMs",
        "endpointRounds", "endpointRoundDelayMs"].some(hit)) logEndpointChain();
      // 换了区域，"哪个端点支持哪个操作"这份记录就不再适用（能力按端点 + 区域 +
      // 操作三元组记），清掉重新探。
      if (hit("region")) resetEndpointUnsupported();
      // 影响代理绑定或端点重定向的配置项，改动后都要重新 applyState。
      const needsApply = ["enabled", "apiKeys", "activeApiKey", "region", "ports",
        "mode", "relayBaseUrl", "relayApiKey", "relayPorts"].some(hit);
      // 只影响翻译行为的配置项，改了不用重绑服务器，刷个面板就行。
      const relayTweaked = ["relayMaxTokens", "relayThinking", "relayThinkingBudget",
        "relayEffortMode", "relayEffortBudgets", "relayDefaultModel", "relayModelMapping",
        "relayInterceptIntentClassifier", "relayPromptCaching"].some(hit);
      if (!needsApply && !relayTweaked) return;
      // 直接改配置加进来的密钥也要有添加时间。
      if (hit("apiKeys")) {
        try { await syncKeyAddedAt(); } catch {}
      }
      // 换了站点或换了 Key，上一个站点的模型列表和用量口径都不能再用。
      if (hit("relayBaseUrl") || hit("relayApiKey")) relay.invalidateRelayCaches();
      if (needsApply) await applyState({ silent: true });
      panelProvider && panelProvider.pushState();
    })
  );

  // 侧载安装后 Kiro 常常不提示重载，靠这个监视器自己发现并提醒。
  context.subscriptions.push(startUpdateWatch());

  await applyState({ silent: true });
  updateStatusBar();
  // 权限自动放行：按当前开关同步一次 ~/.kiro/settings/permissions.yaml。
  syncAutoAllow("启动");
  // 把生效的生成端点链打进日志，方便确认首选端点和回退参数。
  logEndpointChain();
  // 自动续号：开着就把心跳挂起来，可用密钥掉到阈值以下会自己去号池补。
  syncRenewLoop();
  // 启动时后台识别一次地区（自动模式 + 已有密钥时）。不 await：识别要发两个网络
  // 请求，不该拖慢插件激活；结果出来后会自己写配置、刷面板和状态栏。
  ensureRegionDetected({ silent: true }).catch(() => {});
  // 首轮账号巡检延后一点再跑：激活这会儿地区识别、端点校验都在飞，别挤在一起。
  // 之后交给 HEALTH_SWEEP_MS 的心跳。
  const firstSweep = setTimeout(() => { healthSweepOnce().catch(() => {}); }, 20000);
  context.subscriptions.push({ dispose: () => clearTimeout(firstSweep) });
}

function deactivate() {
  // NOTE: intentionally do NOT restore the endpoint override here.
  // deactivate() runs on every window reload; kiro-agent reads the endpoints
  // once at init. Wiping them on reload would drop the redirect before the
  // reloaded host re-applies it. Turn the gateway switch off to undo.
  if (krsServer) krsServer.stop();
  if (cpsServer) cpsServer.stop();
  stopUpdateWatch();
  stopDailyReset();
  stopRenewLoop();
  stopHealthSweep();
  stopLivenessScheduler();
  // Persist counters that are still inside the debounce window, otherwise the
  // last few seconds of traffic would be lost on reload.
  if (_statsFlushTimer) {
    clearTimeout(_statsFlushTimer);
    _statsFlushTimer = null;
    persistStatsNow();
  }
  // 这两个节流定时器原先漏在外面。窗口重载时它们还挂着，回调醒来时面板早就没了
  // （pushStats 里有 panelProvider 判空所以不会报错），但 _activeSyncTimer 会在
  // 卸载之后再写一次配置，属于不该发生的副作用。
  if (_statsPushTimer) { clearTimeout(_statsPushTimer); _statsPushTimer = null; }
  if (_activeSyncTimer) { clearTimeout(_activeSyncTimer); _activeSyncTimer = null; _activeSyncWant = ""; }
}

module.exports = { activate, deactivate };
