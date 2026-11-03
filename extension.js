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
// Upstream connection pool
//
// Every new connection pays for a full handshake: this machine → Clash → node server → target site, TCP across the three hops plus
// TLS, 4–6 RTTs in total. Measured at about 1.4s, while reusing an existing connection takes only 0.30s — one request
// is a 1.1-second gap, the single biggest cost on the whole path.
//
// Node's https.globalAgent has keepAlive on by default, but an idle socket is kept for only 5 seconds
// (measured: a 4s gap reuses in 0.31s, a 6s gap jumps back to 1.61s). The few requests Kiro fires within one turn
// can hit reuse, but across turns (the user reading the reply, typing) they almost always exceed 5 seconds, and the handshake is back.
// So we keep our own pool and stretch idle retention to 30 seconds.
//
// Prerequisite: Kiro must set
//     "http.proxySupport": "off"
//     "http.experimental.systemCertificatesV2": true
// Otherwise @vscode/proxy-agent replaces the agent passed in here entirely, and the one it puts in its place,
// PacProxyAgent, has keepAlive explicitly commented out (see vscode#228872), so this does nothing.
const UPSTREAM_AGENT = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 32,
  maxFreeSockets: 8,
  scheduling: "lifo", // Prefer the most recently used socket; the hit rate is higher than fifo
  timeout: 310000,    // Line this up with the per-request timeout so the agent does not cut off a long generation first
  family: 4,          // A broken IPv6 path drops the connection before the TLS handshake finishes
});

// The cost of reuse: an idle socket may already have been closed upstream, and a resend then reports ECONNRESET.
// The extension's existing isTransportFailure already lists econnreset as a transport failure, and the backoff-resend
// path catches exactly that, so no extra fault tolerance is needed here.
// Protocol-translation layer for relay mode. It does not require("vscode"); all config, logs, and stats are injected from here
// during activate via relay.init().
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
// stripProfileArnFromBody only covers operations that have a request body. The control plane has a batch of REST GET operations
// (GetUsageLimits / ListAvailableModels and the like) that serialize profileArn as a query parameter.
// A GET has no body, so that cleanup is a no-op and profileArn goes out together with the ksk_ credential.
// Upstream sees the impossible combination "API key credential + an OAuth identity's profileArn" and returns
// HTTP 403 {"message":"Invalid token"}.
//
// Symptom: Kiro's built-in account panel shows "Unable to fetch account usage data: Invalid
// token". The same URL with this parameter removed measures as 200 plus normal usage data.
// So the query string follows the same rule: if profileArn appears, strip it, and keep every other parameter as-is,
// order unchanged — forwarding is still "not one byte changed except the credentials and profileArn".
function stripProfileArnFromUrl(rawUrl) {
  const url = String(rawUrl || "");
  const q = url.indexOf("?");
  if (q < 0) return url;
  const pathPart = url.slice(0, q);
  // Search case-insensitively: parameter-name casing is not guaranteed across SDK versions.
  const kept = [];
  let removed = false;
  for (const pair of url.slice(q + 1).split("&")) {
    if (!pair) continue;
    const name = pair.split("=")[0];
    if (decodeURIComponent(name).toLowerCase() === "profilearn") { removed = true; continue; }
    kept.push(pair);
  }
  if (!removed) return url; // If it is not there, return the URL unchanged and never re-encode
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
  // Remote sessions often have several windows open at once; only the one holding the port actually forwards.
  // Config written in another window is not necessarily readable here, so the selected item's index is also written to a local file.
  // The file holds only the index, not the refresh token.
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
  // Also record when a new key was added, and drop the entry for a deleted key (the panel shows "added on").
  await syncKeyAddedAt(clean);
  await pruneJsonCreds(clean);
  return clean;
}
// When each key was added. Stored in globalState by fingerprint (no plaintext). The key list itself is
// a string array in config and cannot carry this kind of metadata.
function keyAddedAll() {
  const m = pref("keyAddedAt", {});
  return m && typeof m === "object" ? m : {};
}
function keyAddedAt(key) {
  const fp = keyFingerprint(key);
  if (!fp) return 0;
  return Number(keyAddedAll()[fp]) || 0;
}
// Stamp "now" onto keys that still have no timestamp, and drop keys that no longer exist. The first time you upgrade to this version,
// old keys have no real add time, so the moment we first see them is as close as we can get.
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
// Region candidates for auto-detection. Kiro currently only runs in Virginia (us-east-1) and Frankfurt
const REGION_CANDIDATES = ["us-east-1", "eu-central-1"];
// Auto-detection results are cached per key for this long. After expiry the next call probes again (if the subscription moves to another region
// we do not keep using the old result forever).
const REGION_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
function configuredRegion() {
  const r = String(get("region", DEFAULT_REGION) || DEFAULT_REGION).trim();
  return r || DEFAULT_REGION;
}
// Home region of a JSON credential. The region inside profileArn is where the account was registered, which is more reliable than "the usage API returned 200":
// Get-Usage-Limits can also return 200 in another region, but List-Available-Models then returns an empty list.
function jsonHomeRegion(key) {
  if (!isJsonKey(key)) return "";
  const cred = getJsonCred(key);
  if (!cred) return "";
  return regionFromProfileArn(cred.profileArn) || String(cred.region || "").trim();
}
// Cache of usage probes. Invalidate it when it contradicts profileArn, or a BuilderId-style account gets pinned to
// a region where usage can be queried but the model list is empty.
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
// Whether "region" is left to auto-detection. On by default: most users do not know which
// region their key belongs to. Having the extension ask both candidate endpoints once each is more reliable than making the user guess.
function isRegionAuto() {
  return pref("regionAuto", true) === true;
}
async function setRegionAutoPref(v) {
  await setPref("regionAuto", !!v);
}
// Regions that take part in probing: the built-in candidates plus the current config value (which may be a custom region the user typed).
function regionCandidates() {
  return [...new Set([...REGION_CANDIDATES, getRegion()]
    .map((r) => String(r || "").trim())
    .filter(Boolean))];
}
// Detection results are cached by key fingerprint (first 16 hex chars of sha256); the key plaintext is not stored.
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
  // Keep only keys that still exist; a deleted key leaves no trace.
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
// Working mode: official (APIKEY direct) / relay (relay station)
const MODE_OFFICIAL = "official";
const MODE_RELAY = "relay";
const MODE_LABEL = { official: "APIKEY 直连", relay: "中转站" };
// User-visible host strings. The panel has its own dictionary. Longest match wins.
const HOST_EN = {
  "APIKEY 直连": "API key",
  "中转站": "Relay",
  "未开启": "Off",
  "重新加载窗口": "Reload Window",
  "切换并重新加载": "Switch and reload",
  "Kiro Gateway 已接管内置对话。需要重新加载窗口后 Kiro 才会走新端点。": "Kiro Gateway is now in front of built-in chat. Reload the window before Kiro uses the new endpoint.",
  "Kiro Gateway 未启用（点击打开面板）": "Kiro Gateway is off (click to open the panel)",
  " · 中转站地址或 Key 还没填": " · relay address or key is missing",
  " · 还没有可用的 API Key": " · no API key yet",
  "中转站模式 · ": "Relay · ",
  " 个模型": " models",
  "APIKEY 直连 · region=": "API key · region=",
  "（自动识别）": " (auto)",
  "工作区设置覆盖了 ": "A workspace setting overrides ",
  "，请删除工作区中的同名配置后重新加载窗口。": ". Remove that workspace value, then reload the window.",
  "无法写入或验证 ": "Could not write or verify ",
  "。请打开日志查看实际 settings.json 路径。": ". Open the log to see the settings.json path.",
  "没能读到任何文件内容": "Could not read any file",
  "这些 JSON 凭证已经在列表里了": "These JSON credentials are already in the list",
  "文件里没有可识别的凭证（需要 refreshToken 或 ksk_）": "No usable credential in the file (need a refreshToken or a ksk_ key)",
  "已从文件导入 ": "Imported ",
  " 个凭证，忽略 ": " credentials, skipped ",
  " 个（无效或重复）": " (invalid or duplicate)",
  " 个凭证": " credentials",
  " 个文件读失败": " files could not be read",
  "自动识别失败：候选地区都没有响应，已保持 ": "Region detection failed: no candidate region responded. Kept ",
  "自动识别失败: ": "Region detection failed: ",
  "已自动识别地区: ": "Region detected: ",
  "上一轮探活还没跑完，稍后再试": "The previous liveness check is still running. Try again shortly.",
  "中转站配置已保存": "Relay settings saved",
  "密钥不能为空": "The key cannot be empty",
  "该密钥或 JSON 凭证已存在": "That key or JSON credential already exists",
  "无法识别：请粘贴 ksk_ 密钥或 JSON 凭证（需含 refreshToken）": "Unrecognized. Paste a ksk_ key or a JSON credential that includes refreshToken.",
  "已添加密钥": "Key added",
  "已添加 ": "Added ",
  " 个密钥，忽略 ": " keys, skipped ",
  " 个密钥（含当前使用的密钥）并关闭网关。重新加载窗口后恢复 Kiro 默认服务。": " keys (including the one in use) and turned the gateway off. Reload the window to restore Kiro's own service.",
  " 个密钥": " keys",
  "没有可添加的密钥（无效或重复）。支持 ksk_ 或含 refreshToken 的 JSON。": "Nothing to add (invalid or duplicate). ksk_ keys and JSON with refreshToken are accepted.",
  "已删除密钥": "Key deleted",
  "已删除 ": "Deleted ",
  "删除失败: 没有选中的密钥": "Delete failed: no key selected",
  "已删除当前使用的密钥并关闭网关。重新加载窗口后恢复 Kiro 默认服务。": "Deleted the key in use and turned the gateway off. Reload the window to restore Kiro's own service.",
  "删除失败: 未找到该密钥": "Delete failed: key not found",
  "已切换密钥，立即生效": "Switched keys. It takes effect now.",
  "已复制 JSON 凭证到剪贴板": "Copied the JSON credential",
  "已复制完整密钥到剪贴板": "Copied the full key",
  "复制失败: 未找到该密钥": "Copy failed: key not found",
  "复制失败: ": "Copy failed: ",
  "导出失败: 没有可导出的密钥": "Export failed: no key to export",
  "已导出 ": "Exported ",
  "导出失败: ": "Export failed: ",
  "已开启地区自动识别，正在探测…": "Automatic region detection is on. Probing…",
  "地区已自动识别: ": "Region detected: ",
  "Region 已保存: ": "Region saved: ",
  "请先添加 API Key 再识别地区": "Add an API key before detecting the region",
  "网关已开启，面板和状态栏已经生效，可以接着用。Kiro 自带对话要重新加载窗口后才走你的 API Key。": "The gateway is on. The panel and status bar already show it. Reload the window before Kiro's own chat uses your API key.",
  "网关已关闭，可以接着用。Kiro 自带对话要重新加载窗口后才恢复默认端点。": "The gateway is off. Reload the window before Kiro's own chat returns to the default endpoint.",
  "自动续号配置已保存": "Auto-renew settings saved",
  "已触发一次续号": "Started one renew round",
  "续号失败: ": "Renew failed: ",
  "已重置续号计数": "Renew counters reset",
  "已导入 ": "Imported ",
  " 个新 key": " new keys",
  "没有可导入的新 key": "No new key to import",
  "已丢弃 ": "Discarded ",
  " 个待导入的 key": " keys that were waiting to be imported",
  "已重置全部账号状态": "Account status reset",
  "打开链接失败: ": "Could not open the link: ",
  "统计已清零": "Stats reset",
  "已复制日志到剪贴板": "Copied the log",
  "官方 ksk_ 密钥直连 Kiro 服务": "Official ksk_ keys, straight to Kiro",
  "转发到 Anthropic 格式的第三方中转站": "Forward to an Anthropic-format relay",
  "选择工作模式": "Choose the route",
  "当前：": "Current: ",
  "Kiro Gateway: 还没有配置密钥，无法探活。": "Kiro Gateway: no key is configured, so liveness cannot run.",
  "Kiro Gateway: 开始探活（每把密钥消耗一次生成请求）…": "Kiro Gateway: liveness check started (each key spends one generation request)…",
  "Kiro Gateway: 上一轮探活还没跑完，稍后再试。": "Kiro Gateway: the previous liveness check is still running. Try again shortly.",
  "Kiro Gateway 探活完成：可用 ": "Kiro Gateway liveness done: available ",
  " · 禁用 ": " · disabled ",
  " · 溢出 ": " · overage ",
  " · 额度用尽 ": " · quota used up ",
  " · 失效 ": " · invalid ",
  " · 已删 ": " · removed ",
  " 把": "",
  "（.git / .vscode / .kiro/agents / .kiro/hooks / *.code-workspace / mcp.json 仍会逐项询问）": " (.git / .vscode / .kiro/agents / .kiro/hooks / *.code-workspace / mcp.json are still asked one by one)",
  "Kiro Key 有效 · ": "Kiro key works · ",
  "Kiro Key 测试失败: ": "Kiro key test failed: ",
  "导入 ": "Imported ",
  "暂存 ": "Held ",
  " 个新 key，等你确认导入": " new keys, waiting for you to import",
  "，跳过 ": ", skipped ",
  " 个重复": " duplicates",
  " 个验证不通过": " failed the check",
  "号池暂无可用号": "The pool has no usable key right now",
  " 秒后再看一次": "s, then check again",
  "拉到的 ": "Fetched ",
  " 个 key 全是重复，": " keys were all duplicates, ",
  "冷却 ": "cooldown ",
  " 秒": "s",
  "连续失败 ": "",
  " 次触发熔断，冷却 ": " failures in a row opened the breaker, cooldown ",
  "没拿到可用的新 key": "No usable new key",
  "，退避 ": ", backing off ",
  " 秒后重试": "s before retry",
  "已手动触发": "Triggered manually",
  "出错: ": "Error: ",
  "，": ", "
};

function uiLocale() {
  const picked = String(get("language", "auto") || "auto");
  if (picked === "zh" || picked === "en") return picked;
  const lang = String((vscode.env && vscode.env.language) || "").toLowerCase();
  return lang.startsWith("zh") ? "zh" : "en";
}
function tr(s) {
  let text = s == null ? "" : String(s);
  if (!text || uiLocale() !== "en") return text;
  const keys = tr.keys || (tr.keys = Object.keys(HOST_EN).sort((a, b) => b.length - a.length));
  for (const zh of keys) {
    if (zh && text.includes(zh)) text = text.split(zh).join(HOST_EN[zh]);
  }
  return text;
}

function getMode() {
  return get("mode", MODE_OFFICIAL) === MODE_RELAY ? MODE_RELAY : MODE_OFFICIAL;
}
function isRelayMode() {
  return getMode() === MODE_RELAY;
}
function modeLabel() {
  return tr(MODE_LABEL[getMode()] || getMode());
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
// The port the current mode actually uses. Endpoint redirect, health checks, and server bind all follow it.
function activePorts() {
  return isRelayMode() ? getRelayPorts() : getPorts();
}
// All relay-mode config, packed into one object for relay.js (it does not know vscode's configuration API).
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
// Whether the current mode's credentials are complete. Official direct needs a ksk_ key; relay needs an address plus a Key. If either is missing,
// do not take over the endpoints, or Kiro's chat box becomes a dead pool.
function credentialsReady() {
  return isRelayMode() ? relay.relayConfigured() : !!getApiKey();
}

// ---------------------------------------------------------------------------
// JSON credentials (OAuth refreshToken / accessToken)
//
// The panel can paste kiro-auth-token.json or similar JSON. On disk, apiKeys keeps only one stable
// json_<fingerprint> placeholder; the real token lives in globalState, so the identity does not change on refresh.
// Social / Desktop go through prod.{region}.auth.desktop.kiro.dev/refreshToken;
// ones with clientId+clientSecret go through AWS SSO OIDC.
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
// With multiple windows, the selection is written to a local file, and the window that owns the port reads the index before each forward.
// Switch only if this process already holds that account's credentials; otherwise keep the original account, do not refresh, and do not mark it dead.
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
    // A common shape of account-export bundles: accounts[].credentials is an object, not an array.
    // Merge the outer fields with the inner credentials first, then recognize them, so refreshToken is picked up whichever layer it sits on.
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
// The panel caches account usage under keys[].full. For a JSON credential, full is the display name, not the internal json_ id,
// and sync results must use the same key or the plan and credits will not line up with the row.
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
    // Retry only when TLS has not been established yet. That failure happens before the HTTP body is written out,
    // so the refreshToken never reached the server and will not be rotated. Timeouts, disconnects, and an existing HTTP response are not resent.
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
  // Kiro's BuilderId / IdC uses SSO OIDC CreateToken: POST /token, JSON, camelCase fields.
  // application/x-www-form-urlencoded is treated as an illegal request by this API and it returns
  // 400 invalid_request (the one whose location/reason are empty); the refresh token itself is not bad.
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
      // Refresh 5 minutes early. If this step fails, the original accessToken often has not expired yet,
      // and the usage query should not fail the whole call with "credential refresh failed".
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
// When addIfMissing=false, only rewrite a profileArn that already exists; never invent one. When forwarding
// a request Kiro itself sent, that is exactly what we want: wherever it put profileArn, we only replace the value there,
// and every other position stays as it was.
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
  // profileArn should have only one place to land. Official generate requests (POST awsJson) put it in the body.
  // Adding another copy on the query string after the body already has it becomes an extra parameter the official client never sends — the forwarded
  // bytes must match what Kiro originally meant to send, so here the query string is only rewritten, never added to. A request with no body,
  // a REST GET, can only carry it on the query string.
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
// Seamless automatic key switching.
const SWITCH_DEFAULT_COOLDOWN_MS = 5 * 60 * 1000;
function getSwitchPrefs() {
  const cd = Math.round(Number(pref("switchCooldownMs", SWITCH_DEFAULT_COOLDOWN_MS)));
  return {
    enabled: pref("autoSwitch", true) !== false,
    cooldownMs: Number.isFinite(cd) ? Math.min(Math.max(cd, 0), 24 * 60 * 60 * 1000) : SWITCH_DEFAULT_COOLDOWN_MS,
    // Balanced routing
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
// Generate-plane endpoint table
const GEN_ENDPOINTS = [
  { id: "q", label: "AmazonQ", base: (r) => "https://q." + r + ".amazonaws.com" },
  { id: "krs", label: "KiroKRS", base: (r) => runtimeBaseFor(r) },
];
// Note: do not add x-amz-target onto a forwarded request.
function genEndpointById(id) {
  return GEN_ENDPOINTS.find((e) => e.id === id) || GEN_ENDPOINTS[0];
}
// The IDE's native generate plane. Non-generate operations always go only through it.
function krsOnlyChain() {
  return [genEndpointById("krs")];
}
// krs is the default first choice.
function getPreferredEndpointId() {
  const v = String(get("preferredEndpoint", "krs") || "krs").toLowerCase();
  return GEN_ENDPOINTS.some((e) => e.id === v) ? v : "krs";
}
function getEndpointFallback() {
  return get("endpointFallback", true) !== false;
}
// Endpoint cooldown defaults to 5 seconds.
function getEndpointCooldownMs() {
  const v = Math.round(Number(get("endpointCooldownMs", 5000)));
  return Number.isFinite(v) ? Math.min(Math.max(v, 0), 30 * 60 * 1000) : 5000;
}
// How many rounds the endpoint chain may run, and how long to back off between rounds.
function getEndpointRoundPrefs() {
  const rounds = Math.round(Number(get("endpointRounds", 2)));
  const delay = Math.round(Number(get("endpointRoundDelayMs", 1500)));
  return {
    rounds: Number.isFinite(rounds) ? Math.min(Math.max(rounds, 1), 5) : 2,
    delayMs: Number.isFinite(delay) ? Math.min(Math.max(delay, 0), 30000) : 1500,
  };
}
// Throttle patience mode.
function getThrottlePatience() {
  const cap = Math.round(Number(get("throttleBackoffCapMs", 30000)));
  return {
    forever: get("throttleRetryForever", true) !== false,
    capMs: Number.isFinite(cap) ? Math.min(Math.max(cap, 1000), 300000) : 30000,
  };
}
// Next wait for exponential backoff: double it, but not past cap. When cur=0, use base.
function nextBackoffMs(cur, base, cap) {
  const next = cur > 0 ? cur * 2 : Math.max(base, 1);
  return Math.min(next, cap);
}
// Whether this failure is endpoint-level throttling.
function isThrottleFailure(status, text) {
  if (status === 429) return true;
  // A transport error has no status code; a 2xx can also hide a throttle error frame (HTTP 200 + ThrottlingException).
  if (!status || (status >= 200 && status < 300)) return THROTTLE_RE.test(String(text || ""));
  return false;
}
// Whether this failure means "this endpoint does not recognize this operation" (a missing endpoint capability, separate from throttling).
const UNSUPPORTED_OP_RE = /unknownoperation|operation is not recognized/i;
function isUnsupportedOperationFailure(status, text) {
  // Match the text only, and do not gate on the status code: upstream sometimes returns 200 and then sends an error frame in the event stream. What the call site passes in
  return UNSUPPORTED_OP_RE.test(String(text || ""));
}
// Whether this failure is a temporary upstream fault (a retryable 5xx).
const TRANSIENT_SERVER_RE = /internalserver|internalfailure|serviceunavailable|badgateway|gatewaytimeout|502 bad gateway|503 service/i;
// Transport failure: the request never reached upstream, or the connection dropped halfway.
const TRANSPORT_FAILURE_RE = new RegExp([
  "socket disconnected",            // Cut off before the TLS handshake (the typical look of proxy jitter)
  "before secure tls",
  "econnreset", "econnrefused", "econnaborted",
  "epipe", "etimedout", "ehostunreach", "enetunreach", "enetreset",
  "eai_again",                      // Temporary DNS failure
  "socket hang up",
  "upstream timeout",               // One we synthesize ourselves inside on("timeout")
  "request timeout",
  "tunneling socket could not be established", // The proxy tunnel failed to establish
].join("|"), "i");
function isTransportFailure(text) {
  return TRANSPORT_FAILURE_RE.test(String(text || ""));
}
function isTransientServerFailure(status, text) {
  const s = Number(status) || 0;
  // A definite 5xx status code is enough to decide; no need to read the body.
  if (s >= 500 && s < 600) return true;
  // A transport failure has no status code and can only be recognized from the error text.
  if (isTransportFailure(text)) return true;
  // Upstream sometimes returns 200 first and then sends an error frame in the event stream; then only signatures in the body work.
  return TRANSIENT_SERVER_RE.test(String(text || ""));
}
function getServerErrorRetryPrefs() {
  const max = Math.round(Number(get("serverErrorRetryMax", 5)));
  return {
    enabled: get("serverErrorRetry", true) !== false,
    max: Number.isFinite(max) ? Math.min(Math.max(max, 1), 20) : 5,
  };
}

// Known missing endpoint capabilities. The key is "endpoint + region + operation", because the same endpoint differs by region.
// Memory only: probe again after a window reload, so if upstream one day adds the operation it comes back on its own.
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
// Drop endpoints already known not to recognize this operation, saving a round trip that is doomed to fail.
// Never return an empty chain: if everything was dropped, fall back to the original chain — sending and getting an error beats not sending at all.
function filterUnsupportedEndpoints(chain, region, op) {
  const keep = chain.filter((e) => !isEndpointUnsupported(e.id, region, op));
  return keep.length > 0 ? keep : chain;
}
// The next decision for endpoint fallback. Pulled out as a pure function so it can be tested — the scheduler itself lives in a closure with a lot of state,
// and reproducing it end to end costs too much.
//   { action: "switch", index }              an untried endpoint remains this round; switch immediately
//   { action: "round", nextRound, delayMs }  every endpoint was hit this round; back off, then walk the chain again
//   { action: "giveup" }                     rounds are exhausted; hand control back to the caller
// skipIds: endpoints already shown, during this request, not to support the current operation are always skipped.
//
// The capability-gap table filters epChain when the request starts, but a gap discovered mid-request is only written into
// the table; epChain is already fixed. A new round clears triedEndpoints, so within the same request an endpoint already known not to
// recognize this operation gets picked again and again, each time a doomed 400, pure wasted round trips, and under throttling it also
// stirs the rate bucket. So a new round must land on an available endpoint too, and the round branch returns index as well.
function planEndpointFallback(chain, triedIds, round, prefs, skipIds) {
  const skip = skipIds || new Set();
  const usable = [];
  for (let i = 0; i < chain.length; i++) {
    if (!skip.has(chain[i].id)) usable.push(i);
  }
  // Every endpoint in the chain rejects this operation: switching endpoints is a dead end, so stop spinning.
  if (usable.length === 0) return { action: "giveup" };
  for (const i of usable) {
    if (!triedIds.has(chain[i].id)) return { action: "switch", index: i };
  }
  if (round >= prefs.rounds) return { action: "giveup" };
  return { action: "round", nextRound: round + 1, delayMs: prefs.delayMs, index: usable[0] };
}
// Endpoint cooldown: an endpoint that just failed with 429 makes later requests start at the next one instead of hitting it again.
// Memory only; probe again after a window reload.
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
// Endpoint order for this request: the preferred one first, then the rest in table order. With fallback off, only the preferred one remains.
function genEndpointChain() {
  const preferred = getPreferredEndpointId();
  const head = GEN_ENDPOINTS.filter((e) => e.id === preferred);
  if (!getEndpointFallback()) return head;
  return [...head, ...GEN_ENDPOINTS.filter((e) => e.id !== preferred)];
}
// Starting endpoint index: skip ones still cooling down. If every one is cooling down, still start at 0 (better than not sending).
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
// Log the endpoint chain currently in effect, so it is easy to confirm which endpoint we are actually on.
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
// never routed through us. This marker makes "the path really went through" unmistakable in
// the log, so "did not go through the proxy" vs "did, but upstream errored" is obvious at a glance.
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
//   errors   : count only failures finally handed back to Kiro. If an upstream failure is caught by an automatic key switch
//              (resend on the next key) or by an automatic retry, Kiro still sees a successful
//              answer, and that failure is not counted — otherwise a seamless switch inflates the error count
//              and it looks like something is wrong. A 429 with no account left to switch to, an upstream 5xx, a network error: only failures that are
//              actually returned to Kiro are counted.
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

// Stats count only "today": day records which local date this batch of counters belongs to, and they zero themselves after midnight.
let _stats = { requests: 0, errors: 0, tokens: 0, credits: 0, since: 0, day: "" };
let _statsInflight = 0; // open generation calls right now
// Per-key breakdown ("personal usage" in the panel): the same live counters, but
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
// Local date key, used to tell whether we are still on the same day.
function todayKey(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate());
}
// Timestamp of today at 00:00, the start of the day's stats.
function startOfToday() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}
// On a new day, zero both the totals and each key's counters. Every entry that reads or writes stats calls
// this first, so whether there is traffic, the panel pulls, or the timer fires, what you see is today's data.
// This only mutates the data and does not push, so it cannot recurse with pushStats.
function ensureToday() {
  const today = todayKey();
  if (_stats.day === today) return false;
  _stats = { requests: 0, errors: 0, tokens: 0, credits: 0, since: startOfToday(), day: today };
  _keyStats = {};
  if (_statsFlushTimer) { clearTimeout(_statsFlushTimer); _statsFlushTimer = null; }
  persistStatsNow();
  return true;
}
// At local midnight, reset once on purpose: with no traffic and no panel pull, the display still rolls over.
let _dayRolloverTimer = null;
function scheduleDailyReset() {
  if (_dayRolloverTimer) clearTimeout(_dayRolloverTimer);
  // Two seconds past tomorrow's midnight, a little margin to avoid jitter right on the boundary.
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
    // Data saved by an older version has no day field. Treat it as "not today"; it is cleared after load.
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
// Operations that are allowed to rotate across endpoints.
//
// Endpoint fallback only holds for operations both planes recognize. Diverting a non-rotatable operation only burns two
// round trips and finally hands Kiro an error that was doomed to fail. In the measured matrix (see above GEN_ENDPOINTS),
// GenerateAssistantResponse is the only operation available on all four combinations of q. and krs, us-east-1 and eu-central-1,
// so only it is eligible to rotate. converse has never shown up in the logs and there is no measured
// data, so it stays out — measure it first if it is ever needed.
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
// that key's own bucket (personal usage).
function statsRequestStarted(inBytes, key) {
  ensureToday(); // The first request of a new day must not be added onto yesterday's numbers
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
// Manual reset: clear today's counters. The owning date stays today.
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
// Seamless automatic key switching
// ---------------------------------------------------------------------------
// Only errors of the kind "this key is unusable right now" trigger a switch: throttling, auth failure, quota exhausted.
// Other errors (network jitter, upstream 5xx) belong to automatic retry and should not spend a key.
// Throttle wording. One "throttl" covers ThrottlingException / throttled / throttling
// and that whole family of spellings; "rate exceeded" is another way upstream phrases it, and the official probe recognizes it too.
const THROTTLE_RE = /too many requests|throttl|rate ?limit|rate exceeded|slow down/i;
const INVALID_RE = /access denied|unauthorized|invalid.{0,12}(api ?key|token)|token.{0,12}expired|forbidden/i;
const QUOTA_RE = /quota|usage ?limit|limit ?(reached|exceeded)|exhaust|insufficient|out of credit|no credit/i;
// The overage cap (OVERAGE_EXCEEDED_RE) is defined in the liveness section, next to DEAD_KINDS.
// keyFailureKind below uses it — those are all runtime calls, so it is long since initialized by the time it is read.
// The account was suspended by upstream risk control. The original text is "Your User ID is temporarily suspended. We detected
// unusual user activity and locked it as a security precaution. To restore
// access, please contact our support team…" An account like this will not recover on its own; you have to switch accounts.
//
// Only phrases specific enough are recognized here. Earlier, restore access / security precaution / locked
// and the like each stood as their own rule, so one sentence that happened to appear in any error body would mark a healthy account suspended, so
// those weak signals now count only when they must show up as a pair.
const SUSPENDED_RE = /temporarily suspended|(?:user id|account)[^.\n]{0,40}\bsuspended\b/i;
function looksSuspended(text) {
  const t = String(text || "");
  if (SUSPENDED_RE.test(t)) return true;
  // Either sentence alone can appear in some other notice; conclude only when both signals show up together.
  return /unusual (?:user )?activity/i.test(t) && /security precaution/i.test(t);
}
// Early signals in the suspension copy.
//
// The suspension notice streams down token by token. The first few frames are often only enough to spell out "Your User ID is"
// and a few words, while the real deciding keywords (temporarily suspended) are still ahead. Hitting these prefix signals
// means this may be a suspension notice, so it is worth widening the decision window by a few more frames before deciding — once the stream is released there is
// no second chance to switch accounts transparently. A normal answer does not contain these words and is unaffected.
const SUSPENDED_HINT_RE = /your user id|\bsuspend|unusual (?:user )?activity|security precaution/i;
function maybeSuspendedPrefix(text) {
  return SUSPENDED_HINT_RE.test(String(text || ""));
}
// Reassemble the body text out of a streaming answer.
//
// Upstream sometimes skips an error code and streams "account suspended" back as an ordinary answer over HTTP 200
// (Kiro's chat window shows that temporarily suspended notice directly). This response is an AWS
// event stream. The body is cut into many small frames and sent token by token, so a keyword breaks across frames, and matching the raw
// bytes misses it — extract the text fields from each frame, join them into one string, then decide.
function extractStreamText(raw) {
  const text = String(raw || "");
  let out = "";
  const re = /"(?:content|text|message|errorMessage)"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(text)) !== null) out += m[1];
  return out;
}
// Evidence text used to judge account state: the raw bytes, plus the body reassembled from each frame.
//
// Both are required — the raw bytes handle an ordinary JSON error body, and the reassembled body handles one cut into small frames
// whose keywords break across frames. If the branch that buffers the error body passes only the raw bytes, a framed
// "temporarily suspended" never matches, account state is never marked, and the panel keeps showing "healthy".
function failureEvidence(raw) {
  const text = String(raw || "");
  return text + "\n" + extractStreamText(text);
}
// Buffer this many bytes before judging: one event-stream frame carries a frame header and a payload, and usually one chunk
// is enough to judge. If TCP slices the start very fine, wait one more chunk.
const HEAD_MIN_BYTES = 256;
// Not having enough buffered is not a reason to wait forever: while the model is thinking, upstream may send only tiny heartbeat frames. Past this time,
// release it directly. The worst case only adds this much delay to the first byte of a normal answer.
const HEAD_WAIT_MS = 300;
// When an early signal of suspension copy has already appeared at the start, switch to this wider window and wait for the keywords to arrive.
// The default 256 bytes / 300ms is only enough to take in the frame header and the first few tokens. The suspension copy's
// "temporarily suspended" usually has not arrived yet — the moment the window closes, it is released, and from then on this account
// is never judged suspended, and so is never switched away from automatically.
const SUSPECT_MIN_BYTES = 4 * 1024;
const SUSPECT_WAIT_MS = 2000;
// Byte cap for keeping on scanning the body after release. Once this much is buffered with no hit, stop buffering, so a long answer does not keep
// piling strings up in memory.
const TAIL_SCAN_CAP = 64 * 1024;
// An error frame stuffed into the stream. Upstream sometimes returns 200 first, then sends an exception frame in the event stream, and Kiro
// displays it as "Something went wrong: [InternalServerException] …". The status code is 200, so
// looking only at the status code, automatic retry and automatic key switching both cannot reach this kind of failure.
//
// Only recognize an unescaped frame structure (":exception-type", "__type", "errorMessage"): quotes in the answer body
// appear as \" inside JSON, so even if the user happens to be talking with the AI about
// InternalServerException, it is not treated as an error frame.
const STREAM_ERROR_RE = /:exception-type|"__type"\s*:\s*"[^"]*(?:Exception|Error|Fault)|"errorMessage"\s*:\s*"/;
// Matchable text for an in-stream error frame. Return an empty string when there is no error frame.
// What comes back is handed to the retry rules and the key-switch decision, so it has to carry the exception type and the error message.
function streamErrorText(raw) {
  const text = String(raw || "");
  if (!STREAM_ERROR_RE.test(text)) return "";
  const type = exceptionName(text);
  // The error message may sit in a message / errorMessage field; extractStreamText pulls those out too.
  const detail = extractStreamText(text);
  const joined = (type + " " + detail).trim();
  return joined || text.slice(0, 500);
}
// Cooldown length depends on the reason: throttling is temporary; invalid, quota exhausted, and suspended are held much longer.
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
// Which account state each reason finally lands on. Suspended is its own state, and the panel shows "suspended" on its own,
// which is not the same thing as the key itself failing authentication.
// upstream is deliberately left unmapped: a 5xx is upstream's own problem and says nothing about whether this account is good, so it must not
// put a label on the account.
// overage folds into the quota state: to the user both mean "quota exhausted", and the panel does not need two words for it. Internally we keep
// a separate kind only so logs and the delete reason can say whether base ran out or even the overage was burned through.
const KIND_TO_STATE = {
  denied: "denied", quota: "quota", overage: "quota", invalid: "invalid", suspended: "suspended",
};
// Soft failure: resending on another account is worth a try (different accounts may land on different backends), but do not mark the account dead and do not hold it for the
// user-configured cooldown — that duration is for "something is wrong with the account" and is often several minutes. Using it on upstream jitter
// would knock every account out at once.
const SOFT_KINDS = new Set(["upstream"]);
const SOFT_COOLDOWN_MS = 20 * 1000;
// Chinese state names used in host-side logs. Internally we still subdivide them (cooldown length and the switch decision need that); only
// the outward presentation collapses them into three. See publicState.
const STATE_LABEL_HOST = {
  ok: "正常",
  denied: "被拒绝",
  quota: "额度用尽",
  invalid: "已失效",
  suspended: "已禁用",
  unknown: "未检测",
};
// Decide whether an upstream failure means this key should be switched, and return the reason or null.
//
// Look at hard evidence such as the status code first. Body keywords only fill in detail behind a status code: switching keys and marking the account dead just because the body
// contains forbidden / quota is far too easy a way to condemn a healthy account (an upstream 5xx
// error page, or request content echoed back, can all carry those words).
function keyFailureKind(status, bodyText) {
  const text = String(bodyText || "");
  // Suspension copy is specific enough that a hit can be treated as certain, with no need to wait for a status code.
  if (looksSuspended(text)) return "suspended";
  // The overage cap is the same, and more reliable than the status code: upstream returns it as HTTP 400, and a 400 falls through below into
  // the keyword fallback, where it is easy to read as some other reason. The moment either of these signature strings appears, the account is truly dead, so accept it first.
  if (OVERAGE_EXCEEDED_RE.test(text)) return "overage";
  if (status === 402) return "quota";
  // A 429 has to be split into two cases. It cannot all be treated as throttling.
  //
  // Upstream also returns 429 when quota is exhausted. Trusting the status code alone would read "this month's quota is used up" as "requests are going out too fast"
  // — the first needs a different account or a wait for reset, the second is fine after a few minutes, and the conclusions are opposites. Waiting for the wrong one is waiting for nothing.
  // So look at the body for quota wording first, and if it is there, count it as quota exhausted. The official account probe likewise ranks the quota
  // decision ahead of throttling.
  if (status === 429) return QUOTA_RE.test(text) ? "quota" : "throttle";
  if (status === 401) return "invalid";
  if (status === 403) {
    // A 403 can be an invalid key, or another way of saying the quota is exhausted.
    if (QUOTA_RE.test(text)) return "quota";
    if (INVALID_RE.test(text)) return "invalid";
    // A 403 with no clear reason is no longer waved through as "unrelated to the key" — upstream may return a 403 with no clue at all when quota is exhausted, risk control
    // is throttling, or the region does not match. Handing it back to Kiro as-is just
    // fails this turn of the conversation outright. Treat it as "this account is unusable for now": switch accounts and resend, plus a short cooldown, but do not mark it dead
    // (denied is not terminal; it comes back on its own once the cooldown passes), so the cost of a wrong call is only a few minutes of not being selected.
    return "denied";
  }
  // A transport error (status=0): the link is down or DNS is dead, and switching accounts will not get through either. Switch only when the body explicitly
  // says throttling.
  if (!status) {
    if (THROTTLE_RE.test(text)) return "throttle";
    return null;
  }
  // An upstream 5xx (500 / 502 / 503 / 504): first see whether throttling was wrapped as a 5xx; otherwise treat it as a soft
  // failure — resending on another account often gets through, and only a short 20-second cooldown is applied, with no change to account state.
  if (status >= 500) {
    if (THROTTLE_RE.test(text)) return "throttle";
    return "upstream";
  }
  // A 2xx must never be taken to mean authentication failed.
  //
  // A 2xx from upstream means this request's credentials passed authentication — reading "key invalid" out of such a response
  // is a contradiction. The pure keyword fallback below would hit forbidden /
  // unauthorized / access denied inside INVALID_RE, so an HTTP 200 plus an error frame (or the user happening to be talking to the AI
  // about a 403) could mark a healthy key invalid, and that is terminal: it gets frozen and is never probed again.
  // Under a 2xx only two conclusions are kept: suspension copy (already decided above) and an explicit throttle.
  if (status >= 200 && status < 300) {
    if (THROTTLE_RE.test(text)) return "throttle";
    return null;
  }
  if (THROTTLE_RE.test(text)) return "throttle";
  if (QUOTA_RE.test(text)) return "quota";
  if (INVALID_RE.test(text)) return "invalid";
  return null;
}
// key -> { until, kind }. Memory only: probing again after a window reload is safer than keeping a
// blacklist that may already be stale.
const _keyCooldown = new Map();
// Account health. key -> { state, at }. state is one of:
//   ok        healthy, usable
//   quota     quota exhausted (credits are maxed out, or upstream says so explicitly)
//   invalid   invalid (authentication was refused)
//   suspended the account was suspended by upstream
//   unknown   not probed yet, or the probe failed only because of the network
// Two sources: the result of syncing account info, and whether a real request succeeded or failed.
const _keyHealth = new Map();
// Terminal states: all three mean something is wrong with the account itself, and it will not get better on its own. Once decided, freeze it —
// do not probe it again, and do not let later network jitter overwrite it, until the key is deleted or the user resets the state by hand.
const TERMINAL_STATES = new Set(["invalid", "quota", "suspended"]);
function isTerminalState(state) {
  return TERMINAL_STATES.has(String(state || ""));
}
// Recheck window for a terminal state: once it is due, unfreeze automatically so the account joins selection and probing again.
//
// Terminal states used to be permanent, and quota became a deadlock: quota exhausted → frozen → selection skips it and
// account sync skips it too (saving a round trip) → so we never get fresh data saying the quota has recovered → it can
// never unfreeze. But Kiro quota resets on a cycle. This is a temporary state and should not be a death sentence.
//   quota     recheck once after 3 hours. The reset cycle is usually longer than that; a few extra probes cost only one
//             very cheap GET, and in return the account is used again the moment quota recovers.
//   invalid   a key that was truly revoked will not heal itself, but a cross-region refusal and upstream auth jitter look exactly
//             the same. Leave a chance to recheck after 12 hours, so one wrong call does not retire the account forever.
//   suspended a risk-control lock needs a human appeal. An automatic recheck is pointless, so it stays frozen permanently.
const FREEZE_TTL_MS = { quota: 3 * 60 * 60 * 1000, invalid: 12 * 60 * 60 * 1000 };
// When this terminal state expires. Returning 0 means frozen forever. hint is an exact expiry the caller supplies
// (for example a quota reset time parsed from the usage API); use it when it is more accurate than the default TTL.
function freezeExpiresAt(state, hint) {
  const ttl = FREEZE_TTL_MS[state];
  if (!ttl) return 0;
  const at = Number(hint) || 0;
  return at > Date.now() ? at : Date.now() + ttl;
}
// Whether this key's state is still frozen (terminal, and the recheck time has not arrived).
// Unfreeze on expiry while we are here. This function is called over and over on the hot key-selection path, so putting the unfreeze here means any
// path that asks "can this account be used" gets recheck behavior, with no extra check scattered around.
// opts.silent: after unfreezing, do not push back to the panel. Used by keyStatusSnapshot / setKeyHealth —
// they are already building a snapshot, or they push once themselves right after, and another push here becomes a nested call
// (pushStats → keyStatusSnapshot → keyHealthFrozen → pushStats …).
function keyHealthFrozen(key, opts = {}) {
  const h = _keyHealth.get(key);
  if (!h || !isTerminalState(h.state)) return false;
  if (!h.until || h.until > Date.now()) return true;
  // The recheck window is due: drop the old conclusion. If it really is still bad, the next probe or request will judge it again,
  // at the cost of one round trip.
  _keyHealth.delete(key);
  saveKeyHealthSoon();
  log("账号状态复检: " + maskKey(key) + " 的「" + (STATE_LABEL_HOST[h.state] || h.state)
    + "」判定已到期，恢复参与挑号");
  if (!opts.silent && panelProvider) panelProvider.pushStats();
  return false;
}
// opts.force: allow overwriting a terminal state. force is granted in only two cases — this key actually ran a request successfully
// (the hardest evidence, used to correct a wrong call), and the user reset the state by hand.
// opts.until: the exact expiry of the terminal state. If omitted, compute it from FREEZE_TTL_MS.
function setKeyHealth(key, state, opts = {}) {
  if (!key || !state) return;
  // Give an expired terminal state one chance to unfreeze first. Otherwise an account that is already past its recheck window stays blocked by the old conclusion,
  // and a newly probed result can never be written in. Do not push the panel from here; the code below pushes itself.
  keyHealthFrozen(key, { silent: true });
  const prev = _keyHealth.get(key);
  // This only records state. It does not delete accounts. Deletion goes through the liveness section (runLivenessScan →
  // deleteKeyAutomatic): that path is based on the response from a request we actually sent, which is much more reliable than inferring here from
  // used >= total on the usage API — a POWER-style account still has
  // overage left after base is exceeded and can still run, yet usage already shows 10508/10000. Deleting on that number throws away a good account.
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
// Turn an account-sync result into a health state.
//
// Conclude here only when the evidence is hard enough: the status code is the main basis, and body keywords only distinguish different reasons behind the same
// status code. The old approach ran the whole error message against a regex like /\b(401|403)\b/. A stray 403 digit in the body, or one "forbidden",
// and a healthy account was marked invalid,
// and once marked it was never reversed.
function noteAccountHealth(key, ok, info, err) {
  if (ok) {
    const used = Number(info && info.used);
    const total = Number(info && info.total);
    const exhausted = Number.isFinite(used) && Number.isFinite(total) && total > 0 && used >= total;
    // Save the usage first: key selection uses it to prefer accounts with plenty of quota left.
    noteKeyUsage(key, info);
    const prev = _keyHealth.get(key);
    // The one case that cannot be reversed just because usage is readable is suspension: a risk-control lock often blocks only the inference API,
    // while the usage query still returns 200. To reverse a suspension, this account has to actually complete a request
    // (clearCooldown), or the user has to reset the state by hand.
    if (prev && prev.state === "suspended") {
      maybeAdoptUsableKey();
      return;
    }
    // In every other case, real account data is the most reliable first-hand information, and it is allowed to overturn an earlier terminal verdict
    // (accounts previously misjudged as invalid correct themselves here).
    // When quota is exhausted, if the usage API gave an exact reset time, use that as the recheck time. It is more accurate than the default TTL.
    setKeyHealth(key, exhausted ? "quota" : "ok", { force: true, until: info && info.resetAt });
    maybeAdoptUsableKey();
    return;
  }
  const status = Number(err && err.status) || 0;
  // Prefer the response body for the text, and fall back to Error.message (which also carries a truncated response body).
  const text = String((err && (err.body || err.message)) || err || "");
  // Suspension copy is specific enough that a hit is accepted directly.
  if (looksSuspended(text)) { setKeyHealth(key, "suspended"); scheduleDeadDrop(key, "suspended"); }
  // The overage-cap reason constant is more reliable than the status code, so accept it first (upstream returns it as 400, and it would fall into the later fallback
  // and be read as some other reason). Once both base and overage are burned through, it shares a state with quota exhausted.
  else if (OVERAGE_EXCEEDED_RE.test(text)) { setKeyHealth(key, "quota"); scheduleDeadDrop(key, "overage"); }
  // A 429 also has to pass the quota wording first: when quota is exhausted, upstream returns 429 as well, and accepting the status code first would read "quota used up"
  // as "sending too fast". Keep the same order as in keyFailureKind.
  else if (status === 402 || ((status === 403 || status === 429) && QUOTA_RE.test(text))) {
    setKeyHealth(key, "quota");
    // 402 / 403 are explicit refusals and can be used to retire the account. A 429 only sets a status and does not delete — it is throttling at heart, and the sweep
    // hits management endpoints concurrently, which is the easiest way to bump into a 429. One "quota" in the body is not enough to conclude the quota is truly gone.
    if (status !== 429) scheduleDeadDrop(key, "quota");
  }
  else if (status === 401) setKeyHealth(key, "invalid");
  else if (status === 403) {
    // A 403 does not necessarily mean the key is bad: mark it invalid only when the body explicitly says authentication was refused. If the reason cannot be seen, keep the previous
    // conclusion — this API refusing us says nothing about account state, and downgrading an account that was judged healthy to "not checked"
    // only makes it look like something is wrong.
    if (INVALID_RE.test(text)) setKeyHealth(key, "invalid");
  }
  // Throttling is a real conclusion, not "we could not find out", so record it and let the panel show "throttled". But only record it;
  // do not exclude the key — no key cooldown, and no change to account state.
  //
  // What used to be applied here was coolDownKey(key, "throttle"), which makes keyIsUsable return false and kicks
  // a key that is actually healthy out of selection for 5 minutes. The sweep hits management endpoints concurrently and is itself the most likely to hit a
  // 429. Excluding on every hit could retire most of the pool at once. The other three paths in this project (endpoint fallback, in-stream
  // errors, and inference liveness) also deliberately refuse to treat a 429 as an account problem. Stay consistent here.
  else if (status === 429) {
    noteKeyThrottled(key);
    return;
  }
  // An upstream 5xx, a timeout, or a network error says nothing about the account itself: keep the previous conclusion.
  else if (status >= 500 || !status) return;
  else setKeyHealth(key, "unknown");
  maybeAdoptUsableKey();
}
// When the currently selected key is already unusable, switch to an available one on our own, instead of waiting for the next request to hit the wall.
// This runs after account sync has just produced a conclusion, and after the user adds or deletes a key, so a newly added key can
// take over immediately.
function maybeAdoptUsableKey() {
  if (!getSwitchPrefs().enabled) return;
  const active = getActiveApiKey();
  if (!active || keyIsUsable(active)) return;
  const next = rankUsableKeys([active])[0];
  if (!next) return;
  const h = _keyHealth.get(active);
  // Translate state names (quota / invalid / …) with the host-side map. Do not borrow KIND_LABEL: the two
  // merely happen to share a few key names, and adding a new state would display as undefined.
  log("自动切换密钥: 当前 " + maskKey(active) + " "
    + (STATE_LABEL_HOST[h && h.state] || "不可用") + " → 换用 " + maskKey(next));
  adoptKey(next);
}
// When a key is deleted or added again, clear the state it left behind. Otherwise deleting and adding the same key back inherits
// the previous "invalid / quota exhausted / suspended" conclusion, and automatic switching will never select it again.
function forgetKeyHealth(keys) {
  const list = Array.isArray(keys) ? keys : [keys];
  let changed = false;
  for (const k of list) {
    if (!k) continue;
    if (_keyHealth.delete(k)) changed = true;
    if (_keyCooldown.delete(k)) changed = true;
    // Clear the caches key selection uses at the same time: once the key is gone, keeping usage and probe times is pointless and is
    // memory that never shrinks.
    _keyUsage.delete(k);
    _keyLastUsedAt.delete(k);
    _keyProbeAt.delete(k);
    _keyThrottledAt.delete(k);
  }
  if (!changed) return;
  saveKeyHealthSoon();
  if (panelProvider) panelProvider.pushStats();
}
// A terminal state has to survive across windows, or one reload starts over from "not checked" and an account already confirmed bad is
// probed all over again. What is persisted is the key fingerprint; globalState does not store another copy of the key in plaintext.
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
    // Store the recheck time too. Otherwise reloading the window restarts the recheck window, and an account that was about to expire
    // gets frozen for another full round.
    out[keyFingerprint(key)] = { state: h.state, at: h.at || Date.now(), until: h.until || 0 };
  }
  try { await extContext.globalState.update(KEY_HEALTH_STATE_KEY, out); } catch {}
}
// Restore terminal states at startup. Only accept fingerprints of keys that still exist; drop entries for deleted ones along the way.
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
    // A missing until is a permanent terminal state saved by an older version. quota / invalid now both have a recheck window,
    // so give them one. Otherwise an account marked dead before the upgrade can never be reversed.
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
  // Persist once, to flush leftover entries for deleted keys.
  saveKeyHealthSoon();
}
// Manual user reset: clear cooldown and health state together. Every key goes back to "not checked", and the next sync or
// request produces a fresh conclusion. A terminal state is reversed through this exit.
function resetKeyHealth() {
  _keyCooldown.clear();
  _keyHealth.clear();
  // Clear probe times too: the user hit reset because they want an immediate re-judgment, and it must not be blocked by the "do not probe again within 4 minutes"
  // throttle. Leaving the usage data is harmless; it only affects selection order, and the next probe overwrites it.
  _keyProbeAt.clear();
  // The throttle mark is part of the state judgment, so the reset clears it too.
  _keyThrottledAt.clear();
  // Clear the memory of "bad accounts just deleted" as well. Reset means every verdict is overturned. If this memory stays, and the user
  // tries to take that account back, the pool treats it as a duplicate and blocks it.
  _deadKeyAt.clear();
  saveKeyHealthSoon();
  // Run a sweep right after the reset, so the panel's "not checked" gets a conclusion quickly.
  healthSweepOnce().catch(() => {});
}
// Whether a key can be used right now: not while cooling down, and not if it is invalid, quota-exhausted, or suspended.
// "Unknown" still counts as usable — not having been probed does not mean it is bad.
function keyIsUsable(key) {
  if (!key) return false;
  if (cooldownLeft(key)) return false;
  return !keyHealthFrozen(key);
}
// The most recent usage seen for each key, used during selection to prefer the one with more quota left.
const _keyUsage = new Map(); // key -> { used, total, at }
// When each key was last used by a real request, for rotation within the same tier.
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
// Remaining-quota ratio (0 to 1). Return null when there is no usage data, and treat it as "unknown" in the sort.
function keyHeadroom(key) {
  const u = _keyUsage.get(key);
  if (!u) return null;
  return Math.max(0, Math.min(1, (u.total - u.used) / u.total));
}
// Sort usable keys by "which one should be used right now".
//
// Every selection entry used to be getApiKeys().find(keyIsUsable) — always the first usable key in the list.
// With many accounts that piles the whole load onto the first few: the first one fills up and throttles → switch to the second → the second
// fills up too → they die one by one, while accounts later in the list with plenty of quota are never used. The moment a cooldown ends it goes
// straight back to the first one, and the cycle repeats.
//
// Sort rules:
//   1. A state confirmed healthy ranks ahead of "not checked" (not checked does not mean bad, but healthy is certain)
//   2. More remaining quota comes first, spreading load onto accounts that have plenty (a gap under 2% counts as the same tier)
//   3. If those are equal, pick the one unused the longest, which rotates on its own
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
// Quota tiers for balanced routing: remaining quota is bucketed coarsely at 25% steps, and only crossing a bucket counts as "richer".
//
// Why not compare exact values the way rankUsableKeys does: _keyUsage is updated only when account info syncs,
// and quota spent by a request that already went out is not reflected immediately. Comparing exact values would treat 90% left and 88% left as
// "richer" too, so every request picks the same key until the next sync notices it has dropped — balancing
// collapses into "always use the key with the most quota". Buckets smooth that noise out, and within a bucket rotation goes to "unused the longest".
// That 2% test is enough for failover (low frequency, and it runs only after hitting a wall), but not for picking a key on every request.
//
// Anything too old counts as unknown (return null): stale quota should not drive selection. Falling back to pure rotation is better.
const USAGE_FRESH_MS = 10 * 60 * 1000;
const HEADROOM_BUCKET = 0.25;
function keyHeadroomBucket(key) {
  const u = _keyUsage.get(key);
  if (!u || Date.now() - Number(u.at || 0) > USAGE_FRESH_MS) return null;
  const h = Math.max(0, Math.min(1, (u.total - u.used) / u.total));
  return Math.floor(h / HEADROOM_BUCKET);
}
// The pool and ordering for balanced routing. Two deliberate differences from rankUsableKeys:
//
//   * Only accounts whose state is confirmed healthy. rankUsableKeys also counts "not checked" as usable, which is for failover —
//     after hitting a wall, an untried key is better than none. Ordinary load spreading should not pull in an unchecked
//     account: it may already be bad and just not discovered yet, and its turn would waste a round trip.
//     Accounts that are cooling down or already marked dead are blocked earlier, inside keyIsUsable.
//   * Quota is compared by tier, and within a tier we rotate by "unused the longest" (noteKeyUsed records the time on every forward),
//     so consecutive requests spread naturally across healthy accounts.
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
      // Use the higher quota tier first. If either side has no fresh data, skip this comparison and look at rotation directly.
      if (a.bucket != null && b.bucket != null && a.bucket !== b.bucket) return b.bucket - a.bucket;
      return a.last - b.last;
    })
    .map((e) => e.key);
}
// Four account states are shown outward: healthy / throttled / quota exhausted / suspended.
//
// The remaining distinctions (403 refused, upstream fault, not checked) are transient — the extension switches accounts and waits out
// the cooldown on its own, and the user does not need to follow along. They all collapse to "healthy".
// Authentication failure is folded into "suspended": to the user the two mean exactly the same thing — this account cannot be used,
// so switch to another or delete it. There is no need for two words for the same action.
//
// Throttling is shown on its own because the remedy differs from the other three: nothing is wrong with the account, it is just sending
// too fast right now, and it recovers on its own in a few minutes. Folding it into "healthy" would show everything fine while requests keep switching accounts; folding it into
// "quota exhausted" would make people think they have to pay or switch accounts.
const PUBLIC_STATE = { quota: "quota", suspended: "suspended", invalid: "suspended" };
function publicState(state) {
  return PUBLIC_STATE[String(state || "")] || "ok";
}
// A record of having been throttled, only so the panel can show "throttled".
//
// The point is that it does not take part in selection. The other three paths in this project (forwarding's endpoint fallback, in-stream errors, inference liveness)
// also deliberately refuse to record a 429 as account state — throttling is usually a concurrency quota at the endpoint or region level, not this account being bad,
// and excluding it from selection only leaves a healthy account sitting idle. The account sweep in particular hits management endpoints concurrently and
// is itself likely to hit a 429. Excluding on that could retire most of the pool at once, and then there is no account left to use.
// So this only records and does not exclude: keyIsUsable does not look at it at all.
// The TTL matches passiveStatus in the official probe — if no new throttle signal appears within 10 minutes, it disappears on its own.
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
// For the panel: the display state of each key.
// Only the state word. No remaining cooldown and no recheck time — those are internal cadence, and the panel does not show them.
function keyStatusSnapshot() {
  const out = {};
  for (const key of getApiKeys()) {
    // Run the freeze check once first, which also clears a terminal state that has expired, so one panel pull can see the recheck result.
    // This must be silent: this function is pushStats' data source, and pushing again on unfreeze would nest the calls.
    keyHealthFrozen(key, { silent: true });
    const h = _keyHealth.get(key);
    const pub = publicState(h && h.state);
    // A terminal state outranks throttling: when an account is both quota-exhausted and inside a throttle cooldown, what should be reported is the former — once the throttle
    // passes it still cannot be used.
    out[key] = { state: pub !== "ok" ? pub : (keyThrottled(key) ? "throttled" : "ok") };
  }
  return out;
}
function coolDownKey(key, kind) {
  if (!key) return;
  // Record account state first. It has nothing to do with how long the cooldown is.
  // Quota exhausted, authentication failed, and suspended all mean something is wrong with this account itself, and they are terminal. Throttling is only temporary;
  // once the cooldown passes it can be used again, so do not hang a bad-account label on it.
  // This step has to happen before the cooldown: the cooldown minutes can be set to 0, and the old code returned immediately when ms<=0,
  // which skipped the state judgment along with it — the account was already unusable, the panel kept showing healthy,
  // and switching would not skip it either.
  if (KIND_TO_STATE[kind]) setKeyHealth(key, KIND_TO_STATE[kind], { reason: KIND_LABEL[kind] });
  // A conclusion hit during forwarding is the answer upstream gave to one real request — quota exhausted, overage cap,
  // and account suspended remove the account from the list directly, with no wait for the liveness probe (which is off by default).
  // This line was once merged into the wrong place, inside cooldownLeft, where there is no kind variable, so every cooldown read
  // threw ReferenceError and broke the whole panel state push.
  scheduleDeadDrop(key, kind);
  const { cooldownMs } = getSwitchPrefs();
  // A soft failure (upstream 5xx) has nothing to do with the account itself. A fixed 20-second short cooldown is enough: let the other accounts in the same round
  // take over, and it recovers soon. Using the user-configured cooldown (5 minutes by default) would, on one upstream
  // hiccup, exclude every account at once, and then there is no account left to use.
  const ms = SOFT_KINDS.has(kind) ? SOFT_COOLDOWN_MS : cooldownMs * (COOLDOWN_FACTOR[kind] || 1);
  if (ms <= 0) {
    log("[KRS] 密钥 " + maskKey(key) + " " + (KIND_LABEL[kind] || kind) + "（冷却已关闭）");
    return;
  }
  _keyCooldown.set(key, { until: Date.now() + ms, kind });
  log("[KRS] 密钥 " + maskKey(key) + " " + (KIND_LABEL[kind] || kind)
    + "，冷却 " + Math.round(ms / 1000) + "s");
  // Throttling is now a state the panel can see, so push once as soon as it is written, instead of making the user wait for the next 5-second poll to
  // see "throttled". Recovery after the cooldown still relies on polling, and that delay does not matter.
  if (panelProvider) panelProvider.pushStats();
}
// Remaining cooldown in milliseconds (0 = usable). Expired entries are cleared along the way.
function cooldownLeft(key) {
  const entry = _keyCooldown.get(key);
  if (!entry) return 0;
  const left = entry.until - Date.now();
  if (left <= 0) { _keyCooldown.delete(key); return 0; }
  return left;
}
// Having been used successfully means this key is good. Clear the cooldown immediately and mark it healthy again.
// A request that actually got through is the hardest evidence, so pass force: if it was previously misjudged as terminal, this can reverse it.
function clearCooldown(key) {
  if (_keyCooldown.has(key)) {
    _keyCooldown.delete(key);
    if (panelProvider) panelProvider.pushStats();
  }
  // Getting through means the throttle has already passed, with no need to wait out the 10-minute TTL.
  clearKeyThrottled(key);
  setKeyHealth(key, "ok", { force: true });
}
// For the panel: keys currently cooling down.
function cooldownSnapshot() {
  const out = [];
  for (const key of [..._keyCooldown.keys()]) {
    const left = cooldownLeft(key);
    if (left > 0) out.push({ key, leftMs: left, kind: _keyCooldown.get(key).kind });
  }
  return out;
}
// Which key this request should start with.
//
// When balanced routing is off (or no account is confirmed healthy), the old behavior applies: prefer the one the user selected, and only if its state is not
// healthy (cooling down, invalid, quota exhausted) move on to the next one.
// When it is on, do not stick to the selected one. Every request asks again "which one should be used right now" —
// Within a tier, rankHealthyKeys puts "unused the longest" first, and every forward calls noteKeyUsed,
// so consecutive requests rotate naturally across healthy accounts instead of piling everything onto the first one.
function pickStartKey() {
  const active = getActiveApiKey();
  const prefs = getSwitchPrefs();
  if (!prefs.enabled) return active;
  if (prefs.loadBalance) {
    const picked = rankHealthyKeys()[0];
    if (picked) return picked;
    // There is not a single account "confirmed healthy" (common right after adding accounts, before account info has synced, when everything is unchecked).
    // We cannot sit and wait then. Fall through to the old logic below and get the request out first.
  }
  if (!active || keyIsUsable(active)) return active;
  return rankUsableKeys([active])[0] || active;
}
// The next key not yet tried, and whose state is healthy. Skip invalid and quota-exhausted ones, and do not waste a round trip.
// Order comes from rankUsableKeys (healthy first, more quota first, unused the longest first).
function nextUsableKey(tried) {
  return rankUsableKeys(tried)[0] || null;
}
// Persist the switch, so later requests, the status bar, and the panel all follow.
async function adoptKey(key) {
  try {
    await set("activeApiKey", key);
    // In automatic mode, also switch the region to this key's own region. This only reads the cache and sends no probe:
    // forwarding is a hot path and cannot wait an extra round trip just to identify the region. If the cache has nothing, leave things as they are; a later
    // account sync or a panel action will fill it in.
    if (isRegionAuto()) {
      const r = trustedCachedRegion(key) || jsonHomeRegion(key);
      if (r && r !== configuredRegion()) await applyDetectedRegion(r, { silent: true });
      // This account has not had its region probed yet: probe once in the background, instead of waiting for the first request to hit a cross-region 403 and then correcting it.
      else if (!trustedCachedRegion(key) && !jsonHomeRegion(key)) ensureRegionForKeySoon(key);
    }
    updateStatusBar();
    if (panelProvider) panelProvider.pushState();
  } catch (e) {
    log("!! 切换密钥失败: " + (e?.message || e));
  }
}
// The account balanced routing actually used should be visible to the user: the panel's selection and the status bar both follow, otherwise the UI
// still shows the previous one and does not match the one that is really running.
//
// But forwarding is a hot path — within one turn Kiro fires several requests in a row (intent classification, generation, …), and writing
// VS Code config on every one of them is too heavy. So this is throttled:
//   * if the key did not change, do nothing (the most common case)
//   * if it did change, do not write immediately; hold a short window and then persist. If it changes again inside the window, persist only the last one
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
    // During that short hold, this account may already have been deleted, or just marked dead, so confirm once more before persisting.
    if (!want || want === getActiveApiKey()) return;
    if (!getApiKeys().includes(want) || !keyIsUsable(want)) return;
    adoptKey(want);
  }, ACTIVE_SYNC_DEBOUNCE_MS);
}

// ---------------------------------------------------------------------------
// Memory of bad accounts just deleted
// ---------------------------------------------------------------------------
// The real deletion happens in the liveness section (runLivenessScan → deleteKeyAutomatic): the basis for retiring an account is
// the response from a request we actually sent, which is much harder evidence than inferring from the usage API. This only covers one thing liveness does not —
//
// Remember a bad account that was just deleted, for a while. The pool (especially a shared carpool-style pool) is likely to hand the same account back down
// right away, and it was just judged quota-exhausted or suspended — accepting it again only repeats "import → hit the wall → mark dead
// → delete" and wastes round trips. Skip it as a duplicate during this window. If the same account comes back after the window,
// accept it again, because the quota may genuinely be on a new cycle by then.
const DEAD_KEY_MEMORY_MS = 6 * 60 * 60 * 1000;
const _deadKeyAt = new Map(); // key -> when it was deleted automatically
function rememberDeadKey(key) {
  if (key) _deadKeyAt.set(key, Date.now());
}
function isRecentlyDeadKey(key) {
  const at = Number(_deadKeyAt.get(key) || 0);
  if (!at) return false;
  if (Date.now() - at > DEAD_KEY_MEMORY_MS) { _deadKeyAt.delete(key); return false; }
  return true;
}
// Deletion entries other than the liveness probe.
//
// A real liveness probe (runLivenessScan) is off by default — each probe of an account burns one generate request. If only that path
// can trigger deletion, most people's bad accounts would never be cleared. The two paths below cost nothing extra: the forwarding request was going to be
// sent anyway, and the free sweep is a control-plane usage GET.
//
// Only these three kinds of "upstream itself refused to serve" are accepted. Quota exhausted inferred from used >= total on the usage API does not count:
// a POWER-style account still has overage left after base is exceeded and can still run, yet usage already shows 10508/10000,
// and deleting on that number loses an account that can still be used, and it is irreversible.
const HARD_DEAD_KINDS = new Set(["suspended", "overage", "quota"]);
const HARD_DROP_DELAY_MS = 800;
const _dropQueue = new Map(); // key -> reason for deletion
let _dropTimer = null;
function scheduleDeadDrop(key, kind) {
  if (!key || !HARD_DEAD_KINDS.has(kind) || !getAutoDeleteOnDead()) return;
  _dropQueue.set(key, KIND_LABEL[kind] || kind);
  if (_dropTimer) return;
  // The judgment happens on the sync path (coolDownKey / noteAccountHealth both push the panel as they go). Awaiting a delete there
  // would nest, so hold a short window and then do it.
  _dropTimer = setTimeout(async () => {
    _dropTimer = null;
    // Delete one at a time: the list has to be reread each time (the previous delete already changed the config), and computing indexes in a batch would shift them.
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
// Prompt injection (prefix / suffix prompts)
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
// Replace the current user message with the rule's auto-reply text before a re-send,
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
// Auto retry (automatic retry)
// ---------------------------------------------------------------------------
// Off by default: this gateway's contract is to surface the selected key's real
// error instead of silently papering over it. When enabled, an upstream failure
// whose status or body matches a rule is re-sent (same key) up to `max` times
// before the error reaches Kiro.
// Whenever Kiro shows an upstream error it wraps this prefix around it, for example what you see in the chat window:
// "Something went wrong: [InternalServerException] Encountered an unexpected
// error…". Kiro itself adds this sentence; it is not in the upstream original — and it is the only thing the user can see,
// so writing a rule from it is the most natural thing to do. Count this sentence when matching, or a rule written from the UI copy
// will never hit.
const KIRO_ERROR_PREFIX = "Something went wrong";
// Short name of the exception type. __type in an event stream often carries a package prefix
// (com.amazon.coral.service#InternalServerException). Whoever writes the rule usually only remembers
// the tail, so a separate short name is appended as well.
function exceptionName(text) {
  const m = String(text || "").match(/([A-Za-z][A-Za-z0-9_]*(?:Exception|Error|Fault))\b/);
  return m ? m[1] : "";
}
// The text a rule matches against: status code + Kiro's fixed prefix + the upstream original + the exception short name.
function retryHaystack(status, bodyText) {
  const body = String(bodyText || "");
  const parts = ["HTTP " + status, KIRO_ERROR_PREFIX, body];
  const type = exceptionName(body);
  if (type) parts.push(type);
  return parts.join(" ").toLowerCase();
}
// opts.replyOnly: look only at rules that carry auto-reply text.
//
// A rule with reply text means "continue the conversation with this sentence", which is mutually exclusive with an automatic key switch (resend the same content
// on another key), so the forwarding path lets it take priority over switching. The typical case is
// "on Access denied → reply continue": Access denied is also the keyword the switch decision uses for an invalid key.
// Without a chance for the reply text to cut in line, this rule never gets to run.
// A rule with an empty reply still lets the switch go first — resending as-is and resending on another account are no different, and switching accounts means more.
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
// Hand a response body that has already been buffered back to Kiro.
//
// content-length is not a hop-by-hop header and would be forwarded as-is, so it must be rewritten to the number of bytes actually written:
// when the error body exceeds ERR_BODY_CAP only the first slice is forwarded, and when reading the response stream fails not a single byte
// went out — yet the header still says the full length, and Kiro waits for bytes that will never come, until it times out.
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
  // When the extension is off, Kiro's bearer and x-amzn-kiro-profile belong to the same account.
  // If only the token is swapped here, the header is still the account the IDE is logged into, and the conversation is judged access_denied.
  // A JSON account is changed to its own profileArn; if it has none, remove the header, so someone else's identity is not left behind. ksk_ does not carry these headers.
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
// opts.sniff(bodyText, status, req): sniff the response body off to the side.
//
// The extension needs some upstream data for itself (model billing multipliers, account usage), but the bytes forwarded to Kiro
// must stay identical to the official original. So sniffing is a side path: write each chunk to Kiro unchanged, and also keep
// a copy for ourselves. Stop keeping the copy once the cap is reached, and never let sniffing change or delay what is forwarded.
// Turn it on only for JSON responses that are known to be small. Everything else goes through pipe.
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

      // Backoff-resend state for a transport failure. Resend only when the request cannot be sent or the connection drops halfway. Once upstream
      // has given response headers (res.headersSent), never resend — bytes are already streaming to Kiro by then,
      // and a resend would interleave two responses.
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
          // Side-path sniff: forwarding still writes one chunk at a time, unchanged. The copy is only accumulated along the way.
          const seen = [];
          let seenLen = 0;
          upRes.on("data", (c) => {
            const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
            if (seenLen < SNIFF_CAP) {
              seen.push(buf);
              seenLen += buf.length;
            }
            // Backpressure has to be wired up ourselves. pipe used to do this for us, and switching to manual forwarding dropped it: when downstream
            // cannot write, write returns false, and if upstream is not paused then, the data all piles up in memory.
            // Right now we only sniff small JSON such as usage and models, so the difference is invisible, but do not leave a trap for later.
            let flushed = true;
            try { flushed = res.write(buf); } catch { return; }
            if (!flushed) {
              upRes.pause();
              res.once("drain", () => upRes.resume());
            }
          });
          upRes.on("end", () => {
            try { res.end(); } catch {}
            // A sniff failure must never affect this forward — the bytes went out long ago, and this is only us taking a look.
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
// Retry without interrupting
// ---------------------------------------------------------------------------
// Principle: one turn of conversation must not fail because of an internal action such as switching accounts, checking state, or cooling down. However upstream refuses,
// the gateway finds a way to turn it into a successful answer — switch accounts, wait out a cooldown, switch back, all inside the same
// HTTP request. Kiro only sees the final result.
//
// Only two boundaries hold this in:
//   1. Kiro itself cancelled (the user hit stop, or the window reloaded) — nobody is waiting for an answer, so stop immediately
//   2. The time budget is used up — going on any longer and the client will time out on its own, and only then is the last failure handed back as it is
const NO_INTERRUPT_BUDGET_MS = 15 * 60 * 1000;
// Poll interval when every account is cooling down: wait for the one that expires soonest, but wait at least this long before trying again,
// so we do not spin empty.
const NO_INTERRUPT_WAIT_MS = 2500;

// The KRS (generate plane) handler. It starts from the key the user selected by default. The moment upstream says this key
// is unusable right now (throttling / 403 / quota exhausted / auth failure / upstream 5xx), switch to the
// next available key and resend inside the same request — that is the "seamless switch". Kiro only sees the final result, and there is no need to
// reload the window. When every account is cooling down, do not give up; come around again when one expires, until the budget runs out.
// Automatic switching can be turned off in settings. Off, it is strictly "use only the selected one".
function makeKrsHandler() {
  return function handle(req, res) {
    if (req.url === HEALTH_PATH) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(HEALTH_MARKER);
      return;
    }
    markProxyHit("KRS", req);
    // Which key to start with is decided by pickStartKey (the currently selected one first, and if it is unusable, move on and
    // pick a healthy one). Here we only confirm that at least one is configured.
    // What used to be written here was "use only the selected one, with no failover". That was the behavior before automatic switching,
    // and leaving it would only mislead — the real switch logic is in trySwitchKey below.
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
      // profileArn is handled inside attempt according to the current credential type: a ksk_ must have it stripped, and a JSON/OAuth credential must carry it.
      // Leave it alone here, or switching to a JSON account in a mixed pool would drop that account's own profileArn.

      const statOp = operationName(req);
      const isChat = BILLED_OP_RE.test(statOp);
      // Only operations both planes recognize take part in endpoint rotation. Everything else goes only through KRS.
      const isRotatable = ROTATABLE_OP_RE.test(statOp);
      const epChain = isRotatable
        ? filterUnsupportedEndpoints(genEndpointChain(), getRegion(), statOp)
        : krsOnlyChain();
      // A non-rotatable operation does not take part in endpoint fallback. Behavior is strictly the old path that only goes through KRS.
      // isRotatable must be used, not isChat: epChain above was already fixed by isRotatable, and using
      // isChat here would mismatch "the chain has only krs, yet fallback is allowed" (SendMessage is exactly
      // that case).
      const epFallbackAllowed = isRotatable && getEndpointFallback();
      // Path, query string, body, and every request header except credentials are passed through unchanged — the only difference from the old
      // KRS-only path is the hostname here. Do not fork by endpoint.
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
      // Fixed prefix/suffix prompts go only on real chat turns.
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
      // Automatic key switch: start from the one the user selected (skip it first if it is cooling down).
      //
      // This no longer limits itself to "try each one only once, then give up". The goal is not to interrupt this turn of Kiro's conversation: as long as
      // the client is still waiting and the time budget is not used up, keep switching accounts, waiting out cooldowns, and resending, and digest every failure
      // inside the gateway. When one full circle fails, clear "already tried" and come around again. The deadline closes it off,
      // so it will not hammer forever.
      const switchCfg = getSwitchPrefs();
      const triedKeys = new Set();
      const deadline = Date.now() + NO_INTERRUPT_BUDGET_MS;
      const startKey = pickStartKey() || getApiKey();
      // Endpoints already tried for this request. A 429 switches only while an untried endpoint remains, and one pass is enough —
      // both endpoints throttling means we really are sending too fast, and switching further only pours requests into the same window.
      const triedEndpoints = new Set();
      const startEpIdx = pickStartEndpointIndex(epChain);
      // Which round the endpoint chain is on. When every endpoint this round hits the limit, back off once and walk it again. Give up only when the rounds run out.
      let epRound = 1;
      // Exponential-backoff state for patience mode. It accumulates across attempt() and resets only when the key changes: switching to another
      // account means the premise "throttling has nothing to do with this key" no longer holds. The new account has its own concurrency headroom, and the backoff
      // should start over.
      let endlessBackoffMs = 0;
      let endlessWaitedMs = 0;
      // Retry count and backoff for a temporary upstream fault (5xx). Kept separate from the throttle backoff: the two have different causes and different
      // conditions for settling, and mixing them interferes with the attempt counts.
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

      // Every attempt carries its own body and key: auto-reply text rewrites the current user message, and an automatic switch replaces
      // the credentials. Both make what goes out next different from last time.
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
        // Record "this account was just used": accounts in the same tier rotate on it, and it will not sit on the first one in the list forever.
        noteKeyUsed(key);
        // When balanced routing picks a different account, take the panel selection and the status bar along (throttled internally;
        // if the account did not change this is a no-op call).
        syncActiveKeySoon(key);
        // Dump the diagnostics in one go: operation name, inbound content-type, and the host plus path actually forwarded.
        // The path is always "/" (the operation is in x-amz-target). Without logging it you cannot tell whether this request is generation,
        // a conversation, or inline completion. content-type decides which protocol upstream uses to parse it. Missing either one means guessing.
        const inCt = String((req.headers && (req.headers["content-type"] || req.headers["Content-Type"])) || "-");
        // Log the body size too: once connections are reused, the remaining bulk of the time is uploading the request body (conversation history plus
        // file contents are retransmitted in full every turn). Without this number there is no way to tell whether to keep tuning the code or to shrink the context.
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
        // counted=false: this failure was digested internally by an automatic key switch or an automatic retry. Kiro
        // never saw a failure, so it should not be recorded in the error count. Only a failure that is finally handed back to
        // Kiro (a 429 with no account left to switch to, an upstream 5xx, a network error, and so on) counts as one error.
        const endOnce = (ok, counted = true) => {
          if (statEnded) return;
          statEnded = true;
          if (!ok && counted) statsRequestFailed(key);
          statsRequestFinished();
        };
        // Re-send after the configured pause, keeping the client waiting. A rule
        // with an auto-reply phrase re-sends that text as the user's message instead of
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
        // A rule that carries auto-reply text is tried once before switching accounts. After the retries run out it still falls through to
        // trySwitchKey, so the fallback for "this key really is invalid" is not lost: it is not that we refuse to switch accounts,
        // only that the reply text is tried first.
        // This holds only for chat requests — a tool turn cannot rewrite the user message (applyRetryReply cannot get
        // currentMessage), so the reply text has nowhere to apply, and letting it cut in line only waits one round for nothing before switching accounts.
        const replyRuleFirst = (status, text) => {
          if (!isChat || n >= maxAttempts) return null;
          return matchedRetryRule(status, text, { replyOnly: true });
        };
        // How long until the soonest cooldown expires (0 when no account is cooling down). This only serves the wait calculation below.
        const soonestCooldownMs = () => {
          const list = cooldownSnapshot();
          if (!list.length) return 0;
          return Math.max(0, Math.min(...list.map((c) => c.leftMs)));
        };
        // The no-interrupt fallback: before any failure is truly handed back to Kiro, ask it once "can this still be saved".
        //   Kiro cancelled on its own, or the budget is used up → false, and hand the failure back as it is
        //   An available account has not been tried yet         → switch accounts and resend immediately
        //   Every account was tried, or all are cooling down    → clear "already tried", wait for the one that expires soonest, and come around again
        // Returning true means this failure has already been taken over. The caller must not write anything else to res.
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
            // One circle is done. Do not give up: forget who was tried this round, and come around again with the account that unfreezes soonest.
            triedKeys.clear();
            next = nextUsableKey(triedKeys);
            if (!next) {
              // There is not even one account that is not cooling down: wait by the nearest unfreeze time, and at least NO_INTERRUPT_WAIT_MS.
              waitMs = Math.min(Math.max(soonestCooldownMs(), NO_INTERRUPT_WAIT_MS), leftMs);
              next = pickStartKey() || key;
            }
          }
          log("[KRS] 不中断重试: " + why + "，" + (waitMs ? Math.round(waitMs / 1000) + "s 后" : "立即")
            + "用 " + maskKey(next) + " 重发（剩余预算 " + Math.round(leftMs / 1000) + "s）");
          const go = () => {
            if (clientGone) return;
            // After a switch, the endpoint chain starts a fresh round: the new account's concurrency headroom is its own, and the endpoint
            // cooldowns and backoff accumulated on the old account do not apply to it.
            triedEndpoints.clear();
            epRound = 1;
            endlessBackoffMs = 0;
            endlessWaitedMs = 0;
            adoptKey(next).then(() => { if (!clientGone) attempt(n, body, next, startEpIdx); });
          };
          if (waitMs > 0) setTimeout(go, waitMs); else go();
          return true;
        };
        // Missing endpoint capability. This is separate from throttling, so it has its own path.
        //
        // The scene: KRS is throttled → divert to q.{region} → that plane does not recognize this operation → 400
        // UnknownOperationException. This 400 is entirely caused by our diversion and must never be handed back to
        // Kiro — what the user sees is a red error in the chat window, and it has nothing to do with the account or with throttling.
        //
        // What to do: record "endpoint + region + operation" in the capability-gap table (later requests skip it directly, and no longer waste a
        // round trip), then switch to an endpoint in the chain that still supports this operation and resend. Back off before sending, because we
        // diverted here in the first place because the original endpoint was throttled, and hitting it again immediately will most likely eat another 429.
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
          // Allow that endpoint to be tried once more: it was blocked by throttling, not because it is unsupported.
          triedEndpoints.delete(epChain[alt].id);
          log("[KRS] 端点能力缺失: " + delayMs + "ms 后改用 " + epChain[alt].label + " 重发");
          setTimeout(() => { if (!clientGone) attempt(n, body, key, alt); }, delayMs);
          return true;
        };
        // Retry a temporary upstream fault.
        //
        // When upstream returns a 5xx / InternalServerException, the error text itself says "please try
        // again", and the next identical request is measured to succeed. This is a transient error and should be digested internally,
        // and the user should not see red text.
        //
        // It shares the same exponential growth and cap as the throttle backoff, but the number of tries is limited: throttling is "wait and it will pass",
        // and waiting long enough is bound to get through, while a 5xx that keeps coming is more likely a real problem (typical when an account is over quota and upstream
        // behavior is unstable and keeps emitting 500). Retrying without limit only leaves the conversation spinning with no result.
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
        // A 429 prefers switching endpoints. Do not switch keys, and do not count it as a retry.
        //
        // Measurement shows 429 USER_REQUEST_RATE_EXCEEDED is an endpoint-level rate, not a problem with this key:
        // in the same second KRS is saturated, q. fires at full speed and every one succeeds. Treating the 429 as a key problem and switching accounts plus
        // cooling the key down does nothing (same machine, same machineId), and it also marks a good account as throttled. So here,
        // before trySwitchKey, intercept once: if the endpoint switch succeeds, do not touch key state at all.
        const trySwitchEndpoint = (status, bodyText) => {
          if (!isThrottleFailure(status, bodyText)) return false;
          if (clientGone || !epFallbackAllowed) return false;
          // Put the endpoint we just hit into a short cooldown, so later requests do not start from it.
          endpointCoolDown(ep.id);
          const prefs = getEndpointRoundPrefs();
          // A capability gap discovered while this request is in flight has to be skipped too. epChain was fixed when the request started,
          // and filtering at construction time cannot stop "we find halfway through that some endpoint does not support it".
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
            // Land on an available endpoint. Do not hardcode 0 — endpoint 0 may be the one just shown to be unsupported.
            const restartIdx = typeof plan.index === "number" ? plan.index : 0;
            setTimeout(() => { if (!clientGone) attempt(n, body, key, restartIdx); }, plan.delayMs);
            return true;
          }
          // Rounds are used up: the endpoint-switch path is finished, and the decision goes back to handleThrottle to try switching accounts.
          //
          // This must not back off in place. The old code entered the patience backoff directly in this branch and
          // returned true, and patience mode is on by default, so trySwitchKeyForThrottle, which comes later inside handleThrottle,
          // never got a chance to run — under throttling it hammered the same account the whole time,
          // and the concurrency headroom of the other accounts in the pool was never used. "Automatically switch keys" on the panel, which says
          // "switch to the next one when throttled", became an empty promise.
          log("[KRS] 端点回退: " + prefs.rounds + " 轮内所有端点都被限流，改试换号");
          return false;
        };
        // The last move for throttling: endpoints and accounts have both been tried once around, so back off for a while and start over.
        //
        // Patience mode (throttleRetryForever) is on by default: do not hand a 429 back to Kiro. Keep retrying with exponential backoff,
        // and stop only when the Kiro side cancels (clientGone). Turning it off restores "report an error once everything has been tried".
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
          // The meaning of the backoff is "wait for the throttle window to pass, then do a full circle again", so this circle's "already tried" record
          // has to be cleared too. If it is not, on waking up both endpoints and accounts are still marked tried, and the only option is to
          // hammer the last account over and over. The wait was for nothing.
          triedEndpoints.clear();
          triedKeys.clear();
          epRound = 1;
          log("[KRS] 限流退避: " + endlessBackoffMs + "ms 后再来一圈（端点 + 号）"
            + "（已累计等 " + Math.round(endlessWaitedMs / 1000) + "s，稳态上限 "
            + Math.round(patience.capMs / 1000) + "s；关 throttleRetryForever 可恢复旧行为）");
          // Land on an available endpoint: hardcoding 0 would waste one hit, every round, on the endpoint already known to be unsupported.
          const idx0 = epChain.findIndex(
            (e) => !isEndpointUnsupported(e.id, getRegion(), statOp));
          setTimeout(() => {
            if (!clientGone) attempt(n, body, key, idx0 >= 0 ? idx0 : 0);
          }, endlessBackoffMs);
          return true;
        };
        // Switching accounts under throttling. This runs after every endpoint has been tried — different accounts have their own concurrency headroom,
        // and switching accounts often gets through immediately, which is much better value than waiting out a whole backoff round.
        //
        // But never record account state on the current key: a 429 says nothing about whether this key is good. Marking it "throttled"
        // only misleads the panel, and makes automatic selection skip an account that is actually healthy.
        //
        // The two cases that return false (automatic switching is off, or every account has been tried once around) are taken over by the caller for the
        // patience backoff, and the 429 is not thrown straight back at Kiro.
        const trySwitchKeyForThrottle = () => {
          if (clientGone || !switchCfg.enabled) return false;
          const next = nextUsableKey(triedKeys);
          if (!next) return false;
          log("[KRS] 限流换号: " + maskKey(key) + " → " + maskKey(next)
            + "（端点已全部试过；不标记账号状态）");
          // After a switch, the endpoint chain starts a fresh round: the new account's concurrency headroom is its own.
          triedEndpoints.clear();
          epRound = 1;
          // Switching accounts means the assumption "throttling has nothing to do with the original account" no longer holds, so the patience backoff starts over.
          endlessBackoffMs = 0;
          endlessWaitedMs = 0;
          adoptKey(next).then(() => { if (!clientGone) attempt(n, body, next, startEpIdx); });
          return true;
        };
        // The full throttle chain: switch endpoints (switch within this round → backoff across rounds) → switch accounts → patience backoff and another circle.
        // Key state is never touched the whole way. Only a display mark of "currently being throttled" is written.
        // The order of the three steps is deliberate: an endpoint is cheapest (same account, and the two endpoints have independent throttle buckets), switching accounts is next
        // (another account has its own concurrency headroom), and waiting it out is the most expensive, so it goes last.
        // Returning true means this failure has already been taken over. The caller must not write anything else to res.
        const handleThrottle = (status, bodyText) => {
          if (!isThrottleFailure(status, bodyText)) return false;
          // The mark has to be written here — this is the only entry point for throttling.
          //
          // It used to be written in the throttle branch of trySwitchKey, but once handleThrottle takes over
          // (an endpoint switch or an account switch succeeds) the caller returns immediately and never gets there, so a real throttle
          // went unmarked the whole way and the panel kept showing "healthy".
          // Only mark it, and do not touch state: no cooldown, nothing written to _keyHealth, and keyIsUsable does not look at it at all,
          // so selection can still use this account, and a single-key setup is not judged unusable either.
          noteKeyThrottled(key);
          if (trySwitchEndpoint(status, bodyText)) return true;
          if (trySwitchKeyForThrottle()) return true;
          return throttleBackoffWait();
        };
        // If this key is unusable, switch to the next one and resend immediately inside the same request. Success or failure, Kiro only sees
        // the final result, so the whole process is invisible to the user. The retry count is unaffected: switching keys does not count as a retry.
        const trySwitchKey = (status, bodyText) => {
          // Judge and record the state first, then see whether we can switch accounts. The two have to stay separate: being unable to switch (the switch is off,
          // or the client is already gone) does not mean this account is still good — the old code returned immediately in those cases,
          // without even recording account state, so an account that had already been banned still showed healthy on the panel, and later
          // requests kept picking it.
          const kind = keyFailureKind(status, bodyText);
          if (!kind) return false;
          // Throttling does not record account state: a 429 is an endpoint-level rate problem and says nothing about whether this key is good. Recording
          // "throttled" plus a cooldown only misleads the panel, and in a single-key setup it marks the only
          // good account unusable every minute or two. Throttling belongs on handleThrottle (switch endpoints → backoff across rounds →
          // switch accounts → patience backoff). When that path cannot be walked (for example patience mode is turned off), this still keeps saving it under the
          // no-interrupt rule, it just does not touch state.
          if (kind === "throttle") {
            // Record a note, but only so the panel can show "throttled": no cooldown, no change to account state,
            // and keyIsUsable does not look at it at all. The user needs to see that it is being throttled right now, while selection can still
            // use this account — in a single-key setup the only one must not be judged unusable just because of throttling.
            noteKeyThrottled(key);
            return keepTrying(maskKey(key) + " 限流（不标记账号状态）");
          }
          coolDownKey(key, kind);
          // A wrong region looks exactly like an invalid key, so recheck the region once in the background while we are here.
          recheckRegionOnAuthFailure(key, kind);
          // The currently selected account has already been marked dead. Let an available one take over first, so the next request does not hit the same wall.
          // When automatic switching is off, maybeAdoptUsableKey skips this on its own.
          maybeAdoptUsableKey();
          return keepTrying(maskKey(key) + " " + (KIND_LABEL[kind] || kind));
        };

        const upReq = https.request(
          { method: req.method, hostname: target.hostname, port: 443, path: target.pathname + target.search, headers, timeout: 300000, agent: UPSTREAM_AGENT },
          (upRes) => {
            const status = upRes.statusCode || 0;
            const ok = status >= 200 && status < 300;
            log((ok ? "<- [KRS] " : "!! [KRS] ") + keyTag + " -> HTTP " + status + (ok ? " (serving)" : ""));

            // On failure: buffer the (small) error body first, and decide before any byte reaches Kiro,
            // so a resend can stay transparent.
            // This no longer asks "is there still a card to play" — in no-interrupt mode there is always another card (switch accounts, wait out a cooldown
            // and come around again). Only when keepTrying says no is this error body actually sent.
            if (!ok) {
              const parts = [];
              let size = 0;
              upRes.on("data", (d) => {
                statsAddOutBytes(d.length, key);
                if (size < ERR_BODY_CAP) { parts.push(d); size += d.length; }
              });
              upRes.on("end", () => {
                // The evidence has to include the body after frames are extracted: framed suspension copy cannot be matched from the raw bytes,
                // and the account state would never get marked.
                const bodyText = failureEvidence(Buffer.concat(parts).toString("utf8"));
                // Judge a missing endpoint capability first: this 400 was caused by our diversion and has nothing to do with the account.
                // Handing it back to Kiro is a red error in the chat window.
                if (trySwitchEndpointUnsupported(status, bodyText)) { endOnce(false, false); return; }
                // Throttling: switch endpoints → backoff across rounds → switch accounts → back off and come around again, without touching key state the whole way.
                if (handleThrottle(status, bodyText)) { endOnce(false, false); return; }
                // A temporary upstream fault: back off and resend on the original endpoint. Do not switch keys and do not switch endpoints.
                if (tryRetryServerError(status, bodyText)) { endOnce(false, false); return; }
                // Try a rule that carries auto-reply text again: what it wants is to continue the conversation with that sentence, not to switch accounts.
                const replyRule = replyRuleFirst(status, bodyText);
                if (replyRule) { endOnce(false, false); scheduleRetry(replyRule, { beforeSwitch: true }); return; }
                // Next, switch keys: this one is clearly unusable, and retrying with another key is what makes sense.
                // A successful switch is one seamless switch, and it is not counted in the error count.
                if (trySwitchKey(status, bodyText)) { endOnce(false, false); return; }
                if (n < maxAttempts) {
                  const rule = matchedRetryRule(status, bodyText);
                  // An automatic retry is digested internally the same way. Count an error only when the retry truly cannot move anymore.
                  if (rule) { endOnce(false, false); scheduleRetry(rule); return; }
                }
                // A 4xx that hits no explicit rule is a deterministic request error. Switching keys, switching endpoints, or immediately
                // resending as-is will not change the request, and a 400 in particular must not spin in a hot loop for the whole 15-minute budget.
                // 408/425/429 are still recoverable failures. 429 is already handled by the throttle chain above; every other unknown
                // failure keeps the no-interrupt fallback.
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

            // Hold the response headers, and decide what to do once this first batch of bytes is in hand:
            //   the start is an error frame (200 + InternalServerException and the like) or an account-suspension notice
            //     → treat it as a failure and go through account switching / automatic retry. Not one byte has been written to Kiro yet, so the resend
            //       is transparent, and Kiro only sees the final result.
            //   it is a normal answer → release it immediately.
            // A failure whose status code shows nothing wrong is caught by this step: looking only at HTTP 200, automatic retry and
            // automatic switching both cannot reach it. An error that starts halfway through the answer cannot be helped; the first half was already given to Kiro.
            let head = [];
            let headSize = 0;
            let decided = false;
            let opened = false;
            let handled = false;      // Already taken over by an account switch or a retry; do not forward this response
            let failedContent = false; // The content is actually a failure (an error frame or a suspension notice)
            let headTimer = null;
            // An early signal of suspension copy has already appeared at the start: widen the decision window temporarily and wait for the keywords to arrive.
            let suspectMode = false;
            const dropHeadTimer = () => {
              if (headTimer) { clearTimeout(headTimer); headTimer = null; }
            };
            // Text used for the decision: raw bytes for an ordinary JSON error body, and the reassembled text for a streaming answer cut into
            // small frames whose keywords break across frames. The two are joined together as the evidence.
            const headText = () => {
              const raw = Buffer.concat(head || []).toString("utf8");
              return raw + "\n" + extractStreamText(raw);
            };
            // Keep watching what follows even after release.
            //
            // A suspension notice streams down token by token, and the keywords can easily land outside the decision window — in that
            // case this turn's content has already been given to Kiro (the chat window can show that suspended
            // notice) and cannot be saved. But recording the state as "suspended" lets the next request switch accounts automatically.
            // Without this step, an account that has already been banned is picked over and over, which shows up as "after the account is suspended
            // it does not switch automatically".
            let tailScan = "";
            const scanTail = (chunk) => {
              if (tailScan === null) return;
              tailScan += chunk.toString("utf8");
              if (!looksSuspended(tailScan + "\n" + extractStreamText(tailScan))) {
                // Once the cap is reached without a hit, stop accumulating, so a long answer does not keep piling up in memory.
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
            // Release the buffered start together with the response headers, and hand later bytes to pipe.
            // finalize=true means upstream has already ended. Write it out in one go and finish (pipe must not be used now:
            // the stream has ended, pipe will never fire end, and res would hang).
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
              // Attach the buffered start to the start of the tail scan: a suspension keyword may sit exactly across
              // "the batch that was released" and "the batch after it", and without joining them it is missed again.
              if (buf) {
                tailScan = buf.toString("utf8");
                try { res.write(buf); } catch {}
              }
              upRes.pipe(res);
            };
            // Judge only once. Returning true means it has already been taken over by an account switch or a retry; the caller must not forward any more.
            const decide = () => {
              if (decided) return handled;
              decided = true;
              dropHeadTimer();
              const raw = Buffer.concat(head || []).toString("utf8");
              // Evidence uses headText(): raw bytes for an ordinary JSON error body, and the reassembled text for
              // a streaming answer cut into small frames whose keywords break across frames. Every later decision uses this one copy —
              // if only the raw bytes are passed, framed suspension copy can enter this branch and then fail to match inside keyFailureKind,
              // so the state is recorded but the account cannot be switched.
              const evidence = headText();
              if (looksSuspended(evidence)) {
                failedContent = true;
                log("!! [KRS] " + keyTag + " 上游返回账号被禁用的提示（HTTP " + status + "），判为已禁用");
                if (trySwitchKey(status, evidence)) { handled = true; endOnce(false, false); return true; }
                // When the account cannot be switched (automatic switching is off, or no other account is available): trySwitchKey has already
                // recorded the state as suspended and tried to take over. Do not record it again here.
                return false;
              }
              const streamErr = streamErrorText(raw);
              if (streamErr) {
                failedContent = true;
                log("!! [KRS] " + keyTag + " HTTP " + status + " 但内容是错误帧: " + streamErr.slice(0, 160));
                // An error frame can also hide a missing capability, throttling, and a temporary upstream fault — the status code is 200,
                // and looking only at the status code cannot reach any of those three paths.
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
                // An error frame that cannot be pinned on a particular account (for example an internal upstream exception): in no-interrupt mode
                // try another account, and do not hand this error frame to Kiro to display as "Something went wrong".
                if (keepTrying("流内错误帧")) { handled = true; endOnce(false, false); return true; }
                return false;
              }
              if (ok) {
                clearCooldown(key); // A normal answer came back, so this key really is good
                return false;
              }
              // A failure response reaches here: handle endpoint-level problems first (none of those say anything about whether the key is good),
              // then record account state, and finally hand it to the no-interrupt fallback — if we can switch accounts or wait out a cooldown, never hand the failure
              // back to Kiro.
              if (trySwitchEndpointUnsupported(status, evidence)) { handled = true; endOnce(false, false); return true; }
              if (handleThrottle(status, evidence)) { handled = true; endOnce(false, false); return true; }
              if (tryRetryServerError(status, evidence)) { handled = true; endOnce(false, false); return true; }
              const kind = keyFailureKind(status, evidence);
              // Throttling is the exception: a 429 is an endpoint-level concurrency problem and says nothing about whether this key is good. Do not apply a cooldown and
              // do not change account state. But do record a note for the panel — so the user can see they are being throttled right now,
              // which is a different thing from "the account is bad" (this mark does not take part in selection).
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
              // Already released: pipe keeps forwarding the content as before. Here we only keep scanning for suspension copy, so
              // the next request can switch accounts.
              if (opened) { scanTail(d); return; }
              head.push(d);
              headSize += d.length;
              // An early signal of suspension copy at the start switches to a wider decision window, and we wait for the keywords to arrive.
              // A short timer that was already set must be cancelled and set again, or it still releases early when 300ms is up.
              if (!suspectMode && !decided && maybeSuspendedPrefix(headText())) {
                suspectMode = true;
                dropHeadTimer();
                log("[KRS] " + keyTag + " 开头出现账号异常的迹象，延长判定窗口后再决定是否换号");
              }
              const minBytes = suspectMode ? SUSPECT_MIN_BYTES : HEAD_MIN_BYTES;
              const waitMs = suspectMode ? SUSPECT_WAIT_MS : HEAD_WAIT_MS;
              if (headSize < minBytes && !decided) {
                // The start is too fragmented; wait for the next chunk. If upstream is slow to send, the timer releases it as a fallback.
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
              // Once it has been taken over, drop this upstream response and stop reading its data.
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
              // If the content is actually a failure, this turn never succeeded as far as Kiro is concerned, so count it in the error count.
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
              // If it has not been released yet, the whole thing can be retried transparently. Once released it cannot be saved (the first half of
              // the answer already reached Kiro), and the only option is to close the stream.
              if (!opened && keepTrying("上游响应中断")) {
                handled = true;
                endOnce(false, false);
                return;
              }
              endOnce(false);
              if (!opened) {
                // The response headers are still in hand: hand back the little content that was buffered at its real length. Do not send an empty body carrying
                // upstream's content-length, which would not match.
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
            // A transport failure is retried in place with backoff first: the request never reached upstream (the TLS handshake was cut by the local proxy,
            // a temporary DNS failure, the connection was reset). A resend is not billed twice and does not produce two answers, and it is safer and more likely to succeed than switching accounts —
            // switching accounts does nothing for "the network itself is down".
            if (tryRetryServerError(0, e.message)) { endOnce(false, false); return; }
            // A transport error is usually unrelated to the key. keyFailureKind hits only when the text really contains throttle or
            // invalid wording. If a switch or a retry catches it, do not count an error.
            const replyRule = replyRuleFirst(0, e.message);
            if (replyRule) { endOnce(false, false); scheduleRetry(replyRule, { beforeSwitch: true }); return; }
            if (trySwitchKey(0, e.message)) { endOnce(false, false); return; }
            if (n < maxAttempts) {
              const rule = matchedRetryRule(0, e.message);
              if (rule) { endOnce(false, false); scheduleRetry(rule); return; }
            }
            // Network jitter, a DNS failure, a connection reset: not one byte has been written to Kiro yet, and resending on another account
            // is completely transparent to it. This turn of the conversation should not just break off.
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
// Recognize which operation this CPS request is. Both path addressing and x-amz-target addressing have to be recognized.
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
  // The control plane is passed through unchanged, with an extra side-path sniff that records the little data the extension needs for itself (model billing
  // multipliers, account usage) — the bytes forwarded to Kiro are not affected in any way.
  //
  // The "usage" and "model list" operations used to be intercepted and resent by us, and that dropped four things:
  //   1. Kiro's original query parameters were replaced by hardcoding (resourceType was always AGENTIC_REQUEST),
  //      so whatever data the IDE asked for, it only ever got this one copy
  //   2. The request body was thrown away by req.resume()
  //   3. The official response headers were all dropped, and only a Content-Type was added back
  //   4. On request failure, an HTTP 200 + {} was returned pretending success
  // The result: the percentage circle in the IDE never got the data it actually requested — either numbers for some other resource type,
  // or simply an empty object. And Kiro uses that percentage to decide whether to compress context. If the circle
  // is wrong, compression never fires, and context piles up until it blows up.
  // Now whatever the official side sends, the IDE receives, unchanged.
  const passthrough = makeProxyHandler("CPS", managementBase, {
    sniff: (bodyText, status, req) => {
      if (status < 200 || status >= 300 || !bodyText) return;
      const op = cpsOpOf(req);
      if (op === "models") {
        // Cache each model's billing multiplier, so each request's credit cost is attributed at the real rate.
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
    // Every control-plane operation takes the same path: swap credentials, forward unchanged, and send the response back unchanged.
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
    // Who the port actually belongs to. The panel's top bar uses this to tell four cases apart:
    //   listening this window bound it, and requests are forwarded by this window
    //   standby   the port is held by the same kind of gateway in another Kiro window — this is normal sharing across windows,
    //             requests are forwarded by that window, and this window takes over automatically after it exits. It is not an error
    //   conflict  the port is held by an unrelated program. Change the port, or quit that program
    //   idle      not started
    // Both kinds of occupancy used to be only one line in the log. The panel could not tell them apart, and the user only saw "port in use"
    // with nowhere to go from there.
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
        // Is the occupant one of our own kind? If so, another Kiro window has already brought the gateway up, and this window
        // should stand by. It should not be reported to the user as a fault. Only when it is not one of ours is it a real conflict.
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
      // The port was taken (maybe the first time, or maybe this window took over after the previous holder exited).
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

// Fold the port state of both planes into the one word on the top bar.
//   off      the gateway switch is off, and Kiro uses its own endpoints
//   conflict at least one port is held by an unrelated program — this needs the user to act, so expose it first
//   standby  the port is held by another Kiro window's gateway, and this window stands by (the normal state of sharing across windows)
//   running  both planes belong to this window
//   starting still binding
function gatewayRuntimeState() {
  if (!isEnabled()) return "off";
  const states = [krsServer, cpsServer].filter(Boolean).map((s) => s.state);
  if (!states.length) return "starting";
  if (states.includes("conflict")) return "conflict";
  if (states.every((s) => s === "listening")) return "running";
  if (states.includes("standby")) return "standby";
  return "starting";
}
// The panel needs to show which port the problem is on, so report one copy per plane.
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
// redirect can never miss the plane kiro-agent is really using. The candidates from auto-detection
// are written in too: the detected result can switch from one candidate to another at any time, and covering every
// candidate in the endpoint table ahead of time means a switch does not have to wait for another reload.
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
  // Disk already says 127.0.0.1, but what Kiro actually calls is get(). When the key is not registered, get() stays empty,
  // yet the extension treated "disk is right" as success, and the model list and the conversation kept going to the official address.
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
      vscode.window.showErrorMessage(tr(
        "Kiro Gateway: 工作区设置覆盖了 " + fullEndpointKey(key)
        + "，请删除工作区中的同名配置后重新加载窗口。"
      ));
      return { changed: true, ok: false };
    }
    log("endpoint override verified via settings.json -> 127.0.0.1:" + port
      + (effectiveOk ? " (effective config updated)" : " (disk verified; reload required)"));
    return { changed: true, ok: true };
  }
  vscode.window.showErrorMessage(tr(
    "Kiro Gateway: 无法写入或验证 " + fullEndpointKey(key)
    + "。请打开日志查看实际 settings.json 路径。"
  ));
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
  return extContext?.extension?.id || "tesbo.kiro-gateway";
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

// Updates come from Kiro's extension gallery (Open VSX). Kiro lists them in
// the Extensions view and applies them with Restart Extensions. This extension
// does not scan the local install.

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
// An error that carries the status code and the response body: account-state judgment needs the status code, and must not regex a
// number out of the error text (any stray 403 in the body would mark a healthy account invalid).
function httpError(status, body) {
  const text = String(body || "");
  const e = new Error("HTTP " + status + ": " + text.slice(0, 200));
  e.status = Number(status) || 0;
  e.body = text;
  return e;
}
// Which region a single key uses. In automatic mode, a cache that agrees with profileArn comes first. When the cache and the
// profile disagree (a usage 200 that was a wrong call), use the profile region directly and stop trusting that cache.
function regionForKey(key) {
  const preferred = preferredRegionFor(key);
  if (preferred) return preferred;
  const home = jsonHomeRegion(key);
  if (home) return home;
  return configuredRegion();
}
// A control-plane GET for a particular key. On a cross-region refusal (401/403/404), automatic mode detects once on the spot
// and retries, so "the region was filled in wrong" is not misjudged as "the key is invalid".
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
  // The key currently in use. The detection result is also written to the global config, and proxy forwarding switches along with it.
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
// Automatic region detection
// ---------------------------------------------------------------------------
// Which region a key belongs to is cheapest to learn by asking each candidate region's management endpoint once with it:
//   2xx  → this region recognizes the key; a hit;
//   429  → it recognizes it but is being throttled; a fallback (used only when there is no 2xx);
//   other → it does not belong to this region (403 is the typical cross-region refusal).
// The probe is the lightest GET (Get-Usage-Limits) and does not consume quota.
const REGION_PROBE_PATH = "/Get-Usage-Limits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST";
const REGION_PROBE_TIMEOUT_MS = 8000;
let _regionDetecting = null; // The probe Promise in flight, so concurrent probes are not duplicated
let _regionDetectBusy = false; // The panel needs to show "detecting", so the flag has to be set synchronously before the probe
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
    // A missing domain (ENOTFOUND) or a timeout both land here: this region is unavailable.
    return { region, status: 0, ms: Date.now() - started, hit: false, soft: false, error: e?.message || String(e) };
  }
}
// The usage API can return 200 in both regions. When a JSON account has a profileArn, that region wins;
// with no profile and more than one 200, use "the model list is non-empty" to rule out the empty region.
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
  // If the usage API recognizes the profileArn region, use it. A 200 from the other region must not carry the account away:
  // that side can often report the plan, but the model list is empty.
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
// In automatic mode, make sure the current key's region has been detected.
//   force = true  → ignore the cache and probe again (the panel's "detect again" comes through here)
//   silent = true → no toast, log only (background detection at startup or when switching keys)
// The result is written back to the region setting, so endpoint redirect, proxy forwarding, and the status bar all follow on their own,
// with no need to check automatic mode again somewhere else.
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
  // Set "detecting" before sending the request, so the state pushState sends out really is in progress.
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
// Write the detected region into config. If the value did not change, do nothing, so we do not write config for nothing or fire
// applyState.
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
// When a generate request hits "authentication failed", suspect the region first, not a bad key: a cross-region refusal and a real failure
// look the same (both are 403 + access denied), and only asking again in another region can tell them apart.
// In automatic mode, recheck once in the background. If the region really changed, withdraw the invalid verdict just recorded, and let this key
// join selection again in the new region. Recheck the same key at most once every 60 seconds, so repeated failures do not probe over and over.
const REGION_RECHECK_MIN_GAP_MS = 60 * 1000;
const _regionRecheckAt = new Map(); // key -> last recheck time
// When switching to an account whose region has not been probed, run one probe.
//
// Without it, regionForKey falls back to the global value (that is, the previous account's region). When several accounts belong to different regions,
// this request hits the wrong region, and upstream returns a 403 plus body text identical to "the credential really is bad", so the account is easily
// mislabeled invalid. The forwarding path has cpsGetForKey's cross-region retry as a fallback, but that has to hit the wall once first. Here,
// probe the region ahead of time and write it into the cache. After that regionForKey hits directly, and that wall does not have to be hit.
// Share _regionRecheckAt's throttle with the failure recheck: the two are asking the same question, so ask only once within 60 seconds.
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
  // denied has to be rechecked too: among 403s with no clear reason, "region mismatch" is a large share, and compared with a real failure the
  // response looks exactly the same.
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
// Quota reset time. The field name has changed across several rounds of Kiro versions, so scan recursively and take whichever one is recognized;
// what comes back may be an ISO string, or a timestamp in seconds or milliseconds, and it is folded into a millisecond timestamp either way.
// With this value, the freeze for "quota exhausted" can be held until the real reset moment, instead of a default TTL picked out of the air.
const RESET_AT_FIELDS = [
  "nextDateReset", "nextResetDate", "resetDate", "resetAt", "resetTime",
  "usageLimitResetDate", "nextUsageResetDate", "renewalDate", "periodEnd",
];
function normalizeResetAt(v) {
  if (v == null) return 0;
  if (typeof v === "number" && Number.isFinite(v)) {
    // 10 digits are seconds, 13 digits are milliseconds. Anything under 1e12 is treated as seconds.
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
// Parse a usage response into { subscriptionTitle, tier, used, total, resetAt }.
// Two paths share this parse: the extension probing on its own (fetchAccountInfo), and the side-path sniff when Kiro itself requests usage
// (noteUsageFromBody). The way fields are recognized has to match, or the panel and the IDE will each
// report a different set of numbers.
function parseUsagePayload(data) {
  const title = data?.subscriptionInfo?.subscriptionTitle || data?.subscriptionInfo?.subscriptionType || "";
  const pairs = [];
  collectUsagePairs(data, pairs);
  let used = null, total = null;
  for (const p of pairs) {
    if (p.used != null) used = (used || 0) + p.used;
    if (p.limit != null) total = (total || 0) + p.limit;
  }
  // Quota reset time: include it when present. The freeze for "quota exhausted" is held until that moment and then rechecked automatically.
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
// When Kiro itself requests usage, record a note along the way. This is the freshest first-hand data — the percentage circle in the IDE is
// drawn from it — and it is used to update account state and the remaining quota that selection looks at, and it can also save the extension a probe of its own.
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
// Background account sweep
// ---------------------------------------------------------------------------
// The 30-second account sync in the panel runs inside the webview, and the webview is destroyed entirely the moment it is hidden —
// while the panel is not open, account state can only be updated passively by "a real request hitting the wall": a quota that has already reset is invisible,
// a throttle that lifted long ago is unknown, and the current account keeps being used even after it was filled up somewhere else. It switches only after hitting the wall once.
//
// So the host has to sweep on its own too, only on a much slower cadence, and it shares one "last probe time" with the panel,
// so the two sides do not hit the same account twice. It uses the lightest usage GET and does not consume quota.
const HEALTH_SWEEP_MS = 5 * 60 * 1000;
const HEALTH_PROBE_MIN_GAP_MS = 4 * 60 * 1000; // The same account is probed again only after at least this long
const HEALTH_SWEEP_MAX_KEYS = 6;               // At most this many accounts per round; when there are many, they spread across rounds on their own
const HEALTH_SWEEP_CONCURRENCY = 3;
const _keyProbeAt = new Map(); // key -> last probe time (panel sync writes here too)
let _healthTimer = null;
let _healthSweeping = false;
function noteKeyProbed(key) {
  if (key) _keyProbeAt.set(key, Date.now());
}
// Which accounts this round should probe: the one currently in use comes first (its state matters most), and the rest are ordered by "unprobed the longest".
// Skip ones that are frozen — keyHealthFrozen also clears a terminal state that has expired, so an account that just passed its recheck window
// re-enters the probe queue here on its own.
function keysDueForProbe() {
  const now = Date.now();
  const active = getApiKey();
  return getApiKeys()
    .filter((k) => {
      const st = (_keyHealth.get(k) || {}).state;
      // Quota-exhausted and suspended accounts are probed as usual, ignoring the freeze window. Those two are normally deleted automatically, and if they can still appear in
      // the list, the deletion never landed (a terminal state just restored from disk, or the last delete failed). One probe helps in two
      // ways: a real 200 reverses it on the spot and saves it (quota recovers on its own once the cycle turns), and if it is still bad it
      // triggers deletion once more. It uses the free usage GET and does not burn quota.
      if (st === "quota" || st === "suspended") return true;
      // The rest follow the old rule: skip ones that are frozen. keyHealthFrozen also clears a terminal state that has expired, so an account that just
      // passed its recheck window (for example one misjudged as an auth failure across regions) re-enters the probe queue here on its own.
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
  // Relay mode has no notion of multiple accounts. When the gateway is off, there is also no need to worry about Kiro's official service on its behalf.
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
    // A probe result may make the current account unusable. Switch to another one along the way, instead of waiting for the next request to hit the wall.
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
// After the mode, the switch, or the keys change, decide again whether the sweep should run.
function syncHealthSweep() {
  if (!isRelayMode() && isEnabled() && getApiKeys().length) startHealthSweep();
  else stopHealthSweep();
}

// ---------------------------------------------------------------------------
// Liveness probe plus automatic deletion when an account goes dead
// ---------------------------------------------------------------------------
// The sweep above goes through the control plane (a usage GET) and does not consume quota, but it has a blind spot: when an account is locked by backend risk control
// it often blocks only the inference API, and the usage query still returns 200. What you see is an account that has long been unable to chat, while the panel still
// shows "healthy", until the user sends a message and hits the wall.
//
// So add a real liveness probe that goes through the inference plane: POST runtime.{region}.kiro.dev with a minimal
// GenerateAssistantResponse. The cost is that each real probe consumes one generate request, so there are two gates:
//   * each account is really probed at most once every livenessRealCheckPerKeyIntervalSec seconds (60 seconds by default)
//   * an account already frozen into a terminal state is not probed (a terminal state does not reverse itself)
//
// When the probe finds the account is already dead (suspended, overage cap filled, or monthly quota exhausted), delete it from the key list according to the setting,
// so the user does not have to come back and clear them one by one by hand.
function getLivenessCheckEnabled() {
  return get("livenessCheckEnabled", false) === true;
}
function getLivenessCheckIntervalSec() {
  const v = Math.round(Number(get("livenessCheckIntervalSec", 60)));
  return Number.isFinite(v) ? Math.min(Math.max(v, 10), 3600) : 60;
}
// Minimum interval between real probes of one account. Stops a dense scan from really probing the same account over and over and burning quota on liveness checks.
function getLivenessRealCheckPerKeyIntervalSec() {
  const v = Math.round(Number(get("livenessRealCheckPerKeyIntervalSec", 60)));
  return Number.isFinite(v) ? Math.min(Math.max(v, 10), 3600) : 60;
}
// On by default: once an account is dead, clear it out of the list automatically. Keeping a suspended or quota-exhausted account is useless — it does not
// take part in selection, it only occupies a red row on the panel, and it has to be reconfirmed on every liveness round. Only these three kinds are deleted
// (see DEAD_KINDS). Authentication failure is deliberately not among them; that may only be a mistyped credential or a cross-region misjudgment.
function getAutoDeleteOnDead() {
  return get("autoDeleteOnDead", true) !== false;
}
// Signature of the overage cap. After a POWER account fills base plus overage, the inference plane returns HTTP 400 plus
// __type=ServiceQuotaExceededException + reason=OVERAGE_REQUEST_LIMIT_EXCEEDED.
// keyFailureKind folds it into generic quota, but from the user's point of view this account is beyond saving (they can only wait for the next
// billing cycle). A separate kind makes panel counts and logs easier to tell apart.
const OVERAGE_EXCEEDED_RE = /OVERAGE_REQUEST_LIMIT_EXCEEDED|reached the limit for overages/i;
// Kinds that should be deleted automatically:
//   suspended        the account was suspended by the backend on purpose
//   overage_exceeded the overage cap is filled
//   quota            the monthly quota is exhausted
// invalid is not in this set — that may only be a mistyped credential, and deleting it would take away the user's chance to correct it.
// network / unknown are not in it either: network jitter does not count.
const DEAD_KINDS = new Set(["suspended", "overage_exceeded", "quota"]);
// Timestamp of each account's last real probe. Memory only, so a reload can run a fresh real-probe round immediately.
const _keyLastRealCheck = new Map();
function forgetKeyLastRealCheck() {
  const alive = new Set(getApiKeys());
  for (const k of _keyLastRealCheck.keys()) if (!alive.has(k)) _keyLastRealCheck.delete(k);
}

// A real liveness probe of a single account. The request shape follows the combination already proven in forwarding. Do not invent another set of headers.
async function livenessCheckOne(key) {
  const region = cachedRegionFor(key) || getRegion();
  let hostname;
  try {
    hostname = new URL(runtimeBaseFor(region)).hostname;
  } catch {
    return { kind: "network", detail: "bad region " + region };
  }
  // conversationId changes every time, so upstream does not treat the liveness probe as a continued conversation and accumulate it onto some session, and so the
  // probe does not pollute the history of a real conversation.
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
    // Decide from only the first 16KB. A generate response is streamed, but judging "is the account up" needs at most the head:
    // 2xx plus an early normal frame = ok; 4xx = an immediate error; 2xx plus an early error frame = suspended.
    // The quota has already been spent, and reading more only wastes time and memory.
    const READ_CAP = 16 * 1024;
    const finalize = () => {
      if (done) return;
      done = true;
      const raw = Buffer.concat(bufs).toString("utf8");
      // Recognize the overage cap first: this is the hardest evidence (a hard __type field plus a specific reason constant).
      // Whatever the status code, if it appears in the body the account is confirmed dead.
      if (OVERAGE_EXCEEDED_RE.test(raw)) {
        resolve({ kind: "overage_exceeded", detail: "HTTP " + statusCode + " overage" });
        return;
      }
      if (statusCode >= 200 && statusCode < 300) {
        // A 2xx can also carry an in-stream error frame: upstream sometimes returns "suspended" as 200 plus an error frame.
        if (looksSuspended(failureEvidence(raw))) {
          resolve({ kind: "suspended", detail: "200+stream" });
          return;
        }
        resolve({ kind: "ok" });
        return;
      }
      // 4xx / 5xx reuse keyFailureKind's classification, on exactly the same terms as a forwarding failure and an account sync.
      const kind = keyFailureKind(statusCode, raw);
      if (kind === "suspended") { resolve({ kind: "suspended", detail: "HTTP " + statusCode }); return; }
      if (kind === "invalid") { resolve({ kind: "invalid", detail: "HTTP " + statusCode }); return; }
      if (kind === "quota") { resolve({ kind: "quota", detail: "HTTP " + statusCode }); return; }
      // Throttling means the account is alive and only crowded at this moment, so draw no conclusion.
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
        // A generate request is slow to begin with, but if it really hangs, do not let it drag on too long.
        timeout: 25000,
        // The liveness probe deliberately stays out of the connection pool: it calls req.destroy() to cut the stream early (the head is enough to judge),
        // and a socket cut halfway must not go back into the pool and contaminate normal requests.
        agent: false,
      },
      (res) => {
        statusCode = res.statusCode || 0;
        res.on("data", (c) => {
          total += c.length;
          if (total <= READ_CAP) bufs.push(c);
          // Disconnect once the head is in. destroy goes through the close branch, and the done flag guarantees resolve is not called twice.
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

// Liveness-scan state, for the panel to display.
const _livenessState = {
  lastRunAt: 0,
  lastCounts: { ok: 0, suspended: 0, overage_exceeded: 0, invalid: 0, quota: 0, network: 0, unknown: 0, skipped: 0 },
  lastDeleted: 0,   // How many were deleted in this scan
  totalDeleted: 0,  // How many have been deleted over this session
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

// Delete one account automatically, through the same cleanup the panel delete uses.
// When the active account is deleted and the gateway is on, the gateway used to be turned off and a reload prompted: deleting without turning it off left kiro-agent looking at
// an endpoint with no usable credential, and it would error continuously.
async function deleteKeyAutomatic(key, reason) {
  const list = getApiKeys();
  const idx = list.indexOf(key);
  if (idx < 0) return { deleted: false, activeAffected: false };
  const removingActive = getActiveApiKey() === key;
  list.splice(idx, 1);
  // Record "this one was just deleted": the pool (especially a shared carpool-style pool) is likely to hand the same one back down immediately,
  // and accepting it only repeats import → hit the wall → mark dead → delete, wasting round trips.
  rememberDeadKey(key);
  await setApiKeys(list);
  // forgetKeyHealth has already cleared state, cooldown, usage, and probe time together. This used to also call
  // clearCooldown, which writes an "ok" back as a side effect, leaving a dirty record for an account that is no longer in the list.
  forgetKeyHealth([key]);
  _keyLastRealCheck.delete(key);
  try { await syncKeyAddedAt(list); } catch {}
  // silent: this path is triggered by a background liveness probe and should not pop a native dialog in the user's face.
  await applyState({ silent: true });
  maybeAdoptUsableKey();
  if (removingActive) {
    // Deleting the one currently in use no longer turns the gateway off either.
    //
    // What used to be here was set("enabled", false) and then a prompt to reload. But a pool that refills accounts will bring a new one in at any time,
    // and once the gateway is off the account that comes back has nowhere to land, so the user has to turn it on again by hand — and this path is exactly the one
    // automatic refill hits most often: the account in use burns out and is deleted, and the refill pulls a new one in right after.
    // If the pool still has accounts, switch to the next one. If none remain, let it idle and wait for a refill — the accounts are dead either way, and turning the gateway off or not,
    // no request can go out. Leaving it on lets the account that comes back take over immediately.
    const tail = list.length
      ? "，网关保持开启并切到剩余可用号"
      : "，池子已空，网关保持开启等号池补号";
    log("[探活] 已自动删除正在使用的密钥 " + maskKey(key) + "（" + reason + "）" + tail);
  } else {
    log("[探活] 自动删除 " + maskKey(key) + "（" + reason + "）");
  }
  // No notification. Deletion is fully automatic, and a pool that adds one and deletes one may do it several times in a row. A dialog every time is too noisy,
  // and the user does not have to decide anything on the spot. To trace it, look at the two lines above in the run log.
  if (panelProvider) panelProvider.pushState();
  return { deleted: true, activeAffected: removingActive };
}

const LIVENESS_CONCURRENCY = 4;
const DEAD_KIND_LABEL = {
  suspended: "账号已被禁用",
  overage_exceeded: "溢出额度已打满",
  quota: "额度已用尽",
};
// One scan round: pick the accounts that should be really probed, probe them one by one, write the result onto account state, and delete dead accounts according to the setting.
// manual=true ignores the per-account minimum interval (the user clicked the button themselves and knows the cost).
async function runLivenessScan({ manual = false } = {}) {
  if (_livenessState.running) {
    if (manual) log("[探活] 上一轮还没跑完，本轮跳过");
    return { skipped: true };
  }
  // Relay mode has no notion of multiple accounts. When the gateway is off, there is also no need to worry about Kiro's official service on its behalf.
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
      // An account frozen into a terminal state is not really probed. But if automatic deletion is on, the terminal kinds that count as "dead accounts" are let in for
      // one probe — otherwise an account the sweep froze as quota waits forever for deletion and just lies in the list.
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
          // A real probe getting through is the hardest "this account can be used": even a terminal state can be reversed by it, so pass force.
          // A quota-exhausted account is saved automatically by this step once the billing cycle resets.
          clearCooldown(key);
          setKeyHealth(key, "ok", { force: true });
          okKeys.push(key);
          continue;
        }
        if (r.kind === "network" || r.kind === "unknown") continue; // Jitter draws no conclusion
        // A failure that has a conclusion: record the state, so the panel and the selection logic know immediately. overage folds into quota,
        // because the panel only recognizes those few state names.
        setKeyHealth(key, r.kind === "overage_exceeded" ? "quota" : r.kind);
        if (!getAutoDeleteOnDead() || !DEAD_KINDS.has(r.kind)) continue;
        const reason = (DEAD_KIND_LABEL[r.kind] || r.kind) + " · " + (r.detail || "");
        const out = await deleteKeyAutomatic(key, reason).catch(() => ({ deleted: false }));
        if (out.deleted) deleted++;
        // Deleting the one currently in use no longer turns the gateway off (see deleteKeyAutomatic), so this round does not have to be interrupted.
        // Keep probing the remaining accounts. Clearing the dead ones in one scan is cheaper than leaving them for the next round.
      }
    }
    // When a live account is probed, refresh usage along the way: a control-plane GET, which does not consume generate quota, so the panel header's
    // used / total does not have to wait for the user to click "sync now". Do not await it, and do not hold up this round.
    if (okKeys.length) {
      Promise.all(okKeys.map(async (k) => {
        try { noteAccountHealth(k, true, await fetchAccountInfo(k)); } catch {}
      })).then(() => { if (panelProvider) panelProvider.pushStats(); }).catch(() => {});
    }
    // The one currently in use may have just been judged terminal (marked, but not deleted): let an available account take over, so the next request
    // does not have to hit the same wall. When automatic switching is off, this call skips itself internally.
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
// After the switch, the interval, the mode, or the keys change, decide again whether the liveness probe should run.
function syncLivenessScheduler() {
  if (getLivenessCheckEnabled() && !isRelayMode() && isEnabled() && getApiKeys().length) {
    startLivenessScheduler();
  } else {
    stopLivenessScheduler();
  }
}

// ---------------------------------------------------------------------------
// Automatic refill (the pool refills accounts on its own)
// ---------------------------------------------------------------------------
// When usable keys (not cooling down, and not judged terminal) drop below the threshold, poll the pool API the user configured, on a cadence,
// and validate the new ksk_ accounts that come back before importing them.
//
// A few key conventions:
//   * A duplicate key is skipped and does not count as a success. All duplicates means the pool has not produced a new account, and pulling hard
//     means nothing, so this case enters "duplicate-key cooldown", held longer than the ordinary poll interval.
//   * A failed request backs off exponentially (base backoff × 2^n, clamped to the max backoff, then a random jitter on top).
//     Consecutive failures up to the threshold open the circuit for a while — if the other side is already down, spinning in a loop only gets you blocked.
//   * "Max poll count" is the cap within one trigger (dropping below the threshold). Once it is used up, stop. When usable keys
//     climb back above the threshold it resets on its own, and it can also be reset by hand with "refill now" on the panel.
//   * Pool APIs come in every shape, so parsing has two layers: first recognize by structure (the carpool-team JSON with code / msg /
//     data[].account, which can also carry region and status). If that fails, use a regex to pull out strings that start with ksk_.
//     Plain text, one per line, is accepted the same way.
//   * When the other side explicitly says "no account available right now, restocking", treat it as queued: it is neither a failure (it does not feed the circuit breaker) nor
//     a duplicate (it does not enter the long cooldown). Keep waiting for dispatch at the ordinary interval.
const RENEW_DEFAULTS = {
  enabled: false,
  apiUrl: "",
  // Whether a new account that passed validation is written straight into the key list. Off, it goes to "pending import" and waits for the user to confirm.
  autoImport: true,
  // Keep stocking: when on, ignore the threshold and keep pulling new accounts from the pool at the poll interval (accept one whenever the pool produces one).
  // Off by default — refill only when there are not enough accounts, which is the kindest to the pool.
  alwaysPoll: false,
  threshold: 2,             // Trigger threshold: start refilling when usable keys drop below this number
  intervalSec: 60,          // Poll interval
  maxRounds: 3,             // Max poll count; stop once it is used up
  batchSize: 1,             // Batch size: how many requests to send in one round
  requestGapSec: 5,         // Gap between requests in the same round
  backoffBaseSec: 30,       // Base backoff
  backoffMaxSec: 300,       // Max backoff
  breakerThreshold: 5,      // Consecutive-failure threshold for opening the circuit
  breakerCooldownSec: 300,  // Circuit-breaker cooldown
  dupCooldownSec: 600,      // Duplicate-key cooldown
  jitterPct: 10,            // Random jitter on the backoff
};
// The allowed range for each numeric parameter. The panel clamps once, and the host clamps once more — the config may also have been
// stuffed in by the user editing globalState directly.
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
const RENEW_TICK_MS = 2000;              // Scheduler heartbeat. It only compares times, so it is cheap
const RENEW_FETCH_TIMEOUT_MS = 20000;    // Timeout for a single pool request
const RENEW_BODY_CAP = 512 * 1024;       // Cap on reading the response body, so the other side cannot dump a huge file
// Whatever format the pool returns, this regex pulls keys out of it. It does not include base64's + / = : those characters
// can all be separators in JSON or a URL. Better to pull one short than to swallow trailing punctuation.
const RENEW_KEY_RE = /ksk_[A-Za-z0-9_-]{8,}/g;
// account.key in a structured response is its own field and must be matched as a whole string, not with the global regex above
// (a regex with g has lastIndex, and testing the same one repeatedly skips characters).
const RENEW_KEY_ONE_RE = /^ksk_[A-Za-z0-9_-]{8,}$/;
// zone is a region abbreviation, and it is only useful when a full aws_region was not given.
const RENEW_ZONE_REGION = { us: "us-east-1", eu: "eu-central-1" };
// Business codes: 0 and 200 are both common ways of writing "success". Anything else is treated as failure. A pool that gives no code
// (plain text, one per line) does not take part in this check.
const RENEW_OK_CODES = new Set([0, 200]);
function renewCodeOk(code) {
  return code == null || RENEW_OK_CODES.has(Number(code));
}

// Some pools (the carpool-team / dispatch kind) return structured JSON that carries seat information:
//   { code: 0, msg: "joined the \"US Power carpool\" queue, but no account is available yet…",
//     data: [ { claimId, channelId, channelName, seatNo, seatsTotal, claimType,
//               claimTime, warrantyUntil,
//               account: { key, zone, aws_region, status } } ] }
// A bare string of keys would not have given these three useful things:
//   * account.aws_region — which region the account belongs to is written outright, so validation does not have to probe every candidate region
//     with it (that is a round of concurrent requests, so save it when you can);
//   * account.status — an account that is not active does not even need to be validated, saving a round trip;
//   * code / msg — "restocking, and it will be dispatched to you automatically once it arrives" is a queue, not a fault. Looking only at the HTTP
//     status code would count it as a failure toward the circuit breaker, and the dispatch would be missed.
// If this structure cannot be recognized, return null and let the caller fall back to the regex, so anyone's format can still be consumed.
// status is not placed consistently: some pools write it inside account, some write it on the outer entry, and the field name may also
// be state / accountStatus. Look at both layers — reading only from account would turn a status written on the outer layer into
// an empty string, and the filter would treat that as "the pool gave no status" and let it through, so an account that is not active slips in.
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
  // A full region name (us-east-1 / eu-central-1) can be used directly.
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
  // data is the common spelling, and a top-level array is recognized too.
  const rows = Array.isArray(j.data) ? j.data : Array.isArray(j) ? j : null;
  // None of the three is present: this is not that kind of response, so hand it to the regex.
  if (rows == null && code == null && !msg) return null;
  const items = [];
  const seen = new Set();
  for (const row of rows || []) {
    if (!row || typeof row !== "object") continue;
    // If there is an account, take it from there. If not, treat this layer as carrying the key itself (some pools lay accounts out flat inside data).
    const acc = row.account && typeof row.account === "object" ? row.account : row;
    const key = String(acc.key || acc.apiKey || "").trim();
    // An entry that is still restocking may have a null account. Skip it safely.
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
  // The most recently claimed seat comes first: when one response holds both historical seats and a newly dispatched account, validate the new one first.
  items.sort((a, b) => b.claimTime - a.claimTime);
  return { code, msg, items, rows: rows ? rows.length : 0, structured: true };
}
// One entry point: structure first (it can carry region and status). If the structure cannot be recognized, or the structure contains no accounts, fall back to the
// regex. Whichever path is taken, what comes out is the same entry shape.
function renewItemsFrom(body) {
  const parsed = parseRenewPayload(body);
  if (parsed && parsed.items.length) return parsed;
  const items = extractRenewKeys(body).map((key) => ({
    key, region: "", status: "",
    claimId: 0, channelName: "", seatNo: 0, seatsTotal: 0, claimTime: 0, warrantyUntil: 0,
  }));
  if (!parsed) return { code: null, msg: "", items, rows: 0, structured: false };
  // The structure was recognized but there is no account (restocking): keep code / msg. The scheduler needs them to tell a queue apart from a fault.
  return { ...parsed, items };
}
// Seat information is pressed into one line, shared by the panel's test result and the log.
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
// How many usable keys there are right now. This is the number the "trigger threshold" is compared against: cooling down, invalid,
// quota exhausted, and suspended do not count.
function usableKeyCount() {
  return getApiKeys().filter((k) => keyIsUsable(k)).length;
}
// The pool's test list only needs "which one this is", so keep only the prefix and the last 4 characters.
function maskRenewKey(k) {
  const s = String(k || "");
  if (s.length <= 8) return s;
  return s.slice(0, 4) + "…" + s.slice(-4);
}
function renewSleep(ms) {
  return new Promise((r) => setTimeout(r, Math.max(0, Number(ms) || 0)));
}
// Pull the pool API once. Use the native http/https modules, because the pool address may be a self-hosted http service.
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
// Pull the deduplicated keys out of the response body, keeping the order they appeared in.
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
// Pull once and sort the accounts out. The test button and the real poll both come through here.
// keys is kept so a caller that only cares "how many accounts" does not have to change how it is written.
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
// Validate a new account: ask the usage API once in each candidate region with it. A 2xx (or a throttled 429) means the account
// is real, and it also tells which region it belongs to. An account whose quota is already full is not accepted — importing it would not make it usable.
// The region cache is deliberately not written here: the test button also goes through this function and must not pollute the cache. Caching happens after import.
// hint.region: the region the pool itself wrote down (aws_region / zone in the structured response). Probe only this
// one first, and a hit saves a whole round of multi-region concurrent probes. On a miss, fall back to a full probe — a pool that wrote the wrong region
// has to be covered too.
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
  // Failing to get plan information does not affect the judgment (this API occasionally refuses to be used). The list just shows a little less.
  try { info = await fetchAccountInfo(key); } catch {}
  const used = Number(info && info.used);
  const total = Number(info && info.total);
  if (Number.isFinite(used) && Number.isFinite(total) && total > 0 && used >= total) {
    return { ok: false, region, info, message: "额度已用尽" };
  }
  return { ok: true, region, info, message: "" };
}
// Merge new accounts that passed validation into the key list. entries: [{ key, region }]
async function importRenewKeys(entries) {
  const list = getApiKeys();
  const existing = new Set(list);
  const fresh = entries.filter((e) => e && e.key && !existing.has(e.key));
  if (!fresh.length) return 0;
  await setApiKeys([...list, ...fresh.map((e) => e.key)]);
  // A new account starts from a clean state. Do not inherit a terminal state the same key left behind before.
  forgetKeyHealth(fresh.map((e) => e.key));
  // The region was already probed during validation, so record it along the way. The first use after import does not have to probe again.
  for (const e of fresh) {
    if (e.region) { try { await rememberRegionFor(e.key, e.region); } catch {} }
  }
  await applyState({ silent: true });
  // When the current one is already unusable, let the new account take over immediately.
  maybeAdoptUsableKey();
  if (panelProvider) panelProvider.pushState();
  return fresh.length;
}

// --- Pending-import holding area -----------------------------------------------------------
// When "auto import" is off, a new account that passed validation lands here first, and enters the key
// list only when the user confirms it on the panel. Some people do not want the extension stuffing accounts into the list on its own (for example they want to see the region and the plan first),
// and this holding area is for that use.
//
// Persist it instead of keeping it only in memory: an account that was pulled is still there after a window reload, or the pull was wasted. What is stored is the key in plaintext
// — the same as apiKeys itself (that is a plaintext config item too), so this introduces no new exposure.
const RENEW_PENDING_STATE_KEY = "kiroGateway.renewPending";
const RENEW_PENDING_CAP = 50; // Cap: it will not pile up without limit when nobody comes to confirm
let _renewPending = []; // [{ key, region, title, used, total, note, at }]
function loadRenewPending() {
  if (!extContext) return;
  let saved = null;
  try { saved = extContext.globalState.get(RENEW_PENDING_STATE_KEY); } catch {}
  if (!Array.isArray(saved)) return;
  // Ones already added to the key list by hand, and duplicate entries, are cleared along the way on load.
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
// The shape the panel needs to display. It carries the full key: the panel uses it to click "import this one", the same way the key list does.
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
// Duplicate detection has to look at the holding area too, or an account already held and not yet confirmed is treated as new on the next round,
// and a round trip is spent validating it for nothing.
function renewKnownKeys() {
  // A bad account that was just deleted automatically also counts as "known": the pool is likely to hand the same one back down immediately, and accepting it only walks
  // import → hit the wall → mark dead → delete one more time. If the same one comes back after the memory window, accept it again; the quota may have really reset by then.
  const dead = [];
  for (const k of [..._deadKeyAt.keys()]) if (isRecentlyDeadKey(k)) dead.push(k);
  return new Set([...getApiKeys(), ..._renewPending.map((e) => e.key), ...dead]);
}
// Accounts that passed validation go into the holding area. entries: [{ key, region, info }]
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
  // New ones go in front. When the cap is exceeded, drop the oldest.
  _renewPending = [...add, ..._renewPending].slice(0, RENEW_PENDING_CAP);
  await saveRenewPending();
  if (panelProvider) panelProvider.pushState();
  return add.length;
}
// Import from the holding area. An empty keys means import all of them.
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
// Discard accounts in the holding area. An empty keys means discard all of them.
async function dropPendingKeys(keys) {
  const want = Array.isArray(keys) && keys.length ? new Set(keys.map(String)) : null;
  const before = _renewPending.length;
  _renewPending = want ? _renewPending.filter((e) => !want.has(e.key)) : [];
  if (_renewPending.length === before) return 0;
  await saveRenewPending();
  if (panelProvider) panelProvider.pushState();
  return before - _renewPending.length;
}
// Where a new account that passed validation should go: auto-import writes it straight into the key list, otherwise it waits in the holding area for confirmation.
// Returns { imported, stashed }. The caller uses that to write the log and decide the cadence of the next round.
async function deliverRenewKeys(entries) {
  if (getRenewPrefs().autoImport) {
    return { imported: await importRenewKeys(entries), stashed: 0 };
  }
  return { imported: 0, stashed: await stashRenewKeys(entries) };
}

// --- Scheduling -------------------------------------------------------------------
// phase is the status line on the panel:
//   off      not enabled, or the pool API has not been filled in
//   idle     enough usable keys, standing by
//   waiting  below the threshold, waiting for the next poll
//   polling  pulling accounts
//   backoff  the last round failed, backing off
//   dup      everything pulled was a duplicate, in duplicate-key cooldown
//   pending  auto-import is off, and the holding area already has accounts waiting for the user to confirm, so stop pulling for now
//   breaker  consecutive failures opened the circuit, cooling down
//   stopped  the max poll count is used up, stopped
let _renewTimer = null;
let _renewBusy = false;   // A round is already running; do not stack the heartbeat on top of it
let _renewForce = false;  // The panel's "refill now" was clicked: ignore the threshold and the stopped state, and run one round
let _renew = {
  phase: "off",
  rounds: 0,          // How many rounds this trigger has already run
  fails: 0,           // Consecutive failure count (for the circuit breaker)
  nextAt: 0,          // When the next round is due
  breakerUntil: 0,
  dupUntil: 0,
  imported: 0,        // How many this trigger has imported in total
  stashed: 0,         // How many this trigger has stashed in total (when auto-import is off)
  lastAt: 0,          // When the last round ended
  lastMessage: "",    // Result of the last round, shown directly on the panel
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
    lastMessage: tr(_renew.lastMessage || ""),
  };
}
function setRenewPhase(phase) {
  if (_renew.phase === phase) return;
  _renew.phase = phase;
  // State is pushed along with the stats: the panel pulls stats every few seconds, so the countdown moves on its own.
  if (panelProvider) panelProvider.pushStats();
}
// Exponential backoff: base backoff × 2^(consecutive failures − 1), clamped to the max backoff, then ±jitter% on top.
// The jitter keeps several clients from retrying in the same second, all at once.
function renewBackoffMs(p, fails) {
  const base = Math.max(1000, p.backoffBaseSec * 1000);
  const max = Math.max(base, p.backoffMaxSec * 1000);
  const grown = Math.min(base * Math.pow(2, Math.max(0, fails - 1)), max);
  const jitter = p.jitterPct / 100;
  if (jitter <= 0) return Math.round(grown);
  return Math.max(1000, Math.round(grown + grown * jitter * (Math.random() * 2 - 1)));
}
// Which phase to show right now. The heartbeat's judgment and the immediate refresh after a round share this set of rules,
// so the wording in the two places does not fight. "due" means it is time to pull, and only the heartbeat uses it.
function computeRenewPhase(p, now = Date.now()) {
  if (!p.apiUrl || !p.enabled) return "off";
  // Keep-stocking ignores the threshold: accept a new account whenever the pool produces one, whether or not there are enough right now.
  if (!p.alwaysPoll && usableKeyCount() >= p.threshold) return "idle";
  // Auto-import is off and accounts are already sitting in the holding area: the work is done and only confirmation is left, so do not keep pulling the pool.
  if (!p.autoImport && _renewPending.length > 0) return "pending";
  if (now < _renew.breakerUntil) return "breaker";
  if (now < _renew.dupUntil) return "dup";
  // "Max poll count" is the safety stop for "refill until there are enough, then stop". Keep-stocking has no endpoint to begin with, so it is not limited by it.
  // The circuit breaker and the backoff still apply — those two protect the pool, and no mode gets to skip them.
  if (!p.alwaysPoll && _renew.rounds >= p.maxRounds) return "stopped";
  if (now < _renew.nextAt) return _renew.fails > 0 ? "backoff" : "waiting";
  return "due";
}
// Run one round: send several requests according to "batch size", with "gap between requests in the same round" between them.
// This only pulls, validates, and imports. Cadence decisions are left to runRenewRound.
// force: "refill now" from the panel. This round is not constrained by the enable switch.
async function pollRenewOnce(p, force) {
  const r = { found: 0, dup: 0, invalid: 0, errors: 0, imported: 0, stashed: 0, queued: 0, notes: [] };
  for (let i = 0; i < p.batchSize; i++) {
    if (i > 0 && p.requestGapSec > 0) await renewSleep(p.requestGapSec * 1000);
    // The user may have turned the switch off while we were waiting. Do not keep hitting it.
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
    // The business code failed and not a single account was given: HTTP is 200, but the other side explicitly said no (queue full, token
    // expired, and the like). Using msg as the reason is much more useful than "the response contained no key".
    if (!renewCodeOk(probe.code) && !probe.items.length) {
      r.errors++;
      r.notes.push(probe.msg || "号池返回业务码 " + probe.code);
      continue;
    }
    if (!probe.items.length) {
      // "Joined the carpool queue, no account available yet, restocking, and it will be dispatched to you automatically once it arrives" is a normal queue:
      // treat it as waiting for an account, and do not accumulate it toward the circuit breaker — otherwise a few rounds and it stops, and the dispatch is missed.
      if (probe.structured) {
        r.queued++;
        r.notes.push(probe.msg || "号池暂无可用号");
      } else {
        r.errors++;
        r.notes.push("响应里没有 ksk_ 开头的 key");
      }
      continue;
    }
    // Accept only accounts whose status is active: if the pool set a status and it is not active, do not even validate it.
    // One that gave no status at all (a plain-text pool, one ksk_ per line) cannot be judged, so let it through as before — if that kind of
    // pool were blocked too, not a single account would be accepted.
    const alive = probe.items.filter((it) => !it.status || it.status === "active");
    const skipped = probe.items.filter((it) => it.status && it.status !== "active");
    if (skipped.length) {
      // List the concrete statuses, so it is easy to check against the pool's docs whether the filter blocked the right ones.
      const kinds = [...new Set(skipped.map((it) => it.status))];
      r.notes.push(skipped.length + " 个号状态不是 active（" + kinds.join(" / ") + "），已跳过");
      log("自动续号: 跳过 " + skipped.length + " 个非 active 的号（" + kinds.join(" / ") + "）");
    }
    if (!alive.length) {
      r.queued++;
      continue;
    }
    r.found += alive.length;
    // A duplicate is skipped, and not one round trip is wasted. One already in the pending-import holding area counts as a duplicate too —
    // otherwise accounts that were never confirmed would be validated all over again every round.
    const known = renewKnownKeys();
    const fresh = alive.filter((it) => !known.has(it.key));
    r.dup += alive.length - fresh.length;
    if (!fresh.length) continue;
    const good = [];
    for (const it of fresh) {
      // The entry itself carries the region the pool wrote down. Use it directly when validating, and save a round of multi-region probes.
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
// The full flow of one round: run, then decide from the result when to come back next.
async function runRenewRound(p, force) {
  _renew.rounds++;
  const r = await pollRenewOnce(p, force);
  const now = Date.now();
  // If any account came in, this round had a yield. When "auto import" is off the accounts land in the pending-import holding area, and that still counts as a yield:
  // the work that had to be done is done, and only a confirmation click from the user is left.
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
  // The pool explicitly said it is queued or restocking (data is empty in the structured response): this is neither a failure nor a
  // duplicate. Keep waiting at the ordinary poll interval — dispatch is pushed by the other side, and that moment is what we are waiting for. Holding too long
  // only means waiting for nothing. Keep the consecutive-failure count at zero, so a queue does not feed the circuit breaker full.
  if (r.queued > 0 && r.errors === 0 && r.invalid === 0 && r.dup === 0) {
    _renew.fails = 0;
    _renew.nextAt = now + p.intervalSec * 1000;
    _renew.lastMessage = (r.notes[0] || "号池暂无可用号")
      + "，" + p.intervalSec + " 秒后再看一次";
    log("自动续号: 第 " + _renew.rounds + " 轮 " + _renew.lastMessage);
    return;
  }
  // Not a single one came in. All duplicates means the pool has not produced a new account: this is not a failure and should not open the circuit.
  if (r.dup > 0 && r.errors === 0 && r.invalid === 0) {
    _renew.fails = 0;
    if (p.alwaysPoll) {
      // In keep-stocking mode, duplicates are the normal case (the pool is just sitting on those few accounts) and should not be held down for ten minutes —
      // "waiting beside the pool for a new account" is what this mode is for, so keep looking at the ordinary interval.
      _renew.nextAt = now + p.intervalSec * 1000;
      _renew.lastMessage = "拉到的 " + r.dup + " 个 key 全是重复，"
        + p.intervalSec + " 秒后再看一次";
    } else {
      // In the mode that refills only when accounts are short, all duplicates means this trip was wasted, so hold longer before coming back.
      _renew.dupUntil = now + p.dupCooldownSec * 1000;
      _renew.nextAt = _renew.dupUntil;
      _renew.lastMessage = "拉到的 " + r.dup + " 个 key 全是重复，冷却 " + p.dupCooldownSec + " 秒";
    }
    log("自动续号: 第 " + _renew.rounds + " 轮 " + _renew.lastMessage);
    return;
  }
  // A real failure: back off, and accumulate the consecutive-failure count.
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
// Heartbeat: most of the time it only compares a few times and returns.
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
      // Enough have been refilled: reset every counter for this trigger, and start over the next time it drops.
      if (_renew.rounds || _renew.fails || _renew.nextAt || _renew.breakerUntil || _renew.dupUntil) {
        resetRenewCounters();
      }
      setRenewPhase("idle");
      return;
    }
    // Only "it is time to pull" continues. Every other case is waiting.
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
    // Immediately compute what should be shown from the new counters, and do not make the panel wait for the next heartbeat. This will never be
    // "due": success, duplicate, or failure, the code above has already pushed nextAt into the future.
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
// Called after the switch or a parameter changes: if it is on, make sure the heartbeat is running; if it is off, stop it.
function syncRenewLoop() {
  const p = getRenewPrefs();
  if (p.enabled && p.apiUrl) {
    startRenewLoop();
  } else {
    stopRenewLoop();
    setRenewPhase("off");
  }
}
// "Refill now" on the panel: clear the backoff, the circuit breaker, and the stopped state, ignore the threshold, and run one round immediately.
async function renewKickNow() {
  const p = getRenewPrefs();
  if (!p.apiUrl) throw new Error("请先填写号池 API");
  resetRenewCounters();
  _renewForce = true;
  _renew.lastMessage = "已手动触发";
  // While it is enabled, hang the heartbeat up along the way, so after a manual run it can keep refilling on its own.
  if (p.enabled) startRenewLoop();
  await renewTick();
  return renewStatusSnapshot();
}
// The panel's "test": after one pull, really validate every key (region plus the usage API), and import none of them.
// There used to be a testRenewLink here that only tested the link and did not validate accounts, but its conclusions (up or not, how many
// keys) are all already in this result. Two buttons on the panel only made people click once more, so they were merged.
async function testRenewAvailability(url) {
  const probe = await renewProbe(url);
  rememberRenewTest(probe.items);
  // The panel shows only one line of conclusion. Diagnostic detail goes to the run log — when you need the format, the status code, and the timing,
  // look there. The UI does not spend an extra line on that little information.
  log("号池测试: HTTP " + probe.status
    + (probe.code != null ? " · code " + probe.code : "")
    + " · " + probe.ms + "ms · 提取 " + probe.items.length + " 个 key"
    + (probe.msg ? " · " + probe.msg.slice(0, 120) : ""));
  const existing = renewKnownKeys();
  const rows = [];
  let usable = 0;
  // Iterate with an index: the panel lists accounts that are "healthy and usable" on their own and imports them one by one. A mask alone
  // cannot tell which one to accept — idx points into _renewLastTest.items, and import uses it to get the real key back.
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
    // If the pool already set a status, one that is not active is rejected directly, and a validation round trip is not wasted.
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
      // Quota is split into structured fields: the panel list is laid out the same way as "pending import" (plan · used/total),
      // and it does not have to be parsed back out of the string already assembled in note.
      title: (info && info.subscriptionTitle) || "",
      used: hasQuota ? Math.round(info.used || 0) : null,
      total: hasQuota ? Math.round(info.total) : null,
      seat,
      // When it did not pass, leave the reason here. A failed row still has to be able to say why.
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
// Accounts extracted by the most recent test, for the panel's "import these keys". The test itself never imports, but after looking at
// the result you often want to accept them directly — the panel side only has masks, and without this cache it cannot tell the host which ones to accept.
let _renewLastTest = { items: [], at: 0 };
function rememberRenewTest(items) {
  _renewLastTest = { items: (items || []).map((it) => ({ ...it })), at: Date.now() };
}
// Validate the acceptable accounts from the most recent test once more, then deliver them (into the key list if auto-import is on, into the holding area if it is off).
// Skip ones that already exist, and ones the pool marked as not active.
async function importRenewTestKeys(indices) {
  if (!_renewLastTest.items.length) {
    throw new Error("请先点「测试」拉一次号");
  }
  // Omitting indices means accept every one this round can accept (the panel's "import all"). Passing indexes means accept only
  // the row that was clicked in the list. The index corresponds to _renewLastTest.items; a mask cannot tell which one it is.
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
  // Indexes that can no longer be accepted are reported back to the panel too: a background poll this round may already have accepted some account,
  // and then it should disappear from the "usable accounts" list, instead of staying there to be clicked over and over and skipped every time.
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
  // Indexes that were actually delivered are reported back to the panel, the accepted rows are struck off the usable list, and the rest can still be clicked.
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
  // One that fails validation (invalid) deliberately does not report its index — it may only be network jitter this once,
  // and leaving it in the list means it can be clicked again. Only failing to accept it means it is really bad.
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
  const relayMode = isRelayMode();
  const on = isEnabled() && credentialsReady();
  const icon = relayMode ? "$(arrow-swap)" : "$(key)";
  statusBarItem.command = "kiroGateway.openPanel";
  statusBarItem.backgroundColor = undefined;
  // The status bar carries the mode, so when both modes coexist you can see at a glance which path is in use.
  statusBarItem.text = icon + " Kiro Gateway: " + (on ? modeLabel() : tr("未开启"));
  if (!on) {
    statusBarItem.tooltip = tr("Kiro Gateway 未启用（点击打开面板）"
      + (isEnabled() && !credentialsReady()
        ? relayMode ? " · 中转站地址或 Key 还没填" : " · 还没有可用的 API Key"
        : ""));
  } else if (relayMode) {
    const snap = relay.relaySnapshot();
    statusBarItem.tooltip = tr("中转站模式 · " + snap.baseUrl
      + (snap.models.count ? " · " + snap.models.count + " 个模型" : ""));
  } else {
    statusBarItem.tooltip = tr("APIKEY 直连 · region=" + getRegion()
      + (isRegionAuto() ? "（自动识别）" : "") + " · " + maskKey(getApiKey()));
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
// The mode used the last time the server was bound. A mode change must rebuild the listeners — both the port and the handler have changed.
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
    // live "in progress" indicator can't stay stuck.
    if (_statsInflight !== 0) { _statsInflight = 0; pushStatsNow(); }
  }
  const { bound, changed } = await syncEndpoints();
  // The background account sweep follows the switch, the mode, and the key count: stop it when the gateway is off or switched to relay, and do no
  // pointless probing.
  syncHealthSweep();
  // The inference-plane real liveness probe follows too. It is heavier than the sweep (each one consumes a generate request), so it is off by default,
  // and it runs only when the user explicitly turns on livenessCheckEnabled.
  syncLivenessScheduler();
  updateStatusBar();
  if (changed && !opts.silent) {
    const confirm = tr("重新加载窗口");
    const pick = await vscode.window.showInformationMessage(
      tr("Kiro Gateway 已接管内置对话。需要重新加载窗口后 Kiro 才会走新端点。"),
      confirm
    );
    if (pick === confirm) await vscode.commands.executeCommand("workbench.action.reloadWindow");
  }
  return { bound, changed };
}

// Switch the working mode. The two modes use different ports, and the endpoint redirect has to change with them, so a window reload is required after the switch before it
// really takes effect — Kiro reads the endpoint config only once, at startup.
async function switchModeTo(mode) {
  const next = mode === MODE_RELAY ? MODE_RELAY : MODE_OFFICIAL;
  if (next === getMode()) return getMode();
  const current = modeLabel();
  const target = tr(MODE_LABEL[next] || next);
  const confirm = tr("切换并重新加载");
  const pick = await vscode.window.showInformationMessage(
    uiLocale() === "en"
      ? "The route that is running (" + current + ") will stop. Reload the window before Kiro uses " + target + "."
      : "正在跑的线路（" + current + "）会停掉。重新加载窗口后 Kiro 才会走「" + target + "」。",
    { modal: true },
    confirm
  );
  if (pick !== confirm) return getMode();
  await setMode(next);
  // Drop the previous site's model list and usage cache.
  relay.invalidateRelayCaches();
  await applyState({ silent: true });
  panelProvider && panelProvider.pushState();
  await vscode.commands.executeCommand("workbench.action.reloadWindow");
  return next;
}

// ---------------------------------------------------------------------------
// Webview control panel
// ---------------------------------------------------------------------------
class ControlPanelProvider {
  constructor() { this.view = null; }
  resolveWebviewView(webviewView) {
    this.view = webviewView;
    this.distRoot = vscode.Uri.joinPath(extContext.extensionUri, "webview-ui", "dist");
    webviewView.webview.options = { enableScripts: true, localResourceRoots: [this.distRoot] };
    webviewView.webview.html = this.getHtml(webviewView.webview, this.distRoot);
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
    if (m && typeof m === "object") {
      if ((m.type === "toast" || m.type === "error") && typeof m.message === "string") {
        m = Object.assign({}, m, { message: tr(m.message) });
      } else if (m.type === "needReload" && typeof m.text === "string") {
        m = Object.assign({}, m, { text: tr(m.text) });
      }
    }
    try { this.view.webview.postMessage(m); } catch {}
  }
  pushState() {
    const rh = registryHealth();
    const keys = getApiKeys();
    const active = getActiveApiKey();
    this.post({
      type: "state",
      enabled: isEnabled(),
      // region is the region this account will actually use: in automatic mode, the one it detected for itself. It has a
      // value only after it has been probed; otherwise it falls through to the global config. The panel shows it per account, and the user no longer picks it by hand.
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
      // Two modes: mode decides which set of config the panel shows, and relay* is the whole state on the relay side.
      mode: getMode(),
      relayPorts: getRelayPorts(),
      relay: { ...relayPrefs(), ...relay.relaySnapshot() },
      registered: rh.registered,
      obsolete: rh.obsolete,
      hideApiKey: getHideApiKey(),
      autoRefresh: getAutoRefresh(),
      prompts: getPromptPrefs(),
      autoSwitch: getSwitchPrefs(),
      retry: getRetryPrefs(),
      // The generate-endpoint chain and the throttle-handling policy. The panel shows them read-only; changes go through settings.json or the command palette.
      endpoints: {
        list: GEN_ENDPOINTS.map((e) => ({ id: e.id, label: e.label, base: e.base(getRegion()) })),
        preferred: getPreferredEndpointId(),
        fallback: getEndpointFallback(),
        cooldownMs: getEndpointCooldownMs(),
        ...getEndpointRoundPrefs(),
        patience: getThrottlePatience(),
        serverErrorRetry: getServerErrorRetryPrefs(),
      },
      // The switches for the liveness probe and for automatic deletion of a dead account, plus the result of the last round.
      liveness: livenessStateSnapshot(),
      // Automatically approve the Agent command-confirmation dialog.
      autoAllow: autoAllowEnabled(),
      autoRenew: getRenewPrefs(),
      // Pending-import holding area: when "auto import" is off, a new account lands here first and waits for the user to confirm it on the panel.
      renewPending: renewPendingSnapshot(),
      // Whether the gateway is actually up and running. The switch being on does not mean the port is ours — with multiple windows it is often
      // the window next door doing the forwarding, and the top bar has to say so.
      gateway: gatewayRuntimeState(),
      gatewayPlanes: gatewayPlaneStates(),
      version: currentVersion(),
      repoUrl: REPO_URL,
    });
    this.pushStats();
  }
  // Live counters for the panel's "stats" card. Keys that are cooling down are sent along: the panel pulls every few seconds,
  // so the remaining cooldown can tick on its own.
  pushStats() {
    this.post({
      type: "stats",
      stats: statsSnapshot(),
      keyStats: keyStatsSnapshot(),
      cooldowns: cooldownSnapshot(),
      keyStatus: keyStatusSnapshot(),
      // The automatic-refill runtime state travels with the stats: the panel pulls every few seconds, and the countdown moves on its own.
      renew: renewStatusSnapshot(),
      // Remaining endpoint cooldown, the last liveness-round result, and capability gaps already discovered are all moving quantities. They are pushed
      // along with the stats, and the panel does not have to compute them itself.
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
  // post-add sync can fail even though the key is valid (a manual "sync now"
  // a moment later succeeds). Retrying a few times papers over that window so
  // the new key doesn't render a stale "sync failed".
  async syncAccounts(targets, opts = {}) {
    const { retries = 0, retryDelayMs = 1500, force = false } = opts;
    const keys = getApiKeys();
    let valid = targets.filter((idx) => idx >= 0 && idx < keys.length);
    // Invalid, suspended, and quota exhausted are terminal: do not probe them again, which saves a round trip, and the state will not
    // be overwritten by network jitter. Those rows keep showing the plan and credits from last time. Only when the user, on some row,
    // clicks "sync account info" by hand (force) is it queried again, as the exit for a manual review.
    if (!force) valid = valid.filter((idx) => !keyHealthFrozen(keys[idx]));
    // After filtering, none may be left. An accountDone still has to be sent then, or the panel's "syncing…"
    // spins forever.
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
      // This probe from the panel is also recorded in "last probe time", so the host's background sweep does not hit
      // the same account once more right after.
      noteKeyProbed(keys[idx]);
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const info = await fetchAccountInfo(keys[idx]);
          // The sync result is also used to judge account state (healthy / quota exhausted / invalid).
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
      // Hand over the whole error object: it carries the HTTP status code and the response body, which is the hard basis for the judgment.
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
      // --- Generate endpoints / liveness / auto-approve -------------------------------------
      // An endpoint-parameter change affects which host the next forward uses. After the change, log the chain that is in effect.
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
      // Endpoint cooldowns and capability gaps live only in memory. Clearing them is "forget those last few failures",
      // and the next request starts again from the preferred endpoint.
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
        // The config listener syncs once too. The explicit call here is so a click on the panel takes effect immediately, without waiting for the event.
        syncAutoAllow("面板");
        this.pushState();
        break;
      }
      // --- Two modes and the relay -----------------------------------------------
      case "setMode": {
        const next = msg.mode === MODE_RELAY ? MODE_RELAY : MODE_OFFICIAL;
        if (next === getMode()) break;
        await switchModeTo(next);
        break;
      }
      case "setLanguage": {
        const next = msg.value === "en" ? "en" : "zh";
        if (get("language", "auto") === next) break;
        await set("language", next);
        break;
      }
      case "setRelay": {
        // The panel submits the whole draft at once: address, Key, and the translation parameters are persisted together, so writing config item by item
        // does not let an intermediate state fire applyState several times.
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
        // In relay mode, changing the address or the Key changes the "are the credentials complete" conclusion, and the endpoints have to be taken over again.
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
          // On delete, throw away its state judgment too, so a terminal state is not left in what was persisted.
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
          // silent: switching keys does not touch the port or the enabled state. The local endpoint does not change, so there is no need to urge a reload.
          await applyState({ silent: true });
          // After the key changes, line the region up with the region this key belongs to: a cache hit costs nothing,
          // and only a miss probes once (the two candidates concurrently, usually under a second).
          await ensureRegionDetected({ silent: true });
          this.pushState();
          // The proxy reads the current key live on every forward, so a manual switch takes effect immediately, the same as an automatic switch —
          // the latter goes through the same path (adoptKey) and never prompts a reload. The "reload the window" dialog that used to pop here was a leftover,
          // an extra click for the user for nothing. A toast is enough.
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
        // value === "__auto" → leave it to auto-detection; any other value → fix the region the user picked.
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
        // "Detect again" on the panel: ignore the cache, probe again, and report the result back to the user.
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
        // silent: the top of the panel lights up its own reload hint (not a modal, and it does not interrupt the work),
        // and the native VS Code dialog is suppressed here, so the same thing is not prompted twice.
        await applyState({ silent: true });
        this.pushState();
        // The copy has to make clear that "the switch itself has already taken effect": the port, the status bar, and the panel change on the spot,
        // and the reload only makes Kiro's built-in chat switch endpoints. Otherwise a user who sees "reload required" thinks
        // the click just now did not take effect, and waits there for nothing.
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
          // A passed test is also one real probe, and it is used to refresh account state.
          noteAccountHealth(key, true, { used: r.used, total: r.total });
          this.post({ type: "testResult", index: i, ok: true, result: r });
        } catch (e) {
          const msg = e?.message || String(e);
          // Pass the error object, not a string: the status code is on the object, and the judgment depends on it.
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
          // If balancing was just turned off, the currently selected one may be left over from the last round of rotation. If it is still healthy,
          // keep using it (it is the one the user sees). Only if it is not healthy does maybeAdoptUsableKey switch to another.
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
      case "setRenew": {
        // The panel's "save config" submits the whole config at once, and the host clamps the ranges once more.
        await setRenewPrefs(msg.patch || {});
        // If a parameter changed, reset this trigger's cadence counters: the new interval and threshold should take effect immediately,
        // instead of waiting for the old backoff to finish.
        resetRenewCounters();
        syncRenewLoop();
        this.pushState();
        this.post({ type: "toast", message: "自动续号配置已保存" });
        break;
      }
      case "testRenewKeys": {
        // There is only one "test" button on the panel: pull the link once, then validate the accounts that came back, one by one.
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
        // The exit that reverses a stop or an open circuit: zero the counters, and the heartbeat immediately rejudges whether to refill.
        resetRenewCounters();
        _renew.lastMessage = "已重置续号计数";
        syncRenewLoop();
        this.pushStats();
        this.post({ type: "toast", message: "已重置续号计数" });
        break;
      case "importPending": {
        // An empty keys means import all of them.
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
        // Import from the usable-account list: omitting indices means import all, and passing an index means accept only that row.
        // Validate once more, then deliver according to the "auto import" setting.
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
            // The accepted indexes are sent back, the panel strikes the matching rows off the usable list, and the rest can still be clicked.
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
        // Clear the "invalid / quota exhausted / suspended" judgments along with it (including the persisted copy), and send every
        // key back to the not-checked state. The next request or sync produces a fresh conclusion. An account whose quota is exhausted
        // is reversed from here when a new cycle arrives and it should recover.
        resetKeyHealth();
        // Clear the region-detection cache along with it: the next sync or forward detects again, and a subscription that changed region can
        // be reversed from here too.
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
        // force is carried only by "sync account info" on a row's right-click menu: the user is pointing at some account and asking for a review,
        // and even a frozen terminal state is queried again. Timed refresh and "sync now" do not pass force, so a terminal state
        // is not probed over and over.
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
    const boot = "<script>globalThis.__KK_LANG=" + JSON.stringify(uiLocale()) + ";</script>";
    html = html.replace(/<head>/i, "<head>\n    " + boot + "\n    " + csp);
    return html;
  }
  refreshHtml() {
    if (!this.view || !this.distRoot) return;
    this.view.webview.html = this.getHtml(this.view.webview, this.distRoot);
  }
}

// ---------------------------------------------------------------------------
// Automatically approve the Agent command-confirmation dialog (Allow)
// ---------------------------------------------------------------------------
// Kiro's Trust v2 reads rules from ~/.kiro/settings/permissions.yaml. PolicySession
// watches that file and rebuilds automatically after a change, with no need to reload the window.
//
// The rule written in is the rule body of Kiro's built-in "allow-all" preset itself:
//   { capability: "all", effect: "allow" }
// The legal values of capability are the groups all / builtin / filesystem / sandbox_network plus a dozen or so
// individual items. all = builtin + mcp, so one rule covers shell, file read and write, MCP, and web, all of it.
//
// There are six built-in forced-ask items [editing this file has no effect], because Trust v2's decision order is
// deny > ask > allow, and these rules are injected unconditionally by kiro-agent (source: "kiro-scope"):
//   .git  .vscode  .kiro/agents/**  .kiro/hooks/**  **/*.code-workspace  **/mcp.json
// There is also one hard deny: the Agent tool is not allowed to write ~/.kiro/settings/ or .kiro/settings/.
// Note that this deny governs the Agent's fs_write tool. The extension writes with Node fs directly and does not go through
// the policy engine, so the write below is possible.
const AUTO_ALLOW_MARKER = "# kiro-gateway:auto-allow";
const AUTO_ALLOW_MARKER_LINE =
  AUTO_ALLOW_MARKER + "  由插件维护：关掉 autoAllow.enabled 会自动删除下面这条规则";
const AUTO_ALLOW_HEADER = [
  "# Kiro Trust v2 权限规则",
  "# 本文件由 Kiro Gateway 创建。删掉整个文件即可恢复 Kiro 默认的逐项确认。",
];

// A minimal YAML scanner. It only recognizes one structure, "list items one level under the top-level rules:", which is enough to tell
// whether there is an all/allow rule and to locate the section the extension itself wrote. A third-party YAML dependency is deliberately not pulled in:
// a vsix has to be self-contained, and adding a dependency means bundling node_modules.
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
    // Back at another top-level key, which means the rules section has ended
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

// Is there already an equivalent allow-all rule (no matter who wrote it).
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

// Reuse the indentation of the list items already in the file, so mixing two indent styles does not break the YAML.
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

// text -> { text, changed, reason }. A pure function; it does not touch the disk.
// reason is one of: created / inserted / already-allowed / no-rules-key
function addAutoAllowRule(text) {
  const raw = String(text == null ? "" : text);
  const meaningful = raw.split(/\r?\n/).some((l) => l.trim() !== "" && !/^\s*#/.test(l));
  if (!meaningful) return { text: freshPermissionsText(), changed: true, reason: "created" };
  if (hasAllowAllRule(raw)) return { text: raw, changed: false, reason: "already-allowed" };
  const at = findRulesKeyLine(raw);
  // There is no top-level rules: key, so do not guess the structure — better to do nothing than to corrupt the user's file.
  if (at < 0) return { text: raw, changed: false, reason: "no-rules-key" };
  const lines = raw.split(/\r?\n/);
  lines.splice(at + 1, 0, ...buildAutoAllowLines(ruleItemIndent(raw)));
  return { text: lines.join("\n"), changed: true, reason: "inserted" };
}

// Delete only the section the extension itself wrote (located by the marker line). Leave rules of the same kind that the user wrote by hand untouched.
// reason is one of: removed / absent
function removeAutoAllowRule(text) {
  const raw = String(text == null ? "" : text);
  const lines = raw.split(/\r?\n/);
  const at = lines.findIndex((l) => l.includes(AUTO_ALLOW_MARKER));
  if (at < 0) return { text: raw, changed: false, reason: "absent" };
  let end = at; // including the marker line
  let i = at + 1;
  while (i < lines.length && lines[i].trim() === "") i++;
  const dash = i < lines.length ? lines[i].match(/^(\s*)-\s*(.*)$/) : null;
  if (dash) {
    const dashIndent = dash[1].length;
    end = i;
    // A following line that is indented deeper belongs to the same list item
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

// Atomic write plus a first-time backup, the same approach as writeEndpointToSettingsFile.
// Encoding is fixed as UTF-8 with no BOM: Node's "utf8" writes no BOM, so a Chinese comment is not rejected by the parser.
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

// Idempotent: if it is already allowed, write nothing. When the switch is turned off, take back only the section the extension itself added.
function syncAutoAllow(why) {
  const on = autoAllowEnabled();
  const file = permissionsYamlPath();
  const tag = "auto-allow" + (why ? " (" + why + ")" : "");
  try {
    const exists = fsMod.existsSync(file);
    // Trust v2 recognizes both permissions.yaml and permissions.json, and YAML takes priority.
    // When only json exists, creating a yaml would make the user's existing json rules be ignored as a whole. Do not touch it in that case.
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
  // Restore the judgments for invalid / quota exhausted / suspended: these accounts should not be probed again after a window reload either.
  loadKeyHealth();
  // New accounts that were pulled last time but not yet confirmed for import keep waiting for confirmation after a window reload.
  loadRenewPending();
  // Keep only today's data: on load, roll forward by date once, then attach the timer that clears automatically at midnight.
  ensureToday();
  scheduleDailyReset();
  log("activate · 模式=" + modeLabel());
  logKiroHostInfo();
  selfHeal();
  // Hand config reads, logs, and stats hooks to the relay translation layer. Stats go through the same set of counters, so on the panel the
  // request count and usage are the same numbers in both modes.
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
  // Backfill an add-time for keys that already exist: keys added before the upgrade to this version, and keys the user stuffed in by editing the config
  // directly, all receive their first timestamp here.
  try { await syncKeyAddedAt(); } catch (e) { log("syncKeyAddedAt failed: " + (e?.message || e)); }

  panelProvider = new ControlPanelProvider();
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("kiroGateway.controlPanel", panelProvider)
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("kiroGateway.openPanel", async () => {
      await vscode.commands.executeCommand("workbench.view.extension.kiroGateway");
    }),
    // Clicking "pending reload to take effect" on the status bar comes through here, and it can also be triggered by hand from the command palette.
    vscode.commands.registerCommand("kiroGateway.reloadWindow", async () => {
      await vscode.commands.executeCommand("workbench.action.reloadWindow");
    }),
    vscode.commands.registerCommand("kiroGateway.toggle", async () => {
      await set("enabled", !isEnabled());
      await applyState();
      panelProvider && panelProvider.pushState();
    }),
    // Switch mode from the command palette. The endpoints have to change ports, so after the switch, prompt a window reload as usual.
    vscode.commands.registerCommand("kiroGateway.importJsonFiles", async () => {
      const result = await importJsonCredentialFiles();
      if (result.cancelled) return;
      if (result.message && (!result.ingested || !result.ingested.added.length)) {
        vscode.window.showWarningMessage("Kiro Gateway: " + tr(result.message));
        return;
      }
      await applyIngestedCredentials(result.ingested, result.failed);
    }),
    vscode.commands.registerCommand("kiroGateway.switchMode", async () => {
      const pick = await vscode.window.showQuickPick(
        [
          { label: tr(MODE_LABEL.official), description: tr("官方 ksk_ 密钥直连 Kiro 服务"), mode: MODE_OFFICIAL },
          { label: tr(MODE_LABEL.relay), description: tr("转发到 Anthropic 格式的第三方中转站"), mode: MODE_RELAY },
        ],
        { title: tr("选择工作模式"), placeHolder: tr("当前：") + modeLabel() }
      );
      if (!pick || pick.mode === getMode()) return;
      await switchModeTo(pick.mode);
    }),
    // Run one real liveness round right away. A manual trigger ignores the "minimum interval per account" gate — the user pressed the button,
    // and they know it costs one generate request.
    vscode.commands.registerCommand("kiroGateway.livenessCheckNow", async () => {
      if (!getApiKeys().length) {
        vscode.window.showWarningMessage(tr("Kiro Gateway: 还没有配置密钥，无法探活。"));
        return;
      }
      vscode.window.showInformationMessage(tr("Kiro Gateway: 开始探活（每把密钥消耗一次生成请求）…"));
      const r = await runLivenessScan({ manual: true });
      if (r && r.skipped) {
        vscode.window.showInformationMessage(tr("Kiro Gateway: 上一轮探活还没跑完，稍后再试。"));
        return;
      }
      const c = (r && r.counts) || {};
      vscode.window.showInformationMessage(tr(
        "Kiro Gateway 探活完成：可用 " + (c.ok || 0)
        + " · 禁用 " + (c.suspended || 0)
        + " · 溢出 " + (c.overage_exceeded || 0)
        + " · 额度用尽 " + (c.quota || 0)
        + " · 失效 " + (c.invalid || 0)
        + ((r && r.deleted) ? " · 已删 " + r.deleted + " 把" : "")
      ));
    }),
    // Toggle automatic approval of Agent commands from the command palette, instead of digging through settings.
    vscode.commands.registerCommand("kiroGateway.toggleAutoAllow", async () => {
      const next = !autoAllowEnabled();
      await set("autoAllow.enabled", next);
      // The config-change listener syncs permissions.yaml along the way. This only shows the prompt.
      vscode.window.showInformationMessage(
        uiLocale() === "en"
          ? "Kiro Gateway: auto-allow Agent commands is " + (next ? "on" : "off")
            + (next ? " (.git / .vscode / .kiro/agents / .kiro/hooks / *.code-workspace / mcp.json are still asked one by one)" : "")
          : "Kiro Gateway: Agent 命令自动放行已" + (next ? "开启" : "关闭")
            + (next ? "（.git / .vscode / .kiro/agents / .kiro/hooks / *.code-workspace / mcp.json 仍会逐项询问）" : "")
      );
    }),
    vscode.commands.registerCommand("kiroGateway.test", async () => {
      try {
        const r = await testKey();
        vscode.window.showInformationMessage(tr("Kiro Key 有效 · " + (r.subscription || "") + " · " + r.modelCount + " 个模型"));
      } catch (e) {
        vscode.window.showErrorMessage(tr("Kiro Key 测试失败: " + (e?.message || e)));
      }
    })
  );

  // React to relevant config changes.
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      const hit = (k) => e.affectsConfiguration("kiroGateway." + k);
      if (hit("language")) {
        updateStatusBar();
        if (panelProvider) panelProvider.refreshHtml();
      }
      // Automatic permission approval: the moment the switch changes, sync permissions.yaml immediately. Kiro's PolicySession
      // watches this file, and the change takes effect with no window reload.
      if (hit("autoAllow.enabled")) syncAutoAllow("配置变更");
      // When the liveness switch or the interval changes, hang the timer again.
      if (["livenessCheckEnabled", "livenessCheckIntervalSec"].some(hit)) syncLivenessScheduler();
      // When endpoint-related config changes, log the chain currently in effect, so there is no guessing.
      if (["preferredEndpoint", "endpointFallback", "endpointCooldownMs",
        "endpointRounds", "endpointRoundDelayMs"].some(hit)) logEndpointChain();
      // Once the region changes, the record of which endpoint supports which operation no longer applies (capability is keyed by endpoint + region +
      // operation), so clear it and probe again.
      if (hit("region")) resetEndpointUnsupported();
      // Config items that affect proxy binding or endpoint redirect all have to run applyState again after a change.
      const needsApply = ["enabled", "apiKeys", "activeApiKey", "region", "ports",
        "mode", "relayBaseUrl", "relayApiKey", "relayPorts"].some(hit);
      // Config items that only affect translation behavior do not need the server rebound. Refreshing the panel is enough.
      const relayTweaked = ["relayMaxTokens", "relayThinking", "relayThinkingBudget",
        "relayEffortMode", "relayEffortBudgets", "relayDefaultModel", "relayModelMapping",
        "relayInterceptIntentClassifier", "relayPromptCaching"].some(hit);
      if (!needsApply && !relayTweaked) return;
      // A key added by editing the config directly needs an add-time too.
      if (hit("apiKeys")) {
        try { await syncKeyAddedAt(); } catch {}
      }
      // Once the site or the Key changes, the previous site's model list and usage figures must not be reused.
      if (hit("relayBaseUrl") || hit("relayApiKey")) relay.invalidateRelayCaches();
      if (needsApply) await applyState({ silent: true });
      panelProvider && panelProvider.pushState();
    })
  );

  await applyState({ silent: true });
  updateStatusBar();
  // Automatic permission approval: sync ~/.kiro/settings/permissions.yaml once, according to the current switch.
  syncAutoAllow("启动");
  // Log the generate-endpoint chain that is in effect, so the preferred endpoint and the fallback parameters are easy to confirm.
  logEndpointChain();
  // Automatic refill: when it is on, start the heartbeat. When usable keys fall below the threshold, it goes to the pool and refills on its own.
  syncRenewLoop();
  // At startup, detect the region once in the background (automatic mode, and only when a key already exists). Do not await it: detection sends two network
  // requests and must not slow plugin activation. When the result comes back it writes the config and refreshes the panel and the status bar on its own.
  ensureRegionDetected({ silent: true }).catch(() => {});
  // Delay the first account sweep a little: during activation, region detection and endpoint checks are both in flight, so do not pile them together.
  // After that, leave it to the HEALTH_SWEEP_MS heartbeat.
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
  // These two throttled timers used to be left outside. On a window reload they were still pending, and by the time the callback woke the panel was long gone
  // (pushStats checks that panelProvider is non-null, so it does not throw), but _activeSyncTimer would write the config once more
  // after deactivation, a side effect that should not happen.
  if (_statsPushTimer) { clearTimeout(_statsPushTimer); _statsPushTimer = null; }
  if (_activeSyncTimer) { clearTimeout(_activeSyncTimer); _activeSyncTimer = null; _activeSyncWant = ""; }
}

module.exports = { activate, deactivate };
