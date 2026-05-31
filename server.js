const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || "0.0.0.0";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const TENCENT_DOCS_WEBHOOK_URL = process.env.TENCENT_DOCS_WEBHOOK_URL || "";
const FEISHU_APP_ID = process.env.FEISHU_APP_ID || "";
const FEISHU_APP_SECRET = process.env.FEISHU_APP_SECRET || "";
const FEISHU_BITABLE_APP_TOKEN = process.env.FEISHU_BITABLE_APP_TOKEN || "";
const FEISHU_TABLE_ID = process.env.FEISHU_TABLE_ID || "";
const ROOT = __dirname;
let DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
let DATA_FILE = path.join(DATA_DIR, "signups.json");
const sessions = new Map();
const attempts = new Map();
let feishuTokenCache = null;

const TEAM = "\u961f\u4f0d\u62a5\u540d";
const SOLO = "\u4e2a\u4eba\u62a5\u540d";

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mp3": "audio/mpeg",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon"
};

function securityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  };
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...securityHeaders(), ...headers });
  res.end(body);
}

function sendJson(res, status, payload) {
  send(res, status, JSON.stringify(payload), {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
}

async function ensureStore() {
  try {
    await fsp.mkdir(DATA_DIR, { recursive: true });
  } catch (error) {
    if (!["EACCES", "EROFS", "EPERM"].includes(error.code)) throw error;
    DATA_DIR = path.join(os.tmpdir(), "msc-signup-data");
    DATA_FILE = path.join(DATA_DIR, "signups.json");
    await fsp.mkdir(DATA_DIR, { recursive: true });
  }
  try {
    await fsp.access(DATA_FILE);
  } catch {
    await fsp.writeFile(DATA_FILE, "[]\n", "utf8");
  }
}

async function readSignups() {
  await ensureStore();
  const raw = await fsp.readFile(DATA_FILE, "utf8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeSignups(items) {
  await ensureStore();
  await fsp.writeFile(DATA_FILE, `${JSON.stringify(items, null, 2)}\n`, "utf8");
}

async function saveFeishuRecordId(signupId, recordId) {
  if (!signupId || !recordId) return;
  const items = await readSignups();
  const item = items.find((entry) => entry.id === signupId);
  if (!item) return;
  item.feishuRecordId = recordId;
  await writeSignups(items);
}

function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie || "";
  header.split(";").forEach((part) => {
    const [key, ...rest] = part.trim().split("=");
    if (key) cookies[key] = decodeURIComponent(rest.join("="));
  });
  return cookies;
}

function isAuthed(req) {
  const sid = parseCookies(req).msc_admin_session;
  return Boolean(sid && sessions.has(sid));
}

function cleanSessionCookie() {
  return "msc_admin_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
}

function sessionCookie(req, token) {
  const secure = req.headers["x-forwarded-proto"] === "https" || req.socket.encrypted;
  return `msc_admin_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secure ? "; Secure" : ""}`;
}

function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();
}

function checkRateLimit(req, key, maxHits, windowMs) {
  const now = Date.now();
  const id = `${key}:${clientIp(req)}`;
  const hits = (attempts.get(id) || []).filter((time) => now - time < windowMs);
  hits.push(now);
  attempts.set(id, hits);
  return hits.length <= maxHits;
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024 * 1024) throw new Error("\u8bf7\u6c42\u5185\u5bb9\u8fc7\u5927");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

function cleanText(value, maxLength = 300) {
  return String(value || "").trim().slice(0, maxLength);
}

function normalizeSignup(input) {
  const signupType = cleanText(input.signupType, 20);
  const teamName = cleanText(input.teamName, 80);
  const captainName = cleanText(input.captainName, 80);
  const contact = cleanText(input.contact, 120);
  const members = Array.isArray(input.members)
    ? input.members.slice(0, 6).map((member) => ({
        gameId: cleanText(member.gameId, 80),
        role: cleanText(member.role, 50)
      })).filter((member) => member.gameId || member.role)
    : [];

  if (![TEAM, SOLO].includes(signupType)) throw new Error("\u8bf7\u9009\u62e9\u62a5\u540d\u7c7b\u578b");
  if (signupType === TEAM && !teamName) throw new Error("\u961f\u4f0d\u62a5\u540d\u9700\u8981\u586b\u5199\u961f\u4f0d\u540d");
  if (!captainName) throw new Error("\u8bf7\u586b\u5199\u8054\u7cfb\u4eba\u59d3\u540d");
  if (!contact) throw new Error("\u8bf7\u586b\u5199\u8054\u7cfb\u65b9\u5f0f");

  const now = new Date();
  return {
    id: crypto.randomUUID(),
    createdAt: now.toISOString(),
    createdAtText: new Intl.DateTimeFormat("zh-CN", {
      dateStyle: "medium",
      timeStyle: "short",
      hour12: false,
      timeZone: "Asia/Shanghai"
    }).format(now),
    signupType,
    teamName,
    captainName,
    contact,
    mainPosition: cleanText(input.mainPosition, 50),
    canBeAssigned: cleanText(input.canBeAssigned, 10),
    members,
    substitute: cleanText(input.substitute, 160),
    notes: cleanText(input.notes, 800)
  };
}

function csvValue(value) {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

function toCsv(items) {
  const header = [
    "\u62a5\u540d\u7f16\u53f7",
    "\u63d0\u4ea4\u65f6\u95f4",
    "\u62a5\u540d\u7c7b\u578b",
    "\u961f\u4f0d\u540d",
    "\u8054\u7cfb\u4eba",
    "\u8054\u7cfb\u65b9\u5f0f",
    "\u5e38\u7528\u4f4d\u7f6e",
    "\u63a5\u53d7\u62fc\u961f",
    "\u961f\u5458\u4fe1\u606f",
    "\u66ff\u8865\u4fe1\u606f",
    "\u5907\u6ce8"
  ];
  const rows = items.map((item) => [
    item.id,
    item.createdAtText,
    item.signupType,
    item.teamName,
    item.captainName,
    item.contact,
    item.mainPosition,
    item.canBeAssigned,
    (item.members || []).map((member, index) => `${index + 1}. ${member.gameId || "-"}\uff08${member.role || "\u672a\u586b"}\uff09`).join("\uff1b"),
    item.substitute,
    item.notes
  ]);
  return "\uFEFF" + [header, ...rows].map((row) => row.map(csvValue).join(",")).join("\n");
}

function flattenSignup(signup) {
  return {
    id: signup.id,
    createdAt: signup.createdAt,
    createdAtText: signup.createdAtText,
    signupType: signup.signupType,
    teamName: signup.teamName,
    captainName: signup.captainName,
    contact: signup.contact,
    mainPosition: signup.mainPosition,
    canBeAssigned: signup.canBeAssigned,
    membersText: (signup.members || []).map((member, index) => `${index + 1}. ${member.gameId || "-"} (${member.role || "N/A"})`).join("; "),
    substitute: signup.substitute,
    notes: signup.notes
  };
}

async function syncSignup(signup) {
  const result = {};
  if (TENCENT_DOCS_WEBHOOK_URL) {
    result.webhook = await syncWebhook(signup);
  }
  if (feishuEnabled()) {
    result.feishu = await syncFeishu(signup);
  }
  return Object.keys(result).length ? result : { enabled: false };
}

async function syncWebhook(signup) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(TENCENT_DOCS_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(flattenSignup(signup)),
      signal: controller.signal
    });
    const text = await response.text();
    if (!response.ok) {
      return { enabled: true, ok: false, status: response.status, body: text.slice(0, 300) };
    }
    return { enabled: true, ok: true, status: response.status };
  } catch (error) {
    return { enabled: true, ok: false, error: error.message };
  } finally {
    clearTimeout(timer);
  }
}

function feishuEnabled() {
  return Boolean(FEISHU_APP_ID && FEISHU_APP_SECRET && FEISHU_BITABLE_APP_TOKEN && FEISHU_TABLE_ID);
}

async function getFeishuTenantAccessToken() {
  const now = Date.now();
  if (feishuTokenCache && feishuTokenCache.expiresAt > now + 60 * 1000) {
    return feishuTokenCache.token;
  }

  const response = await fetch("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      app_id: FEISHU_APP_ID,
      app_secret: FEISHU_APP_SECRET
    })
  });
  const data = await response.json();
  if (!response.ok || data.code !== 0) {
    throw new Error(`Feishu token error: ${data.msg || response.status}`);
  }

  feishuTokenCache = {
    token: data.tenant_access_token,
    expiresAt: now + Math.max(60, Number(data.expire || 7200) - 60) * 1000
  };
  return feishuTokenCache.token;
}

function feishuFields(signup) {
  const flat = flattenSignup(signup);
  return {
    "\u62a5\u540d\u7f16\u53f7": flat.id,
    "\u63d0\u4ea4\u65f6\u95f4": flat.createdAtText,
    "\u62a5\u540d\u7c7b\u578b": flat.signupType,
    "\u961f\u4f0d\u540d": flat.teamName,
    "\u8054\u7cfb\u4eba": flat.captainName,
    "\u8054\u7cfb\u65b9\u5f0f": flat.contact,
    "\u5e38\u7528\u4f4d\u7f6e": flat.mainPosition,
    "\u63a5\u53d7\u62fc\u961f": flat.canBeAssigned,
    "\u961f\u5458\u4fe1\u606f": flat.membersText,
    "\u66ff\u8865\u4fe1\u606f": flat.substitute,
    "\u5907\u6ce8": flat.notes
  };
}

async function syncFeishu(signup) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const token = await getFeishuTenantAccessToken();
    const appToken = encodeURIComponent(FEISHU_BITABLE_APP_TOKEN);
    const tableId = encodeURIComponent(FEISHU_TABLE_ID);
    const response = await fetch(`https://open.feishu.cn/open-apis/bitable/v1/apps/${appToken}/tables/${tableId}/records`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ fields: feishuFields(signup) }),
      signal: controller.signal
    });
    const data = await response.json();
    if (!response.ok || data.code !== 0) {
      return { enabled: true, ok: false, status: response.status, code: data.code, message: data.msg };
    }
    return { enabled: true, ok: true, recordId: data.data && data.data.record && data.data.record.record_id };
  } catch (error) {
    return { enabled: true, ok: false, error: error.message };
  } finally {
    clearTimeout(timer);
  }
}

async function deleteFeishuRecord(recordId) {
  if (!feishuEnabled()) {
    return { enabled: false, skipped: true };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const token = await getFeishuTenantAccessToken();
    const appToken = encodeURIComponent(FEISHU_BITABLE_APP_TOKEN);
    const tableId = encodeURIComponent(FEISHU_TABLE_ID);
    const encodedRecordId = encodeURIComponent(recordId);
    const response = await fetch(`https://open.feishu.cn/open-apis/bitable/v1/apps/${appToken}/tables/${tableId}/records/${encodedRecordId}`, {
      method: "DELETE",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      signal: controller.signal
    });
    const data = await response.json();
    if (!response.ok || data.code !== 0) {
      return { enabled: true, ok: false, status: response.status, code: data.code, message: data.msg };
    }
    return { enabled: true, ok: true, recordId };
  } catch (error) {
    return { enabled: true, ok: false, error: error.message };
  } finally {
    clearTimeout(timer);
  }
}

async function serveStatic(req, res, pathname) {
  const requested = pathname === "/" ? "/index.html" : pathname;
  const filePath = path.normalize(path.join(ROOT, decodeURIComponent(requested)));
  const relative = path.relative(ROOT, filePath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    send(res, 403, "Forbidden", { "Content-Type": "text/plain; charset=utf-8" });
    return;
  }
  try {
    const stat = await fsp.stat(filePath);
    if (!stat.isFile()) throw new Error("Not file");
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      ...securityHeaders(),
      "Content-Type": mimeTypes[ext] || "application/octet-stream"
    });
    fs.createReadStream(filePath).pipe(res);
  } catch {
    send(res, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" });
  }
}

async function handleApi(req, res, pathname) {
  try {
    if (req.method === "POST" && pathname === "/api/signup") {
      if (!checkRateLimit(req, "signup", 20, 60 * 60 * 1000)) {
        sendJson(res, 429, { ok: false, message: "\u63d0\u4ea4\u8fc7\u4e8e\u9891\u7e41\uff0c\u8bf7\u7a0d\u540e\u518d\u8bd5" });
        return;
      }
      const body = await readBody(req);
      const signup = normalizeSignup(body);
      const items = await readSignups();
      items.unshift(signup);
      await writeSignups(items);
      const sync = await syncSignup(signup);
      if (sync.feishu && sync.feishu.ok && sync.feishu.recordId) {
        await saveFeishuRecordId(signup.id, sync.feishu.recordId);
      }
      sendJson(res, 201, { ok: true, id: signup.id, sync });
      return;
    }

    if (req.method === "POST" && pathname === "/api/admin/login") {
      if (!ADMIN_PASSWORD) {
        sendJson(res, 500, { ok: false, message: "\u540e\u53f0\u5bc6\u7801\u672a\u914d\u7f6e\uff0c\u8bf7\u8054\u7cfb\u7ec4\u7ec7\u8005" });
        return;
      }
      if (!checkRateLimit(req, "admin-login", 8, 15 * 60 * 1000)) {
        sendJson(res, 429, { ok: false, message: "\u767b\u5f55\u5c1d\u8bd5\u8fc7\u4e8e\u9891\u7e41\uff0c\u8bf7\u7a0d\u540e\u518d\u8bd5" });
        return;
      }
      const body = await readBody(req);
      if (String(body.password || "") !== ADMIN_PASSWORD) {
        sendJson(res, 401, { ok: false, message: "\u5bc6\u7801\u4e0d\u6b63\u786e" });
        return;
      }
      const token = crypto.randomBytes(24).toString("hex");
      sessions.set(token, { createdAt: Date.now() });
      send(res, 200, JSON.stringify({ ok: true }), {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": sessionCookie(req, token),
        "Cache-Control": "no-store"
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/admin/logout") {
      const sid = parseCookies(req).msc_admin_session;
      if (sid) sessions.delete(sid);
      send(res, 200, JSON.stringify({ ok: true }), {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": cleanSessionCookie(),
        "Cache-Control": "no-store"
      });
      return;
    }

    if (pathname === "/api/admin/signups") {
      if (!isAuthed(req)) {
        sendJson(res, 401, { ok: false, message: "\u8bf7\u5148\u767b\u5f55\u540e\u53f0" });
        return;
      }
      const items = await readSignups();
      sendJson(res, 200, { ok: true, items });
      return;
    }

    if (req.method === "POST" && pathname === "/api/admin/delete") {
      if (!isAuthed(req)) {
        sendJson(res, 401, { ok: false, message: "\u8bf7\u5148\u767b\u5f55\u540e\u53f0" });
        return;
      }
      const body = await readBody(req);
      const id = cleanText(body.id, 120);
      if (!id) {
        sendJson(res, 400, { ok: false, message: "\u8bf7\u9009\u62e9\u8981\u5220\u9664\u7684\u62a5\u540d\u8bb0\u5f55" });
        return;
      }
      const items = await readSignups();
      const item = items.find((entry) => entry.id === id);
      const nextItems = items.filter((item) => item.id !== id);
      if (nextItems.length === items.length) {
        sendJson(res, 404, { ok: false, message: "\u6ca1\u6709\u627e\u5230\u8fd9\u6761\u62a5\u540d\u8bb0\u5f55" });
        return;
      }
      const sync = {};
      if (item && item.feishuRecordId) {
        sync.feishu = await deleteFeishuRecord(item.feishuRecordId);
        if (!sync.feishu.ok) {
          sendJson(res, 502, { ok: false, message: "\u98de\u4e66\u8868\u683c\u540c\u6b65\u5220\u9664\u5931\u8d25\uff0c\u540e\u53f0\u8bb0\u5f55\u5df2\u4fdd\u7559", sync });
          return;
        }
      }
      await writeSignups(nextItems);
      sendJson(res, 200, { ok: true, deletedId: id, count: nextItems.length, sync });
      return;
    }

    if (pathname === "/api/admin/download.csv") {
      if (!isAuthed(req)) {
        send(res, 401, "\u8bf7\u5148\u767b\u5f55\u540e\u53f0", { "Content-Type": "text/plain; charset=utf-8" });
        return;
      }
      const items = await readSignups();
      const filename = `msc-signups-${new Date().toISOString().slice(0, 10)}.csv`;
      send(res, 200, toCsv(items), {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Cache-Control": "no-store"
      });
      return;
    }

    sendJson(res, 404, { ok: false, message: "\u63a5\u53e3\u4e0d\u5b58\u5728" });
  } catch (error) {
    sendJson(res, 400, { ok: false, message: error.message || "\u8bf7\u6c42\u5931\u8d25" });
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);
  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url.pathname);
    return;
  }
  await serveStatic(req, res, url.pathname);
});

function localNetworkUrls() {
  const urls = [`http://127.0.0.1:${PORT}`];
  const interfaces = os.networkInterfaces();
  Object.values(interfaces).flat().forEach((item) => {
    if (!item || item.family !== "IPv4" || item.internal) return;
    urls.push(`http://${item.address}:${PORT}`);
  });
  return [...new Set(urls)];
}

ensureStore().then(() => {
  server.listen(PORT, HOST, () => {
    console.log("MSC signup site is running.");
    console.log("Open one of these URLs:");
    localNetworkUrls().forEach((url) => console.log(`  ${url}`));
    console.log(ADMIN_PASSWORD ? "Admin password is configured." : "Admin password is NOT configured.");
  });
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
