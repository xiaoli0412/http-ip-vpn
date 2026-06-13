const http = require('http');
const net = require('net');
const url = require('url');
const fs = require('fs');
const path = require('path');

const express = require('express');

const PROXY_PORT = parseInt(process.env.PROXY_PORT, 10) || 8080;
const ADMIN_PORT = parseInt(process.env.ADMIN_PORT, 10) || 9090;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ============ CONFIG ============
const configFile = path.join(DATA_DIR, 'config.json');
let appConfig = {
  user: process.env.ADMIN_USER || 'admin',
  pass: process.env.ADMIN_PASS || 'admin',
  autoClear: { enabled: true, maxAge: 86400000, maxEntries: 10000 }
};

function loadConfig() {
  try {
    if (fs.existsSync(configFile)) {
      const d = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
      if (d.user) appConfig.user = d.user;
      if (d.pass) appConfig.pass = d.pass;
      if (d.autoClear) Object.assign(appConfig.autoClear, d.autoClear);
    }
  } catch (e) { console.error('config load:', e.message); }
}
function saveConfig() {
  fs.writeFileSync(configFile, JSON.stringify(appConfig, null, 2));
}
loadConfig();

// ============ WHITELIST ============
const whitelistFile = path.join(DATA_DIR, 'whitelist.json');
let whitelist = new Set();

function loadWhitelist() {
  try {
    if (fs.existsSync(whitelistFile)) whitelist = new Set(JSON.parse(fs.readFileSync(whitelistFile, 'utf-8')));
  } catch (e) { console.error('whitelist load:', e.message); }
}
function saveWhitelist() { fs.writeFileSync(whitelistFile, JSON.stringify([...whitelist], null, 2)); }
loadWhitelist();

// ============ STATS ============
const statsFile = path.join(DATA_DIR, 'stats.json');
let stats = { totalRequests: 0, totalBytesSent: 0, totalBytesReceived: 0, byIp: {}, byHost: {}, history: [] };
let statsDirty = false;
let lastFlush = Date.now();

function loadStats() {
  try {
    if (fs.existsSync(statsFile)) stats = JSON.parse(fs.readFileSync(statsFile, 'utf-8'));
  } catch (e) { console.error('stats load:', e.message); }
}
function flushStats() {
  if (!statsDirty) return;
  try { fs.writeFileSync(statsFile, JSON.stringify(stats, null, 2)); statsDirty = false; } catch (e) {}
}
function trackRequest(ip, host, method, bS, bR, status, dur) {
  stats.totalRequests++; stats.totalBytesSent += bS; stats.totalBytesReceived += bR;
  (stats.byIp[ip] = stats.byIp[ip] || { requests: 0, bytesSent: 0, bytesReceived: 0 }).requests++;
  stats.byIp[ip].bytesSent += bS; stats.byIp[ip].bytesReceived += bR;
  (stats.byHost[host] = stats.byHost[host] || { requests: 0, bytesSent: 0, bytesReceived: 0 }).requests++;
  stats.byHost[host].bytesSent += bS; stats.byHost[host].bytesReceived += bR;
  stats.history.push({ ts: Date.now(), ip, host, method, bytesSent: bS, bytesReceived: bR, status, duration: dur });
  if (stats.history.length > 20000) stats.history = stats.history.slice(-10000);
  statsDirty = true;
  if (Date.now() - lastFlush > 30000) { flushStats(); lastFlush = Date.now(); }
}
loadStats();
setInterval(flushStats, 30000);

// ============ LOGS ============
const logsFile = path.join(DATA_DIR, 'logs.json');
let logs = [];

function loadLogs() {
  try { if (fs.existsSync(logsFile)) logs = JSON.parse(fs.readFileSync(logsFile, 'utf-8')); } catch (e) {}
}
function flushLogs() {
  try { fs.writeFileSync(logsFile, JSON.stringify(logs.slice(-5000), null, 2)); } catch (e) {}
}
function addLog(level, type, msg, detail) {
  logs.push({ ts: Date.now(), level, type, msg, detail: detail || null });
  if (logs.length > appConfig.autoClear.maxEntries) logs = logs.slice(-Math.floor(appConfig.autoClear.maxEntries / 2));
}
function autoClearLogs() {
  if (!appConfig.autoClear.enabled) return;
  const cutoff = Date.now() - appConfig.autoClear.maxAge;
  const before = logs.length;
  logs = logs.filter(l => l.ts > cutoff);
  if (logs.length < before) flushLogs();
}
loadLogs();
setInterval(autoClearLogs, 3600000);

// ============ UNAUTHORIZED ============
const unauthFile = path.join(DATA_DIR, 'unauthorized.json');
let unauthorizedLogs = [];

function loadUnauth() {
  try { if (fs.existsSync(unauthFile)) unauthorizedLogs = JSON.parse(fs.readFileSync(unauthFile, 'utf-8')); } catch (e) {}
}
function flushUnauth() {
  try { fs.writeFileSync(unauthFile, JSON.stringify(unauthorizedLogs.slice(-5000), null, 2)); } catch (e) {}
}
function trackUnauthorized(ip, target, method) {
  unauthorizedLogs.push({ ts: Date.now(), ip, target, method });
  if (unauthorizedLogs.length > 10000) unauthorizedLogs = unauthorizedLogs.slice(-5000);
}
loadUnauth();

// ============ UTILITIES ============
function normalizeIp(ip) { return (ip || '').replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1'); }
function getClientIp(req) { return normalizeIp(req.socket.remoteAddress); }

// ============ PROXY SERVER ============
const proxyServer = http.createServer((req, res) => {
  const clientIp = getClientIp(req);

  if (!whitelist.has(clientIp)) {
    trackUnauthorized(clientIp, req.url, req.method);
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url);
  const startTime = Date.now();
  let bytesSent = 0, bytesReceived = 0;

  const opts = {
    hostname: parsedUrl.hostname, port: parsedUrl.port || 80, path: parsedUrl.path,
    method: req.method, headers: { ...req.headers }
  };
  delete opts.headers['proxy-connection'];

  const proxyReq = http.request(opts, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.on('data', c => bytesReceived += c.length);
    proxyRes.on('end', () => {
      res.end();
      trackRequest(clientIp, parsedUrl.hostname, req.method, bytesSent, bytesReceived, proxyRes.statusCode, Date.now() - startTime);
    });
    proxyRes.pipe(res, { end: false });
  });
  proxyReq.setTimeout(30000, () => { proxyReq.destroy(); res.writeHead(504); res.end(); });
  proxyReq.on('error', () => { try { res.writeHead(502); res.end(); } catch (e) {} });

  req.on('data', c => bytesSent += c.length);
  req.pipe(proxyReq);
});

proxyServer.on('connect', (req, clientSocket, head) => {
  const clientIp = normalizeIp(clientSocket.remoteAddress);
  if (!whitelist.has(clientIp)) {
    trackUnauthorized(clientIp, req.url, 'CONNECT');
    clientSocket.end(); return;
  }
  const [hostname, pStr] = req.url.split(':');
  const port = parseInt(pStr, 10) || 443;
  const startTime = Date.now();
  let bS = 0, bR = 0, ended = false;
  const done = () => { if (ended) return; ended = true; trackRequest(clientIp, hostname, 'CONNECT', bS, bR, 200, Date.now() - startTime); };
  const sock = net.connect(port, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) sock.write(head);
    sock.on('data', c => { bR += c.length; clientSocket.write(c); });
    clientSocket.on('data', c => { bS += c.length; sock.write(c); });
    clientSocket.on('end', () => { if (!ended) { ended = true; sock.end(); done(); } });
    sock.on('end', () => { if (!ended) { ended = true; clientSocket.end(); done(); } });
    clientSocket.on('error', () => sock.end());
    sock.on('error', () => clientSocket.end());
  });
  sock.on('error', () => clientSocket.end());
  sock.setTimeout((parseInt(process.env.TIMEOUT_SECONDS, 10) || 300) * 1000, () => { sock.end(); clientSocket.end(); });
});

// ============ ADMIN SERVER ============
const app = express();

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Proxy Admin"');
    return res.status(401).send();
  }
  try {
    const raw = Buffer.from(h.slice(6), 'base64').toString();
    const i = raw.indexOf(':');
    if (i > 0 && raw.slice(0, i) === appConfig.user && raw.slice(i + 1) === appConfig.pass) return next();
  } catch (e) {}
  res.set('WWW-Authenticate', 'Basic realm="Proxy Admin"');
  res.status(401).send();
}

app.use('/api', auth);
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Config
app.get('/api/config', (req, res) => {
  res.json({ user: appConfig.user, autoClear: appConfig.autoClear });
});
app.put('/api/config/credentials', (req, res) => {
  const { user, pass } = req.body;
  if (user && user.length >= 2) appConfig.user = user;
  if (pass && pass.length >= 4) appConfig.pass = pass;
  saveConfig();
  addLog('info', 'config', 'Admin credentials updated');
  res.json({ success: true });
});
app.put('/api/config/autoclear', (req, res) => {
  const { enabled, maxAge, maxEntries } = req.body;
  if (typeof enabled === 'boolean') appConfig.autoClear.enabled = enabled;
  if (maxAge) appConfig.autoClear.maxAge = maxAge;
  if (maxEntries) appConfig.autoClear.maxEntries = maxEntries;
  saveConfig();
  addLog('info', 'config', 'Auto-clear settings updated');
  res.json({ success: true });
});

// Whitelist
app.get('/api/whitelist', (req, res) => {
  res.json({ ips: [...whitelist].map(ip => ({ ip })), count: whitelist.size });
});
app.post('/api/whitelist', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'Invalid IP' });
  whitelist.add(ip); saveWhitelist();
  addLog('info', 'config', `Whitelist added: ${ip}`);
  res.json({ success: true, ip });
});
app.delete('/api/whitelist/:ip', (req, res) => {
  const ip = req.params.ip;
  const d = whitelist.delete(ip);
  if (d) saveWhitelist();
  if (d) addLog('info', 'config', `Whitelist removed: ${ip}`);
  res.json({ success: d, ip });
});

// Stats
app.get('/api/stats/summary', (req, res) => {
  const n = Date.now();
  const r = stats.history.filter(h => n - h.ts < 86400000);
  res.json({
    totalRequests: stats.totalRequests, totalBytesSent: stats.totalBytesSent, totalBytesReceived: stats.totalBytesReceived,
    recentRequests: r.length, recentBytesSent: r.reduce((s, h) => s + h.bytesSent, 0),
    recentBytesReceived: r.reduce((s, h) => s + h.bytesReceived, 0),
    activeIps: new Set(r.map(h => h.ip)).size, whitelistCount: whitelist.size,
    unauthorizedCount: unauthorizedLogs.length,
    uptime: n - startedAt
  });
});
app.get('/api/stats/byip', (req, res) => res.json({ byIp: stats.byIp }));
app.get('/api/stats/byhost', (req, res) => res.json({ byHost: stats.byHost }));
app.get('/api/stats/history', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  res.json({ history: stats.history.slice(-limit).reverse() });
});
app.post('/api/stats/reset', (req, res) => {
  stats = { totalRequests: 0, totalBytesSent: 0, totalBytesReceived: 0, byIp: {}, byHost: {}, history: [] };
  statsDirty = true; flushStats();
  addLog('info', 'system', 'Statistics reset');
  res.json({ success: true });
});

// Timeline for charts (pre-aggregated, lightweight)
app.get('/api/stats/timeline', (req, res) => {
  const hours = Math.min(parseInt(req.query.hours) || 24, 168);
  const now = Date.now();
  const interval = hours <= 24 ? 3600000 : 14400000; // 1h for 24h, 4h for 7d
  const buckets = {};
  for (let i = 0; i < hours; i++) {
    const t = Math.floor((now - i * 3600000) / interval) * interval;
    if (!buckets[t]) buckets[t] = { requests: 0, bytes: 0, count: 0 };
    buckets[t].count++;
  }
  stats.history.forEach(h => {
    const t = Math.floor(h.ts / interval) * interval;
    if (buckets[t]) { buckets[t].requests++; buckets[t].bytes += h.bytesSent + h.bytesReceived; }
  });
  const timeline = Object.entries(buckets).sort(([a], [b]) => a - b).map(([ts, d]) => ({ ts: +ts, requests: d.requests, bytes: d.bytes }));
  res.json({ timeline, interval });
});

// Unauthorized
app.get('/api/unauthorized', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  res.json({ list: unauthorizedLogs.slice(-limit).reverse(), total: unauthorizedLogs.length });
});
app.delete('/api/unauthorized', (req, res) => {
  unauthorizedLogs = [];
  flushUnauth();
  addLog('info', 'system', 'Unauthorized logs cleared');
  res.json({ success: true });
});

// Logs
app.get('/api/logs', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const type = req.query.type;
  let filtered = logs;
  if (type) filtered = filtered.filter(l => l.type === type);
  res.json({ logs: filtered.slice(-limit).reverse(), total: logs.length });
});
app.delete('/api/logs', (req, res) => {
  logs = []; flushLogs();
  res.json({ success: true });
});

// SPA fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============ START ============
const startedAt = Date.now();

proxyServer.listen(PROXY_PORT, '0.0.0.0', () => {
  addLog('info', 'system', `Proxy started on port ${PROXY_PORT}`);
});
app.listen(ADMIN_PORT, '0.0.0.0', () => {
  addLog('info', 'system', `Admin panel on port ${ADMIN_PORT}`);
  console.log(`Proxy :${PROXY_PORT}  Admin :${ADMIN_PORT}  user:${appConfig.user}`);
});

process.on('SIGTERM', () => { flushStats(); flushLogs(); flushUnauth(); process.exit(0); });
process.on('SIGINT', () => { flushStats(); flushLogs(); flushUnauth(); process.exit(0); });
