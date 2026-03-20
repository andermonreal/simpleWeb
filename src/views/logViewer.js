'use strict';

const { escHtml } = require('../utils/helpers');
const { LOGIN_EVENT_TYPES } = require('../config');

// ══════════════════════════════════════════════════════════
// Public API
// ══════════════════════════════════════════════════════════

/**
 * Renders the full admin log-viewer page as an HTML string.
 * @param {import('../types').LogViewerContext} ctx
 * @returns {string}
 */
function buildLogViewerHTML(ctx) {
  const { globalStats, ipStats } = ctx;
  const totalUniqueIPs = Object.keys(ipStats).length;

  return `<!DOCTYPE html>
<html lang="es">
<head>
  ${buildHead()}
</head>
<body>
  ${buildTopbar(ctx, totalUniqueIPs)}
  <div class="page-wrap">
    ${buildStatCards(ctx, globalStats, totalUniqueIPs)}
    ${buildFilterBar(ctx)}
    ${buildTableCard(ctx)}
    ${buildPagination(ctx)}
    <div class="page-footer mt-3">
      ${ctx.totalFiltered} resultados · <strong>${globalStats.total}</strong> registros totales ·
      Página <strong>${ctx.page}</strong> de <strong>${ctx.totalPages}</strong>
    </div>
  </div>
  ${buildIpModal(ipStats, totalUniqueIPs)}
  ${buildUsersModal()}
  ${buildChangePasswordModal()}
  ${buildToast()}
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>${buildClientScript(ctx)}</script>
</body>
</html>`;
}

/**
 * Renders the "logged out" confirmation page.
 * @returns {string}
 */
function buildLoggedOutHTML() {
  return `<!DOCTYPE html>
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
</body></html>`;
}

// ══════════════════════════════════════════════════════════
// Layout sections
// ══════════════════════════════════════════════════════════

function buildHead() {
  return `
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Login Logger · Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet"/>
  <style>${STYLES}</style>`;
}

function buildTopbar({ type, ipFilter, filter }, totalUniqueIPs) {
  return `
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
      <i class="bi bi-clock me-1"></i>${new Date().toLocaleString('es-ES')}
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
</header>`;
}

function buildStatCards({ type, ipFilter, filter }, stats, totalUniqueIPs) {
  const isLoginActive = ['login_all', 'login_attempt', 'max_attempts_redirect'].includes(type);

  const cards = [
    {
      href: '/admin/logs?type=login_all',
      active: isLoginActive,
      color: '#e53e3e',
      bg: '#fff0f0',
      icon: 'bi-key-fill',
      value: stats.loginCount,
      label: 'Intentos login',
      hint: `${stats.loginNormal} normales · <span style="color:#7e22ce;">${stats.maxAttempts} redirigidos</span>`,
    },
    {
      href: '/admin/logs?type=max_attempts_redirect',
      active: type === 'max_attempts_redirect',
      color: '#7e22ce',
      bg: '#faf0ff',
      icon: 'bi-arrow-right-circle-fill',
      value: stats.maxAttempts,
      label: 'Redirigidos',
      hint: 'Clic para filtrar',
    },
    {
      href: '/admin/logs',
      active: !type && !ipFilter && !filter,
      color: '#3b82f6',
      bg: '#eff6ff',
      icon: 'bi-collection-fill',
      value: stats.total,
      label: 'Total registros',
      hint: 'Ver todos',
    },
    {
      href: '/admin/logs?type=admin_access_denied',
      active: type === 'admin_access_denied',
      color: '#dd6b20',
      bg: '#fff8f0',
      icon: 'bi-shield-exclamation',
      value: stats.adminDenied,
      label: 'Admin denegados',
      hint: 'Clic para filtrar',
    },
    {
      href: '/admin/logs?type=rate_limit_exceeded',
      active: type === 'rate_limit_exceeded',
      color: '#ca8a04',
      bg: '#fefce8',
      icon: 'bi-slash-circle-fill',
      value: stats.rateLimited,
      label: 'Rate limits',
      hint: 'Clic para filtrar',
    },
  ];

  const cardHTML = cards.map((c) => `
    <div class="col-6 col-md-4 col-xl">
      <a href="${c.href}" class="stat-card ${c.active ? 'active-filter' : ''}">
        <div class="stat-icon" style="background:${c.bg};color:${c.color};"><i class="bi ${c.icon}"></i></div>
        <div>
          <div class="stat-value" style="color:${c.color};">${c.value}</div>
          <div class="stat-label">${c.label}</div>
          <div class="stat-hint">${c.hint}</div>
        </div>
      </a>
    </div>`).join('');

  const ipCard = `
    <div class="col-6 col-md-4 col-xl">
      <div class="stat-card" style="cursor:pointer;" data-bs-toggle="modal" data-bs-target="#ipModal" title="Ver panel de IPs">
        <div class="stat-icon" style="background:#f0fdf4;color:#16a34a;"><i class="bi bi-globe2"></i></div>
        <div><div class="stat-value" style="color:#16a34a;">${totalUniqueIPs}</div><div class="stat-label">IPs únicas</div><div class="stat-hint">Clic para ver panel</div></div>
      </div>
    </div>`;

  return `<div class="row g-3 mb-4">${cardHTML}${ipCard}</div>`;
}

function buildFilterBar({ filter, type, ipFilter, excludeList, showList, limit }) {
  const typeOptions = [
    ['', 'Todos los eventos'],
    ['login_all', '🔑 todos los logins (normal + redirigido)'],
    ['login_attempt', '🔑 login_attempt (solo normales)'],
    ['max_attempts_redirect', '🚨 max_attempts (solo redirigidos)'],
    ['page_visit', '👁 page_visit'],
    ['admin_access', '🛡 admin_access'],
    ['admin_access_denied', '⛔ admin_denied'],
    ['rate_limit_exceeded', '🚫 rate_limit'],
  ].map(([v, l]) => `<option value="${v}" ${type === v ? 'selected' : ''}>${l}</option>`).join('');

  const limitOptions = [25, 50, 100, 200, 500]
    .map((n) => `<option value="${n}" ${n == limit ? 'selected' : ''}>${n} / pág.</option>`)
    .join('');

  const excludePills = buildExcludePills(excludeList);
  const showPills = buildShowPills(showList);

  return `
<div class="filter-card mb-4">
  <form method="GET" action="/admin/logs" id="filterForm" class="row g-2 align-items-end">
    <div class="col-12 col-sm-6 col-lg-5">
      <div class="filter-label"><i class="bi bi-search me-1"></i>Buscar</div>
      <div class="input-group">
        <span class="input-group-text bg-white border-end-0" style="border-color:#e2e8f0;"><i class="bi bi-search text-muted" style="font-size:.78rem;"></i></span>
        <input type="text" name="filter" class="form-control border-start-0" placeholder="IP, usuario, contraseña…" value="${escHtml(filter)}"/>
      </div>
    </div>
    <div class="col-6 col-sm-3 col-lg-2">
      <div class="filter-label"><i class="bi bi-list-ol me-1"></i>Por página</div>
      <select name="limit" class="form-select">${limitOptions}</select>
    </div>
    <div class="col-12 col-sm-6 col-lg-5 d-flex gap-2">
      <button type="submit" class="btn btn-primary flex-grow-1"><i class="bi bi-funnel-fill me-1"></i>Filtrar</button>
      <a href="/admin/logs" class="btn btn-outline-secondary px-3" title="Limpiar filtros"><i class="bi bi-x-lg"></i></a>
    </div>
    <!-- Hidden input serialised from ipFilterPills before submit -->
    <input type="hidden" name="ip" id="ipFilterHidden" value="${escHtml(ipFilter)}"/>
    <div id="excludeInputs"></div>
    <div id="showInputs"></div>
    <div class="col-12">
      <div class="filter-label mb-2"><i class="bi bi-eye-fill me-1 text-success"></i>Mostrar solo eventos <span class="text-muted" style="font-weight:400;text-transform:none;letter-spacing:0;">(clic para activar · si hay activos solo se muestran esos)</span></div>
      <div class="d-flex gap-2 flex-wrap" id="showToggles">${showPills}</div>
    </div>
    <div class="col-12">
      <div class="filter-label mb-2"><i class="bi bi-eye-slash me-1"></i>Excluir eventos <span class="text-muted" style="font-weight:400;text-transform:none;letter-spacing:0;">(clic para ocultar/mostrar)</span></div>
      <div class="d-flex gap-2 flex-wrap" id="excludeToggles">${excludePills}</div>
    </div>
    <!-- Filtrar por IP (server-side, results filtered) -->
    <div class="col-12">
      <div class="filter-label mb-2">
        <i class="bi bi-geo-alt-fill me-1 text-primary"></i>Filtrar por IP
        <span class="text-muted ms-1" style="font-weight:400;text-transform:none;letter-spacing:0;">— solo muestra logs de estas IPs</span>
      </div>
      <div class="d-flex gap-2 flex-wrap align-items-center" id="ipFilterPills">
        <div class="input-group input-group-sm ip-add-input" style="width:260px;">
          <input type="text" id="addIpFilterInput" class="form-control" placeholder="1.2.3.4 o varios por coma" style="font-family:var(--font-mono);font-size:.75rem;"/>
          <button class="btn btn-outline-primary" type="button" id="addIpFilterBtn" title="Añadir IP(s) al filtro"><i class="bi bi-plus-lg"></i></button>
        </div>
      </div>
    </div>
    <!-- IPs completamente ocultas del panel -->
    <div class="col-12" id="hiddenIpsSection">
      <div class="filter-label mb-2">
        <i class="bi bi-x-circle-fill me-1 text-danger"></i>IPs ocultas del panel
        <span class="text-muted ms-1" style="font-weight:400;text-transform:none;letter-spacing:0;">— no aparecen en la tabla principal</span>
      </div>
      <div class="d-flex gap-2 flex-wrap align-items-center" id="hiddenIpsPills">
        <div class="input-group input-group-sm ip-add-input" style="width:260px;">
          <input type="text" id="addHiddenIpInput" class="form-control" placeholder="IP o varios separados por coma" style="font-family:var(--font-mono);font-size:.75rem;"/>
          <button class="btn btn-outline-danger" type="button" id="addHiddenIpBtn" title="Añadir IP(s) a ocultas"><i class="bi bi-plus-lg"></i></button>
        </div>
      </div>
    </div>
  </form>
</div>`;
}

function buildExcludePills(excludeList) {
  const ALL_EVENTS = [
    ['login_attempt', '🔑 login_attempt'],
    ['max_attempts_redirect', '🚨 max_attempts'],
    ['page_visit', '👁 page_visit'],
    ['admin_access', '🛡 admin_access'],
    ['admin_access_denied', '⛔ admin_denied'],
    ['rate_limit_exceeded', '🚫 rate_limit'],
  ];

  const bothLoginExcluded = excludeList.includes('login_attempt') && excludeList.includes('max_attempts_redirect');

  const masterPill = `<button type="button" class="exclude-pill btn btn-sm ${bothLoginExcluded ? 'excluded' : ''}" data-event="login_all">🔑 todos los logins</button>`;

  const pills = ALL_EVENTS.map(([v, label]) =>
    `<button type="button" class="exclude-pill btn btn-sm ${excludeList.includes(v) ? 'excluded' : ''}" data-event="${v}">${label}</button>`
  ).join('');

  return masterPill + pills;
}

function buildShowPills(showList) {
  const ALL_EVENTS = [
    ['login_attempt', '🔑 login_attempt'],
    ['max_attempts_redirect', '🚨 max_attempts'],
    ['page_visit', '👁 page_visit'],
    ['admin_access', '🛡 admin_access'],
    ['admin_access_denied', '⛔ admin_denied'],
    ['rate_limit_exceeded', '🚫 rate_limit'],
  ];

  const bothLoginShown = showList.includes('login_attempt') && showList.includes('max_attempts_redirect');

  const masterPill = `<button type="button" class="show-pill btn btn-sm ${bothLoginShown ? 'shown' : ''}" data-event="login_all">🔑 todos los logins</button>`;

  const pills = ALL_EVENTS.map(([v, label]) =>
    `<button type="button" class="show-pill btn btn-sm ${showList.includes(v) ? 'shown' : ''}" data-event="${v}">${label}</button>`
  ).join('');

  return masterPill + pills;
}

function buildTableCard({ lines, page, totalPages, totalFiltered, filter, type, ipFilter, excludeList, showList, limit }) {
  const ipList = ipFilter ? ipFilter.split(/[,\s]+/).filter(Boolean) : [];
  const activeFilters = [
    filter && `<span class="badge bg-warning bg-opacity-15 text-warning-emphasis border border-warning border-opacity-25"><i class="bi bi-funnel-fill me-1"></i>"${escHtml(filter)}"</span>`,
    ipList.length && ipList.map(ip => `<span class="badge bg-info bg-opacity-15 text-info-emphasis border border-info border-opacity-25"><i class="bi bi-geo-alt me-1"></i>${escHtml(ip)}</span>`).join(''),
    excludeList.length && `<span class="badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25"><i class="bi bi-eye-slash me-1"></i>${excludeList.length} oculto${excludeList.length > 1 ? 's' : ''}</span>`,
    showList.length && `<span class="badge bg-success bg-opacity-10 text-success border border-success border-opacity-25"><i class="bi bi-eye-fill me-1"></i>${showList.length} solo estos</span>`,
  ].filter(Boolean).join('');

  const tableContent = lines.length === 0
    ? buildEmptyState()
    : `<div class="table-responsive"><table class="table table-hover mb-0"><thead><tr>
        <th><i class="bi bi-clock me-1"></i>Timestamp</th>
        <th><i class="bi bi-geo-alt me-1"></i>IP</th>
        <th>Evento</th>
        <th>Método / Ruta</th>
        <th><i class="bi bi-person me-1"></i>Usuario</th>
        <th><i class="bi bi-key me-1"></i>Contraseña <small class="text-muted fw-normal">(clic=b64↔texto)</small></th>
        <th>User-Agent</th>
        <th style="width:36px;"></th>
      </tr></thead>
      <tbody>${lines.map(buildTableRow).join('')}</tbody>
    </table></div>`;

  return `
<div class="table-card">
  <div class="table-card-header">
    <span class="table-card-title"><i class="bi bi-table text-primary"></i> Registros</span>
    <span class="badge bg-primary bg-opacity-10 text-primary border border-primary border-opacity-25">${totalFiltered} coincidencias</span>
    <span class="badge bg-secondary bg-opacity-10 text-secondary">Pág. ${page}/${totalPages}</span>
    ${activeFilters}
  </div>
  ${tableContent}
</div>`;
}

function buildTableRow(l) {
  const isLogin = l.message === 'login_attempt';
  const isRedirect = l.message === 'max_attempts_redirect';
  const isDenied = l.message === 'admin_access_denied';
  const rowClass = (isLogin || isRedirect) ? 'row-login' : isDenied ? 'row-denied' : '';

  return `<tr data-line="${l._lineIndex}" data-ip="${escHtml(l.ip)}" class="${rowClass}">
    <td class="text-nowrap small font-mono text-secondary">${escHtml(l.timestamp) || '—'}</td>
    <td>
      <div class="ip-cell-wrap" data-ip="${escHtml(l.ip)}">
        <code class="ip-code ip-clickable" data-ip="${escHtml(l.ip)}" title="Filtrar por esta IP">${escHtml(l.ip) || '—'}</code>
        <small class="ip-geo" data-ip="${escHtml(l.ip)}">…</small>
      </div>
    </td>
    <td>${renderEventBadge(l.message)}</td>
    <td class="text-nowrap">
      ${renderMethodBadge(l.method)}
      <code class="small text-dark">${renderPath(l)}</code>
      ${isRedirect && l.redirectTo ? `<br/><small class="text-muted font-mono" style="font-size:.68rem;">→ ${escHtml(l.redirectTo)}</small>` : ''}
    </td>
    <td>${(isLogin || isRedirect || isDenied)
      ? `<strong class="text-danger">${escHtml(l.username || l.attemptedUser)}</strong>`
      : '<span class="text-muted">—</span>'}</td>
    <td>${renderPasswordCell(l, isLogin, isRedirect)}</td>
    <td class="small text-muted text-truncate" style="max-width:180px" title="${escHtml(l.userAgent)}">${escHtml(l.userAgent) || '—'}</td>
    <td class="text-center">
      <button class="btn-del btn btn-xs px-1 py-0 btn-outline-danger" data-line="${l._lineIndex}" title="Eliminar entrada" style="font-size:.68rem;"><i class="bi bi-trash3"></i></button>
    </td>
  </tr>`;
}

// ══════════════════════════════════════════════════════════
// Table cell renderers
// ══════════════════════════════════════════════════════════

function renderMethodBadge(method) {
  if (!method) return '';
  const colorMap = { GET: 'success', POST: 'primary', DELETE: 'danger' };
  const cls = colorMap[method] || 'secondary';
  return `<span class="badge bg-${cls} bg-opacity-10 text-${cls} border border-${cls} border-opacity-25 font-mono">${method}</span>`;
}

const EVENT_BADGE_MAP = {
  login_attempt: ['login-badge', '🔑 login_attempt'],
  max_attempts_redirect: ['purple', '🚨 max_attempts'],
  admin_access: ['success', '🛡 admin_access'],
  admin_access_denied: ['danger', '⛔ admin_denied'],
  rate_limit_exceeded: ['warning text-dark', '🚫 rate_limit'],
  page_visit: ['info text-dark', '👁 page_visit'],
};

function renderEventBadge(message) {
  const [cls, label] = EVENT_BADGE_MAP[message] || ['secondary', escHtml(message) || '—'];

  if (cls === 'login-badge') {
    return `<span class="badge rounded-pill px-2" style="background:#fff0f0;color:#c0392b;border:1px solid #f5c6c6;">${label}</span>`;
  }
  if (cls === 'purple') {
    return `<span class="badge rounded-pill px-2" style="background:#faf0ff;color:#7e22ce;border:1px solid #e9d5ff;">${label}</span>`;
  }
  return `<span class="badge rounded-pill bg-${cls} px-2">${label}</span>`;
}

function renderPath(l) {
  if (l.page && l.path) {
    const page = String(l.page).replace(/\/$/, '');
    const route = String(l.path).startsWith('/') ? l.path : `/${l.path}`;
    return escHtml(page + route);
  }
  return escHtml(l.path || '');
}

function renderPasswordCell(l, isLogin, isRedirect) {
  const hasPassword = (isLogin || isRedirect) && l.password && l.password !== '(vacío)';

  if (hasPassword) {
    return `<code class="pw-code pw-toggle" data-b64="${escHtml(l.password)}" data-state="b64" title="Clic para decodificar Base64">${escHtml(l.password)}</code>`;
  }
  if (isLogin || isRedirect) {
    return `<span class="text-muted fst-italic small">(vacío)</span>`;
  }
  return `<span class="text-muted">—</span>`;
}

function buildEmptyState() {
  return `
  <div class="empty-state">
    <i class="bi bi-inbox d-block mb-3"></i>
    <p class="fw-semibold text-secondary">No hay registros que mostrar</p>
    <p class="small">Ajusta los filtros o espera a que lleguen nuevos eventos.</p>
  </div>`;
}

// ══════════════════════════════════════════════════════════
// Pagination
// ══════════════════════════════════════════════════════════

function buildPagination({ page, totalPages, filter, type, ipFilter, excludeList, limit }) {
  if (totalPages <= 1) return '';

  const buildUrl = (p) => {
    const q = new URLSearchParams();
    if (filter) q.set('filter', filter);
    if (type) q.set('type', type);
    if (ipFilter) q.set('ip', ipFilter);
    if (limit !== 50) q.set('limit', limit);
    excludeList.forEach((e) => q.append('exclude', e));
    q.set('page', p);
    return `/admin/logs?${q.toString()}`;
  };

  const WING = 2;
  const pages = [...new Set([
    1,
    ...Array.from({ length: 2 * WING + 1 }, (_, i) => page - WING + i).filter((p) => p > 1 && p < totalPages),
    totalPages,
  ])].sort((a, b) => a - b);

  let items = '';
  let prev = 0;
  for (const p of pages) {
    if (p - prev > 1) items += `<li class="page-item disabled"><span class="page-link">…</span></li>`;
    items += `<li class="page-item ${p === page ? 'active' : ''}"><a class="page-link" href="${buildUrl(p)}">${p}</a></li>`;
    prev = p;
  }

  return `
<nav aria-label="Paginación"><ul class="pagination pagination-sm justify-content-center flex-wrap mb-0">
  <li class="page-item ${page <= 1 ? 'disabled' : ''}"><a class="page-link" href="${page > 1 ? buildUrl(page - 1) : '#'}">‹ Ant.</a></li>
  ${items}
  <li class="page-item ${page >= totalPages ? 'disabled' : ''}"><a class="page-link" href="${page < totalPages ? buildUrl(page + 1) : '#'}">Sig. ›</a></li>
</ul></nav>
<div class="d-flex justify-content-center align-items-center gap-2 mt-2" style="font-size:.8rem;">
  <span class="text-muted">Ir a página:</span>
  <div class="input-group input-group-sm" style="width:115px;">
    <input type="number" id="gotoPage" class="form-control text-center" min="1" max="${totalPages}" value="${page}" style="font-size:.8rem;"/>
    <button class="btn btn-outline-secondary" onclick="goToPage()">Ir</button>
  </div>
  <span class="text-muted">de <strong>${totalPages}</strong></span>
</div>`;
}

// ══════════════════════════════════════════════════════════
// Modals
// ══════════════════════════════════════════════════════════

function buildIpModal(ipStats, totalUniqueIPs) {
  const rows = Object.entries(ipStats)
    .sort((a, b) => b[1].total - a[1].total)
    .map(([ip, s]) => {
      const risk = s.logins > 10 ? 'danger' : s.logins > 3 ? 'warning' : 'success';
      const label = s.logins > 10 ? 'Alto' : s.logins > 3 ? 'Medio' : 'Bajo';
      return `<tr data-ip="${escHtml(ip)}">
        <td>
          <div class="ip-cell-wrap ip-cell-modal" data-ip="${escHtml(ip)}">
            <code class="ip-code ip-modal-filter" data-ip="${escHtml(ip)}" style="cursor:pointer">${escHtml(ip)}</code>
            <br/><small class="ip-geo ip-geo-modal" data-ip="${escHtml(ip)}">…</small>
          </div>
        </td>
        <td class="text-center"><span class="badge bg-primary bg-opacity-10 text-primary">${s.total}</span></td>
        <td class="text-center"><span class="badge bg-danger bg-opacity-10 text-danger">${s.logins}</span></td>
        <td class="text-center"><span class="badge bg-${risk} bg-opacity-15 text-${risk}-emphasis border border-${risk} border-opacity-25">${label}</span></td>
        <td class="small text-muted font-mono">${escHtml(s.lastSeen) || '—'}</td>
        <td class="text-nowrap">
          <a href="/admin/logs?ip=${encodeURIComponent(ip)}" class="btn btn-xs btn-outline-primary py-0 px-2 me-1" style="font-size:.7rem;" title="Filtrar por esta IP">Filtrar</a>
          <button class="btn btn-xs py-0 px-2 me-1 btn-modal-toggle-hide" data-ip="${escHtml(ip)}" style="font-size:.7rem;" title="Ocultar del panel principal"><i class="bi bi-x-circle"></i></button>
          <button class="btn btn-xs py-0 px-2 btn-modal-toggle-blur" data-ip="${escHtml(ip)}" style="font-size:.7rem;" title="Blurrear en el panel"><i class="bi bi-eye"></i></button>
        </td>
      </tr>`;
    }).join('');

  return `
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
            <input type="text" id="ipModalSearch" class="form-control" placeholder="Buscar IP, ciudad, país…" oninput="filterIpTable(this.value)"/>
          </div>
        </div>
        <div class="table-responsive">
          <table class="table table-hover mb-0 modal-ip-table">
            <thead><tr>
              <th>IP / Ubicación</th>
              <th class="text-center" style="cursor:pointer;" onclick="sortIpTable('total')">Total <i class="bi bi-arrow-down-up"></i></th>
              <th class="text-center" style="cursor:pointer;" onclick="sortIpTable('logins')">Logins <i class="bi bi-arrow-down-up"></i></th>
              <th class="text-center">Riesgo</th>
              <th>Último evento</th>
              <th></th>
            </tr></thead>
            <tbody id="ipTableBody">${rows}</tbody>
          </table>
        </div>
        ${totalUniqueIPs === 0 ? `<div class="text-center text-muted p-4"><i class="bi bi-inbox"></i> Sin datos de IPs</div>` : ''}
      </div>
      <div class="modal-footer">
        <small class="text-muted me-auto"><i class="bi bi-info-circle me-1"></i>Clic en una IP para filtrar · Clic en la ubicación para abrir Google Maps.</small>
        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Cerrar</button>
      </div>
    </div>
  </div>
</div>`;
}

function buildUsersModal() {
  return `
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
          <span>Cambios inmediatos, persistidos en <code>logs/admin-users.json</code>.</span>
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
</div>`;
}

function buildChangePasswordModal() {
  return `
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
</div>`;
}

function buildToast() {
  return `
<div class="toast-container">
  <div id="appToast" class="toast align-items-center border-0 text-white" role="alert">
    <div class="d-flex">
      <div id="appToastBody" class="toast-body fw-semibold"></div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  </div>
</div>`;
}

// ══════════════════════════════════════════════════════════
// Client-side JavaScript
// ══════════════════════════════════════════════════════════

function buildClientScript({ excludeList, showList }) {
  return `
// ── Auto-refresh ─────────────────────────────────────────
const refreshSelect    = document.getElementById('refreshSelect');
const refreshCountdown = document.getElementById('refreshCountdown');
let refreshInterval    = parseInt(localStorage.getItem('ll_refresh') || '30');
let refreshTimer       = null;
let refreshRemaining   = 0;

function updateRefresh(val) {
  refreshInterval = parseInt(val);
  localStorage.setItem('ll_refresh', refreshInterval);
  clearRefreshTimer();
  refreshCountdown.textContent = '';
  if (refreshInterval > 0) startRefreshTimer();
}
function startRefreshTimer() {
  refreshRemaining = refreshInterval;
  refreshCountdown.textContent = refreshRemaining + 's';
  refreshTimer = setInterval(() => {
    refreshRemaining--;
    refreshCountdown.textContent = refreshRemaining + 's';
    if (refreshRemaining <= 0) { clearRefreshTimer(); location.reload(); }
  }, 1000);
}
function clearRefreshTimer() {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}
refreshSelect.value = String(refreshInterval);
if (refreshInterval > 0) startRefreshTimer();
document.querySelectorAll('.modal').forEach(m => {
  m.addEventListener('show.bs.modal',   clearRefreshTimer);
  m.addEventListener('hidden.bs.modal', () => { if (refreshInterval > 0) startRefreshTimer(); });
});

// ── Pagination ───────────────────────────────────────────
function goToPage() {
  const p = parseInt(document.getElementById('gotoPage')?.value);
  if (!p || p < 1) return;
  const url = new URL(location.href);
  url.searchParams.set('page', p);
  location.href = url.toString();
}
document.getElementById('gotoPage')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); goToPage(); }
});

// ── IP filter (pill-tag style) ────────────────────────────
(function initIpFilter() {
  const hiddenInput = document.getElementById('ipFilterHidden');
  const container   = document.getElementById('ipFilterPills');
  const textInput   = document.getElementById('addIpFilterInput');
  const addBtn      = document.getElementById('addIpFilterBtn');

  // Bootstrap initial state from the server-rendered value
  const initial = (hiddenInput?.value || '').split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
  const ipSet   = new Set(initial);

  function sync() {
    if (hiddenInput) hiddenInput.value = [...ipSet].join(',');
  }

  function renderPills() {
    if (!container) return;
    container.querySelectorAll('.ip-pill.type-filter').forEach(p => p.remove());
    const inputGroup = container.querySelector('.ip-add-input');

    [...ipSet].forEach(ip => {
      const pill = document.createElement('span');
      pill.className = 'ip-pill type-filter';
      pill.innerHTML = ip + ' <span class="pill-remove" title="Quitar filtro">✕</span>';
      pill.querySelector('.pill-remove').addEventListener('click', () => {
        ipSet.delete(ip);
        sync();
        renderPills();
      });
      container.insertBefore(pill, inputGroup);
    });
  }

  function addIPs(raw) {
    raw.split(/[,\s]+/).map(s => s.trim()).filter(Boolean).forEach(ip => ipSet.add(ip));
    if (textInput) textInput.value = '';
    sync();
    renderPills();
  }

  addBtn?.addEventListener('click',  () => addIPs(textInput?.value || ''));
  textInput?.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addIPs(textInput.value); } });

  // Clicking an IP code in the table adds it to the filter pills
  document.querySelectorAll('code.ip-clickable').forEach(el => {
    el.addEventListener('click', e => {
      e.stopPropagation();
      addIPs(el.dataset.ip);
      // Auto-submit so the server re-filters immediately
      document.getElementById('filterForm')?.submit();
    });
  });

  // Modal IP filter click
  document.querySelectorAll('.ip-modal-filter').forEach(el => {
    el.addEventListener('click', () => {
      bootstrap.Modal.getInstance(document.getElementById('ipModal'))?.hide();
      addIPs(el.dataset.ip);
      document.getElementById('filterForm')?.submit();
    });
  });

  renderPills();
})();

// ── Exclude toggles ──────────────────────────────────────
const excludedSet = new Set(${JSON.stringify(excludeList)});

function syncExcludeInputs() {
  const container = document.getElementById('excludeInputs');
  container.innerHTML = '';
  excludedSet.forEach(ev => {
    const inp = document.createElement('input');
    inp.type = 'hidden'; inp.name = 'exclude'; inp.value = ev;
    container.appendChild(inp);
  });
}

document.querySelectorAll('.exclude-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    const ev = btn.dataset.event;
    if (ev === 'login_all') {
      const bothOn = excludedSet.has('login_attempt') && excludedSet.has('max_attempts_redirect');
      if (bothOn) {
        excludedSet.delete('login_attempt');
        excludedSet.delete('max_attempts_redirect');
      } else {
        excludedSet.add('login_attempt');
        excludedSet.add('max_attempts_redirect');
      }
      document.querySelectorAll('.exclude-pill[data-event="login_attempt"], .exclude-pill[data-event="max_attempts_redirect"]')
        .forEach(p => p.classList.toggle('excluded', excludedSet.has(p.dataset.event)));
      btn.classList.toggle('excluded', excludedSet.has('login_attempt') && excludedSet.has('max_attempts_redirect'));
    } else {
      excludedSet.has(ev) ? excludedSet.delete(ev) : excludedSet.add(ev);
      btn.classList.toggle('excluded', excludedSet.has(ev));
      const masterPill = document.querySelector('.exclude-pill[data-event="login_all"]');
      if (masterPill) {
        masterPill.classList.toggle('excluded',
          excludedSet.has('login_attempt') && excludedSet.has('max_attempts_redirect'));
      }
    }
    syncExcludeInputs();
    clearTimeout(btn._debounce);
    btn._debounce = setTimeout(() => {
      document.getElementById('filterForm').submit();
    }, 350);
  });
});
syncExcludeInputs();

// ── Show-only toggles ────────────────────────────────────
const shownSet = new Set(${JSON.stringify(showList)});

function syncShowInputs() {
  const container = document.getElementById('showInputs');
  container.innerHTML = '';
  shownSet.forEach(ev => {
    const inp = document.createElement('input');
    inp.type = 'hidden'; inp.name = 'show'; inp.value = ev;
    container.appendChild(inp);
  });
}

document.querySelectorAll('.show-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    const ev = btn.dataset.event;
    if (ev === 'login_all') {
      const bothOn = shownSet.has('login_attempt') && shownSet.has('max_attempts_redirect');
      if (bothOn) {
        shownSet.delete('login_attempt');
        shownSet.delete('max_attempts_redirect');
      } else {
        shownSet.add('login_attempt');
        shownSet.add('max_attempts_redirect');
      }
      document.querySelectorAll('.show-pill[data-event="login_attempt"], .show-pill[data-event="max_attempts_redirect"]')
        .forEach(p => p.classList.toggle('shown', shownSet.has(p.dataset.event)));
      btn.classList.toggle('shown', shownSet.has('login_attempt') && shownSet.has('max_attempts_redirect'));
    } else {
      shownSet.has(ev) ? shownSet.delete(ev) : shownSet.add(ev);
      btn.classList.toggle('shown', shownSet.has(ev));
      const masterPill = document.querySelector('.show-pill[data-event="login_all"]');
      if (masterPill) {
        masterPill.classList.toggle('shown',
          shownSet.has('login_attempt') && shownSet.has('max_attempts_redirect'));
      }
    }
    syncShowInputs();
    clearTimeout(btn._debounce);
    btn._debounce = setTimeout(() => {
      document.getElementById('filterForm').submit();
    }, 350);
  });
});
syncShowInputs();

// ── Password Base64 toggle ────────────────────────────────
document.querySelectorAll('.pw-toggle').forEach(el => {
  el.addEventListener('click', e => {
    e.stopPropagation();
    const isB64 = el.dataset.state === 'b64';
    if (isB64) {
      try {
        el.textContent    = atob(el.dataset.b64);
        el.dataset.state  = 'plain';
        el.title          = 'Clic para volver a codificar en Base64';
        el.style.background = '#fef9c3';
        el.style.color      = '#92400e';
      } catch { el.textContent = '[error al decodificar]'; }
    } else {
      el.textContent      = el.dataset.b64;
      el.dataset.state    = 'b64';
      el.title            = 'Clic para decodificar';
      el.style.background = '';
      el.style.color      = '';
    }
  });
});

// ── Delete log line ───────────────────────────────────────
document.querySelectorAll('.btn-del').forEach(btn => {
  btn.addEventListener('click', async e => {
    e.stopPropagation();
    if (!confirm('¿Eliminar este registro de log? Esta acción no se puede deshacer.')) return;
    try {
      const res  = await fetch('/admin/logs/line/' + btn.dataset.line, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok && data.success) {
        const row = btn.closest('tr');
        row.style.transition = 'opacity .3s, transform .3s';
        row.style.opacity    = '0';
        row.style.transform  = 'translateX(20px)';
        setTimeout(() => row.remove(), 320);
        showToast('🗑 Registro eliminado', 'success');
      } else {
        showToast(data.error || 'Error al eliminar', 'danger');
      }
    } catch { showToast('Error de red', 'danger'); }
  });
});

// ── IP modal table ───────────────────────────────────────
function filterIpTable(q) {
  q = q.toLowerCase();
  document.querySelectorAll('#ipTableBody tr').forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
const ipSortDir = { total: -1, logins: -1 };
function sortIpTable(col) {
  ipSortDir[col] *= -1;
  const tbody = document.getElementById('ipTableBody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const idx   = col === 'total' ? 1 : 2;
  rows.sort((a, b) =>
    ((parseInt(b.cells[idx]?.textContent) || 0) - (parseInt(a.cells[idx]?.textContent) || 0)) * ipSortDir[col]
  );
  rows.forEach(r => tbody.appendChild(r));
}

// ── User management ───────────────────────────────────────
let currentEditUser = null;

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function loadUsers() {
  const tbody = document.getElementById('usersTableBody');
  try {
    const data = await fetch('/admin/users').then(r => r.json());
    if (!data.users?.length) {
      tbody.innerHTML = '<tr><td colspan="2" class="text-center text-muted">Sin usuarios</td></tr>';
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
      </tr>\`).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="2" class="text-danger small">Error al cargar usuarios</td></tr>';
  }
}

document.getElementById('usersModal').addEventListener('show.bs.modal', loadUsers);

async function deleteUser(username) {
  if (!confirm('¿Eliminar al usuario "' + username + '"?')) return;
  const res  = await fetch('/admin/users/' + encodeURIComponent(username), { method: 'DELETE' });
  const data = await res.json();
  if (res.ok) { showToast('🗑 Usuario eliminado', 'success'); await loadUsers(); }
  else showToast(data.error || 'Error', 'danger');
}

function openChangePass(username) {
  currentEditUser = username;
  document.getElementById('cpModalUser').textContent = username;
  document.getElementById('cpNewPass').value  = '';
  document.getElementById('cpConfirm').value  = '';
  document.getElementById('cpAlert').className = 'd-none mb-3';
  document.getElementById('cpPwBar').style.width = '0%';
  document.getElementById('cpPwLabel').textContent = '';
  bootstrap.Modal.getInstance(document.getElementById('usersModal'))?.hide();
  setTimeout(() => new bootstrap.Modal(document.getElementById('changePassModal')).show(), 200);
}

function backToUsers() {
  bootstrap.Modal.getInstance(document.getElementById('changePassModal'))?.hide();
  setTimeout(() => new bootstrap.Modal(document.getElementById('usersModal')).show(), 200);
}

async function saveNewPassword() {
  const newPass  = document.getElementById('cpNewPass').value;
  const confirm2 = document.getElementById('cpConfirm').value;
  const alertDiv = document.getElementById('cpAlert');
  const btn      = document.getElementById('cpSaveBtn');

  alertDiv.className = 'd-none mb-3';
  if (!newPass)            return showAlert(alertDiv, 'La contraseña es obligatoria.');
  if (newPass.length < 8)  return showAlert(alertDiv, 'Mínimo 8 caracteres.');
  if (newPass !== confirm2) return showAlert(alertDiv, 'Las contraseñas no coinciden.');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Guardando…';
  try {
    const res  = await fetch('/admin/users/' + encodeURIComponent(currentEditUser) + '/password', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: newPass }),
    });
    const data = await res.json();
    if (res.ok && data.success) {
      backToUsers();
      showToast('✅ Contraseña actualizada para ' + currentEditUser, 'success');
    } else {
      showAlert(alertDiv, data.error || 'Error.');
    }
  } catch { showAlert(alertDiv, 'Error de red.'); }
  finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-key-fill me-1"></i>Guardar contraseña';
  }
}

async function addUser() {
  const username = document.getElementById('addUsername').value.trim();
  const password = document.getElementById('addPassword').value;
  const alertDiv = document.getElementById('addUserAlert');

  alertDiv.className = 'd-none mb-3';
  if (!username || !password) return showAlert(alertDiv, 'Usuario y contraseña son obligatorios.');
  if (password.length < 8)    return showAlert(alertDiv, 'Mínimo 8 caracteres.');

  const res  = await fetch('/admin/users', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (res.ok && data.success) {
    document.getElementById('addUsername').value = '';
    document.getElementById('addPassword').value = '';
    document.getElementById('addPwBar').style.width = '0%';
    document.getElementById('addPwLabel').textContent = '';
    await loadUsers();
    showToast('✅ Usuario creado: ' + username, 'success');
  } else {
    showAlert(alertDiv, data.error || 'Error.');
  }
}

// ── UI helpers ───────────────────────────────────────────
function showAlert(el, msg) {
  el.className = 'alert alert-danger mb-3';
  el.textContent = msg;
}

function togglePw(id) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

function checkPwStrength(barId, labelId, pw) {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw))        score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const levels = [
    { p: '20%',  c: '#ef4444', t: 'Muy débil' },
    { p: '40%',  c: '#f97316', t: 'Débil'     },
    { p: '60%',  c: '#eab308', t: 'Media'      },
    { p: '80%',  c: '#84cc16', t: 'Buena'      },
    { p: '100%', c: '#22c55e', t: 'Excelente'  },
  ];
  const lvl = levels[Math.min(score, 4)];
  const bar   = document.getElementById(barId);
  const label = document.getElementById(labelId);
  bar.style.width      = lvl.p;
  bar.style.background = lvl.c;
  label.textContent    = lvl.t;
  label.style.color    = lvl.c;
}

function showToast(msg, type = 'success') {
  const toast = document.getElementById('appToast');
  const body  = document.getElementById('appToastBody');
  toast.className = 'toast align-items-center border-0 text-white bg-' + (type === 'success' ? 'success' : 'danger');
  body.textContent = msg;
  bootstrap.Toast.getOrCreateInstance(toast, { delay: 4000 }).show();
}

function doLogout() {
  fetch('/admin/logout-clear', {
    headers: { 'Authorization': 'Basic ' + btoa('__invalid__:__invalid__') },
    cache:   'no-store',
  }).finally(() => window.location.replace('/admin/logged-out'));
}

document.querySelectorAll('[title]').forEach(el => {
  try { new bootstrap.Tooltip(el, { trigger: 'hover', placement: 'top' }); } catch {}
});

// ── Hidden & Filtered IPs ─────────────────────────────────
//
// Two independent lists persisted in localStorage:
//
//   hiddenIPs   → rows removed from the main panel AND blurred in the modal.
//                 Safe mode: IP cannot be accidentally exposed anywhere.
//
//   hiddenIPs  → rows completely removed from the main panel (display:none)
//                 Still visible (normal) in the modal.
//
// Blur mode (per IP) is only manageable from the modal toggle button
// and does NOT affect panel visibility — it just blurs the IP cell
// in the panel when hovered away.

(function initIPPrivacy() {
  const LS_HIDDEN  = 'll_hidden_ips';
  const LS_BLURRED = 'll_blurred_ips';

  function loadSet(key) {
    try { return new Set(JSON.parse(localStorage.getItem(key) || '[]')); } catch { return new Set(); }
  }
  function saveSet(key, set) {
    try { localStorage.setItem(key, JSON.stringify([...set])); } catch {}
  }

  let hiddenIPs  = loadSet(LS_HIDDEN);
  let blurredIPs = loadSet(LS_BLURRED);

  // ── Apply state to every element in the page ─────────────
  function applyAll() {
    // Main table rows: hidden → display:none ; blurred → blur effect
    document.querySelectorAll('tr[data-ip]').forEach(row => {
      const ip = row.dataset.ip;
      if (!ip) return;
      row.classList.toggle('ip-row-hidden', hiddenIPs.has(ip));
      const wrap = row.querySelector('.ip-cell-wrap');
      if (wrap) wrap.classList.toggle('ip-blurred', blurredIPs.has(ip) && !hiddenIPs.has(ip));
    });

    // Modal rows — hiddenIPs and blurredIPs both blur the cell there
    document.querySelectorAll('#ipTableBody tr[data-ip]').forEach(row => {
      const ip   = row.dataset.ip;
      const cell = row.querySelector('.ip-cell-modal');
      if (cell) cell.classList.toggle('ip-blurred', hiddenIPs.has(ip) || blurredIPs.has(ip));

      // Update toggle button states
      const hideBtn = row.querySelector('.btn-modal-toggle-hide');
      const blurBtn = row.querySelector('.btn-modal-toggle-blur');
      if (hideBtn) {
        hideBtn.classList.toggle('active', hiddenIPs.has(ip));
        hideBtn.title = hiddenIPs.has(ip) ? 'Mostrar en el panel' : 'Ocultar del panel (modo seguro)';
        hideBtn.innerHTML = hiddenIPs.has(ip)
          ? '<i class="bi bi-x-circle-fill"></i>'
          : '<i class="bi bi-x-circle"></i>';
      }
      if (blurBtn) {
        blurBtn.classList.toggle('active', blurredIPs.has(ip));
        blurBtn.title = blurredIPs.has(ip) ? 'Quitar blur' : 'Blurrear en el panel';
        blurBtn.innerHTML = blurredIPs.has(ip)
          ? '<i class="bi bi-eye-slash-fill"></i>'
          : '<i class="bi bi-eye"></i>';
      }
    });

    renderPills();
  }

  // ── Filter bar pills ─────────────────────────────────────
  function renderPills() {
    renderPillGroup('hiddenIpsPills',  hiddenIPs,  'type-hidden',  LS_HIDDEN,  'addHiddenIpInput',  'addHiddenIpBtn');
    renderPillGroup('blurredIpsPills', blurredIPs, 'type-blurred', LS_BLURRED, 'addBlurredIpInput', 'addBlurredIpBtn');
  }

  function renderPillGroup(containerId, set, pillClass, lsKey, inputId, btnId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.querySelectorAll('.ip-pill').forEach(p => p.remove());

    [...set].forEach(ip => {
      const pill = document.createElement('span');
      pill.className = 'ip-pill ' + pillClass;
      pill.innerHTML = ip + ' <span class="pill-remove" data-ip="' + ip + '">✕</span>';
      pill.querySelector('.pill-remove').addEventListener('click', () => {
        set.delete(ip);
        saveSet(lsKey, set);
        applyAll();
      });
      const inputGroup = container.querySelector('.ip-add-input');
      container.insertBefore(pill, inputGroup);
    });
  }

  // ── Multi-IP input helpers ────────────────────────────────
  function parseIPs(raw) {
    return raw.split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
  }

  function wireInput(inputId, btnId, set, lsKey) {
    const input = document.getElementById(inputId);
    const btn   = document.getElementById(btnId);
    if (!input || !btn) return;

    function addIPs() {
      const ips = parseIPs(input.value);
      if (!ips.length) return;
      ips.forEach(ip => set.add(ip));
      saveSet(lsKey, set);
      input.value = '';
      applyAll();
    }

    btn.addEventListener('click', addIPs);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addIPs(); } });
  }

  wireInput('addHiddenIpInput',  'addHiddenIpBtn',  hiddenIPs,  LS_HIDDEN);
  wireInput('addBlurredIpInput', 'addBlurredIpBtn', blurredIPs, LS_BLURRED);

  // ── Modal toggle buttons (delegated) ─────────────────────
  document.getElementById('ipTableBody')?.addEventListener('click', e => {
    const hideBtn = e.target.closest('.btn-modal-toggle-hide');
    const blurBtn = e.target.closest('.btn-modal-toggle-blur');

    if (hideBtn) {
      e.stopPropagation();
      const ip = hideBtn.dataset.ip;
      if (hiddenIPs.has(ip)) hiddenIPs.delete(ip);
      else                    hiddenIPs.add(ip);
      saveSet(LS_HIDDEN, hiddenIPs);
      applyAll();
    }

    if (blurBtn) {
      e.stopPropagation();
      const ip = blurBtn.dataset.ip;
      if (blurredIPs.has(ip)) blurredIPs.delete(ip);
      else                     blurredIPs.add(ip);
      saveSet(LS_BLURRED, blurredIPs);
      applyAll();
    }
  });

  // Run on load
  applyAll();
})();

// ── IP Geolocation ────────────────────────────────────────
// Collects all unique IPs (table + modal), fetches location once per IP
// via the server-side proxy (avoids CORS), caches in sessionStorage,
// then renders "🇪🇸 Pamplona, Spain" as a clickable link → Google Maps.

(function initGeo() {
  const GEO_CACHE_KEY = 'll_geo_cache';
  const SKIP_IPS      = new Set(['unknown', '127.0.0.1', '::1', '::ffff:127.0.0.1']);
  const DELAY_MS      = 120;

  let cache = {};
  try { cache = JSON.parse(sessionStorage.getItem(GEO_CACHE_KEY) || '{}'); } catch {}

  function saveCache() {
    try { sessionStorage.setItem(GEO_CACHE_KEY, JSON.stringify(cache)); } catch {}
  }

  function mapsUrl(lat, lng, label) {
    if (lat && lng) return 'https://www.google.com/maps?q=' + lat + ',' + lng;
    return 'https://www.google.com/maps/search/' + encodeURIComponent(label);
  }

  function applyGeo(ip, { label, flag, lat, lng }) {
    document.querySelectorAll('.ip-geo[data-ip="' + ip + '"]').forEach(el => {
      if (el.classList.contains('loaded') || el.classList.contains('error')) return;
      const text = (flag ? flag + '\u202F' : '') + label;
      const url  = mapsUrl(lat, lng, label);
      el.textContent  = text;
      el.title        = 'Abrir en Google Maps';
      el.classList.add('loaded');
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        window.open(url, '_blank', 'noopener');
      });
    });
  }

  function applyError(ip) {
    document.querySelectorAll('.ip-geo[data-ip="' + ip + '"]').forEach(el => {
      el.textContent = 'Desconocida';
      el.classList.add('error');
    });
  }

  // Gather unique IPs from ALL .ip-geo elements (table rows + modal rows)
  const geoEls    = document.querySelectorAll('.ip-geo[data-ip]');
  const uniqueIPs = [...new Set([...geoEls].map(el => el.dataset.ip))]
    .filter(ip => ip && !SKIP_IPS.has(ip));

  // Paint cached entries immediately — no flash of "…"
  uniqueIPs.filter(ip => cache[ip]).forEach(ip => {
    if (cache[ip].error) applyError(ip);
    else applyGeo(ip, cache[ip]);
  });

  // Fetch uncached IPs one by one (rate-limit friendly)
  const pending = uniqueIPs.filter(ip => !cache[ip]);

  pending.forEach((ip, i) => {
    setTimeout(async () => {
      try {
        const res  = await fetch('/admin/geo/' + encodeURIComponent(ip));
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        const label = [data.city, data.country_name].filter(Boolean).join(', ') || '—';
        const flag  = data.country_code
          ? String.fromCodePoint(...[...data.country_code.toUpperCase()]
              .map(c => 0x1F1E0 - 65 + c.charCodeAt(0)))
          : '';

        cache[ip] = { label, flag, lat: data.latitude, lng: data.longitude };
        saveCache();
        applyGeo(ip, cache[ip]);
      } catch {
        cache[ip] = { error: true };
        saveCache();
        applyError(ip);
      }
    }, i * DELAY_MS);
  });
})();`;
}

// ══════════════════════════════════════════════════════════
// Styles (extracted as a constant for cleanliness)
// ══════════════════════════════════════════════════════════
const STYLES = `
  :root{--font-body:'Inter',system-ui,sans-serif;--font-mono:'JetBrains Mono',monospace;--clr-bg:#f0f4f8;--clr-surface:#ffffff;--clr-border:#e2e8f0;--clr-text:#1e293b;--clr-muted:#94a3b8;--clr-accent:#3b82f6;--topbar-h:58px;--radius-card:14px;--shadow-card:0 1px 3px rgba(0,0,0,.06),0 4px 16px rgba(0,0,0,.04);}
  *,*::before,*::after{box-sizing:border-box;}
  body{font-family:var(--font-body);background:var(--clr-bg);color:var(--clr-text);font-size:.875rem;margin:0;}
  .font-mono{font-family:var(--font-mono)!important;}
  .topbar{position:fixed;top:0;left:0;right:0;z-index:1040;background:var(--clr-surface);border-bottom:1px solid var(--clr-border);height:var(--topbar-h);display:flex;align-items:center;gap:.6rem;padding:0 1.25rem;box-shadow:0 1px 4px rgba(0,0,0,.06);}
  .topbar-brand{font-weight:700;font-size:1rem;color:var(--clr-text);text-decoration:none;display:flex;align-items:center;gap:.5rem;flex-shrink:0;}
  .topbar-brand .logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:grid;place-items:center;color:#fff;font-size:.85rem;}
  .live-indicator{display:flex;align-items:center;gap:.4rem;font-size:.72rem;color:var(--clr-muted);flex-shrink:0;}
  .live-dot{width:7px;height:7px;border-radius:50%;background:#22c55e;animation:livePulse 2s infinite;}
  @keyframes livePulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.45);}70%{box-shadow:0 0 0 6px rgba(34,197,94,0);}100%{box-shadow:0 0 0 0 rgba(34,197,94,0);}}
  .topbar-right{margin-left:auto;display:flex;align-items:center;gap:.45rem;}
  .refresh-wrap{display:flex;align-items:center;gap:.3rem;font-size:.72rem;color:var(--clr-muted);}
  .refresh-wrap select{font-size:.72rem;padding:2px 6px;border:1px solid var(--clr-border);border-radius:6px;background:var(--clr-surface);color:var(--clr-text);cursor:pointer;}
  #refreshCountdown{font-weight:700;min-width:28px;text-align:right;}
  .page-wrap{max-width:1600px;margin:0 auto;padding:calc(var(--topbar-h) + 1.5rem) 1.25rem 3rem;}
  .stat-card{background:var(--clr-surface);border:1px solid var(--clr-border);border-radius:var(--radius-card);padding:1.1rem 1.3rem;display:flex;align-items:center;gap:1rem;box-shadow:var(--shadow-card);transition:transform .15s,box-shadow .15s,border-color .15s;text-decoration:none;color:inherit;}
  .stat-card:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.1);color:inherit;}
  .stat-card.active-filter{border-color:var(--clr-accent);box-shadow:0 0 0 3px rgba(59,130,246,.18);}
  .stat-icon{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;font-size:1.25rem;flex-shrink:0;}
  .stat-value{font-size:1.7rem;font-weight:700;line-height:1;letter-spacing:-.02em;}
  .stat-label{font-size:.68rem;color:var(--clr-muted);text-transform:uppercase;letter-spacing:.08em;margin-top:3px;}
  .stat-hint{font-size:.6rem;color:#a0aec0;margin-top:2px;}
  .filter-card{background:var(--clr-surface);border:1px solid var(--clr-border);border-radius:var(--radius-card);padding:1.1rem 1.3rem;box-shadow:var(--shadow-card);}
  .filter-card .form-control,.filter-card .form-select{font-size:.82rem;border-color:var(--clr-border);background:#f8fafc;}
  .filter-card .form-control:focus,.filter-card .form-select:focus{background:#fff;border-color:var(--clr-accent);box-shadow:0 0 0 3px rgba(59,130,246,.14);}
  .filter-label{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--clr-muted);margin-bottom:.4rem;}
  .exclude-pill{font-size:.72rem;padding:.25rem .65rem;border-radius:20px;border:1.5px solid var(--clr-border);background:var(--clr-surface);color:var(--clr-text);transition:all .15s;user-select:none;}
  .exclude-pill:hover{border-color:#94a3b8;background:#f1f5f9;}
  .exclude-pill.excluded{background:#fef2f2;border-color:#fca5a5;color:#ef4444;text-decoration:line-through;opacity:.75;}
  .exclude-pill.excluded:hover{opacity:1;}
  .show-pill{font-size:.72rem;padding:.25rem .65rem;border-radius:20px;border:1.5px solid var(--clr-border);background:var(--clr-surface);color:var(--clr-text);transition:all .15s;user-select:none;}
  .show-pill:hover{border-color:#6ee7b7;background:#f0fdf4;}
  .show-pill.shown{background:#f0fdf4;border-color:#6ee7b7;color:#059669;font-weight:600;}
  .show-pill.shown:hover{opacity:.85;}
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
  .ip-code{font-family:var(--font-mono);font-size:.78em;background:#eff6ff;color:#2563eb;padding:2px 7px;border-radius:6px;white-space:nowrap;}
  .ip-clickable{cursor:pointer;transition:background .15s;}
  .ip-clickable:hover{background:#dbeafe;}
  /* ── IP cell wrapper ── */
  .ip-cell-wrap{display:inline-flex;flex-direction:column;gap:2px;}
  /* ── Blurred IP: hover reveals, mouse-out re-blurs ── */
  .ip-cell-wrap.ip-blurred .ip-code,
  .ip-cell-wrap.ip-blurred .ip-geo{filter:blur(7px);user-select:none;transition:filter .2s;pointer-events:none;}
  .ip-cell-wrap.ip-blurred:hover .ip-code,
  .ip-cell-wrap.ip-blurred:hover .ip-geo{filter:none;}
  .ip-cell-wrap.ip-blurred{cursor:default;}
  /* ── Hidden rows: completely removed from view ── */
  tr.ip-row-hidden{display:none!important;}
  /* ── Modal: blurred cell hover reveal ── */
  .ip-cell-modal.ip-blurred .ip-code,
  .ip-cell-modal.ip-blurred .ip-geo-modal{filter:blur(7px);user-select:none;transition:filter .2s;pointer-events:none;}
  .ip-cell-modal.ip-blurred:hover .ip-code,
  .ip-cell-modal.ip-blurred:hover .ip-geo-modal{filter:none;}
  .ip-cell-modal.ip-blurred{cursor:default;}
  /* ── Modal action buttons state ── */
  .btn-modal-toggle-hide{border:1.5px solid #fca5a5;color:#ef4444;background:transparent;}
  .btn-modal-toggle-hide:hover,.btn-modal-toggle-hide.active{background:#fef2f2;border-color:#ef4444;color:#dc2626;}
  .btn-modal-toggle-hide.active{background:#fee2e2;}
  .btn-modal-toggle-blur{border:1.5px solid #c7d2fe;color:#6366f1;background:transparent;}
  .btn-modal-toggle-blur:hover,.btn-modal-toggle-blur.active{background:#eef2ff;border-color:#6366f1;color:#4338ca;}
  .btn-modal-toggle-blur.active{background:#e0e7ff;}
  /* ── IP pills in filter bar ── */
  .ip-pill{display:inline-flex;align-items:center;gap:.4rem;border-radius:20px;padding:.22rem .65rem;font-size:.72rem;font-family:var(--font-mono);transition:border-color .15s;}
  .ip-pill.type-hidden{background:#fef2f2;border:1.5px solid #fca5a5;color:#dc2626;}
  .ip-pill.type-blurred{background:#eef2ff;border:1.5px solid #c7d2fe;color:#4338ca;}
  .ip-pill.type-filter{background:#eff6ff;border:1.5px solid #93c5fd;color:#1d4ed8;}
  .ip-pill .pill-remove{cursor:pointer;font-weight:700;opacity:.6;transition:opacity .15s;font-family:sans-serif;line-height:1;}
  .ip-pill .pill-remove:hover{opacity:1;}
  .ip-add-input .form-control:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.12);}
  .ip-geo{font-family:var(--font-body);font-size:.67rem;color:var(--clr-muted);white-space:nowrap;display:inline-block;margin-top:2px;}
  .ip-geo.loaded{color:#2563eb;cursor:pointer;text-decoration:none;}
  .ip-geo.loaded:hover{text-decoration:underline;color:#1d4ed8;}
  .ip-geo.error{color:#cbd5e1;font-style:italic;cursor:default;}
  .pw-code{font-family:var(--font-mono);font-size:.78em;background:#fff1f2;color:#dc2626;padding:2px 7px;border-radius:6px;word-break:break-all;}
  .pw-toggle{cursor:pointer;transition:background .15s,color .15s;}
  .pw-toggle:hover{filter:brightness(.92);}
  .btn-del{opacity:.3;transition:opacity .15s;}
  tr:hover .btn-del{opacity:.75;}
  .btn-del:hover{opacity:1!important;}
  .pw-strength{height:4px;border-radius:2px;transition:width .3s,background .3s;}
  .ip-filter-badge{display:inline-flex;align-items:center;gap:.35rem;background:#eff6ff;border:1px solid #bfdbfe;color:#2563eb;border-radius:20px;padding:.2rem .65rem;font-size:.72rem;font-family:var(--font-mono);}
  .ip-filter-badge .remove-ip{cursor:pointer;color:#93c5fd;}
  .ip-filter-badge .remove-ip:hover{color:#dc2626;}
  .modal-ip-table td,.modal-ip-table th{font-size:.8rem;padding:.45rem .7rem;vertical-align:middle;}
  .modal-ip-table thead th,.users-table thead th{background:#f8fafc;font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:#64748b;font-weight:700;border-bottom:2px solid #e2e8f0!important;}
  .users-table td,.users-table th{font-size:.82rem;padding:.5rem .75rem;vertical-align:middle;}
  .pagination .page-link{font-size:.78rem;padding:.3rem .65rem;color:var(--clr-accent);}
  .pagination .page-item.active .page-link{background:var(--clr-accent);border-color:var(--clr-accent);}
  .pagination .page-item.disabled .page-link{color:var(--clr-muted);}
  .toast-container{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;}
  .empty-state{padding:4rem 2rem;text-align:center;color:var(--clr-muted);}
  .empty-state .bi{font-size:3rem;color:#cbd5e1;}
  .page-footer{text-align:center;color:var(--clr-muted);font-size:.72rem;padding-top:.75rem;}
  ::-webkit-scrollbar{width:5px;height:5px;}
  ::-webkit-scrollbar-track{background:transparent;}
  ::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px;}`;

module.exports = { buildLogViewerHTML, buildLoggedOutHTML };
