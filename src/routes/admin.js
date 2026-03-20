'use strict';

const express = require('express');
const fs      = require('fs');

const logger          = require('../utils/logger');
const { buildLogEntry } = require('../utils/helpers');
const { basicAuth }   = require('../middleware/auth');
const userService     = require('../services/userService');
const logService      = require('../services/logService');
const { buildLogViewerHTML, buildLoggedOutHTML } = require('../views/logViewer');
const { ACCESS_LOG }  = require('../config');

const router = express.Router();

// ── Admin user management ───────────────────────────────

router.get('/users', basicAuth, (_req, res) => {
  res.json({ users: userService.getUsernames() });
});

router.post('/users', basicAuth, async (req, res) => {
  const { username, password } = req.body;
  try {
    await userService.create(username, password);
    logger.info('admin_user_added', { ...buildLogEntry(req), event: 'ADMIN_USER_ADDED', newUser: username });
    res.json({ success: true, message: `Usuario "${username}" creado.` });
  } catch (err) {
    const status = err.message.includes('ya existe') ? 409 : 400;
    res.status(status).json({ error: err.message });
  }
});

router.put('/users/:username/password', basicAuth, async (req, res) => {
  const { username } = req.params;
  const { password }  = req.body;
  try {
    await userService.changePassword(username, password);
    logger.info('admin_password_changed', { ...buildLogEntry(req), event: 'ADMIN_PASS_CHANGED', user: username });
    res.json({ success: true, message: `Contraseña de "${username}" actualizada.` });
  } catch (err) {
    const status = err.message.includes('no encontrado') ? 404 : 400;
    res.status(status).json({ error: err.message });
  }
});

router.delete('/users/:username', basicAuth, (req, res) => {
  const { username } = req.params;
  try {
    userService.remove(username);
    logger.info('admin_user_deleted', { ...buildLogEntry(req), event: 'ADMIN_USER_DELETED', user: username });
    res.json({ success: true, message: `Usuario "${username}" eliminado.` });
  } catch (err) {
    const status = err.message.includes('no encontrado') ? 404 : 400;
    res.status(status).json({ error: err.message });
  }
});

// ── Log viewer ──────────────────────────────────────────

router.get('/logs', basicAuth, (req, res) => {
  const options = parseLogQueryOptions(req.query);

  const allLogs = logService.readAll();
  const stats   = logService.computeStats(allLogs);
  const filtered = logService.applyFilters(allLogs, options);
  const { items, totalFiltered, totalPages, currentPage } = logService.paginate(filtered, options);

  res.send(buildLogViewerHTML({
    lines: items,
    ...options,
    page: currentPage,
    totalPages,
    totalFiltered,
    globalStats: stats,
    ipStats: stats.ipStats,
  }));
});

router.get('/logs/download', basicAuth, (req, res) => {
  if (!fs.existsSync(ACCESS_LOG)) return res.status(404).send('No hay logs disponibles.');
  res.download(ACCESS_LOG, 'access.log');
});

router.delete('/logs/line/:index', basicAuth, (req, res) => {
  const lineIndex = parseInt(req.params.index, 10);
  if (isNaN(lineIndex)) return res.status(400).json({ error: 'Índice inválido.' });

  const deleted = logService.deleteLine(lineIndex);
  if (!deleted) return res.status(404).json({ error: 'Línea no encontrada.' });

  res.json({ success: true });
});

// ── Geo proxy ───────────────────────────────────────────
// Fetches IP geolocation server-side to avoid CORS restrictions.
// Results are NOT cached here — the client handles its own sessionStorage cache.

const SKIP_GEO_IPS = new Set(['unknown', '127.0.0.1', '::1', '::ffff:127.0.0.1']);

router.get('/geo/:ip', basicAuth, async (req, res) => {
  const { ip } = req.params;

  if (!ip || SKIP_GEO_IPS.has(ip)) {
    return res.json({ city: null, country_name: null, country_code: null });
  }

  try {
    const upstream = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      headers: { 'User-Agent': 'login-logger/1.0' },
      signal: AbortSignal.timeout(5000),
    });

    if (!upstream.ok) throw new Error(`ipapi.co responded ${upstream.status}`);

    const data = await upstream.json();

    if (data.error) throw new Error(data.reason || 'lookup failed');

    res.json({
      city:         data.city         || null,
      country_name: data.country_name || null,
      country_code: data.country_code || null,
      latitude:     data.latitude     || null,
      longitude:    data.longitude    || null,
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// ── Session ─────────────────────────────────────────────

/**
 * Sending invalid credentials forces the browser to clear its saved Basic Auth.
 * The client then navigates to /admin/logged-out to confirm.
 */
router.get('/logout-clear', (_req, res) => {
  res.setHeader('WWW-Authenticate', 'Basic realm="Admin Logs"');
  res.status(401).send('logged out');
});

router.get('/logged-out', (req, res) => {
  logger.info('admin_logout', { ...buildLogEntry(req), event: 'ADMIN_LOGOUT' });
  res.send(buildLoggedOutHTML());
});

// ── Helpers ──────────────────────────────────────────────

/**
 * Normalises and validates query-string options for the log viewer.
 * @param {import('qs').ParsedQs} query
 */
function parseLogQueryOptions(query) {
  const excludeRaw = query.exclude;
  const showRaw    = query.show;

  return {
    limit:       Math.min(Math.max(parseInt(query.limit) || 50, 1), 500),
    page:        Math.max(parseInt(query.page) || 1, 1),
    filter:      String(query.filter || ''),
    type:        String(query.type   || ''),
    ipFilter:    String(query.ip     || ''),
    excludeList: excludeRaw
      ? (Array.isArray(excludeRaw) ? excludeRaw : [excludeRaw])
      : [],
    showList: showRaw
      ? (Array.isArray(showRaw) ? showRaw : [showRaw])
      : [],
  };
}

module.exports = router;
