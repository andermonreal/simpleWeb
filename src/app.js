'use strict';

const express = require('express');
const helmet  = require('helmet');

const { PUBLIC_DIR } = require('./config');
const logger         = require('./utils/logger');
const { buildLogEntry } = require('./utils/helpers');
const apiRouter      = require('./routes/api');
const adminRouter    = require('./routes/admin');

const app = express();

// ── Security ─────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1);

// ── Body parsing ─────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Static assets ─────────────────────────────────────────
app.use(express.static(PUBLIC_DIR));

// ── Application routes ────────────────────────────────────
app.use('/',       apiRouter);
app.use('/admin',  adminRouter);

// ── Error handlers ────────────────────────────────────────
app.use((req, res) => {
  logger.warn('not_found', { ...buildLogEntry(req), event: '404_NOT_FOUND' });
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error('server_error', { ...buildLogEntry(req), event: '500_SERVER_ERROR', error: err.message });
  res.status(500).json({ error: 'Error interno del servidor' });
});

module.exports = app;
