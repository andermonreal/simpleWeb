'use strict';

const rateLimit = require('express-rate-limit');
const { RATE_LIMIT } = require('../config');
const { getClientIP, buildLogEntry } = require('../utils/helpers');
const logger = require('../utils/logger');

const loginLimiter = rateLimit({
  windowMs:     RATE_LIMIT.WINDOW_MS,
  max:          RATE_LIMIT.MAX_REQUESTS,
  keyGenerator: (req) => getClientIP(req),
  handler(req, res) {
    logger.warn('rate_limit_exceeded', { ...buildLogEntry(req), event: 'RATE_LIMIT' });
    res.status(429).json({
      success: false,
      error:   'Demasiados intentos. Espera 15 minutos.',
    });
  },
});

module.exports = { loginLimiter };
