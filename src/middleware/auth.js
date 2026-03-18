'use strict';

const userService = require('../services/userService');
const logger      = require('../utils/logger');
const { buildLogEntry, toBase64 } = require('../utils/helpers');

const REALM = 'Basic realm="Admin Logs"';

/**
 * Express middleware that enforces HTTP Basic Auth using the admin user store.
 * Logs both successful and failed access attempts.
 *
 * @type {import('express').RequestHandler}
 */
async function basicAuth(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader?.startsWith('Basic ')) {
    return rejectUnauthorized(res);
  }

  const decoded  = Buffer.from(authHeader.split(' ')[1], 'base64').toString();
  const colonIdx = decoded.indexOf(':');
  const username = decoded.slice(0, colonIdx);
  const password = decoded.slice(colonIdx + 1);

  const isValid = await userService.verifyCredentials(username, password);

  if (isValid) {
    logger.info('admin_access', { ...buildLogEntry(req), event: 'ADMIN_LOG_VIEW' });
    return next();
  }

  logger.warn('admin_access_denied', {
    ...buildLogEntry(req),
    event:          'ADMIN_UNAUTHORIZED',
    attemptedUser:  username || '(vacío)',
    password:       password ? toBase64(password) : '(vacío)',
    passwordLength: password?.length ?? 0,
  });

  return rejectUnauthorized(res);
}

function rejectUnauthorized(res) {
  res.setHeader('WWW-Authenticate', REALM);
  return res.status(401).send('Credenciales de administrador incorrectas');
}

module.exports = { basicAuth };
