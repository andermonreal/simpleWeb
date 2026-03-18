'use strict';

const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..', '..');
const LOGS_DIR = path.join(ROOT_DIR, 'logs');

module.exports = Object.freeze({
  PORT: process.env.PORT || 3000,

  // Paths
  LOGS_DIR,
  USERS_FILE: path.join(LOGS_DIR, 'admin-users.json'),
  ACCESS_LOG:  path.join(LOGS_DIR, 'access.log'),
  ERROR_LOG:   path.join(LOGS_DIR, 'error.log'),
  PUBLIC_DIR:  path.join(ROOT_DIR, 'public'),

  // Rate limiting
  RATE_LIMIT: {
    WINDOW_MS:    15 * 60 * 1000,
    MAX_REQUESTS: 20,
  },

  // Security
  BCRYPT_ROUNDS:       12,
  MIN_PASSWORD_LENGTH: 8,

  // Default admin credentials (password: supersecret123)
  DEFAULT_ADMIN: {
    username: 'admin',
    passHash: '$2b$12$CtjIMHgVJWakAJU3V/cWB.V9oHkVYlS/4IyWWyA2eHrrsCsm7tOqu',
  },

  // Log events that are indexed in the viewer
  RELEVANT_EVENTS: Object.freeze([
    'login_attempt',
    'max_attempts_redirect',
    'page_visit',
    'admin_access',
    'admin_access_denied',
    'rate_limit_exceeded',
  ]),

  // Events that are grouped under the "login_all" virtual filter
  LOGIN_EVENT_TYPES: Object.freeze(['login_attempt', 'max_attempts_redirect']),
});
