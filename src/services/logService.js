'use strict';

const fs = require('fs');
const { ACCESS_LOG, RELEVANT_EVENTS, LOGIN_EVENT_TYPES } = require('../config');

// ── Raw log I/O ──────────────────────────────────────────

/**
 * Reads and parses all relevant log entries from the access log file.
 * Each returned entry includes its original line index for deletion support.
 * @returns {Array<Record<string, unknown>>}
 */
function readAll() {
  if (!fs.existsSync(ACCESS_LOG)) return [];

  return fs
    .readFileSync(ACCESS_LOG, 'utf-8')
    .split('\n')
    .reduce((acc, raw, i) => {
      try {
        const parsed = JSON.parse(raw);
        if (RELEVANT_EVENTS.includes(parsed.message)) {
          acc.push({ ...parsed, _lineIndex: i });
        }
      } catch { /* skip malformed lines */ }
      return acc;
    }, []);
}

/**
 * Removes a single log line by its index in the access log file.
 * @param {number} lineIndex
 * @returns {boolean} true if the line was found and removed
 */
function deleteLine(lineIndex) {
  if (!fs.existsSync(ACCESS_LOG)) return false;

  const lines = fs.readFileSync(ACCESS_LOG, 'utf-8').split('\n');
  if (lineIndex < 0 || lineIndex >= lines.length) return false;

  lines.splice(lineIndex, 1);
  fs.writeFileSync(ACCESS_LOG, lines.join('\n'), 'utf-8');
  return true;
}

// ── Statistics ───────────────────────────────────────────

/**
 * Computes global stats and per-IP aggregates from a set of log entries.
 * @param {Array<Record<string, unknown>>} logs
 * @returns {import('../types').LogStats}
 */
function computeStats(logs) {
  const loginNormal = logs.filter((l) => l.message === 'login_attempt').length;
  const maxAttempts = logs.filter((l) => l.message === 'max_attempts_redirect').length;

  const ipStats = logs.reduce((acc, l) => {
    if (!l.ip) return acc;
    if (!acc[l.ip]) acc[l.ip] = { total: 0, logins: 0, lastSeen: '' };

    acc[l.ip].total++;
    if (LOGIN_EVENT_TYPES.includes(l.message)) acc[l.ip].logins++;
    if ((l.timestamp || '') > acc[l.ip].lastSeen) acc[l.ip].lastSeen = l.timestamp || '';

    return acc;
  }, {});

  return {
    total:        logs.length,
    loginNormal,
    maxAttempts,
    loginCount:   loginNormal + maxAttempts,
    adminDenied:  logs.filter((l) => l.message === 'admin_access_denied').length,
    rateLimited:  logs.filter((l) => l.message === 'rate_limit_exceeded').length,
    ipStats,
  };
}

// ── Filtering & Pagination ───────────────────────────────

/**
 * @typedef {Object} FilterOptions
 * @property {string} type
 * @property {string} ipFilter
 * @property {string} filter
 * @property {string[]} excludeList
 */

/**
 * Applies all active filters to a log array.
 * @param {Array<Record<string, unknown>>} logs
 * @param {FilterOptions} options
 * @returns {Array<Record<string, unknown>>}
 */
function applyFilters(logs, { type, ipFilter, filter, excludeList }) {
  return logs.filter((l) => {
    if (excludeList.includes(l.message)) return false;
    if (type && type !== 'login_all' && l.message !== type) return false;
    if (type === 'login_all' && !LOGIN_EVENT_TYPES.includes(l.message)) return false;
    if (ipFilter && !(l.ip && l.ip.includes(ipFilter))) return false;
    if (filter && !JSON.stringify(l).toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });
}

/**
 * @typedef {Object} PaginationOptions
 * @property {number} page
 * @property {number} limit
 */

/**
 * @typedef {Object} PaginationResult
 * @property {Array<Record<string, unknown>>} items
 * @property {number} totalFiltered
 * @property {number} totalPages
 * @property {number} currentPage
 */

/**
 * Reverses and paginates a filtered log array.
 * @param {Array<Record<string, unknown>>} logs
 * @param {PaginationOptions} options
 * @returns {PaginationResult}
 */
function paginate(logs, { page, limit }) {
  const reversed      = [...logs].reverse();
  const totalFiltered = reversed.length;
  const totalPages    = Math.max(Math.ceil(totalFiltered / limit), 1);
  const currentPage   = Math.min(page, totalPages);
  const offset        = (currentPage - 1) * limit;

  return {
    items: reversed.slice(offset, offset + limit),
    totalFiltered,
    totalPages,
    currentPage,
  };
}

module.exports = { readAll, deleteLine, computeStats, applyFilters, paginate };
