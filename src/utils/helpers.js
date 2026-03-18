'use strict';

/**
 * Resolves the real client IP from common proxy headers.
 * @param {import('express').Request} req
 * @returns {string}
 */
function getClientIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip']        ||
    req.headers['cf-connecting-ip'] ||
    req.headers['true-client-ip']   ||
    req.socket?.remoteAddress       ||
    req.connection?.remoteAddress   ||
    'unknown'
  );
}

/**
 * Builds a base log entry object from the incoming request plus any extras.
 * @param {import('express').Request} req
 * @param {Record<string, unknown>} [extra]
 * @returns {Record<string, unknown>}
 */
function buildLogEntry(req, extra = {}) {
  return {
    ip:       getClientIP(req),
    method:   req.method,
    path:     req.path,
    userAgent: req.headers['user-agent']       || 'unknown',
    referer:   req.headers['referer']          || null,
    language:  req.headers['accept-language']  || null,
    encoding:  req.headers['accept-encoding']  || null,
    origin:    req.headers['origin']           || null,
    host:      req.headers['host']             || null,
    ...extra,
  };
}

/**
 * Encodes a plain-text string to Base64.
 * @param {string} str
 * @returns {string}
 */
function toBase64(str) {
  return Buffer.from(str).toString('base64');
}

/**
 * Escapes HTML special characters to prevent XSS in server-rendered HTML.
 * @param {unknown} value
 * @returns {string}
 */
function escHtml(value) {
  if (value == null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = { getClientIP, buildLogEntry, toBase64, escHtml };
