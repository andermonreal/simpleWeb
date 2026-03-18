'use strict';

const fs     = require('fs');
const bcrypt = require('bcryptjs');

const { USERS_FILE, DEFAULT_ADMIN, BCRYPT_ROUNDS, MIN_PASSWORD_LENGTH } = require('../config');
const logger = require('../utils/logger');

/** @type {Array<{username: string, passHash: string}>} */
let users = [];

// ── Persistence ─────────────────────────────────────────

function load() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
      if (Array.isArray(parsed) && parsed.length > 0) {
        users = parsed;
        logger.info(`✅  ${users.length} usuario(s) admin cargado(s)`);
        return;
      }
    }
  } catch (err) {
    logger.warn('No se pudo cargar admin-users.json', { error: err.message });
  }

  // Fall back to default admin
  users = [{ username: DEFAULT_ADMIN.username, passHash: DEFAULT_ADMIN.passHash }];
  persist();
}

function persist() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
}

// ── Validation ───────────────────────────────────────────

/**
 * @param {string|undefined} password
 * @throws {Error} if password is invalid
 */
function validatePassword(password) {
  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`La contraseña debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres.`);
  }
}

// ── Queries ──────────────────────────────────────────────

function getAll() {
  return users;
}

function getUsernames() {
  return users.map((u) => u.username);
}

/** @returns {{username: string, passHash: string} | undefined} */
function findByUsername(username) {
  return users.find((u) => u.username === username);
}

/**
 * @param {string} username
 * @param {string} password
 * @returns {Promise<boolean>}
 */
async function verifyCredentials(username, password) {
  const user = findByUsername(username);
  if (!user) return false;
  return bcrypt.compare(password || '', user.passHash);
}

// ── Mutations ────────────────────────────────────────────

/**
 * @param {string} username
 * @param {string} password
 * @throws {Error}
 */
async function create(username, password) {
  if (!username) throw new Error('El nombre de usuario es obligatorio.');
  validatePassword(password);
  if (findByUsername(username)) throw new Error(`El usuario "${username}" ya existe.`);

  const passHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  users.push({ username, passHash });
  persist();
}

/**
 * @param {string} username
 * @param {string} newPassword
 * @throws {Error}
 */
async function changePassword(username, newPassword) {
  validatePassword(newPassword);

  const idx = users.findIndex((u) => u.username === username);
  if (idx === -1) throw new Error(`Usuario "${username}" no encontrado.`);

  users[idx].passHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  persist();
}

/**
 * @param {string} username
 * @throws {Error}
 */
function remove(username) {
  if (users.length <= 1) throw new Error('No puedes eliminar el último usuario admin.');

  const idx = users.findIndex((u) => u.username === username);
  if (idx === -1) throw new Error(`Usuario "${username}" no encontrado.`);

  users.splice(idx, 1);
  persist();
}

module.exports = { load, getAll, getUsernames, findByUsername, verifyCredentials, create, changePassword, remove };
