'use strict';

const winston = require('winston');
const { ACCESS_LOG, ERROR_LOG } = require('../config');

const { combine, timestamp, json, colorize, printf } = winston.format;

const consoleFormat = combine(
  colorize(),
  printf(({ timestamp: ts, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
    return `${ts} [${level}] ${message} ${metaStr}`;
  })
);

const logger = winston.createLogger({
  level: 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    json()
  ),
  transports: [
    new winston.transports.File({
      filename: ACCESS_LOG,
      maxsize:  10 * 1024 * 1024,
      maxFiles: 10,
      tailable: true,
    }),
    new winston.transports.File({
      filename: ERROR_LOG,
      level:    'error',
      maxsize:  5 * 1024 * 1024,
      maxFiles: 5,
      tailable: true,
    }),
    new winston.transports.Console({ format: consoleFormat }),
  ],
});

module.exports = logger;
