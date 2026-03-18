'use strict';

const fs = require('fs');

const { PORT, LOGS_DIR } = require('./src/config');
const app = require('./src/app');
const logger = require('./src/utils/logger');
const userService = require('./src/services/userService');

// Ensure the logs directory exists before anything tries to write to it
if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}

// Initialise persistent services
userService.load();

// Start HTTP server
app.listen(PORT, () => {
  logger.info('server_start', { event: 'SERVER_STARTED', port: PORT, pid: process.pid });

  console.log(`
🚀  Servidor en      http://localhost:${PORT}
📊  Visor de logs    http://localhost:${PORT}/admin/logs
    (usuario: admin | contraseña: supersecret123)
`);
});
