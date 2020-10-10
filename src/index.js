const { createLogger, format, transports } = require('winston');
const config = require('../config');
const app = require('./app');
const { sequelize } = require('./models');
const server = require('http').createServer(app);

const logger = createLogger({
  format: format.combine(format.splat(), format.simple()),
  transports: [new transports.Console()],
});

process.on('unhandledRejection', (reason, p) => {
  logger.error('Unhandled Rejection at: Promise %s %s', p, reason);
});

sequelize.sync({}).then(() => {
  server.on('listening', () => {
    logger.info('server started on %s:%d', config.host, config.port);
  });
  server.listen(config.port);
});
