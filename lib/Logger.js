const winston = require('winston');

require('dotenv').config();

const knownLevels = ['silly', 'debug', 'info', 'warn', 'error'];
let level = process.env.LOG_LEVEL || 'info';

if (!knownLevels.includes(level)) {
    console.warn(`Using log level "debug" instead of unknown level "${level}"; LOG_LEVEL must be one of `
        + `"${knownLevels.join(', ')}".`)
    level = 'debug';
}

const Logger = winston.createLogger({
    level,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.colorize(),
        winston.format.splat(),
        winston.format.simple(),
    ),
    transports: [new winston.transports.Console()],
});

module.exports = Logger;
