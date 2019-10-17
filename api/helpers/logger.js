const moment = require('moment');
const winston = require('winston');

/**
 * Centralized logger that uses Winston 2.x.
 *
 * Note:
 * updating to 3.x will require code changes.
 *
 * Usage:
 * const log = require('./logger')('my label')
 * log.info('Some info!')
 * log.error('An error:', error)
 * ...etc
 *
 * If you wish to print an object, you must JSON.stringify() it first.
 *
 * Valid LOG_LEVEL:
 * error, warn, info, verbose, debug, silly.
 */

const getLogger = function(logLabel) {
  return winston.loggers.get(logLabel || 'default', {
    transports: [
      new winston.transports.Console({
        level: process.env.LOG_LEVEL || 'info',
        label: logLabel || '',
        formatter: info => {
          return `[${moment().format('DD-MM-YYYY HH:mm:ss')}] [${info.level}] (${info.label}): ${info.message}`;
        }
      })
    ]
  });
};

module.exports = label => getLogger(label);
