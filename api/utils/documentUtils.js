'use strict';

var clamav = require('clamav.js');

var CLAMAV_SERVICE_HOST = process.env.CLAMAV_SERVICE_HOST || '127.0.0.1';
var CLAMAV_SERVICE_PORT = process.env.CLAMAV_SERVICE_PORT || '3310';

const defaultLog = require('./logger')('documentUtils');

// TODO Make this event driven instead of synchronous?

/**
 * TODO: populate this documentation
 *
 * @param {*} buffer
 * @returns
 */
exports.avScan = function(buffer) {
  return new Promise(function(resolve, reject) {
    var stream = require('stream');
    // Initiate the source
    var bufferStream = new stream.PassThrough();
    // Write your buffer
    bufferStream.end(buffer);

    clamav.ping(CLAMAV_SERVICE_PORT, CLAMAV_SERVICE_HOST, 1000, function(error) {
      if (error) {
        defaultLog.error(`ClamAV service: ${CLAMAV_SERVICE_HOST}:${CLAMAV_SERVICE_PORT} is not available: ${error}`);
        resolve(false);
      } else {
        defaultLog.info(`ClamAV service is alive: ${CLAMAV_SERVICE_HOST}:${CLAMAV_SERVICE_PORT}`);

        clamav
          .createScanner(CLAMAV_SERVICE_PORT, CLAMAV_SERVICE_HOST)
          .scan(bufferStream, function(err, object, malicious) {
            if (error) {
              defaultLog.error('Virus scan error', error);
              resolve(false);
            } else if (malicious) {
              defaultLog.warn('Malicious object FOUND');
              resolve(false);
            } else {
              defaultLog.info('Virus scan OK');
              resolve(true);
            }
          });
      }
    });
  });
};
