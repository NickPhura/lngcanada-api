'use strict';
const _ = require('lodash');
const defaultLog = require('./logger')('actions');

exports.publish = function(o) {
  return new Promise(function(resolve, reject) {
    var exists = _.find(o.tags, function(item) {
      return _.isEqual(item, ['public']);
    });

    // Object was already published?
    if (exists) {
      defaultLog.info('HTTP 409, Object already published:', exists);
      reject({
        code: 409,
        message: 'Object already published'
      });
    } else {
      // Add publish, save then return.
      o.tags.push(['public']);
      o.save().then(resolve, function(err) {
        reject({ code: 400, message: err.message });
      });
    }
  });
};

exports.isPublished = function(o) {
  return _.find(o.tags, function(item) {
    return _.isEqual(item, ['public']);
  });
};

exports.unPublish = function(o) {
  return new Promise(function(resolve, reject) {
    var exists = _.remove(o.tags, function(item) {
      return _.isEqual(item, ['public']);
    });
    // Object wasn't already published?
    if (exists.length === 0) {
      defaultLog.info('HTTP 409, Object already unpublished:', exists);
      reject({
        code: 409,
        message: 'Object already unpublished'
      });
    } else {
      o.markModified('tags');
      // Remove publish, save then return.
      o.save().then(resolve, function(err) {
        reject({ code: 400, message: err.message });
      });
    }
  });
};

exports.delete = function(o) {
  return new Promise(function(resolve, reject) {
    _.remove(o.tags, function(item) {
      return _.isEqual(item, ['public']);
    });
    o.isDeleted = true;
    o.markModified('tags');
    o.markModified('isDeleted');
    // save then return.
    o.save().then(resolve, function(err) {
      reject({ code: 400, message: err.message });
    });
  });
};

/**
 * Sends an http response.
 *
 * Note on code param: If no `code` param is provided, `object.code` will be used if exists, or else `500`.
 *
 * @param {*} res an http response
 * @param {number} code an http code (200, 404, etc)
 * @param {*} object the response data.
 * @returns {*} res an http response
 */
exports.sendResponse = function(res, code, object) {
  const httpErrorCode = code || (object && object.code) || 500;
  res.writeHead(httpErrorCode, { 'Content-Type': 'application/json' });
  return res.end(JSON.stringify(object));
};
