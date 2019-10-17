/**
 * This script performs various updates to ACRFD applications in order to keep them up to date with whatever information is in Tantalis (the source of truth).
 *
 * 1. Authenticates with ACRFD
 * 2. Unpublishes retired applications:
 *    a. Fetches all ACRFD applications that have reached a retired state (assumes 6 months is the retirement period), and unpublishes any found.
 * 3. AUthenticates with Tantalis
 * 4. Updates non-deleted ACRFD applications:
 *    a. Fetches all Tantalis applications that have had their status history effective date update within the last 1 week.
 *    b. Fetches all non-deleted ACRFD tantalisIDs.
 *    c. For each ACRFD application with a matching Tantalis application:
 *      i. Updates the ACRFD application features and meta to match whatever is in Tantalis (the source of truth).
 */

// winston logger needs to be created before any local classes that use the logger are loaded.
const defaultLog = require('../api/helpers/logger')('updateShapes');

const Promise = require('es6-promise').Promise;
const _ = require('lodash');
const request = require('request');
const querystring = require('querystring');
const moment = require('moment');
const TTLSUtils = require('../api/helpers/ttlsUtils');
const Actions = require('../api/helpers/actions');

let username = '';
let password = '';
let protocol = 'http';
let host = 'localhost';
let port = '3000';
let uri = '';
let client_id = '';
let grant_type = '';
let auth_endpoint = 'http://localhost:3000/api/login/token';
let _accessToken = '';

const args = process.argv.slice(2);
defaultLog.info('=======================================================');
if (args.length !== 8) {
  defaultLog.error(
    'Please specify proper parameters: <username> <password> <protocol> <host> <port> <client_id> <grant_type> <auth_endpoint>'
  );
  defaultLog.info('Example: node updateShapes.js admin admin http localhost 3000 client_id grant_type auth_endpoint');
  defaultLog.info('=======================================================');
  process.exit(1);
  return;
} else {
  username = args[0];
  password = args[1];
  protocol = args[2];
  host = args[3];
  port = args[4];
  client_id = args[5];
  grant_type = args[6];
  auth_endpoint = args[7];
  uri = protocol + '://' + host + ':' + port + '/';
  defaultLog.info('Using connection:', uri);
  defaultLog.info('-----------------------------------------------');
}

// Used when unpublishing retired applications.
const retiredStatuses = [
  'ABANDONED',
  'CANCELLED',
  'OFFER NOT ACCEPTED',
  'OFFER RESCINDED',
  'RETURNED',
  'REVERTED',
  'SOLD',
  'SUSPENDED',
  'WITHDRAWN',
  'ACTIVE',
  'COMPLETED',
  'DISPOSITION IN GOOD STANDING',
  'EXPIRED',
  'HISTORIC',
  'DISALLOWED'
];

// Used to renew the ACRFD login tokes before it expires if the update script takes longer than the lifespan of the token.
let jwt_login = null; // the ACRFD login token
let jwt_expiry = null; // how long the token lasts before expiring
let jwt_login_time = null; // time we last logged in

/**
 * Logs in to ACRFD.
 *
 * @param {String} username
 * @param {String} password
 * @returns {Promise} promise that resolves with the jwt_login token.
 */
const loginToACRFD = function(username, password) {
  return new Promise((resolve, reject) => {
    const body = querystring.stringify({
      grant_type: grant_type,
      client_id: client_id,
      username: username,
      password: password
    });
    const contentLength = body.length;
    request.post(
      {
        url: auth_endpoint,
        headers: {
          'Content-Length': contentLength,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body
      },
      (error, res, body) => {
        if (error) {
          defaultLog.error(' - loginToACRFD error:', error);
          reject(error);
        } else if (res.statusCode !== 200) {
          defaultLog.warn(' - loginToACRFD response:', res.statusCode, body);
          reject(res.statusCode + ' ' + body);
        } else {
          const data = JSON.parse(body);
          jwt_login = data.access_token;
          jwt_expiry = data.expires_in;
          jwt_login_time = moment();
          resolve(data.access_token);
        }
      }
    );
  });
};

/**
 * Renews the jwt_login token if token expires soon.
 *
 * @returns {Promise}
 */
const renewJWTLogin = function() {
  return new Promise((resolve, reject) => {
    const duration = moment.duration(moment().diff(jwt_login_time)).asSeconds();
    // if less than 60 seconds left before token expiry.
    if (duration > jwt_expiry - 60) {
      defaultLog.info(' - Requesting new ACRFD login token.');
      return loginToACRFD(username, password).then(() => resolve());
    } else {
      resolve();
    }
  });
};

/**
 * Fetches all ACRFD applications that have a retired status AND a statusHistoryEffectiveDate older than 6 months ago.
 *
 * @returns {Promise} promise that resolves with the list of retired applications.
 */
const getApplicationsToUnpublish = function() {
  defaultLog.info(' - fetching retired applications.');
  return new Promise((resolve, reject) => {
    const untilDate = moment().subtract(6, 'months');

    // get all applications that are in a retired status and that have a last status update date older than 6 months ago.
    let queryString = `?statusHistoryEffectiveDate[until]=${untilDate.toISOString()}`;
    retiredStatuses.forEach(status => (queryString += `&status[eq]=${encodeURIComponent(status)}`));

    request.get(
      {
        url: uri + 'api/application' + queryString,
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + jwt_login
        }
      },
      (error, res, body) => {
        if (error) {
          defaultLog.error(' - getApplicationsToUnpublish error:', error);
          reject(error);
        } else if (res.statusCode !== 200) {
          defaultLog.warn(' - getApplicationsToUnpublish response:', res.statusCode, body);
          reject(res.statusCode + ' ' + body);
        } else {
          const data = JSON.parse(body);

          // only return applications that are currently published
          const appsToUnpublish = _.filter(data, app => {
            return Actions.isPublished(app);
          });
          resolve(appsToUnpublish);
        }
      }
    );
  });
};

/**
 * Unpublishes ACRFD applications.
 *
 * @param {*} applicationsToUnpublish array of applications
 * @returns {Promise}
 */
const unpublishApplications = function(applicationsToUnpublish) {
  return applicationsToUnpublish.reduce((previousApp, currentApp) => {
    return previousApp.then(() => {
      return new Promise((resolve, reject) => {
        request.put(
          {
            url: uri + 'api/application/' + currentApp._id + '/unpublish',
            headers: {
              'Content-Type': 'application/json',
              Authorization: 'Bearer ' + jwt_login
            },
            body: JSON.stringify(currentApp)
          },
          (error, res, body) => {
            if (error) {
              defaultLog.error(' - unpublishApplications error:', error);
              reject(error);
            } else if (res.statusCode !== 200) {
              defaultLog.warn(' - unpublishApplications response:', res.statusCode, body);
              reject(res.statusCode + ' ' + body);
            } else {
              defaultLog.info(` - Unpublished application, _id: ${currentApp._id}`);
              const data = JSON.parse(body);
              resolve(data);
            }
          }
        );
      });
    });
  }, Promise.resolve());
};

/**
 * Updates an ACRFD applications features and meta with the latest data from Tantalis.
 *
 * @param {string} acrfdAppID Application _id.
 * @returns {Promise}
 */
const updateACRFDApplication = function(acrfdAppID) {
  return new Promise((resolve, reject) => {
    // only update the ones that aren't deleted
    const url = uri + `api/application/${acrfdAppID}/refresh`;
    request.put(
      {
        url: url,
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + jwt_login
        }
      },
      (error, res, body) => {
        if (error) {
          defaultLog.error(' - updateACRFDApplication error:', error);
          reject(error);
        } else if (res.statusCode !== 200) {
          defaultLog.warn(' - updateACRFDApplication response:', res.statusCode, body);
          reject(res.statusCode + ' ' + body);
        } else {
          let obj = {};
          try {
            obj = JSON.parse(body);
            resolve(obj);
          } catch (e) {
            defaultLog.info(' - updateACRFDApplication parse error:', e);
          }
        }
      }
    );
  });
};

/**
 * Gets all non-deleted ACRFD applications.
 *
 * Note: Only returns _id and tantalisID fields.
 *
 * @returns {Promise} promise that resolves with an array of ACRFD applications.
 */
const getAllACRFDApplicationIDs = function() {
  return new Promise((resolve, reject) => {
    // only update the ones that aren't deleted
    const url = uri + 'api/application/' + '?fields=tantalisID&isDeleted=false';
    request.get(
      {
        url: url,
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer ' + jwt_login
        }
      },
      (error, res, body) => {
        if (error) {
          defaultLog.error(' - getAllACRFDApplicationIDs error:', error);
          reject(error);
        } else if (res.statusCode !== 200) {
          defaultLog.warn(' - getAllACRFDApplicationIDs response:', res.statusCode, body);
          reject(res.statusCode + ' ' + body);
        } else {
          let obj = {};
          try {
            obj = JSON.parse(body);
            resolve(obj);
          } catch (e) {
            defaultLog.info(' - getAllACRFDApplicationIDs parse error:', e);
          }
        }
      }
    );
  });
};

/**
 *  Main call chain that utilizes the above functions to update ACRFD applications.
 */
defaultLog.info('1. Authenticating with ACRFD.');
loginToACRFD(username, password)
  .then(() => {
    defaultLog.info('-----------------------------------------------');
    defaultLog.info('2. Unpublishing retired applications.');
    return getApplicationsToUnpublish().then(applicationsToUnpublish => {
      defaultLog.info(` - found ${applicationsToUnpublish.length} retired applications.`);
      return unpublishApplications(applicationsToUnpublish);
    });
  })
  .then(() => {
    defaultLog.info('-----------------------------------------------');
    defaultLog.info('3. Authenticating with Tantalis.');
    return TTLSUtils.loginWebADE().then(accessToken => {
      defaultLog.info(' - TTLS API login token:', accessToken);
      _accessToken = accessToken;
      return _accessToken;
    });
  })
  .then(() => {
    defaultLog.info('-----------------------------------------------');
    defaultLog.info(
      '4. Fetching all Tantalis applications that have had their status history effective date updated in the last week.'
    );
    const lastWeek = moment()
      .subtract(1, 'week')
      .format('YYYYMMDD');
    return TTLSUtils.getAllApplicationIDs(_accessToken, { updated: lastWeek });
  })
  .then(recentlyUpdatedApplicationIDs => {
    defaultLog.info('-----------------------------------------------');
    defaultLog.info(
      '5. Fetching all non-deleted ACRFD applications and cross referencing with recently updated Tantalis applications.'
    );
    return getAllACRFDApplicationIDs().then(allACRFDApplicationIDs => {
      return allACRFDApplicationIDs
        .filter(acrfdApp => recentlyUpdatedApplicationIDs.includes(acrfdApp.tantalisID))
        .map(acrfdApp => acrfdApp._id);
    });
  })
  .then(applicationIDsToUpdate => {
    defaultLog.info(
      ` - Found ${applicationIDsToUpdate.length} ACRFD Applications with a matching recently updated Tantalis application.`
    );
    // For each ACRFD application with a matching recently updated application from Tantalis, fetch the matching record in ACRFD and update it
    return applicationIDsToUpdate.reduce((previousItem, currentItem) => {
      return previousItem.then(() => {
        defaultLog.info('-----------------------------------------------');
        defaultLog.info(`6. Updating ACRFD Application, _id: ${currentItem}`);
        // Each iteration, check if the ACRFD login token is nearly expired and needs to be re-fetched
        return renewJWTLogin().then(() => {
          return updateACRFDApplication(currentItem);
        });
      });
    }, Promise.resolve());
  })
  .then(() => {
    defaultLog.info('-----------------------------------------------');
    defaultLog.info('Done!');
    defaultLog.info('=======================================================');
  })
  .catch(error => {
    defaultLog.error('-----------------------------------------------');
    defaultLog.error(' - General error:', error);
    defaultLog.error('=======================================================');
    process.exit(1);
  });
