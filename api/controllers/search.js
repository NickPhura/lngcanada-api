var defaultLog = require('../helpers/logger')('search');
var Actions = require('../helpers/actions');
var TTLSUtils = require('../helpers/ttlsUtils');
var _accessToken = null;

exports.protectedTTLSGetApplicationsByFileNumber = function(args, res, rest) {
  var fileNumber = args.swagger.params.fileNumber.value;
  defaultLog.info('Searching TTLS API for Crown Land FileNumber:', fileNumber);
  return new Promise(function(r, j) {
    return TTLSUtils.loginWebADE()
      .then(function(accessToken) {
        _accessToken = accessToken;
        defaultLog.info('TTLS API Logged in:', _accessToken);
        // fileNumber lookup
        return TTLSUtils.getApplicationByFilenumber(_accessToken, fileNumber);
      })
      .then(r, j);
  })
    .then(function(promises) {
      defaultLog.info('returning number of items:', promises.length);

      // Call the api again but this time grab all the related information on each app
      // returned form the CL file lookup.
      var allApps = [];
      Promise.resolve()
        .then(function() {
          return promises.reduce(function(previousItem, currentItem) {
            return previousItem.then(function() {
              // return Actions.publish(currentItem);
              defaultLog.info('executing disp:', currentItem.DISPOSITION_TRANSACTION_SID);
              return TTLSUtils.getApplicationByDispositionID(
                _accessToken,
                currentItem.DISPOSITION_TRANSACTION_SID
              ).then(function(appData) {
                allApps.push(appData);
                return appData;
              });
            });
          }, Promise.resolve());
        })
        .then(function() {
          // All done with promises in the array, return to the caller.
          defaultLog.debug('search results: ', JSON.stringify(allApps));
          return Actions.sendResponse(res, 200, allApps);
        });
    })
    .catch(function(err) {
      defaultLog.error('protectedTTLSGetApplicationsByFileNumber:', JSON.stringify(err));
      return Actions.sendResponse(res, null, err);
    });
};

exports.protectedTTLSGetApplicationByDisp = function(args, res, rest) {
  var dtId = args.swagger.params.dtId.value;
  defaultLog.info('Searching TTLS API for Disposition Transaction ID:', dtId);
  return new Promise(function(resolve, reject) {
    return TTLSUtils.loginWebADE()
      .then(function(accessToken) {
        _accessToken = accessToken;
        defaultLog.info('TTLS API Logged in:', _accessToken);
        // Disp lookup
        return TTLSUtils.getApplicationByDispositionID(_accessToken, dtId);
      })
      .then(resolve, reject);
  })
    .then(function(data) {
      defaultLog.info('returning:', data.DISPOSITION_TRANSACTION_SID);
      return Actions.sendResponse(res, 200, data);
    })
    .catch(function(err) {
      defaultLog.error('protectedTTLSGetApplicationByDisp:', JSON.stringify(err));
      return Actions.sendResponse(res, null, err);
    });
};

exports.protectedOptions = function(args, res, rest) {
  res.status(200).send();
};
