'use strict';

/**
 * This file contains various utility functions for working with Tantalis and Tantalis data.
 */

const _ = require('lodash');
const mongoose = require('mongoose');
const qs = require('qs');
const request = require('request');
const turf = require('@turf/turf');
const helpers = require('@turf/helpers');
const spatialUtils = require('./spatialUtils');
const defaultLog = require('./logger')('ttlsUtils');

let tantalisAPI =
  process.env.TTLS_API_ENDPOINT ||
  'https://t1api.nrs.gov.bc.ca/ttls-api/v1/' ||
  'https://api.nrs.gov.bc.ca/ttls-api/v1/';
let webADEAPI =
  process.env.WEBADE_AUTH_ENDPOINT ||
  'https://t1api.nrs.gov.bc.ca/oauth2/v1/' ||
  'https://api.nrs.gov.bc.ca/oauth2/v1/';
let username = process.env.WEBADE_USERNAME || 'ACRFD_SERVICE_CLIENT' || 'TTLS-EXT';
let password = process.env.WEBADE_PASSWORD;

// WebADE Login
exports.loginWebADE = function() {
  // Login to webADE and return access_token for use in subsequent calls.
  return new Promise(function(resolve, reject) {
    const url = webADEAPI + 'oauth/token?grant_type=client_credentials&disableDeveloperFilter=true&scope=TTLS.*';

    defaultLog.debug('WebADE Login url:', url);

    request.get(
      {
        url,
        headers: {
          Authorization: 'Basic ' + Buffer.from(username + ':' + password).toString('base64')
        }
      },
      function(err, res, body) {
        if (err) {
          defaultLog.error('WebADE Login Error:', err);
          reject(err);
        } else if (res && res.statusCode !== 200) {
          defaultLog.warn('WebADE Login Response:', res.statusCode, body);
          reject({ code: (res && res.statusCode) || null });
        } else {
          try {
            var obj = JSON.parse(body);
            defaultLog.debug('o:', JSON.stringify(obj));
            if (obj && obj.access_token) {
              resolve(obj.access_token);
            } else {
              reject();
            }
          } catch (e) {
            defaultLog.error('WebADE Login Error:', e);
            reject(e);
          }
        }
      }
    );
  });
};

/**
 * Fetches all applications by crown land file number.
 *
 * @param {string} accessToken Tantalis bearer token
 * @param {string} dispositionID disposition ID
 * @param {number} [pageNumber=1] page number
 * @param {number} [pageRowCount=100] records per page
 * @returns {Promise} promise that resolves with a single application
 */
exports.getApplicationByFilenumber = function(accessToken, clFile, pageNumber = 1, pageRowCount = 100) {
  return new Promise(function(resolve, reject) {
    const url =
      tantalisAPI +
      'landUseApplications' +
      `?fileNumber=${clFile}&pageNumber=${pageNumber}&pageRowCount=${pageRowCount}`;

    defaultLog.info('Looking up tantalis applications by crown land file number:', url);

    request.get(
      {
        url,
        auth: {
          bearer: accessToken
        }
      },
      function(err, res, body) {
        if (err) {
          defaultLog.error('TTLS API Error:', err);
          reject(err);
        } else if (res && res.statusCode !== 200) {
          defaultLog.warn('TTLS API Response:', res.statusCode, body);
          reject({ code: (res && res.statusCode) || null });
        } else {
          try {
            var obj = JSON.parse(body);
            defaultLog.debug('o:', JSON.stringify(obj));
            var applications = [];
            if (obj && obj.elements && obj.elements.length > 0) {
              for (let app of obj.elements) {
                var application = {};
                application.TENURE_PURPOSE = app.purposeCode && app.purposeCode['description'];
                application.TENURE_SUBPURPOSE =
                  app.purposeCode &&
                  app.purposeCode.subPurposeCodes &&
                  app.purposeCode.subPurposeCodes[0] &&
                  app.purposeCode.subPurposeCodes[0]['description'];
                application.TENURE_TYPE = app.landUseTypeCode && app.landUseTypeCode['description'];
                application.TENURE_SUBTYPE =
                  app.landUseTypeCode &&
                  app.landUseTypeCode.landUseSubTypeCodes &&
                  app.landUseTypeCode.landUseSubTypeCodes[0] &&
                  app.landUseTypeCode.landUseSubTypeCodes[0]['description'];
                application.TENURE_STATUS = app.statusCode && app.statusCode['description'];
                application.TENURE_REASON = app.reasonCode && app.reasonCode['description'];
                application.TENURE_STAGE = app.stageCode && app.stageCode['description'];
                application.TENURE_LOCATION = app.locationDescription;
                application.RESPONSIBLE_BUSINESS_UNIT = app.businessUnit && app.businessUnit.name;
                application.CROWN_LANDS_FILE = app.fileNumber;
                application.DISPOSITION_TRANSACTION_SID = app.landUseApplicationId;
                applications.push(application);
              }
            } else {
              defaultLog.info('No results found.');
            }
            resolve(applications);
          } catch (e) {
            defaultLog.error('Object Parsing Failed:', e);
            reject(e);
          }
        }
      }
    );
  });
};

/**
 * Fetches an application by its disposition ID.
 *
 * @param {string} accessToken Tantalis bearer token
 * @param {string} dispositionID disposition ID
 * @param {number} [pageNumber=1] page number (optional)
 * @param {number} [pageRowCount=100] records per page (optional)
 * @returns {Promise} promise that resolves with a single application
 */
exports.getApplicationByDispositionID = function(accessToken, dispositionID, pageNumber = 1, pageRowCount = 100) {
  return new Promise(function(resolve, reject) {
    const url =
      tantalisAPI + 'landUseApplications/' + dispositionID + `?pageNumber=${pageNumber}&pageRowCount=${pageRowCount}`;

    defaultLog.info('Looking up tantalis applications by disposition id:', url);

    request.get(
      {
        url,
        auth: {
          bearer: accessToken
        }
      },
      function(err, res, body) {
        if (err) {
          defaultLog.error('TTLS API Error:', err);
          reject(err);
        } else if (res && res.statusCode !== 200) {
          defaultLog.warn('TTLS API Response:', res.statusCode, body);
          reject({ code: (res && res.statusCode) || null });
        } else {
          try {
            var obj = JSON.parse(body);
            defaultLog.debug('o:', JSON.stringify(obj));
            var application = {};
            if (obj) {
              // Setup the application object.
              application.TENURE_PURPOSE = obj.purposeCode && obj.purposeCode['description'];
              application.TENURE_SUBPURPOSE =
                obj.purposeCode &&
                obj.purposeCode.subPurposeCodes &&
                obj.purposeCode.subPurposeCodes[0] &&
                obj.purposeCode.subPurposeCodes[0]['description'];
              application.TENURE_TYPE = obj.landUseTypeCode && obj.landUseTypeCode['description'];
              application.TENURE_SUBTYPE =
                obj.landUseTypeCode &&
                obj.landUseTypeCode.landUseSubTypeCodes &&
                obj.landUseTypeCode.landUseSubTypeCodes[0] &&
                obj.landUseTypeCode.landUseSubTypeCodes[0]['description'];
              application.TENURE_STATUS = obj.statusCode && obj.statusCode['description'];
              application.TENURE_REASON = obj.reasonCode && obj.reasonCode['description'];
              application.TENURE_STAGE = obj.stageCode && obj.stageCode['description'];
              application.TENURE_LOCATION = obj.locationDescription;
              application.RESPONSIBLE_BUSINESS_UNIT = obj.businessUnit && obj.businessUnit.name;
              application.CROWN_LANDS_FILE = obj.fileNumber;
              application.DISPOSITION_TRANSACTION_SID = dispositionID;
              application.parcels = [];
              application.interestedParties = [];
              application.statusHistoryEffectiveDate =
                obj.statusHistory && obj.statusHistory[0] != null
                  ? new Date(obj.statusHistory[0].effectiveDate) // convert Unix Epoch Time (ms)
                  : null;

              // WKT conversion to GEOJSON
              for (let geo of obj.interestParcels) {
                if (geo.wktGeometry) {
                  var feature = {};
                  feature.TENURE_LEGAL_DESCRIPTION = geo.legalDescription;
                  feature.TENURE_AREA_IN_HECTARES = geo.areaInHectares;
                  feature.INTRID_SID = geo.interestParcelId;
                  feature.FEATURE_CODE = geo.featureCode;
                  feature.FEATURE_AREA_SQM = geo.areaInSquareMetres;
                  feature.FEATURE_LENGTH_M = geo.areaLengthInMetres;
                  feature.TENURE_EXPIRY = geo.expiryDate;

                  var crs = {};
                  crs.properties = {};
                  crs.properties.name = 'urn:ogc:def:crs:EPSG::4326';

                  const geometryArray = spatialUtils.getGeometryArray(geo);

                  // geometryArray.forEach(geometry => {
                  application.parcels.push({
                    type: 'Feature',
                    // NB: always store as GeometryCollection - this is currently the simplest way of handling
                    // both regular Geometry {Polygon}, {Line}, {etc} AND GeometryCollection [{Polygon}, {Line}, {etc}]
                    // types without introducing new mongo collections and code to handle the fact that
                    // GeometryCollections have a different spec than the regular Geometry types.
                    geometry: { type: 'GeometryCollection', geometries: geometryArray },
                    properties: feature,
                    crs: crs
                  });
                  // });
                }
              }

              // Calculate areaHectares, prepare centroid calculation
              var centroids = helpers.featureCollection([]);
              application.areaHectares = 0.0;
              _.each(application.parcels, function(f) {
                // Get the polygon and put it for later centroid calculation
                if (f.geometry) {
                  centroids.features.push(turf.centroid(f));
                }

                if (f.properties && f.properties.TENURE_AREA_IN_HECTARES) {
                  application.areaHectares += parseFloat(f.properties.TENURE_AREA_IN_HECTARES);
                }
              });

              // Centroid of all the shapes.
              if (centroids.features.length > 0) {
                application.centroid = turf.centroid(centroids).geometry.coordinates;
              }

              // Interested Parties
              for (let party of obj.interestedParties) {
                var partyObj = {};
                partyObj.interestedPartyType = party.interestedPartyType;

                if (party.interestedPartyType == 'I') {
                  partyObj.firstName = party.individual && party.individual.firstName;
                  partyObj.lastName = party.individual && party.individual.lastName;
                } else {
                  // party.interestedPartyType == 'O'
                  partyObj.legalName = party.organization && party.organization.legalName;
                  partyObj.divisionBranch = party.organization && party.organization.divisionBranch;
                }
                // Check if we've already added this.
                if (!_.includes(application.interestedParties, partyObj)) {
                  application.interestedParties.push(partyObj);
                }
              }
              resolve(application);
            } else {
              defaultLog.info('Nothing found.');
              resolve(null);
            }
          } catch (e) {
            defaultLog.error('Object Parsing Failed:', e);
            reject(e);
          }
        }
      }
    );
  });
};

/**
 * Fetches all application landUseApplicationIds (aka: dispositionID, tantalisID) from Tantalis given the filter params provided.
 *
 * @param {string} accessToken Tantalis API access token. (required)
 * @param {object} [filterParams={}] Object containing Tantalis query filters. See Tantalis API Spec. (optional)
 * @returns an array of matching Tantalis IDs.
 */
exports.getAllApplicationIDs = function(accessToken, filterParams = {}) {
  return new Promise(function(resolve, reject) {
    try {
      internalGetAllApplicationIDs(accessToken, filterParams).then(applicationIDs => {
        defaultLog.info(`found ${applicationIDs.length} applications.`);
        resolve(applicationIDs);
      });
    } catch (error) {
      defaultLog.error('getAllApplicationIDs error:', error);
      reject(error);
    }
  });
};

/**
 * Recursively Fetches all pages of application landUseApplicationIds (aka: dispositionID, tantalisID) from Tantalis given the filter params provided.
 *
 * @param {*} accessToken Tantalis API access token. (required)
 * @param {*} [filterParams={}] Object containing Tantalis query filters. See Tantalis API Spec. (optional)
 * @param {number} [pageNumber=1] pagination - page number (optional)
 * @param {number} [pageRowCount=100] pagination - records per page (optional)
 * @param {*} [applicationIDs=[]] array to store application ids, necessary to support recursive calls (optional)
 * @returns {*} applicationIDs array of application IDs
 */
const internalGetAllApplicationIDs = function(
  accessToken,
  filterParams = {},
  pageNumber = 1,
  pageRowCount = 100, // fetch the maximum number of results each time
  applicationIDs = []
) {
  return new Promise(function(resolve, reject) {
    const url =
      tantalisAPI +
      'landUseApplications' +
      `?${qs.stringify(filterParams)}` +
      `&pageNumber=${pageNumber}` +
      `&pageRowCount=${pageRowCount}`;

    defaultLog.info('Looking up all tantalis applications:', url);

    request.get(
      {
        url,
        auth: {
          bearer: accessToken
        }
      },
      function(err, res, body) {
        if (err) {
          defaultLog.error('TTLS API Error:', err);
          reject(err);
        } else if (res && res.statusCode !== 200) {
          defaultLog.warn('TTLS API Response:', res.statusCode, body);
          reject({ code: (res && res.statusCode) || null });
        } else {
          try {
            var obj = JSON.parse(body);
            defaultLog.debug('o:', JSON.stringify(obj));
            _.forEach(obj.elements, function(element) {
              if (element) {
                applicationIDs.push(element.landUseApplicationId);
              }
            });

            resolve({ applicationIDs: applicationIDs, totalRowCount: obj.totalRowCount });
          } catch (error) {
            defaultLog.error('internalGetAllApplicationIDs error:', error);
            reject(error);
          }
        }
      }
    );
  }).then(paginatedApplications => {
    defaultLog.debug('internalGetAllApplicationIDs: ', JSON.stringify(paginatedApplications));

    if (paginatedApplications.totalRowCount > paginatedApplications.applicationIDs.length) {
      // if total count > current application count, increment the pagination and fetch more results.
      return internalGetAllApplicationIDs(
        accessToken,
        filterParams,
        ++pageNumber,
        pageRowCount,
        paginatedApplications.applicationIDs
      );
    }

    // if all pages of results have been collected
    return Promise.resolve(applicationIDs);
  });
};

/**
 * Given an ACRFD applications tantalisID (disposition ID), makes all necessary calls to update it with the latest information from Tantalis.
 *
 * @param {string} applicationToUpdate an Application
 * @param {string} ttlsAccessToken a tantalis api bearer token
 * @returns {Promise}
 */
exports.updateApplication = function(applicationToUpdate) {
  return this.loginWebADE().then(ttlsAccessToken => {
    return this.getApplicationByDispositionID(ttlsAccessToken, applicationToUpdate.tantalisID).then(tantalisApp => {
      if (!tantalisApp) {
        defaultLog.warn('updateApplication - no Tantalis application found - not updating.');
        return Promise.resolve();
      }

      return deleteAllApplicationFeatures(applicationToUpdate)
        .then(() => {
          return updateFeatures(applicationToUpdate, tantalisApp);
        })
        .then(updatedApplicationAndFeatures => {
          return updateApplicationMeta(updatedApplicationAndFeatures.application, tantalisApp).then(
            updatedApplication => {
              return Promise.resolve({
                application: updatedApplication,
                features: updatedApplicationAndFeatures.features
              });
            }
          );
        });
    });
  });
};

/**
 * Deletes the existing application features.
 *
 * @param {Application} applicationObjectID Application ObjectID
 * @returns {Promise}
 */
const deleteAllApplicationFeatures = function(applicationObjectID) {
  return new Promise(function(resolve, reject) {
    const featureModel = mongoose.model('Feature');
    featureModel.deleteMany({ applicationID: applicationObjectID }, function(error, data) {
      if (error) {
        defaultLog.error('deleteAllApplicationFeatures:', error);
        reject(error);
      }

      resolve(data);
    });
  });
};

/**
 * Updates and saves the application features.
 *
 * @param {Application} acrfdApp application as it exists in ACRFD
 * @param {Application} tantalisApp application with the latest values from Tantalis
 * @returns {Promise} promise that resolves wih the updated ACRFD application and features, in the form:
 *                   { application: updatedApplication, features: [updatedFeature] }
 */
const updateFeatures = function(acrfdApp, tantalisApp) {
  return new Promise(function(resolve, reject) {
    // defaultLog.info("returning:", tantalisApp);
    // Store the features in the DB
    let allFeaturesForDisp = [];
    acrfdApp.areaHectares = tantalisApp.areaHectares;

    let turf = require('@turf/turf');
    let helpers = require('@turf/helpers');

    let centroids = helpers.featureCollection([]);
    _.each(tantalisApp.parcels, function(f) {
      // Tags default public
      f.tags = [['sysadmin'], ['public']];
      // copy in all the app meta just to stay consistent.
      f.properties.RESPONSIBLE_BUSINESS_UNIT = tantalisApp.RESPONSIBLE_BUSINESS_UNIT;
      f.properties.TENURE_PURPOSE = tantalisApp.TENURE_PURPOSE;
      f.properties.TENURE_SUBPURPOSE = tantalisApp.TENURE_SUBPURPOSE;
      f.properties.TENURE_STATUS = tantalisApp.TENURE_STATUS;
      f.properties.TENURE_REASON = tantalisApp.TENURE_REASON;
      f.properties.TENURE_TYPE = tantalisApp.TENURE_TYPE;
      f.properties.TENURE_STAGE = tantalisApp.TENURE_STAGE;
      f.properties.TENURE_SUBTYPE = tantalisApp.TENURE_SUBTYPE;
      f.properties.TENURE_LOCATION = tantalisApp.TENURE_LOCATION;
      f.properties.DISPOSITION_TRANSACTION_SID = tantalisApp.DISPOSITION_TRANSACTION_SID;
      f.properties.CROWN_LANDS_FILE = tantalisApp.CROWN_LANDS_FILE;

      allFeaturesForDisp.push(f);
      // Get the polygon and put it for later centroid calculation
      centroids.features.push(turf.centroid(f));
    });
    // Centroid of all the shapes.
    if (centroids.features.length > 0) {
      acrfdApp.centroid = turf.centroid(centroids).geometry.coordinates;
    }
    acrfdApp.client = '';
    for (let [idx, client] of Object.entries(tantalisApp.interestedParties)) {
      if (idx > 0) {
        acrfdApp.client += ', ';
      }
      if (client.interestedPartyType == 'O') {
        acrfdApp.client += client.legalName;
      } else {
        acrfdApp.client += client.firstName + ' ' + client.lastName;
      }
    }
    acrfdApp.statusHistoryEffectiveDate = tantalisApp.statusHistoryEffectiveDate;

    const updatedFeatures = [];
    Promise.resolve()
      .then(function() {
        return allFeaturesForDisp.reduce(function(previousFeature, currentFeature) {
          return previousFeature.then(function() {
            return saveFeature(currentFeature, acrfdApp._id).then(updatedFeature => {
              updatedFeature.forEach(element => {
                updatedFeatures.push(element);
              });
            });
          });
        }, Promise.resolve());
      })
      .then(function() {
        resolve({ application: acrfdApp, features: updatedFeatures });
      });
  });
};

/**
 * Creates a feature.
 *
 * @param {Feature} feature Feature object
 * @param {String} acrfdapplicationObjectIDAppId Application ObjectID
 * @returns {Promise}
 */
const saveFeature = function(feature, applicationObjectID) {
  return new Promise(function(resolve, reject) {
    feature.applicationID = applicationObjectID;

    // Define security tag defaults.  Default public and sysadmin.
    feature.tags = [['sysadmin'], ['public']];

    var featureModel = require('mongoose').model('Feature');
    featureModel.create([feature], { upsert: false, new: true }, function(error, updatedFeature) {
      if (error) {
        defaultLog.error('saveFeature:', error);
        reject(error);
      }

      resolve(updatedFeature);
    });
  });
};

/**
 * Updates and saves the ACRFD application meta.
 *
 * @param {Application} acrfdApp
 * @param {Object} tantalisApp
 * @returns
 */
const updateApplicationMeta = function(acrfdApp, tantalisApp) {
  return new Promise(function(resolve, reject) {
    let updatedAppObject = {};
    updatedAppObject.businessUnit = tantalisApp.RESPONSIBLE_BUSINESS_UNIT;
    updatedAppObject.purpose = tantalisApp.TENURE_PURPOSE;
    updatedAppObject.subpurpose = tantalisApp.TENURE_SUBPURPOSE;
    updatedAppObject.status = tantalisApp.TENURE_STATUS;
    updatedAppObject.reason = tantalisApp.TENURE_REASON;
    updatedAppObject.type = tantalisApp.TENURE_TYPE;
    updatedAppObject.tenureStage = tantalisApp.TENURE_STAGE;
    updatedAppObject.subtype = tantalisApp.TENURE_SUBTYPE;
    updatedAppObject.location = tantalisApp.TENURE_LOCATION;
    updatedAppObject.legalDescription = tantalisApp.TENURE_LEGAL_DESCRIPTION;
    updatedAppObject.centroid = acrfdApp.centroid;
    updatedAppObject.areaHectares = acrfdApp.areaHectares;
    updatedAppObject.client = acrfdApp.client;
    updatedAppObject.statusHistoryEffectiveDate = acrfdApp.statusHistoryEffectiveDate;

    const ApplicationModel = mongoose.model('Application');
    ApplicationModel.findOneAndUpdate({ _id: acrfdApp._id }, updatedAppObject, { new: true }, function(
      error,
      updatedApp
    ) {
      if (error) {
        defaultLog.error('updateApplicationMeta:', error);
        reject(error);
      }

      resolve(updatedApp);
    });
  });
};
