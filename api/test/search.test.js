const test_helper = require('./test_helper');
const app = test_helper.app;
const request = require('supertest');
const fieldNames = [];
const TTLSUtils = require('../helpers/ttlsUtils');

const searchController = require('../controllers/search.js');
require('../helpers/models/application');
require('../helpers/models/feature');

/*************************************
  Mock Route Handlers + Helper Methods
*************************************/

app.get('/api/ttlsapi/crownLandFileNumber/:id', function(req, res) {
  let extraFields = test_helper.buildParams({ fileNumber: req.params.id });
  let params = test_helper.createSwaggerParams(fieldNames, extraFields);
  return searchController.protectedTTLSGetApplicationsByFileNumber(params, res);
});

app.get('/api/ttlsapi/dispositionTransactionId/:id', function(req, res) {
  let extraFields = test_helper.buildParams({ dtId: req.params.id });
  let params = test_helper.createSwaggerParams(fieldNames, extraFields);
  return searchController.protectedTTLSGetApplicationByDisp(params, res);
});

/*************************************
  General Test Data + Helper Methods
*************************************/

/*************************************
  Tests
*************************************/

describe('GET /api/ttlsapi/crownLandFileNumber/', () => {
  let clFileNumber = 555555;
  const firstResult = { DISPOSITION_TRANSACTION_SID: 111111 };
  const secondResult = { DISPOSITION_TRANSACTION_SID: 222222 };
  const dispSearchResult = {};

  describe('when the ttls api login call returns successfully', () => {
    let loginPromise = new Promise(function(resolve, reject) {
      resolve('ACCESS_TOKEN');
    });

    let appFileNumSearchPromise = new Promise(function(resolve, reject) {
      resolve([firstResult, secondResult]);
    });

    let appDispSearchPromise = new Promise(function(resolve, reject) {
      resolve(dispSearchResult);
    });

    beforeEach(() => {
      spyOn(TTLSUtils, 'loginWebADE').and.returnValue(loginPromise);

      spyOn(TTLSUtils, 'getApplicationByFilenumber').and.returnValue(appFileNumSearchPromise);

      spyOn(TTLSUtils, 'getApplicationByDispositionID').and.returnValue(appDispSearchPromise);
    });

    test('logs in and then searches TTLS by CLFileNumber with that access token', done => {
      request(app)
        .get('/api/ttlsapi/crownLandFileNumber/' + clFileNumber)
        .expect(200)
        .then(response => {
          expect(TTLSUtils.loginWebADE).toHaveBeenCalled();
          expect(TTLSUtils.getApplicationByFilenumber).toHaveBeenCalledWith('ACCESS_TOKEN', '555555');
          done();
        });
    });

    test('searches TTLS getApplicationByDispositionID once for each disp returned by the file number search', done => {
      request(app)
        .get('/api/ttlsapi/crownLandFileNumber/' + clFileNumber)
        .expect(200)
        .then(response => {
          expect(TTLSUtils.getApplicationByFilenumber).toHaveBeenCalledWith('ACCESS_TOKEN', '555555');

          expect(TTLSUtils.getApplicationByDispositionID).toHaveBeenCalledWith('ACCESS_TOKEN', 111111);
          expect(TTLSUtils.getApplicationByDispositionID).toHaveBeenCalledWith('ACCESS_TOKEN', 222222);

          done();
        });
    });

    test('returns the search results from each getAppliationByDispositionID call', done => {
      request(app)
        .get('/api/ttlsapi/crownLandFileNumber/' + clFileNumber)
        .expect(200)
        .then(response => {
          expect(response.body.length).toEqual(2);
          expect(response.body).toEqual([dispSearchResult, dispSearchResult]);

          done();
        });
    });
  });

  describe('when the ttls api login call fails', () => {
    let loginPromise = new Promise(function(resolve, reject) {
      reject({ code: 503, message: 'Ooh boy something went wrong' });
    });

    beforeEach(() => {
      spyOn(TTLSUtils, 'loginWebADE').and.returnValue(loginPromise);
    });

    test('returns that error response', done => {
      request(app)
        .get('/api/ttlsapi/crownLandFileNumber/' + clFileNumber)
        .expect(503)
        .then(response => {
          expect(response.body.message).toEqual('Ooh boy something went wrong');
          done();
        });
    });
  });
});

describe('GET /api/ttlsapi/dispositionTransactionId/', () => {
  let dispositionId = 666666;
  const searchResult = {
    DISPOSITION_TRANSACTION_SID: 666666
  };

  describe('when the ttls api login call returns successfully', () => {
    let loginPromise = new Promise(function(resolve, reject) {
      resolve('ACCESS_TOKEN');
    });

    let appDispSearchPromise = new Promise(function(resolve, reject) {
      resolve(searchResult);
    });

    beforeEach(() => {
      spyOn(TTLSUtils, 'loginWebADE').and.returnValue(loginPromise);

      spyOn(TTLSUtils, 'getApplicationByDispositionID').and.returnValue(appDispSearchPromise);
    });

    test('logs in and then retrieves the application with that access token', done => {
      request(app)
        .get('/api/ttlsapi/dispositionTransactionId/' + dispositionId)
        .expect(200)
        .then(response => {
          expect(TTLSUtils.loginWebADE).toHaveBeenCalled();
          expect(TTLSUtils.getApplicationByDispositionID).toHaveBeenCalledWith('ACCESS_TOKEN', '666666');
          done();
        });
    });
  });

  describe('when the ttls api login call fails', () => {
    let loginPromise = new Promise(function(resolve, reject) {
      reject({ code: 503, message: 'Ooh boy something went wrong' });
    });

    beforeEach(() => {
      spyOn(TTLSUtils, 'loginWebADE').and.returnValue(loginPromise);
    });

    test('returns that error response', done => {
      request(app)
        .get('/api/ttlsapi/dispositionTransactionId/' + dispositionId)
        .expect(503)
        .then(response => {
          expect(response.body.message).toEqual('Ooh boy something went wrong');
          done();
        });
    });
  });
});
