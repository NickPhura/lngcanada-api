const test_helper = require('./test_helper');
const app = test_helper.app;
const decisionFactory = require('./factories/decision_factory').factory;
const applicationFactory = require('./factories/application_factory').factory;
const mongoose = require('mongoose');
const request = require('supertest');
const _ = require('lodash');

const decisionController = require('../controllers/decision.js');
require('../helpers/models/decision');
const Decision = mongoose.model('Decision');

/*************************************
  Mock Route Handlers + Helper Methods
*************************************/

const fieldNames = ['name'];

function paramsWithDecId(req) {
  let params = test_helper.buildParams({ decisionId: req.params.id });
  return test_helper.createSwaggerParams(fieldNames, params);
}

function publicParamsWithDecId(req) {
  let params = test_helper.buildParams({ decisionId: req.params.id });
  return test_helper.createPublicSwaggerParams(fieldNames, params);
}

app.get('/api/decision', function(req, res) {
  let swaggerParams = test_helper.createSwaggerParams(fieldNames);
  return decisionController.protectedGet(swaggerParams, res);
});

app.get('/api/decision/:id', function(req, res) {
  return decisionController.protectedGet(paramsWithDecId(req), res);
});

app.get('/api/public/decision', function(req, res) {
  let publicSwaggerParams = test_helper.createPublicSwaggerParams(fieldNames);
  return decisionController.publicGet(publicSwaggerParams, res);
});

app.get('/api/public/decision/:id', function(req, res) {
  return decisionController.publicGet(publicParamsWithDecId(req), res);
});

app.post('/api/decision/', function(req, res) {
  let extraFields = test_helper.buildParams({ decision: req.body });
  let params = test_helper.createSwaggerParams(fieldNames, extraFields);
  return decisionController.protectedPost(params, res);
});

app.put('/api/decision/:id/publish', function(req, res) {
  return decisionController.protectedPublish(paramsWithDecId(req), res);
});

app.put('/api/decision/:id/unpublish', function(req, res) {
  return decisionController.protectedUnPublish(paramsWithDecId(req), res);
});

app.delete('/api/decision/:id', function(req, res) {
  return decisionController.protectedDelete(paramsWithDecId(req), res);
});

/*************************************
  General Test Data + Helper Methods
*************************************/

const decisionsData = [
  {
    name: 'Special Decision',
    tags: [['public'], ['sysadmin']],
    isDeleted: false
  },
  { name: 'Vanilla Ice Cream', tags: [['public']], isDeleted: false },
  { name: 'Confidential Decision', tags: [['sysadmin']], isDeleted: false },
  { name: 'Deleted Decision', tags: [['public'], ['sysadmin']], isDeleted: true }
];

function setupDecisions(decisionsData) {
  return new Promise(function(resolve, reject) {
    decisionFactory
      .createMany('decision', decisionsData)
      .then(decisionsArray => {
        resolve(decisionsArray);
      })
      .catch(error => {
        reject(error);
      });
  });
}

/*************************************
  Tests
*************************************/

describe('GET /decision', () => {
  test('returns a list of non-deleted, public and sysadmin decision', done => {
    setupDecisions(decisionsData).then(decisions => {
      request(app)
        .get('/api/decision')
        .expect(200)
        .then(response => {
          expect(response.body.length).toEqual(3);

          let firstDecision = _.find(response.body, { name: 'Special Decision' });
          expect(firstDecision).toHaveProperty('_id');
          expect(firstDecision['tags']).toEqual(expect.arrayContaining([['public'], ['sysadmin']]));

          let secondDecision = _.find(response.body, { name: 'Vanilla Ice Cream' });
          expect(secondDecision).toHaveProperty('_id');
          expect(secondDecision['tags']).toEqual(expect.arrayContaining([['public']]));

          let secretDecision = _.find(response.body, { name: 'Confidential Decision' });
          expect(secretDecision).toHaveProperty('_id');
          expect(secretDecision['tags']).toEqual(expect.arrayContaining([['sysadmin']]));
          done();
        });
    });
  });

  test('returns an empty array when there are no decisions', done => {
    request(app)
      .get('/api/decision')
      .expect(200)
      .then(response => {
        expect(response.body.length).toBe(0);
        expect(response.body).toEqual([]);
        done();
      });
  });

  test('can search based on application', done => {
    applicationFactory.create('application', { name: 'Detailed application with decision' }).then(application => {
      let decisionAttrs = {
        _application: application._id,
        name: 'Important Decision'
      };
      decisionFactory.create('decision', decisionAttrs, { public: false }).then(decision => {
        request(app)
          .get('/api/decision')
          .query({ _application: application._id })
          .expect(200)
          .then(response => {
            expect(response.body.length).toBe(1);
            let resultingDecision = response.body[0];
            expect(resultingDecision).not.toBeNull();
            done();
          });
      });
    });
  });
});

describe('GET /decision/{id}', () => {
  test('returns a single Decision ', done => {
    setupDecisions(decisionsData).then(decisions => {
      Decision.findOne({ name: 'Special Decision' })
        .exec()
        .then(decision => {
          const decisionId = decision._id.toString();
          let uri = `/api/decision/${decisionId}`;

          request(app)
            .get(uri)
            .expect(200)
            .then(response => {
              expect(response.body.length).toBe(1);
              let responseObj = response.body[0];
              expect(responseObj).toMatchObject({
                _id: decisionId,
                tags: expect.arrayContaining([['public'], ['sysadmin']]),
                name: 'Special Decision'
              });
              done();
            });
        });
    });
  });
});

describe('GET /public/decision', () => {
  test('returns a list of public decisions', done => {
    setupDecisions(decisionsData).then(decisions => {
      request(app)
        .get('/api/public/decision')
        .expect(200)
        .then(response => {
          expect(response.body.length).toEqual(2);

          let firstDecision = _.find(response.body, { name: 'Special Decision' });
          expect(firstDecision).toHaveProperty('_id');
          expect(firstDecision['tags']).toEqual(expect.arrayContaining([['public'], ['sysadmin']]));

          let secondDecision = _.find(response.body, { name: 'Vanilla Ice Cream' });
          expect(secondDecision).toHaveProperty('_id');
          expect(secondDecision['tags']).toEqual(expect.arrayContaining([['public']]));
          done();
        });
    });
  });

  test('can search based on application', done => {
    applicationFactory.create('application', { name: 'Detailed application with decision' }).then(application => {
      let decisionAttrs = {
        _application: application._id,
        name: 'Important Decision'
      };
      decisionFactory.create('decision', decisionAttrs, { public: true }).then(decision => {
        request(app)
          .get('/api/public/decision')
          .query({ _application: application._id })
          .expect(200)
          .then(response => {
            expect(response.body.length).toBe(1);
            let resultingDecision = response.body[0];
            expect(resultingDecision).not.toBeNull();
            done();
          });
      });
    });
  });

  test('returns an empty array when there are no Decisions', done => {
    request(app)
      .get('/api/public/decision')
      .expect(200)
      .then(response => {
        expect(response.body.length).toBe(0);
        expect(response.body).toEqual([]);
        done();
      });
  });
});

describe('GET /public/decision/{id}', () => {
  test('returns a single public decision ', done => {
    setupDecisions(decisionsData).then(decisions => {
      Decision.findOne({ name: 'Special Decision' }).exec(function(error, decision) {
        if (error) {
          throw error;
        }
        let specialDecisionId = decision._id.toString();
        let uri = '/api/public/decision/' + specialDecisionId;

        request(app)
          .get(uri)
          .expect(200)
          .then(response => {
            expect(response.body.length).toBe(1);
            let responseObj = response.body[0];
            expect(responseObj).toMatchObject({
              _id: specialDecisionId,
              tags: expect.arrayContaining([['public'], ['sysadmin']]),
              name: 'Special Decision'
            });
            done();
          });
      });
    });
  });
});

describe('POST /decision', () => {
  test('creates a new decision', done => {
    let decisionObj = {
      name: 'Victoria'
    };

    request(app)
      .post('/api/decision')
      .send(decisionObj)
      .expect(200)
      .then(response => {
        expect(response.body).toHaveProperty('_id');
        Decision.findById(response.body['_id']).exec(function(error, decision) {
          expect(decision).not.toBeNull();
          expect(decision.name).toBe('Victoria');
          done();
        });
      });
  });

  test('defaults to sysadmin for tags', done => {
    let decisionObj = {
      name: 'Victoria'
    };
    request(app)
      .post('/api/decision')
      .send(decisionObj)
      .expect(200)
      .then(response => {
        expect(response.body).toHaveProperty('_id');
        Decision.findById(response.body['_id']).exec(function(error, decision) {
          expect(decision).not.toBeNull();

          expect(decision.tags.length).toEqual(1);
          expect(decision.tags[0]).toEqual(expect.arrayContaining(['sysadmin']));

          done();
        });
      });
  });
});

describe('PUT /decision/:id', () => {
  let existingDecision;
  beforeEach(() => {
    existingDecision = new Decision({
      name: 'SOME_DECISION'
    });
    return existingDecision.save();
  });

  test('updates a decision', done => {
    let updateData = {
      name: 'SOME_NEW_DECISION'
    };
    let uri = '/api/decision/' + existingDecision._id;
    request(app)
      .put(uri)
      .send(updateData)
      .then(response => {
        Decision.findOne({ name: 'SOME_DECISION' }).exec(function(error, decision) {
          expect(decision).toBeDefined();
          expect(decision).not.toBeNull();
          done();
        });
      });
  });

  test('404s if the decision does not exist', done => {
    let uri = '/api/decision/' + 'NON_EXISTENT_ID';
    request(app)
      .put(uri)
      .send({ name: 'hacker_man', internal: { tags: [] } })
      .expect(404)
      .then(response => {
        done();
      });
  });

  test('does not allow updating tags', done => {
    let existingDecision = new Decision({
      name: 'EXISTING',
      tags: [['sysadmin']]
    });
    let updateData = {
      tags: [['public'], ['sysadmin']]
    };
    existingDecision.save().then(decision => {
      let uri = '/api/decision/' + decision._id;
      request(app)
        .put(uri)
        .send(updateData)
        .then(response => {
          Decision.findById(decision._id).exec(function(error, updatedDecision) {
            expect(updatedDecision.tags.length).toEqual(1);
            expect(updatedDecision.tags[0]).toEqual(expect.arrayContaining(['sysadmin']));

            done();
          });
        });
    });
  });
});

describe('PUT /decision/:id/publish', () => {
  test('publishes a decision', done => {
    let existingDecision = new Decision({
      name: 'EXISTING',
      tags: []
    });
    existingDecision.save().then(decision => {
      let uri = '/api/decision/' + decision._id + '/publish';
      request(app)
        .put(uri)
        .expect(200)
        .send({})
        .then(response => {
          Decision.findOne({ name: 'EXISTING' }).exec(function(error, updatedDecision) {
            expect(updatedDecision).toBeDefined();
            expect(updatedDecision.tags[0]).toEqual(expect.arrayContaining(['public']));
            done();
          });
        });
    });
  });

  test('404s if the decision does not exist', done => {
    let uri = '/api/decision/' + 'NON_EXISTENT_ID' + '/publish';
    request(app)
      .put(uri)
      .send({})
      .expect(404)
      .then(response => {
        done();
      });
  });
});

describe('PUT /decision/:id/unpublish', () => {
  test('unpublishes a decision', done => {
    let existingDecision = new Decision({
      name: 'EXISTING',
      tags: [['public']]
    });
    existingDecision.save().then(decision => {
      let uri = '/api/decision/' + decision._id + '/unpublish';
      request(app)
        .put(uri)
        .expect(200)
        .send({})
        .then(response => {
          Decision.findOne({ name: 'EXISTING' }).exec(function(error, updatedDecision) {
            expect(updatedDecision).toBeDefined();
            expect(updatedDecision.tags[0]).toEqual(expect.arrayContaining([]));
            done();
          });
        });
    });
  });

  test('404s if the decision does not exist', done => {
    let uri = '/api/decision/' + 'NON_EXISTENT_ID' + '/unpublish';
    request(app)
      .put(uri)
      .send({})
      .expect(404)
      .then(response => {
        done();
      });
  });
});

describe('DELETE /decision/id', () => {
  test('It soft deletes a decision', done => {
    setupDecisions(decisionsData).then(decisions => {
      Decision.findOne({ name: 'Vanilla Ice Cream' }).exec(function(error, decision) {
        let vanillaDecisionId = decision._id.toString();
        let uri = '/api/decision/' + vanillaDecisionId;
        request(app)
          .delete(uri)
          .expect(200)
          .then(response => {
            Decision.findOne({ name: 'Vanilla Ice Cream' }).exec(function(error, decision) {
              expect(decision.isDeleted).toBe(true);
              done();
            });
          });
      });
    });
  });

  test('404s if the decision does not exist', done => {
    let uri = '/api/decision/' + 'NON_EXISTENT_ID';
    request(app)
      .delete(uri)
      .expect(404)
      .then(response => {
        done();
      });
  });
});
