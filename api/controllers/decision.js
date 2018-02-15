var auth        = require("../helpers/auth");
var _           = require('lodash');
var defaultLog  = require('winston').loggers.get('default');
var mongoose    = require('mongoose');
var Actions     = require('../helpers/actions');
var Utils       = require('../helpers/utils');

exports.protectedOptions = function (args, res, rest) {
  res.status(200).send();
}

exports.publicGet = function (args, res, next) {
  // Build match query if on decisionId route
  var query = {};
  if (args.swagger.params.decisionId) {
    query = Utils.buildQuery("_id", args.swagger.params.decisionId.value, query);
  }
  _.assignIn(query, { isDeleted: false });

  getDecisions(['public'], query, args.swagger.params.fields.value)
  .then(function (data) {
    return Actions.sendResponse(res, 200, data);
  });
};
exports.protectedGet = function(args, res, next) {
  var self        = this;
  self.scopes     = args.swagger.params.auth_payload.scopes;

  var Decision = mongoose.model('Decision');

  defaultLog.info("args.swagger.params:", args.swagger.params.auth_payload.scopes);

  // Build match query if on decisionId route
  var query = {};
  if (args.swagger.params.decisionId) {
    query = Utils.buildQuery("_id", args.swagger.params.decisionId.value, query);
  }
  // Unless they specifically ask for it, hide deleted results.
  if (args.swagger.params.isDeleted && args.swagger.params.isDeleted.value != undefined) {
    _.assignIn(query, { isDeleted: args.swagger.params.isDeleted.value });
  } else {
    _.assignIn(query, { isDeleted: false });
  }

  getDecisions(args.swagger.params.auth_payload.scopes, query, args.swagger.params.fields.value)
  .then(function (data) {
    return Actions.sendResponse(res, 200, data);
  });
};

//  Create a new decision
exports.protectedPost = function (args, res, next) {
  var obj = args.swagger.params.decision.value;
  defaultLog.info("Incoming new object:", obj);

  var Decision = mongoose.model('Decision');
  var decision = new Decision(obj);
  // Define security tag defaults
  decision.tags = [['sysadmin']];
  decision.save()
  .then(function (a) {
    defaultLog.info("Saved new decision object:", a);
    return Actions.sendResponse(res, 200, a);
  });
};

// Update an existing decision
exports.protectedPut = function (args, res, next) {
  var objId = args.swagger.params.decisionId.value;
  defaultLog.info("ObjectID:", args.swagger.params.decisionId.value);

  var obj = args.swagger.params.decision.value;
  // Strip security tags - these will not be updated on this route.
  delete obj.tags;
  defaultLog.info("Incoming updated object:", obj);

  var Decision = require('mongoose').model('Decision');
  Decision.findOneAndUpdate({_id: objId}, obj, {upsert:false, new: true}, function (err, o) {
    if (o) {
      defaultLog.info("o:", o);
      return Actions.sendResponse(res, 200, o);
    } else {
      defaultLog.info("Couldn't find that object!");
      return Actions.sendResponse(res, 404, {});
    }
  });
}

var getDecisions = function (role, query, fields) {
  return new Promise(function (resolve, reject) {
    var Decision = mongoose.model('Decision');
    var projection = {};

    // Fields we always return
    var defaultFields = ['_id',
                        'code',
                        'name',
                        'tags'];
    _.each(defaultFields, function (f) {
        projection[f] = 1;
    });

    // Add requested fields - sanitize first by including only those that we can/want to return
    var sanitizedFields = _.remove(fields, function (f) {
      return (_.indexOf(['name',
                        'code'], f) !== -1);
    });
    _.each(sanitizedFields, function (f) {
      projection[f] = 1;
    });

    Decision.aggregate([
      {
        "$match": query
      },
      {
        "$project": projection
      },
      {
        $redact: {
         $cond: {
            if: {
              $anyElementTrue: {
                    $map: {
                      input: "$tags" ,
                      as: "fieldTag",
                      in: { $setIsSubset: [ "$$fieldTag", role ] }
                    }
                  }
                },
              then: "$$DESCEND",
              else: "$$PRUNE"
            }
          }
        }
    ]).exec()
    .then(function (data) {
      defaultLog.info("data:", data);
      resolve(data);
    });
  });
};