'use strict';

const app = require('express')();
const fs = require('fs');
const swaggerTools = require('swagger-tools');
const YAML = require('yamljs');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const swaggerConfig = YAML.load('./api/swagger/swagger.yaml');

const defaultLog = require('./api/utils/logger')('app');
const authUtils = require('./api/utils/authUtils');

const UPLOAD_DIR = process.env.UPLOAD_DIRECTORY || './uploads/';
const HOSTNAME = process.env.API_HOSTNAME || 'localhost:3000';
const DB_CONNECTION =
  'mongodb://' +
  (process.env.MONGODB_SERVICE_HOST || process.env.DB_1_PORT_27017_TCP_ADDR || 'localhost') +
  '/' +
  (process.env.MONGODB_DATABASE || 'nrpti-dev');
const DB_USERNAME = process.env.MONGODB_USERNAME || '';
const DB_PASSWORD = process.env.MONGODB_PASSWORD || '';

// Increase post body sizing
app.use(bodyParser.json({ limit: '10mb', extended: true }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

// Enable CORS
app.use(function(req, res, next) {
  defaultLog.info(req.method, req.url);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,Content-Type,Authorization,responseType');
  res.setHeader('Access-Control-Expose-Headers', 'x-total-count');
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.setHeader('Expires', '-1');
  res.setHeader('Pragma', 'no-cache');
  next();
});

// Dynamically set the hostname based on what environment we're in.
swaggerConfig.host = HOSTNAME;

// Swagger UI needs to be told that we only serve https in Openshift
if (HOSTNAME !== 'localhost:3000') {
  swaggerConfig.schemes = ['https'];
}

swaggerTools.initializeMiddleware(swaggerConfig, function(middleware) {
  app.use(middleware.swaggerMetadata());

  const swaggerValidatorConfig = { validateResponse: false };
  app.use(middleware.swaggerValidator(swaggerValidatorConfig));

  const swaggerSecurityConfig = {
    Bearer: authUtils.verifyToken
  };

  app.use(middleware.swaggerSecurity(swaggerSecurityConfig));

  const swaggerRouterConfig = {
    controllers: './api/controllers',
    useStubs: false
  };

  app.use(middleware.swaggerRouter(swaggerRouterConfig));

  const swaggerUIConfig = { apiDocs: '/api/docs', swaggerUi: '/api/docs' };

  app.use(middleware.swaggerUi(swaggerUIConfig));

  // Ensure uploads directory exists, otherwise create it.
  try {
    if (!fs.existsSync(UPLOAD_DIR)) {
      fs.mkdirSync(UPLOAD_DIR);
    }
  } catch (error) {
    defaultLog.info("Couldn't create uploads folder.  Uploads will fail until this is resolved:", error);
  }

  // Load database and models
  const mongooseDBConfig = {
    user: DB_USERNAME,
    pass: DB_PASSWORD,
    reconnectTries: Number.MAX_VALUE, // Never stop trying to reconnect
    reconnectInterval: 500, // Reconnect every 500ms
    poolSize: 10, // Maintain up to 10 socket connections
    // If not connected, return errors immediately rather than waiting for reconnect
    bufferMaxEntries: 0,
    connectTimeoutMS: 10000, // Give up initial connection after 10 seconds
    socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false // https://mongoosejs.com/docs/deprecations.html#-findandmodify-
  };

  defaultLog.info('Attempting to connect to mongo database:', DB_CONNECTION);

  mongoose.connect(encodeURI(DB_CONNECTION), mongooseDBConfig).then(
    () => {
      defaultLog.info('Database connected');

      defaultLog.info('Loading database models');

      // Load database models
      require('./api/models/record');
      require('./api/models/document');

      // Start application
      app.listen(3000, '0.0.0.0', function() {
        defaultLog.info('Started server on port 3000');
      });
    },
    error => {
      defaultLog.info('Mongoose connect error:', error);
      return;
    }
  );
});
