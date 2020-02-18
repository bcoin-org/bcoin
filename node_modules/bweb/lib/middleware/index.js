/*!
 * middleware.js - middleware for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

exports.basicAuth = require('./basicauth');
exports.bodyParser = require('./bodyparser');
exports.cookieParser = require('./cookie');
exports.cors = require('./cors');
exports.fileServer = require('./file');
exports.jsonRPC = require('./jsonrpc');
exports.router = require('./router');
