/*!
 * middleware.js - middleware for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

function middleware() {
  return async (req, res) => {};
}

exports.basicAuth = middleware;
exports.bodyParser = middleware;
exports.cookieParser = middleware;
exports.cors = middleware;
exports.fileServer = middleware;
exports.jsonRPC = middleware;
exports.router = middleware;
