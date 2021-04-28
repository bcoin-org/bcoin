/*!
 * bweb.js - a web server
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const Server = require('./server');
const Router = require('./router');
const {RPC, RPCError, errors} = require('./rpc');
const middleware = require('./middleware/index');

exports.Server = Server;
exports.createServer = options => new Server(options);
exports.server = options => new Server(options);

exports.Router = Router;
exports.router = () => new Router();

exports.RPC = RPC;
exports.rpc = () => new RPC();

exports.RPCError = RPCError;
exports.errors = errors;

exports.middleware = middleware;
