/*!
 * rpcclient.js - json rpc client for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../protocol/network');
var request = require('./request');
var util = require('../utils/util');
var co = require('../utils/co');

/**
 * Bcoin RPC client.
 * @alias module:http.RPCClient
 * @constructor
 * @param {String} uri
 * @param {Object?} options
 */

function RPCClient(options) {
  if (!(this instanceof RPCClient))
    return new RPCClient(options);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { uri: options };

  this.options = options;
  this.network = Network.get(options.network);

  this.uri = options.uri || 'http://localhost:' + this.network.rpcPort;
  this.apiKey = options.apiKey;
  this.id = 0;
}

/**
 * Make a json rpc request.
 * @private
 * @param {String} method - RPC method name.
 * @param {Array} params - RPC parameters.
 * @returns {Promise} - Returns Object?.
 */

RPCClient.prototype.execute = co(function* execute(method, params) {
  var res = yield request({
    method: 'POST',
    uri: this.uri,
    pool: true,
    json: {
      method: method,
      params: params,
      id: this.id++
    },
    auth: {
      username: 'bitcoinrpc',
      password: this.apiKey || ''
    },
    expect: 'json'
  });

  if (!res.body)
    throw new Error('No body for JSON-RPC response.');

  if (res.body.error)
    throw new RPCError(res.body.error.message, res.body.error.code);

  if (res.statusCode !== 200)
    throw new Error('Status code: ' + res.statusCode);

  return res.body.result;
});

/*
 * Helpers
 */

function RPCError(msg, code) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, RPCError);

  this.type = 'RPCError';
  this.message = msg + '';
  this.code = code >>> 0;
}

util.inherits(RPCError, Error);

/*
 * Expose
 */

module.exports = RPCClient;
