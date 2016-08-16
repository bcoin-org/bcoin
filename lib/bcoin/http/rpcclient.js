/*!
 * rpcclient.js - json rpc client for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../network');
var request = require('./request');

/**
 * BCoin RPC client.
 * @exports RPCClient
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
 * @param {Function} callback - Returns [Error, Object?].
 */

RPCClient.prototype.call = function call(method, params, callback) {
  request({
    method: 'POST',
    uri: this.uri,
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
  }, function(err, res, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback();

    if (res.statusCode === 400)
      return callback(null, body.result);

    if (res.statusCode !== 200) {
      if (body.error)
        return callback(new Error(body.error.message));
      return callback(new Error('Status code: ' + res.statusCode));
    }

    return callback(null, body.result);
  });
};

/*
 * Expose
 */

module.exports = RPCClient;
