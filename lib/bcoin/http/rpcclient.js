/*!
 * rpcclient.js - json rpc client for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../network');
var utils = require('../utils');
var assert = utils.assert;
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

  if (this.apiKey) {
    if (typeof this.apiKey === 'string') {
      assert(utils.isHex(this.apiKey), 'API key must be a hex string.');
      this.apiKey = new Buffer(this.apiKey, 'hex');
    }
    assert(Buffer.isBuffer(this.apiKey));
    assert(this.apiKey.length === 32, 'API key must be 32 bytes.');
  }
}

/**
 * Make an http request to endpoint.
 * @private
 * @param {String} method
 * @param {String} endpoint - Path.
 * @param {Object} json - Body or query depending on method.
 * @param {Function} callback - Returns [Error, Object?].
 */

RPCClient.prototype.call = function call(method, params, callback) {
  var self = this;

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
      password: this.apiKey ? this.apiKey.toString('hex') : ''
    },
    expect: 'json'
  }, function(err, res, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback();

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
