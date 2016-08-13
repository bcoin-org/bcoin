/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Network = require('../network');
var AsyncObject = require('../async');
var RPCClient = require('./rpcclient');
var utils = require('../utils');
var assert = utils.assert;
var request = require('./request');

/**
 * BCoin HTTP client.
 * @exports HTTPClient
 * @constructor
 * @param {String} uri
 * @param {Object?} options
 */

function HTTPClient(options) {
  if (!(this instanceof HTTPClient))
    return new HTTPClient(options);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { uri: options };

  AsyncObject.call(this);

  this.options = options;
  this.network = Network.get(options.network);

  this.uri = options.uri || 'http://localhost:' + this.network.rpcPort;
  this.socket = null;
  this.apiKey = options.apiKey;
  this.auth = options.auth;
  this.rpc = new RPCClient(options);

  // Open automatically.
  this.open();
}

utils.inherits(HTTPClient, AsyncObject);

/**
 * Open the client, wait for socket to connect.
 * @alias HTTPClient#open
 * @param {Function} callback
 */

HTTPClient.prototype._open = function _open(callback) {
  var self = this;
  var IOClient;

  try {
    IOClient = require('socket.io-client');
  } catch (e) {
    ;
  }

  if (!IOClient)
    return callback();

  this.socket = new IOClient(this.uri, {
    transports: ['websocket'],
    forceNew: true
  });

  this.socket.on('error', function(err) {
    self.emit('error', err);
  });

  this.socket.on('version', function(info) {
    if (info.network !== self.network.type)
      self.emit('error', new Error('Wrong network.'));
  });

  this.socket.on('wallet tx', function(details) {
    self.emit('tx', details);
  });

  this.socket.on('wallet confirmed', function(details) {
    self.emit('confirmed', details);
  });

  this.socket.on('wallet unconfirmed', function(details) {
    self.emit('unconfirmed', details);
  });

  this.socket.on('wallet conflict', function(details) {
    self.emit('conflict', details);
  });

  this.socket.on('wallet updated', function(details) {
    self.emit('updated', details);
  });

  this.socket.on('wallet address', function(receive) {
    self.emit('address', receive);
  });

  this.socket.on('wallet balance', function(balance) {
    self.emit('balance', {
      id: balance.id,
      confirmed: utils.satoshi(balance.confirmed),
      unconfirmed: utils.satoshi(balance.unconfirmed),
      total: utils.satoshi(balance.total)
    });
  });

  this.socket.on('connect', function() {
    self.socket.emit('auth', self.apiKey, function(err) {
      if (err)
        return callback(new Error(err.error));
      callback();
    });
  });
};

/**
 * Close the client, wait for the socket to close.
 * @alias HTTPClient#close
 * @param {Function} callback
 */

HTTPClient.prototype._close = function close(callback) {
  if (!this.socket)
    return utils.nextTick(callback);

  this.socket.destroy();
  this.socket = null;

  return utils.nextTick(callback);
};

/**
 * Make an http request to endpoint.
 * @private
 * @param {String} method
 * @param {String} endpoint - Path.
 * @param {Object} json - Body or query depending on method.
 * @param {Function} callback - Returns [Error, Object?].
 */

HTTPClient.prototype._request = function _request(method, endpoint, json, callback) {
  var self = this;
  var query, network, height;

  if (!callback) {
    callback = json;
    json = null;
  }

  if (this.token) {
    if (!json)
      json = {};
    json.token = this.token;
  }

  if (json && method === 'get') {
    query = json;
    json = null;
  }

  request({
    method: method,
    uri: this.uri + endpoint,
    query: query,
    json: json,
    auth: {
      username: 'bitcoinrpc',
      password: this.apiKey || ''
    },
    expect: 'json'
  }, function(err, res, body) {
    if (err)
      return callback(err);

    network = res.headers['x-bcoin-network'];

    if (network !== self.network.type)
      return callback(new Error('Wrong network.'));

    height = +res.headers['x-bcoin-height'];

    if (utils.isNumber(height))
      self.network.updateHeight(height);

    if (res.statusCode === 404)
      return callback();

    if (!body)
      return callback(new Error('No body.'));

    if (res.statusCode !== 200) {
      if (body.error)
        return callback(new Error(body.error));
      return callback(new Error('Status code: ' + res.statusCode));
    }

    try {
      return callback(null, body);
    } catch (e) {
      return callback(e);
    }
  });
};

/**
 * Make a GET http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Querystring.
 * @param {Function} callback - Returns [Error, Object?].
 */

HTTPClient.prototype._get = function _get(endpoint, json, callback) {
  return this._request('get', endpoint, json, callback);
};

/**
 * Make a POST http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @param {Function} callback - Returns [Error, Object?].
 */

HTTPClient.prototype._post = function _post(endpoint, json, callback) {
  return this._request('post', endpoint, json, callback);
};

/**
 * Make a PUT http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @param {Function} callback - Returns [Error, Object?].
 */

HTTPClient.prototype._put = function _put(endpoint, json, callback) {
  return this._request('put', endpoint, json, callback);
};

/**
 * Make a DELETE http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @param {Function} callback - Returns [Error, Object?].
 */

HTTPClient.prototype._del = function _del(endpoint, json, callback) {
  return this._request('delete', endpoint, json, callback);
};

/**
 * Get a mempool snapshot.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

HTTPClient.prototype.getMempool = function getMempool(callback) {
  return this._get('/mempool', callback);
};

/**
 * Get some info about the server (network and version).
 * @param {Function} callback - Returns [Error, Object].
 */

HTTPClient.prototype.getInfo = function getInfo(callback) {
  return this._get('/', callback);
};

/**
 * Get coins that pertain to an address from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

HTTPClient.prototype.getCoinsByAddress = function getCoinsByAddress(address, callback) {
  var body = { addresses: address };

  return this._post('/coin/address', body, callback);
};

/**
 * Retrieve a coin from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

HTTPClient.prototype.getCoin = function getCoin(hash, index, callback) {
  return this._get('/coin/' + hash + '/' + index, callback);
};

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

HTTPClient.prototype.getTXByAddress = function getTXByAddress(address, callback) {
  var body = { addresses: address };

  return this._post('/tx/address', body, callback);
};

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

HTTPClient.prototype.getTX = function getTX(hash, callback) {
  return this._get('/tx/' + hash, callback);
};

/**
 * Retrieve a block from the chain database.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

HTTPClient.prototype.getBlock = function getBlock(hash, callback) {
  return this._get('/block/' + hash, callback);
};

/**
 * Add a transaction to the mempool and broadcast it.
 * @param {TX} tx
 * @param {Function} callback
 */

HTTPClient.prototype.broadcast = function broadcast(tx, callback) {
  var body = { tx: toHex(tx) };

  return this._post('/broadcast', body, callback);
};

/**
 * Listen for events on wallet id.
 * @param {WalletID} id
 */

HTTPClient.prototype.join = function join(id, token, callback) {
  if (!this.socket)
    return callback();

  this.socket.emit('wallet join', id, token, callback);
};

/**
 * Unlisten for events on wallet id.
 * @param {WalletID} id
 */

HTTPClient.prototype.leave = function leave(id, callback) {
  if (!this.socket)
    return callback();

  this.socket.emit('wallet leave', id, callback);
};

/**
 * Listen for events on all wallets.
 */

HTTPClient.prototype.all = function all(token, callback) {
  this.join('!all', token, callback);
};

/**
 * Unlisten for events on all wallets.
 */

HTTPClient.prototype.none = function none(callback) {
  this.leave('!all', callback);
};

/**
 * Request the raw wallet JSON (will create wallet if it does not exist).
 * @private
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, Object].
 */

HTTPClient.prototype.createWallet = function createWallet(options, callback) {
  return this._post('/wallet', options, callback);
};

/**
 * Get the raw wallet JSON.
 * @private
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object].
 */

HTTPClient.prototype.getWallet = function getWallet(id, callback) {
  return this._get('/wallet/' + id, callback);
};

/**
 * Get wallet transaction history.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

HTTPClient.prototype.getHistory = function getHistory(id, account, callback) {
  var options;

  if (typeof account === 'function') {
    callback = account;
    account = null;
  }

  options = { account: account };

  return this._get('/wallet/' + id + '/tx/history', options, callback);
};

/**
 * Get wallet coins.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

HTTPClient.prototype.getCoins = function getCoins(id, account, callback) {
  var options;

  if (typeof account === 'function') {
    callback = account;
    account = null;
  }

  options = { account: account };

  return this._get('/wallet/' + id + '/coin', options, callback);
};

/**
 * Get all unconfirmed transactions.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

HTTPClient.prototype.getUnconfirmed = function getUnconfirmed(id, account, callback) {
  var options;

  if (typeof account === 'function') {
    callback = account;
    account = null;
  }

  options = { account: account };

  return this._get('/wallet/' + id + '/tx/unconfirmed', options, callback);
};

/**
 * Calculate wallet balance.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

HTTPClient.prototype.getBalance = function getBalance(id, account, callback) {
  var options;

  if (typeof account === 'function') {
    callback = account;
    account = null;
  }

  options = { account: account };

  return this._get('/wallet/' + id + '/balance', options, callback);
};

/**
 * Get last N wallet transactions.
 * @param {WalletID} id
 * @param {Number} limit - Max number of transactions.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

HTTPClient.prototype.getLast = function getLast(id, account, limit, callback) {
  var options;

  if (typeof account === 'function') {
    callback = account;
    account = null;
  }

  options = { account: account, limit: limit };

  return this._get('/wallet/' + id + '/tx/last', options, callback);
};

/**
 * Get wallet transactions by timestamp range.
 * @param {WalletID} id
 * @param {Object} options
 * @param {Number} options.start - Start time.
 * @param {Number} options.end - End time.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

HTTPClient.prototype.getRange = function getRange(id, account, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = account;
    account = null;
  }

  options = {
    account: account,
    start: options.start,
    end: options.end ,
    limit: options.limit,
    reverse: options.reverse
  };

  return this._get('/wallet/' + id + '/tx/range', options, callback);
};

/**
 * Get transaction (only possible if the transaction
 * is available in the wallet history).
 * @param {WalletID} id
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

HTTPClient.prototype.getWalletTX = function getWalletTX(id, account, hash, callback) {
  var options;

  if (typeof hash === 'function') {
    callback = hash;
    hash = account;
    account = null;
  }

  options = { account: account };

  return this._get('/wallet/' + id + '/tx/' + hash, options, callback);
};

/**
 * Get unspent coin (only possible if the transaction
 * is available in the wallet history).
 * @param {WalletID} id
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

HTTPClient.prototype.getWalletCoin = function getWalletCoin(id, account, hash, index, callback) {
  var options, path;

  if (typeof hash === 'function') {
    callback = index;
    index = hash;
    hash = account;
    account = null;
  }

  options = { account: account };

  path = '/wallet/' + id + '/coin/' + hash + '/' + index;

  return this._get(path, options, callback);
};

/**
 * Create a transaction, fill, sign, and broadcast.
 * @param {WalletID} id
 * @param {Object} options
 * @param {Base58Address} options.address
 * @param {Amount} options.value
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

HTTPClient.prototype.send = function send(id, options, callback) {
  options = utils.merge({}, options);
  options.outputs = options.outputs || [];

  if (options.rate)
    options.rate = utils.btc(options.rate);

  options.outputs = options.outputs.map(function(output) {
    return {
      value: utils.btc(output.value),
      address: output.address,
      script: toHex(output.script)
    };
  });

  return this._post('/wallet/' + id + '/send', options, callback);
};

/**
 * Generate a new token.
 * @param {(String|Buffer)?} passphrase
 * @param {Function} callback
 */

HTTPClient.prototype.retoken = function retoken(id, passphrase, callback) {
  var options = { passphrase: passphrase };

  return this._post('/wallet/' + id + '/retoken', options, function(err, body) {
    if (err)
      return callback(err);

    return callback(null, body.token);
  });
};

/**
 * Change or set master key's passphrase.
 * @param {(String|Buffer)?} old
 * @param {String|Buffer} new_
 * @param {Function} callback
 */

HTTPClient.prototype.setPassphrase = function setPassphrase(id, old, new_, callback) {
  var options = { old: old, passphrase: new_ };

  return this._post('/wallet/' + id + '/passphrase', options, callback);
};

/**
 * Create a transaction, fill.
 * @param {WalletID} id
 * @param {Object} options
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

HTTPClient.prototype.createTX = function createTX(id, options, callback) {
  options = utils.merge({}, options);

  if (options.rate)
    options.rate = utils.btc(options.rate);

  options.outputs = options.outputs.map(function(output) {
    return {
      value: utils.btc(output.value),
      address: output.address,
      script: toHex(output.script)
    };
  });

  return this._post('/wallet/' + id + '/create', options, callback);
};

/**
 * Sign a transaction.
 * @param {WalletID} id
 * @param {TX} tx
 * @param {Object} options
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

HTTPClient.prototype.sign = function sign(id, tx, options, callback) {
  var body;

  if (typeof options === 'function') {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  body = utils.merge({}, options);
  body.tx = toHex(tx);

  return this._post('/wallet/' + id + '/sign', body, callback);
};

/**
 * Fill a transaction with coins.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

HTTPClient.prototype.fillCoins = function fillCoins(id, tx, callback) {
  var body = { tx: toHex(tx) };
  return this._post('/wallet/' + id + '/fill', body, callback);
};

/**
 * @param {WalletID} id
 * @param {Number} now - Current time.
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @param {Function} callback
 */

HTTPClient.prototype.zap = function zap(id, account, age, callback) {
  var body;

  if (typeof age === 'function') {
    callback = age;
    age = account;
    account = null;
  }

  body = {
    account: account,
    age: age
  };

  assert(utils.isNumber(age));

  return this._post('/wallet/' + id + '/zap', body, callback);
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {WalletID} id
 * @param {(String|Number)?} account
 * @param {HDPublicKey|Base58String} key - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @param {Function} callback
 */

HTTPClient.prototype.addKey = function addKey(id, account, key, callback) {
  var options;

  if (typeof key === 'function') {
    callback = key;
    key = account;
    account = null;
  }

  key = key.xpubkey || key;
  options = { account: account, key: key };

  return this._put('/wallet/' + id + '/key', options, callback);
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {WalletID} id
 * @param {(String|Number)?} account
 * @param {HDPublicKey|Base58String} key - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @param {Function} callback
 */

HTTPClient.prototype.removeKey = function removeKey(id, account, key, callback) {
  var options;

  if (typeof key === 'function') {
    callback = key;
    key = account;
    account = null;
  }

  key = key.xpubkey || key;
  options = { account: account, key: key };

  return this._del('/wallet/' + id + '/key', options, callback);
};

/**
 * Get wallet accounts.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Array].
 */

HTTPClient.prototype.getAccounts = function getAccounts(id, callback) {
  var path = '/wallet/' + id + '/account';
  return this._get(path, callback);
};

/**
 * Create account.
 * @param {WalletID} id
 * @param {Object} options
 * @param {Function} callback - Returns [Error, Array].
 */

HTTPClient.prototype.createAccount = function createAccount(id, options, callback) {
  var path;

  if (typeof options === 'function') {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { account: options };

  path = '/wallet/' + id + '/account';

  return this._post(path, options, callback);
};

/*
 * Helpers
 */

function toHex(obj) {
  if (!obj)
    return;

  if (obj.toRaw)
    obj = obj.toRaw();

  if (Buffer.isBuffer(obj))
    obj = obj.toString('hex');

  return obj;
}

/*
 * Expose
 */

module.exports = HTTPClient;
