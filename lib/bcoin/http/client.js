/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var network = bcoin.protocol.network;
var utils = require('../utils');
var assert = utils.assert;
var request = require('./request');

/**
 * Client
 * @exports Client
 * @constructor
 * @param {String} uri
 * @param {Object?} options
 */

function Client(uri, options) {
  if (!(this instanceof Client))
    return new Client(uri, options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.uri = uri;
  this.loaded = false;
  this.id = null;
  this.options = options;
  this._init();
}

utils.inherits(Client, EventEmitter);

Client.prototype._init = function _init() {
  var self = this;
  var io;

  return;
  try {
    io = require('socket.io');
  } catch (e) {
    ;
  }

  if (!io)
    return;

  this.socket = new io.Socket(this.uri);

  this.socket.on('error', function(err) {
    self.emit('error', err);
  });

  this.socket.on('open', function() {
    self.socket.on('version', function(info) {
      bcoin.debug('Connected to bcoin server: %s (%s)',
        info.version, info.network);
      assert(info.network === network.type, 'Wrong network.');
    });

    self.socket.on('tx', function(tx, map) {
      try {
        tx = bcoin.tx.fromJSON(tx);
      } catch (e) {
        return self.emit('error', e);
      }
      self.emit('tx', tx, map);
    });

    self.socket.on('confirmed', function(tx, map) {
      try {
        tx = bcoin.tx.fromJSON(tx);
      } catch (e) {
        return self.emit('error', e);
      }
      self.emit('confirmed', tx, map);
    });

    self.socket.on('updated', function(tx, map) {
      try {
        tx = bcoin.tx.fromJSON(tx);
      } catch (e) {
        return self.emit('error', e);
      }
      self.emit('updated', tx, map);
    });

    self.socket.on('balance', function(balance, id) {
      self.emit('balance', {
        confirmed: utils.satoshi(balance.confirmed),
        unconfirmed: utils.satoshi(balance.unconfirmed),
        total: utils.satoshi(balance.total)
      }, id);
    });

    self.socket.on('balances', function(json) {
      var balances = {};
      Object.keys(json).forEach(function(id) {
        balances[id] = {
          confirmed: utils.satoshi(json[id].confirmed),
          unconfirmed: utils.satoshi(json[id].unconfirmed),
          total: utils.satoshi(json[id].total)
        };
      });
      self.emit('balances', balances);
    });

    self.loaded = true;
    self.emit('open');
  });
};

/**
 * Open the client, wait for the socket to load.
 * @param {Function} callback
 */

Client.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Listen for events on wallet id.
 * @param {WalletID} id
 */

Client.prototype.listenWallet = function listenWallet(id) {
  if (!this.socket)
    return;

  this.socket.join(id);
};

/**
 * Unlisten for events on wallet id.
 * @param {WalletID} id
 */

Client.prototype.unlistenWallet = function unlistenWallet(id) {
  if (!this.socket)
    return;

  this.socket.leave(id);
};

/**
 * Listen for events on all wallets.
 */

Client.prototype.listenAll = function listenAll() {
  this.listenWallet('!all');
};

/**
 * Unlisten for events on all wallets.
 */

Client.prototype.unlistenAll = function unlistenAll() {
  this.unlistenWallet('!all');
};

/**
 * Close the client, wait for the socket to close.
 * @method
 * @param {Function} callback
 */

Client.prototype.close =
Client.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

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

Client.prototype._request = function _request(method, endpoint, json, callback) {
  var self = this;
  var query;
  var networkType;

  if (!callback) {
    callback = json;
    json = null;
  }

  if (json && method === 'get') {
    query = json;
    json = true;
  }

  request({
    method: method,
    uri: this.uri + endpoint,
    query: query,
    json: json,
    expect: 'json'
  }, function(err, res, body) {
    if (err)
      return callback(err);

    networkType = res.headers['x-bcoin-network'];
    assert(networkType === network.type, 'Wrong network.');

    if (res.statusCode === 404)
      return callback();

    if (!body)
      return callback(new Error('No body.'));

    if (res.statusCode !== 200)
      return callback(new Error('Status code: ' + res.statusCode));

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

Client.prototype._get = function _get(endpoint, json, callback) {
  return this._request('get', endpoint, json, callback);
};

/**
 * Make a POST http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @param {Function} callback - Returns [Error, Object?].
 */

Client.prototype._post = function _post(endpoint, json, callback) {
  return this._request('post', endpoint, json, callback);
};

/**
 * Make a PUT http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @param {Function} callback - Returns [Error, Object?].
 */

Client.prototype._put = function _put(endpoint, json, callback) {
  return this._request('put', endpoint, json, callback);
};

/**
 * Make a DELETE http request to endpoint.
 * @private
 * @param {String} endpoint - Path.
 * @param {Object} json - Body.
 * @param {Function} callback - Returns [Error, Object?].
 */

Client.prototype._del = function _del(endpoint, json, callback) {
  return this._request('delete', endpoint, json, callback);
};

/**
 * Request the raw wallet JSON (will create wallet if it does not exist).
 * @private
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, Object].
 */

Client.prototype._createWallet = function createWallet(options, callback) {
  return this._post('/wallet', options, callback);
};

/**
 * Get the raw wallet JSON.
 * @private
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object].
 */

Client.prototype._getWallet = function getWallet(id, callback) {
  return this._get('/wallet/' + id, callback);
};

/**
 * Get wallet and setup http provider (note that the
 * passphrase is _not_ sent over the wire).
 * @param {WalletID} id
 * @param {String?} passphrase
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

Client.prototype.getWallet = function getWallet(id, passphrase, callback) {
  var self = this;
  var provider;

  return this._getWallet(id, function(err, json) {
    if (err)
      return callback(err);

    try {
      json = bcoin.wallet._fromJSON(json, passphrase);
    } catch (e) {
      return callback(e);
    }

    json.provider = new bcoin.http.provider(self.url);

    return callback(null, new bcoin.wallet(json));
  });
};

/**
 * Get wallet and setup http provider (note that the
 * passphrase is _not_ sent over the wire).
 * @param {WalletID} id
 * @param {String?} passphrase
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

Client.prototype.createWallet = function createWallet(options, callback) {
  var self = this;
  return this._createWallet(options, function(err, json) {
    if (err)
      return callback(err);

    try {
      json = bcoin.wallet._fromJSON(json, options.passphrase);
    } catch (e) {
      return callback(e);
    }

    json.provider = new bcoin.http.provider(self.url);

    return callback(null, new bcoin.wallet(json));
  });
};

/**
 * Get wallet transaction history.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Client.prototype.getWalletAll = function getWalletAll(id, callback) {
  return this._get('/wallet/' + id + '/tx/all', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.tx.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Get wallet coins.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Client.prototype.getWalletCoins = function getWalletCoins(id, callback) {
  return this._get('/wallet/' + id + '/coin', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.coin.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Get all unconfirmed transactions.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Client.prototype.getWalletPending = function getPending(id, callback) {
  return this._get('/wallet/' + id + '/tx/pending', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.coin.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Calculate wallet balance.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

Client.prototype.getWalletBalance = function getBalance(id, callback) {
  return this._get('/wallet/' + id + '/balance', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(new Error('Not found.'));

    return callback(null, {
      confirmed: utils.satoshi(body.confirmed),
      unconfirmed: utils.satoshi(body.unconfirmed),
      total: utils.satoshi(body.total)
    });
  });
};

/**
 * Get last N wallet transactions.
 * @param {WalletID} id
 * @param {Number} limit - Max number of transactions.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Client.prototype.getWalletLast = function getLast(id, limit, callback) {
  var options = { limit: limit };
  return this._get('/wallet/' + id + '/tx/last', options, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.tx.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Get wallet transactions by timestamp range.
 * @param {WalletID} id
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Client.prototype.getWalletRange = function getWalletRange(id, options, callback) {
  return this._get('/wallet/' + id + '/tx/range', options, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.tx.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Get transaction (only possible if the transaction
 * is available in the wallet history).
 * @param {WalletID} id
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Client.prototype.getWalletTX = function getTX(id, hash, callback) {
  hash = utils.revHex(hash);

  return this._get('/wallet/' + id + '/tx/' + hash, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback();

    try {
      body = bcoin.tx.fromJSON(body);
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Get unspent coin (only possible if the transaction
 * is available in the wallet history).
 * @param {WalletID} id
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Client.prototype.getWalletCoin = function getCoin(id, hash, index, callback) {
  var path;

  hash = utils.revHex(hash);
  path = '/wallet/' + id + '/coin/' + hash + '/' + index;

  return this._get(path, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback();

    try {
      body = bcoin.coin.fromJSON(body);
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Sync wallet receive and change depth with the server.
 * @param {WalletID} id
 * @param {Object} options
 * @param {Number} options.receiveDepth
 * @param {Number} options.changeDepth
 * @param {Function} callback
 */

Client.prototype.syncWallet = function syncWallet(id, options, callback) {
  var body = {
    receiveDepth: options.receiveDepth,
    changeDepth: options.changeDepth
  };

  return this._put('/wallet/' + id, body, function(err) {
    if (err)
      return callback(err);
    return callback();
  });
};

/**
 * Get coins that pertain to an address from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Client.prototype.getCoinsByAddress = function getCoinsByAddress(address, callback) {
  var body = { addresses: address };

  return this._post('/coin/address', body, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.coin.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Retrieve a coin from the mempool or chain database.
 * Takes into account spent coins in the mempool.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

Client.prototype.getCoin = function getCoin(hash, index, callback) {
  hash = utils.revHex(hash);

  return this._get('/coin/' + hash + '/' + index, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback();

    try {
      body = bcoin.coin.fromJSON(body);
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Retrieve transactions pertaining to an
 * address from the mempool or chain database.
 * @param {Base58Address|Base58Address[]} addresses
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Client.prototype.getTXByAddress = function getTXByAddress(address, callback) {
  var body = { addresses: address };

  return this._post('/tx/address', body, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.tx.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Retrieve a transaction from the mempool or chain database.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Client.prototype.getTX = function getTX(hash, callback) {
  hash = utils.revHex(hash);

  return this._get('/tx/' + hash, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback();

    try {
      body = bcoin.tx.fromJSON(body);
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Retrieve a block from the chain database.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link Block}].
 */

Client.prototype.getBlock = function getBlock(hash, callback) {
  if (typeof hash !== 'number')
    hash = utils.revHex(hash);

  return this._get('/block/' + hash, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback();

    try {
      body = bcoin.block.fromJSON(body);
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Add a transaction to the mempool and broadcast it.
 * @param {TX} tx
 * @param {Function} callback
 */

Client.prototype.broadcast = function broadcast(tx, callback) {
  var body = { tx: utils.toHex(tx.toRaw()) };

  callback = utils.ensure(callback);

  return this._post('/broadcast', body, function(err) {
    if (err)
      return callback(err);
    return callback();
  });
};

/**
 * Create a transaction, fill, sign, and broadcast.
 * @param {WalletID} id
 * @param {Object} options
 * @param {Base58Address} options.address
 * @param {BN} options.value
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Client.prototype.walletSend = function walletSend(id, options, callback) {
  var body = {
    address: options.address,
    value: utils.btc(options.value)
  };

  callback = utils.ensure(callback);

  return this._post('/wallet/' + id + '/send', body, function(err, body) {
    if (err)
      return callback(err);

    try {
      body = bcoin.tx.fromJSON(body);
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * @param {WalletID} id
 * @param {Number} now - Current time.
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @param {Function} callback
 */

Client.prototype.zapWallet = function zapWallet(id, now, age, callback) {
  var body = {
    now: now,
    age: age
  };

  assert(utils.isFinite(now));
  assert(utils.isFinite(age));
  assert(now >= age);

  callback = utils.ensure(callback);

  return this._post('/wallet/' + id + '/zap', body, function(err) {
    if (err)
      return callback(err);
    return callback();
  });
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {WalletID} id
 * @param {HDPublicKey[]|Base58String[]} keys - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @param {Function} callback
 */

Client.prototype.addKey = function addKey(id, keys, callback) {
  if (!Array.isArray(keys))
    keys = [keys];

  keys = keys.map(function(key) {
    return key || key.xpubkey;
  });

  callback = utils.ensure(callback);

  return this._put('/wallet/' + id + '/key', keys, function(err) {
    if (err)
      return callback(err);
    return callback();
  });
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {WalletID} id
 * @param {HDPublicKey[]|Base58String[]} keys - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @param {Function} callback
 */

Client.prototype.removeKey = function removeKey(id, keys, callback) {
  if (!Array.isArray(keys))
    keys = [keys];

  keys = keys.map(function(key) {
    return key || key.xpubkey;
  });

  callback = utils.ensure(callback);

  return this._del('/wallet/' + id + '/key', keys, function(err) {
    if (err)
      return callback(err);
    return callback();
  });
};

/**
 * Get a mempool snapshot.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Client.prototype.getMempool = function getMempool(callback) {
  return this._get('/mempool', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    try {
      body = body.map(function(data) {
        return bcoin.tx.fromJSON(data);
      });
    } catch (e) {
      return callback(e);
    }

    return callback(null, body);
  });
};

/**
 * Get some info about the server (network and version).
 * @param {Function} callback - Returns [Error, Object].
 */

Client.prototype.getInfo = function getInfo(callback) {
  return this._get('/', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(new Error('Info not available.'));

    return callback(null, body);
  });
};

return Client;
};
