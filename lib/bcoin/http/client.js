/**
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../../bcoin');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var request = require('./request');

/**
 * Client
 */

function Client(uri) {
  if (!(this instanceof Client))
    return new Client(uri);

  EventEmitter.call(this);

  this.uri = uri;
  this.id = null;
  this._init();
}

utils.inherits(Client, EventEmitter);

Client.prototype._init = function _init() {
  var self = this;
  var io;

  try {
    io = require('socket.io');
  } catch (e) {
    ;
  }

  if (!io)
    return;

  this.socket = new io.Socket(this.uri);

  this.socket.on('open', function() {
    self.socket.on('tx', function(tx, map) {
      self.emit('tx', bcoin.tx.fromJSON(tx), map);
    });

    self.socket.on('confirmed', function(tx, map) {
      self.emit('confirmed', bcoin.tx.fromJSON(tx), map);
    });

    self.socket.on('updated', function(tx, map) {
      self.emit('updated', bcoin.tx.fromJSON(tx), map);
    });

    self.socket.on('balance', function(balance, id) {
      self.emit('balance', utils.satoshi(balance), id);
    });

    self.socket.on('balances', function(balances) {
      Object.keys(balances).forEach(function(id) {
        balances[id] = utils.satoshi(balances[id]);
      });
      self.emit('balances', balances);
    });

    self.socket.on('error', function(err) {
      self.emit('error', err);
    });
  });
};

Client.prototype.listenWallet = function listenWallet(id) {
  this.socket.join(id);
};

Client.prototype.unlistenWallet = function unlistenWallet(id) {
  this.socket.leave(id);
};

Client.prototype.listenAll = function listenAll() {
  this.listenWallet('!all');
};

Client.prototype.unlistenAll = function unlistenAll() {
  this.unlistenWallet('!all');
};

Client.prototype.destroy = function destroy() {
  this.socket.destroy();
  this.socket = null;
};

Client.prototype._request = function _request(method, endpoint, json, callback) {
  var query;

  if (!callback) {
    callback = json;
    json = null;
  }

  if (json && method === 'get') {
    json = null;
    query = json;
  }

  request({
    method: method,
    uri: this.uri + '/' + endpoint,
    query: query,
    json: json,
    expect: 'json'
  }, function(err, res, body) {
    if (err)
      return callback(err);

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

Client.prototype._get = function _get(endpoint, json, callback) {
  return this._request('get', endpoint, json, callback);
};

Client.prototype._post = function _post(endpoint, json, callback) {
  return this._request('post', endpoint, json, callback);
};

Client.prototype._put = function _put(endpoint, json, callback) {
  return this._request('put', endpoint, json, callback);
};

Client.prototype._del = function _del(endpoint, json, callback) {
  return this._request('delete', endpoint, json, callback);
};

Client.prototype.getWalletAll = function getWalletAll(id, callback) {
  return this._get('/wallet/' + id + '/tx/all', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, body.map(function(data) {
      return bcoin.tx.fromJSON(data);
    }));
  });
};

Client.prototype.getWalletCoins = function getWalletCoins(id, callback) {
  return this._get('/wallet/' + id + '/coin', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, body.map(function(data) {
      return bcoin.coin.fromJSON(data);
    }));
  });
};

Client.prototype.getWalletPending = function getPending(id, callback) {
  return this._get('/wallet/' + id + '/tx/pending', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, body.map(function(data) {
      return bcoin.coin.fromJSON(data);
    }));
  });
};

Client.prototype.getWalletBalance = function getBalance(id, callback) {
  return this._get('/wallet/' + id + '/balance', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(new Error('Not found.'));

    return callback(null, utils.satoshi(body.balance));
  });
};

Client.prototype.getWalletLast = function getLast(id, limit, callback) {
  var options = { limit: limit };
  return this._get('/wallet/' + id + '/tx/last', options, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, body.map(function(data) {
      return bcoin.tx.fromJSON(data);
    }));
  });
};

Client.prototype.getWalletRange = function getWalletRange(id, options, callback) {
  return this._get('/wallet/' + id + '/tx/range', options, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, body.map(function(data) {
      return bcoin.tx.fromJSON(data);
    }));
  });
};

Client.prototype.getWalletTX = function getTX(id, hash, callback) {
  hash = utils.revHex(hash);

  return this._get('/wallet/' + id + '/tx/' + hash, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, bcoin.tx.fromJSON(body));
  });
};

Client.prototype.getWalletCoin = function getCoin(id, hash, index, callback) {
  hash = utils.revHex(hash);

  return this._get('/wallet/' + id + '/coin/' + hash + '/' + index, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, bcoin.coin.fromJSON(body));
  });
};

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

Client.prototype.getCoinByAddress = function getCoinByAddress(address, callback) {
  var body = { addresses: address };

  return this._post('/coin/address', body, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, body.map(function(data) {
      return bcoin.coin.fromJSON(data);
    }));
  });
};

Client.prototype.getCoin = function getCoin(hash, index, callback) {
  hash = utils.revHex(hash);

  return this._get('/coin/' + hash + '/' + index, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, bcoin.coin.fromJSON(body));
  });
};

Client.prototype.getTXByAddress = function getTXByAddress(address, callback) {
  var body = { addresses: address };

  return this._post('/tx/address', body, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, body.map(function(data) {
      return bcoin.tx.fromJSON(data);
    }));
  });
};

Client.prototype.getTX = function getTX(hash, callback) {
  hash = utils.revHex(hash);

  return this._get('/tx/' + hash, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, bcoin.tx.fromJSON(body));
  });
};

Client.prototype.getBlock = function getBlock(hash, callback) {
  if (typeof hash !== 'number')
    hash = utils.revHex(hash);

  return this._get('/block/' + hash, function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(null, []);

    return callback(null, bcoin.block.fromJSON(body));
  });
};

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
 * Expose
 */

module.exports = Client;
