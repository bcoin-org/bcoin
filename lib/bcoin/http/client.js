/**
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../../bcoin');
var network = bcoin.protocol.network;
var utils = require('../utils');
var request = require('./request');

/**
 * Client
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

  try {
    io = require('socket.io');
  } catch (e) {
    ;
  }

  if (!io)
    return;

  this.socket = new io.Socket(this.uri);

  this.socket.on('open', function() {
    self.socket.on('version', function(info) {
      utils.debug('Connected to bcoin server: %s (%s)',
        info.version, info.network);
      if (self.options.setNetwork)
        network.set(info.network);
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
        unconfirmed: utils.satoshi(balance.unconfirmed)
      }, id);
    });

    self.socket.on('balances', function(json) {
      var balances = {};
      Object.keys(json).forEach(function(id) {
        balances[id] = {
          confirmed: utils.satoshi(json[id].confirmed),
          unconfirmed: utils.satoshi(json[id].unconfirmed)
        };
      });
      self.emit('balances', balances);
    });

    self.socket.on('error', function(err) {
      self.emit('error', err);
    });

    self.loaded = true;
    self.emit('open');
  });
};

Client.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

Client.prototype.listenWallet = function listenWallet(id) {
  if (!this.socket)
    return;

  this.socket.join(id);
};

Client.prototype.unlistenWallet = function unlistenWallet(id) {
  if (!this.socket)
    return;

  this.socket.leave(id);
};

Client.prototype.listenAll = function listenAll() {
  this.listenWallet('!all');
};

Client.prototype.unlistenAll = function unlistenAll() {
  this.unlistenWallet('!all');
};

Client.prototype.close =
Client.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.socket)
    return utils.nextTick(callback);

  this.socket.destroy();
  this.socket = null;

  return utils.nextTick(callback);
};

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

    if (self.options.setNetwork) {
      networkType = res.headers['x-bcoin-network'];
      if (networkType && network.type !== networkType)
        network.set(networkType);
    }

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

Client.prototype._createWallet = function createWallet(options, callback) {
  return this._post('/wallet', options, callback);
};

Client.prototype._getWallet = function getWallet(id, callback) {
  return this._get('/wallet/' + id, callback);
};

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

Client.prototype.getWalletBalance = function getBalance(id, callback) {
  return this._get('/wallet/' + id + '/balance', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(new Error('Not found.'));

    return callback(null, {
      confirmed: utils.satoshi(body.confirmed),
      unconfirmed: utils.satoshi(body.unconfirmed)
    });
  });
};

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

Client.prototype.broadcast = function broadcast(tx, callback) {
  var body = { tx: utils.toHex(tx.toRaw()) };

  callback = utils.ensure(callback);

  return this._post('/broadcast', body, function(err) {
    if (err)
      return callback(err);
    return callback();
  });
};

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

Client.prototype.getInfo = function getInfo(callback) {
  return this._get('/', function(err, body) {
    if (err)
      return callback(err);

    if (!body)
      return callback(new Error('Info not available.'));

    return callback(null, body);
  });
};

/**
 * Expose
 */

module.exports = Client;
