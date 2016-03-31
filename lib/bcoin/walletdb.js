/**
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var DUMMY = new Buffer([0]);

/**
 * WalletDB
 */

function WalletDB(node, options) {
  if (!(this instanceof WalletDB))
    return new WalletDB(node, options);

  if (WalletDB.global)
    return WalletDB.global;

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.node = node;
  this.options = options;
  this.loaded = false;

  WalletDB.global = this;

  this._init();
}

utils.inherits(WalletDB, EventEmitter);

WalletDB._db = {};

WalletDB.prototype.dump = function dump(callback) {
  var records = {};

  var iter = this.db.iterator({
    gte: 'w',
    lte: 'w~',
    keys: true,
    values: true,
    fillCache: false,
    keyAsBuffer: false,
    valueAsBuffer: true
  });

  callback = utils.ensure(callback);

  (function next() {
    iter.next(function(err, key, value) {
      if (err) {
        return iter.end(function() {
          callback(err);
        });
      }

      if (key === undefined) {
        return iter.end(function(err) {
          if (err)
            return callback(err);
          return callback(null, records);
        });
      }

      records[key] = value;

      next();
    });
  })();
};

WalletDB.prototype._init = function _init() {
  var self = this;

  if (this.loaded)
    return;

  this.db = bcoin.ldb('wallet', {
    cacheSize: 8 << 20,
    writeBufferSize: 4 << 20
  });

  this.db.open(function(err) {
    if (err)
      return self.emit('error', err);

    self.emit('open');
    self.loaded = true;
  });

  this.tx = new bcoin.txdb('w', this.db, {
    indexExtra: true,
    indexAddress: true,
    mapAddress: true,
    verify: this.options.verify
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });

  this.tx.on('tx', function(tx, map) {
    self.emit('tx', tx, map);
    map.all.forEach(function(id) {
      self.emit(id + ' tx', tx);
    });
  });

  this.tx.on('confirmed', function(tx, map) {
    self.emit('confirmed', tx, map);
    map.all.forEach(function(id) {
      self.emit(id + ' confirmed', tx);
    });
  });

  this.tx.on('unconfirmed', function(tx, map) {
    self.emit('unconfirmed', tx, map);
    map.all.forEach(function(id) {
      self.emit(id + ' unconfirmed', tx);
    });
  });

  this.tx.on('updated', function(tx, map) {
    var balances = {};

    self.emit('updated', tx, map);

    utils.forEachSerial(map.output, function(id, next) {
      if (self.listeners('balance').length === 0
          && self.listeners(id + ' balance').length === 0) {
        return next();
      }

      self.getBalance(id, function(err, balance) {
        if (err)
          return self.emit('error', err);

        balances[id] = balance;

        self.emit('balance', balance, id);
        self.emit(id + ' balance', balance);
      });
    }, function(err) {
      if (err)
        self.emit('error', err);

      self.emit('balances', balances, map);
    });

    // Only sync for confirmed txs.
    if (tx.ts === 0)
      return;

    utils.forEachSerial(map.output, function(id, next) {
      self.syncOutputDepth(id, tx, next);
    }, function(err) {
      if (err)
        self.emit('error', err);
    });
  });
};

WalletDB.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

WalletDB.prototype.close =
WalletDB.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);
  this.db.close(callback);
};

WalletDB.prototype.syncOutputDepth = function syncOutputDepth(id, tx, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    // Allocate new addresses if necessary.
    json = bcoin.wallet.syncOutputDepth(json, tx);

    if (!json)
      return callback();

    self.saveJSON(id, json, function(err) {
      if (err)
        return callback(err);

      self.emit('sync output depth', id, tx);

      callback();
    });
  });
};

WalletDB.prototype.setDepth = function setDepth(id, receive, change, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    // Allocate new addresses if necessary.
    json = bcoin.wallet.setDepth(json, receive, change);

    if (!json)
      return callback();

    self.saveJSON(id, json, function(err) {
      if (err)
        return callback(err);

      self.emit('set depth', id, receive, change);

      callback();
    });
  });
};

WalletDB.prototype.getJSON = function getJSON(id, callback) {
  if (typeof id === 'object')
    id = id.id;

  callback = utils.ensure(callback);

  return this._getDB(id, callback);
};

WalletDB.prototype.saveJSON = function saveJSON(id, json, callback) {
  var self = this;

  callback = utils.ensure(callback);

  return this._saveDB(id, json, function(err, json) {
    var batch;

    if (err)
      return callback(err);

    if (json) {
      batch = self.db.batch();
      Object.keys(json.addressMap).forEach(function(address) {
        batch.put('w/a/' + address + '/' + json.id, DUMMY);
      });
      return batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, json);
      });
    }

    return callback(null, json);
  });
};

WalletDB.prototype.removeJSON = function removeJSON(id, callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (typeof id === 'object')
    id = id.id;

  return this._removeDB(id, function(err, json) {
    var batch;

    if (err)
      return callback(err);

    if (json) {
      batch = self.db.batch();
      Object.keys(json.addressMap).forEach(function(address) {
        batch.del('w/a/' + address + '/' + json.id);
      });
      return batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, json);
      });
    }

    return callback(null, json);
  });
};

WalletDB.prototype._getDB = function _getDB(id, callback) {
  var key;

  callback = utils.ensure(callback);

  key = 'w/w/' + id;

  this.db.get(key, function(err, json) {
    if (err && err.type === 'NotFoundError')
      return callback();

    if (err)
      return callback(err);

    try {
      json = JSON.parse(json.toString('utf8'));
    } catch (e) {
      return callback(e);
    }

    return callback(null, json);
  });
};

WalletDB.prototype._saveDB = function _saveDB(id, json, callback) {
  var key = 'w/w/' + id;
  var data;

  callback = utils.ensure(callback);

  data = new Buffer(JSON.stringify(json), 'utf8');

  this.db.put(key, data, function(err) {
    if (err)
      return callback(err);

    return callback(null, json);
  });
};

WalletDB.prototype._removeDB = function _removeDB(id, callback) {
  var self = this;
  var key = 'w/w/' + id;

  callback = utils.ensure(callback);

  this._getDB(id, function(err, json) {
    if (err)
      return callback(err);

    self.db.del(key, function(err) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      return callback(null, json);
    });
  });
};

WalletDB.prototype.get = function get(id, passphrase, callback) {
  var self = this;

  if (typeof passphrase === 'function') {
    callback = passphrase;
    passphrase = null;
  }

  callback = utils.ensure(callback);

  return this.getJSON(id, function(err, options) {
    var wallet;

    if (err)
      return callback(err);

    if (!options)
      return callback();

    try {
      options = bcoin.wallet._fromJSON(options, passphrase);
      options.provider = new Provider(self);
      wallet = new bcoin.wallet(options);
    } catch (e) {
      return callback(e);
    }

    return callback(null, wallet);
  });
};

WalletDB.prototype.save = function save(options, callback) {
  callback = utils.ensure(callback);

  if (options instanceof bcoin.wallet)
    assert(options.db === this);

  this.saveJSON(options.id, options, callback);
};

WalletDB.prototype.remove = function remove(id, callback) {
  callback = utils.ensure(callback);

  if (id instanceof bcoin.wallet) {
    id.destroy();
    id = id.id;
  }

  return this.removeJSON(id, callback);
};

WalletDB.prototype.create = function create(options, callback) {
  var self = this;

  callback = utils.ensure(callback);

  function getJSON(id, callback) {
    if (!id)
      return callback();

    return self.getJSON(id, function(err, json) {
      if (err)
        return callback(err);

      return callback(null, json);
    });
  }

  return getJSON(options.id, function(err, json) {
    var wallet;

    if (err)
      return callback(err);

    if (json) {
      try {
        options = bcoin.wallet._fromJSON(json, options.passphrase);
        options.provider = new Provider(self);
        wallet = new bcoin.wallet(options);
      } catch (e) {
        return callback(e);
      }
      done();
    } else {
      if (bcoin.protocol.network.witness)
        options.witness = options.witness !== false;

      options.provider = new Provider(self);
      wallet = new bcoin.wallet(options);
      self.saveJSON(wallet.id, wallet.toJSON(), done);
    }

    function done(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
    }
  });
};

WalletDB.prototype.update = function update(wallet, address) {
  var self = this;
  var batch;

  // Ugly hack to avoid extra writes.
  if (!wallet.changeAddress && wallet.changeDepth > 1)
    return;

  batch = this.db.batch();

  batch.put(
    'w/a/' + address.getKeyAddress() + '/' + wallet.id,
    DUMMY);

  if (address.type === 'multisig') {
    batch.put(
      'w/a/' + address.getScriptAddress() + '/' + wallet.id,
      DUMMY);
  }

  if (address.witness) {
    batch.put(
      'w/a/' + address.getProgramAddress() + '/' + wallet.id,
      DUMMY);
  }

  batch.write(function(err) {
    if (err)
      self.emit('error', err);

    // XXX might have to encrypt key - slow
    self._saveDB(wallet.id, wallet.toJSON(), function(err) {
      if (err)
        self.emit('error', err);
    });
  });
};

WalletDB.prototype.addTX = function addTX(tx, callback) {
  return this.tx.add(tx, callback);
};

WalletDB.prototype.getTX = function getTX(hash, callback) {
  return this.tx.getTX(hash, callback);
};

WalletDB.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.tx.getCoin(hash, index, callback);
};

WalletDB.prototype.getAll = function getAll(id, callback) {
  id = id.id || id;
  return this.tx.getAllByAddress(id, callback);
};

WalletDB.prototype.getCoins = function getCoins(id, callback) {
  id = id.id || id;
  return this.tx.getCoinsByAddress(id, callback);
};

WalletDB.prototype.getPending = function getPending(id, callback) {
  id = id.id || id;
  return this.tx.getPendingByAddress(id, callback);
};

WalletDB.prototype.getBalance = function getBalance(id, callback) {
  id = id.id || id;
  return this.tx.getBalanceByAddress(id, callback);
};

WalletDB.prototype.getLastTime = function getLastTime(id, callback) {
  id = id.id || id;
  return this.tx.getLastTime(id, callback);
};

WalletDB.prototype.getLast = function getLast(id, limit, callback) {
  id = id.id || id;
  return this.tx.getLast(id, limit, callback);
};

WalletDB.prototype.getRange = function getRange(id, options, callback) {
  id = id.id || id;
  return this.tx.getRange(id, options, callback);
};

WalletDB.prototype.fillTX = function fillTX(tx, callback) {
  return this.tx.fillTX(tx, callback);
};

WalletDB.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.tx.fillCoins(tx, callback);
};

WalletDB.prototype.removeBlockSPV = function removeBlockSPV(block, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.tx.getHeightHashes(block.height, function(err, txs) {
    if (err)
      return callback(err);

    utils.forEachSerial(txs, function(tx, next) {
      self.tx.unconfirm(tx, next);
    }, callback);
  });
};

WalletDB.prototype.removeBlock = function removeBlock(block, callback) {
  var self = this;

  callback = utils.ensure(callback);

  utils.forEachSerial(block.txs, function(tx, next) {
    self.tx.unconfirm(tx.hash('hex'), next);
  }, callback);
};

/**
 * Provider
 */

function Provider(db) {
  if (!(this instanceof Provider))
    return new Provider(db);

  EventEmitter.call(this);

  this.loaded = false;
  this.db = db;
  this.id = null;

  this._init();
}

utils.inherits(Provider, EventEmitter);

Provider.prototype._init = function _init() {
  var self = this;

  if (this.db.loaded) {
    this.loaded = true;
    return;
  }

  this.db.once('open', function() {
    self.loaded = true;
    self.emit('open');
  });
};

Provider.prototype.open = function open(callback) {
  return this.db.open(callback);
};

Provider.prototype.setID = function setID(id) {
  var self = this;

  assert(!this.id);

  this.id = id;

  this.db.on(id + ' tx', this._onTX = function(tx) {
    self.emit('tx', tx);
  });

  this.db.on(id + ' updated', this._onUpdated = function(tx) {
    self.emit('updated', tx);
  });

  this.db.on(id + ' confirmed', this._onConfirmed = function(tx) {
    self.emit('confirmed', tx);
  });

  this.db.on(id + ' unconfirmed', this._onUnconfirmed = function(tx) {
    self.emit('unconfirmed', tx);
  });

  this.db.on(id + ' balance', this._onBalance = function(balance) {
    self.emit('balance', balance);
  });
};

Provider.prototype.destroy = function destroy() {
  if (this.db) {
    if (this._onTX) {
      this.removeListener(this.id + ' tx', this._onTX);
      delete this._onTX;
    }

    if (this._onUpdated) {
      this.removeListener(this.id + ' updated', this._onUpdated);
      delete this._onUpdated;
    }

    if (this._onConfirmed) {
      this.removeListener(this.id + ' confirmed', this._onConfirmed);
      delete this._onConfirmed;
    }

    if (this._onUnconfirmed) {
      this.removeListener(this.id + ' unconfirmed', this._onUnconfirmed);
      delete this._onUnconfirmed;
    }

    if (this._onBalance) {
      this.removeListener(this.id + ' balance', this._onBalance);
      delete this._onBalance;
    }
  }

  this.db = null;
};

Provider.prototype.getAll = function getAll(callback) {
  return this.db.getAll(this.id, callback);
};

Provider.prototype.getCoins = function getCoins(callback) {
  return this.db.getCoins(this.id, callback);
};

Provider.prototype.getPending = function getPending(callback) {
  return this.db.getPending(this.id, callback);
};

Provider.prototype.getBalance = function getBalance(callback) {
  return this.db.getBalance(this.id, callback);
};

Provider.prototype.getLastTime = function getLastTime(callback) {
  return this.db.getLastTime(this.id, callback);
};

Provider.prototype.getLast = function getLast(limit, callback) {
  return this.db.getLast(this.id, limit, callback);
};

Provider.prototype.getRange = function getRange(options, callback) {
  return this.db.getRange(this.id, options, callback);
};

Provider.prototype.getTX = function getTX(hash, callback) {
  return this.db.getTX(hash, callback);
};

Provider.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.db.getCoin(hash, index, callback);
};

Provider.prototype.fillTX = function fillTX(tx, callback) {
  return this.db.fillTX(tx, callback);
};

Provider.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.db.fillCoins(tx, callback);
};

Provider.prototype.addTX = function addTX(tx, callback) {
  return this.db.tx.add(tx, callback);
};

Provider.prototype.update = function update(wallet, address) {
  return this.db.update(wallet, address);
};

/**
 * Expose
 */

module.exports = WalletDB;
