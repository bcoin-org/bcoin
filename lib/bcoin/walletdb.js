/**
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var levelup = require('levelup');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

/**
 * WalletDB
 */

function WalletDB(node, options) {
  var self = this;

  if (!(this instanceof WalletDB))
    return new WalletDB(node, options);

  if (WalletDB.global)
    return WalletDB.global;

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.node = node;
  this.options = options;
  this.file = options.file;

  bcoin.ensurePrefix();

  if (!this.file)
    this.file = bcoin.prefix + '/wallet-' + network.type + '.db';

  WalletDB.global = this;

  this._init();
}

utils.inherits(WalletDB, EventEmitter);

WalletDB._db = {};

WalletDB.prototype.dump = function dump(callback) {
  var self = this;
  var records = [];

  var iter = this.db.db.iterator({
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

      records.push([key, value.slice(0, 200).toString('hex')]);

      next();
    });
  })();
};

WalletDB.prototype._init = function _init() {
  var self = this;
  var levelup;

  if (!WalletDB._db[this.file]) {
    // Some lazy loading
    levelup = require('levelup');
    WalletDB._db[this.file] = new levelup(this.file, {
      keyEncoding: 'ascii',
      valueEncoding: 'binary',
      createIfMissing: true,
      errorIfExists: false,
      compression: true,
      cacheSize: 1 * 1024 * 1024,
      writeBufferSize: 1 * 1024 * 1024,
      // blockSize: 4 * 1024,
      maxOpenFiles: 1024,
      // blockRestartInterval: 16,
      db: bcoin.isBrowser
        ? require('level-js')
        : require('level' + 'down')
    });
  }

  this.db = WalletDB._db[this.file];

  this.tx = new bcoin.txdb('w', this.db);
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

  if (json instanceof bcoin.wallet) {
    json = json.toJSON();
  } else {
    if (typeof json.v !== 'number') {
      json = utils.merge({}, json);
      delete json.store;
      delete json.db;
      var save = bcoin.wallet.prototype.save;
      bcoin.wallet.prototype.save = function() {};
      json = new bcoin.wallet(json).toJSON();
      bcoin.wallet.prototype.save = save;
    }
  }

  function cb(err, json) {
    var batch;

    if (err)
      return callback(err);

    if (json) {
      batch = self.db.batch();
      Object.keys(json.addressMap).forEach(function(address) {
        batch.put('w/a/' + address + '/' + json.id, new Buffer([]));
      });
      return batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, json);
      });
    }

    return callback(null, json);
  }

  return this._saveDB(id, json, cb);
};

WalletDB.prototype.removeJSON = function removeJSON(id, callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (typeof id === 'object')
    id = id.id;

  function cb(err, json) {
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
  }

  return this._removeDB(id, cb);
};

WalletDB.prototype.createJSON = function createJSON(id, options, callback) {
  var self = this;
  callback = utils.ensure(callback);
  return this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    if (!json)
      return self.saveJSON(options.id, options, callback);

    return callback(null, json);
  });
};

WalletDB.prototype._getDB = function _getDB(id, callback) {
  var self = this;
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

    wallet = bcoin.wallet.fromJSON(options, passphrase);
    wallet.store = true;
    wallet.db = self;

    return callback(null, wallet);
  });
};

WalletDB.prototype.save = function save(options, callback) {
  var self = this;
  var passphrase = options.passphrase;

  callback = utils.ensure(callback);

  return this.saveJSON(options.id, options, callback);
};

WalletDB.prototype.remove = function remove(id, callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (id instanceof bcoin.wallet) {
    id.store = false;
    id.db = null;
    id = id.id;
  }

  return this.removeJSON(id, callback);
};

WalletDB.prototype.create = function create(options, callback) {
  var self = this;
  var passphrase = options.passphrase;

  callback = utils.ensure(callback);

  if (options instanceof bcoin.wallet) {
    options.store = true;
    options.db = this;
  }

  return this.createJSON(options.id, options, function(err, json) {
    var wallet;

    if (err)
      return callback(err);

    wallet = bcoin.wallet.fromJSON(json, options.passphrase);
    wallet.store = true;
    wallet.db = self;

    return callback(null, wallet);
  });
};

WalletDB.prototype.saveAddress = function saveAddress(id, address, callback) {
  callback = utils.ensure(callback);
  this.db.put('w/a/' + address + '/' + id, new Buffer([]), callback);
};

WalletDB.prototype.removeAddress = function removeAddress(id, address, callback) {
  callback = utils.ensure(callback);
  this.db.del('w/a/' + address + '/' + id, callback);
};

/*
WalletDB.prototype._getIDs = function _getIDs(address, callback) {
  var self = this;
  var ids = [];

  var iter = this.db.db.iterator({
    gte: 'w/a/' + address,
    lte: 'w/a/' + address + '~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
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
          return callback(null, ids);
        });
      }

      ids.push(key.split('/')[2]);

      next();
    });
  })();
};

WalletDB.prototype.test = function test(addresses, callback) {
  var self = this;

  utils.forEachSerial(addresses, function(address, next) {
    self._getIDs(address, function(err, ids) {
      if (err)
        return next(err);

      if (ids.length > 0)
        return callback(null, ids);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback();
  });
};

WalletDB.prototype.ownInput = function ownInput(tx, callback) {
  var self = this;
  var addresses;

  if (tx.getAddress) {
    assert(tx instanceof bcoin.input);
    addresses = tx.getAddress();
    if (addresses)
      addresses = [addresses];
    else
      addresses = [];
  } else {
    addresses = tx.getInputAddresses();
  }

  return this.test(addresses, callback);
};

WalletDB.prototype.ownOutput = function ownOutput(tx, callback) {
  var self = this;
  var addresses;

  if (tx.getAddress) {
    assert(tx instanceof bcoin.output);
    addresses = tx.getAddress();
    if (addresses)
      addresses = [addresses];
    else
      addresses = [];
  } else {
    addresses = tx.getOutputAddresses();
  }

  return this.test(addresses, callback);
};

WalletDB.prototype.ownTX = function ownTX(tx, callback) {
  var self = this;
  return this.ownInput(tx, function(err, input) {
    if (err)
      return callback(err);

    return self.ownOutput(tx, function(err, output) {
      if (err)
        return callback(err);

      if (input || output)
        return callback(null, input, output);

      return callback();
    });
  });
};
*/

WalletDB.prototype.addTX = function addTX(tx, callback) {
  return this.tx.add(tx, callback);
};

WalletDB.prototype.getAll = function getAll(id, callback) {
  var self = this;
  return this.getAddresses(id, function(err, addresses) {
    if (err)
      return callback(err);
    return self.tx.getAllByAddress(addresses, callback);
  });
};

WalletDB.prototype.getUnspent = function getUnspent(id, callback) {
  var self = this;
  return this.getAddresses(id, function(err, addresses) {
    if (err)
      return callback(err);
    return self.tx.getUnspentByAddress(addresses, callback);
  });
};

WalletDB.prototype.getPending = function getPending(id, callback) {
  var self = this;
  return this.getAddresses(id, function(err, addresses) {
    if (err)
      return callback(err);
    return self.tx.getPendingByAddress(addresses, callback);
  });
};

WalletDB.prototype.getBalance = function getBalance(id, callback) {
  var self = this;
  return this.getAddresses(id, function(err, addresses) {
    if (err)
      return callback(err);
    return self.tx.getBalanceByAddress(addresses, callback);
  });
};

WalletDB.prototype.getAddresses = function getAddresses(id, callback) {
  if (typeof id === 'string')
    return callback(null, [id]);

  if (Array.isArray(id))
    return callback(null, id);

  if (id.addressMap)
    return callback(null, Object.keys(id.addressMap));

  if (typeof id === 'object')
    return callback(null, Object.keys(id));

  return this.db.get('w/w/' + id, function(err, buf) {
    var json;

    if (err)
      return callback(err);

    try {
      json = JSON.parse(buf.toString('utf8'));
    } catch (e) {
      return callback(e);
    }

    return callback(null, Object.keys(json.addressMap));
  });
};

WalletDB.prototype.getIDs = function _getIDs(address, callback) {
  var self = this;
  var ids = [];

  var iter = this.db.db.iterator({
    gte: 'w/a/' + address,
    lte: 'w/a/' + address + '~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
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
          return callback(null, ids);
        });
      }

      ids.push(key.split('/')[2]);

      next();
    });
  })();
};

WalletDB.prototype.testTX = function test(tx, callback) {
  var self = this;

  return callback(null, true);
  utils.forEachSerial(tx.getAddresses(), function(address, next) {
    self.getIDs(address, function(err, ids) {
      if (err)
        return next(err);

      if (ids.length > 0)
        return callback(null, true);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, false);
  });
};

/**
 * Expose
 */

module.exports = WalletDB;
