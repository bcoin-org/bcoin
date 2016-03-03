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
  var records = {};

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

      records[key] = value;

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

  this.tx = new bcoin.txdb('w', this.db, {
    addressFilter: this.hasAddress.bind(this)
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });

  this.tx.on('updated', function(tx) {
    self.getIDs(tx.getOutputAddresses(), function(err, ids) {
      if (err)
        return self.emit('error', err);

      self.emit('wallet tx', tx, ids);

      // Only sync for confirmed txs.
      if (tx.ts === 0)
        return;

      utils.forEachSerial(ids, function(id, next) {
        self.getJSON(id, function(err, json) {
          if (err) {
            self.emit('error', err);
            return next();
          }

          // Allocate new addresses if necessary.
          json = bcoin.wallet.sync(json, { txs: [tx] });

          self.saveJSON(id, json, function(err) {
            if (err)
              return next(err);
            next();
          });
        });
      }, function(err) {
        if (err)
          self.emit('error', err);
      });
    });
  });
};

WalletDB.prototype.syncDepth = function syncDepth(id, changeDepth, receiveDepth, callback) {
  callback = utils.ensure(callback);

  if (!receiveDepth)
    receiveDepth = 0;

  if (!changeDepth)
    changeDepth = 0;

  self.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    // Allocate new addresses if necessary.
    json = bcoin.wallet.sync(json, {
      receiveDepth: receiveDepth,
      changeDepth: changeDepth
    });

    self.saveJSON(id, json, function(err) {
      if (err)
        return callback(err);
      self.emit('sync depth', id, receiveDepth, changeDepth);
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
      options.db = self;
      options.tx = self.tx;
      options.provider = self;
      wallet = new bcoin.wallet(options);
    } catch (e) {
      return callback(e);
    }

    return callback(null, wallet);
  });
};

WalletDB.prototype.save = function save(options, callback) {
  var self = this;
  var passphrase = options.passphrase;

  callback = utils.ensure(callback);

  if (options instanceof bcoin.wallet)
    assert(options.db === this);

  this.saveJSON(options.id, options, callback);
};

WalletDB.prototype.remove = function remove(id, callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (id instanceof bcoin.wallet) {
    id.destroy();
    id = id.id;
  }

  return this.removeJSON(id, callback);
};

WalletDB.prototype.create = function create(options, callback) {
  var self = this;
  var passphrase = options.passphrase;

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
        options.db = self;
        options.tx = self.tx;
        options.provider = self;
        wallet = new bcoin.wallet(options);
      } catch (e) {
        return callback(e);
      }
      done();
    } else {
      options.db = self;
      options.tx = self.tx;
      options.provider = self;
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
    new Buffer([]));

  if (address.type === 'multisig') {
    batch.put(
      'w/a/' + address.getScriptAddress() + '/' + wallet.id,
      new Buffer([]));
  }

  if (address.witness) {
    batch.put(
      'w/a/' + address.getProgramAddress() + '/' + wallet.id,
      new Buffer([]));
  }

  batch.write(function(err) {
    if (err)
      self.emit('error', err);

    self._saveDB(wallet.id, wallet.toJSON(), function(err) {
      if (err)
        self.emit('error', err);
    });
  });
};

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

WalletDB.prototype.getLast = function getLast(id, callback) {
  var self = this;
  return this.getAddresses(id, function(err, addresses) {
    if (err)
      return callback(err);

    return self.tx.getLast(addresses, callback);
  });
};

WalletDB.prototype.getAddresses = function getAddresses(id, callback) {
  // Try to avoid a database lookup if we can...
  if (typeof id === 'string' && bcoin.address.validate(id))
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

WalletDB.prototype.hasAddress = function hasAddress(address, callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (!address)
    return callback(null, false);

  var iter = this.db.db.iterator({
    gte: 'w/a/' + address,
    lte: 'w/a/' + address + '~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

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
          return callback(null, false);
        });
      }

      return iter.end(function(err) {
        if (err)
          return callback(err);
        callback(null, true);
      });
    });
  })();
};

WalletDB.prototype.getIDs = function getIDs(address, callback) {
  var self = this;
  var ids = [];

  if (Array.isArray(address)) {
    return utils.forEachSerial(address, function(address, next) {
      self.getIDs(address, function(err, id) {
        if (err)
          return next(err);

        ids = ids.concat(id);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);

      ids = utils.uniqs(ids);

      return callback(null, ids);
    });
  }

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

      ids.push(key.split('/')[3]);

      next();
    });
  })();
};

/**
 * Expose
 */

module.exports = WalletDB;
