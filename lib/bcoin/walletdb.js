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
  this.dir = options.dir;
  this.type = options.type;

  bcoin.ensurePrefix();

  if (!this.file)
    this.file = bcoin.prefix + '/wallet-' + network.type + '.db';

  if (!this.dir)
    this.dir = bcoin.prefix + '/wallet-' + network.type;

  if (!this.type)
    this.type = 'leveldb';

  WalletDB.global = this;

  this._init();
}

utils.inherits(WalletDB, EventEmitter);

WalletDB._db = {};

WalletDB.prototype._init = function _init() {
  var levelup;

  if (this.type === 'file' && !bcoin.fs) {
    this.type = 'leveldb';
    utils.debug('`fs` module not available. Falling back to leveldb.');
  }

  if (this.type === 'file') {
    if (bcoin.fs) {
      try {
        bcoin.fs.statSync(this.dir);
      } catch (e) {
        bcoin.fs.mkdirSync(this.dir, 0750);
      }
    }
    if (+process.env.BCOIN_FRESH === 1) {
      try {
        bcoin.fs.readdirSync(this.dir).forEach(function(file) {
          bcoin.fs.unlinkSync(this.dir + '/' + file);
        }, this);
      } catch (e) {
        ;
      }
    }
    return;
  }

  if (this.type === 'leveldb') {
    if (!WalletDB._db[this.file]) {
      // Some lazy loading
      levelup = require('levelup');
      WalletDB._db[this.file] = new levelup(this.file, {
        keyEncoding: 'ascii',
        valueEncoding: 'utf8',
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
    return;
  }

  throw new Error('Unknown storage type: ' + this.type);
};

WalletDB.prototype.getJSON = function getJSON(id, callback) {
  if (typeof id === 'object')
    id = id.id;

  callback = utils.ensure(callback);

  if (this.type === 'leveldb')
    return this._getDB(id, callback);

  if (this.type === 'file')
    return this._getFile(id, callback);

  throw new Error('Unknown storage type: ' + this.type);
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
      json = new bcoin.wallet(json).toJSON();
    }
  }

  function cb(err, json) {
    var batch;

    if (err)
      return callback(err);

    if (json && self.type === 'leveldb') {
      batch = self.db.batch();
      Object.keys(json.addressMap).forEach(function(address) {
        batch.put('a/' + address + '/' + json.id, '');
      });
      return batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, json);
      });
    }

    return callback(null, json);
  }

  if (this.type === 'leveldb')
    return this._saveDB(id, json, cb);

  if (this.type === 'file')
    return this._saveFile(id, json, cb);

  throw new Error('Unknown storage type: ' + this.type);
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

    if (json && self.type === 'leveldb') {
      batch = self.db.batch();
      Object.keys(json.addressMap).forEach(function(address) {
        batch.del('a/' + address + '/' + json.id);
      });
      return batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, json);
      });
    }

    return callback(null, json);
  }

  if (this.type === 'leveldb')
    return this._removeDB(id, cb);

  if (this.type === 'file')
    return this._removeFile(id, cb);

  throw new Error('Unknown storage type: ' + this.type);
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

WalletDB.prototype._getFile = function _getFile(id, callback) {
  var self = this;
  var file;

  callback = utils.ensure(callback);

  file = this.dir + '/' + id + '.json';

  fs.readFile(file, 'utf8', function(err, json) {
    if (err && err.code === 'ENOENT')
      return callback();

    if (err)
      return callback(err);

    try {
      json = JSON.parse(json);
    } catch (e) {
      return callback(e);
    }

    return callback(null, json);
  });
};

WalletDB.prototype._getDB = function _getDB(id, callback) {
  var self = this;
  var key;

  callback = utils.ensure(callback);

  key = 'w/' + id;

  this.db.get(key, function(err, json) {
    if (err && err.type === 'NotFoundError')
      return callback();

    if (err)
      return callback(err);

    try {
      json = JSON.parse(json);
    } catch (e) {
      return callback(e);
    }

    return callback(null, json);
  });
};

WalletDB.prototype._saveDB = function _saveDB(id, json, callback) {
  var key = 'w/' + id;
  var data;

  callback = utils.ensure(callback);

  data = JSON.stringify(json);

  this.db.put(key, data, function(err) {
    if (err)
      return callback(err);

    return callback(null, json);
  });
};

WalletDB.prototype._saveFile = function _saveFile(id, json, callback) {
  var file = this.dir + '/' + id + '.json';
  var options, data;

  callback = utils.ensure(callback);

  data = JSON.stringify(json, null, 2);

  options = {
    encoding: 'utf8',
    mode: 0600
  };

  fs.writeFile(file, data, options, function(err) {
    if (err)
      return callback(err);

    return callback(null, json);
  });
};

WalletDB.prototype._removeDB = function _removeDB(id, callback) {
  var self = this;
  var key = 'w/' + id;

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

WalletDB.prototype._removeFile = function _removeFile(id, callback) {
  var file = this.dir + '/' + id + '.json';

  callback = utils.ensure(callback);

  this._getFile(id, function(err, json) {
    if (err)
      return callback(err);

    fs.unlink(file, function(err) {
      if (err && err.code !== 'ENOENT')
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

WalletDB.prototype.remove = function save(id, callback) {
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
  if (this.type !== 'leveldb')
    return utils.nextTick(callback);
  this.db.put('a/' + address + '/' + id, '', callback);
};

WalletDB.prototype.removeAddress = function removeAddress(id, address, callback) {
  callback = utils.ensure(callback);
  if (this.type !== 'leveldb')
    return utils.nextTick(callback);
  this.db.del('a/' + address + '/' + id, callback);
};

WalletDB.prototype._getIDs = function _getIDs(address, callback) {
  var self = this;
  var ids = [];

  var iter = this.db.db.iterator({
    gte: 'a/' + address,
    lte: 'a/' + address + '~',
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

  if (this.type !== 'leveldb')
    return utils.nextTick(callback);

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

/**
 * Expose
 */

module.exports = WalletDB;
