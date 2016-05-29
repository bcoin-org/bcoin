/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

/*
 * Database Layout:
 *  (inherits all from txdb)
 *  W/[address] -> id & path data
 *  w/[id] -> wallet
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
var DUMMY = new Buffer([0]);
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

/**
 * WalletDB
 * @exports WalletDB
 * @constructor
 * @param {Object} options
 * @param {String?} options.name - Database name.
 * @param {String?} options.location - Database file location.
 * @param {String?} options.db - Database backend (`"leveldb"` by default).
 * @param {Boolean?} options.verify - Verify transactions as they
 * come in (note that this will not happen on the worker pool).
 * @property {Boolean} loaded
 */

function WalletDB(options) {
  if (!(this instanceof WalletDB))
    return new WalletDB(options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.watchers = [];
  this.options = options;
  this.loaded = false;
  this.network = bcoin.network.get(options.network);

  this._init();
}

utils.inherits(WalletDB, EventEmitter);

/**
 * Dump database (for debugging).
 * @param {Function} callback - Returns [Error, Object].
 */

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

  this.db = bcoin.ldb({
    network: this.network,
    name: this.options.name || 'wallet',
    location: this.options.location,
    db: this.options.db,
    cacheSize: 8 << 20,
    writeBufferSize: 4 << 20
  });

  this.tx = new bcoin.txdb(this, {
    network: this.network,
    verify: this.options.verify,
    useFilter: true
  });

  this.db.open(function(err) {
    if (err)
      return self.emit('error', err);

    self.tx._loadFilter(function(err) {
      if (err)
        return self.emit('error', err);

      self.emit('open');
      self.loaded = true;
    });
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });

  this.tx.on('tx', function(tx, map) {
    self.emit('tx', tx, map);
    map.all.forEach(function(id) {
      self.fire(id, 'tx', tx);
    });
  });

  this.tx.on('confirmed', function(tx, map) {
    self.emit('confirmed', tx, map);
    map.all.forEach(function(id) {
      self.fire(id, 'confirmed', tx);
    });
  });

  this.tx.on('unconfirmed', function(tx, map) {
    self.emit('unconfirmed', tx, map);
    map.all.forEach(function(id) {
      self.fire(id, 'unconfirmed', tx);
    });
  });

  this.tx.on('updated', function(tx, map) {
    var balances = {};

    self.emit('updated', tx, map);
    map.all.forEach(function(id) {
      self.fire(id, 'updated', tx);
    });

    utils.forEachSerial(map.output, function(id, next) {
      if (self.listeners('balance').length === 0
          && !self.hasListener(id, ' balance')) {
        return next();
      }

      self.getBalance(id, function(err, balance) {
        if (err)
          return next(err);

        balances[id] = balance;

        self.emit('balance', balance, id);
        self.fire(id, 'balance', balance);

        next();
      });
    }, function(err) {
      if (err)
        return self.emit('error', err);

      self.emit('balances', balances, map);
    });
  });
};

WalletDB.prototype.sync = function sync(tx, map, callback) {
  var self = this;
  utils.forEachSerial(map.output, function(id, next) {
    self.syncOutputDepth(id, tx, next);
  }, callback);
};

/**
 * Open the walletdb, wait for the database to load.
 * @param {Function} callback
 */

WalletDB.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Close the walletdb, wait for the database to close.
 * @method
 * @param {Function} callback
 */

WalletDB.prototype.close =
WalletDB.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);
  this.db.close(callback);
};

/**
 * Helper function to get a wallet.
 * @private
 * @param {WalletID} id
 * @param {Function} errback
 * @param {Function} callback
 */

WalletDB.prototype.fetchWallet = function fetchWallet(id, errback, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.get(id, function(err, _, wallet) {
    if (err)
      return errback(err);

    if (!wallet)
      return errback(new Error('No wallet.'));

    callback(wallet);
  });
};

WalletDB.prototype.syncOutputDepth = function syncOutputDepth(id, tx, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.syncOutputDepth(tx, callback);
  });
};

WalletDB.prototype.createAddress = function createAddress(id, change, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.createAddress(change, callback);
  });
};

WalletDB.prototype.getReceiveAddress = function getReceiveAddress(id, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    callback(null, wallet.receiveAddress);
  });
};

WalletDB.prototype.getChangeAddress = function getChangeAddress(id, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    callback(null, wallet.changeAddress);
  });
};

WalletDB.prototype.fill = function fill(id, tx, options, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.fill(tx, options, callback);
  });
};

WalletDB.prototype.scriptInputs = function scriptInputs(id, tx, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.scriptInputs(tx, callback);
  });
};

WalletDB.prototype.sign = function sign(id, tx, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  if (typeof options === 'string' || Buffer.isBuffer(options))
    options = { passphrase: options };

  this.fetchWallet(id, callback, function(wallet) {
    wallet.sign(tx, options, callback);
  });
};

WalletDB.prototype.createTX = function createTX(id, options, outputs, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.createTX(options, outputs, callback);
  });
};

WalletDB.prototype.addKey = function addKey(id, key, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.addKey(key, callback);
  });
};

WalletDB.prototype.removeKey = function removeKey(id, key, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.removeKey(key, callback);
  });
};

WalletDB.prototype.getInfo = function getInfo(id, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    callback(null, wallet);
  });
};

WalletDB.prototype.getRedeem = function getRedeem(id, hash, callback) {
  this.fetchWallet(id, callback, function(wallet) {
    wallet.getRedeem(hash, callback);
  });
};

/**
 * Save a "naked" (non-instantiated) wallet. Will
 * also index the address table.
 * @param {WalletID}
 * @param {Object} json - "Naked" wallet.
 * @param {Function} callback - Returns [Error, Object].
 */

WalletDB.prototype.saveJSON = function saveJSON(id, json, callback) {
  this.db.put('w/' + id, json, callback);
};

/**
 * Remove wallet from the database.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object].
 */

WalletDB.prototype.removeJSON = function removeJSON(id, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    self.db.del('w/' + id, function(err) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      return callback(null, json);
    });
  });
};

/**
 * Retrieve object from the database.
 * @private
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object(nakedWallet)].
 */

WalletDB.prototype.getJSON = function getJSON(id, callback) {
  callback = utils.ensure(callback);

  if (!id)
    return callback();

  this.db.get('w/' + id, function(err, json) {
    if (err && err.type === 'NotFoundError')
      return callback();

    if (err)
      return callback(err);

    try {
      json = bcoin.wallet.parseRaw(json);
    } catch (e) {
      return callback(e);
    }

    return callback(null, json);
  });
};

/**
 * Get a wallet from the database, instantiate, decrypt, and setup watcher.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.get = function get(id, callback) {
  var self = this;

  callback = utils.ensure(callback);

  return this.getJSON(id, function(err, json) {
    var wallet;

    if (err)
      return callback(err);

    if (!json)
      return callback();

    try {
      json.db = self;
      wallet = new bcoin.wallet(json);
    } catch (e) {
      return callback(e);
    }

    wallet.init(function(err) {
      if (err)
        return callback(err);

      return callback(null, new bcoin.cwallet(wallet.id, self), wallet);
    });
  });
};

/**
 * Save a wallet to the database (setup ida and encrypt).
 * @param {Wallet} wallet
 * @param {Function} callback
 */

WalletDB.prototype.save = function save(wallet, callback) {
  var self = this;
  if (Array.isArray(wallet)) {
    return utils.forEachSerial(wallet, function(wallet, next) {
      self.save(wallet, next);
    }, callback);
  }
  this.saveJSON(wallet.id, wallet.toRaw(), callback);
};

/**
 * Remove wallet from the database. Destroy wallet if passed in.
 * @param {WalletID} id
 * @param {Function} callback
 */

WalletDB.prototype.remove = function remove(id, callback) {
  var self = this;
  if (Array.isArray(wallet)) {
    return utils.forEachSerial(id, function(id, next) {
      self.remove(id, next);
    }, callback);
  }
  return this.removeJSON(id, callback);
};

/**
 * Create a new wallet, save to database, setup watcher.
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.create = function create(options, callback) {
  var self = this;
  var wallet;

  this.has(options.id, function(err, exists) {
    if (err)
      return callback(err);

    if (err)
      return callback(err);

    if (exists)
      return callback(new Error('Wallet already exists.'));

    if (self.network.witness)
      options.witness = options.witness !== false;

    options.network = self.network;
    options.db = self;
    wallet = new bcoin.wallet(options);

    wallet.init(function(err) {
      if (err)
        return callback(err);

      return callback(null, new bcoin.cwallet(wallet.id, self), wallet);
    });
  });
};

/**
 * Test for the existence of a wallet.
 * @param {WalletID?} id
 * @param {Function} callback
 */

WalletDB.prototype.has = function has(id, callback) {
  if (!id)
    return callback(null, false);

  this.db.hash('w/' + id, callback);
};

/**
 * Attempt to create wallet, return wallet if already exists.
 * @param {WalletID?} id
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback
 */

WalletDB.prototype.ensure = function ensure(options, callback) {
  var self = this;
  return this.get(options.id, function(err, cwallet, wallet) {
    if (err)
      return callback(err);

    if (cwallet)
      return callback(null, cwallet, wallet);

    self.create(options, callback);
  });
};

/**
 * Save an address to the path map.
 * The path map exists in the form of:
 * `W/[address-hash] -> {walletid1=path1, walletid2=path2, ...}`
 * @param {WalletID} id
 * @param {KeyRing[]} addresses
 * @param {Function} callback
 */

WalletDB.prototype.saveAddress = function saveAddress(id, addresses, callback) {
  var self = this;
  var hashes = [];
  var batch = this.db.batch();
  var i, address;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];

    hashes.push([address.getKeyHash('hex'), address.path]);

    if (address.type === 'multisig')
      hashes.push([address.getScriptHash('hex'), address.path]);

    if (address.witness)
      hashes.push([address.getProgramHash('hex'), address.path]);
  }

  utils.forEach(hashes, function(hash, next) {
    if (self.tx.filter)
      self.tx.filter.add(hash[0], 'hex');

    self.db.fetch('W/' + hash[0], parsePaths, function(err, paths) {
      if (err)
        return next(err);

      if (!paths)
        paths = {};

      if (paths[id])
        return next();

      paths[id] = hash[1];

      batch.put('W/' + hash[0], serializePaths(paths));

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    batch.write(callback);
  });
};

/**
 * Test whether an address hash exists in the
 * path map and is relevant to the wallet id.
 * @param {WalletID} id
 * @param {Hash} address
 * @param {Function} callback
 */

WalletDB.prototype.hasAddress = function hasAddress(id, address, callback) {
  this.getAddress(address, function(err, paths) {
    if (err)
      return callback(err);

    if (!paths || !paths[id])
      return callback(null, false);

    return callback(null, true);
  });
};

/**
 * Get path data for the specified address hash.
 * @param {Hash} address
 * @param {Function} callback
 */

WalletDB.prototype.getAddress = function getAddress(address, callback) {
  this.db.fetch('W/' + address, parsePaths, callback);
};

/**
 * Get the corresponding path for an address hash.
 * @param {WalletID} id
 * @param {Hash} address
 * @param {Function} callback
 */

WalletDB.prototype.getPath = function getPath(id, address, callback) {
  this.getAddress(address, function(err, paths) {
    if (err)
      return callback(err);

    if (!paths || !paths[id])
      return callback();

    return callback(null, paths[id]);
  });
};

/**
 * @see {@link TXDB#add}.
 */

WalletDB.prototype.addTX = function addTX(tx, callback) {
  return this.tx.add(tx, callback);
};

/**
 * @see {@link TXDB#getTX}.
 */

WalletDB.prototype.getTX = function getTX(hash, callback) {
  return this.tx.getTX(hash, callback);
};

/**
 * @see {@link TXDB#getCoin}.
 */

WalletDB.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.tx.getCoin(hash, index, callback);
};

/**
 * @see {@link TXDB#getHistory}.
 */

WalletDB.prototype.getHistory = function getHistory(id, callback) {
  return this.tx.getHistory(id, callback);
};

/**
 * @see {@link TXDB#getCoins}.
 */

WalletDB.prototype.getCoins = function getCoins(id, callback) {
  return this.tx.getCoins(id, callback);
};

/**
 * @see {@link TXDB#getUnconfirmed}.
 */

WalletDB.prototype.getUnconfirmed = function getUnconfirmed(id, callback) {
  return this.tx.getUnconfirmed(id, callback);
};

/**
 * @see {@link TXDB#getBalance}.
 */

WalletDB.prototype.getBalance = function getBalance(id, callback) {
  return this.tx.getBalance(id, callback);
};

/**
 * @see {@link TXDB#getLastTime}.
 */

WalletDB.prototype.getLastTime = function getLastTime(id, callback) {
  return this.tx.getLastTime(id, callback);
};

/**
 * @see {@link TXDB#getLast}.
 */

WalletDB.prototype.getLast = function getLast(id, limit, callback) {
  return this.tx.getLast(id, limit, callback);
};

/**
 * @see {@link TXDB#getRange}.
 */

WalletDB.prototype.getRange = function getRange(id, options, callback) {
  return this.tx.getRange(id, options, callback);
};

/**
 * @see {@link TXDB#fillHistory}.
 */

WalletDB.prototype.fillHistory = function fillHistory(tx, callback) {
  return this.tx.fillHistory(tx, callback);
};

/**
 * @see {@link TXDB#fillCoins}.
 */

WalletDB.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.tx.fillCoins(tx, callback);
};

/**
 * Zap all walletdb transactions.
 * @see {@link TXDB#zap}.
 */

WalletDB.prototype.zap = function zap(id, now, age, callback) {
  return this.tx.zap(id, now, age, callback);
};

/**
 * Notify the database that a block has been
 * removed (reorg). Unconfirms transactions by height.
 * @param {MerkleBlock|Block} block
 * @param {Function} callback
 */

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

/**
 * Notify the database that a block has been
 * removed (reorg). Unconfirms transactions.
 * @param {Block} block
 * @param {Function} callback
 */

WalletDB.prototype.removeBlock = function removeBlock(block, callback) {
  var self = this;

  callback = utils.ensure(callback);

  utils.forEachSerial(block.txs, function(tx, next) {
    self.tx.unconfirm(tx.hash('hex'), next);
  }, callback);
};

/**
 * Register an event emitter with the walletdb.
 * @param {WalletID} id
 * @param {EventEmitter} watcher
 */

WalletDB.prototype.register = function register(id, watcher) {
  if (!this.watchers[id])
    this.watchers[id] = [];

  if (this.watchers[id].indexOf(watcher) === -1)
    this.watchers[id].push(watcher);
};

/**
 * Unregister an event emitter with the walletdb.
 * @param {WalletID} id
 * @param {EventEmitter} watcher
 */

WalletDB.prototype.unregister = function unregister(id, watcher) {
  var watchers = this.watchers[id];
  var i;

  if (!watchers)
    return;

  i = watchers.indexOf(watcher);
  if (i !== -1)
    watchers.splice(i, 1);

  if (watchers.length === 0)
    delete this.watchers[id];
};

/**
 * Fire an event for all registered event emitters.
 * @param {WalletID} id
 * @param {...Object} args
 */

WalletDB.prototype.fire = function fire(id) {
  var args = Array.prototype.slice.call(arguments, 1);
  var watchers = this.watchers[id];
  var i;

  if (!watchers)
    return;

  for (i = 0; i < watchers.length; i++)
    watchers[i].emit.apply(watchers[i], args);
};

/**
 * Test for a listener on a registered event emitter.
 * @param {WalletID} id
 * @param {String} event
 * @returns {Boolean}
 */

WalletDB.prototype.hasListener = function hasListener(id, event) {
  var watchers = this.watchers[id];
  var i;

  if (!watchers)
    return false;

  for (i = 0; i < watchers.length; i++) {
    if (watchers[i].listeners(event).length !== 0)
      return true;
  }

  return false;
};

/*
 * Helpers
 */

function parsePaths(data) {
  var p = new BufferReader(data);
  var out = {};

  while (p.left())
    out[p.readVarString('utf8')] = p.readVarString('ascii');

  return out;
}

function serializePaths(out) {
  var p = new BufferWriter();
  var keys = Object.keys(out);
  var i, id, path;

  for (i = 0; i < keys.length; i++) {
    id = keys[i];
    path = out[id];
    p.writeVarString(id, 'utf8');
    p.writeVarString(path, 'ascii');
  }

  return p.render();
}

/*
 * Expose
 */

exports = WalletDB;

module.exports = exports;
