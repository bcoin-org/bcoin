/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/*
 * Database Layout:
 *  (inherits all from txdb)
 *  W/[address] -> id & path data
 *  w/[id] -> wallet
 *  a/[id]/[index] -> account
 *  i/[id]/[name] -> account index
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
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

  this.watchers = {};
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

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });

  this.tx.on('tx', function(tx, map) {
    self.emit('tx', tx, map);
    map.accounts.forEach(function(path) {
      self.fire(path.id, 'tx', tx, path.name);
    });
  });

  this.tx.on('conflict', function(tx, map) {
    self.emit('conflict', tx, map);
    map.accounts.forEach(function(path) {
      self.fire(path.id, 'conflict', tx, path.name);
    });
  });

  this.tx.on('confirmed', function(tx, map) {
    self.emit('confirmed', tx, map);
    map.accounts.forEach(function(path) {
      self.fire(path.id, 'confirmed', tx, path.name);
    });
  });

  this.tx.on('unconfirmed', function(tx, map) {
    self.emit('unconfirmed', tx, map);
    map.accounts.forEach(function(path) {
      self.fire(path.id, 'unconfirmed', tx, path.name);
    });
  });

  this.tx.on('updated', function(tx, map) {
    self.emit('updated', tx, map);
    map.accounts.forEach(function(path) {
      self.fire(path.id, 'updated', tx, path.name);
    });
    self.updateBalances(tx, map, function(err, balances) {
      if (err)
        return self.emit('error', err);

      Object.keys(balances).forEach(function(id) {
        self.fire(id, 'balance', balances[id]);
      });

      self.emit('balances', balances, map);
    });
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
};

WalletDB.prototype.updateBalances = function updateBalances(tx, map, callback) {
  var self = this;
  var balances = {};

  utils.forEachSerial(map.outputs, function(output, next) {
    var id = output.id;

    if (self.listeners('balance').length === 0
        && !self.hasListener(id, 'balance')) {
      return next();
    }

    if (balances[id] != null)
      return next();

    self.getBalance(id, function(err, balance) {
      if (err)
        return next(err);

      balances[id] = balance;

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    return callback(null, balances);
  });
};

WalletDB.prototype.syncOutputs = function syncOutputs(tx, map, callback) {
  var self = this;
  utils.forEachSerial(map.outputs, function(output, next) {
    var id = output.id;
    self.syncOutputDepth(id, tx, function(err, receive, change) {
      if (err)
        return next(err);
      self.fire(id, 'address', receive, change);
      self.emit('address', receive, change, map);
      next();
    });
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
 * Register an object with the walletdb.
 * @param {Object} object
 */

WalletDB.prototype.register = function register(object) {
  var id = object.id;

  if (!this.watchers[id])
    this.watchers[id] = { object: object, refs: 0 };

  // Should never happen, and if it does, I will cry.
  assert(this.watchers[id].object === object, 'I\'m crying.');

  // We do some reference counting here
  // because we're thug like that (police
  // have a fit when your papers legit).
  this.watchers[id].refs++;
};

/**
 * Unregister a object with the walletdb.
 * @param {Object} object
 * @returns {Boolean}
 */

WalletDB.prototype.unregister = function unregister(object) {
  var id = object.id;
  var watcher = this.watchers[id];

  if (!watcher)
    return false;

  assert(watcher.object === object);
  assert(watcher.refs !== 0, '`destroy()` called twice!');

  if (--watcher.refs === 0) {
    delete this.watchers[id];
    return true;
  }

  return false;
};

/**
 * Watch an object (increment reference count).
 * @param {Object} object
 */

WalletDB.prototype.watch = function watch(object) {
  var id = object.id;
  var watcher = this.watchers[id];

  if (!watcher)
    return;

  watcher.refs++;
};

/**
 * Fire an event for a registered object.
 * @param {WalletID} id
 * @param {...Object} args
 */

WalletDB.prototype.fire = function fire(id) {
  var watcher = this.watchers[id];
  var i, args;

  if (!watcher)
    return;

  args = new Array(arguments.length - 1);

  for (i = 1; i < arguments.length; i++)
    args[i - 1] = arguments[i];

  watcher.object.emit.apply(watcher.object, args);
};

/**
 * Test for a listener on a registered object.
 * @param {WalletID} id
 * @param {String} event
 * @returns {Boolean}
 */

WalletDB.prototype.hasListener = function hasListener(id, event) {
  var watcher = this.watchers[id];

  if (!watcher)
    return false;

  if (watcher.object.listeners(event).length !== 0)
    return true;

  return false;
};

/**
 * Get a wallet from the database, setup watcher.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.get = function get(id, callback) {
  var self = this;
  var watcher, wallet;

  if (!id)
    return callback();

  watcher = this.watchers[id];

  if (watcher) {
    watcher.refs++;
    return callback(null, watcher.object);
  }

  this.db.get('w/' + id, function(err, data) {
    if (err && err.type !== 'NotFoundError')
      return callback();

    if (!data)
      return callback();

    try {
      wallet = bcoin.wallet.fromRaw(self, data);
    } catch (e) {
      return callback(e);
    }

    try {
      self.register(wallet);
    } catch (e) {
      return callback(e);
    }

    wallet.open(function(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
    });
  });
};

/**
 * Save a wallet to the database.
 * @param {Wallet} wallet
 * @param {Function} callback
 */

WalletDB.prototype.save = function save(wallet, callback) {
  if (!isAlpha(wallet.id))
    return callback(new Error('Wallet IDs must be alphanumeric.'));

  this.db.put('w/' + wallet.id, wallet.toRaw(), callback);
};

/**
 * Create a new wallet, save to database, setup watcher.
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.create = function create(options, callback) {
  var self = this;
  var wallet;

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  this.has(options.id, function(err, exists) {
    if (err)
      return callback(err);

    if (err)
      return callback(err);

    if (exists)
      return callback(new Error('Wallet already exists.'));

    try {
      wallet = bcoin.wallet.fromOptions(self, options);
    } catch (e) {
      return callback(e);
    }

    try {
      self.register(wallet);
    } catch (e) {
      return callback(e);
    }

    wallet.init(options, function(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
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

  this.db.has('w/' + id, callback);
};

/**
 * Attempt to create wallet, return wallet if already exists.
 * @param {WalletID?} id
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback
 */

WalletDB.prototype.ensure = function ensure(options, callback) {
  var self = this;
  return this.get(options.id, function(err, wallet) {
    if (err)
      return callback(err);

    if (wallet)
      return callback(null, wallet);

    self.create(options, callback);
  });
};

/**
 * Get an account from the database.
 * @param {WalletID} id
 * @param {String|Number} name - Account name/index.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.getAccount = function getAccount(id, name, callback) {
  var self = this;
  var account;

  return this.getAccountIndex(id, name, function(err, index) {
    if (err)
      return callback(err);

    if (index === -1)
      return callback();

    self.db.get('a/' + id + '/' + index, function(err, data) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      if (!data)
        return callback();

      try {
        account = bcoin.account.fromRaw(self, data);
      } catch (e) {
        return callback(e);
      }

      account.open(function(err) {
        if (err)
          return callback(err);

        return callback(null, account);
      });
    });
  });
};

/**
 * List account names and indexes from the db.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Array].
 */

WalletDB.prototype.getAccounts = function getAccounts(id, callback) {
  var accounts = [];
  this.db.iterate({
    gte: 'i/' + id + '/',
    lte: 'i/' + id + '/~',
    values: true,
    parse: function(value, key) {
      var name = key.split('/')[2];
      var index = value.readUInt32LE(0, true);
      accounts[index] = name;
    }
  }, function(err) {
    if (err)
      return callback(err);

    return callback(null, accounts);
  });
};

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} id
 * @param {String|Number} name - Account name/index.
 * @param {Function} callback - Returns [Error, Number].
 */

WalletDB.prototype.getAccountIndex = function getAccountIndex(id, name, callback) {
  if (name == null)
    return callback(null, -1);

  if (typeof name === 'number')
    return callback(null, name);

  return this.db.get('i/' + id + '/' + name, function(err, index) {
    if (err && err.type !== 'NotFoundError')
      return callback();

    if (!index)
      return callback(null, -1);

    return callback(null, index.readUInt32LE(0, true));
  });
};

/**
 * Save an account to the database.
 * @param {Account} account
 * @param {Function} callback
 */

WalletDB.prototype.saveAccount = function saveAccount(account, callback) {
  var index, batch;

  if (!isAlpha(account.name))
    return callback(new Error('Account names must be alphanumeric.'));

  batch = this.db.batch();

  index = new Buffer(4);
  index.writeUInt32LE(account.accountIndex, 0, true);

  batch.put('a/' + account.id + '/' + account.accountIndex, account.toRaw());
  batch.put('i/' + account.id + '/' + account.name, index);

  batch.write(callback);
};

/**
 * Create an account.
 * @param {Object} options - See {@link Account} options.
 * @param {Function} callback - Returns [Error, {@link Account}].
 */

WalletDB.prototype.createAccount = function createAccount(options, callback) {
  var self = this;
  var account;

  this.hasAccount(options.id, options.accountIndex, function(err, exists) {
    if (err)
      return callback(err);

    if (err)
      return callback(err);

    if (exists)
      return callback(new Error('Account already exists.'));

    account = bcoin.account.fromOptions(self, options);

    account.init(function(err) {
      if (err)
        return callback(err);

      return callback(null, account);
    });
  });
};

/**
 * Test for the existence of an account.
 * @param {WalletID} id
 * @param {String|Number} account
 * @param {Function} callback - Returns [Error, Boolean].
 */

WalletDB.prototype.hasAccount = function hasAccount(id, account, callback) {
  var self = this;

  if (!id)
    return callback(null, false);

  this.getAccountIndex(id, account, function(err, index) {
    if (err)
      return callback(err);

    if (index === -1)
      return callback(null, false);

    self.db.has('a/' + id + '/' + index, callback);
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

    hashes.push([address.getKeyHash('hex'), address]);

    if (address.type === 'multisig')
      hashes.push([address.getScriptHash('hex'), address]);

    if (address.witness)
      hashes.push([address.getProgramHash('hex'), address]);
  }

  utils.forEachSerial(hashes, function(hash, next) {
    if (self.tx.filter)
      self.tx.filter.add(hash[0], 'hex');

    self.emit('save address', hash[0], hash[1]);

    self.db.fetch('W/' + hash[0], parsePaths, function(err, paths) {
      if (err)
        return next(err);

      if (!paths)
        paths = {};

      if (paths[id])
        return next();

      paths[id] = Path.fromKeyRing(id, hash[1]);

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
  if (!address)
    return callback();

  this.db.fetch('W/' + address, parsePaths, callback);
};

/**
 * Get all address hashes.
 * @param {WalletId} id
 * @param {Function} callback
 */

WalletDB.prototype.getAddresses = function getAddresses(id, callback) {
  if (!callback) {
    callback = id;
    id = null;
  }

  this.db.iterate({
    gte: 'W',
    lte: 'W~',
    values: true,
    parse: function(value, key) {
      var paths = parsePaths(value);

      if (id && !paths[id])
        return;

      return key.split('/')[1];
    }
  }, callback);
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

WalletDB.prototype.getHistory = function getHistory(id, account, callback) {
  var self = this;
  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getHistory(id, callback);
  });
};

/**
 * @see {@link TXDB#getCoins}.
 */

WalletDB.prototype.getCoins = function getCoins(id, account, callback) {
  var self = this;
  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getCoins(id, callback);
  });
};

/**
 * @see {@link TXDB#getUnconfirmed}.
 */

WalletDB.prototype.getUnconfirmed = function getUnconfirmed(id, account, callback) {
  var self = this;
  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getUnconfirmed(id, callback);
  });
};

/**
 * @see {@link TXDB#getBalance}.
 */

WalletDB.prototype.getBalance = function getBalance(id, account, callback) {
  var self = this;
  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getBalance(id, callback);
  });
};

/**
 * @see {@link TXDB#getLastTime}.
 */

WalletDB.prototype.getLastTime = function getLastTime(id, account, callback) {
  var self = this;

  if (typeof account === 'function') {
    callback = account;
    account = null;
  }

  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getLastTime(id, callback);
  });
};

/**
 * @see {@link TXDB#getLast}.
 */

WalletDB.prototype.getLast = function getLast(id, account, limit, callback) {
  var self = this;

  if (typeof limit === 'function') {
    callback = limit;
    limit = account;
    account = null;
  }

  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getLast(id, limit, callback);
  });
};

WalletDB.prototype.getTimeRange = function getTimeRange(id, account, options, callback) {
  var self = this;

  if (typeof options === 'function') {
    callback = options;
    options = account;
    account = null;
  }

  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getTimeRange(id, options, callback);
  });
};

/**
 * @see {@link TXDB#getRange}.
 */

WalletDB.prototype.getRange = function getRange(id, account, options, callback) {
  var self = this;

  if (typeof options === 'function') {
    callback = options;
    options = account;
    account = null;
  }

  this._getKey(id, account, callback, function(id, callback) {
    self.tx.getRange(id, options, callback);
  });
};

/**
 * @see {@link TXDB#fillHistory}.
 */

WalletDB.prototype.fillHistory = function fillHistory(tx, callback) {
  this.tx.fillHistory(tx, callback);
};

/**
 * @see {@link TXDB#fillCoins}.
 */

WalletDB.prototype.fillCoins = function fillCoins(tx, callback) {
  this.tx.fillCoins(tx, callback);
};

/**
 * Zap all walletdb transactions.
 * @see {@link TXDB#zap}.
 */

WalletDB.prototype.zap = function zap(id, account, age, callback) {
  var self = this;

  if (typeof age === 'function') {
    callback = age;
    age = account;
    account = null;
  }

  this._getKey(id, account, callback, function(id, callback) {
    self.tx.zap(id, age, callback);
  });
};

/**
 * Parse arguments and return an id
 * consisting of `walletid/accountname`.
 * @private
 * @param {WalletID} id
 * @param {String|Number} account
 * @param {Function} errback
 * @param {Function} callback - Returns [String, Function].
 */

WalletDB.prototype._getKey = function _getKey(id, account, errback, callback) {
  if (typeof account === 'function') {
    errback = account;
    account = null;
  }

  if (account == null)
    return callback(id, errback);

  this.getAccountIndex(id, account, function(err, index) {
    if (err)
      return errback(err);

    if (index === -1)
      return errback(new Error('Account not found.'));

    return callback(id + '/' + index, errback);
  });
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

  this.tx.getHeightHashes(block.height, function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      self.tx.unconfirm(hash, next);
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
 * Helper function to get a wallet.
 * @private
 * @param {WalletID} id
 * @param {Function} callback
 * @param {Function} handler
 */

WalletDB.prototype.fetchWallet = function fetchWallet(id, callback, handler) {
  this.get(id, function(err, wallet) {
    if (err)
      return callback(err);

    if (!wallet)
      return callback(new Error('No wallet.'));

    handler(wallet, function(err, result) {
      // Kill the reference.
      wallet.destroy();

      if (err)
        return callback(err);

      callback(null, result);
    });
  });
};

WalletDB.prototype.syncOutputDepth = function syncOutputDepth(id, tx, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.syncOutputDepth(tx, callback);
  });
};

WalletDB.prototype.createAddress = function createAddress(id, name, change, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.createAddress(name, change, callback);
  });
};

WalletDB.prototype.fill = function fill(id, tx, options, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.fill(tx, options, callback);
  });
};

WalletDB.prototype.scriptInputs = function scriptInputs(id, tx, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.scriptInputs(tx, callback);
  });
};

WalletDB.prototype.sign = function sign(id, tx, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.sign(tx, options, callback);
  });
};

WalletDB.prototype.createTX = function createTX(id, options, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.createTX(options, callback);
  });
};

WalletDB.prototype.addKey = function addKey(id, name, key, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.addKey(name, key, callback);
  });
};

WalletDB.prototype.removeKey = function removeKey(id, name, key, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.removeKey(name, key, callback);
  });
};

WalletDB.prototype.getInfo = function getInfo(id, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    callback(null, wallet);
  });
};

WalletDB.prototype.ensureAccount = function ensureAccount(id, options, callback) {
  var self = this;
  var account = options.name || options.account;
  this.fetchWallet(id, callback, function(wallet, callback) {
    self.hasAccount(wallet.id, account, function(err, exists) {
      if (err)
        return callback(err);
      if (exists)
        return wallet.getAccount(account, callback);
      return wallet.createAccount(options, callback);
    });
  });
};

WalletDB.prototype.getRedeem = function getRedeem(id, hash, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.getRedeem(hash, callback);
  });
};

/**
 * Path
 * @constructor
 * @private
 */

function Path() {
  if (!(this instanceof Path))
    return new Path();

  this.id = null;
  this.name = null;
  this.account = 0;
  this.change = 0;
  this.index = 0;
  this.address = null;
}

Path.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  this.id = p.readVarString('utf8');
  this.name = p.readVarString('utf8');
  this.account = p.readU32();
  this.change = p.readU32();
  this.index = p.readU32();
  return this;
};

Path.fromRaw = function fromRaw(data) {
  return new Path().fromRaw(data);
};

Path.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeVarString(this.id, 'utf8');
  p.writeVarString(this.name, 'utf8');
  p.writeU32(this.account);
  p.writeU32(this.change);
  p.writeU32(this.index);

  if (!writer)
    p = p.render();

  return p;
};

Path.prototype.fromKeyRing = function fromKeyRing(id, address) {
  this.id = id;
  this.name = address.name;
  this.account = address.account;
  this.change = address.change;
  this.index = address.index;
  return this;
};

Path.fromKeyRing = function fromKeyRing(id, address) {
  return new Path().fromKeyRing(id, address);
};

Path.prototype.toPath = function() {
  return 'm/' + this.account
    + '\'/' + this.change
    + '/' + this.index;
};

Path.prototype.inspect = function() {
  return '<Path: ' + this.id
    + '/' + this.name
    + ': ' + this.toPath()
    + '>';
};

Path.prototype.toJSON = function toJSON() {
  return {
    id: this.id,
    name: this.name,
    path: this.toPath()
  };
};

Path.prototype.fromJSON = function fromJSON(json) {
  var indexes = bcoin.hd.parsePath(json.path, constants.hd.MAX_INDEX);

  assert(indexes.length === 3);
  assert(indexes[0] >= 0);
  indexes[0] -= constants.hd.HARDENED;

  this.id = json.id;
  this.name = json.name;
  this.account = indexes[0];
  this.change = indexes[1];
  this.index = indexes[2];

  return this;
};

Path.fromJSON = function fromJSON(json) {
  return new Path().fromJSON(json);
};

Path.prototype.toKey = function toKey() {
  return this.id + '/' + this.name + ':' + this.account;
};

Path.prototype.fromKey = function fromKey(key) {
  var parts = key.split('/');
  this.id = parts[0];
  parts = parts[1].split(':');
  this.name = parts[0];
  this.account = +parts[1];
  return this;
};

Path.fromKey = function fromKey(key) {
  return new Path().fromKey(key);
};

Path.prototype.toCompact = function toCompact() {
  return {
    path: 'm/' + this.change + '/' + this.index,
    address: this.address ? this.address.toBase58() : null
  };
};

Path.prototype.fromCompact = function fromCompact(json) {
  var indexes = bcoin.hd.parsePath(json.path, constants.hd.MAX_INDEX);

  assert(indexes.length === 2);

  this.change = indexes[0];
  this.index = indexes[1];
  this.address = json.address
    ? bcoin.address.fromBase58(json.address)
    : null;

  return this;
};

Path.fromCompact = function fromCompact(json) {
  return new Path().fromCompact(json);
};

/*
 * Helpers
 */

function parsePaths(data) {
  var p = new BufferReader(data);
  var out = {};
  var path;

  while (p.left()) {
    path = Path.fromRaw(p);
    out[path.id] = path;
  }

  return out;
}

function serializePaths(out) {
  var p = new BufferWriter();
  var keys = Object.keys(out);
  var i, id, path;

  for (i = 0; i < keys.length; i++) {
    id = keys[i];
    path = out[id];
    path.toRaw(p);
  }

  return p.render();
}

function isAlpha(key) {
  // We allow /-~ (exclusive), 0-} (inclusive)
  return /^[\u0030-\u007d]+$/.test(key);
}

/*
 * Expose
 */

exports = WalletDB;
exports.Path = Path;

module.exports = exports;
