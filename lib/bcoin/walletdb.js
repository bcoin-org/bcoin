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
var AsyncObject = require('./async');
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

  AsyncObject.call(this);

  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.fees = options.fees;
  this.logger = options.logger || bcoin.defaultLogger;

  // We need one read lock for `get` and `create`.
  // It will hold locks specific to wallet ids.
  this.readLock = new ReadLock(this);

  this.db = bcoin.ldb({
    location: this.options.location,
    db: this.options.db,
    cacheSize: 8 << 20,
    writeBufferSize: 4 << 20
  });

  this.tx = new bcoin.txdb(this, {
    verify: this.options.verify,
    useFilter: true
  });

  this.watchers = {};

  this._init();
}

utils.inherits(WalletDB, AsyncObject);

/**
 * Initialize wallet db.
 * @private
 */

WalletDB.prototype._init = function _init() {
  var self = this;

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });

  function handleEvent(event, tx, map) {
    var i, path;

    self.emit(event, tx, map);

    for (i = 0; i < map.accounts.length; i++) {
      path = map.accounts[i];
      self.fire(path.id, event, tx, path.name);
    }
  }

  this.tx.on('tx', function(tx, map) {
    handleEvent('tx', tx, map);
  });

  this.tx.on('conflict', function(tx, map) {
    handleEvent('conflict', tx, map);
  });

  this.tx.on('confirmed', function(tx, map) {
    handleEvent('confirmed', tx, map);
  });

  this.tx.on('unconfirmed', function(tx, map) {
    handleEvent('unconfirmed', tx, map);
  });

  this.tx.on('updated', function(tx, map) {
    handleEvent('updated', tx, map);
  });
};

/**
 * Open the walletdb, wait for the database to load.
 * @alias WalletDB#open
 * @param {Function} callback
 */

WalletDB.prototype._open = function open(callback) {
  var self = this;

  this.db.open(function(err) {
    if (err)
      return callback(err);

    self.db.checkVersion('V', 0, function(err) {
      if (err)
        return callback(err);

      self.tx._loadFilter(callback);
    });
  });
};

/**
 * Close the walletdb, wait for the database to close.
 * @alias WalletDB#close
 * @param {Function} callback
 */

WalletDB.prototype._close = function close(callback) {
  var self = this;
  var keys = Object.keys(this.watchers);
  var watcher;

  utils.forEachSerial(keys, function(key, next) {
    watcher = self.watchers[key];
    watcher.refs = 1;
    watcher.object.destroy(next);
  }, function(err) {
    if (err)
      return callback(err);

    self.db.close(callback);
  });
};

/**
 * Invoke mutex lock.
 * @returns {Function} unlock
 */

WalletDB.prototype._lock = function lock(id, func, args, force) {
  return this.readLock.lock(id, func, args, force);
};

/**
 * Emit balance events after a tx is saved.
 * @private
 * @param {TX} tx
 * @param {WalletMap} map
 * @param {Function} callback
 */

WalletDB.prototype.updateBalances = function updateBalances(tx, map, callback) {
  var self = this;
  var balances = {};
  var i, id, keys;

  utils.forEachSerial(map.outputs, function(output, next) {
    id = output.id;

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

    keys = Object.keys(balances);

    for (i = 0; i < keys.length; i++) {
      id = keys[i];
      self.fire(id, 'balance', balances[id]);
    }

    self.emit('balance', balances, map);

    return callback(null, balances);
  });
};

/**
 * Derive new addresses after a tx is saved.
 * @private
 * @param {TX} tx
 * @param {WalletMap} map
 * @param {Function} callback
 */

WalletDB.prototype.syncOutputs = function syncOutputs(tx, map, callback) {
  var self = this;
  var id;

  utils.forEachSerial(map.outputs, function(output, next) {
    id = output.id;

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
 * Derive new addresses and emit balance.
 * @private
 * @param {TX} tx
 * @param {WalletMap} map
 * @param {Function} callback
 */

WalletDB.prototype.handleTX = function handleTX(tx, map, callback) {
  var self = this;
  this.syncOutputs(tx, map, function(err) {
    if (err)
      return callback(err);

    self.updateBalances(tx, map, callback);
  });
};

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
  var unlock, watcher, wallet;

  unlock = this._lock(id, get, [id, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (!id)
    return callback();

  watcher = this.watchers[id];

  if (watcher) {
    watcher.refs++;
    return callback(null, watcher.object);
  }

  this.db.get('w/' + id, function(err, data) {
    if (err)
      return callback(err);

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
  if (!utils.isAlpha(wallet.id))
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
  var wallet, unlock;

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  unlock = this._lock(options.id, create, [options, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

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

      self.logger.info('Created wallet %s.', wallet.id);

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

  this.get(options.id, function(err, wallet) {
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

  this.getAccountIndex(id, name, function(err, index) {
    if (err)
      return callback(err);

    if (index === -1)
      return callback();

    self.db.get('a/' + id + '/' + index, function(err, data) {
      if (err)
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
      assert(index === accounts.length);
      accounts.push(name);
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

  this.db.get('i/' + id + '/' + name, function(err, index) {
    if (err)
      return callback(err);

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

  if (!utils.isAlpha(account.name))
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

      self.logger.info('Created account %s/%s/%d.',
        account.id,
        account.name,
        account.accountIndex);

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
  var items = [];
  var batch = this.db.batch();
  var i, address, path;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    path = Path.fromKeyRing(address);

    items.push([address.getKeyAddress(), path]);

    if (address.type === 'multisig')
      items.push([address.getScriptAddress(), path]);

    if (address.witness)
      items.push([address.getProgramAddress(), path]);
  }

  utils.forEachSerial(items, function(item, next) {
    var address = item[0];
    var path = item[1];
    var hash = address.getHash('hex');

    if (self.tx.filter)
      self.tx.filter.add(hash, 'hex');

    self.emit('save address', address, path);

    self.db.fetch('W/' + hash, parsePaths, function(err, paths) {
      if (err)
        return next(err);

      if (!paths)
        paths = {};

      if (paths[id])
        return next();

      paths[id] = path;

      batch.put('W/' + hash, serializePaths(paths));

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
 * Add a block's transactions and write the new best hash.
 * @param {Block} block
 * @param {Function} callback
 */

WalletDB.prototype.addBlock = function addBlock(block, callback) {
  this.tx.addBlock(block, callback);
};

/**
 * Unconfirm a block's transactions and write the new best hash.
 * @param {Block} block
 * @param {Function} callback
 */

WalletDB.prototype.removeBlock = function removeBlock(block, callback) {
  this.tx.removeBlock(block, callback);
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
 * @property {WalletID} id
 * @property {String} name - Account name.
 * @property {Number} account - Account index.
 * @property {Number} change - Change index.
 * @property {Number} index - Address index.
 * @property {Address|null} address
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

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Path.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  this.id = p.readVarString('utf8');
  this.name = p.readVarString('utf8');
  this.account = p.readU32();
  this.change = p.readU32();
  this.index = p.readU32();
  return this;
};

/**
 * Instantiate path from serialized data.
 * @param {Buffer} data
 * @returns {Path}
 */

Path.fromRaw = function fromRaw(data) {
  return new Path().fromRaw(data);
};

/**
 * Serialize path.
 * @returns {Buffer}
 */

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

/**
 * Inject properties from keyring.
 * @private
 * @param {WalletID} id
 * @param {KeyRing} address
 */

Path.prototype.fromKeyRing = function fromKeyRing(address) {
  this.id = address.id;
  this.name = address.name;
  this.account = address.account;
  this.change = address.change;
  this.index = address.index;
  return this;
};

/**
 * Instantiate path from keyring.
 * @param {WalletID} id
 * @param {KeyRing} address
 * @returns {Path}
 */

Path.fromKeyRing = function fromKeyRing(address) {
  return new Path().fromKeyRing(address);
};

/**
 * Convert path object to string derivation path.
 * @returns {String}
 */

Path.prototype.toPath = function() {
  return 'm/' + this.account
    + '\'/' + this.change
    + '/' + this.index;
};

/**
 * Convert path to a json-friendly object.
 * @returns {Object}
 */

Path.prototype.toJSON = function toJSON() {
  return {
    id: this.id,
    name: this.name,
    path: this.toPath()
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

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

/**
 * Instantiate path from json object.
 * @param {Object} json
 * @returns {Path}
 */

Path.fromJSON = function fromJSON(json) {
  return new Path().fromJSON(json);
};

/**
 * Convert path to a key in the form of (id|account).
 * @returns {String}
 */

Path.prototype.toKey = function toKey() {
  return this.id + '/' + this.account;
};

/**
 * Convert path to a compact json object.
 * @returns {Object}
 */

Path.prototype.toCompact = function toCompact() {
  return {
    path: 'm/' + this.change + '/' + this.index,
    address: this.address ? this.address.toBase58() : null
  };
};

/**
 * Inject properties from compact json object.
 * @private
 * @param {Object} json
 */

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

/**
 * Instantiate path from compact json object.
 * @param {Object} json
 * @returns {Path}
 */

Path.fromCompact = function fromCompact(json) {
  return new Path().fromCompact(json);
};

/**
 * Inspect the path.
 * @returns {String}
 */

Path.prototype.inspect = function() {
  return '<Path: ' + this.id
    + '/' + this.name
    + ': ' + this.toPath()
    + '>';
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

function ReadLock(parent) {
  if (!(this instanceof ReadLock))
    return new ReadLock(parent);

  this.parent = parent;
  this.jobs = [];
  this.busy = {};
}

ReadLock.prototype.lock = function lock(id, func, args, force) {
  var self = this;
  var called;

  if (force || !id) {
    assert(!id || this.busy[id]);
    return function unlock() {
      assert(!called);
      called = true;
    };
  }

  if (this.busy[id]) {
    this.jobs.push([func, args]);
    return;
  }

  this.busy[id] = true;

  return function unlock() {
    var item;

    assert(!called);
    called = true;

    delete self.busy[id];

    if (self.jobs.length === 0)
      return;

    item = self.jobs.shift();

    item[0].apply(self.parent, item[1]);
  };
};

/*
 * Expose
 */

exports = WalletDB;
exports.Path = Path;

module.exports = exports;
