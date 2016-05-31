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
 *  a/[id]/[index] -> account
 *  i/[id]/[name] -> account index
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
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

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });

  this.tx.on('tx', function(tx, map) {
    self.emit('tx', tx, map);
    map.all.forEach(function(path) {
      self.fire(path.id, 'tx', tx, path.name);
    });
  });

  this.tx.on('confirmed', function(tx, map) {
    self.emit('confirmed', tx, map);
    map.all.forEach(function(path) {
      self.fire(path.id, 'confirmed', tx, path.name);
    });
  });

  this.tx.on('unconfirmed', function(tx, map) {
    self.emit('unconfirmed', tx, map);
    map.all.forEach(function(path) {
      self.fire(path.id, 'unconfirmed', tx, path.name);
    });
  });

  this.tx.on('updated', function(tx, map) {
    var balances = {};

    self.emit('updated', tx, map);
    map.all.forEach(function(path) {
      self.fire(path.id, 'updated', tx, path.name);
    });

    utils.forEachSerial(map.output, function(path, next) {
      if (self.listeners('balance').length === 0
          && !self.hasListener(path.id, 'balance')) {
        return next();
      }

      if (balances[path.id] != null)
        return next();

      self.getBalance(path.id, function(err, balance) {
        if (err)
          return next(err);

        balances[path.id] = balance;

        self.fire(path.id, 'balance', balance);

        next();
      });
    }, function(err) {
      if (err)
        return self.emit('error', err);

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

WalletDB.prototype.sync = function sync(tx, map, callback) {
  var self = this;
  utils.forEachSerial(map.output, function(path, next) {
    self.syncOutputDepth(path.id, tx, next);
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
 * Register a wallet with the walletdb.
 * @param {WalletID} id
 * @param {Wallet} wallet
 */

WalletDB.prototype.register = function register(wallet) {
  var id = wallet.id;

  if (!this.watchers[id])
    this.watchers[id] = { wallet: wallet, refs: 0 };

  // Should never happen, and if it does, I will cry.
  assert(this.watchers[id].wallet === wallet, 'I\'m crying.');

  // We do some reference counting here
  // because we're thug like that (police
  // have a fit when your papers legit).
  this.watchers[id].refs++;
};

/**
 * Unregister a wallet with the walletdb.
 * @param {WalletID} id
 * @param {Wallet} wallet
 */

WalletDB.prototype.unregister = function unregister(wallet) {
  var id = wallet.id;
  var watcher = this.watchers[id];

  if (!watcher)
    return;

  assert(watcher.wallet === wallet);
  assert(watcher.refs !== 0, '`wallet.destroy()` called twice!');

  if (--watcher.refs === 0)
    delete this.watchers[id];
};

/**
 * Fire an event for a registered wallet.
 * @param {WalletID} id
 * @param {...Object} args
 */

WalletDB.prototype.fire = function fire(id) {
  var args = Array.prototype.slice.call(arguments, 1);
  var watcher = this.watchers[id];

  if (!watcher)
    return;

  watcher.wallet.emit.apply(watcher.wallet, args);
};

/**
 * Test for a listener on a registered wallet.
 * @param {WalletID} id
 * @param {String} event
 * @returns {Boolean}
 */

WalletDB.prototype.hasListener = function hasListener(id, event) {
  var watcher = this.watchers[id];

  if (!watcher)
    return false;

  if (watcher.wallet.listeners(event).length !== 0)
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
  var wallet;

  if (!id)
    return callback();

  if (this.watchers[id]) {
    this.watchers[id].refs++;
    return callback(null, this.watchers[id].wallet);
  }

  this.db.get('w/' + id, function(err, data) {
    if (err && err.type !== 'NotFoundError')
      return callback();

    if (!data)
      return callback();

    try {
      data = bcoin.wallet.parseRaw(data);
      data.db = self;
      wallet = new bcoin.wallet(data);
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

  this.has(options.id, function(err, exists) {
    if (err)
      return callback(err);

    if (err)
      return callback(err);

    if (exists)
      return callback(new Error('Wallet already exists.'));

    options = utils.merge({}, options);

    options.network = self.network;
    options.db = self;
    wallet = new bcoin.wallet(options);

    wallet.open(function(err) {
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
        data = bcoin.account.parseRaw(data);
        data.db = self;
        account = new bcoin.account(data);
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

    options = utils.merge({}, options);

    if (self.network.witness)
      options.witness = options.witness !== false;

    options.network = self.network;
    options.db = self;
    account = new bcoin.account(options);

    account.open(function(err) {
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
  if (!address)
    return callback();

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

WalletDB.prototype.zap = function zap(id, age, callback) {
  return this.tx.zap(id, age, callback);
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
 * Helper function to get a wallet.
 * @private
 * @param {WalletID} id
 * @param {Function} callback
 * @param {Function} handler
 */

WalletDB.prototype.fetchWallet = function fetchWallet(id, callback, handler) {
  var self = this;

  this.get(id, function(err, wallet) {
    if (err)
      return callback(err);

    if (!wallet)
      return callback(new Error('No wallet.'));

    handler(wallet, function(err, result) {
      // Kill the reference.
      self.unregister(wallet);

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

WalletDB.prototype.createAddress = function createAddress(id, change, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.createAddress(change, callback);
  });
};

WalletDB.prototype.getReceiveAddress = function getReceiveAddress(id, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    callback(null, wallet.receiveAddress);
  });
};

WalletDB.prototype.getChangeAddress = function getChangeAddress(id, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    callback(null, wallet.changeAddress);
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

WalletDB.prototype.createTX = function createTX(id, options, outputs, callback) {
  if (typeof outputs === 'function') {
    callback = outputs;
    outputs = null;
  }

  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.createTX(options, outputs, callback);
  });
};

WalletDB.prototype.addKey = function addKey(id, key, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.addKey(key, callback);
  });
};

WalletDB.prototype.removeKey = function removeKey(id, key, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.removeKey(key, callback);
  });
};

WalletDB.prototype.getInfo = function getInfo(id, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    callback(null, wallet);
  });
};

WalletDB.prototype.getRedeem = function getRedeem(id, hash, callback) {
  this.fetchWallet(id, callback, function(wallet, callback) {
    wallet.getRedeem(hash, callback);
  });
};

/*
 * Helpers
 */

function parsePaths(data) {
  var p = new BufferReader(data);
  var out = {};
  var id;

  while (p.left()) {
    id = p.readVarString('utf8');
    out[id] = {
      id: id,
      name: p.readVarString('utf8'),
      account: p.readU32(),
      change: p.readU32(),
      index: p.readU32()
    };
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
    p.writeVarString(id, 'utf8');
    p.writeVarString(path.name, 'utf8');
    p.writeU32(path.account);
    p.writeU32(path.change);
    p.writeU32(path.index);
  }

  return p.render();
}

function isAlpha(key) {
  return /^[a-zA-Z0-9]+$/.test(key);
}

/*
 * Expose
 */

exports = WalletDB;

module.exports = exports;
