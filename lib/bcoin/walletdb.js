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
var TXDB = require('./txdb');

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
  this.batches = {};
  this.wallets = {};
  this.workerPool = null;

  this.tip = this.network.genesis.hash;
  this.height = 0;

  // We need one read lock for `get` and `create`.
  // It will hold locks specific to wallet ids.
  this.readLock = new ReadLock(this);
  this.locker = new bcoin.locker(this);

  this.walletCache = new bcoin.lru(10000, 1);
  this.accountCache = new bcoin.lru(10000, 1);
  this.pathCache = new bcoin.lru(100000, 1);

  // Try to optimize for up to 1m addresses.
  // We use a regular bloom filter here
  // because we never want members to
  // lose membership, even if quality
  // degrades.
  // Memory used: 1.7mb
  this.filter = this.options.useFilter !== false
    ? bcoin.bloom.fromRate(1000000, 0.001, -1)
    : null;

  this.db = bcoin.ldb({
    location: this.options.location,
    db: this.options.db,
    cacheSize: 8 << 20,
    writeBufferSize: 4 << 20
  });

  if (bcoin.useWorkers)
    this.workerPool = new bcoin.workers();

  this._init();
}

utils.inherits(WalletDB, AsyncObject);

/**
 * Initialize wallet db.
 * @private
 */

WalletDB.prototype._init = function _init() {
  var self = this;

  if (bcoin.useWorkers) {
    this.workerPool.on('error', function(err) {
      self.emit('error', err);
    });
  }
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

    self.db.checkVersion('V', 1, function(err) {
      if (err)
        return callback(err);

      self.writeGenesis(function(err) {
        if (err)
          return callback(err);

        self.loadFilter(callback);
      });
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
  var keys = Object.keys(this.wallets);
  var wallet;

  utils.forEachSerial(keys, function(key, next) {
    wallet = self.wallets[key];
    wallet.destroy(next);
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
 * Start batch.
 * @private
 * @param {WalletID} id
 */

WalletDB.prototype.start = function start(id) {
  assert(utils.isAlpha(id), 'Bad ID for batch.');
  assert(!this.batches[id], 'Batch already started.');
  this.batches[id] = this.db.batch();
};

/**
 * Drop batch.
 * @private
 * @param {WalletID} id
 */

WalletDB.prototype.drop = function drop(id) {
  var batch = this.batch(id);
  batch.clear();
  delete this.batches[id];
};

/**
 * Get batch.
 * @private
 * @param {WalletID} id
 * @returns {Leveldown.Batch}
 */

WalletDB.prototype.batch = function batch(id) {
  var batch;
  assert(utils.isAlpha(id), 'Bad ID for batch.');
  batch = this.batches[id];
  assert(batch, 'Batch does not exist.');
  return batch;
};

/**
 * Save batch.
 * @private
 * @param {WalletID} id
 * @param {Function} callback
 */

WalletDB.prototype.commit = function commit(id, callback) {
  var batch = this.batch(id);
  delete this.batches[id];
  batch.write(callback);
};

/**
 * Load the bloom filter into memory.
 * @private
 * @param {Function} callback
 */

WalletDB.prototype.loadFilter = function loadFilter(callback) {
  var self = this;

  if (!this.filter)
    return callback();

  this.db.iterate({
    gte: 'W',
    lte: 'W~',
    transform: function(key) {
      key = key.split('/')[1];
      self.filter.add(key, 'hex');
    }
  }, callback);
};

/**
 * Test the bloom filter against an array of address hashes.
 * @private
 * @param {Hash[]} addresses
 * @returns {Boolean}
 */

WalletDB.prototype.testFilter = function testFilter(addresses) {
  var i;

  if (!this.filter)
    return true;

  for (i = 0; i < addresses.length; i++) {
    if (this.filter.test(addresses[i], 'hex'))
      return true;
  }

  return false;
};

/**
 * Dump database (for debugging).
 * @param {Function} callback - Returns [Error, Object].
 */

WalletDB.prototype.dump = function dump(callback) {
  var records = {};
  this.db.each({
    gte: 'w',
    lte: 'w~',
    keys: true,
    values: true
  }, function(key, value, next) {
    records[key] = value;
    next();
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, records);
  });
};

/**
 * Register an object with the walletdb.
 * @param {Object} object
 */

WalletDB.prototype.register = function register(wallet) {
  assert(!this.wallets[wallet.id]);
  this.wallets[wallet.id] = wallet;
};

/**
 * Unregister a object with the walletdb.
 * @param {Object} object
 * @returns {Boolean}
 */

WalletDB.prototype.unregister = function unregister(wallet) {
  assert(this.wallets[wallet.id]);
  delete this.wallets[wallet.id];
};

/**
 * Get a wallet from the database, setup watcher.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.get = function get(id, callback) {
  var self = this;
  var unlock, wallet;

  unlock = this._lock(id, get, [id, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (!id)
    return callback();

  wallet = this.wallets[id];

  if (wallet)
    return callback(null, wallet);

  this._get(id, function(err, wallet) {
    if (err)
      return callback(err);

    if (!wallet)
      return callback();

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
 * Get a wallet from the database, do not setup watcher.
 * @private
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype._get = function get(id, callback) {
  var self = this;
  var wallet;

  if (!id)
    return callback();

  wallet = this.walletCache.get(id);

  if (wallet)
    return callback(null, wallet);

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

    self.walletCache.set(id, wallet);

    return callback(null, wallet);
  });
};

/**
 * Save a wallet to the database.
 * @param {Wallet} wallet
 * @param {Function} callback
 */

WalletDB.prototype.save = function save(wallet) {
  var batch = this.batch(wallet.id);
  this.walletCache.set(wallet.id, wallet);
  batch.put('w/' + wallet.id, wallet.toRaw());
};

/**
 * Test an api key against a wallet's api key.
 * @param {WalletID} id
 * @param {String} token
 * @param {Function} callback
 */

WalletDB.prototype.auth = function auth(id, token, callback) {
  this.get(id, function(err, wallet) {
    if (err)
      return callback(err);

    if (!wallet)
      return callback();

    if (typeof token === 'string') {
      if (!utils.isHex(token))
        return callback(new Error('Authentication error.'));
      token = new Buffer(token, 'hex');
    }

    // Compare in constant time:
    if (!utils.ccmp(token, wallet.token))
      return callback(new Error('Authentication error.'));

    return callback(null, wallet);
  });
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

  if (this.wallets[id])
    return callback(null, true);

  if (this.walletCache.has(id))
    return callback(null, true);

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

  this.getAccountIndex(id, name, function(err, index) {
    if (err)
      return callback(err);

    if (index === -1)
      return callback();

    self._getAccount(id, index, function(err, account) {
      if (err)
        return callback(err);

      if (!account)
        return callback();

      account.open(function(err) {
        if (err)
          return callback(err);

        return callback(null, account);
      });
    });
  });
};

/**
 * Get an account from the database. Do not setup watcher.
 * @private
 * @param {WalletID} id
 * @param {Number} index - Account index.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype._getAccount = function getAccount(id, index, callback) {
  var self = this;
  var key = id + '/' + index;
  var account = this.accountCache.get(key);

  if (account)
    return callback(null, account);

  this.db.get('a/' + key, function(err, data) {
    if (err)
      return callback(err);

    if (!data)
      return callback();

    try {
      account = bcoin.account.fromRaw(self, data);
    } catch (e) {
      return callback(e);
    }

    self.accountCache.set(key, account);

    return callback(null, account);
  });
};

/**
 * List account names and indexes from the db.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Array].
 */

WalletDB.prototype.getAccounts = function getAccounts(id, callback) {
  var map = [];
  var i, accounts;

  if (!utils.isAlpha(id))
    return callback(new Error('Wallet IDs must be alphanumeric.'));

  this.db.iterate({
    gte: 'i/' + id + '/',
    lte: 'i/' + id + '/~',
    values: true,
    parse: function(value, key) {
      var name = key.split('/')[2];
      var index = value.readUInt32LE(0, true);
      map[index] = name;
    }
  }, function(err) {
    if (err)
      return callback(err);

    // Get it out of hash table mode.
    accounts = new Array(map.length);

    for (i = 0; i < map.length; i++) {
      assert(map[i] != null);
      accounts[i] = map[i];
    }

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
  if (!id)
    return callback(null, -1);

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

WalletDB.prototype.saveAccount = function saveAccount(account) {
  var batch = this.batch(account.id);
  var index = new Buffer(4);
  var key = account.id + '/' + account.accountIndex;

  index.writeUInt32LE(account.accountIndex, 0, true);

  batch.put('a/' + key, account.toRaw());
  batch.put('i/' + account.id + '/' + account.name, index);

  this.accountCache.set(key, account);
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

    try {
      account = bcoin.account.fromOptions(self, options);
    } catch (e) {
      return callback(e);
    }

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
  var key;

  if (!id)
    return callback(null, false);

  this.getAccountIndex(id, account, function(err, index) {
    if (err)
      return callback(err);

    if (index === -1)
      return callback(null, false);

    key = id + '/' + index;

    if (self.accountCache.has(key))
      return callback(null, true);

    self.db.has('a/' + key, callback);
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
  var batch = this.batch(id);
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

    if (self.filter)
      self.filter.add(hash, 'hex');

    self.emit('save address', address, path);

    self._getPaths(hash, function(err, paths) {
      if (err)
        return next(err);

      if (!paths)
        paths = {};

      if (paths[id])
        return next();

      paths[id] = path;

      self.pathCache.set(hash, paths);

      batch.put('W/' + hash, serializePaths(paths));

      next();
    });
  }, callback);
};

/**
 * Retrieve paths by hash.
 * @param {Hash} hash
 * @param {Function} callback
 */

WalletDB.prototype._getPaths = function _getPaths(hash, callback) {
  var self = this;
  var paths;

  if (!hash)
    return callback();

  paths = this.pathCache.get(hash);

  if (paths)
    return callback(null, paths);

  this.db.fetch('W/' + hash, parsePaths, function(err, paths) {
    if (err)
      return callback(err);

    if (!paths)
      return callback();

    self.pathCache.set(hash, paths);

    return callback(null, paths);
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
  this._getPaths(address, callback);
};

/**
 * Get all address hashes.
 * @param {WalletID} id
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
 * Get all wallet ids.
 * @param {Function} callback
 */

WalletDB.prototype.getWallets = function getWallets(callback) {
  this.db.iterate({
    gte: 'w',
    lte: 'w~',
    transform: function(key) {
      return key.split('/')[1];
    }
  }, callback);
};

/**
 * Rescan the blockchain.
 * @param {ChainDB} chaindb
 * @param {Function} callback
 */

WalletDB.prototype.rescan = function rescan(chaindb, callback) {
  var self = this;

  this.getAddresses(function(err, hashes) {
    if (err)
      return callback(err);

    self.logger.info('Scanning for %d addresses.', hashes.length);

    chaindb.scan(self.tip, hashes, function(txs, block, next) {
      self.addBlock(block, txs, next);
    }, callback);
  });
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

    handler(wallet, function(err, res1, res2) {
      if (err)
        return callback(err);

      callback(null, res1, res2);
    });
  });
};

/**
 * Map a transactions' addresses to wallet IDs.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link PathInfo[]}].
 */

WalletDB.prototype.mapWallets = function mapWallets(tx, callback) {
  var self = this;
  var addresses = tx.getHashes('hex');
  var wallets;

  if (!this.testFilter(addresses))
    return callback();

  this.getTable(addresses, function(err, table) {
    if (err)
      return callback(err);

    if (!table)
      return callback();

    wallets = PathInfo.map(self, tx, table);

    return callback(null, wallets);
  });
};

/**
 * Map a transactions' addresses to wallet IDs.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link PathInfo}].
 */

WalletDB.prototype.getPathInfo = function getPathInfo(id, tx, callback) {
  var self = this;
  var addresses = tx.getHashes('hex');
  var info;

  this.getTable(addresses, function(err, table) {
    if (err)
      return callback(err);

    if (!table)
      return callback();

    info = new PathInfo(self, id, tx, table);

    return callback(null, info);
  });
};

/**
 * Map address hashes to paths.
 * @param {Hash[]} address - Address hashes.
 * @param {Function} callback - Returns [Error, {@link AddressTable}].
 */

WalletDB.prototype.getTable = function getTable(addresses, callback) {
  var self = this;
  var table = {};
  var count = 0;
  var i, keys, values;

  utils.forEachSerial(addresses, function(address, next) {
    self.getAddress(address, function(err, paths) {
      if (err)
        return next(err);

      if (!paths) {
        assert(!table[address]);
        table[address] = [];
        return next();
      }

      keys = Object.keys(paths);
      values = [];

      for (i = 0; i < keys.length; i++)
        values.push(paths[keys[i]]);

      assert(!table[address]);
      table[address] = values;
      count += values.length;

      return next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    if (count === 0)
      return callback();

    return callback(null, table);
  });
};

/**
 * Write the genesis block as the best hash.
 * @param {Function} callback
 */

WalletDB.prototype.writeGenesis = function writeGenesis(callback) {
  var self = this;

  this.getTip(function(err, hash, height) {
    if (err)
      return callback(err);

    if (hash) {
      self.tip = hash;
      self.height = height;
      return callback();
    }

    self.setTip(self.tip, self.height, callback);
  });
};

/**
 * Get the best block hash.
 * @param {Function} callback
 */

WalletDB.prototype.getTip = function getTip(callback) {
  this.db.fetch('R', function(data) {
    var p = new BufferReader(data);
    return [p.readHash('hex'), p.readU32()];
  }, function(err, items) {
    if (err)
      return callback(err);

    if (!items)
      return callback(null, null, -1);

    return callback(null, items[0], items[1]);
  });
};

/**
 * Write the best block hash.
 * @param {Hash} hash
 * @param {Function} callback
 */

WalletDB.prototype.setTip = function setTip(hash, height, callback) {
  var self = this;
  var p = new BufferWriter();

  p.writeHash(hash);
  p.writeU32(height);

  this.db.put('R', p.render(), function(err) {
    if (err)
      return callback(err);

    self.tip = hash;
    self.height = height;

    return callback();
  });
};

/**
 * Add a block's transactions and write the new best hash.
 * @param {Block} block
 * @param {Function} callback
 */

WalletDB.prototype.addBlock = function addBlock(block, txs, callback, force) {
  var self = this;
  var unlock;

  unlock = this.locker.lock(addBlock, [block, txs, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (this.options.useCheckpoints) {
    if (block.height < this.network.checkpoints.lastHeight)
      return this.setTip(block.hash, block.height, callback);
  }

  if (!Array.isArray(txs))
    txs = [txs];

  utils.forEachSerial(txs, function(tx, next) {
    self.addTX(tx, next, true);
  }, function(err) {
    if (err)
      return callback(err);

    self.setTip(block.hash, block.height, callback);
  });
};

/**
 * Unconfirm a block's transactions
 * and write the new best hash (SPV version).
 * @param {Block} block
 * @param {Function} callback
 */

WalletDB.prototype.removeBlock = function removeBlock(block, callback, force) {
  var self = this;
  var unlock;

  unlock = this.locker.lock(removeBlock, [block, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.getWallets(function(err, wallets) {
    if (err)
      return callback(err);

    utils.forEachSerial(wallets, function(id, next) {
      self.get(id, function(err, wallet) {
        if (err)
          return next(err);

        if (!wallet)
          return next();

        wallet.tx.getHeightHashes(block.height, function(err, hashes) {
          if (err)
            return callback(err);

          utils.forEachSerial(hashes, function(hash, next) {
            wallet.tx.unconfirm(hash, next);
          }, next);
        });
      });
    }, function(err) {
      if (err)
        return callback(err);
      self.setTip(block.prevBlock, block.height - 1, callback);
    });
  });
};

/**
 * Add a transaction to the database, map addresses
 * to wallet IDs, potentially store orphans, resolve
 * orphans, or confirm a transaction.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error].
 */

WalletDB.prototype.addTX = function addTX(tx, callback, force) {
  var self = this;
  this.mapWallets(tx, function(err, wallets) {
    if (err)
      return callback(err);

    if (!wallets)
      return callback();

    self.logger.info(
      'Incoming transaction for %d wallets (%s).',
      wallets.length, tx.rhash);

    utils.forEachSerial(wallets, function(info, next) {
      self.get(info.id, function(err, wallet) {
        if (err)
          return next(err);

        if (!wallet)
          return next();

        self.logger.debug('Adding tx to wallet: %s', info.id);

        wallet.tx.add(tx, info, function(err) {
          if (err)
            return next(err);

          wallet.handleTX(info, next);
        });
      });
    }, callback);
  });
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
    change: this.change === 1,
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
 * Inspect the path.
 * @returns {String}
 */

Path.prototype.inspect = function() {
  return '<Path: ' + this.id
    + '/' + this.name
    + ': ' + this.toPath()
    + '>';
};

/**
 * Path Info
 */

function PathInfo(db, id, tx, table) {
  if (!(this instanceof PathInfo))
    return new PathInfo(db, id, tx, table);

  // Reference to the walletdb.
  this.db = db;

  // All relevant Accounts for
  // inputs and outputs (for database indexing).
  this.accounts = [];

  // All output paths (for deriving during sync).
  this.paths = [];

  // Wallet ID
  this.id = id;

  // Map of address hashes->paths (for everything).
  this.table = null;

  // Map of address hashes->paths (specific to wallet).
  this.pathMap = {};

  // Current transaction.
  this.tx = null;

  // Wallet-specific details cache.
  this._details = null;
  this._json = null;

  if (tx)
    this.fromTX(tx, table);
}

PathInfo.map = function map(db, tx, table) {
  var hashes = Object.keys(table);
  var wallets = {};
  var info = [];
  var i, j, hash, paths, path, id;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      wallets[path.id] = true;
    }
  }

  wallets = Object.keys(wallets);

  if (wallets.length === 0)
    return;

  for (i = 0; i < wallets.length; i++) {
    id = wallets[i];
    info.push(new PathInfo(db, id, tx, table));
  }

  return info;
};

PathInfo.prototype.fromTX = function fromTX(tx, table) {
  var uniq = {};
  var i, j, hashes, hash, paths, path;

  this.tx = tx;
  this.table = table;

  hashes = Object.keys(table);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      if (path.id !== this.id)
        continue;
      this.pathMap[hash] = path;
      if (!uniq[path.account]) {
        uniq[path.account] = true;
        this.accounts.push(path.account);
      }
    }
  }

  hashes = tx.getOutputHashes('hex');

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      if (path.id !== this.id)
        continue;
      this.paths.push(path);
    }
  }

  return this;
};

PathInfo.fromTX = function fromTX(db, id, tx, table) {
  return new PathInfo(db, id).fromTX(tx, table);
};

/**
 * Test whether the map has paths
 * for a given address hash.
 * @param {Hash} address
 * @returns {Boolean}
 */

PathInfo.prototype.hasPath = function hasPath(address) {
  if (!address)
    return false;

  return this.pathMap[address] != null;
};

/**
 * Get paths for a given address hash.
 * @param {Hash} address
 * @returns {Path[]|null}
 */

PathInfo.prototype.getPath = function getPath(address) {
  if (!address)
    return;

  return this.pathMap[address];
};

PathInfo.prototype.toDetails = function toDetails() {
  var details = this._details;

  if (!details) {
    details = new TXDB.Details(this.db, this.id, this.tx, this.table);
    this._details = details;
  }

  return details;
};

PathInfo.prototype.toJSON = function toJSON() {
  var json = this._json;

  if (!json) {
    json = this.toDetails().toJSON();
    this._json = json;
  }

  return json;
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
