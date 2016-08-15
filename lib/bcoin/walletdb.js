/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/*
 * Database Layout:
 *  p/[address] -> path data
 *  w/[wid] -> wallet
 *  l/[id] -> wid
 *  a/[wid]/[index] -> account
 *  i/[wid]/[name] -> account index
 *  t/[wid]/* -> txdb
 *  R -> tip
 *  b/[hash] -> wallet block
 *  t/[hash] -> tx->wid map
 */

var bcoin = require('./env');
var AsyncObject = require('./async');
var utils = require('./utils');
var pad32 = utils.pad32;
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
  this.depth = 0;

  // We need one read lock for `get` and `create`.
  // It will hold locks specific to wallet ids.
  this.readLock = new MappedLock(this);
  this.writeLock = new MappedLock(this);
  this.txLock = new bcoin.locker(this);

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

        self.getDepth(function(err, depth) {
          if (err)
            return callback(err);

          self.depth = depth;

          self.logger.info(
            'WalletDB loaded (depth=%d, height=%d).',
            depth, self.height);

          self.loadFilter(callback);
        });
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
 * Get current wallet wid depth.
 * @private
 * @param {Function} callback
 */

WalletDB.prototype.getDepth = function getDepth(callback) {
  var iter, parts, depth;

  // This may seem like a strange way to do
  // this, but updating a global state when
  // creating a new wallet is actually pretty
  // damn tricky. There would be major atomicity
  // issues if updating a global state inside
  // a "scoped" state. So, we avoid all the
  // nonsense of adding a global lock to
  // walletdb.create by simply seeking to the
  // highest wallet wid.
  iter = this.db.iterator({
    gte: 'w/' + pad32(0),
    lte: 'w/' + pad32(0xffffffff),
    reverse: true,
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false,
    valueAsBuffer: true
  });

  iter.next(function(err, key, value) {
    if (err) {
      return iter.end(function() {
        callback(err);
      });
    }

    iter.end(function(err) {
      if (err)
        return callback(err);

      if (key === undefined)
        return callback(null, 1);

      parts = key.split('/');
      depth = +parts[1];

      callback(null, depth + 1);
    });
  });
};

/**
 * Start batch.
 * @private
 * @param {WalletID} wid
 */

WalletDB.prototype.start = function start(wid) {
  assert(utils.isNumber(wid), 'Bad ID for batch.');
  assert(!this.batches[wid], 'Batch already started.');
  this.batches[wid] = this.db.batch();
};

/**
 * Drop batch.
 * @private
 * @param {WalletID} wid
 */

WalletDB.prototype.drop = function drop(wid) {
  var batch = this.batch(wid);
  batch.clear();
  delete this.batches[wid];
};

/**
 * Get batch.
 * @private
 * @param {WalletID} wid
 * @returns {Leveldown.Batch}
 */

WalletDB.prototype.batch = function batch(wid) {
  var batch;
  assert(utils.isNumber(wid), 'Bad ID for batch.');
  batch = this.batches[wid];
  assert(batch, 'Batch does not exist.');
  return batch;
};

/**
 * Save batch.
 * @private
 * @param {WalletID} wid
 * @param {Function} callback
 */

WalletDB.prototype.commit = function commit(wid, callback) {
  var batch = this.batch(wid);
  delete this.batches[wid];
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
    gte: 'p/' + constants.NULL_HASH,
    lte: 'p/' + constants.HIGH_HASH,
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
    gte: ' ',
    lte: '~',
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
  assert(!this.wallets[wallet.wid]);
  this.wallets[wallet.wid] = wallet;
};

/**
 * Unregister a object with the walletdb.
 * @param {Object} object
 * @returns {Boolean}
 */

WalletDB.prototype.unregister = function unregister(wallet) {
  assert(this.wallets[wallet.wid]);
  delete this.wallets[wallet.wid];
};

/**
 * Map wallet label to wallet id.
 * @param {String} label
 * @param {Function} callback
 */

WalletDB.prototype.getWalletID = function getWalletID(id, callback) {
  var self = this;
  var wid;

  if (!id)
    return callback();

  if (typeof id === 'number')
    return callback(null, id);

  wid = this.walletCache.get(id);

  if (wid)
    return callback(null, wid);

  this.db.fetch('l/' + id, function(data) {
    wid = data.readUInt32LE(0, true);
    self.walletCache.set(id, wid);
    return wid;
  }, callback);
};

/**
 * Get a wallet from the database, setup watcher.
 * @param {WalletID} wid
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.get = function get(wid, callback) {
  var self = this;

  this.getWalletID(wid, function(err, wid) {
    if (err)
      return callback(err);

    if (!wid)
      return callback();

    self._get(wid, function(err, wallet, watched) {
      if (err)
        return callback(err);

      if (!wallet)
        return callback();

      if (watched)
        return callback(null, wallet);

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
  });
};

/**
 * Get a wallet from the database, do not setup watcher.
 * @private
 * @param {WalletID} wid
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype._get = function get(wid, callback) {
  var self = this;
  var unlock, wallet;

  unlock = this.readLock.lock(wid, get, [wid, callback]);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  wallet = this.wallets[wid];

  if (wallet)
    return callback(null, wallet, true);

  this.db.fetch('w/' + pad32(wid), function(data) {
    return bcoin.wallet.fromRaw(self, data);
  }, callback);
};

/**
 * Save a wallet to the database.
 * @param {Wallet} wallet
 * @param {Function} callback
 */

WalletDB.prototype.save = function save(wallet) {
  var batch = this.batch(wallet.wid);
  var wid = new Buffer(4);
  this.walletCache.set(wallet.id, wallet.wid);
  batch.put('w/' + pad32(wallet.wid), wallet.toRaw());
  wid.writeUInt32LE(wallet.wid, 0, true);
  batch.put('l/' + wallet.id, wid);
};

/**
 * Test an api key against a wallet's api key.
 * @param {WalletID} wid
 * @param {String} token
 * @param {Function} callback
 */

WalletDB.prototype.auth = function auth(wid, token, callback) {
  this.get(wid, function(err, wallet) {
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

  unlock = this.writeLock.lock(options.id, create, [options, callback]);

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
      wallet.wid = self.depth++;
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
 * @param {WalletID} id
 * @param {Function} callback
 */

WalletDB.prototype.has = function has(id, callback) {
  this.getWalletID(id, function(err, wid) {
    if (err)
      return callback(err);
    return callback(null, wid != null);
  });
};

/**
 * Attempt to create wallet, return wallet if already exists.
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
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.getAccount = function getAccount(wid, name, callback) {
  var self = this;

  this.getAccountIndex(wid, name, function(err, index) {
    if (err)
      return callback(err);

    if (index === -1)
      return callback();

    self._getAccount(wid, index, function(err, account) {
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
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype._getAccount = function getAccount(wid, index, callback) {
  var self = this;
  var key = pad32(wid) + '/' + pad32(index);
  var account = this.accountCache.get(key);

  if (account)
    return callback(null, account);

  this.db.fetch('a/' + key, function(data) {
    account = bcoin.account.fromRaw(self, data);
    self.accountCache.set(key, account);
    return account;
  }, callback);
};

/**
 * List account names and indexes from the db.
 * @param {WalletID} wid
 * @param {Function} callback - Returns [Error, Array].
 */

WalletDB.prototype.getAccounts = function getAccounts(wid, callback) {
  var map = [];
  var i, accounts;

  this.db.iterate({
    gte: 'i/' + pad32(wid) + '/',
    lte: 'i/' + pad32(wid) + '/~',
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
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @param {Function} callback - Returns [Error, Number].
 */

WalletDB.prototype.getAccountIndex = function getAccountIndex(wid, name, callback) {
  if (!wid)
    return callback(null, -1);

  if (name == null)
    return callback(null, -1);

  if (typeof name === 'number')
    return callback(null, name);

  this.db.get('i/' + pad32(wid) + '/' + name, function(err, index) {
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
  var batch = this.batch(account.wid);
  var index = new Buffer(4);
  var key = pad32(account.wid) + '/' + pad32(account.accountIndex);

  index.writeUInt32LE(account.accountIndex, 0, true);

  batch.put('a/' + key, account.toRaw());
  batch.put('i/' + pad32(account.wid) + '/' + account.name, index);

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

  this.hasAccount(options.wid, options.accountIndex, function(err, exists) {
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
 * @param {WalletID} wid
 * @param {String|Number} account
 * @param {Function} callback - Returns [Error, Boolean].
 */

WalletDB.prototype.hasAccount = function hasAccount(wid, account, callback) {
  var self = this;
  var key;

  if (!wid)
    return callback(null, false);

  this.getAccountIndex(wid, account, function(err, index) {
    if (err)
      return callback(err);

    if (index === -1)
      return callback(null, false);

    key = pad32(wid) + '/' + pad32(index);

    if (self.accountCache.has(key))
      return callback(null, true);

    self.db.has('a/' + key, callback);
  });
};

/**
 * Save an address to the path map.
 * The path map exists in the form of:
 * `p/[address-hash] -> {walletid1=path1, walletid2=path2, ...}`
 * @param {WalletID} wid
 * @param {KeyRing[]} addresses
 * @param {Function} callback
 */

WalletDB.prototype.saveAddress = function saveAddress(wid, addresses, callback) {
  var self = this;
  var items = [];
  var batch = this.batch(wid);
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

      if (paths[wid])
        return next();

      paths[wid] = path;

      self.pathCache.set(hash, paths);

      batch.put('p/' + hash, serializePaths(paths));

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

  this.db.fetch('p/' + hash, parsePaths, function(err, paths) {
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
 * @param {WalletID} wid
 * @param {Hash} address
 * @param {Function} callback
 */

WalletDB.prototype.hasAddress = function hasAddress(wid, address, callback) {
  this.getAddress(address, function(err, paths) {
    if (err)
      return callback(err);

    if (!paths || !paths[wid])
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
 * @param {WalletID} wid
 * @param {Function} callback
 */

WalletDB.prototype.getAddresses = function getAddresses(wid, callback) {
  if (!callback) {
    callback = wid;
    wid = null;
  }

  this.db.iterate({
    gte: 'p/' + constants.NULL_HASH,
    lte: 'p/' + constants.HIGH_HASH,
    values: true,
    parse: function(value, key) {
      var paths = parsePaths(value);

      if (wid && !paths[wid])
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
    gte: 'l/',
    lte: 'l/~',
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

    chaindb.scan(self.height, hashes, function(block, txs, next) {
      self.addBlock(block, txs, next);
    }, callback);
  });
};

/**
 * Helper function to get a wallet.
 * @private
 * @param {WalletID} wid
 * @param {Function} callback
 * @param {Function} handler
 */

WalletDB.prototype.fetchWallet = function fetchWallet(wid, callback, handler) {
  this.get(wid, function(err, wallet) {
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

WalletDB.prototype.getPathInfo = function getPathInfo(wallet, tx, callback) {
  var self = this;
  var addresses = tx.getHashes('hex');
  var info;

  this.getTable(addresses, function(err, table) {
    if (err)
      return callback(err);

    if (!table)
      return callback();

    info = new PathInfo(self, wallet.wid, tx, table);
    info.id = wallet.id;

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

  this.getTip(function(err, block) {
    if (err)
      return callback(err);

    if (block) {
      self.tip = block.hash;
      self.height = block.height;
      return callback();
    }

    self.setTip(self.network.genesis.hash, 0, callback);
  });
};

/**
 * Get the best block hash.
 * @param {Function} callback
 */

WalletDB.prototype.getTip = function getTip(callback) {
  this.db.fetch('R', function(data) {
    return WalletBlock.fromTip(data);
  }, callback);
};

/**
 * Write the best block hash.
 * @param {Hash} hash
 * @param {Number} height
 * @param {Function} callback
 */

WalletDB.prototype.setTip = function setTip(hash, height, callback) {
  var self = this;
  var block = new WalletBlock(hash, height);
  this.db.put('R', block.toTip(), function(err) {
    if (err)
      return callback(err);

    self.tip = block.hash;
    self.height = block.height;

    return callback();
  });
};

/**
 * Connect a block.
 * @param {WalletBlock} block
 * @param {Function} callback
 */

WalletDB.prototype.writeBlock = function writeBlock(block, matches, callback) {
  var self = this;
  var batch = this.db.batch();
  var i, hash, wallets;

  batch.put('R', block.toTip());

  if (block.hashes.length > 0) {
    batch.put('b/' + block.hash, block.toRaw());

    for (i = 0; i < block.hashes.length; i++) {
      hash = block.hashes[i];
      wallets = matches[i];
      batch.put('t/' + hash, serializeWallets(wallets));
    }
  }

  batch.write(callback);
};

/**
 * Disconnect a block.
 * @param {WalletBlock} block
 * @param {Function} callback
 */

WalletDB.prototype.unwriteBlock = function unwriteBlock(block, callback) {
  var self = this;
  var batch = this.db.batch();
  var prev = new WalletBlock(block.prevBlock, block.height - 1);

  batch.put('R', prev.toTip());
  batch.del('b/' + block.hash);

  batch.write(callback);
};

/**
 * Get a wallet block (with hashes).
 * @param {Hash} hash
 * @param {Function} callback
 */

WalletDB.prototype.getBlock = function getBlock(hash, callback) {
  this.db.fetch('b/' + hash, function(err, data) {
    return WalletBlock.fromRaw(hash, data);
  }, callback);
};

/**
 * Get a TX->Wallet map.
 * @param {Hash} hash
 * @param {Function} callback
 */

WalletDB.prototype.getWalletsByTX = function getWalletsByTX(hash, callback) {
  this.db.fetch('t/' + hash, parseWallets, callback);
};

/**
 * Add a block's transactions and write the new best hash.
 * @param {ChainEntry} entry
 * @param {Function} callback
 */

WalletDB.prototype.addBlock = function addBlock(entry, txs, callback, force) {
  var self = this;
  var block, matches, hash, unlock;

  unlock = this.txLock.lock(addBlock, [entry, txs, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (this.options.useCheckpoints) {
    if (entry.height <= this.network.checkpoints.lastHeight)
      return this.setTip(entry.hash, entry.height, callback);
  }

  block = WalletBlock.fromEntry(entry);
  matches = [];

  // Update these early so transactions
  // get correct confirmation calculations.
  this.tip = block.hash;
  this.height = block.height;

  // NOTE: Atomicity doesn't matter here. If we crash
  // during this loop, the automatic rescan will get
  // the database back into the correct state.
  utils.forEachSerial(txs, function(tx, next) {
    self.addTX(tx, function(err, wallets) {
      if (err)
        return next(err);

      if (!wallets)
        return next();

      hash = tx.hash('hex');
      block.hashes.push(hash);
      matches.push(wallets);

      next();
    }, true);
  }, function(err) {
    if (err)
      return callback(err);

    self.writeBlock(block, matches, callback);
  });
};

/**
 * Unconfirm a block's transactions
 * and write the new best hash (SPV version).
 * @param {ChainEntry} entry
 * @param {Function} callback
 */

WalletDB.prototype.removeBlock = function removeBlock(entry, callback, force) {
  var self = this;
  var unlock;

  unlock = this.txLock.lock(removeBlock, [entry, callback], force);

  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  // Note:
  // If we crash during a reorg, there's not much to do.
  // Reorgs cannot be rescanned. The database will be
  // in an odd state, with some txs being confirmed
  // when they shouldn't be. That being said, this
  // should eventually resolve itself when a new block
  // comes in.
  this.getBlock(entry.hash, function(err, block) {
    if (err)
      return callback(err);

    // Not a saved block, but we
    // still want to reset the tip.
    if (!block)
      block = WalletBlock.fromEntry(entry);

    // Unwrite the tip as fast as we can.
    self.unwriteBlock(block, function(err) {
      if (err)
        return callback(err);

      utils.forEachSerial(block.hashes, function(hash, next) {
        self.getWalletsByTX(hash, function(err, wallets) {
          if (err)
            return next(err);

          if (!wallets)
            return next();

          utils.forEachSerial(wallets, function(wid, next) {
            self.get(wid, function(err, wallet) {
              if (err)
                return next(err);

              if (!wallet)
                return next();

              wallet.tx.unconfirm(hash, next);
            });
          }, function(err) {
            if (err)
              return callback(err);

            self.tip = block.hash;
            self.height = block.height;

            return callback();
          });
        });
      });
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

  // Note:
  // Atomicity doesn't matter here. If we crash,
  // the automatic rescan will get the database
  // back in the correct state.
  this.mapWallets(tx, function(err, wallets) {
    if (err)
      return callback(err);

    if (!wallets)
      return callback();

    self.logger.info(
      'Incoming transaction for %d wallets (%s).',
      wallets.length, tx.rhash);

    utils.forEachSerial(wallets, function(info, next) {
      self.get(info.wid, function(err, wallet) {
        if (err)
          return next(err);

        if (!wallet)
          return next();

        self.logger.debug('Adding tx to wallet: %s', info.wid);

        info.id = wallet.id;

        wallet.tx.add(tx, info, function(err) {
          if (err)
            return next(err);

          wallet.handleTX(info, next);
        });
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, wallets);
    });
  });
};

/**
 * Get the corresponding path for an address hash.
 * @param {WalletID} wid
 * @param {Hash} address
 * @param {Function} callback
 */

WalletDB.prototype.getPath = function getPath(wid, address, callback) {
  this.getAddress(address, function(err, paths) {
    if (err)
      return callback(err);

    if (!paths || !paths[wid])
      return callback();

    return callback(null, paths[wid]);
  });
};

/**
 * Path
 * @constructor
 * @private
 * @property {WalletID} wid
 * @property {String} name - Account name.
 * @property {Number} account - Account index.
 * @property {Number} change - Change index.
 * @property {Number} index - Address index.
 * @property {Address|null} address
 */

function Path() {
  if (!(this instanceof Path))
    return new Path();

  this.wid = null;
  this.name = null;
  this.account = 0;
  this.change = 0;
  this.index = 0;

  // NOTE: Passed in by caller.
  this.id = null;
}

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Path.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  this.wid = p.readU32();
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

  p.writeU32(this.wid);
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
 * @param {WalletID} wid
 * @param {KeyRing} address
 */

Path.prototype.fromKeyRing = function fromKeyRing(address) {
  this.wid = address.wid;
  this.id = address.id;
  this.name = address.name;
  this.account = address.account;
  this.change = address.change;
  this.index = address.index;
  return this;
};

/**
 * Instantiate path from keyring.
 * @param {WalletID} wid
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

  this.wid = json.wid;
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
 * Inspect the path.
 * @returns {String}
 */

Path.prototype.inspect = function() {
  return '<Path: ' + this.id
    + '(' + this.wid + ')'
    + '/' + this.name
    + ': ' + this.toPath()
    + '>';
};

/**
 * Path Info
 */

function PathInfo(db, wid, tx, table) {
  if (!(this instanceof PathInfo))
    return new PathInfo(db, wid, tx, table);

  // Reference to the walletdb.
  this.db = db;

  // All relevant Accounts for
  // inputs and outputs (for database indexing).
  this.accounts = [];

  // All output paths (for deriving during sync).
  this.paths = [];

  // Wallet ID
  this.wid = wid;

  // Wallet Label (passed in by caller).
  this.id = null;

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
  var i, j, hash, paths, path, wid;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      wallets[path.wid] = true;
    }
  }

  wallets = Object.keys(wallets);

  if (wallets.length === 0)
    return;

  for (i = 0; i < wallets.length; i++) {
    wid = +wallets[i];
    info.push(new PathInfo(db, wid, tx, table));
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
      if (path.wid !== this.wid)
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
      if (path.wid !== this.wid)
        continue;
      this.paths.push(path);
    }
  }

  return this;
};

PathInfo.fromTX = function fromTX(db, wid, tx, table) {
  return new PathInfo(db, wid).fromTX(tx, table);
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
    details = new TXDB.Details(this);
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
    out[path.wid] = path;
  }

  return out;
}

function serializePaths(out) {
  var p = new BufferWriter();
  var keys = Object.keys(out);
  var i, wid, path;

  for (i = 0; i < keys.length; i++) {
    wid = keys[i];
    path = out[wid];
    path.toRaw(p);
  }

  return p.render();
}

function serializeWallets(wallets) {
  var p = new BufferWriter();
  var i, info;

  for (i = 0; i < wallets.length; i++) {
    info = wallets[i];
    p.writeU32(info.wid);
  }

  return p.render();
}

function parseWallets(data) {
  var p = new BufferReader(data);
  var wallets = [];
  while (p.left())
    wallets.push(p.readU32());
  return wallets;
}

function WalletBlock(hash, height) {
  if (!(this instanceof WalletBlock))
    return new WalletBlock(hash, height);

  this.hash = hash || constants.NULL_HASH;
  this.height = height != null ? height : -1;
  this.prevBlock = constants.NULL_HASH;
  this.hashes = [];
}

WalletBlock.prototype.fromEntry = function fromEntry(entry) {
  this.hash = entry.hash;
  this.height = entry.height;
  this.prevBlock = entry.prevBlock;
  return this;
};

WalletBlock.prototype.fromJSON = function fromJSON(json) {
  this.hash = utils.revHex(json.hash);
  this.height = json.height;
  if (json.prevBlock)
    this.prevBlock = utils.revHex(json.prevBlock);
  return this;
};

WalletBlock.prototype.fromRaw = function fromRaw(hash, data) {
  var p = new BufferReader(data);
  this.hash = hash;
  this.height = p.readU32();
  while (p.left())
    this.hashes.push(p.readHash('hex'));
  return this;
};

WalletBlock.prototype.fromTip = function fromTip(data) {
  var p = new BufferReader(data);
  this.hash = p.readHash('hex');
  this.height = p.readU32();
  return this;
};

WalletBlock.fromEntry = function fromEntry(entry) {
  return new WalletBlock().fromEntry(entry);
};

WalletBlock.fromJSON = function fromJSON(json) {
  return new WalletBlock().fromJSON(json);
};

WalletBlock.fromRaw = function fromRaw(hash, data) {
  return new WalletBlock().fromTip(hash, data);
};

WalletBlock.fromTip = function fromTip(data) {
  return new WalletBlock().fromTip(data);
};

WalletBlock.prototype.toTip = function toTip(data) {
  var p = new BufferWriter();
  p.writeHash(this.hash);
  p.writeU32(this.height);
  return p.render();
};

WalletBlock.prototype.toRaw = function toRaw(data) {
  var p = new BufferWriter();
  var i;

  p.writeU32(this.height);

  for (i = 0; i < this.hashes.length; i++)
    p.writeHash(this.hashes[i]);

  return p.render();
};

WalletBlock.prototype.toJSON = function toJSON() {
  return {
    hash: utils.revHex(this.hash),
    height: this.height
  };
};

function MappedLock(parent) {
  if (!(this instanceof MappedLock))
    return new MappedLock(parent);

  this.parent = parent;
  this.jobs = [];
  this.busy = {};
}

MappedLock.prototype.lock = function lock(key, func, args, force) {
  var self = this;
  var called;

  if (force || key == null) {
    assert(key == null || this.busy[key]);
    return function unlock() {
      assert(!called);
      called = true;
    };
  }

  if (this.busy[key]) {
    this.jobs.push([func, args]);
    return;
  }

  this.busy[key] = true;

  return function unlock() {
    var item;

    assert(!called);
    called = true;

    delete self.busy[key];

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
