/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var AsyncObject = require('../utils/async');
var utils = require('../utils/utils');
var co = require('../utils/co');
var Locker = require('../utils/locker');
var LRU = require('../utils/lru');
var crypto = require('../crypto/crypto');
var assert = require('assert');
var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var Path = require('./path');
var Wallet = require('./wallet');
var Account = require('./account');
var ldb = require('../db/ldb');
var Bloom = require('../utils/bloom');
var Logger = require('../node/logger');
var TX = require('../primitives/tx');
var records = require('./records');
var BlockMapRecord = records.BlockMapRecord;
var HeaderRecord = records.HeaderRecord;
var PathMapRecord = records.PathMapRecord;
var TXMapRecord = records.TXMapRecord;
var TXDB = require('./txdb');
var U32 = utils.U32;

/*
 * Database Layout:
 *  p[addr-hash] -> wallet ids
 *  P[wid][addr-hash] -> path data
 *  w[wid] -> wallet
 *  l[id] -> wid
 *  a[wid][index] -> account
 *  i[wid][name] -> account index
 *  t[wid]* -> txdb
 *  R -> tip
 *  b[hash] -> wallet block
 *  e[hash] -> tx->wid map
 */

var layout = {
  p: function p(hash) {
    var key = new Buffer(1 + (hash.length / 2));
    key[0] = 0x70;
    key.write(hash, 1, 'hex');
    return key;
  },
  pp: function pp(key) {
    return key.toString('hex', 1);
  },
  P: function P(wid, hash) {
    var key = new Buffer(1 + 4 + (hash.length / 2));
    key[0] = 0x50;
    key.writeUInt32BE(wid, 1, true);
    key.write(hash, 5, 'hex');
    return key;
  },
  Pp: function Pp(key) {
    return key.toString('hex', 5);
  },
  w: function w(wid) {
    var key = new Buffer(5);
    key[0] = 0x77;
    key.writeUInt32BE(wid, 1, true);
    return key;
  },
  ww: function ww(key) {
    return key.readUInt32BE(1, true);
  },
  l: function l(id) {
    var len = Buffer.byteLength(id, 'ascii');
    var key = new Buffer(1 + len);
    key[0] = 0x6c;
    if (len > 0)
      key.write(id, 1, 'ascii');
    return key;
  },
  ll: function ll(key) {
    return key.toString('ascii', 1);
  },
  a: function a(wid, index) {
    var key = new Buffer(9);
    key[0] = 0x61;
    key.writeUInt32BE(wid, 1, true);
    key.writeUInt32BE(index, 5, true);
    return key;
  },
  i: function i(wid, name) {
    var len = Buffer.byteLength(name, 'ascii');
    var key = new Buffer(5 + len);
    key[0] = 0x69;
    key.writeUInt32BE(wid, 1, true);
    if (len > 0)
      key.write(name, 5, 'ascii');
    return key;
  },
  ii: function ii(key) {
    return [key.readUInt32BE(1, true), key.toString('ascii', 5)];
  },
  R: new Buffer([0x52]),
  c: function c(height) {
    var key = new Buffer(5);
    key[0] = 0x63;
    key.writeUInt32BE(height, 1, true);
    return key;
  },
  cc: function cc(key) {
    return key.readUInt32BE(1, true);
  },
  b: function b(height) {
    var key = new Buffer(5);
    key[0] = 0x62;
    key.writeUInt32BE(height, 1, true);
    return key;
  },
  bb: function bb(key) {
    return key.readUInt32BE(1, true);
  },
  e: function e(hash) {
    var key = new Buffer(33);
    key[0] = 0x65;
    key.write(hash, 1, 'hex');
    return key;
  },
  ee: function ee(key) {
    return key.toString('hex', 1);
  }
};

if (utils.isBrowser)
  layout = require('./browser').walletdb;

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
  this.network = Network.get(options.network);
  this.logger = options.logger || Logger.global;
  this.client = options.client;

  this.tip = null;
  this.height = -1;
  this.depth = 0;
  this.wallets = {};

  // We need one read lock for `get` and `create`.
  // It will hold locks specific to wallet ids.
  this.readLock = new Locker.Mapped();
  this.writeLock = new Locker();
  this.txLock = new Locker();

  this.widCache = new LRU(10000);
  this.pathMapCache = new LRU(100000);

  // Try to optimize for up to 1m addresses.
  // We use a regular bloom filter here
  // because we never want members to
  // lose membership, even if quality
  // degrades.
  // Memory used: 1.7mb
  this.filter = this.options.useFilter !== false
    ? Bloom.fromRate(1000000, 0.001, -1)
    : null;

  this.db = ldb({
    location: this.options.location,
    db: this.options.db,
    maxOpenFiles: this.options.maxFiles,
    cacheSize: 8 << 20,
    writeBufferSize: 4 << 20,
    bufferKeys: !utils.isBrowser
  });

  this._init();
}

utils.inherits(WalletDB, AsyncObject);

/**
 * Database layout.
 * @type {Object}
 */

WalletDB.layout = layout;

/**
 * Initialize wallet db.
 * @private
 */

WalletDB.prototype._init = function _init() {
  ;
};

/**
 * Open the walletdb, wait for the database to load.
 * @alias WalletDB#open
 * @returns {Promise}
 */

WalletDB.prototype._open = co(function* open() {
  yield this.db.open();
  yield this.db.checkVersion('V', 4);
  yield this.writeGenesis();

  if (this.options.wipeNoReally)
    yield this.wipe();

  this.depth = yield this.getDepth();

  this.logger.info(
    'WalletDB loaded (depth=%d, height=%d).',
    this.depth, this.height);

  yield this.loadFilter();
  yield this.connect();
  yield this.resend();
});

/**
 * Close the walletdb, wait for the database to close.
 * @alias WalletDB#close
 * @returns {Promise}
 */

WalletDB.prototype._close = co(function* close() {
  var keys = Object.keys(this.wallets);
  var i, key, wallet;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    wallet = this.wallets[key];
    yield wallet.destroy();
  }

  yield this.db.close();
});

/**
 * Connect and sync with the chain server.
 * @returns {Promise}
 */

WalletDB.prototype.connect = co(function* connect() {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._connect();
  } finally {
    unlock();
  }
});

/**
 * Connect and sync with the chain server (without a lock).
 * @private
 * @returns {Promise}
 */

WalletDB.prototype._connect = co(function* connect() {
  var hashes, tip, height;

  if (!this.client)
    return;

  // yield this.client.connect();
  // yield this.client.watchChain();

  hashes = yield this.getHashes();

  yield this.watchAddress(hashes);

  if (this.options.noScan) {
    tip = yield this.client.getTip();

    if (!tip)
      throw new Error('Could not get chain tip.');

    yield this.forceTip(tip);

    return;
  }

  assert(this.network.block.keepBlocks > 36);

  height = this.height - 36;

  if (height < 0)
    height = 0;

  yield this.scan(height, hashes);
});

/**
 * Force a rescan.
 * @param {ChainClient} chain
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.rescan = co(function* rescan(height) {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._rescan(height);
  } finally {
    unlock();
  }
});

/**
 * Force a rescan (without a lock).
 * @private
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype._rescan = co(function* rescan(height) {
  var hashes;

  if (!this.client)
    return;

  assert(utils.isNumber(height), 'Must pass in a height.');

  hashes = yield this.getHashes();

  yield this.watchAddress(hashes);

  yield this.scan(height, hashes);
});

/**
 * Sync with the chain server (without a lock).
 * @private
 * @param {Number} height
 * @param {Hashes[]} hashes
 * @returns {Promise}
 */

WalletDB.prototype.scan = co(function* sync(height, hashes) {
  var self = this;
  var blocks;

  if (!this.client)
    return;

  assert(utils.isNumber(height), 'Must pass in a height.');

  blocks = this.height - height;

  if (blocks < 0)
    throw new Error('Cannot rescan future blocks.');

  if (blocks > this.network.block.keepBlocks)
    throw new Error('Cannot roll back beyond keepBlocks.');

  yield this.rollback(height);

  this.logger.info('Scanning for %d addresses.', hashes.length);

  yield this.client.scan(this.tip.hash, hashes, function(block, txs) {
    return self._addBlock(block, txs);
  });
});

/**
 * Add addresses to chain server filter.
 * @param {Hashes[]} hashes
 * @returns {Promise}
 */

WalletDB.prototype.watchAddress = co(function* watchAddress(hashes) {
  if (!this.client) {
    this.emit('watch address', hashes);
    return;
  }

  yield this.client.watchAddress(hashes);
});

/**
 * Broadcast a transaction via chain server.
 * @param {TX} tx
 * @returns {Promise}
 */

WalletDB.prototype.send = co(function* send(tx) {
  if (!this.client) {
    this.emit('send', tx);
    return;
  }

  yield this.client.send(tx);
});

/**
 * Estimate smart fee from chain server.
 * @param {Number} blocks
 * @returns {Promise}
 */

WalletDB.prototype.estimateFee = co(function* estimateFee(blocks) {
  if (!this.client)
    return this.network.feeRate;

  return yield this.client.estimateFee(blocks);
});

/**
 * Backup the wallet db.
 * @param {String} path
 * @returns {Promise}
 */

WalletDB.prototype.backup = function backup(path) {
  return this.db.backup(path);
};

/**
 * Wipe the txdb - NEVER USE.
 * @returns {Promise}
 */

WalletDB.prototype.wipe = co(function* wipe() {
  var batch = this.db.batch();
  var dummy = new Buffer(0);
  var i, keys, key, gte, lte;

  this.logger.warning('Wiping txdb...');
  this.logger.warning('I hope you know what you\'re doing.');

  keys = yield this.db.keys({
    gte: TXDB.layout.prefix(0x00000000, dummy),
    lte: TXDB.layout.prefix(0xffffffff, dummy)
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    batch.del(key);
  }

  gte = new Buffer(33);
  key.fill(0);
  key[0] = 0x62;

  lte = new Buffer(33);
  key.fill(255);
  key[0] = 0x62;

  keys = yield this.db.keys({
    gte: gte,
    lte: lte
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    batch.del(key);
  }

  keys = yield this.db.keys({
    gte: layout.b(0),
    lte: layout.b(0xffffffff)
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    batch.del(key);
  }

  keys = yield this.db.keys({
    gte: layout.c(0),
    lte: layout.c(0xffffffff)
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    batch.del(key);
  }

  keys = yield this.db.keys({
    gte: layout.e(constants.NULL_HASH),
    lte: layout.e(constants.HIGH_HASH)
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    batch.del(key);
  }

  batch.del(layout.R);

  yield batch.write();
  yield this.writeGenesis();
});

/**
 * Get current wallet wid depth.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.getDepth = co(function* getDepth() {
  var iter, item, depth;

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
    gte: layout.w(0x00000000),
    lte: layout.w(0xffffffff),
    reverse: true
  });

  item = yield iter.next();

  if (!item)
    return 1;

  yield iter.end();

  depth = layout.ww(item.key);

  return depth + 1;
});

/**
 * Get current block height.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.getHeight = co(function* getHeight() {
  var data = yield this.db.get(layout.R);

  if (!data)
    return -1;

  return data.readUInt32LE(0, true);
});

/**
 * Start batch.
 * @private
 * @param {WalletID} wid
 */

WalletDB.prototype.start = function start(wallet) {
  assert(!wallet.current, 'Batch already started.');
  wallet.current = this.db.batch();
  wallet.accountCache.start();
  wallet.pathCache.start();
  return wallet.current;
};

/**
 * Drop batch.
 * @private
 * @param {WalletID} wid
 */

WalletDB.prototype.drop = function drop(wallet) {
  var batch = this.batch(wallet);
  wallet.current = null;
  wallet.accountCache.drop();
  wallet.pathCache.drop();
  batch.clear();
};

/**
 * Clear batch.
 * @private
 * @param {WalletID} wid
 */

WalletDB.prototype.clear = function clear(wallet) {
  var batch = this.batch(wallet);
  wallet.accountCache.clear();
  wallet.pathCache.clear();
  batch.clear();
};

/**
 * Get batch.
 * @private
 * @param {WalletID} wid
 * @returns {Leveldown.Batch}
 */

WalletDB.prototype.batch = function batch(wallet) {
  assert(wallet.current, 'Batch does not exist.');
  return wallet.current;
};

/**
 * Save batch.
 * @private
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.commit = co(function* commit(wallet) {
  var batch = this.batch(wallet);

  try {
    yield batch.write();
  } catch (e) {
    wallet.current = null;
    wallet.accountCache.drop();
    wallet.pathCache.drop();
    throw e;
  }

  wallet.current = null;
  wallet.accountCache.commit();
  wallet.pathCache.commit();
});

/**
 * Load the bloom filter into memory.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.loadFilter = co(function* loadFilter() {
  var iter, item, hash;

  if (!this.filter)
    return;

  iter = this.db.iterator({
    gte: layout.p(constants.NULL_HASH),
    lte: layout.p(constants.HIGH_HASH)
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    hash = layout.pp(item.key);
    this.filter.add(hash, 'hex');
  }

  iter = this.db.iterator({
    gte: layout.e(constants.NULL_HASH),
    lte: layout.e(constants.HIGH_HASH)
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    hash = layout.ee(item.key);
    this.filter.add(hash, 'hex');
  }
});

/**
 * Test the bloom filter against a tx or address hash.
 * @private
 * @param {Hash} hash
 * @returns {Boolean}
 */

WalletDB.prototype.testFilter = function testFilter(hash) {
  if (!this.filter)
    return true;

  return this.filter.test(hash, 'hex');
};

/**
 * Add hash to filter.
 * @private
 * @param {Hash} hash
 */

WalletDB.prototype.addFilter = function addFilter(hash) {
  if (!this.filter)
    return;

  return this.filter.add(hash, 'hex');
};

/**
 * Dump database (for debugging).
 * @returns {Promise} - Returns Object.
 */

WalletDB.prototype.dump = function dump() {
  return this.db.dump();
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
 * @returns {Promise}
 */

WalletDB.prototype.getWalletID = co(function* getWalletID(id) {
  var wid, data;

  if (!id)
    return;

  if (typeof id === 'number')
    return id;

  wid = this.widCache.get(id);

  if (wid)
    return wid;

  data = yield this.db.get(layout.l(id));

  if (!data)
    return;

  wid = data.readUInt32LE(0, true);

  this.widCache.set(id, wid);

  return wid;
});

/**
 * Get a wallet from the database, setup watcher.
 * @param {WalletID} wid
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.get = co(function* get(id) {
  var wid = yield this.getWalletID(id);
  var unlock;

  if (!wid)
    return;

  unlock = yield this.readLock.lock(wid);

  try {
    return yield this._get(wid);
  } finally {
    unlock();
  }
});

/**
 * Get a wallet from the database without a lock.
 * @private
 * @param {WalletID} wid
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype._get = co(function* get(wid) {
  var wallet = this.wallets[wid];
  var data;

  if (wallet)
    return wallet;

  data = yield this.db.get(layout.w(wid));

  if (!data)
    return;

  wallet = Wallet.fromRaw(this, data);

  yield wallet.open();

  this.register(wallet);

  return wallet;
});

/**
 * Save a wallet to the database.
 * @param {Wallet} wallet
 */

WalletDB.prototype.save = function save(wallet) {
  var wid = wallet.wid;
  var id = wallet.id;
  var batch = this.batch(wallet);

  this.widCache.set(id, wid);

  batch.put(layout.w(wid), wallet.toRaw());
  batch.put(layout.l(id), U32(wid));
};

/**
 * Rename a wallet.
 * @param {Wallet} wallet
 * @param {String} id
 * @returns {Promise}
 */

WalletDB.prototype.rename = co(function* rename(wallet, id) {
  var unlock = yield this.writeLock.lock();
  try {
    return yield this._rename(wallet, id);
  } finally {
    unlock();
  }
});

/**
 * Rename a wallet without a lock.
 * @private
 * @param {Wallet} wallet
 * @param {String} id
 * @returns {Promise}
 */

WalletDB.prototype._rename = co(function* _rename(wallet, id) {
  var old = wallet.id;
  var i, paths, path, batch;

  if (!utils.isName(id))
    throw new Error('Bad wallet ID.');

  if (yield this.has(id))
    throw new Error('ID not available.');

  batch = this.start(wallet);
  batch.del(layout.l(old));

  wallet.id = id;

  this.save(wallet);

  yield this.commit(wallet);

  this.widCache.remove(old);

  paths = wallet.pathCache.values();

  for (i = 0; i < paths.length; i++) {
    path = paths[i];
    path.id = id;
  }
});

/**
 * Rename an account.
 * @param {Account} account
 * @param {String} name
 */

WalletDB.prototype.renameAccount = function renameAccount(account, name) {
  var wallet = account.wallet;
  var batch = this.batch(wallet);
  batch.del(layout.i(account.wid, account.name));
  account.name = name;
  this.saveAccount(account);
};

/**
 * Test an api key against a wallet's api key.
 * @param {WalletID} wid
 * @param {String|Buffer} token
 * @returns {Promise}
 */

WalletDB.prototype.auth = co(function* auth(wid, token) {
  var wallet = yield this.get(wid);

  if (!wallet)
    return;

  if (typeof token === 'string') {
    if (!utils.isHex256(token))
      throw new Error('Authentication error.');
    token = new Buffer(token, 'hex');
  }

  // Compare in constant time:
  if (!crypto.ccmp(token, wallet.token))
    throw new Error('Authentication error.');

  return wallet;
});

/**
 * Create a new wallet, save to database, setup watcher.
 * @param {Object} options - See {@link Wallet}.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.create = co(function* create(options) {
  var unlock = yield this.writeLock.lock();

  if (!options)
    options = {};

  try {
    return yield this._create(options);
  } finally {
    unlock();
  }
});

/**
 * Create a new wallet, save to database without a lock.
 * @private
 * @param {Object} options - See {@link Wallet}.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype._create = co(function* create(options) {
  var exists = yield this.has(options.id);
  var wallet;

  if (exists)
    throw new Error('Wallet already exists.');

  wallet = Wallet.fromOptions(this, options);
  wallet.wid = this.depth++;

  yield wallet.init(options);

  this.register(wallet);

  this.logger.info('Created wallet %s.', wallet.id);

  return wallet;
});

/**
 * Test for the existence of a wallet.
 * @param {WalletID} id
 * @returns {Promise}
 */

WalletDB.prototype.has = co(function* has(id) {
  var wid = yield this.getWalletID(id);
  return wid != null;
});

/**
 * Attempt to create wallet, return wallet if already exists.
 * @param {Object} options - See {@link Wallet}.
 * @returns {Promise}
 */

WalletDB.prototype.ensure = co(function* ensure(options) {
  var wallet = yield this.get(options.id);
  if (wallet)
    return wallet;
  return yield this.create(options);
});

/**
 * Get an account from the database by wid.
 * @private
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.getAccount = co(function* getAccount(wid, index) {
  var data = yield this.db.get(layout.a(wid, index));

  if (!data)
    return;

  return Account.fromRaw(this, data);
});

/**
 * List account names and indexes from the db.
 * @param {WalletID} wid
 * @returns {Promise} - Returns Array.
 */

WalletDB.prototype.getAccounts = co(function* getAccounts(wid) {
  var map = [];
  var i, items, item, name, index, accounts;

  items = yield this.db.range({
    gte: layout.i(wid, '\x00'),
    lte: layout.i(wid, '\xff')
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    name = layout.ii(item.key)[1];
    index = item.value.readUInt32LE(0, true);
    map[index] = name;
  }

  // Get it out of hash table mode.
  accounts = [];

  for (i = 0; i < map.length; i++) {
    assert(map[i] != null);
    accounts.push(map[i]);
  }

  return accounts;
});

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @returns {Promise} - Returns Number.
 */

WalletDB.prototype.getAccountIndex = co(function* getAccountIndex(wid, name) {
  var index = yield this.db.get(layout.i(wid, name));

  if (!index)
    return -1;

  return index.readUInt32LE(0, true);
});

/**
 * Save an account to the database.
 * @param {Account} account
 * @returns {Promise}
 */

WalletDB.prototype.saveAccount = function saveAccount(account) {
  var wid = account.wid;
  var wallet = account.wallet;
  var index = account.accountIndex;
  var name = account.name;
  var batch = this.batch(wallet);

  batch.put(layout.a(wid, index), account.toRaw());
  batch.put(layout.i(wid, name), U32(index));

  wallet.accountCache.push(index, account);
};

/**
 * Test for the existence of an account.
 * @param {WalletID} wid
 * @param {String|Number} acct
 * @returns {Promise} - Returns Boolean.
 */

WalletDB.prototype.hasAccount = function hasAccount(wid, index) {
  return this.db.has(layout.a(wid, index));
};

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @returns {Promise} - Returns Number.
 */

WalletDB.prototype.getPathMap = co(function* getPathMap(hash) {
  var map = this.pathMapCache.get(hash);
  var data;

  if (map)
    return map;

  data = yield this.db.get(layout.p(hash));

  if (!data)
    return;

  map = PathMapRecord.fromRaw(hash, data);

  this.pathMapCache.set(hash, map);

  return map;
});

/**
 * Save an address to the path map.
 * @param {WalletID} wid
 * @param {KeyRing[]} ring
 * @returns {Promise}
 */

WalletDB.prototype.saveKey = function saveKey(wallet, ring) {
  return this.savePath(wallet, ring.toPath());
};

/**
 * Save a path to the path map.
 *
 * The path map exists in the form of:
 *   - `p[address-hash] -> wids`
 *   - `P[wid][address-hash] -> path`
 *
 * @param {WalletID} wid
 * @param {Path[]} path
 * @returns {Promise}
 */

WalletDB.prototype.savePath = co(function* savePath(wallet, path) {
  var wid = wallet.wid;
  var hash = path.hash;
  var batch = this.batch(wallet);
  var map, result;

  this.addFilter(hash);

  yield this.watchAddress([path.hash]);

  map = yield this.getPathMap(hash);

  if (!map)
    map = new PathMapRecord(hash);

  if (!map.add(wid))
    return;

  this.pathMapCache.set(hash, map);
  wallet.pathCache.push(hash, path);

  batch.put(layout.p(hash), map.toRaw());
  batch.put(layout.P(wid, hash), path.toRaw());
});

/**
 * Retrieve path by hash.
 * @param {WalletID} wid
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getPath = co(function* getPath(wid, hash) {
  var data = yield this.db.get(layout.P(wid, hash));
  var path;

  if (!data)
    return;

  path = Path.fromRaw(data);
  path.wid = wid;
  path.hash = hash;

  return path;
});

/**
 * Test whether a wallet contains a path.
 * @param {WalletID} wid
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.hasPath = co(function* hasPath(wid, hash) {
  var data = yield this.db.get(layout.P(wid, hash));
  return data != null;
});

/**
 * Get all address hashes.
 * @returns {Promise}
 */

WalletDB.prototype.getHashes = function getHashes() {
  return this.db.keys({
    gte: layout.p(constants.NULL_HASH),
    lte: layout.p(constants.HIGH_HASH),
    parse: layout.pp
  });
};

/**
 * Get all address hashes.
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.getWalletHashes = function getWalletHashes(wid) {
  return this.db.keys({
    gte: layout.P(wid, constants.NULL_HASH),
    lte: layout.P(wid, constants.HIGH_HASH),
    parse: layout.Pp
  });
};

/**
 * Get all paths for a wallet.
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.getWalletPaths = co(function* getWalletPaths(wid) {
  var i, item, items, hash, path;

  items = yield this.db.range({
    gte: layout.P(wid, constants.NULL_HASH),
    lte: layout.P(wid, constants.HIGH_HASH)
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    hash = layout.Pp(item.key);
    path = Path.fromRaw(item.value);

    path.hash = hash;
    path.wid = wid;

    items[i] = path;
  }

  return items;
});

/**
 * Get all wallet ids.
 * @returns {Promise}
 */

WalletDB.prototype.getWallets = function getWallets() {
  return this.db.keys({
    gte: layout.l('\x00'),
    lte: layout.l('\xff'),
    parse: layout.ll
  });
};

/**
 * Encrypt all imported keys for a wallet.
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.encryptKeys = co(function* encryptKeys(wallet, key) {
  var wid = wallet.wid;
  var paths = yield wallet.getPaths();
  var batch = this.batch(wallet);
  var i, path, iv;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    if (!path.data)
      continue;

    assert(!path.encrypted);

    iv = new Buffer(path.hash, 'hex');
    iv = iv.slice(0, 16);

    path.data = crypto.encipher(path.data, key, iv);
    path.encrypted = true;

    wallet.pathCache.set(path.hash, path);

    batch.put(layout.P(wid, path.hash), path.toRaw());
  }
});

/**
 * Decrypt all imported keys for a wallet.
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.decryptKeys = co(function* decryptKeys(wallet, key) {
  var wid = wallet.wid;
  var paths = yield wallet.getPaths();
  var batch = this.batch(wallet);
  var i, path, iv;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    if (!path.data)
      continue;

    assert(path.encrypted);

    iv = new Buffer(path.hash, 'hex');
    iv = iv.slice(0, 16);

    path.data = crypto.decipher(path.data, key, iv);
    path.encrypted = false;

    wallet.pathCache.set(path.hash, path);

    batch.put(layout.P(wid, path.hash), path.toRaw());
  }
});

/**
 * Get keys of all pending transactions
 * in the wallet db (for resending).
 * @returns {Promise}
 */

WalletDB.prototype.getPendingKeys = co(function* getPendingKeys() {
  var layout = TXDB.layout;
  var dummy = new Buffer(0);
  var keys = [];
  var iter, item;

  iter = yield this.db.iterator({
    gte: layout.prefix(0x00000000, dummy),
    lte: layout.prefix(0xffffffff, dummy)
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    if (item.key[5] === 0x70)
      keys.push(item.key);
  }

  return keys;
});

/**
 * Get keys of all pending transactions
 * in the wallet db (for resending).
 * @returns {Promise}
 */

WalletDB.prototype.getPendingTX = co(function* getPendingTX() {
  var layout = TXDB.layout;
  var keys = yield this.getPendingKeys();
  var uniq = {};
  var result = [];
  var i, key, wid, hash;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    wid = layout.pre(key);
    hash = layout.pp(key);

    if (uniq[hash])
      continue;

    uniq[hash] = true;

    key = layout.prefix(wid, layout.t(hash));
    result.push(key);
  }

  return result;
});

/**
 * Get all wallet IDs with pending txs in them.
 * @returns {Promise}
 */

WalletDB.prototype.getPendingWallets = co(function* getPendingWallets() {
  var layout = TXDB.layout;
  var keys = yield this.getPendingKeys();
  var uniq = {};
  var result = [];
  var i, key, wid;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    wid = layout.pre(key);

    if (uniq[wid])
      continue;

    uniq[wid] = true;

    result.push(wid);
  }

  return result;
});

/**
 * Resend all pending transactions.
 * @returns {Promise}
 */

WalletDB.prototype.resend = co(function* resend() {
  var keys = yield this.getPendingTX();
  var i, key, data, tx;

  if (keys.length > 0)
    this.logger.info('Rebroadcasting %d transactions.', keys.length);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    data = yield this.db.get(key);

    if (!data)
      continue;

    tx = TX.fromExtended(data);

    if (tx.isCoinbase())
      continue;

    yield this.send(tx);
  }
});

/**
 * Get all wallet ids by multiple address hashes.
 * @param {Hash[]} hashes
 * @returns {Promise}
 */

WalletDB.prototype.getWalletsByHashes = co(function* getWalletsByHashes(tx) {
  var result = [];
  var hashes = tx.getHashes('hex');
  var i, j, hash, map;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (!this.testFilter(hash))
      continue;

    map = yield this.getPathMap(hash);

    if (!map)
      continue;

    for (j = 0; j < map.wids.length; j++)
      utils.binaryInsert(result, map.wids[j], cmp, true);
  }

  if (result.length === 0)
    return;

  return result;
});

/**
 * Get all wallet ids by multiple address hashes.
 * @param {Hash[]} hashes
 * @returns {Promise}
 */

WalletDB.prototype.getWalletsByInsert = co(function* getWalletsByInsert(tx) {
  var i, j, result, hashes, input, prevout, hash, map;

  if (this.options.resolution)
    return yield this.getWalletsByHashes(tx);

  result = [];
  hashes = tx.getOutputHashes('hex');

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (!this.testFilter(prevout.hash))
      continue;

    map = yield this.getTXMap(prevout.hash);

    if (!map)
      continue;

    for (j = 0; j < map.wids.length; j++)
      utils.binaryInsert(result, map.wids[j], cmp, true);
  }

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (!this.testFilter(hash))
      continue;

    map = yield this.getPathMap(hash);

    if (!map)
      continue;

    for (j = 0; j < map.wids.length; j++)
      utils.binaryInsert(result, map.wids[j], cmp, true);
  }

  if (result.length === 0)
    return;

  return result;
});

/**
 * Write the genesis block as the best hash.
 * @returns {Promise}
 */

WalletDB.prototype.writeGenesis = co(function* writeGenesis() {
  var tip = yield this.getTip();

  if (tip) {
    this.tip = tip;
    this.height = tip.height;
    return;
  }

  yield this.forceTip(this.network.genesis);
});

/**
 * Write the genesis block as the best hash.
 * @returns {Promise}
 */

WalletDB.prototype.forceTip = co(function* forceTip(entry) {
  var tip = HeaderRecord.fromEntry(entry);
  yield this.setTip(tip);
});

/**
 * Get the best block hash.
 * @returns {Promise}
 */

WalletDB.prototype.getTip = co(function* getTip() {
  var height = yield this.getHeight();

  if (height === -1)
    return;

  return yield this.getHeader(height);
});

/**
 * Write the connecting block immediately.
 * @param {HeaderRecord} tip
 * @returns {Promise}
 */

WalletDB.prototype.setTip = co(function* setTip(tip) {
  var batch = this.db.batch();
  var height;

  batch.del(layout.c(tip.height + 1));
  batch.put(layout.c(tip.height), tip.toRaw());
  batch.put(layout.R, U32(tip.height));

  height = tip.height - this.network.block.keepBlocks;

  if (height >= 0)
    batch.del(layout.c(height));

  yield batch.write();

  this.tip = tip;
  this.height = tip.height;
});

/**
 * Connect a block.
 * @param {Wallet} wallet
 * @param {BlockMapRecord} block
 * @returns {Promise}
 */

WalletDB.prototype.writeBlockMap = function writeBlockMap(wallet, height, block) {
  var batch = this.batch(wallet);
  batch.put(layout.b(height), block.toRaw());
};

/**
 * Connect a block.
 * @param {Wallet} wallet
 * @param {BlockMapRecord} block
 * @returns {Promise}
 */

WalletDB.prototype.unwriteBlockMap = function unwriteBlockMap(wallet, height) {
  var batch = this.batch(wallet);
  batch.del(layout.b(height));
};

/**
 * Connect a transaction.
 * @param {Wallet} wallet
 * @param {Hash} hash
 * @param {TXMapRecord} map
 * @returns {Promise}
 */

WalletDB.prototype.writeTXMap = function writeTXMap(wallet, hash, map) {
  var batch = this.batch(wallet);
  batch.put(layout.e(hash), map.toRaw());
  this.addFilter(hash);
};

/**
 * Connect a transaction.
 * @param {Wallet} wallet
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.unwriteTXMap = function unwriteTXMap(wallet, hash) {
  var batch = this.batch(wallet);
  batch.del(layout.e(hash));
};

/**
 * Get a wallet block (with hashes).
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getBlockMap = co(function* getBlockMap(height) {
  var data = yield this.db.get(layout.b(height));

  if (!data)
    return;

  return BlockMapRecord.fromRaw(height, data);
});

/**
 * Get a wallet block (with hashes).
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getHeader = co(function* getHeader(height) {
  var data = yield this.db.get(layout.c(height));

  if (!data)
    return;

  return HeaderRecord.fromRaw(data);
});

/**
 * Get a TX->Wallet map.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getTXMap = co(function* getTXMap(hash) {
  var data = yield this.db.get(layout.e(hash));

  if (!data)
    return;

  return TXMapRecord.fromRaw(hash, data);
});

/**
 * Sync with chain height.
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.rollback = co(function* rollback(height) {
  var tip;

  if (this.height > height) {
    this.logger.info(
      'Rolling back %d blocks to height %d.',
      this.height - height, height);
  }

  while (this.height > height) {
    tip = yield this.getHeader(this.height);

    if (!tip) {
      yield this.forceTip(this.network.genesis);
      throw new Error('Wallet reorgd beyond safe height. Rescan required.');
    }

    yield this._removeBlock(tip);
  }
});

/**
 * Add a block's transactions and write the new best hash.
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype.addBlock = co(function* addBlock(entry, txs) {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._addBlock(entry, txs);
  } finally {
    unlock();
  }
});

/**
 * Add a block's transactions without a lock.
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype._addBlock = co(function* addBlock(entry, txs) {
  var total = 0;
  var i, tip, tx;

  if (entry.height <= this.height) {
    this.logger.warning('Wallet is connecting low blocks.');
    return total;
  }

  if (entry.height !== this.height + 1)
    throw new Error('Bad connection (height mismatch).');

  tip = HeaderRecord.fromEntry(entry);

  yield this.setTip(tip);

  if (this.options.useCheckpoints) {
    if (tip.height <= this.network.checkpoints.lastHeight)
      return 0;
  }

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    if (yield this._insert(tx, tip))
      total++;
  }

  if (total > 0) {
    this.logger.info('Connected block %s (tx=%d).',
      utils.revHex(tip.hash), total);
  }

  return total;
});

/**
 * Unconfirm a block's transactions
 * and write the new best hash (SPV version).
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype.removeBlock = co(function* removeBlock(entry) {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._removeBlock(entry);
  } finally {
    unlock();
  }
});

/**
 * Unconfirm a block's transactions.
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype._removeBlock = co(function* removeBlock(entry) {
  var i, tx, tip, prev, block;

  if (entry.height > this.height) {
    this.logger.warning('Wallet is disconnecting high blocks.');
    return 0;
  }

  if (entry.height !== this.height)
    throw new Error('Bad disconnection (height mismatch).');

  tip = yield this.getHeader(entry.height);

  if (!tip)
    throw new Error('Bad disconnection (block not found).');

  prev = yield this.getHeader(entry.height - 1);

  if (!prev)
    throw new Error('Bad disconnection (no previous block).');

  block = yield this.getBlockMap(tip.height);

  if (!block) {
    yield this.setTip(prev);
    return 0;
  }

  for (i = block.txs.length - 1; i >= 0; i--) {
    tx = block.txs[i];
    yield this._unconfirm(tx, tip);
  }

  yield this.setTip(prev);

  this.logger.warning('Disconnected block %s (tx=%d).',
    utils.revHex(block.hash), block.txs.length);

  return block.txs.length;
});

/**
 * Add a transaction to the database, map addresses
 * to wallet IDs, potentially store orphans, resolve
 * orphans, or confirm a transaction.
 * @param {TX} tx
 * @returns {Promise}
 */

WalletDB.prototype.addTX = co(function* addTX(tx) {
  var unlock = yield this.txLock.lock();
  var entry;

  try {
    if (tx.height !== -1) {
      entry = yield this.getHeader(tx.height);

      if (!entry)
        throw new Error('Inserting unconfirmed transaction.');

      if (tx.block !== entry.hash)
        throw new Error('Inserting unconfirmed transaction.');

      this.logger.warning('Retroactively inserting confirmed transaction.');
    }

    return yield this._insert(tx);
  } finally {
    unlock();
  }
});

/**
 * Add a transaction to the database without a lock.
 * @private
 * @param {TX} tx
 * @param {HeaderRecord} block
 * @returns {Promise}
 */

WalletDB.prototype._insert = co(function* insert(tx, block) {
  var result = false;
  var i, wids, wid, wallet;

  assert(!tx.mutable, 'Cannot add mutable TX to wallet.');

  wids = yield this.getWalletsByInsert(tx);

  if (!wids)
    return;

  this.logger.info(
    'Incoming transaction for %d wallets (%s).',
    wids.length, tx.rhash);

  for (i = 0; i < wids.length; i++) {
    wid = wids[i];
    wallet = yield this.get(wid);

    assert(wallet);

    if (yield wallet.add(tx, block)) {
      this.logger.info(
        'Added transaction to wallet: %s (%d).',
        wallet.id, wid);
      result = true;
    }
  }

  if (!result)
    return;

  return wids;
});

/**
 * Unconfirm a transaction from all
 * relevant wallets without a lock.
 * @private
 * @param {TXHash} hash
 * @param {HeaderRecord} block
 * @returns {Promise}
 */

WalletDB.prototype._unconfirm = co(function* unconfirm(tx, block) {
  var i, wid, wallet;

  for (i = 0; i < tx.wids.length; i++) {
    wid = tx.wids[i];
    wallet = yield this.get(wid);
    assert(wallet);
    yield wallet.unconfirm(tx.hash, block);
  }
});

/**
 * Zap stale transactions.
 * @param {Number} age
 * @returns {Promise}
 */

WalletDB.prototype.zap = co(function* zap(age) {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._zap(age);
  } finally {
    unlock();
  }
});

/**
 * Zap stale transactions without a lock.
 * @private
 * @param {Number} age
 * @returns {Promise}
 */

WalletDB.prototype._zap = co(function* zap(age) {
  var wids = yield this.getPendingWallets();
  var i, wid, wallet;

  for (i = 0; i < wids.length; i++) {
    wid = wids[i];
    wallet = yield this.get(wid);
    assert(wallet);
    yield wallet.zap(age);
  }
});

/*
 * Helpers
 */

function cmp(a, b) {
  return a - b;
}

/*
 * Expose
 */

module.exports = WalletDB;
