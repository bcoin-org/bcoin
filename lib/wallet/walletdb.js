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
  p: function(hash) {
    var key = new Buffer(1 + (hash.length / 2));
    key[0] = 0x70;
    key.write(hash, 1, 'hex');
    return key;
  },
  pp: function(key) {
    return key.toString('hex', 1);
  },
  P: function(wid, hash) {
    var key = new Buffer(1 + 4 + (hash.length / 2));
    key[0] = 0x50;
    key.writeUInt32BE(wid, 1, true);
    key.write(hash, 5, 'hex');
    return key;
  },
  Pp: function(key) {
    return key.toString('hex', 5);
  },
  w: function(wid) {
    var key = new Buffer(5);
    key[0] = 0x77;
    key.writeUInt32BE(wid, 1, true);
    return key;
  },
  ww: function(key) {
    return key.readUInt32BE(1, true);
  },
  l: function(id) {
    var len = Buffer.byteLength(id, 'ascii');
    var key = new Buffer(1 + len);
    key[0] = 0x6c;
    if (len > 0)
      key.write(id, 1, 'ascii');
    return key;
  },
  ll: function(key) {
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
  b: function b(hash) {
    var key = new Buffer(33);
    key[0] = 0x62;
    key.write(hash, 1, 'hex');
    return key;
  },
  e: function e(hash) {
    var key = new Buffer(33);
    key[0] = 0x65;
    key.write(hash, 1, 'hex');
    return key;
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
  this.fees = options.fees;
  this.logger = options.logger || Logger.global;
  this.batches = {};
  this.wallets = {};

  this.tip = this.network.genesis.hash;
  this.height = 0;
  this.depth = 0;

  // We need one read lock for `get` and `create`.
  // It will hold locks specific to wallet ids.
  this.readLock = new Locker.Mapped();
  this.writeLock = new Locker();
  this.txLock = new Locker();

  this.widCache = new LRU(10000);
  this.indexCache = new LRU(10000);
  this.accountCache = new LRU(10000);
  this.pathCache = new LRU(100000);
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
  yield this.db.checkVersion('V', 3);
  yield this.writeGenesis();

  this.depth = yield this.getDepth();

  this.logger.info(
    'WalletDB loaded (depth=%d, height=%d).',
    this.depth, this.height);

  yield this.loadFilter();
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
 * Backup the wallet db.
 * @param {String} path
 * @returns {Promise}
 */

WalletDB.prototype.backup = function backup(path) {
  return this.db.backup(path);
};

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
 * Start batch.
 * @private
 * @param {WalletID} wid
 */

WalletDB.prototype.start = function start(wid) {
  var batch;
  assert(utils.isNumber(wid), 'Bad ID for batch.');
  assert(!this.batches[wid], 'Batch already started.');
  batch = this.db.batch();
  this.batches[wid] = batch;
  return batch;
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
 * @returns {Promise}
 */

WalletDB.prototype.commit = function commit(wid) {
  var batch = this.batch(wid);
  delete this.batches[wid];
  return batch.write();
};

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
});

/**
 * Test the bloom filter against an array of address hashes.
 * @private
 * @param {Hash[]} hashes
 * @returns {Boolean}
 */

WalletDB.prototype.testFilter = function testFilter(hashes) {
  var i;

  if (!this.filter)
    return true;

  for (i = 0; i < hashes.length; i++) {
    if (this.filter.test(hashes[i], 'hex'))
      return true;
  }

  return false;
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

  this.register(wallet);

  yield wallet.open();

  return wallet;
});

/**
 * Save a wallet to the database.
 * @param {Wallet} wallet
 */

WalletDB.prototype.save = function save(wallet) {
  var wid = wallet.wid;
  var id = wallet.id;
  var batch = this.batch(wid);
  var buf = new Buffer(4);

  this.widCache.set(id, wid);

  batch.put(layout.w(wid), wallet.toRaw());

  buf.writeUInt32LE(wid, 0, true);
  batch.put(layout.l(id), buf);
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

  assert(utils.isName(id), 'Bad wallet ID.');

  if (yield this.has(id))
    throw new Error('ID not available.');

  this.widCache.remove(old);

  paths = this.pathCache.values();

  // TODO: Optimize this bullshit.
  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    if (path.wid !== wallet.wid)
      continue;

    path.id = id;
  }

  wallet.id = id;

  batch = this.start(wallet.wid);
  batch.del(layout.l(old));

  this.save(wallet);

  yield this.commit(wallet.wid);
});

/**
 * Rename an account.
 * @param {Account} account
 * @param {String} name
 * @returns {Promise}
 */

WalletDB.prototype.renameAccount = co(function* renameAccount(account, name) {
  var old = account.name;
  var key = account.wid + '/' + old;
  var i, paths, path, batch;

  assert(utils.isName(name), 'Bad account name.');

  if (account.accountIndex === 0)
    throw new Error('Cannot rename primary account.');

  if (yield this.hasAccount(account.wid, name))
    throw new Error('Account name not available.');

  this.indexCache.remove(key);

  paths = this.pathCache.values();

  // TODO: Optimize this bullshit.
  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    if (path.wid !== account.wid)
      continue;

    if (path.account !== account.accountIndex)
      continue;

    path.name = name;
  }

  account.name = name;

  batch = this.start(account.wid);
  batch.del(layout.i(account.wid, old));

  this.saveAccount(account);

  yield this.commit(account.wid);
});

/**
 * Test an api key against a wallet's api key.
 * @param {WalletID} wid
 * @param {String} token
 * @returns {Promise}
 */

WalletDB.prototype.auth = co(function* auth(wid, token) {
  var wallet = yield this.get(wid);
  if (!wallet)
    return;

  if (typeof token === 'string') {
    if (!utils.isHex(token))
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

  this.register(wallet);

  yield wallet.init(options);

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
 * Get an account from the database.
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.getAccount = co(function* getAccount(wid, name) {
  var index = yield this.getAccountIndex(wid, name);
  var account;

  if (index === -1)
    return;

  account = yield this._getAccount(wid, index);

  if (!account)
    return;

  yield account.open();

  return account;
});

/**
 * Get an account from the database by wid.
 * @private
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype._getAccount = co(function* getAccount(wid, index) {
  var key = wid + '/' + index;
  var account = this.accountCache.get(key);
  var data;

  if (account)
    return account;

  data = yield this.db.get(layout.a(wid, index));

  if (!data)
    return;

  account = Account.fromRaw(this, data);

  this.accountCache.set(key, account);

  return account;
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
  var key, index;

  if (!wid)
    return -1;

  if (name == null)
    return -1;

  if (typeof name === 'number')
    return name;

  key = wid + '/' + name;
  index = this.indexCache.get(key);

  if (index != null)
    return index;

  index = yield this.db.get(layout.i(wid, name));

  if (!index)
    return -1;

  index = index.readUInt32LE(0, true);

  this.indexCache.set(key, index);

  return index;
});

/**
 * Lookup the corresponding account index's name.
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @returns {Promise} - Returns String.
 */

WalletDB.prototype.getAccountName = co(function* getAccountName(wid, index) {
  var account = yield this._getAccount(wid, index);

  if (!account)
    return null;

  return account.name;
});

/**
 * Save an account to the database.
 * @param {Account} account
 * @returns {Promise}
 */

WalletDB.prototype.saveAccount = function saveAccount(account) {
  var wid = account.wid;
  var index = account.accountIndex;
  var name = account.name;
  var batch = this.batch(wid);
  var key = wid + '/' + index;
  var buf = new Buffer(4);

  buf.writeUInt32LE(index, 0, true);

  batch.put(layout.a(wid, index), account.toRaw());
  batch.put(layout.i(wid, name), buf);

  this.accountCache.set(key, account);
};

/**
 * Create an account.
 * @param {Object} options - See {@link Account} options.
 * @returns {Promise} - Returns {@link Account}.
 */

WalletDB.prototype.createAccount = co(function* createAccount(options) {
  var exists = yield this.hasAccount(options.wid, options.name);
  var account;

  if (exists)
    throw new Error('Account already exists.');

  account = Account.fromOptions(this, options);

  yield account.init();

  this.logger.info('Created account %s/%s/%d.',
    account.id,
    account.name,
    account.accountIndex);

  return account;
});

/**
 * Test for the existence of an account.
 * @param {WalletID} wid
 * @param {String|Number} account
 * @returns {Promise} - Returns Boolean.
 */

WalletDB.prototype.hasAccount = co(function* hasAccount(wid, account) {
  var index, key;

  if (!wid)
    return false;

  index = yield this.getAccountIndex(wid, account);

  if (index === -1)
    return false;

  key = wid + '/' + index;

  if (this.accountCache.has(key))
    return true;

  return yield this.db.has(layout.a(wid, index));
});

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} wid
 * @param {String|Number} name - Account name/index.
 * @returns {Promise} - Returns Number.
 */

WalletDB.prototype.getWalletsByHash = co(function* getWalletsByHash(hash) {
  var wallets = this.pathMapCache.get(hash);
  var data;

  if (wallets)
    return wallets;

  data = yield this.db.get(layout.p(hash));

  if (!data)
    return;

  wallets = parseWallets(data);

  this.pathMapCache.get(hash, wallets);

  return wallets;
});

/**
 * Save an address to the path map.
 * @param {WalletID} wid
 * @param {KeyRing[]} ring
 * @returns {Promise}
 */

WalletDB.prototype.saveKey = function saveKey(wid, ring) {
  return this.savePath(wid, ring.toPath());
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

WalletDB.prototype.savePath = co(function* savePath(wid, path) {
  var hash = path.hash;
  var batch = this.batch(wid);
  var key = wid + hash;
  var wallets;

  if (this.filter)
    this.filter.add(hash, 'hex');

  this.emit('path', path);

  wallets = yield this.getWalletsByHash(hash);

  if (!wallets)
    wallets = [];

  if (wallets.indexOf(wid) !== -1)
    return;

  wallets.push(wid);

  this.pathMapCache.set(hash, wallets);
  this.pathCache.set(key, path);

  batch.put(layout.p(hash), serializeWallets(wallets));
  batch.put(layout.P(wid, hash), path.toRaw());
});

/**
 * Retrieve paths by hash.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getPaths = co(function* getPaths(hash) {
  var wallets = yield this.getWalletsByHash(hash);
  var i, wid, path, paths;

  if (!wallets)
    return;

  paths = [];

  for (i = 0; i < wallets.length; i++) {
    wid = wallets[i];
    path = yield this.getPath(wid, hash);
    if (path)
      paths.push(path);
  }

  return paths;
});

/**
 * Retrieve path by hash.
 * @param {WalletID} wid
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getPath = co(function* getPath(wid, hash) {
  var key, path, data;

  if (!hash)
    return;

  key = wid + hash;
  path = this.pathCache.get(key);

  if (path)
    return path;

  data = yield this.db.get(layout.P(wid, hash));

  if (!data)
    return;

  path = Path.fromRaw(data);
  path.wid = wid;
  path.hash = hash;
  path.name = yield this.getAccountName(wid, path.account);

  this.pathCache.set(key, path);

  return path;
});

/**
 * Test whether an address hash exists in the
 * path map and is relevant to the wallet id.
 * @param {WalletID} wid
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.hasAddress = co(function* hasAddress(wid, hash) {
  var path = yield this.getPath(wid, hash);
  return path != null;
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
    path.name = yield this.getAccountName(wid, path.account);

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

WalletDB.prototype.encryptKeys = co(function* encryptKeys(wid, key) {
  var paths = yield this.getWalletPaths(wid);
  var batch = this.batch(wid);
  var i, path, iv;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    if (path.data && !path.encrypted) {
      iv = new Buffer(path.hash, 'hex');
      iv = iv.slice(0, 16);
      path.data = crypto.encipher(path.data, key, iv);
      path.encrypted = true;
      this.pathCache.set(wid + path.hash, path);
      batch.put(layout.P(wid, path.hash), path.toRaw());
    }
  }
});

/**
 * Decrypt all imported keys for a wallet.
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.decryptKeys = co(function* decryptKeys(wid, key) {
  var paths = yield this.getWalletPaths(wid);
  var batch = this.batch(wid);
  var i, path, iv;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    if (path.data && path.encrypted) {
      iv = new Buffer(path.hash, 'hex');
      iv = iv.slice(0, 16);
      path.data = crypto.decipher(path.data, key, iv);
      path.encrypted = false;
      this.pathCache.set(wid + path.hash, path);
      batch.put(layout.P(wid, path.hash), path.toRaw());
    }
  }
});

/**
 * Rescan the blockchain.
 * @param {ChainDB} chaindb
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.rescan = co(function* rescan(chaindb, height) {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._rescan(chaindb, height);
  } finally {
    unlock();
  }
});

/**
 * Rescan the blockchain without a lock.
 * @private
 * @param {ChainDB} chaindb
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype._rescan = co(function* rescan(chaindb, height) {
  var self = this;
  var hashes;

  if (height == null)
    height = this.height;

  hashes = yield this.getHashes();

  this.logger.info('Scanning for %d addresses.', hashes.length);

  yield chaindb.scan(height, hashes, function(block, txs) {
    return self._addBlock(block, txs);
  });
});

/**
 * Get keys of all pending transactions
 * in the wallet db (for resending).
 * @returns {Promise}
 */

WalletDB.prototype.getPendingKeys = co(function* getPendingKeys() {
  var layout = require('./txdb').layout;
  var dummy = new Buffer(0);
  var uniq = {};
  var keys = [];
  var result = [];
  var i, iter, item, key, wid, hash;

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
 * Resend all pending transactions.
 * @returns {Promise}
 */

WalletDB.prototype.resend = co(function* resend() {
  var keys = yield this.getPendingKeys();
  var i, key, data, tx;

  if (keys.length > 0)
    this.logger.info('Rebroadcasting %d transactions.', keys.length);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    data = yield this.db.get(key);

    if (!data)
      continue;

    tx = TX.fromExtended(data);

    this.emit('send', tx);
  }
});

/**
 * Map a transactions' addresses to wallet IDs.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link PathInfo[}].
 */

WalletDB.prototype.mapWallets = co(function* mapWallets(tx) {
  var hashes = tx.getHashes('hex');
  var table;

  if (!this.testFilter(hashes))
    return;

  table = yield this.getTable(hashes);

  if (!table)
    return;

  return PathInfo.map(this, tx, table);
});

/**
 * Map a transactions' addresses to wallet IDs.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link PathInfo}.
 */

WalletDB.prototype.getPathInfo = co(function* getPathInfo(wallet, tx) {
  var hashes = tx.getHashes('hex');
  var table = yield this.getTable(hashes);
  var info;

  if (!table)
    return;

  info = new PathInfo(this, wallet.wid, tx, table);
  info.id = wallet.id;

  return info;
});

/**
 * Map address hashes to paths.
 * @param {Hash[]} hashes - Address hashes.
 * @returns {Promise} - Returns {@link AddressTable}.
 */

WalletDB.prototype.getTable = co(function* getTable(hashes) {
  var table = {};
  var match = false;
  var i, hash, paths;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = yield this.getPaths(hash);

    if (!paths) {
      table[hash] = [];
      continue;
    }

    table[hash] = paths;
    match = true;
  }

  if (!match)
    return;

  return table;
});

/**
 * Write the genesis block as the best hash.
 * @returns {Promise}
 */

WalletDB.prototype.writeGenesis = co(function* writeGenesis() {
  var block = yield this.getTip();
  if (block) {
    this.tip = block.hash;
    this.height = block.height;
    return;
  }
  yield this.setTip(this.network.genesis.hash, 0);
});

/**
 * Get the best block hash.
 * @returns {Promise}
 */

WalletDB.prototype.getTip = co(function* getTip() {
  var data = yield this.db.get(layout.R);

  if (!data)
    return;

  return WalletBlock.fromTip(data);
});

/**
 * Write the best block hash.
 * @param {Hash} hash
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.setTip = co(function* setTip(hash, height) {
  var block = new WalletBlock(hash, height);

  yield this.db.put(layout.R, block.toTip());

  this.tip = block.hash;
  this.height = block.height;
});

/**
 * Connect a block.
 * @param {WalletBlock} block
 * @returns {Promise}
 */

WalletDB.prototype.writeBlock = function writeBlock(block, matches) {
  var batch = this.db.batch();
  var i, hash, wallets;

  batch.put(layout.R, block.toTip());

  if (block.hashes.length === 0)
    return batch.write();

  batch.put(layout.b(block.hash), block.toRaw());

  for (i = 0; i < block.hashes.length; i++) {
    hash = block.hashes[i];
    wallets = matches[i];
    batch.put(layout.e(hash), serializeInfo(wallets));
  }

  return batch.write();
};

/**
 * Disconnect a block.
 * @param {WalletBlock} block
 * @returns {Promise}
 */

WalletDB.prototype.unwriteBlock = function unwriteBlock(block) {
  var batch = this.db.batch();
  var prev = new WalletBlock(block.prevBlock, block.height - 1);

  batch.put(layout.R, prev.toTip());
  batch.del(layout.b(block.hash));

  return batch.write();
};

/**
 * Get a wallet block (with hashes).
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getBlock = co(function* getBlock(hash) {
  var data = yield this.db.get(layout.b(hash));

  if (!data)
    return;

  return WalletBlock.fromRaw(hash, data);
});

/**
 * Get a TX->Wallet map.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getWalletsByTX = co(function* getWalletsByTX(hash) {
  var data = yield this.db.get(layout.e(hash));

  if (!data)
    return;

  return parseWallets(data);
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
  var i, block, matches, hash, tx, wallets;

  if (this.options.useCheckpoints) {
    if (entry.height <= this.network.checkpoints.lastHeight) {
      yield this.setTip(entry.hash, entry.height);
      return;
    }
  }

  block = WalletBlock.fromEntry(entry);
  matches = [];

  // Update these early so transactions
  // get correct confirmation calculations.
  this.tip = block.hash;
  this.height = block.height;

  // Atomicity doesn't matter here. If we crash
  // during this loop, the automatic rescan will get
  // the database back into the correct state.
  for (i = 0; i < txs.length; i++) {
    tx = txs[i];

    wallets = yield this._addTX(tx);

    if (!wallets)
      continue;

    hash = tx.hash('hex');
    block.hashes.push(hash);
    matches.push(wallets);
  }

  if (block.hashes.length > 0) {
    this.logger.info('Connecting block %s (%d txs).',
      utils.revHex(block.hash), block.hashes.length);
  }

  yield this.writeBlock(block, matches);
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
  var block = WalletBlock.fromEntry(entry);
  var i, j, data, hash, wallets, wid, wallet;

  // If we crash during a reorg, there's not much to do.
  // Reorgs cannot be rescanned. The database will be
  // in an odd state, with some txs being confirmed
  // when they shouldn't be. That being said, this
  // should eventually resolve itself when a new block
  // comes in.
  data = yield this.getBlock(block.hash);

  if (data)
    block.hashes = data.hashes;

  if (block.hashes.length > 0) {
    this.logger.warning('Disconnecting block %s (%d txs).',
      utils.revHex(block.hash), block.hashes.length);
  }

  // Unwrite the tip as fast as we can.
  yield this.unwriteBlock(block);

  for (i = 0; i < block.hashes.length; i++) {
    hash = block.hashes[i];
    wallets = yield this.getWalletsByTX(hash);

    if (!wallets)
      continue;

    for (j = 0; j < wallets.length; j++) {
      wid = wallets[j];
      wallet = yield this.get(wid);

      if (!wallet)
        continue;

      yield wallet.tx.unconfirm(hash);
    }
  }

  this.tip = block.hash;
  this.height = block.height;
});

/**
 * Add a transaction to the database, map addresses
 * to wallet IDs, potentially store orphans, resolve
 * orphans, or confirm a transaction.
 * @param {TX} tx
 * @returns {Promise}
 */

WalletDB.prototype.addTX = co(function* addTX(tx, force) {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._addTX(tx);
  } finally {
    unlock();
  }
});

/**
 * Add a transaction to the database without a lock.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

WalletDB.prototype._addTX = co(function* addTX(tx, force) {
  var i, wallets, info, wallet;

  assert(!tx.mutable, 'Cannot add mutable TX to wallet.');

  // Atomicity doesn't matter here. If we crash,
  // the automatic rescan will get the database
  // back in the correct state.
  wallets = yield this.mapWallets(tx);

  if (!wallets)
    return;

  this.logger.info(
    'Incoming transaction for %d wallets (%s).',
    wallets.length, tx.rhash);

  for (i = 0; i < wallets.length; i++) {
    info = wallets[i];
    wallet = yield this.get(info.wid);

    if (!wallet)
      continue;

    this.logger.debug('Adding tx to wallet: %s', wallet.id);

    info.id = wallet.id;

    yield wallet.tx.add(tx, info);
    yield wallet.handleTX(info);
  }

  return wallets;
});

/**
 * Path Info
 * @constructor
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
  var wallets = [];
  var info = [];
  var uniq = {};
  var i, j, hash, paths, path, wid;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    paths = table[hash];
    for (j = 0; j < paths.length; j++) {
      path = paths[j];
      if (!uniq[path.wid]) {
        uniq[path.wid] = true;
        wallets.push(path.wid);
      }
    }
  }

  if (wallets.length === 0)
    return;

  for (i = 0; i < wallets.length; i++) {
    wid = wallets[i];
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
 * @param {Hash} hash
 * @returns {Boolean}
 */

PathInfo.prototype.hasPath = function hasPath(hash) {
  if (!hash)
    return false;

  return this.pathMap[hash] != null;
};

/**
 * Get paths for a given address hash.
 * @param {Hash} hash
 * @returns {Path[]|null}
 */

PathInfo.prototype.getPath = function getPath(hash) {
  if (!hash)
    return;

  return this.pathMap[hash];
};

PathInfo.prototype.toDetails = function toDetails() {
  var details = this._details;

  if (!details) {
    details = new Details(this);
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

/**
 * Details
 * @constructor
 */

function Details(info) {
  if (!(this instanceof Details))
    return new Details(info);

  this.db = info.db;
  this.network = info.db.network;
  this.wid = info.wid;
  this.id = info.id;
  this.hash = info.tx.hash('hex');
  this.height = info.tx.height;
  this.block = info.tx.block;
  this.index = info.tx.index;
  this.confirmations = info.tx.getConfirmations(this.db.height);
  this.fee = info.tx.getFee();
  this.ts = info.tx.ts;
  this.ps = info.tx.ps;
  this.tx = info.tx;
  this.inputs = [];
  this.outputs = [];

  this.init(info.table);
}

Details.prototype.init = function init(table) {
  this._insert(this.tx.inputs, this.inputs, table);
  this._insert(this.tx.outputs, this.outputs, table);
};

Details.prototype._insert = function _insert(vector, target, table) {
  var i, j, io, address, hash, paths, path, member;

  for (i = 0; i < vector.length; i++) {
    io = vector[i];
    member = new DetailsMember();

    if (io.prevout)
      member.value = io.coin ? io.coin.value : 0;
    else
      member.value = io.value;

    address = io.getAddress();

    if (address) {
      member.address = address;

      hash = address.getHash('hex');
      paths = table[hash];

      for (j = 0; j < paths.length; j++) {
        path = paths[j];
        if (path.wid === this.wid) {
          path.id = this.id;
          member.path = path;
          break;
        }
      }
    }

    target.push(member);
  }
};

Details.prototype.toJSON = function toJSON() {
  var self = this;
  return {
    wid: this.wid,
    id: this.id,
    hash: utils.revHex(this.hash),
    height: this.height,
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    index: this.index,
    fee: utils.btc(this.fee),
    confirmations: this.confirmations,
    inputs: this.inputs.map(function(input) {
      return input.toJSON(self.network);
    }),
    outputs: this.outputs.map(function(output) {
      return output.toJSON(self.network);
    }),
    tx: this.tx.toRaw().toString('hex')
  };
};

/**
 * DetailsMember
 * @constructor
 */

function DetailsMember() {
  if (!(this instanceof DetailsMember))
    return new DetailsMember();

  this.value = 0;
  this.address = null;
  this.path = null;
}

DetailsMember.prototype.toJSON = function toJSON(network) {
  return {
    value: utils.btc(this.value),
    address: this.address
      ? this.address.toBase58(network)
      : null,
    path: this.path
      ? this.path.toJSON()
      : null
  };
};

/**
 * Wallet Block
 * @constructor
 */

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
  return new WalletBlock().fromRaw(hash, data);
};

WalletBlock.fromTip = function fromTip(data) {
  return new WalletBlock().fromTip(data);
};

WalletBlock.prototype.toTip = function toTip() {
  var p = new BufferWriter();
  p.writeHash(this.hash);
  p.writeU32(this.height);
  return p.render();
};

WalletBlock.prototype.toRaw = function toRaw() {
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

/*
 * Helpers
 */

function parseWallets(data) {
  var p = new BufferReader(data);
  var wallets = [];
  while (p.left())
    wallets.push(p.readU32());
  return wallets;
}

function serializeWallets(wallets) {
  var p = new BufferWriter();
  var i, wid;

  for (i = 0; i < wallets.length; i++) {
    wid = wallets[i];
    p.writeU32(wid);
  }

  return p.render();
}

function serializeInfo(wallets) {
  var p = new BufferWriter();
  var i, info;

  for (i = 0; i < wallets.length; i++) {
    info = wallets[i];
    p.writeU32(info.wid);
  }

  return p.render();
}

/*
 * Expose
 */

module.exports = WalletDB;
