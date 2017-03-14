/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var AsyncObject = require('../utils/asyncobject');
var util = require('../utils/util');
var co = require('../utils/co');
var Lock = require('../utils/lock');
var LRU = require('../utils/lru');
var encoding = require('../utils/encoding');
var crypto = require('../crypto/crypto');
var Network = require('../protocol/network');
var Path = require('./path');
var common = require('./common');
var Wallet = require('./wallet');
var Account = require('./account');
var LDB = require('../db/ldb');
var Bloom = require('../utils/bloom');
var Logger = require('../node/logger');
var Outpoint = require('../primitives/outpoint');
var layouts = require('./layout');
var records = require('./records');
var HTTPServer = require('./http');
var RPC = require('./rpc');
var layout = layouts.walletdb;
var ChainState = records.ChainState;
var BlockMapRecord = records.BlockMapRecord;
var BlockMeta = records.BlockMeta;
var PathMapRecord = records.PathMapRecord;
var OutpointMapRecord = records.OutpointMapRecord;
var TXRecord = records.TXRecord;
var U32 = encoding.U32;
var DUMMY = new Buffer([0]);

/**
 * WalletDB
 * @alias module:wallet.WalletDB
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

  AsyncObject.call(this);

  this.options = new WalletOptions(options);

  this.network = this.options.network;
  this.logger = this.options.logger.context('wallet');
  this.client = this.options.client;
  this.db = LDB(this.options);
  this.rpc = new RPC(this);
  this.primary = null;
  this.http = null;

  if (!HTTPServer.unsupported) {
    this.http = new HTTPServer({
      walletdb: this,
      network: this.network,
      logger: this.logger,
      prefix: this.options.prefix,
      apiKey: this.options.apiKey,
      walletAuth: this.options.walletAuth,
      noAuth: this.options.noAuth,
      host: this.options.host,
      port: this.options.port,
      ssl: this.options.ssl
    });
  }

  this.state = new ChainState();
  this.wallets = Object.create(null);
  this.depth = 0;
  this.rescanning = false;
  this.bound = false;

  this.readLock = new Lock.Mapped();
  this.writeLock = new Lock();
  this.txLock = new Lock();

  this.widCache = new LRU(10000);
  this.pathMapCache = new LRU(100000);

  this.filter = new Bloom();

  this._init();
}

util.inherits(WalletDB, AsyncObject);

/**
 * Database layout.
 * @type {Object}
 */

WalletDB.layout = layout;

/**
 * Initialize walletdb.
 * @private
 */

WalletDB.prototype._init = function _init() {
  var items = 1000000;
  var flag = -1;

  // Highest number of items with an
  // FPR of 0.001. We have to do this
  // by hand because Bloom.fromRate's
  // policy limit enforcing is fairly
  // naive.
  if (this.options.spv) {
    items = 20000;
    flag = Bloom.flags.ALL;
  }

  this.filter = Bloom.fromRate(items, 0.001, flag);
};

/**
 * Open the walletdb, wait for the database to load.
 * @alias WalletDB#open
 * @returns {Promise}
 */

WalletDB.prototype._open = co(function* open() {
  var wallet;

  if (this.options.listen)
    yield this.logger.open();

  yield this.db.open();
  yield this.db.checkVersion('V', 6);

  this.depth = yield this.getDepth();

  if (this.options.wipeNoReally)
    yield this.wipe();

  yield this.load();

  this.logger.info(
    'WalletDB loaded (depth=%d, height=%d, start=%d).',
    this.depth,
    this.state.height,
    this.state.startHeight);

  wallet = yield this.ensure({
    id: 'primary'
  });

  this.logger.info(
    'Loaded primary wallet (id=%s, wid=%d, address=%s)',
    wallet.id, wallet.wid, wallet.getAddress());

  this.primary = wallet;
  this.rpc.wallet = wallet;

  if (this.http && this.options.listen)
    yield this.http.open();
});

/**
 * Close the walletdb, wait for the database to close.
 * @alias WalletDB#close
 * @returns {Promise}
 */

WalletDB.prototype._close = co(function* close() {
  var keys = Object.keys(this.wallets);
  var i, key, wallet;

  yield this.disconnect();

  if (this.http && this.options.listen)
    yield this.http.close();

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    wallet = this.wallets[key];
    yield wallet.destroy();
  }

  yield this.db.close();

  if (this.options.listen)
    yield this.logger.close();
});

/**
 * Load the walletdb.
 * @returns {Promise}
 */

WalletDB.prototype.load = co(function* load() {
  var unlock = yield this.txLock.lock();
  try {
    yield this.connect();
    yield this.init();
    yield this.watch();
    yield this.sync();
    yield this.resend();
  } finally {
    unlock();
  }
});

/**
 * Bind to node events.
 * @private
 */

WalletDB.prototype.bind = function bind() {
  var self = this;

  if (!this.client)
    return;

  if (this.bound)
    return;

  this.bound = true;

  this.client.on('error', function(err) {
    self.emit('error', err);
  });

  this.client.on('block connect', co(function* (entry, txs) {
    try {
      yield self.addBlock(entry, txs);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  this.client.on('block disconnect', co(function* (entry) {
    try {
      yield self.removeBlock(entry);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  this.client.hook('block rescan', co(function* (entry, txs) {
    try {
      yield self.rescanBlock(entry, txs);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  this.client.on('tx', co(function* (tx) {
    try {
      yield self.addTX(tx);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  this.client.on('chain reset', co(function* (tip) {
    try {
      yield self.resetChain(tip);
    } catch (e) {
      self.emit('error', e);
    }
  }));
};

/**
 * Connect to the node server (client required).
 * @returns {Promise}
 */

WalletDB.prototype.connect = co(function* connect() {
  if (!this.client)
    return;

  this.bind();

  yield this.client.open();
  yield this.setFilter();
});

/**
 * Disconnect from node server (client required).
 * @returns {Promise}
 */

WalletDB.prototype.disconnect = co(function* disconnect() {
  if (!this.client)
    return;

  yield this.client.close();
});

/**
 * Initialize and write initial sync state.
 * @returns {Promise}
 */

WalletDB.prototype.init = co(function* init() {
  var state = yield this.getState();
  var startHeight = this.options.startHeight;
  var tip;

  if (state) {
    this.state = state;
    return;
  }

  if (this.client) {
    if (startHeight != null) {
      tip = yield this.client.getEntry(startHeight);
      if (!tip)
        throw new Error('WDB: Could not find start block.');
    } else {
      tip = yield this.client.getTip();
    }
    tip = BlockMeta.fromEntry(tip);
  } else {
    tip = BlockMeta.fromEntry(this.network.genesis);
  }

  this.logger.info(
    'Initializing WalletDB chain state at %s (%d).',
    util.revHex(tip.hash), tip.height);

  yield this.resetState(tip, false);
});

/**
 * Watch addresses and outpoints.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.watch = co(function* watch() {
  var hashes = 0;
  var outpoints = 0;
  var iter, item, data, outpoint, items;

  iter = this.db.iterator({
    gte: layout.p(encoding.NULL_HASH),
    lte: layout.p(encoding.HIGH_HASH)
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    try {
      data = layout.pp(item.key);
      this.filter.add(data, 'hex');
    } catch (e) {
      yield iter.end();
      throw e;
    }

    hashes++;
  }

  iter = this.db.iterator({
    gte: layout.o(encoding.NULL_HASH, 0),
    lte: layout.o(encoding.HIGH_HASH, 0xffffffff)
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    try {
      items = layout.oo(item.key);
      outpoint = new Outpoint(items[0], items[1]);
      data = outpoint.toRaw();
      this.filter.add(data);
    } catch (e) {
      yield iter.end();
      throw e;
    }

    outpoints++;
  }

  this.logger.info('Added %d hashes to WalletDB filter.', hashes);
  this.logger.info('Added %d outpoints to WalletDB filter.', outpoints);

  yield this.setFilter();
});

/**
 * Connect and sync with the chain server.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.sync = co(function* sync() {
  var height = this.state.height;
  var tip, entry;

  if (!this.client)
    return;

  while (height >= 0) {
    tip = yield this.getBlock(height);

    if (!tip)
      break;

    entry = yield this.client.getEntry(tip.hash);

    if (entry)
      break;

    height--;
  }

  if (!entry) {
    height = this.state.startHeight;
    entry = yield this.client.getEntry(this.state.startHash);

    if (!entry)
      height = 0;
  }

  yield this.scan(height);
});

/**
 * Rescan blockchain from a given height.
 * @private
 * @param {Number?} height
 * @returns {Promise}
 */

WalletDB.prototype.scan = co(function* scan(height) {
  var tip;

  if (!this.client)
    return;

  if (height == null)
    height = this.state.startHeight;

  assert(util.isUInt32(height), 'WDB: Must pass in a height.');

  yield this.rollback(height);

  this.logger.info(
    'WalletDB is scanning %d blocks.',
    this.state.height - height + 1);

  tip = yield this.getTip();

  try {
    this.rescanning = true;
    yield this.client.rescan(tip.hash);
  } finally {
    this.rescanning = false;
  }
});

/**
 * Force a rescan.
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
  return yield this.scan(height);
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
  var rate;

  if (!this.client)
    return this.network.feeRate;

  rate = yield this.client.estimateFee(blocks);

  if (rate < this.network.feeRate)
    return this.network.feeRate;

  if (rate > this.network.maxFeeRate)
    return this.network.maxFeeRate;

  return rate;
});

/**
 * Send filter to the remote node.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.setFilter = function setFilter() {
  if (!this.client) {
    this.emit('set filter', this.filter);
    return Promise.resolve();
  }

  return this.client.setFilter(this.filter);
};

/**
 * Add data to remote filter.
 * @private
 * @param {Buffer} data
 * @returns {Promise}
 */

WalletDB.prototype.addFilter = function addFilter(data) {
  if (!this.client) {
    this.emit('add filter', data);
    return Promise.resolve();
  }

  return this.client.addFilter(data);
};

/**
 * Reset remote filter.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.resetFilter = function resetFilter() {
  if (!this.client) {
    this.emit('reset filter');
    return Promise.resolve();
  }

  return this.client.resetFilter();
};

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
  var total = 0;
  var iter, item;

  this.logger.warning('Wiping WalletDB TXDB...');
  this.logger.warning('I hope you know what you\'re doing.');

  iter = this.db.iterator({
    gte: new Buffer([0x00]),
    lte: new Buffer([0xff])
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    try {
      switch (item.key[0]) {
        case 0x62: // b
        case 0x63: // c
        case 0x65: // e
        case 0x74: // t
        case 0x6f: // o
        case 0x68: // h
        case 0x52: // R
          batch.del(item.key);
          total++;
          break;
      }
    } catch (e) {
      yield iter.end();
      throw e;
    }
  }

  this.logger.warning('Wiped %d txdb records.', total);

  yield batch.write();
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
    reverse: true,
    limit: 1
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

WalletDB.prototype.start = function start(wallet) {
  assert(!wallet.current, 'WDB: Batch already started.');
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
  assert(wallet.current, 'WDB: Batch does not exist.');
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
 * Test the bloom filter against a tx or address hash.
 * @private
 * @param {Hash} hash
 * @returns {Boolean}
 */

WalletDB.prototype.testFilter = function testFilter(data) {
  return this.filter.test(data, 'hex');
};

/**
 * Add hash to local and remote filters.
 * @private
 * @param {Hash} hash
 */

WalletDB.prototype.addHash = function addHash(hash) {
  this.filter.add(hash, 'hex');
  return this.addFilter(hash);
};

/**
 * Add outpoint to local filter.
 * @private
 * @param {Hash} hash
 * @param {Number} index
 */

WalletDB.prototype.addOutpoint = function addOutpoint(hash, index) {
  var outpoint = new Outpoint(hash, index);
  this.filter.add(outpoint.toRaw());
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
 * Map wallet id to wid.
 * @param {String} id
 * @returns {Promise} - Returns {WalletID}.
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

  if (!common.isName(id))
    throw new Error('WDB: Bad wallet ID.');

  if (yield this.has(id))
    throw new Error('WDB: ID not available.');

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

  // Remove old wid/name->account index.
  batch.del(layout.i(account.wid, account.name));

  account.name = name;

  this.saveAccount(account);
};

/**
 * Get a wallet with token auth first.
 * @param {WalletID} wid
 * @param {String|Buffer} token
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.auth = co(function* auth(wid, token) {
  var wallet = yield this.get(wid);

  if (!wallet)
    return;

  if (typeof token === 'string') {
    if (!util.isHex256(token))
      throw new Error('WDB: Authentication error.');
    token = new Buffer(token, 'hex');
  }

  // Compare in constant time:
  if (!crypto.ccmp(token, wallet.token))
    throw new Error('WDB: Authentication error.');

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
    throw new Error('WDB: Wallet already exists.');

  wallet = Wallet.fromOptions(this, options);
  wallet.wid = this.depth++;

  yield wallet.init(options);

  this.register(wallet);

  this.logger.info('Created wallet %s in WalletDB.', wallet.id);

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

WalletDB.prototype.getAccounts = function getAccounts(wid) {
  return this.db.values({
    gte: layout.n(wid, 0x00000000),
    lte: layout.n(wid, 0xffffffff),
    parse: function(data) {
      return data.toString('ascii');
    }
  });
};

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} wid
 * @param {String} name - Account name/index.
 * @returns {Promise} - Returns Number.
 */

WalletDB.prototype.getAccountIndex = co(function* getAccountIndex(wid, name) {
  var index = yield this.db.get(layout.i(wid, name));

  if (!index)
    return -1;

  return index.readUInt32LE(0, true);
});

/**
 * Lookup the corresponding account index's name.
 * @param {WalletID} wid
 * @param {Number} index
 * @returns {Promise} - Returns Number.
 */

WalletDB.prototype.getAccountName = co(function* getAccountName(wid, index) {
  var name = yield this.db.get(layout.n(wid, index));

  if (!name)
    return;

  return name.toString('ascii');
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

  // Account data
  batch.put(layout.a(wid, index), account.toRaw());

  // Name->Index lookups
  batch.put(layout.i(wid, name), U32(index));

  // Index->Name lookups
  batch.put(layout.n(wid, index), new Buffer(name, 'ascii'));

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
 * @param {Wallet} wallet
 * @param {WalletKey} ring
 * @returns {Promise}
 */

WalletDB.prototype.saveKey = function saveKey(wallet, ring) {
  return this.savePath(wallet, ring.toPath());
};

/**
 * Save a path to the path map.
 *
 * The path map exists in the form of:
 *   - `p[address-hash] -> wid map`
 *   - `P[wid][address-hash] -> path data`
 *   - `r[wid][account-index][address-hash] -> dummy`
 *
 * @param {Wallet} wallet
 * @param {Path} path
 * @returns {Promise}
 */

WalletDB.prototype.savePath = co(function* savePath(wallet, path) {
  var wid = wallet.wid;
  var hash = path.hash;
  var batch = this.batch(wallet);
  var map;

  yield this.addHash(hash);

  map = yield this.getPathMap(hash);

  if (!map)
    map = new PathMapRecord(hash);

  if (!map.add(wid))
    return;

  this.pathMapCache.set(hash, map);
  wallet.pathCache.push(hash, path);

  // Address Hash -> Wallet Map
  batch.put(layout.p(hash), map.toRaw());

  // Wallet ID + Address Hash -> Path Data
  batch.put(layout.P(wid, hash), path.toRaw());

  // Wallet ID + Account Index + Address Hash -> Dummy
  batch.put(layout.r(wid, path.account, hash), DUMMY);
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

WalletDB.prototype.hasPath = function hasPath(wid, hash) {
  return this.db.has(layout.P(wid, hash));
};

/**
 * Get all address hashes.
 * @returns {Promise}
 */

WalletDB.prototype.getHashes = function getHashes() {
  return this.db.keys({
    gte: layout.p(encoding.NULL_HASH),
    lte: layout.p(encoding.HIGH_HASH),
    parse: layout.pp
  });
};

/**
 * Get all outpoints.
 * @returns {Promise}
 */

WalletDB.prototype.getOutpoints = function getOutpoints() {
  return this.db.keys({
    gte: layout.o(encoding.NULL_HASH, 0),
    lte: layout.o(encoding.HIGH_HASH, 0xffffffff),
    parse: function(key) {
      var items = layout.oo(key);
      return new Outpoint(items[0], items[1]);
    }
  });
};

/**
 * Get all address hashes.
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.getWalletHashes = function getWalletHashes(wid) {
  return this.db.keys({
    gte: layout.P(wid, encoding.NULL_HASH),
    lte: layout.P(wid, encoding.HIGH_HASH),
    parse: layout.Pp
  });
};

/**
 * Get all account address hashes.
 * @param {WalletID} wid
 * @param {Number} account
 * @returns {Promise}
 */

WalletDB.prototype.getAccountHashes = function getAccountHashes(wid, account) {
  return this.db.keys({
    gte: layout.r(wid, account, encoding.NULL_HASH),
    lte: layout.r(wid, account, encoding.HIGH_HASH),
    parse: layout.rr
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
    gte: layout.P(wid, encoding.NULL_HASH),
    lte: layout.P(wid, encoding.HIGH_HASH)
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
 * @param {Buffer} key
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

    path = path.clone();
    path.data = crypto.encipher(path.data, key, iv);
    path.encrypted = true;

    wallet.pathCache.push(path.hash, path);

    batch.put(layout.P(wid, path.hash), path.toRaw());
  }
});

/**
 * Decrypt all imported keys for a wallet.
 * @param {WalletID} wid
 * @param {Buffer} key
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

    path = path.clone();
    path.data = crypto.decipher(path.data, key, iv);
    path.encrypted = false;

    wallet.pathCache.push(path.hash, path);

    batch.put(layout.P(wid, path.hash), path.toRaw());
  }
});

/**
 * Resend all pending transactions.
 * @returns {Promise}
 */

WalletDB.prototype.resend = co(function* resend() {
  var i, keys, key, wid;

  keys = yield this.db.keys({
    gte: layout.w(0x00000000),
    lte: layout.w(0xffffffff)
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    wid = layout.ww(key);
    yield this.resendPending(wid);
  }
});

/**
 * Resend all pending transactions for a specific wallet.
 * @private
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.resendPending = co(function* resendPending(wid) {
  var layout = layouts.txdb;
  var txs = [];
  var i, key, keys, hash, data, wtx, tx;

  keys = yield this.db.keys({
    gte: layout.prefix(wid, layout.p(encoding.NULL_HASH)),
    lte: layout.prefix(wid, layout.p(encoding.HIGH_HASH))
  });

  if (keys.length === 0)
    return;

  this.logger.info(
    'Rebroadcasting %d transactions for %d.',
    keys.length,
    wid);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];

    hash = layout.pp(key);
    key = layout.prefix(wid, layout.t(hash));

    data = yield this.db.get(key);

    if (!data)
      continue;

    wtx = TXRecord.fromRaw(data);

    if (wtx.tx.isCoinbase())
      continue;

    txs.push(wtx.tx);
  }

  txs = common.sortDeps(txs);

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    yield this.send(tx);
  }
});

/**
 * Get all wallet ids by output addresses and outpoints.
 * @param {Hash[]} hashes
 * @returns {Promise}
 */

WalletDB.prototype.getWalletsByTX = co(function* getWalletsByTX(tx) {
  var hashes = tx.getOutputHashes('hex');
  var result = [];
  var i, j, input, prevout, hash, map;

  if (!tx.isCoinbase()) {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;

      if (!this.testFilter(prevout.toRaw()))
        continue;

      map = yield this.getOutpointMap(prevout.hash, prevout.index);

      if (!map)
        continue;

      for (j = 0; j < map.wids.length; j++)
        util.binaryInsert(result, map.wids[j], cmp, true);
    }
  }

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (!this.testFilter(hash))
      continue;

    map = yield this.getPathMap(hash);

    if (!map)
      continue;

    for (j = 0; j < map.wids.length; j++)
      util.binaryInsert(result, map.wids[j], cmp, true);
  }

  if (result.length === 0)
    return;

  return result;
});

/**
 * Get the best block hash.
 * @returns {Promise}
 */

WalletDB.prototype.getState = co(function* getState() {
  var data = yield this.db.get(layout.R);

  if (!data)
    return;

  return ChainState.fromRaw(data);
});

/**
 * Reset the chain state to a tip/start-block.
 * @param {BlockMeta} tip
 * @returns {Promise}
 */

WalletDB.prototype.resetState = co(function* resetState(tip, marked) {
  var batch = this.db.batch();
  var state = this.state.clone();
  var iter, item;

  iter = this.db.iterator({
    gte: layout.h(0),
    lte: layout.h(0xffffffff),
    values: false
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    try {
      batch.del(item.key);
    } catch (e) {
      yield iter.end();
      throw e;
    }
  }

  state.startHeight = tip.height;
  state.startHash = tip.hash;
  state.height = tip.height;
  state.marked = marked;

  batch.put(layout.h(tip.height), tip.toHash());
  batch.put(layout.R, state.toRaw());

  yield batch.write();

  this.state = state;
});

/**
 * Sync the current chain state to tip.
 * @param {BlockMeta} tip
 * @returns {Promise}
 */

WalletDB.prototype.syncState = co(function* syncState(tip) {
  var batch = this.db.batch();
  var state = this.state.clone();
  var i, height, blocks;

  if (tip.height < state.height) {
    // Hashes ahead of our new tip
    // that we need to delete.
    height = state.height;
    blocks = height - tip.height;

    if (blocks > this.options.keepBlocks)
      blocks = this.options.keepBlocks;

    for (i = 0; i < blocks; i++) {
      batch.del(layout.h(height));
      height--;
    }
  } else if (tip.height > state.height) {
    // Prune old hashes.
    assert(tip.height === state.height + 1, 'Bad chain sync.');

    height = tip.height - this.options.keepBlocks;

    if (height >= 0)
      batch.del(layout.h(height));
  }

  state.height = tip.height;

  // Save tip and state.
  batch.put(layout.h(tip.height), tip.toHash());
  batch.put(layout.R, state.toRaw());

  yield batch.write();

  this.state = state;
});

/**
 * Mark the start block once a confirmed tx is seen.
 * @param {BlockMeta} tip
 * @returns {Promise}
 */

WalletDB.prototype.maybeMark = co(function* maybeMark(tip) {
  if (this.state.marked)
    return;

  this.logger.info('Marking WalletDB start block at %s (%d).',
    util.revHex(tip.hash), tip.height);

  yield this.resetState(tip, true);
});

/**
 * Get a block->wallet map.
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.getBlockMap = co(function* getBlockMap(height) {
  var data = yield this.db.get(layout.b(height));

  if (!data)
    return;

  return BlockMapRecord.fromRaw(height, data);
});

/**
 * Add block to the global block map.
 * @param {Wallet} wallet
 * @param {Number} height
 * @param {BlockMapRecord} block
 */

WalletDB.prototype.writeBlockMap = function writeBlockMap(wallet, height, block) {
  var batch = this.batch(wallet);
  batch.put(layout.b(height), block.toRaw());
};

/**
 * Remove a block from the global block map.
 * @param {Wallet} wallet
 * @param {Number} height
 */

WalletDB.prototype.unwriteBlockMap = function unwriteBlockMap(wallet, height) {
  var batch = this.batch(wallet);
  batch.del(layout.b(height));
};

/**
 * Get a Unspent->Wallet map.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise}
 */

WalletDB.prototype.getOutpointMap = co(function* getOutpointMap(hash, index) {
  var data = yield this.db.get(layout.o(hash, index));

  if (!data)
    return;

  return OutpointMapRecord.fromRaw(hash, index, data);
});

/**
 * Add an outpoint to global unspent map.
 * @param {Wallet} wallet
 * @param {Hash} hash
 * @param {Number} index
 * @param {OutpointMapRecord} map
 */

WalletDB.prototype.writeOutpointMap = function writeOutpointMap(wallet, hash, index, map) {
  var batch = this.batch(wallet);

  this.addOutpoint(hash, index);

  batch.put(layout.o(hash, index), map.toRaw());
};

/**
 * Remove an outpoint from global unspent map.
 * @param {Wallet} wallet
 * @param {Hash} hash
 * @param {Number} index
 */

WalletDB.prototype.unwriteOutpointMap = function unwriteOutpointMap(wallet, hash, index) {
  var batch = this.batch(wallet);
  batch.del(layout.o(hash, index));
};

/**
 * Get a wallet block meta.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getBlock = co(function* getBlock(height) {
  var data = yield this.db.get(layout.h(height));
  var block;

  if (!data)
    return;

  block = new BlockMeta();
  block.hash = data.toString('hex');
  block.height = height;

  return block;
});

/**
 * Get wallet tip.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getTip = co(function* getTip() {
  var tip = yield this.getBlock(this.state.height);

  if (!tip)
    throw new Error('WDB: Tip not found!');

  return tip;
});

/**
 * Sync with chain height.
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.rollback = co(function* rollback(height) {
  var tip, marked;

  if (height > this.state.height)
    throw new Error('WDB: Cannot rollback to the future.');

  if (height === this.state.height) {
    this.logger.debug('Rolled back to same height (%d).', height);
    return true;
  }

  this.logger.info(
    'Rolling back %d WalletDB blocks to height %d.',
    this.state.height - height, height);

  tip = yield this.getBlock(height);

  if (tip) {
    yield this.revert(tip.height);
    yield this.syncState(tip);
    return true;
  }

  tip = new BlockMeta();

  if (height >= this.state.startHeight) {
    tip.height = this.state.startHeight;
    tip.hash = this.state.startHash;
    marked = this.state.marked;

    this.logger.warning(
      'Rolling back WalletDB to start block (%d).',
      tip.height);
  } else {
    tip.height = 0;
    tip.hash = this.network.genesis.hash;
    marked = false;

    this.logger.warning('Rolling back WalletDB to genesis block.');
  }

  yield this.revert(tip.height);
  yield this.resetState(tip, marked);

  return false;
});

/**
 * Revert TXDB to an older state.
 * @param {Number} target
 * @returns {Promise}
 */

WalletDB.prototype.revert = co(function* revert(target) {
  var total = 0;
  var i, iter, item, height, block, tx;

  iter = this.db.iterator({
    gte: layout.b(target + 1),
    lte: layout.b(0xffffffff),
    reverse: true,
    values: true
  });

  for (;;) {
    item = yield iter.next();

    if (!item)
      break;

    try {
      height = layout.bb(item.key);
      block = BlockMapRecord.fromRaw(height, item.value);
      total += block.txs.length;

      for (i = block.txs.length - 1; i >= 0; i--) {
        tx = block.txs[i];
        yield this._unconfirm(tx);
      }
    } catch (e) {
      yield iter.end();
      throw e;
    }
  }

  this.logger.info('Rolled back %d WalletDB transactions.', total);
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
 * @param {TX[]} txs
 * @returns {Promise}
 */

WalletDB.prototype._addBlock = co(function* addBlock(entry, txs) {
  var tip = BlockMeta.fromEntry(entry);
  var total = 0;
  var i, tx;

  if (tip.height < this.state.height) {
    this.logger.warning(
      'WalletDB is connecting low blocks (%d).',
      tip.height);
    return total;
  }

  if (tip.height === this.state.height) {
    // We let blocks of the same height
    // through specifically for rescans:
    // we always want to rescan the last
    // block since the state may have
    // updated before the block was fully
    // processed (in the case of a crash).
    this.logger.warning('Already saw WalletDB block (%d).', tip.height);
  } else if (tip.height !== this.state.height + 1) {
    throw new Error('WDB: Bad connection (height mismatch).');
  }

  // Sync the state to the new tip.
  yield this.syncState(tip);

  if (this.options.checkpoints) {
    if (tip.height <= this.network.lastCheckpoint)
      return total;
  }

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    if (yield this._insert(tx, tip))
      total++;
  }

  if (total > 0) {
    this.logger.info('Connected WalletDB block %s (tx=%d).',
      util.revHex(tip.hash), total);
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
  var tip = BlockMeta.fromEntry(entry);
  var i, tx, prev, block;

  if (tip.height > this.state.height) {
    this.logger.warning(
      'WalletDB is disconnecting high blocks (%d).',
      tip.height);
    return 0;
  }

  if (tip.height !== this.state.height)
    throw new Error('WDB: Bad disconnection (height mismatch).');

  prev = yield this.getBlock(tip.height - 1);

  if (!prev)
    throw new Error('WDB: Bad disconnection (no previous block).');

  // Get the map of txids->wids.
  block = yield this.getBlockMap(tip.height);

  if (!block) {
    yield this.syncState(prev);
    return 0;
  }

  for (i = block.txs.length - 1; i >= 0; i--) {
    tx = block.txs[i];
    yield this._unconfirm(tx);
  }

  // Sync the state to the previous tip.
  yield this.syncState(prev);

  this.logger.warning('Disconnected wallet block %s (tx=%d).',
    util.revHex(tip.hash), block.txs.length);

  return block.txs.length;
});

/**
 * Rescan a block.
 * @private
 * @param {ChainEntry} entry
 * @param {TX[]} txs
 * @returns {Promise}
 */

WalletDB.prototype.rescanBlock = co(function* rescanBlock(entry, txs) {
  if (!this.rescanning) {
    this.logger.warning('Unsolicited rescan block: %s.', entry.height);
    return;
  }

  try {
    yield this._addBlock(entry, txs);
  } catch (e) {
    this.emit('error', e);
    throw e;
  }
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

  try {
    return yield this._insert(tx);
  } finally {
    unlock();
  }
});

/**
 * Add a transaction to the database without a lock.
 * @private
 * @param {TX} tx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

WalletDB.prototype._insert = co(function* insert(tx, block) {
  var result = false;
  var i, wids, wid, wallet;

  assert(!tx.mutable, 'WDB: Cannot add mutable TX.');

  wids = yield this.getWalletsByTX(tx);

  if (!wids)
    return;

  this.logger.info(
    'Incoming transaction for %d wallets in WalletDB (%s).',
    wids.length, tx.txid());

  // If this is our first transaction
  // in a block, set the start block here.
  if (block)
    yield this.maybeMark(block);

  // Insert the transaction
  // into every matching wallet.
  for (i = 0; i < wids.length; i++) {
    wid = wids[i];
    wallet = yield this.get(wid);

    assert(wallet);

    if (yield wallet.add(tx, block)) {
      this.logger.info(
        'Added transaction to wallet in WalletDB: %s (%d).',
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
 * @param {TXMapRecord} tx
 * @returns {Promise}
 */

WalletDB.prototype._unconfirm = co(function* unconfirm(tx) {
  var i, wid, wallet;

  for (i = 0; i < tx.wids.length; i++) {
    wid = tx.wids[i];
    wallet = yield this.get(wid);
    assert(wallet);
    yield wallet.unconfirm(tx.hash);
  }
});

/**
 * Handle a chain reset.
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype.resetChain = co(function* resetChain(entry) {
  var unlock = yield this.txLock.lock();
  try {
    return yield this._resetChain(entry);
  } finally {
    unlock();
  }
});

/**
 * Handle a chain reset without a lock.
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype._resetChain = co(function* resetChain(entry) {
  if (entry.height > this.state.height)
    throw new Error('WDB: Bad reset height.');

  // Try to rollback.
  if (yield this.rollback(entry.height))
    return;

  // If we rolled back to the
  // start block, we need a rescan.
  yield this.scan();
});

/**
 * WalletOptions
 * @alias module:wallet.WalletOptions
 * @constructor
 * @param {Object} options
 */

function WalletOptions(options) {
  if (!(this instanceof WalletOptions))
    return new WalletOptions(options);

  this.network = Network.primary;
  this.logger = Logger.global;
  this.client = null;

  this.prefix = null;
  this.location = null;
  this.db = 'memory';
  this.maxFiles = 64;
  this.cacheSize = 16 << 20;
  this.compression = true;
  this.bufferKeys = layout.binary;

  this.spv = false;
  this.witness = false;
  this.checkpoints = false;
  this.startHeight = 0;
  this.keepBlocks = this.network.block.keepBlocks;
  this.wipeNoReally = false;
  this.apiKey = null;
  this.walletAuth = false;
  this.noAuth = false;
  this.ssl = false;
  this.host = '127.0.0.1';
  this.port = this.network.rpcPort + 2;
  this.listen = false;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {WalletOptions}
 */

WalletOptions.prototype.fromOptions = function fromOptions(options) {
  if (options.network != null) {
    this.network = Network.get(options.network);
    this.keepBlocks = this.network.block.keepBlocks;
    this.port = this.network.rpcPort + 2;
  }

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.client != null) {
    assert(typeof options.client === 'object');
    this.client = options.client;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = options.prefix;
    this.location = this.prefix + '/walletdb';
  }

  if (options.location != null) {
    assert(typeof options.location === 'string');
    this.location = options.location;
  }

  if (options.db != null) {
    assert(typeof options.db === 'string');
    this.db = options.db;
  }

  if (options.maxFiles != null) {
    assert(util.isNumber(options.maxFiles));
    this.maxFiles = options.maxFiles;
  }

  if (options.cacheSize != null) {
    assert(util.isNumber(options.cacheSize));
    this.cacheSize = options.cacheSize;
  }

  if (options.compression != null) {
    assert(typeof options.compression === 'boolean');
    this.compression = options.compression;
  }

  if (options.spv != null) {
    assert(typeof options.spv === 'boolean');
    this.spv = options.spv;
  }

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
  }

  if (options.checkpoints != null) {
    assert(typeof options.checkpoints === 'boolean');
    this.checkpoints = options.checkpoints;
  }

  if (options.startHeight != null) {
    assert(typeof options.startHeight === 'number');
    assert(options.startHeight >= 0);
    this.startHeight = options.startHeight;
  }

  if (options.wipeNoReally != null) {
    assert(typeof options.wipeNoReally === 'boolean');
    this.wipeNoReally = options.wipeNoReally;
  }

  if (options.apiKey != null) {
    assert(typeof options.apiKey === 'string');
    this.apiKey = options.apiKey;
  }

  if (options.walletAuth != null) {
    assert(typeof options.walletAuth === 'boolean');
    this.walletAuth = options.walletAuth;
  }

  if (options.noAuth != null) {
    assert(typeof options.noAuth === 'boolean');
    this.noAuth = options.noAuth;
  }

  if (options.ssl != null) {
    assert(typeof options.ssl === 'boolean');
    this.ssl = options.ssl;
  }

  if (options.host != null) {
    assert(typeof options.host === 'string');
    this.host = options.host;
  }

  if (options.port != null) {
    assert(typeof options.port === 'number');
    this.port = options.port;
  }

  if (options.listen != null) {
    assert(typeof options.listen === 'boolean');
    this.listen = options.listen;
  }

  return this;
};

/**
 * Instantiate chain options from object.
 * @param {Object} options
 * @returns {WalletOptions}
 */

WalletOptions.fromOptions = function fromOptions(options) {
  return new WalletOptions().fromOptions(options);
};

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
