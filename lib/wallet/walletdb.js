/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const AsyncObject = require('../utils/asyncobject');
const util = require('../utils/util');
const Lock = require('../utils/lock');
const MappedLock = require('../utils/mappedlock');
const LRU = require('../utils/lru');
const encoding = require('../utils/encoding');
const ccmp = require('../crypto/ccmp');
const aes = require('../crypto/aes');
const Network = require('../protocol/network');
const Path = require('./path');
const common = require('./common');
const Wallet = require('./wallet');
const Account = require('./account');
const LDB = require('../db/ldb');
const Bloom = require('../utils/bloom');
const Logger = require('../node/logger');
const Outpoint = require('../primitives/outpoint');
const layouts = require('./layout');
const records = require('./records');
const HTTPServer = require('./http');
const RPC = require('./rpc');
const layout = layouts.walletdb;
const ChainState = records.ChainState;
const BlockMapRecord = records.BlockMapRecord;
const BlockMeta = records.BlockMeta;
const PathMapRecord = records.PathMapRecord;
const OutpointMapRecord = records.OutpointMapRecord;
const TXRecord = records.TXRecord;
const U32 = encoding.U32;

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
  this.wallets = new Map();
  this.depth = 0;
  this.rescanning = false;
  this.bound = false;

  this.readLock = new MappedLock();
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
  let items = 1000000;
  let flag = -1;

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

WalletDB.prototype._open = async function open() {
  let wallet;

  if (this.options.listen)
    await this.logger.open();

  await this.db.open();
  await this.db.checkVersion('V', 6);

  this.depth = await this.getDepth();

  if (this.options.wipeNoReally)
    await this.wipe();

  await this.load();

  this.logger.info(
    'WalletDB loaded (depth=%d, height=%d, start=%d).',
    this.depth,
    this.state.height,
    this.state.startHeight);

  wallet = await this.ensure({
    id: 'primary'
  });

  this.logger.info(
    'Loaded primary wallet (id=%s, wid=%d, address=%s)',
    wallet.id, wallet.wid, wallet.getAddress());

  this.primary = wallet;
  this.rpc.wallet = wallet;

  if (this.http && this.options.listen)
    await this.http.open();
};

/**
 * Close the walletdb, wait for the database to close.
 * @alias WalletDB#close
 * @returns {Promise}
 */

WalletDB.prototype._close = async function close() {
  let wallet;

  await this.disconnect();

  if (this.http && this.options.listen)
    await this.http.close();

  for (wallet of this.wallets.values())
    await wallet.destroy();

  await this.db.close();

  if (this.options.listen)
    await this.logger.close();
};

/**
 * Load the walletdb.
 * @returns {Promise}
 */

WalletDB.prototype.load = async function load() {
  let unlock = await this.txLock.lock();
  try {
    await this.connect();
    await this.init();
    await this.watch();
    await this.sync();
    await this.resend();
  } finally {
    unlock();
  }
};

/**
 * Bind to node events.
 * @private
 */

WalletDB.prototype.bind = function bind() {
  if (!this.client)
    return;

  if (this.bound)
    return;

  this.bound = true;

  this.client.on('error', (err) => {
    this.emit('error', err);
  });

  this.client.on('block connect', async (entry, txs) => {
    try {
      await this.addBlock(entry, txs);
    } catch (e) {
      this.emit('error', e);
    }
  });

  this.client.on('block disconnect', async (entry) => {
    try {
      await this.removeBlock(entry);
    } catch (e) {
      this.emit('error', e);
    }
  });

  this.client.hook('block rescan', async (entry, txs) => {
    try {
      await this.rescanBlock(entry, txs);
    } catch (e) {
      this.emit('error', e);
    }
  });

  this.client.on('tx', async (tx) => {
    try {
      await this.addTX(tx);
    } catch (e) {
      this.emit('error', e);
    }
  });

  this.client.on('chain reset', async (tip) => {
    try {
      await this.resetChain(tip);
    } catch (e) {
      this.emit('error', e);
    }
  });
};

/**
 * Connect to the node server (client required).
 * @returns {Promise}
 */

WalletDB.prototype.connect = async function connect() {
  if (!this.client)
    return;

  this.bind();

  await this.client.open();
  await this.setFilter();
};

/**
 * Disconnect from node server (client required).
 * @returns {Promise}
 */

WalletDB.prototype.disconnect = async function disconnect() {
  if (!this.client)
    return;

  await this.client.close();
};

/**
 * Initialize and write initial sync state.
 * @returns {Promise}
 */

WalletDB.prototype.init = async function init() {
  let state = await this.getState();
  let startHeight = this.options.startHeight;
  let tip;

  if (state) {
    this.state = state;
    return;
  }

  if (this.client) {
    if (startHeight != null) {
      tip = await this.client.getEntry(startHeight);
      if (!tip)
        throw new Error('WDB: Could not find start block.');
    } else {
      tip = await this.client.getTip();
    }
    tip = BlockMeta.fromEntry(tip);
  } else {
    tip = BlockMeta.fromEntry(this.network.genesis);
  }

  this.logger.info(
    'Initializing WalletDB chain state at %s (%d).',
    util.revHex(tip.hash), tip.height);

  await this.resetState(tip, false);
};

/**
 * Watch addresses and outpoints.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.watch = async function watch() {
  let hashes = 0;
  let outpoints = 0;
  let iter;

  iter = this.db.iterator({
    gte: layout.p(encoding.NULL_HASH),
    lte: layout.p(encoding.HIGH_HASH)
  });

  for (;;) {
    let item = await iter.next();

    if (!item)
      break;

    try {
      let data = layout.pp(item.key);
      this.filter.add(data, 'hex');
    } catch (e) {
      await iter.end();
      throw e;
    }

    hashes++;
  }

  iter = this.db.iterator({
    gte: layout.o(encoding.NULL_HASH, 0),
    lte: layout.o(encoding.HIGH_HASH, 0xffffffff)
  });

  for (;;) {
    let item = await iter.next();

    if (!item)
      break;

    try {
      let [hash, index] = layout.oo(item.key);
      let outpoint = new Outpoint(hash, index);
      let data = outpoint.toRaw();
      this.filter.add(data);
    } catch (e) {
      await iter.end();
      throw e;
    }

    outpoints++;
  }

  this.logger.info('Added %d hashes to WalletDB filter.', hashes);
  this.logger.info('Added %d outpoints to WalletDB filter.', outpoints);

  await this.setFilter();
};

/**
 * Connect and sync with the chain server.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.sync = async function sync() {
  let height = this.state.height;
  let entry;

  if (!this.client)
    return;

  while (height >= 0) {
    let tip = await this.getBlock(height);

    if (!tip)
      break;

    entry = await this.client.getEntry(tip.hash);

    if (entry)
      break;

    height--;
  }

  if (!entry) {
    height = this.state.startHeight;
    entry = await this.client.getEntry(this.state.startHash);

    if (!entry)
      height = 0;
  }

  await this.scan(height);
};

/**
 * Rescan blockchain from a given height.
 * @private
 * @param {Number?} height
 * @returns {Promise}
 */

WalletDB.prototype.scan = async function scan(height) {
  let tip;

  if (!this.client)
    return;

  if (height == null)
    height = this.state.startHeight;

  assert(util.isUInt32(height), 'WDB: Must pass in a height.');

  await this.rollback(height);

  this.logger.info(
    'WalletDB is scanning %d blocks.',
    this.state.height - height + 1);

  tip = await this.getTip();

  try {
    this.rescanning = true;
    await this.client.rescan(tip.hash);
  } finally {
    this.rescanning = false;
  }
};

/**
 * Force a rescan.
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.rescan = async function rescan(height) {
  let unlock = await this.txLock.lock();
  try {
    return await this._rescan(height);
  } finally {
    unlock();
  }
};

/**
 * Force a rescan (without a lock).
 * @private
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype._rescan = async function rescan(height) {
  return await this.scan(height);
};

/**
 * Broadcast a transaction via chain server.
 * @param {TX} tx
 * @returns {Promise}
 */

WalletDB.prototype.send = async function send(tx) {
  if (!this.client) {
    this.emit('send', tx);
    return;
  }

  await this.client.send(tx);
};

/**
 * Estimate smart fee from chain server.
 * @param {Number} blocks
 * @returns {Promise}
 */

WalletDB.prototype.estimateFee = async function estimateFee(blocks) {
  let rate;

  if (!this.client)
    return this.network.feeRate;

  rate = await this.client.estimateFee(blocks);

  if (rate < this.network.feeRate)
    return this.network.feeRate;

  if (rate > this.network.maxFeeRate)
    return this.network.maxFeeRate;

  return rate;
};

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

WalletDB.prototype.wipe = async function wipe() {
  let batch = this.db.batch();
  let total = 0;
  let iter;

  this.logger.warning('Wiping WalletDB TXDB...');
  this.logger.warning('I hope you know what you\'re doing.');

  iter = this.db.iterator({
    gte: Buffer.from([0x00]),
    lte: Buffer.from([0xff])
  });

  for (;;) {
    let item = await iter.next();

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
      await iter.end();
      throw e;
    }
  }

  this.logger.warning('Wiped %d txdb records.', total);

  await batch.write();
};

/**
 * Get current wallet wid depth.
 * @private
 * @returns {Promise}
 */

WalletDB.prototype.getDepth = async function getDepth() {
  let iter, item, depth;

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

  item = await iter.next();

  if (!item)
    return 1;

  await iter.end();

  depth = layout.ww(item.key);

  return depth + 1;
};

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
  let batch = this.batch(wallet);
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
  let batch = this.batch(wallet);
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

WalletDB.prototype.commit = async function commit(wallet) {
  let batch = this.batch(wallet);

  try {
    await batch.write();
  } catch (e) {
    wallet.current = null;
    wallet.accountCache.drop();
    wallet.pathCache.drop();
    throw e;
  }

  wallet.current = null;
  wallet.accountCache.commit();
  wallet.pathCache.commit();
};

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
  let outpoint = new Outpoint(hash, index);
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
  assert(!this.wallets.has(wallet.wid));
  this.wallets.set(wallet.wid, wallet);
};

/**
 * Unregister a object with the walletdb.
 * @param {Object} object
 * @returns {Boolean}
 */

WalletDB.prototype.unregister = function unregister(wallet) {
  assert(this.wallets.has(wallet.wid));
  this.wallets.delete(wallet.wid);
};

/**
 * Map wallet id to wid.
 * @param {String} id
 * @returns {Promise} - Returns {WalletID}.
 */

WalletDB.prototype.getWalletID = async function getWalletID(id) {
  let wid, data;

  if (!id)
    return;

  if (typeof id === 'number')
    return id;

  wid = this.widCache.get(id);

  if (wid)
    return wid;

  data = await this.db.get(layout.l(id));

  if (!data)
    return;

  wid = data.readUInt32LE(0, true);

  this.widCache.set(id, wid);

  return wid;
};

/**
 * Get a wallet from the database, setup watcher.
 * @param {WalletID} wid
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.get = async function get(id) {
  let wid = await this.getWalletID(id);
  let unlock;

  if (!wid)
    return;

  unlock = await this.readLock.lock(wid);

  try {
    return await this._get(wid);
  } finally {
    unlock();
  }
};

/**
 * Get a wallet from the database without a lock.
 * @private
 * @param {WalletID} wid
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype._get = async function get(wid) {
  let wallet = this.wallets.get(wid);
  let data;

  if (wallet)
    return wallet;

  data = await this.db.get(layout.w(wid));

  if (!data)
    return;

  wallet = Wallet.fromRaw(this, data);

  await wallet.open();

  this.register(wallet);

  return wallet;
};

/**
 * Save a wallet to the database.
 * @param {Wallet} wallet
 */

WalletDB.prototype.save = function save(wallet) {
  let wid = wallet.wid;
  let id = wallet.id;
  let batch = this.batch(wallet);

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

WalletDB.prototype.rename = async function rename(wallet, id) {
  let unlock = await this.writeLock.lock();
  try {
    return await this._rename(wallet, id);
  } finally {
    unlock();
  }
};

/**
 * Rename a wallet without a lock.
 * @private
 * @param {Wallet} wallet
 * @param {String} id
 * @returns {Promise}
 */

WalletDB.prototype._rename = async function _rename(wallet, id) {
  let old = wallet.id;
  let paths, batch;

  if (!common.isName(id))
    throw new Error('WDB: Bad wallet ID.');

  if (await this.has(id))
    throw new Error('WDB: ID not available.');

  batch = this.start(wallet);
  batch.del(layout.l(old));

  wallet.id = id;

  this.save(wallet);

  await this.commit(wallet);

  this.widCache.remove(old);

  paths = wallet.pathCache.values();

  for (let path of paths)
    path.id = id;
};

/**
 * Rename an account.
 * @param {Account} account
 * @param {String} name
 */

WalletDB.prototype.renameAccount = function renameAccount(account, name) {
  let wallet = account.wallet;
  let batch = this.batch(wallet);

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

WalletDB.prototype.auth = async function auth(wid, token) {
  let wallet = await this.get(wid);

  if (!wallet)
    return;

  if (typeof token === 'string') {
    if (!util.isHex256(token))
      throw new Error('WDB: Authentication error.');
    token = Buffer.from(token, 'hex');
  }

  // Compare in constant time:
  if (!ccmp(token, wallet.token))
    throw new Error('WDB: Authentication error.');

  return wallet;
};

/**
 * Create a new wallet, save to database, setup watcher.
 * @param {Object} options - See {@link Wallet}.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.create = async function create(options) {
  let unlock = await this.writeLock.lock();

  if (!options)
    options = {};

  try {
    return await this._create(options);
  } finally {
    unlock();
  }
};

/**
 * Create a new wallet, save to database without a lock.
 * @private
 * @param {Object} options - See {@link Wallet}.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype._create = async function create(options) {
  let exists = await this.has(options.id);
  let wallet;

  if (exists)
    throw new Error('WDB: Wallet already exists.');

  wallet = Wallet.fromOptions(this, options);
  wallet.wid = this.depth++;

  await wallet.init(options);

  this.register(wallet);

  this.logger.info('Created wallet %s in WalletDB.', wallet.id);

  return wallet;
};

/**
 * Test for the existence of a wallet.
 * @param {WalletID} id
 * @returns {Promise}
 */

WalletDB.prototype.has = async function has(id) {
  let wid = await this.getWalletID(id);
  return wid != null;
};

/**
 * Attempt to create wallet, return wallet if already exists.
 * @param {Object} options - See {@link Wallet}.
 * @returns {Promise}
 */

WalletDB.prototype.ensure = async function ensure(options) {
  let wallet = await this.get(options.id);
  if (wallet)
    return wallet;
  return await this.create(options);
};

/**
 * Get an account from the database by wid.
 * @private
 * @param {WalletID} wid
 * @param {Number} index - Account index.
 * @returns {Promise} - Returns {@link Wallet}.
 */

WalletDB.prototype.getAccount = async function getAccount(wid, index) {
  let data = await this.db.get(layout.a(wid, index));

  if (!data)
    return;

  return Account.fromRaw(this, data);
};

/**
 * List account names and indexes from the db.
 * @param {WalletID} wid
 * @returns {Promise} - Returns Array.
 */

WalletDB.prototype.getAccounts = function getAccounts(wid) {
  return this.db.values({
    gte: layout.n(wid, 0x00000000),
    lte: layout.n(wid, 0xffffffff),
    parse: data => data.toString('ascii')
  });
};

/**
 * Lookup the corresponding account name's index.
 * @param {WalletID} wid
 * @param {String} name - Account name/index.
 * @returns {Promise} - Returns Number.
 */

WalletDB.prototype.getAccountIndex = async function getAccountIndex(wid, name) {
  let index = await this.db.get(layout.i(wid, name));

  if (!index)
    return -1;

  return index.readUInt32LE(0, true);
};

/**
 * Lookup the corresponding account index's name.
 * @param {WalletID} wid
 * @param {Number} index
 * @returns {Promise} - Returns Number.
 */

WalletDB.prototype.getAccountName = async function getAccountName(wid, index) {
  let name = await this.db.get(layout.n(wid, index));

  if (!name)
    return;

  return name.toString('ascii');
};

/**
 * Save an account to the database.
 * @param {Account} account
 * @returns {Promise}
 */

WalletDB.prototype.saveAccount = function saveAccount(account) {
  let wid = account.wid;
  let wallet = account.wallet;
  let index = account.accountIndex;
  let name = account.name;
  let batch = this.batch(wallet);

  // Account data
  batch.put(layout.a(wid, index), account.toRaw());

  // Name->Index lookups
  batch.put(layout.i(wid, name), U32(index));

  // Index->Name lookups
  batch.put(layout.n(wid, index), Buffer.from(name, 'ascii'));

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

WalletDB.prototype.getPathMap = async function getPathMap(hash) {
  let map = this.pathMapCache.get(hash);
  let data;

  if (map)
    return map;

  data = await this.db.get(layout.p(hash));

  if (!data)
    return;

  map = PathMapRecord.fromRaw(hash, data);

  this.pathMapCache.set(hash, map);

  return map;
};

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

WalletDB.prototype.savePath = async function savePath(wallet, path) {
  let wid = wallet.wid;
  let hash = path.hash;
  let batch = this.batch(wallet);
  let map;

  await this.addHash(hash);

  map = await this.getPathMap(hash);

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
  batch.put(layout.r(wid, path.account, hash), null);
};

/**
 * Retrieve path by hash.
 * @param {WalletID} wid
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getPath = async function getPath(wid, hash) {
  let data = await this.db.get(layout.P(wid, hash));
  let path;

  if (!data)
    return;

  path = Path.fromRaw(data);
  path.wid = wid;
  path.hash = hash;

  return path;
};

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
    parse: (key) => {
      let [hash, index] = layout.oo(key);
      return new Outpoint(hash, index);
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

WalletDB.prototype.getWalletPaths = async function getWalletPaths(wid) {
  let paths = [];

  let items = await this.db.range({
    gte: layout.P(wid, encoding.NULL_HASH),
    lte: layout.P(wid, encoding.HIGH_HASH)
  });

  for (let item of items) {
    let hash = layout.Pp(item.key);
    let path = Path.fromRaw(item.value);

    path.hash = hash;
    path.wid = wid;

    paths.push(path);
  }

  return paths;
};

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

WalletDB.prototype.encryptKeys = async function encryptKeys(wallet, key) {
  let wid = wallet.wid;
  let paths = await wallet.getPaths();
  let batch = this.batch(wallet);

  for (let path of paths) {
    let iv;

    if (!path.data)
      continue;

    assert(!path.encrypted);

    iv = Buffer.from(path.hash, 'hex');
    iv = iv.slice(0, 16);

    path = path.clone();
    path.data = aes.encipher(path.data, key, iv);
    path.encrypted = true;

    wallet.pathCache.push(path.hash, path);

    batch.put(layout.P(wid, path.hash), path.toRaw());
  }
};

/**
 * Decrypt all imported keys for a wallet.
 * @param {WalletID} wid
 * @param {Buffer} key
 * @returns {Promise}
 */

WalletDB.prototype.decryptKeys = async function decryptKeys(wallet, key) {
  let wid = wallet.wid;
  let paths = await wallet.getPaths();
  let batch = this.batch(wallet);

  for (let path of paths) {
    let iv;

    if (!path.data)
      continue;

    assert(path.encrypted);

    iv = Buffer.from(path.hash, 'hex');
    iv = iv.slice(0, 16);

    path = path.clone();
    path.data = aes.decipher(path.data, key, iv);
    path.encrypted = false;

    wallet.pathCache.push(path.hash, path);

    batch.put(layout.P(wid, path.hash), path.toRaw());
  }
};

/**
 * Resend all pending transactions.
 * @returns {Promise}
 */

WalletDB.prototype.resend = async function resend() {
  let keys, key, wid;

  keys = await this.db.keys({
    gte: layout.w(0x00000000),
    lte: layout.w(0xffffffff)
  });

  for (key of keys) {
    wid = layout.ww(key);
    await this.resendPending(wid);
  }
};

/**
 * Resend all pending transactions for a specific wallet.
 * @private
 * @param {WalletID} wid
 * @returns {Promise}
 */

WalletDB.prototype.resendPending = async function resendPending(wid) {
  let layout = layouts.txdb;
  let txs = [];
  let keys;

  keys = await this.db.keys({
    gte: layout.prefix(wid, layout.p(encoding.NULL_HASH)),
    lte: layout.prefix(wid, layout.p(encoding.HIGH_HASH))
  });

  if (keys.length === 0)
    return;

  this.logger.info(
    'Rebroadcasting %d transactions for %d.',
    keys.length,
    wid);

  for (let key of keys) {
    let hash = layout.pp(key);
    let tkey = layout.prefix(wid, layout.t(hash));
    let data = await this.db.get(tkey);
    let wtx;

    if (!data)
      continue;

    wtx = TXRecord.fromRaw(data);

    if (wtx.tx.isCoinbase())
      continue;

    txs.push(wtx.tx);
  }

  txs = common.sortDeps(txs);

  for (let tx of txs)
    await this.send(tx);
};

/**
 * Get all wallet ids by output addresses and outpoints.
 * @param {Hash[]} hashes
 * @returns {Promise}
 */

WalletDB.prototype.getWalletsByTX = async function getWalletsByTX(tx) {
  let hashes = tx.getOutputHashes('hex');
  let result = [];

  if (!tx.isCoinbase()) {
    for (let input of tx.inputs) {
      let prevout = input.prevout;
      let map;

      if (!this.testFilter(prevout.toRaw()))
        continue;

      map = await this.getOutpointMap(prevout.hash, prevout.index);

      if (!map)
        continue;

      for (let wid of map.wids)
        util.binaryInsert(result, wid, cmp, true);
    }
  }

  for (let hash of hashes) {
    let map;

    if (!this.testFilter(hash))
      continue;

    map = await this.getPathMap(hash);

    if (!map)
      continue;

    for (let wid of map.wids)
      util.binaryInsert(result, wid, cmp, true);
  }

  if (result.length === 0)
    return;

  return result;
};

/**
 * Get the best block hash.
 * @returns {Promise}
 */

WalletDB.prototype.getState = async function getState() {
  let data = await this.db.get(layout.R);

  if (!data)
    return;

  return ChainState.fromRaw(data);
};

/**
 * Reset the chain state to a tip/start-block.
 * @param {BlockMeta} tip
 * @returns {Promise}
 */

WalletDB.prototype.resetState = async function resetState(tip, marked) {
  let batch = this.db.batch();
  let state = this.state.clone();
  let iter;

  iter = this.db.iterator({
    gte: layout.h(0),
    lte: layout.h(0xffffffff),
    values: false
  });

  for (;;) {
    let item = await iter.next();

    if (!item)
      break;

    try {
      batch.del(item.key);
    } catch (e) {
      await iter.end();
      throw e;
    }
  }

  state.startHeight = tip.height;
  state.startHash = tip.hash;
  state.height = tip.height;
  state.marked = marked;

  batch.put(layout.h(tip.height), tip.toHash());
  batch.put(layout.R, state.toRaw());

  await batch.write();

  this.state = state;
};

/**
 * Sync the current chain state to tip.
 * @param {BlockMeta} tip
 * @returns {Promise}
 */

WalletDB.prototype.syncState = async function syncState(tip) {
  let batch = this.db.batch();
  let state = this.state.clone();

  if (tip.height < state.height) {
    // Hashes ahead of our new tip
    // that we need to delete.
    let height = state.height;
    let blocks = height - tip.height;

    if (blocks > this.options.keepBlocks)
      blocks = this.options.keepBlocks;

    for (let i = 0; i < blocks; i++) {
      batch.del(layout.h(height));
      height--;
    }
  } else if (tip.height > state.height) {
    // Prune old hashes.
    let height = tip.height - this.options.keepBlocks;

    assert(tip.height === state.height + 1, 'Bad chain sync.');

    if (height >= 0)
      batch.del(layout.h(height));
  }

  state.height = tip.height;

  // Save tip and state.
  batch.put(layout.h(tip.height), tip.toHash());
  batch.put(layout.R, state.toRaw());

  await batch.write();

  this.state = state;
};

/**
 * Mark the start block once a confirmed tx is seen.
 * @param {BlockMeta} tip
 * @returns {Promise}
 */

WalletDB.prototype.maybeMark = async function maybeMark(tip) {
  if (this.state.marked)
    return;

  this.logger.info('Marking WalletDB start block at %s (%d).',
    util.revHex(tip.hash), tip.height);

  await this.resetState(tip, true);
};

/**
 * Get a block->wallet map.
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.getBlockMap = async function getBlockMap(height) {
  let data = await this.db.get(layout.b(height));

  if (!data)
    return;

  return BlockMapRecord.fromRaw(height, data);
};

/**
 * Add block to the global block map.
 * @param {Wallet} wallet
 * @param {Number} height
 * @param {BlockMapRecord} block
 */

WalletDB.prototype.writeBlockMap = function writeBlockMap(wallet, height, block) {
  let batch = this.batch(wallet);
  batch.put(layout.b(height), block.toRaw());
};

/**
 * Remove a block from the global block map.
 * @param {Wallet} wallet
 * @param {Number} height
 */

WalletDB.prototype.unwriteBlockMap = function unwriteBlockMap(wallet, height) {
  let batch = this.batch(wallet);
  batch.del(layout.b(height));
};

/**
 * Get a Unspent->Wallet map.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise}
 */

WalletDB.prototype.getOutpointMap = async function getOutpointMap(hash, index) {
  let data = await this.db.get(layout.o(hash, index));

  if (!data)
    return;

  return OutpointMapRecord.fromRaw(hash, index, data);
};

/**
 * Add an outpoint to global unspent map.
 * @param {Wallet} wallet
 * @param {Hash} hash
 * @param {Number} index
 * @param {OutpointMapRecord} map
 */

WalletDB.prototype.writeOutpointMap = function writeOutpointMap(wallet, hash, index, map) {
  let batch = this.batch(wallet);

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
  let batch = this.batch(wallet);
  batch.del(layout.o(hash, index));
};

/**
 * Get a wallet block meta.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getBlock = async function getBlock(height) {
  let data = await this.db.get(layout.h(height));
  let block;

  if (!data)
    return;

  block = new BlockMeta();
  block.hash = data.toString('hex');
  block.height = height;

  return block;
};

/**
 * Get wallet tip.
 * @param {Hash} hash
 * @returns {Promise}
 */

WalletDB.prototype.getTip = async function getTip() {
  let tip = await this.getBlock(this.state.height);

  if (!tip)
    throw new Error('WDB: Tip not found!');

  return tip;
};

/**
 * Sync with chain height.
 * @param {Number} height
 * @returns {Promise}
 */

WalletDB.prototype.rollback = async function rollback(height) {
  let tip, marked;

  if (height > this.state.height)
    throw new Error('WDB: Cannot rollback to the future.');

  if (height === this.state.height) {
    this.logger.debug('Rolled back to same height (%d).', height);
    return true;
  }

  this.logger.info(
    'Rolling back %d WalletDB blocks to height %d.',
    this.state.height - height, height);

  tip = await this.getBlock(height);

  if (tip) {
    await this.revert(tip.height);
    await this.syncState(tip);
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

  await this.revert(tip.height);
  await this.resetState(tip, marked);

  return false;
};

/**
 * Revert TXDB to an older state.
 * @param {Number} target
 * @returns {Promise}
 */

WalletDB.prototype.revert = async function revert(target) {
  let total = 0;
  let iter;

  iter = this.db.iterator({
    gte: layout.b(target + 1),
    lte: layout.b(0xffffffff),
    reverse: true,
    values: true
  });

  for (;;) {
    let item = await iter.next();

    if (!item)
      break;

    try {
      let height = layout.bb(item.key);
      let block = BlockMapRecord.fromRaw(height, item.value);

      total += block.txs.length;

      for (let i = block.txs.length - 1; i >= 0; i--) {
        let tx = block.txs[i];
        await this._unconfirm(tx);
      }
    } catch (e) {
      await iter.end();
      throw e;
    }
  }

  this.logger.info('Rolled back %d WalletDB transactions.', total);
};

/**
 * Add a block's transactions and write the new best hash.
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype.addBlock = async function addBlock(entry, txs) {
  let unlock = await this.txLock.lock();
  try {
    return await this._addBlock(entry, txs);
  } finally {
    unlock();
  }
};

/**
 * Add a block's transactions without a lock.
 * @private
 * @param {ChainEntry} entry
 * @param {TX[]} txs
 * @returns {Promise}
 */

WalletDB.prototype._addBlock = async function addBlock(entry, txs) {
  let tip = BlockMeta.fromEntry(entry);
  let total = 0;
  let tx;

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
  await this.syncState(tip);

  if (this.options.checkpoints) {
    if (tip.height <= this.network.lastCheckpoint)
      return total;
  }

  for (tx of txs) {
    if (await this._insert(tx, tip))
      total++;
  }

  if (total > 0) {
    this.logger.info('Connected WalletDB block %s (tx=%d).',
      util.revHex(tip.hash), total);
  }

  return total;
};

/**
 * Unconfirm a block's transactions
 * and write the new best hash (SPV version).
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype.removeBlock = async function removeBlock(entry) {
  let unlock = await this.txLock.lock();
  try {
    return await this._removeBlock(entry);
  } finally {
    unlock();
  }
};

/**
 * Unconfirm a block's transactions.
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype._removeBlock = async function removeBlock(entry) {
  let tip = BlockMeta.fromEntry(entry);
  let prev, block;

  if (tip.height > this.state.height) {
    this.logger.warning(
      'WalletDB is disconnecting high blocks (%d).',
      tip.height);
    return 0;
  }

  if (tip.height !== this.state.height)
    throw new Error('WDB: Bad disconnection (height mismatch).');

  prev = await this.getBlock(tip.height - 1);

  if (!prev)
    throw new Error('WDB: Bad disconnection (no previous block).');

  // Get the map of txids->wids.
  block = await this.getBlockMap(tip.height);

  if (!block) {
    await this.syncState(prev);
    return 0;
  }

  for (let i = block.txs.length - 1; i >= 0; i--) {
    let tx = block.txs[i];
    await this._unconfirm(tx);
  }

  // Sync the state to the previous tip.
  await this.syncState(prev);

  this.logger.warning('Disconnected wallet block %s (tx=%d).',
    util.revHex(tip.hash), block.txs.length);

  return block.txs.length;
};

/**
 * Rescan a block.
 * @private
 * @param {ChainEntry} entry
 * @param {TX[]} txs
 * @returns {Promise}
 */

WalletDB.prototype.rescanBlock = async function rescanBlock(entry, txs) {
  if (!this.rescanning) {
    this.logger.warning('Unsolicited rescan block: %s.', entry.height);
    return;
  }

  try {
    await this._addBlock(entry, txs);
  } catch (e) {
    this.emit('error', e);
    throw e;
  }
};

/**
 * Add a transaction to the database, map addresses
 * to wallet IDs, potentially store orphans, resolve
 * orphans, or confirm a transaction.
 * @param {TX} tx
 * @returns {Promise}
 */

WalletDB.prototype.addTX = async function addTX(tx) {
  let unlock = await this.txLock.lock();

  try {
    return await this._insert(tx);
  } finally {
    unlock();
  }
};

/**
 * Add a transaction to the database without a lock.
 * @private
 * @param {TX} tx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

WalletDB.prototype._insert = async function insert(tx, block) {
  let wids = await this.getWalletsByTX(tx);
  let result = false;

  assert(!tx.mutable, 'WDB: Cannot add mutable TX.');

  if (!wids)
    return;

  this.logger.info(
    'Incoming transaction for %d wallets in WalletDB (%s).',
    wids.length, tx.txid());

  // If this is our first transaction
  // in a block, set the start block here.
  if (block)
    await this.maybeMark(block);

  // Insert the transaction
  // into every matching wallet.
  for (let wid of wids) {
    let wallet = await this.get(wid);

    assert(wallet);

    if (await wallet.add(tx, block)) {
      this.logger.info(
        'Added transaction to wallet in WalletDB: %s (%d).',
        wallet.id, wid);
      result = true;
    }
  }

  if (!result)
    return;

  return wids;
};

/**
 * Unconfirm a transaction from all
 * relevant wallets without a lock.
 * @private
 * @param {TXMapRecord} tx
 * @returns {Promise}
 */

WalletDB.prototype._unconfirm = async function unconfirm(tx) {
  for (let wid of tx.wids) {
    let wallet = await this.get(wid);
    assert(wallet);
    await wallet.unconfirm(tx.hash);
  }
};

/**
 * Handle a chain reset.
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype.resetChain = async function resetChain(entry) {
  let unlock = await this.txLock.lock();
  try {
    return await this._resetChain(entry);
  } finally {
    unlock();
  }
};

/**
 * Handle a chain reset without a lock.
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

WalletDB.prototype._resetChain = async function resetChain(entry) {
  if (entry.height > this.state.height)
    throw new Error('WDB: Bad reset height.');

  // Try to rollback.
  if (await this.rollback(entry.height))
    return;

  // If we rolled back to the
  // start block, we need a rescan.
  await this.scan();
};

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
    this.location = path.join(this.prefix, 'walletdb');
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
