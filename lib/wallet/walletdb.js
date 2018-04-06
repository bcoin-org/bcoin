/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const EventEmitter = require('events');
const bio = require('bufio');
const {BloomFilter} = require('bfilter');
const {Lock, MapLock} = require('bmutex');
const bdb = require('bdb');
const Logger = require('blgr');
const ccmp = require('bcrypto/lib/ccmp');
const aes = require('bcrypto/lib/aes');
const util = require('../utils/util');
const Network = require('../protocol/network');
const Path = require('./path');
const common = require('./common');
const Wallet = require('./wallet');
const Account = require('./account');
const Outpoint = require('../primitives/outpoint');
const layouts = require('./layout');
const records = require('./records');
const NullClient = require('./nullclient');
const layout = layouts.wdb;
const tlayout = layouts.txdb;

const {
  ChainState,
  BlockMeta,
  TXRecord,
  MapRecord
} = records;

/**
 * WalletDB
 * @alias module:wallet.WalletDB
 * @extends EventEmitter
 */

class WalletDB extends EventEmitter {
  /**
   * Create a wallet db.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.options = new WalletOptions(options);

    this.network = this.options.network;
    this.logger = this.options.logger.context('wallet');
    this.workers = this.options.workers;
    this.client = this.options.client || new NullClient(this);
    this.feeRate = this.options.feeRate;
    this.db = bdb.create(this.options);

    this.primary = null;
    this.state = new ChainState();
    this.height = 0;
    this.wallets = new Map();
    this.depth = 0;
    this.rescanning = false;
    this.filterSent = false;

    // Wallet read lock.
    this.readLock = new MapLock();

    // Wallet write lock (creation and rename).
    this.writeLock = new Lock();

    // Lock for handling anything tx related.
    this.txLock = new Lock();

    // Address and outpoint filter.
    this.filter = new BloomFilter();

    this.init();
  }

  /**
   * Initialize walletdb.
   * @private
   */

  init() {
    let items = 3000000;
    let flag = -1;

    // Highest number of items with an
    // FPR of 0.001. We have to do this
    // by hand because BloomFilter.fromRate's
    // policy limit enforcing is fairly
    // naive.
    if (this.options.spv) {
      items = 20000;
      flag = BloomFilter.flags.ALL;
    }

    this.filter = BloomFilter.fromRate(items, 0.001, flag);
    this._bind();
  }

  /**
   * Bind to node events.
   * @private
   */

  _bind() {
    this.client.on('error', (err) => {
      this.emit('error', err);
    });

    this.client.on('connect', async () => {
      try {
        await this.syncNode();
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.client.on('disconnect', async () => {
      this.filterSent = false;
    });

    this.client.bind('block connect', async (entry, txs) => {
      try {
        await this.addBlock(entry, txs);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.client.bind('block disconnect', async (entry) => {
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

    this.client.bind('tx', async (tx) => {
      try {
        await this.addTX(tx);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.client.bind('chain reset', async (tip) => {
      try {
        await this.resetChain(tip);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  /**
   * Open the walletdb, wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    await this.db.open();
    await this.db.verify(layout.V.build(), 'wallet', 7);

    await this.verifyNetwork();

    this.depth = await this.getDepth();

    if (this.options.wipeNoReally)
      await this.wipe();

    await this.watch();
    await this.connect();

    this.logger.info(
      'WalletDB loaded (depth=%d, height=%d, start=%d).',
      this.depth,
      this.state.height,
      this.state.startHeight);

    const wallet = await this.ensure({
      id: 'primary'
    });

    const addr = await wallet.receiveAddress();

    this.logger.info(
      'Loaded primary wallet (id=%s, wid=%d, address=%s)',
      wallet.id, wallet.wid, addr.toString(this.network));

    this.primary = wallet;
  }

  /**
   * Verify network.
   * @returns {Promise}
   */

  async verifyNetwork() {
    const raw = await this.db.get(layout.O.build());

    if (!raw) {
      const b = this.db.batch();
      b.put(layout.O.build(), fromU32(this.network.magic));
      return b.write();
    }

    const magic = raw.readUInt32LE(0, true);

    if (magic !== this.network.magic)
      throw new Error('Network mismatch for WalletDB.');

    return undefined;
  }

  /**
   * Close the walletdb, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    await this.disconnect();

    for (const wallet of this.wallets.values()) {
      await wallet.destroy();
      this.unregister(wallet);
    }

    return this.db.close();
  }

  /**
   * Watch addresses and outpoints.
   * @private
   * @returns {Promise}
   */

  async watch() {
    const piter = this.db.iterator({
      gte: layout.p.min(),
      lte: layout.p.max()
    });

    let hashes = 0;

    await piter.each((key) => {
      const data = layout.p.parse(key);

      this.filter.add(data, 'hex');

      hashes += 1;
    });

    this.logger.info('Added %d hashes to WalletDB filter.', hashes);

    const oiter = this.db.iterator({
      gte: layout.o.min(),
      lte: layout.o.max()
    });

    let outpoints = 0;

    await oiter.each((key) => {
      const [hash, index] = layout.o.parse(key);
      const outpoint = new Outpoint(hash, index);
      const data = outpoint.toRaw();

      this.filter.add(data);

      outpoints += 1;
    });

    this.logger.info('Added %d outpoints to WalletDB filter.', outpoints);
  }

  /**
   * Connect to the node server (client required).
   * @returns {Promise}
   */

  async connect() {
    return this.client.open();
  }

  /**
   * Disconnect from node server (client required).
   * @returns {Promise}
   */

  async disconnect() {
    return this.client.close();
  }

  /**
   * Sync state with server on every connect.
   * @returns {Promise}
   */

  async syncNode() {
    const unlock = await this.txLock.lock();
    try {
      this.logger.info('Resyncing from server...');
      await this.syncState();
      await this.syncFilter();
      await this.syncChain();
      await this.resend();
    } finally {
      unlock();
    }
  }

  /**
   * Initialize and write initial sync state.
   * @returns {Promise}
   */

  async syncState() {
    const cache = await this.getState();

    if (cache) {
      if (!await this.getBlock(0))
        return this.migrateState(cache);

      this.state = cache;
      this.height = cache.height;

      return undefined;
    }

    this.logger.info('Initializing database state from server.');

    const b = this.db.batch();
    const hashes = await this.client.getHashes();

    let tip = null;

    for (let height = 0; height < hashes.length; height++) {
      const hash = hashes[height];
      const meta = new BlockMeta(hash, height);
      b.put(layout.h.build(height), meta.toHash());
      tip = meta;
    }

    assert(tip);

    const state = this.state.clone();
    state.startHeight = tip.height;
    state.startHash = tip.hash;
    state.height = tip.height;
    state.marked = false;

    b.put(layout.R.build(), state.toRaw());

    await b.write();

    this.state = state;
    this.height = state.height;

    return undefined;
  }

  /**
   * Migrate sync state.
   * @private
   * @param {ChainState} state
   * @returns {Promise}
   */

  async migrateState(state) {
    const b = this.db.batch();

    this.logger.info('Migrating to new sync state.');

    const hashes = await this.client.getHashes(0, state.height);

    for (let height = 0; height < hashes.length; height++) {
      const hash = hashes[height];
      const meta = new BlockMeta(hash, height);
      b.put(layout.h.build(height), meta.toHash());
    }

    await b.write();

    this.state = state;
    this.height = state.height;
  }

  /**
   * Connect and sync with the chain server.
   * @private
   * @returns {Promise}
   */

  async syncChain() {
    let height = this.state.height;

    this.logger.info('Syncing state from height %d.', height);

    for (;;) {
      const tip = await this.getBlock(height);
      assert(tip);

      if (await this.client.getEntry(tip.hash))
        break;

      assert(height !== 0);
      height -= 1;
    }

    return this.scan(height);
  }

  /**
   * Rescan blockchain from a given height.
   * @private
   * @param {Number?} height
   * @returns {Promise}
   */

  async scan(height) {
    if (height == null)
      height = this.state.startHeight;

    assert((height >>> 0) === height, 'WDB: Must pass in a height.');

    this.logger.info(
      'WalletDB is scanning %d blocks.',
      this.state.height - height + 1);

    await this.rollback(height);

    const tip = await this.getTip();

    try {
      this.rescanning = true;
      await this.client.rescan(tip.hash);
    } finally {
      this.rescanning = false;
    }
  }

  /**
   * Force a rescan.
   * @param {Number} height
   * @returns {Promise}
   */

  async rescan(height) {
    const unlock = await this.txLock.lock();
    try {
      return await this._rescan(height);
    } finally {
      unlock();
    }
  }

  /**
   * Force a rescan (without a lock).
   * @private
   * @param {Number} height
   * @returns {Promise}
   */

  async _rescan(height) {
    return this.scan(height);
  }

  /**
   * Broadcast a transaction via chain server.
   * @param {TX} tx
   * @returns {Promise}
   */

  async send(tx) {
    return this.client.send(tx);
  }

  /**
   * Estimate smart fee from chain server.
   * @param {Number} blocks
   * @returns {Promise}
   */

  async estimateFee(blocks) {
    if (this.feeRate > 0)
      return this.feeRate;

    const rate = await this.client.estimateFee(blocks);

    if (rate < this.network.feeRate)
      return this.network.feeRate;

    if (rate > this.network.maxFeeRate)
      return this.network.maxFeeRate;

    return rate;
  }

  /**
   * Send filter to the remote node.
   * @private
   * @returns {Promise}
   */

  syncFilter() {
    this.logger.info('Sending filter to server (%dmb).',
      this.filter.size / 8 / (1 << 20));

    this.filterSent = true;
    return this.client.setFilter(this.filter);
  }

  /**
   * Add data to remote filter.
   * @private
   * @param {Buffer} data
   * @returns {Promise}
   */

  addFilter(data) {
    if (!this.filterSent)
      return undefined;
    return this.client.addFilter(data);
  }

  /**
   * Reset remote filter.
   * @private
   * @returns {Promise}
   */

  resetFilter() {
    if (!this.filterSent)
      return undefined;
    return this.client.resetFilter();
  }

  /**
   * Backup the wallet db.
   * @param {String} path
   * @returns {Promise}
   */

  backup(path) {
    return this.db.backup(path);
  }

  /**
   * Wipe the txdb - NEVER USE.
   * @returns {Promise}
   */

  async wipe() {
    this.logger.warning('Wiping WalletDB TXDB...');
    this.logger.warning('I hope you know what you\'re doing.');

    const iter = this.db.iterator();
    const b = this.db.batch();

    let total = 0;

    await iter.each((key) => {
      switch (key[0]) {
        case 0x62: // b
        case 0x63: // c
        case 0x65: // e
        case 0x74: // t
        case 0x6f: // o
        case 0x68: // h
        case 0x52: // R
          b.del(key);
          total += 1;
          break;
      }
    });

    this.logger.warning('Wiped %d txdb records.', total);

    return b.write();
  }

  /**
   * Get current wallet wid depth.
   * @private
   * @returns {Promise}
   */

  async getDepth() {
    const raw = await this.db.get(layout.D.build());

    if (!raw)
      return 0;

    return raw.readUInt32LE(0, true);
  }

  /**
   * Test the bloom filter against a tx or address hash.
   * @private
   * @param {Hash} hash
   * @returns {Boolean}
   */

  testFilter(data) {
    return this.filter.test(data, 'hex');
  }

  /**
   * Add hash to local and remote filters.
   * @private
   * @param {Hash} hash
   */

  addHash(hash) {
    this.filter.add(hash, 'hex');
    return this.addFilter(hash);
  }

  /**
   * Add outpoint to local filter.
   * @private
   * @param {Hash} hash
   * @param {Number} index
   */

  addOutpoint(hash, index) {
    const outpoint = new Outpoint(hash, index);
    this.filter.add(outpoint.toRaw());
  }

  /**
   * Dump database (for debugging).
   * @returns {Promise} - Returns Object.
   */

  dump() {
    return this.db.dump();
  }

  /**
   * Register an object with the walletdb.
   * @param {Object} object
   */

  register(wallet) {
    assert(!this.wallets.has(wallet.wid));
    this.wallets.set(wallet.wid, wallet);
  }

  /**
   * Unregister a object with the walletdb.
   * @param {Object} object
   * @returns {Boolean}
   */

  unregister(wallet) {
    assert(this.wallets.has(wallet.wid));
    this.wallets.delete(wallet.wid);
  }

  /**
   * Map wallet id to wid.
   * @param {String|Number} id
   * @returns {Promise} - Returns {Number}.
   */

  async ensureWID(id) {
    if (typeof id === 'number') {
      if (!await this.db.has(layout.W.build(id)))
        return -1;
      return id;
    }

    return this.getWID(id);
  }

  /**
   * Map wallet id to wid.
   * @param {String} id
   * @returns {Promise} - Returns {Number}.
   */

  async getWID(id) {
    const data = await this.db.get(layout.l.build(id));

    if (!data)
      return -1;

    assert(data.length === 4);

    return data.readUInt32LE(0, true);
  }

  /**
   * Map wallet wid to id.
   * @param {Number} wid
   * @returns {Promise} - Returns {String}.
   */

  async getID(wid) {
    const data = await this.db.get(layout.W.build(wid));

    if (!data)
      return null;

    return toString(data);
  }

  /**
   * Get a wallet from the database, setup watcher.
   * @param {Number|String} id
   * @returns {Promise} - Returns {@link Wallet}.
   */

  async get(id) {
    const wid = await this.ensureWID(id);

    if (wid === -1)
      return null;

    const unlock = await this.readLock.lock(wid);

    try {
      return await this._get(wid);
    } finally {
      unlock();
    }
  }

  /**
   * Get a wallet from the database without a lock.
   * @private
   * @param {Number} wid
   * @returns {Promise} - Returns {@link Wallet}.
   */

  async _get(wid) {
    const cache = this.wallets.get(wid);

    if (cache)
      return cache;

    const id = await this.getID(wid);

    if (!id)
      return null;

    const data = await this.db.get(layout.w.build(wid));
    assert(data);

    const wallet = Wallet.fromRaw(this, data);

    wallet.wid = wid;
    wallet.id = id;

    await wallet.open();

    this.register(wallet);

    return wallet;
  }

  /**
   * Save a wallet to the database.
   * @param {Wallet} wallet
   */

  save(b, wallet) {
    const wid = wallet.wid;
    const id = wallet.id;

    b.put(layout.w.build(wid), wallet.toRaw());
    b.put(layout.W.build(wid), fromString(id));
    b.put(layout.l.build(id), fromU32(wid));
  }

  /**
   * Increment the wid depth.
   * @param {Batch} b
   * @param {Number} wid
   */

  increment(b, wid) {
    b.put(layout.D.build(), fromU32(wid + 1));
  }

  /**
   * Rename a wallet.
   * @param {Wallet} wallet
   * @param {String} id
   * @returns {Promise}
   */

  async rename(wallet, id) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._rename(wallet, id);
    } finally {
      unlock();
    }
  }

  /**
   * Rename a wallet without a lock.
   * @private
   * @param {Wallet} wallet
   * @param {String} id
   * @returns {Promise}
   */

  async _rename(wallet, id) {
    if (!common.isName(id))
      throw new Error('WDB: Bad wallet ID.');

    if (await this.has(id))
      throw new Error('WDB: ID not available.');

    const b = this.db.batch();

    // Update wid->id index.
    b.put(layout.W.build(wallet.wid), fromString(id));

    // Delete old id->wid index.
    b.del(layout.l.build(wallet.id));

    // Add new id->wid index.
    b.put(layout.l.build(id), fromU32(wallet.wid));

    await b.write();

    wallet.id = id;
  }

  /**
   * Rename an account.
   * @param {Account} account
   * @param {String} name
   */

  renameAccount(b, account, name) {
    const wid = account.wid;
    const index = account.accountIndex;

    // Remove old wid/name->account index.
    b.del(layout.i.build(wid, account.name));

    // Name->Index lookups
    b.put(layout.i.build(wid, name), fromU32(index));

    // Index->Name lookups
    b.put(layout.n.build(wid, index), fromString(name));

    account.name = name;
  }

  /**
   * Remove a wallet.
   * @param {Number|String} id
   * @returns {Promise}
   */

  async remove(id) {
    const wid = await this.ensureWID(id);

    if (wid === -1)
      return false;

    // Grab all locks.
    const unlock1 = await this.readLock.lock(wid);
    const unlock2 = await this.writeLock.lock();
    const unlock3 = await this.txLock.lock();

    try {
      return await this._remove(wid);
    } finally {
      unlock3();
      unlock2();
      unlock1();
    }
  }

  /**
   * Remove a wallet (without a lock).
   * @private
   * @param {Number} wid
   * @returns {Promise}
   */

  async _remove(wid) {
    const id = await this.getID(wid);

    if (!id)
      return false;

    if (id === 'primary')
      throw new Error('Cannot remove primary wallet.');

    const b = this.db.batch();

    b.del(layout.w.build(wid));
    b.del(layout.W.build(wid));
    b.del(layout.l.build(id));

    const piter = this.db.iterator({
      gte: layout.P.min(wid),
      lte: layout.P.max(wid)
    });

    await piter.each((key, value) => {
      const [, hash] = layout.P.parse(key);
      b.del(key);
      return this.removePathMap(b, hash, wid);
    });

    const removeRange = (opt) => {
      return this.db.iterator(opt).each(key => b.del(key));
    };

    await removeRange({
      gte: layout.r.min(wid),
      lte: layout.r.max(wid)
    });

    await removeRange({
      gte: layout.a.min(wid),
      lte: layout.a.max(wid)
    });

    await removeRange({
      gte: layout.i.min(wid),
      lte: layout.i.max(wid)
    });

    await removeRange({
      gte: layout.n.min(wid),
      lte: layout.n.max(wid)
    });

    await removeRange({
      gt: layout.t.build(wid),
      lt: layout.t.build(wid + 1)
    });

    const bucket = this.db.bucket(layout.t.build(wid));

    const biter = bucket.iterator({
      gte: tlayout.b.min(),
      lte: tlayout.b.max()
    });

    await biter.each((key, value) => {
      const height = tlayout.b.parse(key);
      return this.removeBlockMap(b, height, wid);
    });

    const siter = bucket.iterator({
      gte: tlayout.s.min(),
      lte: tlayout.s.max(),
      keys: true
    });

    await siter.each((key, value) => {
      const [hash, index] = tlayout.s.parse(key);
      return this.removeOutpointMap(b, hash, index, wid);
    });

    const uiter = bucket.iterator({
      gte: tlayout.p.min(),
      lte: tlayout.p.max(),
      keys: true
    });

    await uiter.each((key, value) => {
      const hash = tlayout.p.parse(key);
      return this.removeTXMap(b, hash, wid);
    });

    const wallet = this.wallets.get(wid);

    if (wallet) {
      await wallet.destroy();
      this.unregister(wallet);
    }

    await b.write();

    return true;
  }

  /**
   * Get a wallet with token auth first.
   * @param {Number|String} id
   * @param {Buffer} token
   * @returns {Promise} - Returns {@link Wallet}.
   */

  async auth(id, token) {
    const wallet = await this.get(id);

    if (!wallet)
      return null;

    // Compare in constant time:
    if (!ccmp(token, wallet.token))
      throw new Error('WDB: Authentication error.');

    return wallet;
  }

  /**
   * Create a new wallet, save to database, setup watcher.
   * @param {Object} options - See {@link Wallet}.
   * @returns {Promise} - Returns {@link Wallet}.
   */

  async create(options) {
    const unlock = await this.writeLock.lock();

    if (!options)
      options = {};

    try {
      return await this._create(options);
    } finally {
      unlock();
    }
  }

  /**
   * Create a new wallet, save to database without a lock.
   * @private
   * @param {Object} options - See {@link Wallet}.
   * @returns {Promise} - Returns {@link Wallet}.
   */

  async _create(options) {
    if (options.id) {
      if (await this.has(options.id))
        throw new Error('WDB: Wallet already exists.');
    }

    const wallet = Wallet.fromOptions(this, options);

    wallet.wid = this.depth;

    await wallet.init(options, options.passphrase);

    this.depth += 1;

    this.register(wallet);

    this.logger.info('Created wallet %s in WalletDB.', wallet.id);

    return wallet;
  }

  /**
   * Test for the existence of a wallet.
   * @param {Number|String} id
   * @returns {Promise}
   */

  async has(id) {
    const wid = await this.ensureWID(id);
    return wid !== -1;
  }

  /**
   * Attempt to create wallet, return wallet if already exists.
   * @param {Object} options - See {@link Wallet}.
   * @returns {Promise}
   */

  async ensure(options) {
    if (options.id) {
      const wallet = await this.get(options.id);

      if (wallet)
        return wallet;
    }

    return this.create(options);
  }

  /**
   * Get an account from the database by wid.
   * @private
   * @param {Number} wid
   * @param {Number} index - Account index.
   * @returns {Promise} - Returns {@link Wallet}.
   */

  async getAccount(wid, index) {
    const name = await this.getAccountName(wid, index);

    if (!name)
      return null;

    const data = await this.db.get(layout.a.build(wid, index));
    assert(data);

    const account = Account.fromRaw(this, data);

    account.accountIndex = index;
    account.name = name;

    return account;
  }

  /**
   * List account names and indexes from the db.
   * @param {Number} wid
   * @returns {Promise} - Returns Array.
   */

  async getAccounts(wid) {
    return this.db.values({
      gte: layout.n.min(wid),
      lte: layout.n.max(wid),
      parse: toString
    });
  }

  /**
   * Lookup the corresponding account name's index.
   * @param {Number} wid
   * @param {String} name - Account name/index.
   * @returns {Promise} - Returns Number.
   */

  async getAccountIndex(wid, name) {
    const index = await this.db.get(layout.i.build(wid, name));

    if (!index)
      return -1;

    return index.readUInt32LE(0, true);
  }

  /**
   * Lookup the corresponding account index's name.
   * @param {Number} wid
   * @param {Number} index
   * @returns {Promise} - Returns Number.
   */

  async getAccountName(wid, index) {
    const name = await this.db.get(layout.n.build(wid, index));

    if (!name)
      return null;

    return toString(name);
  }

  /**
   * Save an account to the database.
   * @param {Account} account
   * @returns {Promise}
   */

  saveAccount(b, account) {
    const wid = account.wid;
    const index = account.accountIndex;
    const name = account.name;

    // Account data
    b.put(layout.a.build(wid, index), account.toRaw());

    // Name->Index lookups
    b.put(layout.i.build(wid, name), fromU32(index));

    // Index->Name lookups
    b.put(layout.n.build(wid, index), fromString(name));
  }

  /**
   * Test for the existence of an account.
   * @param {Number} wid
   * @param {String|Number} acct
   * @returns {Promise} - Returns Boolean.
   */

  async hasAccount(wid, index) {
    return this.db.has(layout.a.build(wid, index));
  }

  /**
   * Save an address to the path map.
   * @param {Wallet} wallet
   * @param {WalletKey} ring
   * @returns {Promise}
   */

  async saveKey(b, wid, ring) {
    return this.savePath(b, wid, ring.toPath());
  }

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

  async savePath(b, wid, path) {
    // Address Hash -> Wallet Map
    await this.addPathMap(b, path.hash, wid);

    // Wallet ID + Address Hash -> Path Data
    b.put(layout.P.build(wid, path.hash), path.toRaw());

    // Wallet ID + Account Index + Address Hash -> Dummy
    b.put(layout.r.build(wid, path.account, path.hash), null);
  }

  /**
   * Retrieve path by hash.
   * @param {Number} wid
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getPath(wid, hash) {
    const path = await this.readPath(wid, hash);

    if (!path)
      return null;

    path.name = await this.getAccountName(wid, path.account);
    assert(path.name);

    return path;
  }

  /**
   * Retrieve path by hash.
   * @param {Number} wid
   * @param {Hash} hash
   * @returns {Promise}
   */

  async readPath(wid, hash) {
    const data = await this.db.get(layout.P.build(wid, hash));

    if (!data)
      return null;

    const path = Path.fromRaw(data);
    path.hash = hash;

    return path;
  }

  /**
   * Test whether a wallet contains a path.
   * @param {Number} wid
   * @param {Hash} hash
   * @returns {Promise}
   */

  async hasPath(wid, hash) {
    return this.db.has(layout.P.build(wid, hash));
  }

  /**
   * Get all address hashes.
   * @returns {Promise}
   */

  async getHashes() {
    return this.db.keys({
      gte: layout.p.min(),
      lte: layout.p.max(),
      parse: key => layout.p.parse(key)
    });
  }

  /**
   * Get all outpoints.
   * @returns {Promise}
   */

  async getOutpoints() {
    return this.db.keys({
      gte: layout.o.min(),
      lte: layout.o.max(),
      parse: (key) => {
        const [hash, index] = layout.o.parse(key);
        return new Outpoint(hash, index);
      }
    });
  }

  /**
   * Get all address hashes.
   * @param {Number} wid
   * @returns {Promise}
   */

  async getWalletHashes(wid) {
    return this.db.keys({
      gte: layout.P.min(wid),
      lte: layout.P.max(wid),
      parse: key => layout.P.parse(key)[1]
    });
  }

  /**
   * Get all account address hashes.
   * @param {Number} wid
   * @param {Number} account
   * @returns {Promise}
   */

  async getAccountHashes(wid, account) {
    return this.db.keys({
      gte: layout.r.min(wid, account),
      lte: layout.r.max(wid, account),
      parse: key => layout.r.parse(key)[2]
    });
  }

  /**
   * Get all paths for a wallet.
   * @param {Number} wid
   * @returns {Promise}
   */

  async getWalletPaths(wid) {
    const items = await this.db.range({
      gte: layout.P.min(wid),
      lte: layout.P.min(wid)
    });

    const paths = [];

    for (const {key, value} of items) {
      const [, hash] = layout.P.parse(key);
      const path = Path.fromRaw(value);

      path.hash = hash;
      path.name = await this.getAccountName(wid, path.account);
      assert(path.name);

      paths.push(path);
    }

    return paths;
  }

  /**
   * Get all wallet ids.
   * @returns {Promise}
   */

  async getWallets() {
    return this.db.values({
      gte: layout.W.min(),
      lte: layout.W.max(),
      parse: toString
    });
  }

  /**
   * Encrypt all imported keys for a wallet.
   * @param {Number} wid
   * @param {Buffer} key
   * @returns {Promise}
   */

  async encryptKeys(b, wid, key) {
    const iter = this.db.iterator({
      gte: layout.P.min(wid),
      lte: layout.P.max(wid),
      values: true
    });

    await iter.each((k, value) => {
      const [, hash] = layout.P.parse(k);
      const path = Path.fromRaw(value);

      if (!path.data)
        return;

      assert(!path.encrypted);

      const bhash = Buffer.from(hash, 'hex');
      const iv = bhash.slice(0, 16);

      path.data = aes.encipher(path.data, key, iv);
      path.encrypted = true;

      b.put(k, path.toRaw());
    });
  }

  /**
   * Decrypt all imported keys for a wallet.
   * @param {Number} wid
   * @param {Buffer} key
   * @returns {Promise}
   */

  async decryptKeys(b, wid, key) {
    const iter = this.db.iterator({
      gte: layout.P.min(wid),
      lte: layout.P.max(wid),
      values: true
    });

    await iter.each((k, value) => {
      const [, hash] = layout.P.parse(k);
      const path = Path.fromRaw(value);

      if (!path.data)
        return;

      assert(path.encrypted);

      const bhash = Buffer.from(hash, 'hex');
      const iv = bhash.slice(0, 16);

      path.data = aes.decipher(path.data, key, iv);
      path.encrypted = false;

      b.put(k, path.toRaw());
    });
  }

  /**
   * Resend all pending transactions.
   * @returns {Promise}
   */

  async resend() {
    const wids = await this.db.keys({
      gte: layout.w.min(),
      lte: layout.w.max(),
      parse: key => layout.w.parse(key)
    });

    this.logger.info('Resending from %d wallets.', wids.length);

    for (const wid of wids)
      await this.resendPending(wid);
  }

  /**
   * Resend all pending transactions for a specific wallet.
   * @private
   * @param {Number} wid
   * @returns {Promise}
   */

  async resendPending(wid) {
    const prefix = layout.t.build(wid);
    const b = this.db.bucket(prefix);

    const hashes = await b.keys({
      gte: tlayout.p.min(),
      lte: tlayout.p.max(),
      parse: key => tlayout.p.parse(key)
    });

    if (hashes.length === 0)
      return;

    this.logger.info(
      'Rebroadcasting %d transactions for %d.',
      hashes.length,
      wid);

    const txs = [];

    for (const hash of hashes) {
      const data = await b.get(tlayout.t.build(hash));

      if (!data)
        continue;

      const wtx = TXRecord.fromRaw(data);

      if (wtx.tx.isCoinbase())
        continue;

      txs.push(wtx.tx);
    }

    for (const tx of common.sortDeps(txs))
      await this.send(tx);
  }

  /**
   * Get all wallet ids by output addresses and outpoints.
   * @param {Hash[]} hashes
   * @returns {Promise}
   */

  async getWalletsByTX(tx) {
    const wids = new Set();

    if (!tx.isCoinbase()) {
      for (const {prevout} of tx.inputs) {
        const {hash, index} = prevout;

        if (!this.testFilter(prevout.toRaw()))
          continue;

        const map = await this.getOutpointMap(hash, index);

        if (!map)
          continue;

        for (const wid of map.wids)
          wids.add(wid);
      }
    }

    const hashes = tx.getOutputHashes('hex');

    for (const hash of hashes) {
      if (!this.testFilter(hash))
        continue;

      const map = await this.getPathMap(hash);

      if (!map)
        continue;

      for (const wid of map.wids)
        wids.add(wid);
    }

    if (wids.size === 0)
      return null;

    return wids;
  }

  /**
   * Get the best block hash.
   * @returns {Promise}
   */

  async getState() {
    const data = await this.db.get(layout.R.build());

    if (!data)
      return null;

    return ChainState.fromRaw(data);
  }

  /**
   * Sync the current chain state to tip.
   * @param {BlockMeta} tip
   * @returns {Promise}
   */

  async setTip(tip) {
    const b = this.db.batch();
    const state = this.state.clone();

    if (tip.height < state.height) {
      // Hashes ahead of our new tip
      // that we need to delete.
      while (state.height !== tip.height) {
        b.del(layout.h.build(state.height));
        state.height -= 1;
      }
    } else if (tip.height > state.height) {
      assert(tip.height === state.height + 1, 'Bad chain sync.');
      state.height += 1;
    }

    if (tip.height < state.startHeight) {
      state.startHeight = tip.height;
      state.startHash = tip.hash;
      state.marked = false;
    }

    // Save tip and state.
    b.put(layout.h.build(tip.height), tip.toHash());
    b.put(layout.R.build(), state.toRaw());

    await b.write();

    this.state = state;
    this.height = state.height;
  }

  /**
   * Mark current state.
   * @param {BlockMeta} block
   * @returns {Promise}
   */

  async markState(block) {
    const state = this.state.clone();
    state.startHeight = block.height;
    state.startHash = block.hash;
    state.marked = true;

    const b = this.db.batch();
    b.put(layout.R.build(), state.toRaw());
    await b.write();

    this.state = state;
    this.height = state.height;
  }

  /**
   * Get a wallet map.
   * @param {Buffer} key
   * @returns {Promise}
   */

  async getMap(key) {
    const data = await this.db.get(key);

    if (!data)
      return null;

    return MapRecord.fromRaw(data);
  }

  /**
   * Add wid to a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async addMap(b, key, wid) {
    const data = await this.db.get(key);

    if (!data) {
      const map = new MapRecord();
      map.add(wid);
      b.put(key, map.toRaw());
      return;
    }

    assert(data.length >= 4);

    const len = data.readUInt32LE(0, true);
    const bw = bio.write(data.length + 4);

    bw.writeU32(len + 1);
    bw.copy(data, 4, data.length);
    bw.writeU32(wid);

    b.put(key, bw.render());
  }

  /**
   * Remove wid from a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async removeMap(b, key, wid) {
    const map = await this.getMap(key);

    if (!map)
      return;

    if (!map.remove(wid))
      return;

    if (map.size === 0) {
      b.del(key);
      return;
    }

    b.put(key, map.toRaw());
  }

  /**
   * Get a wallet map.
   * @param {Buffer} key
   * @returns {Promise}
   */

  async getPathMap(hash) {
    return this.getMap(layout.p.build(hash));
  }

  /**
   * Add wid to a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async addPathMap(b, hash, wid) {
    await this.addHash(hash);
    return this.addMap(b, layout.p.build(hash), wid);
  }

  /**
   * Remove wid from a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async removePathMap(b, hash, wid) {
    return this.removeMap(b, layout.p.build(hash), wid);
  }

  /**
   * Get a wallet map.
   * @param {Buffer} key
   * @returns {Promise}
   */

  async getBlockMap(height) {
    return this.getMap(layout.b.build(height));
  }

  /**
   * Add wid to a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async addBlockMap(b, height, wid) {
    return this.addMap(b, layout.b.build(height), wid);
  }

  /**
   * Remove wid from a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async removeBlockMap(b, height, wid) {
    return this.removeMap(b, layout.b.build(height), wid);
  }

  /**
   * Get a wallet map.
   * @param {Buffer} key
   * @returns {Promise}
   */

  async getTXMap(hash) {
    return this.getMap(layout.T.build(hash));
  }

  /**
   * Add wid to a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async addTXMap(b, hash, wid) {
    return this.addMap(b, layout.T.build(hash), wid);
  }

  /**
   * Remove wid from a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async removeTXMap(b, hash, wid) {
    return this.removeMap(b, layout.T.build(hash), wid);
  }

  /**
   * Get a wallet map.
   * @param {Buffer} key
   * @returns {Promise}
   */

  async getOutpointMap(hash, index) {
    return this.getMap(layout.o.build(hash, index));
  }

  /**
   * Add wid to a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async addOutpointMap(b, hash, index, wid) {
    await this.addOutpoint(hash, index);
    return this.addMap(b, layout.o.build(hash, index), wid);
  }

  /**
   * Remove wid from a wallet map.
   * @param {Wallet} wallet
   * @param {Buffer} key
   * @param {Number} wid
   */

  async removeOutpointMap(b, hash, index, wid) {
    return this.removeMap(b, layout.o.build(hash, index), wid);
  }

  /**
   * Get a wallet block meta.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getBlock(height) {
    const data = await this.db.get(layout.h.build(height));

    if (!data)
      return null;

    const block = new BlockMeta();
    block.hash = data.toString('hex');
    block.height = height;

    return block;
  }

  /**
   * Get wallet tip.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getTip() {
    const tip = await this.getBlock(this.state.height);

    if (!tip)
      throw new Error('WDB: Tip not found!');

    return tip;
  }

  /**
   * Sync with chain height.
   * @param {Number} height
   * @returns {Promise}
   */

  async rollback(height) {
    if (height > this.state.height)
      throw new Error('WDB: Cannot rollback to the future.');

    if (height === this.state.height) {
      this.logger.info('Rolled back to same height (%d).', height);
      return;
    }

    this.logger.info(
      'Rolling back %d WalletDB blocks to height %d.',
      this.state.height - height, height);

    const tip = await this.getBlock(height);
    assert(tip);

    await this.revert(tip.height);
    await this.setTip(tip);
  }

  /**
   * Revert TXDB to an older state.
   * @param {Number} target
   * @returns {Promise}
   */

  async revert(target) {
    const iter = this.db.iterator({
      gte: layout.b.build(target + 1),
      lte: layout.b.max(),
      reverse: true,
      values: true
    });

    let total = 0;

    await iter.each(async (key, value) => {
      const height = layout.b.parse(key);
      const block = MapRecord.fromRaw(value);

      for (const wid of block.wids) {
        const wallet = await this.get(wid);
        assert(wallet);
        total += await wallet.revert(height);
      }
    });

    this.logger.info('Rolled back %d WalletDB transactions.', total);
  }

  /**
   * Add a block's transactions and write the new best hash.
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async addBlock(entry, txs) {
    const unlock = await this.txLock.lock();
    try {
      return await this._addBlock(entry, txs);
    } finally {
      unlock();
    }
  }

  /**
   * Add a block's transactions without a lock.
   * @private
   * @param {ChainEntry} entry
   * @param {TX[]} txs
   * @returns {Promise}
   */

  async _addBlock(entry, txs) {
    const tip = BlockMeta.fromEntry(entry);

    if (tip.height < this.state.height) {
      this.logger.warning(
        'WalletDB is connecting low blocks (%d).',
        tip.height);
      return 0;
    }

    if (tip.height >= this.network.block.slowHeight)
      this.logger.debug('Adding block: %d.', tip.height);

    if (tip.height === this.state.height) {
      // We let blocks of the same height
      // through specifically for rescans:
      // we always want to rescan the last
      // block since the state may have
      // updated before the block was fully
      // processed (in the case of a crash).
      this.logger.warning('Already saw WalletDB block (%d).', tip.height);
    } else if (tip.height !== this.state.height + 1) {
      await this.scan(this.state.height);
      return 0;
    }

    // Sync the state to the new tip.
    await this.setTip(tip);

    if (this.options.checkpoints && !this.state.marked) {
      if (tip.height <= this.network.lastCheckpoint)
        return 0;
    }

    let total = 0;

    for (const tx of txs) {
      if (await this._addTX(tx, tip))
        total += 1;
    }

    if (total > 0) {
      this.logger.info('Connected WalletDB block %s (tx=%d).',
        util.revHex(tip.hash), total);
    }

    return total;
  }

  /**
   * Unconfirm a block's transactions
   * and write the new best hash (SPV version).
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async removeBlock(entry) {
    const unlock = await this.txLock.lock();
    try {
      return await this._removeBlock(entry);
    } finally {
      unlock();
    }
  }

  /**
   * Unconfirm a block's transactions.
   * @private
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async _removeBlock(entry) {
    const tip = BlockMeta.fromEntry(entry);

    if (tip.height === 0)
      throw new Error('WDB: Bad disconnection (genesis block).');

    if (tip.height > this.state.height) {
      this.logger.warning(
        'WalletDB is disconnecting high blocks (%d).',
        tip.height);
      return 0;
    }

    if (tip.height !== this.state.height)
      throw new Error('WDB: Bad disconnection (height mismatch).');

    const prev = await this.getBlock(tip.height - 1);
    assert(prev);

    // Get the map of block->wids.
    const map = await this.getBlockMap(tip.height);

    if (!map) {
      await this.setTip(prev);
      return 0;
    }

    let total = 0;

    for (const wid of map.wids) {
      const wallet = await this.get(wid);
      assert(wallet);
      total += await wallet.revert(tip.height);
    }

    // Sync the state to the previous tip.
    await this.setTip(prev);

    this.logger.warning('Disconnected wallet block %s (tx=%d).',
      util.revHex(tip.hash), total);

    return total;
  }

  /**
   * Rescan a block.
   * @private
   * @param {ChainEntry} entry
   * @param {TX[]} txs
   * @returns {Promise}
   */

  async rescanBlock(entry, txs) {
    if (!this.rescanning) {
      this.logger.warning('Unsolicited rescan block: %d.', entry.height);
      return;
    }

    if (entry.height > this.state.height + 1) {
      this.logger.warning('Rescan block too high: %d.', entry.height);
      return;
    }

    try {
      await this._addBlock(entry, txs);
    } catch (e) {
      this.emit('error', e);
      throw e;
    }
  }

  /**
   * Add a transaction to the database, map addresses
   * to wallet IDs, potentially store orphans, resolve
   * orphans, or confirm a transaction.
   * @param {TX} tx
   * @returns {Promise}
   */

  async addTX(tx) {
    const unlock = await this.txLock.lock();
    try {
      return await this._addTX(tx);
    } finally {
      unlock();
    }
  }

  /**
   * Add a transaction to the database without a lock.
   * @private
   * @param {TX} tx
   * @param {BlockMeta} block
   * @returns {Promise}
   */

  async _addTX(tx, block) {
    const wids = await this.getWalletsByTX(tx);

    assert(!tx.mutable, 'WDB: Cannot add mutable TX.');

    if (!wids)
      return null;

    if (block && !this.state.marked)
      await this.markState(block);

    this.logger.info(
      'Incoming transaction for %d wallets in WalletDB (%s).',
      wids.size, tx.txid());

    let result = false;

    // Insert the transaction
    // into every matching wallet.
    for (const wid of wids) {
      const wallet = await this.get(wid);

      assert(wallet);

      if (await wallet.add(tx, block)) {
        this.logger.info(
          'Added transaction to wallet in WalletDB: %s (%d).',
          wallet.id, wid);
        result = true;
      }
    }

    if (!result)
      return null;

    return wids;
  }

  /**
   * Handle a chain reset.
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async resetChain(entry) {
    const unlock = await this.txLock.lock();
    try {
      return await this._resetChain(entry);
    } finally {
      unlock();
    }
  }

  /**
   * Handle a chain reset without a lock.
   * @private
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async _resetChain(entry) {
    if (entry.height > this.state.height)
      throw new Error('WDB: Bad reset height.');

    return this.rollback(entry.height);
  }
}

/**
 * Wallet Options
 * @alias module:wallet.WalletOptions
 */

class WalletOptions {
  /**
   * Create wallet options.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = Logger.global;
    this.workers = null;
    this.client = null;
    this.feeRate = 0;

    this.prefix = null;
    this.location = null;
    this.memory = true;
    this.maxFiles = 64;
    this.cacheSize = 16 << 20;
    this.compression = true;

    this.spv = false;
    this.witness = false;
    this.checkpoints = false;
    this.wipeNoReally = false;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {WalletOptions}
   */

  fromOptions(options) {
    if (options.network != null)
      this.network = Network.get(options.network);

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.workers != null) {
      assert(typeof options.workers === 'object');
      this.workers = options.workers;
    }

    if (options.client != null) {
      assert(typeof options.client === 'object');
      this.client = options.client;
    }

    if (options.feeRate != null) {
      assert((options.feeRate >>> 0) === options.feeRate);
      this.feeRate = options.feeRate;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.location = path.join(this.prefix, 'wallet');
    }

    if (options.location != null) {
      assert(typeof options.location === 'string');
      this.location = options.location;
    }

    if (options.memory != null) {
      assert(typeof options.memory === 'boolean');
      this.memory = options.memory;
    }

    if (options.maxFiles != null) {
      assert((options.maxFiles >>> 0) === options.maxFiles);
      this.maxFiles = options.maxFiles;
    }

    if (options.cacheSize != null) {
      assert(Number.isSafeInteger(options.cacheSize) && options.cacheSize >= 0);
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

    if (options.wipeNoReally != null) {
      assert(typeof options.wipeNoReally === 'boolean');
      this.wipeNoReally = options.wipeNoReally;
    }

    return this;
  }

  /**
   * Instantiate chain options from object.
   * @param {Object} options
   * @returns {WalletOptions}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
}

/*
 * Helpers
 */

function fromU32(num) {
  const data = Buffer.allocUnsafe(4);
  data.writeUInt32LE(num, 0, true);
  return data;
}

function fromString(str) {
  const buf = Buffer.alloc(1 + str.length);
  buf[0] = str.length;
  buf.write(str, 1, str.length, 'ascii');
  return buf;
}

function toString(buf) {
  assert(buf.length > 0);
  assert(buf[0] === buf.length - 1);
  return buf.toString('ascii', 1, buf.length);
}

/*
 * Expose
 */

module.exports = WalletDB;
