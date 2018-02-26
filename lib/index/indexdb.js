/*!
 * indexdb.js - storage for indexes
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const EventEmitter = require('events');
const {Lock} = require('bmutex');
const bdb = require('bdb');
const Logger = require('blgr');
const Block = require('../primitives/block');
const TXMeta = require('../primitives/txmeta');
const Address = require('../primitives/address');
const Network = require('../protocol/network');
const consensus = require('../protocol/consensus');
const layout = require('./layout');
const records = require('./records');
const NullClient = require('./nullclient');
const GCSFilter = require('golomb/lib/golomb');

const {
  ChainState,
  BlockMeta
} = records;

/**
 * Compact filter types.
 * @const {Number}
 * @default
 */

const FILTERS = {
  REGULAR: 0,
  EXTENDED: 1
};

/**
 * IndexDB
 * @alias module:index.IndexDB
 * @extends EventEmitter
 */

class IndexDB extends EventEmitter {
  /**
   * Create a index db.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.options = new IndexOptions(options);

    this.network = this.options.network;
    this.logger = this.options.logger.context('index');
    this.workers = this.options.workers;
    this.client = this.options.client || new NullClient(this);
    this.db = bdb.create(this.options);
    this.rescanning = false;

    this.state = new ChainState();
    this.height = 0;

    this.lock = new Lock();

    this.init();
  }

  /**
   * Initialize indexdb.
   * @private
   */

  init() {
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

    this.client.bind('block connect', async (entry, block, view) => {
      try {
        await this.addBlock(entry, block, view);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.client.bind('block disconnect', async (entry, block, view) => {
      try {
        await this.removeBlock(entry, block, view);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.client.hook('block rescan', async (entry, block, view) => {
      try {
        await this.rescanBlock(entry, block, view);
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
   * Open the indexdb, wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    await this.db.open();
    await this.db.verify(layout.V.build(), 'index', 7);

    await this.verifyNetwork();

    await this.connect();
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
      throw new Error('Network mismatch for IndexDB.');

    return undefined;
  }

  /**
   * Close the indexdb, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    await this.disconnect();
    return this.db.close();
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
    const unlock = await this.lock.lock();
    try {
      this.logger.info('Resyncing from server...');
      await this.syncState();
      await this.syncChain();
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

      this.logger.info(
        'IndexDB loaded (height=%d, start=%d).',
        this.state.height,
        this.state.startHeight);
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
    state.startHeight = 0;
    state.height = tip.height;

    b.put(layout.R.build(), state.toRaw());

    this.state = state;
    this.height = state.height;

    const genesis = this.network.genesisBlock;
    const block = Block.fromRaw(genesis, 'hex');
    const prevHash = Buffer.from(block.prevBlock, 'hex');

    // Genesis prev filter headers are defined to be zero hashes
    b.put(layout.G.build(prevHash), consensus.ZERO_HASH);
    b.put(layout.X.build(prevHash), consensus.ZERO_HASH);

    await b.write();

    await this.indexFilters(null, block, null);

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
   * Rescan a block.
   * @private
   * @param {ChainEntry} entry
   * @param {TX[]} txs
   * @returns {Promise}
   */

  async rescanBlock(entry, block, view) {
    if (!this.rescanning) {
      this.logger.warning('Unsolicited rescan block: %d.', entry.height);
      return;
    }

    if (entry.height % 1000 === 0)
      this.logger.debug('rescanned block: %d.', entry.height);

    if (entry.height > this.state.height + 1) {
      this.logger.warning('Rescan block too high: %d.', entry.height);
      return;
    }

    try {
      await this._addBlock(entry, block, view);
    } catch (e) {
      this.emit('error', e);
      throw e;
    }
  }

  /**
   * Rescan blockchain from a given height.
   * @private
   * @param {Number?} height
   * @returns {Promise}
   */

  async scan(height) {
    assert((height >>> 0) === height, 'WDB: Must pass in a height.');

    await this.rollback(height);

    if (this.state.startHeight < height)
      height = this.state.startHeight;

    const tip = this.state.height;

    this.logger.info(
      'IndexDB is scanning %d blocks.',
      tip - height + 1);

    try {
      this.rescanning = true;
      this.logger.debug('rescanning from %d to %d', height, tip);
      await this.client.rescan(height);
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
    const unlock = await this.lock.lock();
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

    state.startHeight = tip.height;

    // Save tip and state.
    b.put(layout.h.build(tip.height), tip.toHash());
    b.put(layout.R.build(), state.toRaw());

    await b.write();

    this.state = state;
    this.height = state.height;
  }

  /**
   * Get a index block meta.
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
   * Get index tip.
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
      'Rolling back %d IndexDB blocks to height %d.',
      this.state.height - height, height);

    const tip = await this.getBlock(height);
    assert(tip);

    await this.revert(tip.height);
    await this.setTip(tip);
  }

  /**
   * Index a transaction by txid.
   * @private
   * @param (ChainEntry) entry
   * @param (Block) block
   * @param (CoinView) view
   */

  async indexTX(entry, block, view) {
    if (!this.options.indexTX)
      return null;

    const b = this.db.batch();

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      const meta = TXMeta.fromTX(tx, entry, i);
      b.put(layout.t.build(hash), meta.toRaw());
    }

    return b.write();
  }

  /**
   * Remove transaction from index.
   * @private
   * @param (ChainEntry) entry
   * @param (Block) block
   * @param (CoinView) view
   */

  async unindexTX(entry, block, view) {
    if (!this.options.indexTX)
      return null;

    const b = this.db.batch();

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      b.del(layout.t.build(hash));
    }

    return b.write();
  }

  /**
   * Index a transaction by address.
   * @private
   * @param (ChainEntry) entry
   * @param (Block) block
   * @param (CoinView) view
   */

  async indexAddress(entry, block, view) {
    if (!this.options.indexAddress)
      return null;

    const b = this.db.batch();

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      for (const addr of tx.getHashes(view))
        b.put(layout.T.build(addr, hash), null);

      if (!tx.isCoinbase()) {
        for (const {prevout} of tx.inputs) {
          const {hash, index} = prevout;
          const coin = view.getOutput(prevout);
          assert(coin);

          const addr = coin.getHash();

          if (!addr)
            continue;

          b.del(layout.C.build(addr, hash, index));
        }
      }

      for (let i = 0; i < tx.outputs.length; i++) {
        const output = tx.outputs[i];
        const addr = output.getHash();

        if (!addr)
          continue;

        b.put(layout.C.build(addr, hash, i), null);
      }
    }

    return b.write();
  }

  /**
   * Remove address from index.
   * @private
   * @param (ChainEntry) entry
   * @param (Block) block
   * @param (CoinView) view
   */

  async unindexAddress(entry, block, view) {
    if (!this.options.indexAddress)
      return null;

    const b = this.db.batch();
    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];
      const hash = tx.hash();
      for (const addr of tx.getHashes(view))
        b.del(layout.T.build(addr, hash));

      if (!tx.isCoinbase()) {
        for (const {prevout} of tx.inputs) {
          const {hash, index} = prevout;
          const coin = view.getOutput(prevout);
          assert(coin);

          const addr = coin.getHash();

          if (!addr)
            continue;

          b.put(layout.C.build(addr, hash, index), null);
        }
      }

      for (let i = 0; i < tx.outputs.length; i++) {
        const output = tx.outputs[i];
        const addr = output.getHash();

        if (!addr)
          continue;

        b.del(layout.C.build(addr, hash, i));
      }
    }

    return b.write();
  }

  /**
   * Retrieve compact filter by hash and type..
   * @param {Hash} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Buffer}.
   */

  async getCFilter(hash, type) {
    assert(hash);
    assert(typeof type === 'number');

    if (!this.options.indexFilters)
      return false;

    let pair;
    switch (type) {
      case FILTERS.REGULAR:
        pair = layout.g;
        break;
      case FILTERS.EXTENDED:
        pair = layout.x;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }
    const cfilter = await this.db.get(pair.build(hash));
    assert(cfilter, `Missing cfilter ${hash.toString('hex')} ${type}.`);

    return cfilter;
  }

  /**
   * Retrieve compact filter header by hash and type..
   * @param {Hash} hash
   * @param {Number} type
   * @returns {Promise} - Returns {@link Hash}.
   */

  async getCFHeader(hash, type) {
    assert(hash);
    assert(typeof type === 'number');

    if (!this.options.indexFilters)
      return false;

    let pair;
    switch (type) {
      case FILTERS.REGULAR:
        pair = layout.G;
        break;
      case FILTERS.EXTENDED:
        pair = layout.X;
        break;
      default:
        assert(false, 'Bad filter type.');
        break;
    }
    const cfheader = await this.db.get(pair.build(hash));
    assert(cfheader, `Missing cfheader ${hash.toString('hex')} ${type}.`);

    return cfheader;
  }

  /**
   * Save compact filter for block.
   * @private
   * @param (ChainEntry) entry
   * @param (Block) block
   * @param (CoinView) view
   */

  async indexFilters(entry, block, view) {
    if (!this.options.indexFilters)
      return;

    const hash = block.hash();

    const prevBasic = await this.getCFHeader(
      Buffer.from(block.prevBlock, 'hex'),
      FILTERS.REGULAR
    );
    const prevExt = await this.getCFHeader(
      Buffer.from(block.prevBlock, 'hex'),
      FILTERS.EXTENDED
    );

    let basicRaw;
    const b = this.db.batch();
    const basic = GCSFilter.fromBlock(block);
    if (basic.data.length > 0)
      basicRaw = basic.toRaw();
    b.put(layout.g.build(hash), basicRaw);
    b.put(layout.G.build(hash), basic.header(prevBasic));

    let extRaw;
    const ext = GCSFilter.fromExtended(block);
    if (ext.data.length > 0)
      extRaw = ext.toRaw();
    b.put(layout.x.build(hash), extRaw);
    b.put(layout.X.build(hash), ext.header(prevExt));

    await b.write();
  }

  /**
   * Remove compact filter for block.
   * @private
   * @param (ChainEntry) entry
   * @param (Block) block
   * @param (CoinView) view
   */

  async unindexFilters(entry, block, view) {
    if (!this.options.indexFilters)
      return;

    const b = this.db.batch();

    const hash = block.hash();
    b.del(layout.g(hash));
    b.del(layout.x(hash));
    b.del(layout.G(hash));
    b.del(layout.X(hash));

    await b.write();
  }

  /**
   * Add a block's transactions and write the new best hash.
   * @param {ChainEntry} entry
   * @param {Block} block
   * @returns {Promise}
   */

  async addBlock(entry, block, view) {
    const unlock = await this.lock.lock();
    try {
      return await this._addBlock(entry, block, view);
    } finally {
      unlock();
    }
  }

  /**
   * Add a block's transactions without a lock.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @returns {Promise}
   */

  async _addBlock(entry, block, view) {
    const tip = BlockMeta.fromEntry(entry);

    if (tip.height >= this.network.block.slowHeight)
      this.logger.debug('Adding block: %d.', tip.height);

    await this.indexTX(entry, block, view);
    await this.indexAddress(entry, block, view);
    await this.indexFilters(entry, block, view);

    // Sync the state to the new tip.
    await this.setTip(tip);

    return;
  }

  /**
   * Unconfirm a block's transactions
   * and write the new best hash (SPV version).
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async removeBlock(entry, block, view) {
    const unlock = await this.lock.lock();
    try {
      return await this._removeBlock(entry, block, view);
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

  async _removeBlock(entry, block, view) {
    const tip = BlockMeta.fromEntry(entry);

    if (tip.height === 0)
      throw new Error('WDB: Bad disconnection (genesis block).');

    if (tip.height > this.state.height) {
      this.logger.warning(
        'IndexDB is disconnecting high blocks (%d).',
        tip.height);
      return;
    }

    if (tip.height !== this.state.height)
      throw new Error('WDB: Bad disconnection (height mismatch).');

    await this.unindexTX(entry, block,);
    await this.unindexAddress(entry, block, view);
    await this.unindexFilters(entry, block, view);

    const prev = await this.getBlock(tip.height - 1);
    assert(prev);

    // Sync the state to the previous tip.
    await this.setTip(prev);

    return;
  }

  /**
   * Get a transaction with metadata.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TXMeta}.
   */

  async getMeta(hash) {
    if (!this.options.indexTX)
      return null;

    const data = await this.db.get(layout.t.build(hash));

    if (!data)
      return null;

    return TXMeta.fromRaw(data);
  }

  /**
   * Retrieve a transaction.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TX}.
   */

  async getTX(hash) {
    const meta = await this.getMeta(hash);

    if (!meta)
      return null;

    return meta.tx;
  }

  /**
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasTX(hash) {
    if (!this.options.indexTX)
      return false;

    return this.db.has(layout.t.build(hash));
  }

  /**
   * Get all coins pertinent to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getCoinsByAddress(addrs) {
    if (!this.options.indexAddress)
      return [];

    if (!Array.isArray(addrs))
      addrs = [addrs];

    const coins = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr);

      const keys = await this.db.keys({
        gte: layout.C.min(hash),
        lte: layout.C.max(hash),
        parse: (key) => {
          const [, txid, index] = layout.C.parse(key);
          return [txid, index];
        }
      });

      for (const [hash, index] of keys) {
        const coin = await this.getCoin(hash, index);
        assert(coin);
        coins.push(coin);
      }
    }

    return coins;
  }

  /**
   * Get all transaction hashes to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link Hash}[].
   */

  async getHashesByAddress(addrs) {
    if (!this.options.indexTX || !this.options.indexAddress)
      return [];

    const hashes = Object.create(null);

    for (const addr of addrs) {
      const hash = Address.getHash(addr);

      await this.db.keys({
        gte: layout.T.min(hash),
        lte: layout.T.max(hash),
        parse: (key) => {
          const [, txid] = layout.T.parse(key);
          hashes[txid] = true;
        }
      });
    }

    return Object.keys(hashes);
  }

  /**
   * Get all transactions pertinent to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getTXByAddress(addrs) {
    const mtxs = await this.getMetaByAddress(addrs);
    const out = [];

    for (const mtx of mtxs)
      out.push(mtx.tx);

    return out;
  }

  /**
   * Get all transactions pertinent to an address.
   * @param {Address[]} addrs
   * @returns {Promise} - Returns {@link TXMeta}[].
   */

  async getMetaByAddress(addrs) {
    if (!this.options.indexTX || !this.options.indexAddress)
      return [];

    if (!Array.isArray(addrs))
      addrs = [addrs];

    const hashes = await this.getHashesByAddress(addrs);
    const mtxs = [];

    for (const hash of hashes) {
      const mtx = await this.getMeta(hash);
      assert(mtx);
      mtxs.push(mtx);
    }

    return mtxs;
  }

  /**
   * Handle a chain reset.
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async resetChain(entry) {
    const unlock = await this.lock.lock();
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
 * Index Options
 * @alias module:index.IndexOptions
 */

class IndexOptions {
  /**
   * Create index options.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = Logger.global;
    this.workers = null;
    this.client = null;

    this.prefix = null;
    this.location = null;
    this.memory = true;
    this.maxFiles = 64;
    this.cacheSize = 16 << 20;
    this.compression = true;
    this.indexTX = false;
    this.indexAddress = false;
    this.indexFilters = false;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {IndexOptions}
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

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.location = path.join(this.prefix, 'index');
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

    if (options.indexTX != null) {
      assert(typeof options.indexTX === 'boolean');
      this.indexTX = options.indexTX;
    }

    if (options.indexAddress != null) {
      assert(typeof options.indexAddress === 'boolean');
      this.indexAddress = options.indexAddress;
    }

    if (options.indexFilters != null) {
      assert(typeof options.indexFilters === 'boolean');
      this.indexFilters = options.indexFilters;
    }

    return this;
  }

  /**
   * Instantiate chain options from object.
   * @param {Object} options
   * @returns {IndexOptions}
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

/*
 * Expose
 */

module.exports = IndexDB;
