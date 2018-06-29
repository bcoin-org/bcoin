/*!
 * indexer.js - storage for indexes
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('bfile');
const EventEmitter = require('events');
const {Lock} = require('bmutex');
const Logger = require('blgr');
const Network = require('../protocol/network');
const layout = require('./layout');
const records = require('./records');
const ChainClient = require('./chainclient');
const NullClient = require('./nullclient');

const {
  ChainState,
  BlockMeta
} = records;

/**
 * Indexer
 * @alias module:indexer.Indexer
 * @extends EventEmitter
 * @property {IndexerDB} db
 * @property {Number} height
 * @property {ChainState} state
 * @emits Indexer#chain tip
 */

class Indexer extends EventEmitter {
  /**
   * Create a index db.
   * @constructor
   * @param {String} module
   * @param {Object} options
   */

  constructor(module, options) {
    super();

    assert(typeof module === 'string');
    assert(module.length > 0);

    this.options = new IndexOptions(module, options);

    this.network = this.options.network;
    this.logger = this.options.logger.context(`${module}indexer`);
    this.client = this.options.client || new NullClient(this);
    this.db = null;
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
   * Bind to chain events.
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

    this.client.on('block connect', async (entry, block, view) => {
      if (this.rescanning)
        return;
      try {
        await this.addBlock(entry, block, view);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.client.on('block disconnect', async (entry, block, view) => {
      if (this.rescanning)
        return;
      try {
        await this.removeBlock(entry, block, view);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.client.on('block rescan', async (entry, block, view) => {
      try {
        await this.rescanBlock(entry, block, view);
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

    this.client.on('chain tip', async () => {
      this.logger.debug('Indexer: finished rescan');
      const tip = await this.getTip();
      this.emit('chain tip', tip);
    });
  }

  /**
   * Ensure prefix directory (prefix/index).
   * @returns {Promise}
   */

  async ensure() {
    if (fs.unsupported)
      return undefined;

    if (this.options.memory)
      return undefined;

    return fs.mkdirp(this.options.prefix);
  }

  /**
   * Open the indexdb, wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    await this.ensure();
    await this.db.open();
    await this.db.verify(layout.V.encode(), 'index', 0);

    await this.verifyNetwork();

    await this.connect();
  }

  /**
   * Verify network.
   * @returns {Promise}
   */

  async verifyNetwork() {
    const raw = await this.db.get(layout.O.encode());

    if (!raw) {
      const b = this.db.batch();
      b.put(layout.O.encode(), fromU32(this.network.magic));
      return b.write();
    }

    const magic = raw.readUInt32LE(0, true);

    if (magic !== this.network.magic)
      throw new Error('Network mismatch for Indexer.');

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
   * Connect to the chain server (client required).
   * @returns {Promise}
   */

  async connect() {
    return this.client.open();
  }

  /**
   * Disconnect from chain server (client required).
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
      this.state = cache;
      this.height = cache.height;

      this.logger.info(
        'Indexer loaded (height=%d, start=%d).',
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
      b.put(layout.h.encode(height), meta.toHash());
      tip = meta;
    }

    assert(tip);

    const state = this.state.clone();
    state.startHeight = 0;
    state.height = tip.height;

    b.put(layout.R.encode(), state.toRaw());

    await b.write();

    this.state = state;
    this.height = state.height;

    return undefined;
  }

  /**
   * Connect and sync with the chain server.
   * @private
   * @returns {Promise}
   */

  async syncChain() {
    let height = this.state.height;

    this.logger.info('Syncing state from height %d.', height);

    // re-org when we're offline might
    // leave chain in different state.
    // scan chain backwards until we
    // find a known 'good' height
    for (;;) {
      const tip = await this.getBlock(height);
      assert(tip);

      if (await this.client.getEntry(tip.hash))
        break;

      assert(height !== 0);
      height -= 1;
    }

    // start scan from last indexed OR
    // last known 'good' height whichever
    // is lower, because `scan` scans from
    // low to high blocks
    if (this.state.startHeight < height)
      height = this.state.startHeight;

    this.logger.spam('Starting block rescan from: %d.', height);
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
    this.logger.spam('Rescanning block: %d.', entry.height);

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
    assert((height >>> 0) === height, 'Indexer: Must pass in a height.');

    await this.rollback(height);

    const tip = this.state.height;

    this.logger.info(
      'Indexer is scanning %d blocks.',
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
    const data = await this.db.get(layout.R.encode());

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
        b.del(layout.h.encode(state.height));
        state.height -= 1;
      }
    } else if (tip.height > state.height) {
      assert(tip.height === state.height + 1, 'Bad chain sync.');
      state.height += 1;
    }

    state.startHeight = tip.height;

    // Save tip and state.
    b.put(layout.h.encode(tip.height), tip.toHash());
    b.put(layout.R.encode(), state.toRaw());

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
    const data = await this.db.get(layout.h.encode(height));

    if (!data)
      return null;

    const block = new BlockMeta();
    block.hash = data;
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
      throw new Error('Indexer: Tip not found!');

    return tip;
  }

  /**
   * Sync with chain height.
   * @param {Number} height
   * @returns {Promise}
   */

  async rollback(height) {
    if (height > this.state.height)
      throw new Error('Indexer: Cannot rollback to the future.');

    if (height === this.state.height) {
      this.logger.info('Rolled back to same height (%d).', height);
      return;
    }

    this.logger.info(
      'Rolling back %d Indexer blocks to height %d.',
      this.state.height - height, height);

    const tip = await this.getBlock(height);
    assert(tip);

    await this.revert(tip.height);
    await this.setTip(tip);
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

    if (tip.height >= this.network.block.slowHeight && !this.rescanning)
      this.logger.debug('Adding block: %d.', tip.height);

    this.logger.spam('Adding block: %d.', entry.height);

    if (tip.height === this.state.height) {
      // We let blocks of the same height
      // through specifically for rescans:
      // we always want to rescan the last
      // block since the state may have
      // updated before the block was fully
      // processed (in the case of a crash).
      this.logger.warning('Already saw Indexer block (%d).', tip.height);
    } else if (tip.height !== this.state.startHeight + 1) {
      await this.scan(this.state.height);
      return;
    }

    this.logger.spam('Indexing block: %d.', entry.height);

    await this.indexBlock(entry, block, view);

    // Sync the state to the new tip.
    await this.setTip(tip);

    return;
  }

  /**
   * Process block indexing
   * Indexers will implement this method to process the block for indexing
   * @param {ChainEntry} entry
   * @param {Block} block
   * @returns {Promise}
   */

  async indexBlock(entry, block, view) {
    ;
  }

  /**
   * Undo block indexing
   * Indexers will implement this method to undo indexing for the block
   * @param {ChainEntry} entry
   * @param {Block} block
   * @returns {Promise}
   */

  async unindexBlock(entry, block, view) {
    ;
  }

  /**
   * Revert db to an older state.
   * @param {Number} target
   * @returns {Promise}
   */

  async revert(target) {
    ;
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

    this.logger.spam('Removing block: %d.', entry.height);

    if (tip.height === 0)
      throw new Error('Indexer: Bad disconnection (genesis block).');

    if (tip.height > this.state.height) {
      this.logger.warning(
        'Indexer is disconnecting high blocks (%d).',
        tip.height);
      return;
    }

    if (tip.height !== this.state.height)
      throw new Error('Indexer: Bad disconnection (height mismatch).');

    this.logger.spam('Unindexing block: %d.', entry.height);

    await this.unindexBlock(entry, block, view);

    const prev = await this.getBlock(tip.height - 1);
    assert(prev);

    // Sync the state to the previous tip.
    await this.setTip(prev);

    return;
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
      throw new Error('Indexer: Bad reset height.');

    return this.rollback(entry.height);
  }
}

/**
 * Index Options
 * @alias module:indexer.IndexOptions
 */

class IndexOptions {
  /**
   * Create index options.
   * @constructor
   * @param {String} module
   * @param {Object} options
   */

  constructor(module, options) {
    this.module = module;
    this.network = Network.primary;
    this.logger = Logger.global;
    this.client = null;
    this.chain = null;
    this.indexers = null;

    this.prefix = null;
    this.location = null;
    this.memory = true;
    this.maxFiles = 64;
    this.cacheSize = 16 << 20;
    this.compression = true;

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

    if (options.client != null) {
      assert(typeof options.client === 'object');
      this.client = options.client;
    }

    if (options.chain != null) {
      assert(typeof options.chain === 'object');
      this.client = new ChainClient(options.chain);
    }

    if (!this.client) {
      throw new Error('Client is required');
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.prefix = path.join(this.prefix, 'index');
      this.location = path.join(this.prefix, this.module);
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

/**
 * fromU32
 * read a 4 byte Uint32LE
 * @param {Number} num number
 * @returns {Buffer} buffer
 */
function fromU32(num) {
  const data = Buffer.allocUnsafe(4);
  data.writeUInt32LE(num, 0, true);
  return data;
}

/*
 * Expose
 */

module.exports = Indexer;
