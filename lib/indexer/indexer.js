/*!
 * indexer.js - storage for indexes
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('bfile');
const bio = require('bufio');
const EventEmitter = require('events');
const Logger = require('blgr');
const Network = require('../protocol/network');
const util = require('../utils/util');
const layout = require('./layout');
const {ZERO_HASH} = require('../protocol/consensus');

/**
 * Indexer
 * @alias module:indexer.Indexer
 * @extends EventEmitter
 * @property {IndexerDB} db
 * @property {Number} height
 * @emits Indexer#chain tip
 */

class Indexer extends EventEmitter {
  /**
   * Create an indexer.
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
    this.blocks = this.options.blocks;
    this.chain = this.options.chain;

    this.db = null;
    this.batch = null;
    this.syncing = false;
    this.height = 0;
  }

  /**
   * Start a new batch write.
   * @returns {Batch}
   */

  start() {
    assert(this.batch === null, 'Already started.');
    this.batch = this.db.batch();
    return this.batch;
  }

  /**
   * Put key and value to the current batch.
   * @param {String} key
   * @param {Buffer} value
   */

  put(key, value) {
    this.batch.put(key, value);
  }

  /**
   * Delete key from the current batch.
   * @param {String} key
   */

  del(key) {
    this.batch.del(key);
  }

  /**
   * Commit the current batch.
   * @returns {Promise}
   */

  async commit() {
    await this.batch.write();
    this.batch = null;
  }

  /**
   * Open the indexer, open the database,
   * initialize height, and bind to events.
   * @returns {Promise}
   */

  async open() {
    this.logger.info('Indexer is loading.');

    await this.ensure();
    await this.db.open();
    await this.db.verify(layout.V.encode(), 'index', 0);
    await this.verifyNetwork();

    // Initialize the indexed height.
    const data = await this.db.get(layout.R.encode());
    if (data)
      this.height = bio.readU32(data, 0);

    // Bind to chain events.
    this.bind();
  }

  /**
   * Close the indexdb, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    return this.db.close();
  }

  /**
   * Ensure prefix directory (prefix/index).
   * @returns {Promise}
   */

  async ensure() {
    if (fs.unsupported)
      return;

    if (this.options.memory)
      return;

    await fs.mkdirp(this.options.prefix);
  }

  /**
   * Verify network of index.
   * @returns {Promise}
   */

  async verifyNetwork() {
    let raw = await this.db.get(layout.O.encode());

    if (!raw) {
      raw = bio.write(4).writeU32(this.network.magic).render();
      await this.db.put(layout.O.encode(), raw);
      return;
    }

    const magic = bio.readU32(raw, 0);

    if (magic !== this.network.magic)
      throw new Error('Indexer: Network mismatch.');
  }

  /**
   * Bind to chain events.
   * @private
   */

  bind() {
    this.chain.on('connect', async (entry, block, view) => {
      try {
        await this.sync(entry, block, view);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.chain.on('disconnect', async (entry, block, view) => {
      try {
        await this.sync(entry, block, view);
      } catch (e) {
        this.emit('error', e);
      }
    });

    this.chain.on('reset', async (tip) => {
      try {
        await this.sync(tip);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  /**
   * Get a chain entry for the main chain only.
   * @private
   * @returns {Promise}
   */

  async getEntry(hash) {
    const entry = await this.chain.getEntry(hash);

    if (!entry)
      return null;

    if (!await this.chain.isMainChain(entry))
      return null;

    return entry;
  }

  /**
   * Get a index block meta.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async getBlockMeta(height) {
    const data = await this.db.get(layout.h.encode(height));

    if (!data)
      return null;

    return new BlockMeta(data, height);
  }

  /**
   * Sync with the chain.
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async sync(entry, block, view) {
    if (this.syncing)
      return;

    this.syncing = true;

    const connected = await this._syncBlock(entry, block, view);

    if (connected) {
      this.syncing = false;
    } else {
      (async () => {
        await this._syncChain(entry);
        this.syncing = false;
      })();
    }
  }

  /**
   * Sync with the chain with a block.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async _syncBlock(entry, block, view) {
    // In the case that the next block is being
    // connected or the current block disconnected
    // use the block and view being passed directly,
    // instead of reading that information again.
    if (entry && block && view) {
      if (entry.height === this.height + 1) {
        await this._addBlock(entry, block, view);
        return true;
      } else if (entry.height === this.height) {
        await this._removeBlock(entry, block, view);
        return true;
      }
    }
    return false;
  }

  /**
   * Sync with the chain.
   * @private
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async _syncChain(entry) {
    let height = this.height;

    // In the case that the indexer has never
    // started, sync to the best height.
    if (!height) {
      await this._rollforward();
      return;
    }

    // Check for a re-org that might
    // leave chain in a different state.
    // Scan chain backwards until we
    // find a common height.
    for (;;) {
      const tip = await this.getBlockMeta(height);
      assert(tip);

      if (await this.getEntry(tip.hash))
        break;

      assert(height !== 0);
      height -= 1;
    }

    // In the case that the chain is reset
    // the entry will be less than the
    // current height.
    if (entry && entry.height < height)
      height = entry.height;

    if (height < this.height) {
      await this._rollback(height);
      await this._rollforward();
    } else {
      await this._rollforward();
    }
  }

  /**
   * Scan blockchain to the best chain height.
   * @private
   * @returns {Promise}
   */

  async _rollforward() {
    this.logger.info('Indexing to best height.');

    for (let i = this.height + 1; ; i++) {
      const entry = await this.getEntry(i);
      if (!entry)
        break;

      const block = await this.chain.getBlock(entry.hash);
      assert(block);

      const view = await this.chain.getBlockView(block);
      assert(view);

      await this._addBlock(entry, block, view);
    }
  }

  /**
   * Rollback to a given chain height.
   * @param {Number} height
   * @returns {Promise}
   */

  async _rollback(height) {
    if (height > this.height) {
      this.logger.warning(
        'Ignoring rollback to future height (%d).',
        height);
      return;
    }

    this.logger.info('Rolling back to height %d.', height);

    while (this.height > height) {
      const tip = await this.getBlockMeta(this.height);
      assert(tip);

      const entry = await this.chain.getEntry(tip.hash);
      assert(entry);

      const block = await this.chain.getBlock(entry.hash);
      assert(block);

      const view = await this.chain.getBlockView(block);
      assert(view);

      await this._removeBlock(entry, block, view);
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
    assert(block.hasRaw(), 'Expected raw data for block.');

    const start = util.bench();

    if (entry.height !== this.height + 1)
      throw new Error('Indexer: Can not add block.');

    const tip = new BlockMeta(entry.hash, entry.height);

    // Start the batch write.
    this.start();

    // Call the implemented indexer to add to
    // the batch write.
    await this.indexBlock(entry, block, view);

    // Sync the height to the new tip.
    const height = await this._setTip(tip);

    // Commit the write batch to disk.
    await this.commit();

    // Update height _after_ successful commit.
    this.height = height;

    // Log the current indexer status.
    this.logStatus(start, block, entry);
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
   * Unconfirm a block's transactions.
   * @private
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async _removeBlock(entry, block, view) {
    const start = util.bench();

    if (entry.height !== this.height)
      throw new Error('Indexer: Can not remove block.');

    const tip = new BlockMeta(entry.hash, entry.height);

    // Start the batch write.
    this.start();

    // Call the implemented indexer to add to
    // the batch write.
    await this.unindexBlock(entry, block, view);

    const prev = await this.getBlockMeta(tip.height - 1);
    assert(prev);

    // Sync the height to the previous tip.
    const height = await this._setTip(prev);

    // Commit the write batch to disk.
    await this.commit();

    // Update height _after_ successful commit.
    this.height = height;

    // Log the current indexer status.
    this.logStatus(start, block, entry);
  }

  /**
   * Update the current height to tip.
   * @param {BlockMeta} tip
   * @returns {Promise}
   */

  async _setTip(tip) {
    if (tip.height < this.height) {
      assert(tip.height === this.height - 1);
      this.del(layout.h.encode(this.height));
    } else if (tip.height > this.height) {
      assert(tip.height === this.height + 1);
    }

    // Add to batch write to save tip and height.
    this.put(layout.h.encode(tip.height), tip.hash);

    const raw = bio.write(4).writeU32(tip.height).render();
    this.put(layout.R.encode(), raw);

    return tip.height;
  }

  /**
   * Test whether the indexer has reached its slow height.
   * @private
   * @returns {Boolean}
   */

  isSlow() {
    if (this.height === 1 || this.height % 20 === 0)
      return true;

    if (this.height >= this.network.block.slowHeight)
      return true;

    return false;
  }

  /**
   * Log the current indexer status.
   * @private
   * @param {Array} start
   * @param {Block} block
   * @param {ChainEntry} entry
   */

  logStatus(start, block, entry) {
    if (!this.isSlow())
      return;

    const elapsed = util.bench(start);

    this.logger.info(
      'Block (%d) added to indexer (txs=%d time=%d).',
      entry.height,
      block.txs.length,
      elapsed);
  }
}

/**
 * Block Meta
 */

class BlockMeta {
  constructor(hash, height) {
    this.hash = hash || ZERO_HASH;
    this.height =  height || 0;

    assert(Buffer.isBuffer(this.hash) && this.hash.length === 32);
    assert(Number.isInteger(this.height));
  }
}

/**
 * Index Options
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
    this.blocks = null;
    this.chain = null;

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
    assert(options.blocks && typeof options.blocks === 'object',
           'Indexer requires a blockstore.');
    assert(options.chain && typeof options.chain === 'object',
           'Indexer requires chain.');

    this.blocks = options.blocks;
    this.chain = options.chain;

    if (options.network != null)
      this.network = Network.get(options.network);

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
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
   * Instantiate indexer options from object.
   * @param {Object} options
   * @returns {IndexOptions}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
}

/*
 * Expose
 */

module.exports = Indexer;
