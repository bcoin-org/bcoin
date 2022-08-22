/*!
 * indexer.js - abstract interface for bcoin indexers
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
const CoinView = require('../coins/coinview');
const Block = require('../primitives/block');
const {ZERO_HASH} = require('../protocol/consensus');

/**
 * Indexer
 * The class which indexers inherit from and implement the
 * `indexBlock` and `unindexBlock` methods and database
 * and storage initialization for indexing blocks.
 * @alias module:indexer.Indexer
 * @extends EventEmitter
 * @abstract
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

    this.closing = false;
    this.db = null;
    this.batch = null;
    this.bound = [];
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

    this.closing = false;
    await this.ensure();
    await this.db.open();
    await this.db.verify(layout.V.encode(), 'index', 1);
    await this.verifyNetwork();

    // Initialize the indexed height.
    const data = await this.db.get(layout.R.encode());
    if (data)
      this.height = bio.readU32(data, 0);
    else
      await this.saveGenesis();

    // Bind to chain events.
    this.bind();
  }

  /**
   * Close the indexer, wait for the database to close,
   * unbind all events.
   * @returns {Promise}
   */

  async close() {
    this.closing = true;
    await this.db.close();
    for (const [event, listener] of this.bound)
      this.chain.removeListener(event, listener);

    this.bound.length = 0;
    this.closing = false;
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

    await fs.mkdirp(this.options.location);
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
   * A special case for indexing the genesis block. The genesis
   * block coins are not spendable, however indexers can still index
   * the block for historical and informational purposes.
   * @private
   * @returns {Promise}
   */

  async saveGenesis() {
    this.start();

    const block = Block.fromRaw(Buffer.from(this.network.genesisBlock, 'hex'));
    const meta = new BlockMeta(block.hash(), 0);

    await this.indexBlock(meta, block, new CoinView());
    await this._setTip(meta);
    await this.commit();

    this.height = 0;
  }

  /**
   * Bind to chain events and save listeners for removal on close
   * @private
   */

  bind() {
    const listener = async (entry, block, view) => {
      const meta = new BlockMeta(entry.hash, entry.height);

      try {
        await this.sync(meta, block, view);
      } catch (e) {
        this.emit('error', e);
      }
    };

    for (const event of ['connect', 'disconnect', 'reset']) {
      this.bound.push([event, listener]);
      this.chain.on(event, listener);
    }
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
   * @param {Number} height
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
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async sync(meta, block, view) {
    if (this.syncing)
      return;

    this.syncing = true;

    const connected = await this._syncBlock(meta, block, view);

    if (connected) {
      this.syncing = false;
    } else {
      (async () => {
        try {
          await this._syncChain();
        } catch (e) {
          this.emit('error', e);
        } finally {
          this.syncing = false;
        }
      })();
    }
  }

  /**
   * Sync with the chain with a block.
   * @private
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async _syncBlock(meta, block, view) {
    // In the case that the next block is being
    // connected or the current block disconnected
    // use the block and view being passed directly,
    // instead of reading that information again.
    if (meta && block && view) {
      if (meta.height === this.height + 1) {
        // Make sure that the block is connected to
        // the indexer chain.
        const prev = await this.getBlockMeta(this.height);
        if (prev.hash.compare(block.prevBlock) !== 0)
          return false;

        await this._addBlock(meta, block, view);
        return true;
      } else if (meta.height === this.height) {
        // Make sure that this is the current block.
        const current = await this.getBlockMeta(this.height);
        if (current.hash.compare(block.hash()) !== 0)
          return false;

        await this._removeBlock(meta, block, view);
        return true;
      }
    }
    return false;
  }

  /**
   * Sync with the chain.
   * @private
   * @returns {Promise}
   */

  async _syncChain() {
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
    while (height > 0) {
      const meta = await this.getBlockMeta(height);
      assert(meta);

      if (await this.getEntry(meta.hash))
        break;

      height -= 1;
    }

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
    this.logger.info('Indexing to best height from height (%d).', this.height);

    for (let height = this.height + 1; ; height++) {
      const entry = await this.getEntry(height);
      if (!entry)
        break;

      const meta = new BlockMeta(entry.hash, height);

      const block = await this.chain.getBlock(entry.hash);
      assert(block);

      const view = await this.chain.getBlockView(block);
      assert(view);

      if (this.closing)
        return;

      await this._addBlock(meta, block, view);
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

    while (this.height > height && this.height > 1) {
      const meta = await this.getBlockMeta(this.height);
      assert(meta);

      const block = await this.chain.getBlock(meta.hash);
      assert(block);

      const view = await this.chain.getBlockView(block);
      assert(view);

      await this._removeBlock(meta, block, view);
    }
  }

  /**
   * Add a block's transactions without a lock.
   * @private
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async _addBlock(meta, block, view) {
    const start = util.bench();

    if (meta.height !== this.height + 1)
      throw new Error('Indexer: Can not add block.');

    // Start the batch write.
    this.start();

    // Call the implemented indexer to add to
    // the batch write.
    await this.indexBlock(meta, block, view);

    // Sync the height to the new tip.
    const height = await this._setTip(meta);

    // Commit the write batch to disk.
    await this.commit();

    // Update height _after_ successful commit.
    this.height = height;

    // Log the current indexer status.
    this.logStatus(start, block, meta);
  }

  /**
   * Process block indexing
   * Indexers will implement this method to process the block for indexing
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async indexBlock(meta, block, view) {
    ;
  }

  /**
   * Undo block indexing
   * Indexers will implement this method to undo indexing for the block
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async unindexBlock(meta, block, view) {
    ;
  }

  /**
   * Prune block indexing
   * Indexers will implement this method to prune indexing for the block
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async pruneBlock(meta, block, view) {
    ;
  }

  /**
   * Unconfirm a block's transactions.
   * @private
   * @param {BlockMeta} meta
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async _removeBlock(meta, block, view) {
    const start = util.bench();

    if (meta.height !== this.height)
      throw new Error('Indexer: Can not remove block.');

    // Start the batch write.
    this.start();

    // Call the implemented indexer to add to
    // the batch write.
    await this.unindexBlock(meta, block, view);

    const prev = await this.getBlockMeta(meta.height - 1);
    assert(prev);

    // Sync the height to the previous tip.
    const height = await this._setTip(prev);

    // Commit the write batch to disk.
    await this.commit();

    // Prune block data _after_ successful commit.
    await this.pruneBlock(meta);

    // Update height _after_ successful commit.
    this.height = height;

    // Log the current indexer status.
    this.logStatus(start, block, meta, true);
  }

  /**
   * Update the current height to tip.
   * @param {BlockMeta} meta
   * @returns {Promise}
   */

  async _setTip(meta) {
    if (meta.height < this.height) {
      assert(meta.height === this.height - 1);
      this.del(layout.h.encode(this.height));
    } else if (meta.height > this.height) {
      assert(meta.height === this.height + 1);
    }

    // Add to batch write to save tip and height.
    this.put(layout.h.encode(meta.height), meta.hash);

    const raw = bio.write(4).writeU32(meta.height).render();
    this.put(layout.R.encode(), raw);

    return meta.height;
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
   * @param {BlockMeta} meta
   * @param {Boolean} reverse
   */

  logStatus(start, block, meta, reverse) {
    if (!this.isSlow())
      return;

    const elapsed = util.bench(start);

    const msg = reverse ? 'removed from' : 'added to';

    this.logger.info(
      'Block (%d) %s indexer (txs=%d time=%d).',
      meta.height,
      msg,
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
    assert(!options.prune, 'Can not index while pruned.');

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
