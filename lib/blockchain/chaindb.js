/*!
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bdb = require('bdb');
const bio = require('bufio');
const {encoding} = bio;
const LRU = require('blru');
const {BufferMap} = require('buffer-map');
const {BloomFilter} = require('bfilter');
const Amount = require('../btc/amount');
const Network = require('../protocol/network');
const CoinView = require('../coins/coinview');
const UndoCoins = require('../coins/undocoins');
const layout = require('./layout');
const consensus = require('../protocol/consensus');
const Block = require('../primitives/block');
const MerkleBlock = require('../primitives/merkleblock');
const Outpoint = require('../primitives/outpoint');
const ChainEntry = require('./chainentry');
const CoinEntry = require('../coins/coinentry');

/**
 * ChainDB
 * @alias module:blockchain.ChainDB
 */

class ChainDB {
  /**
   * Create a chaindb.
   * @constructor
   */

  constructor(options) {
    this.options = options;
    this.network = this.options.network;
    this.logger = this.options.logger.context('chaindb');
    this.blocks = this.options.blocks;

    this.db = bdb.create(this.options);

    this.stateCache = new StateCache(this.network);
    this.state = new ChainState();
    this.pending = null;
    this.current = null;

    this.cacheHash = new LRU(this.options.entryCache, null, BufferMap);
    this.cacheHeight = new LRU(this.options.entryCache);
    this.cacheInvalid = new LRU(100, null, BufferMap);

    this.mostWork = null;
  }

  /**
   * Open and wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    this.logger.info('Opening ChainDB...');

    await this.db.open();
    await this.db.verify(layout.V.encode(), 'chain', 7);

    const state = await this.getState();

    if (state) {
      // Verify options have not changed.
      await this.verifyFlags(state);

      // Verify deployment params have not changed.
      await this.verifyDeployments();

      // Load state caches.
      this.stateCache = await this.getStateCache();

      // Grab the chainstate if we have one.
      this.state = state;

      this.logger.info('ChainDB successfully loaded.');
    } else {
      // Database is fresh.
      // Write initial state.
      await this.saveFlags();
      await this.saveDeployments();
      await this.saveGenesis();

      this.logger.info('ChainDB successfully initialized.');
    }

    // Load in-memory most work entry.
    await this.setMostWork();

    this.logger.info(
      'Chain State: hash=%h tx=%d coin=%d value=%s.',
      this.state.tip,
      this.state.tx,
      this.state.coin,
      Amount.btc(this.state.value));
  }

  /**
   * Close and wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    return this.db.close();
  }

  /**
   * Start a batch.
   * @returns {Batch}
   */

  start() {
    assert(!this.current);
    assert(!this.pending);

    this.current = this.db.batch();
    this.pending = this.state.clone();

    this.cacheHash.start();
    this.cacheHeight.start();
    this.cacheInvalid.start();

    return this.current;
  }

  /**
   * Put key and value to current batch.
   * @param {String} key
   * @param {Buffer} value
   */

  put(key, value) {
    assert(this.current);
    this.current.put(key, value);
  }

  /**
   * Delete key from current batch.
   * @param {String} key
   */

  del(key) {
    assert(this.current);
    this.current.del(key);
  }

  /**
   * Get current batch.
   * @returns {Batch}
   */

  batch() {
    assert(this.current);
    return this.current;
  }

  /**
   * Drop current batch.
   * @returns {Batch}
   */

  drop() {
    const batch = this.current;

    assert(this.current);
    assert(this.pending);

    this.current = null;
    this.pending = null;

    this.cacheHash.drop();
    this.cacheHeight.drop();
    this.cacheInvalid.drop();
    this.stateCache.drop();

    batch.clear();
  }

  /**
   * Commit current batch.
   * @returns {Promise}
   */

  async commit() {
    assert(this.current);
    assert(this.pending);

    try {
      await this.current.write();
    } catch (e) {
      this.current = null;
      this.pending = null;
      this.cacheHash.drop();
      this.cacheHeight.drop();
      this.cacheInvalid.drop();
      throw e;
    }

    // Overwrite the entire state
    // with our new best state
    // only if it is committed.
    // Note that alternate chain
    // tips do not commit anything.
    if (this.pending.committed)
      this.state = this.pending;

    this.current = null;
    this.pending = null;

    this.cacheHash.commit();
    this.cacheHeight.commit();
    this.cacheInvalid.commit();
    this.stateCache.commit();
  }

  /**
   * Test the cache for a present entry hash or height.
   * @param {Hash|Number} block - Hash or height.
   */

  hasCache(block) {
    if (typeof block === 'number')
      return this.cacheHeight.has(block);

    assert(Buffer.isBuffer(block));

    return this.cacheHash.has(block);
  }

  /**
   * Get an entry directly from the LRU cache.
   * @param {Hash|Number} block - Hash or height.
   */

  getCache(block) {
    if (typeof block === 'number')
      return this.cacheHeight.get(block);

    assert(Buffer.isBuffer(block));

    return this.cacheHash.get(block);
  }

  /**
   * Get the height of a block by hash.
   * @param {Hash} hash
   * @returns {Promise} - Returns Number.
   */

  async getHeight(hash) {
    if (typeof hash === 'number')
      return hash;

    assert(Buffer.isBuffer(hash));

    if (hash.equals(consensus.ZERO_HASH))
      return -1;

    const entry = this.cacheHash.get(hash);

    if (entry)
      return entry.height;

    const height = await this.db.get(layout.h.encode(hash));

    if (!height)
      return -1;

    return height.readUInt32LE(0, true);
  }

  /**
   * Get the hash of a block by height. Note that this
   * will only return hashes in the main chain.
   * @param {Number} height
   * @returns {Promise} - Returns {@link Hash}.
   */

  async getHash(height) {
    if (Buffer.isBuffer(height))
      return height;

    assert(typeof height === 'number');

    if (height < 0)
      return null;

    const entry = this.cacheHeight.get(height);

    if (entry)
      return entry.hash;

    return this.db.get(layout.H.encode(height));
  }

  /**
   * Retrieve a chain entry by height.
   * @param {Number} height
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  async getEntryByHeight(height) {
    assert(typeof height === 'number');

    if (height < 0)
      return null;

    const cache = this.cacheHeight.get(height);

    if (cache)
      return cache;

    const hash = await this.db.get(layout.H.encode(height));

    if (!hash)
      return null;

    const state = this.state;
    const entry = await this.getEntryByHash(hash);

    if (!entry)
      return null;

    // By the time getEntry has completed,
    // a reorg may have occurred. This entry
    // may not be on the main chain anymore.
    if (this.state === state)
      this.cacheHeight.set(entry.height, entry);

    return entry;
  }

  /**
   * Retrieve a chain entry by hash.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  async getEntryByHash(hash) {
    assert(Buffer.isBuffer(hash));

    if (hash.equals(consensus.ZERO_HASH))
      return null;

    const cache = this.cacheHash.get(hash);

    if (cache)
      return cache;

    const raw = await this.db.get(layout.e.encode(hash));

    if (!raw)
      return null;

    const entry = ChainEntry.fromRaw(raw);

    // There's no efficient way to check whether
    // this is in the main chain or not, so
    // don't add it to the height cache.
    this.cacheHash.set(entry.hash, entry);

    return entry;
  }

  /**
   * Retrieve a chain entry.
   * @param {Number|Hash} block - Height or hash.
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  getEntry(block) {
    if (typeof block === 'number')
      return this.getEntryByHeight(block);
    return this.getEntryByHash(block);
  }

  /**
   * Test whether the chain has a header entry.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasHeader(hash) {
    return this.db.has(layout.e.encode(hash));
  }

  /**
   * Determine the height for a skip entry to jump back.
   * @param {Number} height
   * @returns {Promise} - Returns Number.
   */

  static getSkipHeight(height) {
    if (height < 2)
      return 0;

    // Flip the lowest 1 bit (in binary) to 0.
    const flipLow = n =>  n & (n - 1);

    if (height & 1) {
      return flipLow(flipLow(height - 1)) + 1;
    } else {
      return flipLow(height);
    }
  }

  /**
   * Get skip entry for an entry.
   * @param {Number} height
   * @returns {Promise} - Returns Number.
   */

  async getSkip(entry) {
    return this.getAncestor(entry, ChainDB.getSkipHeight(entry.height));
  }

  /**
   * Get ancestor by `height`.
   * @param {ChainEntry} entry
   * @param {Number} height
   * @returns {Promise} - Returns ChainEntry.
   */

  async getAncestor(entry, height) {
    if (height < 0)
      return null;

    assert(height >= 0);
    assert(height <= entry.height);

    if (await this.isMainChain(entry))
      return this.getEntryByHeight(height);

    while (entry.height !== height) {
      const skip = ChainDB.getSkipHeight(entry.height);
      const prev = ChainDB.getSkipHeight(entry.height - 1);

      const skipBetter = skip > height;
      const prevBetter = prev < skip - 2 && prev >= height;

      const hash = await this.db.get(layout.s.encode(entry.hash));

      if (hash && (skip === height || (skipBetter && !prevBetter))) {
        entry = await this.getEntry(hash);
      } else {
        const cache = this.getPrevCache(entry);

        if (cache)
          entry = cache;
        else
          entry = await this.getPrevious(entry);
      }
      assert(entry);
    }

    return entry;
  }

  /**
   * Get previous entry.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns ChainEntry.
   */

  getPrevious(entry) {
    return this.getEntryByHash(entry.prevBlock);
  }

  /**
   * Get previous cached entry.
   * @param {ChainEntry} entry
   * @returns {ChainEntry|null}
   */

  getPrevCache(entry) {
    return this.cacheHash.get(entry.prevBlock) || null;
  }

  /**
   * Get next entry.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns ChainEntry.
   */

  async getNext(entry) {
    const hash = await this.getNextHash(entry.hash);

    if (!hash)
      return null;

    return this.getEntryByHash(hash);
  }

  /**
   * Get next entry.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns ChainEntry.
   */

  async getNextEntry(entry) {
    const next = await this.getEntryByHeight(entry.height + 1);

    if (!next)
      return null;

    // Not on main chain.
    if (!next.prevBlock.equals(entry.hash))
      return null;

    return next;
  }

  /**
   * Will get an array of next entries that branch from
   * this entry (main and non-main).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link ChainEntry}[].
   */

  async getNextEntries(hash) {
    const hashes = await this.getNextHashes(hash);
    const entries = [];

    for (const hash of hashes)
      entries.push(await this.getEntryByHash(hash));

    return entries;
  }

  /**
   * This will get a number of the next block entries. Will
   * work on main and non-main chains.
   * @param {ChainEntry} entry - The chain tip.
   * @param {Number} height - The start height.
   * @param {Number} limit - The max number of entries.
   * @returns {Promise} - Returns {@link ChainEntry}[].
   */
  async getNextPath(entry, height, limit) {
    const entries = [];

    if (height < 0 || limit <= 0)
      return entries;

    const start = height + limit;

    if (start < entry.height)
      entry = await this.getAncestor(entry, start);

    while (entry.height > height) {
      entries.unshift(entry);
      entry = await this.getPrevious(entry);
    }

    return entries;
  }

  /**
   * Will get an array of next entry hashes that branch
   * from this entry (main and non-main).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Hash}[].
   */

  async getNextHashes(hash) {
    const raw = await this.db.get(layout.r.encode(hash));

    const hashes = [];

    if (raw) {
      const br = bio.read(raw);
      const len = br.readVarint();

      for (let i = 0; i < len; i++)
        hashes.push(br.readBytes(32));
    }

    return hashes;
  }

  /**
   * Will queue a write of references of next entries that branch
   * from this entry (main and non-main).
   * @param {Hash} hash
   * @param {Hash} next
   * @returns {Promise}
   */

  putNextHashes(hash, hashes) {
    let size = encoding.sizeVarint(hashes.length);
    size += 32 * hashes.length;

    const raw = bio.write(size);
    raw.writeVarint(hashes.length);
    for (const hash of hashes)
      raw.writeBytes(hash);

    return this.put(layout.r.encode(hash), raw.render());
  }

  /**
   * Will queue delete of an array of next entries that
   * branch from this entry (main and non-main).
   * @param {Hash} hash
   * @param {Hash} next
   * @returns {Promise}
   */

  deleteNextHashes(hash) {
    return this.del(layout.r.encode(hash));
  }

  /**
   * Retrieve the tip entry from the tip record.
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  getTip() {
    return this.getEntryByHash(this.state.tip);
  }

  /**
   * Retrieve the tip entry from the tip record.
   * @returns {Promise} - Returns {@link ChainState}.
   */

  async getState() {
    const data = await this.db.get(layout.R.encode());

    if (!data)
      return null;

    return ChainState.fromRaw(data);
  }

  /**
   * Write genesis block to database.
   * @returns {Promise}
   */

  async saveGenesis() {
    const genesis = this.network.genesisBlock;
    const block = Block.fromRaw(genesis, 'hex');
    const entry = ChainEntry.fromBlock(block);

    this.logger.info('Writing genesis block to ChainDB.');

    // Save the header entry.
    await this.saveEntry(entry, new ChainEntry());

    // Save the block.
    if (this.options.spv)
      await this.writeBlock(block.toMerkle(new BloomFilter()));
    else
      await this.writeBlock(block);

    // Connect to the main chain.
    return this.connect(entry, block, new CoinView());
  }

  /**
   * Retrieve the database flags.
   * @returns {Promise} - Returns {@link ChainFlags}.
   */

  async getFlags() {
    const data = await this.db.get(layout.O.encode());

    if (!data)
      return null;

    return ChainFlags.fromRaw(data);
  }

  /**
   * Verify current options against db options.
   * @param {ChainState} state
   * @returns {Promise}
   */

  async verifyFlags(state) {
    const options = this.options;
    const flags = await this.getFlags();

    let needsSave = false;
    let needsPrune = false;

    if (!flags)
      throw new Error('No flags found.');

    if (options.network !== flags.network)
      throw new Error('Network mismatch for chain.');

    if (options.spv && !flags.spv)
      throw new Error('Cannot retroactively enable SPV.');

    if (!options.spv && flags.spv)
      throw new Error('Cannot retroactively disable SPV.');

    if (!flags.witness) {
      if (!options.forceFlags)
        throw new Error('Cannot retroactively enable witness.');
      needsSave = true;
    }

    if (options.bip91 !== flags.bip91) {
      if (!options.forceFlags)
        throw new Error('Cannot retroactively alter BIP91 flag.');
      needsSave = true;
    }

    if (options.bip148 !== flags.bip148) {
      if (!options.forceFlags)
        throw new Error('Cannot retroactively alter BIP148 flag.');
      needsSave = true;
    }

    if (options.prune && !flags.prune) {
      if (!options.forceFlags)
        throw new Error('Cannot retroactively prune.');
      needsPrune = true;
    }

    if (!options.prune && flags.prune)
      throw new Error('Cannot retroactively unprune.');

    if (needsSave) {
      await this.logger.info('Rewriting chain flags.');
      await this.saveFlags();
    }

    if (needsPrune) {
      await this.logger.info('Retroactively pruning chain.');
      await this.prune(state.tip);
    }
  }

  /**
   * Get state caches.
   * @returns {Promise} - Returns {@link StateCache}.
   */

  async getStateCache() {
    const stateCache = new StateCache(this.network);

    const items = await this.db.range({
      gte: layout.v.min(),
      lte: layout.v.max(),
      values: true
    });

    for (const item of items) {
      const [bit, hash] = layout.v.decode(item.key);
      const state = item.value[0];
      stateCache.insert(bit, hash, state);
    }

    return stateCache;
  }

  /**
   * Save deployment table.
   * @returns {Promise}
   */

  saveDeployments() {
    const b = this.db.batch();
    this.writeDeployments(b);
    return b.write();
  }

  /**
   * Save deployment table.
   * @returns {Promise}
   */

  writeDeployments(b) {
    const bw = bio.write(1 + 21 * this.network.deploys.length);

    bw.writeU8(this.network.deploys.length);

    for (const deployment of this.network.deploys) {
      bw.writeU8(deployment.bit);
      bw.writeI64(deployment.startTime);
      bw.writeU32(deployment.timeout);
      bw.writeI32(deployment.threshold);
      bw.writeI32(deployment.window);
    }

    b.put(layout.D.encode(), bw.render());
  }

  /**
   * Check for outdated deployments.
   * @private
   * @returns {Promise}
   */

  async checkDeployments() {
    const raw = await this.db.get(layout.D.encode());

    assert(raw, 'No deployment table found.');

    const br = bio.read(raw);
    const count = br.readU8();
    const invalid = [];

    for (let i = 0; i < count; i++) {
      const bit = br.readU8();
      const start = br.readI64();
      const timeout = br.readU32();
      const threshold = br.readI32();
      const window = br.readI32();
      const deployment = this.network.byBit(bit);

      if (deployment
          && start === deployment.startTime
          && timeout === deployment.timeout
          && threshold === deployment.threshold
          && window === deployment.window) {
        continue;
      }

      invalid.push(bit);
    }

    return invalid;
  }

  /**
   * Potentially invalidate state cache.
   * @returns {Promise}
   */

  async verifyDeployments() {
    let invalid;

    try {
      invalid = await this.checkDeployments();
    } catch (e) {
      if (e.type !== 'EncodingError')
        throw e;
      invalid = [];
      for (let i = 0; i < 32; i++)
        invalid.push(i);
    }

    if (invalid.length === 0)
      return true;

    const b = this.db.batch();

    for (const bit of invalid) {
      this.logger.warning('Versionbit deployment params modified.');
      this.logger.warning('Invalidating cache for bit %d.', bit);
      await this.invalidateCache(bit, b);
    }

    this.writeDeployments(b);

    await b.write();

    return false;
  }

  /**
   * Invalidate state cache.
   * @private
   * @returns {Promise}
   */

  async invalidateCache(bit, b) {
    const keys = await this.db.keys({
      gte: layout.v.min(bit),
      lte: layout.v.max(bit)
    });

    for (const key of keys)
      b.del(key);
  }

  /**
   * Retroactively prune the database.
   * @returns {Promise}
   */

  async prune() {
    const options = this.options;
    const keepBlocks = this.network.block.keepBlocks;
    const pruneAfter = this.network.block.pruneAfterHeight;

    const flags = await this.getFlags();

    if (flags.prune)
      throw new Error('Chain is already pruned.');

    const height = await this.getHeight(this.state.tip);

    if (height <= pruneAfter + keepBlocks)
      return false;

    const start = pruneAfter + 1;
    const end = height - keepBlocks;

    for (let i = start; i <= end; i++) {
      const hash = await this.getHash(i);

      if (!hash)
        throw new Error(`Cannot find hash for ${i}.`);

      await this.blocks.pruneUndo(hash);
      await this.blocks.prune(hash);
    }

    try {
      options.prune = true;

      const flags = ChainFlags.fromOptions(options);
      assert(flags.prune);

      await this.db.put(layout.O.encode(), flags.toRaw());
    } catch (e) {
      options.prune = false;
      throw e;
    }

    return true;
  }

  /**
   * Get the _next_ block hash (does not work by height).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Hash}.
   */

  async getNextHash(hash) {
    return this.db.get(layout.n.encode(hash));
  }

  /**
   * Check to see if a block is on the main chain.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async isMainHash(hash) {
    assert(Buffer.isBuffer(hash));

    if (hash.equals(consensus.ZERO_HASH))
      return false;

    if (hash.equals(this.network.genesis.hash))
      return true;

    if (hash.equals(this.state.tip))
      return true;

    const cacheHash = this.cacheHash.get(hash);

    if (cacheHash) {
      const cacheHeight = this.cacheHeight.get(cacheHash.height);
      if (cacheHeight)
        return cacheHeight.hash.equals(hash);
    }

    if (await this.getNextHash(hash))
      return true;

    return false;
  }

  /**
   * Test whether the entry is in the main chain.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns Boolean.
   */

  async isMainChain(entry) {
    if (entry.isGenesis())
      return true;

    if (entry.hash.equals(this.state.tip))
      return true;

    const cache = this.getCache(entry.height);

    if (cache)
      return entry.hash.equals(cache.hash);

    if (await this.getNextHash(entry.hash))
      return true;

    return false;
  }

  /**
   * Test whether the entry is marked invalid.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasInvalid(hash) {
    if (this.cacheInvalid.has(hash))
      return true;

    const invalid = await this.db.has(layout.i.encode(hash));

    if (invalid) {
      this.cacheInvalid.set(hash, true);
      return true;
    }

    return false;
  }

  /**
   * Set an entry as invalid.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async setInvalid(hash) {
    await this.db.put(layout.i.encode(hash));
    this.cacheInvalid.set(hash, true);
  }

  /**
   * Set an entry as no-longer invalid.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async removeInvalid(hash) {
    await this.db.del(layout.i.encode(hash));
    this.cacheInvalid.remove(hash);
  }

  /**
   * Get hash range.
   * @param {Number} [start=-1]
   * @param {Number} [end=-1]
   * @returns {Promise}
   */

  async getHashes(start = -1, end = -1) {
    if (start === -1)
      start = 0;

    if (end === -1)
      end >>>= 0;

    assert((start >>> 0) === start);
    assert((end >>> 0) === end);

    return this.db.values({
      gte: layout.H.min(start),
      lte: layout.H.max(end)
    });
  }

  /**
   * Get all entries.
   * @returns {Promise} - Returns {@link ChainEntry}[].
   */

  async getEntries() {
    return this.db.values({
      gte: layout.e.min(),
      lte: layout.e.max(),
      parse: data => ChainEntry.fromRaw(data)
    });
  }

  /**
   * Get all tip hashes sorted by chainwork.
   * @param {Object} options
   * @param {Boolean} options.reverse
   * @param {Number} options.limit
   * @returns {Promise} - Returns {@link Hash}[].
   */

  async getTipEntries(options = {}) {
    const opts = {
      gte: layout.w.min(),
      lte: layout.w.max(),
      parse: data => ChainEntry.fromRaw(data),
      reverse: options.reverse
    };

    if (options.limit != null)
      opts.limit = options.limit;

    return this.db.values(opts);
  }

  /**
   * Get the most chainwork entry.
   * @returns {Promise} - Returns {@link ChainEntry}.
   */

  async getMostWorkEntry() {
    const entries = await this.getTipEntries({reverse: true, limit: 1});
    if (!entries.length)
      return null;

    return entries[0];
  }

  /**
   * Get a coin (unspents only).
   * @private
   * @param {Outpoint} prevout
   * @returns {Promise} - Returns {@link CoinEntry}.
   */

  async readCoin(prevout) {
    if (this.options.spv)
      return null;

    const {hash, index} = prevout;

    const raw = await this.db.get(layout.c.encode(hash, index));

    if (!raw)
      return null;

    return CoinEntry.fromRaw(raw);
  }

  /**
   * Get a coin (unspents only).
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  async getCoin(hash, index) {
    const prevout = new Outpoint(hash, index);
    const coin = await this.readCoin(prevout);

    if (!coin)
      return null;

    return coin.toCoin(prevout);
  }

  /**
   * Check whether coins are still unspent. Necessary for bip30.
   * @see https://bitcointalk.org/index.php?topic=67738.0
   * @param {TX} tx
   * @returns {Promise} - Returns Boolean.
   */

  async hasCoins(tx) {
    for (let i = 0; i < tx.outputs.length; i++) {
      const key = layout.c.encode(tx.hash(), i);
      if (await this.db.has(key))
        return true;
    }
    return false;
  }

  /**
   * Get coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getCoinView(tx) {
    const view = new CoinView();

    for (const {prevout} of tx.inputs) {
      const coin = await this.readCoin(prevout);

      if (coin)
        view.addEntry(prevout, coin);
    }

    return view;
  }

  /**
   * Get coins necessary to be resurrected during a reorg.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getUndoCoins(hash) {
    const data = await this.blocks.readUndo(hash);

    if (!data)
      return new UndoCoins();

    return UndoCoins.fromRaw(data);
  }

  /**
   * Retrieve a block from the database (not filled with coins).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Block}.
   */

  async getBlock(hash) {
    const data = await this.getRawBlock(hash);

    if (!data)
      return null;

    if (this.options.spv)
      return MerkleBlock.fromExtendedRaw(data);

    return Block.fromRaw(data);
  }

  /**
   * Retrieve a block from the database (not filled with coins).
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link Block}.
   */

  async getRawBlock(block) {
    const hash = await this.getHash(block);

    if (!hash)
      return null;

    if (this.options.spv)
      return this.blocks.readMerkle(hash);

    return this.blocks.read(hash);
  }

  /**
   * Check if a block exists.
   * @param {Hash} hash
   * @returns {Promise} Returns Boolean.
   */

  async hasBlock(hash) {
    if (this.options.spv)
      return this.blocks.hasMerkle(hash);
    else
      return this.blocks.has(hash);
  }

  /**
   * Write a block to disk.
   * @param {Block|MerkleBlock} block
   * @returns {Promise}
   */

  async writeBlock(block) {
    const hash = block.hash();

    if (this.options.spv)
      await this.blocks.writeMerkle(hash, block.toExtendedRaw());
    else
      await this.blocks.write(hash, block.toRaw());
  }

  /**
   * Get a historical block coin viewpoint.
   * @param {Block} hash
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getBlockView(block) {
    const view = new CoinView();
    const undo = await this.getUndoCoins(block.hash());

    if (undo.isEmpty())
      return view;

    for (let i = block.txs.length - 1; i > 0; i--) {
      const tx = block.txs[i];

      for (let j = tx.inputs.length - 1; j >= 0; j--) {
        const input = tx.inputs[j];
        undo.apply(view, input.prevout);
      }
    }

    // Undo coins should be empty.
    assert(undo.isEmpty(), 'Undo coins data inconsistency.');

    return view;
  }

  /**
   * Scan the blockchain for transactions containing specified address hashes.
   * @param {Hash} start - Block hash to start at.
   * @param {Bloom} filter - Bloom filter containing tx and address hashes.
   * @param {Function} iter - Iterator.
   * @returns {Promise}
   */

  async scan(start, filter, iter) {
    if (start == null)
      start = this.network.genesis.hash;

    if (typeof start === 'number')
      this.logger.info('Scanning from height %d.', start);
    else
      this.logger.info('Scanning from block %h.', start);

    let entry = await this.getEntry(start);

    if (!entry)
      return;

    if (!await this.isMainChain(entry))
      throw new Error('Cannot rescan an alternate chain.');

    let total = 0;

    while (entry) {
      const block = await this.getBlock(entry.hash);
      const txs = [];

      total += 1;

      if (!block) {
        if (!this.options.spv && !this.options.prune)
          throw new Error('Block not found.');
        await iter(entry, txs);
        entry = await this.getNext(entry);
        continue;
      }

      this.logger.info(
        'Scanning block %h (%d).',
        entry.hash, entry.height);

      for (let i = 0; i < block.txs.length; i++) {
        const tx = block.txs[i];

        let found = false;

        for (let j = 0; j < tx.outputs.length; j++) {
          const output = tx.outputs[j];
          const hash = output.getHash();

          if (!hash)
            continue;

          if (filter.test(hash)) {
            const prevout = Outpoint.fromTX(tx, j);
            filter.add(prevout.toRaw());
            found = true;
          }
        }

        if (found) {
          txs.push(tx);
          continue;
        }

        if (i === 0)
          continue;

        for (const {prevout} of tx.inputs) {
          if (filter.test(prevout.toRaw())) {
            txs.push(tx);
            break;
          }
        }
      }

      await iter(entry, txs);

      entry = await this.getNext(entry);
    }

    this.logger.info('Finished scanning %d blocks.', total);
  }

  /**
   * Save an entry. Only one entry must be written at
   * a time, this is necessary as the reference counts
   * for previous entries need to be updated.
   * @param {ChainEntry} entry
   * @param {ChainEntry} prev
   * @returns {Promise}
   */

  async saveEntry(entry, prev) {
    this.start();
    try {
      await this._saveEntry(entry, prev);
    } catch (e) {
      this.drop();
      throw e;
    }
    await this.commit();

    // Update the in-memory entry _after_
    // successful commit.
    this.updateMostWork(entry);
  }

  /**
   * Save an entry.
   * @private
   * @param {ChainEntry} entry
   * @param {ChainEntry} prev
   * @returns {Promise}
   */

  async _saveEntry(entry, prev) {
    const hash = entry.hash;

    // Hash->height index.
    this.put(layout.h.encode(hash), fromU32(entry.height));

    // Entry data.
    this.put(layout.e.encode(hash), entry.toRaw());
    this.cacheHash.push(entry.hash, entry);

    // Tip chainwork index.
    this.del(layout.w.encode(fromBN(prev.chainwork), prev.hash));
    const raw = entry.toRaw();
    this.put(layout.w.encode(fromBN(entry.chainwork), hash), raw);

    // Add the skip entry.
    if (!entry.isGenesis()) {
      const skip = await this.getSkip(entry);
      this.put(layout.s.encode(hash), skip.hash);
    }

    // Push this entry to the next reference for
    // the previous block.
    const nexts = await this.getNextHashes(prev.hash);
    nexts.push(hash);
    this.putNextHashes(prev.hash, nexts);

    // Update state caches.
    this.saveUpdates();
  }

  /**
   * Update the in-memory most work entry.
   * @param {ChainEntry} entry
   */

  updateMostWork(entry) {
    if (!this.mostWork) {
      this.mostWork = entry;
    } else if (entry.chainwork.gt(this.mostWork.chainwork)) {
      this.mostWork = entry;
    } else if (entry.chainwork.eq(this.mostWork.chainwork)) {
      if (entry.hash.compare(this.mostWork.hash) > 0)
        this.mostWork = entry;
    }
    assert(this.mostWork);
  }

  /**
   * Sets the in-memory most work entry from the database.
   * @returns {Promise}
   */

  async setMostWork() {
    this.mostWork = await this.getMostWorkEntry();
    assert(this.mostWork);
  }

  /**
   * Set an entry as main and connect block.
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async connect(entry, block, view) {
    this.start();
    try {
      await this._connect(entry, block, view);
    } catch (e) {
      this.drop();
      throw e;
    }
    await this.commit();
  }

  /**
   * Set an entry as main and connect block.
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise}
   */

  async _connect(entry, block, view) {
    const hash = block.hash();

    // Hash->next-block index.
    if (!entry.isGenesis())
      this.put(layout.n.encode(entry.prevBlock), hash);

    // Height->hash index.
    this.put(layout.H.encode(entry.height), hash);
    this.cacheHeight.push(entry.height, entry);

    // Re-insert into cache.
    this.cacheHash.push(entry.hash, entry);

    // Update state caches.
    this.saveUpdates();

    // Connect block and save coins.
    await this.connectBlock(entry, block, view);

    // Commit new chain state.
    this.put(layout.R.encode(), this.pending.commit(hash));
  }

  /**
   * Disconnect block from the chain.
   * @param {ChainEntry} entry
   * @param {Block} block
   * @returns {Promise}
   */

  async disconnect(entry, block) {
    this.start();

    let view;
    try {
      view = await this._disconnect(entry, block);
    } catch (e) {
      this.drop();
      throw e;
    }

    await this.commit();

    return view;
  }

  /**
   * Disconnect block.
   * @private
   * @param {ChainEntry} entry
   * @param {Block} block
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async _disconnect(entry, block) {
    // Remove hash->next-block index.
    this.del(layout.n.encode(entry.prevBlock));

    // Remove height->hash index.
    this.del(layout.H.encode(entry.height));
    this.cacheHeight.unpush(entry.height);

    // Update state caches.
    this.saveUpdates();

    // Disconnect inputs.
    const view = await this.disconnectBlock(entry, block);

    // Revert chain state to previous tip.
    this.put(layout.R.encode(), this.pending.commit(entry.prevBlock));

    return view;
  }

  /**
   * Save state cache updates.
   * @private
   */

  saveUpdates() {
    const updates = this.stateCache.updates;

    if (updates.length === 0)
      return;

    this.logger.info('Saving %d state cache updates.', updates.length);

    for (const update of updates) {
      const {bit, hash} = update;
      this.put(layout.v.encode(bit, hash), update.toRaw());
    }
  }

  /**
   * Reset the chain to a height or hash. Useful for replaying
   * the blockchain download for SPV.
   * @param {Hash|Number} block - hash/height
   * @returns {Promise}
   */

  async reset(block) {
    const entry = await this.getEntry(block);

    if (!entry)
      throw new Error('Block not found.');

    if (!await this.isMainChain(entry))
      throw new Error('Cannot reset on alternate chain.');

    if (this.options.prune)
      throw new Error('Cannot reset when pruned.');

    // We need to remove all alternate
    // chains first. This is ugly, but
    // it's the only safe way to reset
    // the chain.
    await this.removeChains();

    let tip = await this.getTip();
    assert(tip);

    this.logger.debug('Resetting main chain to: %h', entry.hash);

    for (;;) {
      this.start();

      // Stop once we hit our target tip.
      if (tip.hash.equals(entry.hash)) {
        this.put(layout.R.encode(), this.pending.commit(tip.hash));
        await this.commit();
        break;
      }

      assert(!tip.isGenesis());

      const prev = await this.getPrevious(tip);
      assert(prev);

      // Revert the tip index.
      this.del(layout.w.encode(fromBN(tip.chainwork), tip.hash));
      const raw = prev.toRaw();
      this.put(layout.w.encode(fromBN(prev.chainwork), prev.hash), raw);

      // Remove all records (including
      // main-chain-only records).
      this.del(layout.H.encode(tip.height));
      this.del(layout.h.encode(tip.hash));
      this.del(layout.e.encode(tip.hash));
      this.del(layout.n.encode(tip.prevBlock));
      this.del(layout.r.encode(tip.prevBlock));
      this.del(layout.s.encode(tip.hash));

      // Disconnect and remove block data.
      try {
        await this.removeBlock(tip);
      } catch (e) {
        this.drop();
        throw e;
      }

      // Revert chain state to previous tip.
      this.put(layout.R.encode(), this.pending.commit(tip.prevBlock));

      await this.commit();

      // Update the in-memory entry _after_
      // successful commit.
      await this.setMostWork();

      // Update caches _after_ successful commit.
      this.cacheHeight.remove(tip.height);
      this.cacheHash.remove(tip.hash);

      tip = prev;
    }

    return tip;
  }

  /**
   * This will prune the headers and tips to keep a maximum
   * number of the current best chain tips. It will prune the
   * least chainwork tips.
   *
   * @private
   * @param {Number} max
   * @returns {Promise}
   */

  async pruneTips(max) {
    assert(Number.isSafeInteger(max));

    let tips = await this.getTipEntries();

    if (tips.length <= max)
      return;

    // Select the tips with the least amount of work.
    tips = tips.slice(0, tips.length - max);

    for (const tip of tips) {
      let hashes = [];

      this.start();
      try {
        hashes = await this._removeChain(tip);
      } catch (e) {
        this.drop();
        throw e;
      }
      await this.commit();

      for (const hash of hashes) {
        if (this.options.spv)
          this.blocks.pruneMerkle(hash);
        else
          this.blocks.prune(hash);
      }
    }
  }

  /**
   * Remove all alternate chains.
   * @returns {Promise}
   */

  async removeChains() {
    const tips = await this.getTipEntries();

    for (const tip of tips) {
      this.start();
      try {
        await this._removeChain(tip);
      } catch (e) {
        this.drop();
        throw e;
      }
      await this.commit();

      // Update the in-memory entry _after_
      // successful commit.
      await this.setMostWork();
    }
  }

  /**
   * Queue removal of an alternate chain. Only one chain must be
   * removed per atomic commit, due to the reference counting of
   * previous blocks that need to be updated.
   * @private
   * @param {ChainEntry} tip - Alternate chain tip.
   * @returns {Promise}
   */

  async _removeChain(tip) {
    let entry = tip;

    this.logger.debug('Removing alternate chain: %h.', entry.hash);

    const hashes = [];

    for (;;) {
      if (await this.isMainChain(entry))
        break;

      assert(!entry.isGenesis());

      const prev = await this.getPrevious(entry);

      // Queue restore the tip if there are not other chains
      // that build from the chain tip.
      if (prev.hash.equals(this.state.tip)) {
        const prevNexts = await this.getNextHashes(prev.hash);
        if (prevNexts.length === 1) {
          const raw = prev.toRaw();
          this.put(layout.w.encode(fromBN(prev.chainwork), prev.hash), raw);
        }
      }

      // Queue up removal of all non-main-chain records.
      this.del(layout.w.encode(fromBN(entry.chainwork), entry.hash));
      this.del(layout.h.encode(entry.hash));
      this.del(layout.e.encode(entry.hash));
      this.del(layout.s.encode(entry.hash));

      // Queue up hash and invalid flag to be removed
      // on successful write.
      this.cacheHash.unpush(entry.hash);
      this.cacheInvalid.unpush(entry.hash);

      // Track removed hashes.
      hashes.push(entry.hash);

      // Get the previous entry's next references.
      let nexts = await this.getNextHashes(entry.prevBlock);

      // If other chains fork from the previous, remove
      // the reference and do not continue to previous.
      if (nexts.length > 1) {
        nexts = nexts.filter(next => !next.equals(entry.hash));
        this.putNextHashes(entry.prevBlock, nexts);
        break;
      } else {
        this.deleteNextHashes(entry.prevBlock);
      }

      entry = prev;
      assert(entry);
    }

    return hashes;
  }

  /**
   * Remove a block (not an entry) to the database.
   * Disconnect inputs.
   * @param {ChainEntry} entry
   * @returns {Promise} - Returns {@link Block}.
   */

  async removeBlock(entry) {
    if (this.options.spv)
      return new CoinView();

    const block = await this.getBlock(entry.hash);

    if (!block)
      throw new Error('Block not found.');

    return this.disconnectBlock(entry, block);
  }

  /**
   * Commit coin view to database.
   * @private
   * @param {CoinView} view
   */

  saveView(view) {
    for (const [hash, coins] of view.map) {
      for (const [index, coin] of coins.outputs) {
        if (coin.spent) {
          this.del(layout.c.encode(hash, index));
          continue;
        }

        const raw = coin.toRaw();

        this.put(layout.c.encode(hash, index), raw);
      }
    }
  }

  /**
   * Connect block inputs.
   * @param {ChainEntry} entry
   * @param {Block} block
   * @param {CoinView} view
   * @returns {Promise} - Returns {@link Block}.
   */

  async connectBlock(entry, block, view) {
    if (this.options.spv)
      return undefined;

    const hash = block.hash();

    this.pending.connect(block);

    // Genesis block's coinbase is unspendable.
    if (entry.isGenesis())
      return undefined;

    // Update chain state value.
    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];

      if (i > 0) {
        for (const {prevout} of tx.inputs)
          this.pending.spend(view.getOutput(prevout));
      }

      for (const output of tx.outputs) {
        if (output.script.isUnspendable())
          continue;

        this.pending.add(output);
      }
    }

    // Commit new coin state.
    this.saveView(view);

    // Write undo coins (if there are any).
    if (!view.undo.isEmpty())
      await this.blocks.writeUndo(hash, view.undo.commit());

    // Prune height-288 if pruning is enabled.
    return this.pruneBlock(entry);
  }

  /**
   * Disconnect block inputs.
   * @param {ChainEntry} entry
   * @param {Block} block
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async disconnectBlock(entry, block) {
    const view = new CoinView();

    if (this.options.spv)
      return view;

    const hash = block.hash();
    const undo = await this.getUndoCoins(hash);

    this.pending.disconnect(block);

    // Disconnect all transactions.
    for (let i = block.txs.length - 1; i >= 0; i--) {
      const tx = block.txs[i];

      if (i > 0) {
        for (let j = tx.inputs.length - 1; j >= 0; j--) {
          const {prevout} = tx.inputs[j];
          undo.apply(view, prevout);
          this.pending.add(view.getOutput(prevout));
        }
      }

      // Remove any created coins.
      view.removeTX(tx, entry.height);

      for (let j = tx.outputs.length - 1; j >= 0; j--) {
        const output = tx.outputs[j];

        if (output.script.isUnspendable())
          continue;

        this.pending.spend(output);
      }
    }

    // Undo coins should be empty.
    assert(undo.isEmpty(), 'Undo coins data inconsistency.');

    // Commit new coin state.
    this.saveView(view);

    return view;
  }

  /**
   * Prune a block from the chain and
   * add current block to the prune queue.
   * @private
   * @param {ChainEntry} entry
   * @returns {Promise}
   */

  async pruneBlock(entry) {
    if (!this.options.prune)
      return;

    const height = entry.height - this.network.block.keepBlocks;

    if (height <= this.network.block.pruneAfterHeight)
      return;

    const hash = await this.getHash(height);

    if (!hash)
      return;

    if (this.options.spv) {
      await this.blocks.pruneMerkle(hash);
    } else {
      await this.blocks.pruneUndo(hash);
      await this.blocks.prune(hash);
    }
  }

  /**
   * Save database options.
   * @returns {Promise}
   */

  saveFlags() {
    const flags = ChainFlags.fromOptions(this.options);
    const b = this.db.batch();
    b.put(layout.O.encode(), flags.toRaw());
    return b.write();
  }
}

/**
 * ChainFlags
 */

class ChainFlags {
  /**
   * Create chain flags.
   * @alias module:blockchain.ChainFlags
   * @constructor
   */

  constructor(options) {
    this.network = Network.primary;
    this.spv = false;
    this.witness = true;
    this.bip91 = false;
    this.bip148 = false;
    this.prune = false;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    this.network = Network.get(options.network);

    if (options.spv != null) {
      assert(typeof options.spv === 'boolean');
      this.spv = options.spv;
    }

    if (options.bip91 != null) {
      assert(typeof options.bip91 === 'boolean');
      this.bip91 = options.bip91;
    }

    if (options.bip148 != null) {
      assert(typeof options.bip148 === 'boolean');
      this.bip148 = options.bip148;
    }

    if (options.prune != null) {
      assert(typeof options.prune === 'boolean');
      this.prune = options.prune;
    }

    return this;
  }

  static fromOptions(data) {
    return new ChainFlags().fromOptions(data);
  }

  toRaw() {
    const bw = bio.write(12);

    let flags = 0;

    if (this.spv)
      flags |= 1 << 0;

    if (this.witness)
      flags |= 1 << 1;

    if (this.prune)
      flags |= 1 << 2;

    if (this.bip91)
      flags |= 1 << 5;

    if (this.bip148)
      flags |= 1 << 6;

    bw.writeU32(this.network.magic);
    bw.writeU32(flags);
    bw.writeU32(0);

    return bw.render();
  }

  fromRaw(data) {
    const br = bio.read(data);

    this.network = Network.fromMagic(br.readU32());

    const flags = br.readU32();

    this.spv = (flags & 1) !== 0;
    this.witness = (flags & 2) !== 0;
    this.prune = (flags & 4) !== 0;
    this.bip91 = (flags & 32) !== 0;
    this.bip148 = (flags & 64) !== 0;

    return this;
  }

  static fromRaw(data) {
    return new ChainFlags().fromRaw(data);
  }
}

/**
 * Chain State
 */

class ChainState {
  /**
   * Create chain state.
   * @alias module:blockchain.ChainState
   * @constructor
   */

  constructor() {
    this.tip = consensus.ZERO_HASH;
    this.tx = 0;
    this.coin = 0;
    this.value = 0;
    this.committed = false;
  }

  clone() {
    const state = new ChainState();
    state.tip = this.tip;
    state.tx = this.tx;
    state.coin = this.coin;
    state.value = this.value;
    return state;
  }

  connect(block) {
    this.tx += block.txs.length;
  }

  disconnect(block) {
    this.tx -= block.txs.length;
  }

  add(coin) {
    this.coin += 1;
    this.value += coin.value;
  }

  spend(coin) {
    this.coin -= 1;
    this.value -= coin.value;
  }

  commit(hash) {
    this.tip = hash;
    this.committed = true;
    return this.toRaw();
  }

  toRaw() {
    const bw = bio.write(56);
    bw.writeHash(this.tip);
    bw.writeU64(this.tx);
    bw.writeU64(this.coin);
    bw.writeU64(this.value);
    return bw.render();
  }

  static fromRaw(data) {
    const state = new ChainState();
    const br = bio.read(data);
    state.tip = br.readHash();
    state.tx = br.readU64();
    state.coin = br.readU64();
    state.value = br.readU64();
    return state;
  }
}

/**
 * State Cache
 */

class StateCache {
  /**
   * Create state cache.
   * @alias module:blockchain.StateCache
   * @constructor
   */

  constructor(network) {
    this.network = network;
    this.bits = [];
    this.updates = [];
    this.init();
  }

  init() {
    for (let i = 0; i < 32; i++)
      this.bits.push(null);

    for (const {bit} of this.network.deploys) {
      assert(!this.bits[bit]);
      this.bits[bit] = new BufferMap();
    }
  }

  set(bit, entry, state) {
    const cache = this.bits[bit];

    assert(cache);

    if (cache.get(entry.hash) !== state) {
      cache.set(entry.hash, state);
      this.updates.push(new CacheUpdate(bit, entry.hash, state));
    }
  }

  get(bit, entry) {
    const cache = this.bits[bit];

    assert(cache);

    const state = cache.get(entry.hash);

    if (state == null)
      return -1;

    return state;
  }

  commit() {
    this.updates.length = 0;
  }

  drop() {
    for (const {bit, hash} of this.updates) {
      const cache = this.bits[bit];
      assert(cache);
      cache.delete(hash);
    }

    this.updates.length = 0;
  }

  insert(bit, hash, state) {
    const cache = this.bits[bit];
    assert(cache);
    cache.set(hash, state);
  }
}

/**
 * Cache Update
 */

class CacheUpdate {
  /**
   * Create cache update.
   * @constructor
   * @ignore
   */

  constructor(bit, hash, state) {
    this.bit = bit;
    this.hash = hash;
    this.state = state;
  }

  toRaw() {
    const data = Buffer.allocUnsafe(1);
    data[0] = this.state;
    return data;
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

function fromBN(bn) {
  return bn.toString('hex', 64);
}

/*
 * Expose
 */

module.exports = ChainDB;
