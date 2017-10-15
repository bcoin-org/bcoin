/*!
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const Amount = require('../btc/amount');
const encoding = require('../utils/encoding');
const Network = require('../protocol/network');
const CoinView = require('../coins/coinview');
const UndoCoins = require('../coins/undocoins');
const LDB = require('../db/ldb');
const layout = require('./layout');
const LRU = require('../utils/lru');
const Block = require('../primitives/block');
const Outpoint = require('../primitives/outpoint');
const Address = require('../primitives/address');
const ChainEntry = require('./chainentry');
const TXMeta = require('../primitives/txmeta');
const CoinEntry = require('../coins/coinentry');
const U8 = encoding.U8;
const U32 = encoding.U32;

/**
 * The database backend for the {@link Chain} object.
 * @alias module:blockchain.ChainDB
 * @constructor
 * @param {Boolean?} options.prune - Whether to prune the chain.
 * @param {Boolean?} options.spv - SPV-mode, will not save block
 * data, only entries.
 * @param {String?} options.name - Database name
 * @param {String?} options.location - Database location
 * @param {String?} options.db - Database backend name
 * @property {Boolean} prune
 * @emits ChainDB#open
 * @emits ChainDB#error
 */

function ChainDB(options) {
  if (!(this instanceof ChainDB))
    return new ChainDB(options);

  this.options = options;
  this.network = this.options.network;
  this.logger = this.options.logger.context('chaindb');

  this.db = LDB(this.options);
  this.stateCache = new StateCache(this.network);
  this.state = new ChainState();
  this.pending = null;
  this.current = null;

  this.coinCache = new LRU(this.options.coinCache, getSize);
  this.cacheHash = new LRU(this.options.entryCache);
  this.cacheHeight = new LRU(this.options.entryCache);
}

/**
 * Database layout.
 * @type {Object}
 */

ChainDB.layout = layout;

/**
 * Open the chain db, wait for the database to load.
 * @returns {Promise}
 */

ChainDB.prototype.open = async function open() {
  this.logger.info('Opening ChainDB...');

  await this.db.open();
  await this.db.checkVersion('V', 3);

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

  this.logger.info(
    'Chain State: hash=%s tx=%d coin=%d value=%s.',
    this.state.rhash(),
    this.state.tx,
    this.state.coin,
    Amount.btc(this.state.value));
};

/**
 * Close the chain db, wait for the database to close.
 * @returns {Promise}
 */

ChainDB.prototype.close = function close() {
  return this.db.close();
};

/**
 * Start a batch.
 * @returns {Batch}
 */

ChainDB.prototype.start = function start() {
  assert(!this.current);
  assert(!this.pending);

  this.current = this.db.batch();
  this.pending = this.state.clone();

  this.coinCache.start();
  this.cacheHash.start();
  this.cacheHeight.start();

  return this.current;
};

/**
 * Put key and value to current batch.
 * @param {String} key
 * @param {Buffer} value
 */

ChainDB.prototype.put = function put(key, value) {
  assert(this.current);
  this.current.put(key, value);
};

/**
 * Delete key from current batch.
 * @param {String} key
 */

ChainDB.prototype.del = function del(key) {
  assert(this.current);
  this.current.del(key);
};

/**
 * Get current batch.
 * @returns {Batch}
 */

ChainDB.prototype.batch = function batch() {
  assert(this.current);
  return this.current;
};

/**
 * Drop current batch.
 * @returns {Batch}
 */

ChainDB.prototype.drop = function drop() {
  const batch = this.current;

  assert(this.current);
  assert(this.pending);

  this.current = null;
  this.pending = null;

  this.coinCache.drop();
  this.cacheHash.drop();
  this.cacheHeight.drop();
  this.stateCache.drop();

  batch.clear();
};

/**
 * Commit current batch.
 * @returns {Promise}
 */

ChainDB.prototype.commit = async function commit() {
  assert(this.current);
  assert(this.pending);

  try {
    await this.current.write();
  } catch (e) {
    this.current = null;
    this.pending = null;
    this.coinCache.drop();
    this.cacheHash.drop();
    this.cacheHeight.drop();
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

  this.coinCache.commit();
  this.cacheHash.commit();
  this.cacheHeight.commit();
  this.stateCache.commit();
};

/**
 * Test the cache for a present entry hash or height.
 * @param {Hash|Number} block - Hash or height.
 */

ChainDB.prototype.hasCache = function hasCache(block) {
  if (typeof block === 'number')
    return this.cacheHeight.has(block);

  assert(typeof block === 'string');

  return this.cacheHash.has(block);
};

/**
 * Get an entry directly from the LRU cache.
 * @param {Hash|Number} block - Hash or height.
 */

ChainDB.prototype.getCache = function getCache(block) {
  if (typeof block === 'number')
    return this.cacheHeight.get(block);

  assert(typeof block === 'string');

  return this.cacheHash.get(block);
};

/**
 * Get the height of a block by hash.
 * @param {Hash} hash
 * @returns {Promise} - Returns Number.
 */

ChainDB.prototype.getHeight = async function getHeight(hash) {
  if (typeof hash === 'number')
    return hash;

  assert(typeof hash === 'string');

  if (hash === encoding.NULL_HASH)
    return -1;

  const entry = this.cacheHash.get(hash);

  if (entry)
    return entry.height;

  const height = await this.db.get(layout.h(hash));

  if (!height)
    return -1;

  return height.readUInt32LE(0, true);
};

/**
 * Get the hash of a block by height. Note that this
 * will only return hashes in the main chain.
 * @param {Number} height
 * @returns {Promise} - Returns {@link Hash}.
 */

ChainDB.prototype.getHash = async function getHash(height) {
  if (typeof height === 'string')
    return height;

  assert(typeof height === 'number');

  if (height < 0)
    return null;

  const entry = this.cacheHeight.get(height);

  if (entry)
    return entry.hash;

  const hash = await this.db.get(layout.H(height));

  if (!hash)
    return null;

  return hash.toString('hex');
};

/**
 * Retrieve a chain entry by height.
 * @param {Number} height
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntryByHeight = async function getEntryByHeight(height) {
  assert(typeof height === 'number');

  if (height < 0)
    return null;

  const cache = this.cacheHeight.get(height);

  if (cache)
    return cache;

  const data = await this.db.get(layout.H(height));

  if (!data)
    return null;

  const hash = data.toString('hex');

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
};

/**
 * Retrieve a chain entry by hash.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntryByHash = async function getEntryByHash(hash) {
  assert(typeof hash === 'string');

  if (hash === encoding.NULL_HASH)
    return null;

  const cache = this.cacheHash.get(hash);

  if (cache)
    return cache;

  const raw = await this.db.get(layout.e(hash));

  if (!raw)
    return null;

  const entry = ChainEntry.fromRaw(raw);

  // There's no efficient way to check whether
  // this is in the main chain or not, so
  // don't add it to the height cache.
  this.cacheHash.set(entry.hash, entry);

  return entry;
};

/**
 * Retrieve a chain entry.
 * @param {Number|Hash} block - Height or hash.
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntry = function getEntry(block) {
  if (typeof block === 'number')
    return this.getEntryByHeight(block);
  return this.getEntryByHash(block);
};

/**
 * Test whether the chain contains a block.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.hasEntry = async function hasEntry(hash) {
  const height = await this.getHeight(hash);
  return height !== -1;
};

/**
 * Get ancestor by `height`.
 * @param {ChainEntry} entry
 * @param {Number} height
 * @returns {Promise} - Returns ChainEntry.
 */

ChainDB.prototype.getAncestor = async function getAncestor(entry, height) {
  if (height < 0)
    return null;

  assert(height >= 0);
  assert(height <= entry.height);

  if (await this.isMainChain(entry))
    return await this.getEntryByHeight(height);

  while (entry.height !== height) {
    const cache = this.getPrevCache(entry);

    if (cache)
      entry = cache;
    else
      entry = await this.getPrevious(entry);

    assert(entry);
  }

  return entry;
};

/**
 * Get previous entry.
 * @param {ChainEntry} entry
 * @returns {Promise} - Returns ChainEntry.
 */

ChainDB.prototype.getPrevious = function getPrevious(entry) {
  return this.getEntryByHash(entry.prevBlock);
};

/**
 * Get previous cached entry.
 * @param {ChainEntry} entry
 * @returns {ChainEntry|null}
 */

ChainDB.prototype.getPrevCache = function getPrevCache(entry) {
  return this.cacheHash.get(entry.prevBlock) || null;
};

/**
 * Get next entry.
 * @param {ChainEntry} entry
 * @returns {Promise} - Returns ChainEntry.
 */

ChainDB.prototype.getNext = async function getNext(entry) {
  const hash = await this.getNextHash(entry.hash);

  if (!hash)
    return null;

  return await this.getEntryByHash(hash);
};

/**
 * Get next entry.
 * @param {ChainEntry} entry
 * @returns {Promise} - Returns ChainEntry.
 */

ChainDB.prototype.getNextEntry = async function getNextEntry(entry) {
  const next = await this.getEntryByHeight(entry.height + 1);

  if (!next)
    return null;

  // Not on main chain.
  if (next.prevBlock !== entry.hash)
    return null;

  return next;
};

/**
 * Retrieve the tip entry from the tip record.
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getTip = function getTip() {
  return this.getEntryByHash(this.state.tip);
};

/**
 * Retrieve the tip entry from the tip record.
 * @returns {Promise} - Returns {@link ChainState}.
 */

ChainDB.prototype.getState = async function getState() {
  const data = await this.db.get(layout.R);

  if (!data)
    return null;

  return ChainState.fromRaw(data);
};

/**
 * Write genesis block to database.
 * @returns {Promise}
 */

ChainDB.prototype.saveGenesis = async function saveGenesis() {
  const genesis = this.network.genesisBlock;
  const block = Block.fromRaw(genesis, 'hex');
  const entry = ChainEntry.fromBlock(block);

  this.logger.info('Writing genesis block to ChainDB.');

  await this.save(entry, block, new CoinView());
};

/**
 * Retrieve the database flags.
 * @returns {Promise} - Returns {@link ChainFlags}.
 */

ChainDB.prototype.getFlags = async function getFlags() {
  const data = await this.db.get(layout.O);

  if (!data)
    return null;

  return ChainFlags.fromRaw(data);
};

/**
 * Verify current options against db options.
 * @param {ChainState} state
 * @returns {Promise}
 */

ChainDB.prototype.verifyFlags = async function verifyFlags(state) {
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

  if (options.indexTX && !flags.indexTX)
    throw new Error('Cannot retroactively enable TX indexing.');

  if (!options.indexTX && flags.indexTX)
    throw new Error('Cannot retroactively disable TX indexing.');

  if (options.indexAddress && !flags.indexAddress)
    throw new Error('Cannot retroactively enable address indexing.');

  if (!options.indexAddress && flags.indexAddress)
    throw new Error('Cannot retroactively disable address indexing.');

  if (needsSave) {
    await this.logger.info('Rewriting chain flags.');
    await this.saveFlags();
  }

  if (needsPrune) {
    await this.logger.info('Retroactively pruning chain.');
    await this.prune(state.tip);
  }
};

/**
 * Get state caches.
 * @returns {Promise} - Returns {@link StateCache}.
 */

ChainDB.prototype.getStateCache = async function getStateCache() {
  const stateCache = new StateCache(this.network);

  const items = await this.db.range({
    gte: layout.v(0, encoding.ZERO_HASH),
    lte: layout.v(255, encoding.MAX_HASH),
    values: true
  });

  for (const item of items) {
    const [bit, hash] = layout.vv(item.key);
    const state = item.value[0];
    stateCache.insert(bit, hash, state);
  }

  return stateCache;
};

/**
 * Save deployment table.
 * @returns {Promise}
 */

ChainDB.prototype.saveDeployments = function saveDeployments() {
  const batch = this.db.batch();
  this.writeDeployments(batch);
  return batch.write();
};

/**
 * Save deployment table.
 * @returns {Promise}
 */

ChainDB.prototype.writeDeployments = function writeDeployments(batch) {
  const bw = new StaticWriter(1 + 17 * this.network.deploys.length);

  bw.writeU8(this.network.deploys.length);

  for (const deployment of this.network.deploys) {
    bw.writeU8(deployment.bit);
    bw.writeU32(deployment.startTime);
    bw.writeU32(deployment.timeout);
    bw.writeI32(deployment.threshold);
    bw.writeI32(deployment.window);
  }

  batch.put(layout.V, bw.render());
};

/**
 * Check for outdated deployments.
 * @private
 * @returns {Promise}
 */

ChainDB.prototype.checkDeployments = async function checkDeployments() {
  const raw = await this.db.get(layout.V);

  assert(raw, 'No deployment table found.');

  const br = new BufferReader(raw);
  const count = br.readU8();
  const invalid = [];

  for (let i = 0; i < count; i++) {
    const bit = br.readU8();
    const start = br.readU32();
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
};

/**
 * Potentially invalidate state cache.
 * @returns {Promise}
 */

ChainDB.prototype.verifyDeployments = async function verifyDeployments() {
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

  const batch = this.db.batch();

  for (const bit of invalid) {
    this.logger.warning('Versionbit deployment params modified.');
    this.logger.warning('Invalidating cache for bit %d.', bit);
    await this.invalidateCache(bit, batch);
  }

  this.writeDeployments(batch);

  await batch.write();

  return false;
};

/**
 * Invalidate state cache.
 * @private
 * @returns {Promise}
 */

ChainDB.prototype.invalidateCache = async function invalidateCache(bit, batch) {
  const keys = await this.db.keys({
    gte: layout.v(bit, encoding.ZERO_HASH),
    lte: layout.v(bit, encoding.MAX_HASH)
  });

  for (const key of keys)
    batch.del(key);
};

/**
 * Retroactively prune the database.
 * @returns {Promise}
 */

ChainDB.prototype.prune = async function prune() {
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
  const batch = this.db.batch();

  for (let i = start; i <= end; i++) {
    const hash = await this.getHash(i);

    if (!hash)
      throw new Error(`Cannot find hash for ${i}.`);

    batch.del(layout.b(hash));
    batch.del(layout.u(hash));
  }

  try {
    options.prune = true;

    const flags = ChainFlags.fromOptions(options);
    assert(flags.prune);

    batch.put(layout.O, flags.toRaw());

    await batch.write();
  } catch (e) {
    options.prune = false;
    throw e;
  }

  await this.db.compactRange();

  return true;
};

/**
 * Get the _next_ block hash (does not work by height).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Hash}.
 */

ChainDB.prototype.getNextHash = async function getNextHash(hash) {
  const data = await this.db.get(layout.n(hash));

  if (!data)
    return null;

  return data.toString('hex');
};

/**
 * Check to see if a block is on the main chain.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.isMainHash = async function isMainHash(hash) {
  assert(typeof hash === 'string');

  if (hash === encoding.NULL_HASH)
    return false;

  if (hash === this.network.genesis.hash)
    return true;

  if (hash === this.state.tip)
    return true;

  const cacheHash = this.cacheHash.get(hash);

  if (cacheHash) {
    const cacheHeight = this.cacheHeight.get(cacheHash.height);
    if (cacheHeight)
      return cacheHeight.hash === hash;
  }

  if (await this.getNextHash(hash))
    return true;

  return false;
};

/**
 * Test whether the entry is in the main chain.
 * @param {ChainEntry} entry
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.isMainChain = async function isMainChain(entry) {
  if (entry.isGenesis())
    return true;

  if (entry.hash === this.state.tip)
    return true;

  const cache = this.getCache(entry.height);

  if (cache)
    return entry.hash === cache.hash;

  if (await this.getNextHash(entry.hash))
    return true;

  return false;
};

/**
 * Get all entries.
 * @returns {Promise} - Returns {@link ChainEntry}[].
 */

ChainDB.prototype.getEntries = function getEntries() {
  return this.db.values({
    gte: layout.e(encoding.ZERO_HASH),
    lte: layout.e(encoding.MAX_HASH),
    parse: value => ChainEntry.fromRaw(value)
  });
};

/**
 * Get all tip hashes.
 * @returns {Promise} - Returns {@link Hash}[].
 */

ChainDB.prototype.getTips = function getTips() {
  return this.db.keys({
    gte: layout.p(encoding.ZERO_HASH),
    lte: layout.p(encoding.MAX_HASH),
    parse: layout.pp
  });
};

/**
 * Get a coin (unspents only).
 * @private
 * @param {Outpoint} prevout
 * @returns {Promise} - Returns {@link CoinEntry}.
 */

ChainDB.prototype.readCoin = async function readCoin(prevout) {
  if (this.options.spv)
    return null;

  const {hash, index} = prevout;
  const key = prevout.toKey();
  const state = this.state;

  const cache = this.coinCache.get(key);

  if (cache)
    return CoinEntry.fromRaw(cache);

  const raw = await this.db.get(layout.c(hash, index));

  if (!raw)
    return null;

  if (state === this.state)
    this.coinCache.set(key, raw);

  return CoinEntry.fromRaw(raw);
};

/**
 * Get a coin (unspents only).
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

ChainDB.prototype.getCoin = async function getCoin(hash, index) {
  const prevout = new Outpoint(hash, index);
  const coin = await this.readCoin(prevout);

  if (!coin)
    return null;

  return coin.toCoin(prevout);
};

/**
 * Check whether coins are still unspent. Necessary for bip30.
 * @see https://bitcointalk.org/index.php?topic=67738.0
 * @param {TX} tx
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.hasCoins = async function hasCoins(tx) {
  for (let i = 0; i < tx.outputs.length; i++) {
    const key = layout.c(tx.hash(), i);
    if (await this.db.has(key))
      return true;
  }
  return false;
};

/**
 * Get coin viewpoint.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getCoinView = async function getCoinView(tx) {
  const view = new CoinView();

  for (const {prevout} of tx.inputs) {
    const coin = await this.readCoin(prevout);

    if (coin)
      view.addEntry(prevout, coin);
  }

  return view;
};

/**
 * Get coin viewpoint (historical).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getSpentView = async function getSpentView(tx) {
  const view = await this.getCoinView(tx);

  for (const {prevout} of tx.inputs) {
    if (view.hasEntry(prevout))
      continue;

    const {hash, index} = prevout;
    const meta = await this.getMeta(hash);

    if (!meta)
      continue;

    const {tx, height} = meta;

    if (index < tx.outputs.length)
      view.addIndex(tx, index, height);
  }

  return view;
};

/**
 * Get coins necessary to be resurrected during a reorg.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Coin}[].
 */

ChainDB.prototype.getUndoCoins = async function getUndoCoins(hash) {
  const data = await this.db.get(layout.u(hash));

  if (!data)
    return new UndoCoins();

  return UndoCoins.fromRaw(data);
};

/**
 * Retrieve a block from the database (not filled with coins).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getBlock = async function getBlock(hash) {
  const data = await this.getRawBlock(hash);

  if (!data)
    return null;

  return Block.fromRaw(data);
};

/**
 * Retrieve a block from the database (not filled with coins).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getRawBlock = async function getRawBlock(block) {
  if (this.options.spv)
    return null;

  const hash = await this.getHash(block);

  if (!hash)
    return null;

  return await this.db.get(layout.b(hash));
};

/**
 * Get a historical block coin viewpoint.
 * @param {Block} hash
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getBlockView = async function getBlockView(block) {
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
};

/**
 * Get a transaction with metadata.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXMeta}.
 */

ChainDB.prototype.getMeta = async function getMeta(hash) {
  if (!this.options.indexTX)
    return null;

  const data = await this.db.get(layout.t(hash));

  if (!data)
    return null;

  return TXMeta.fromRaw(data);
};

/**
 * Retrieve a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

ChainDB.prototype.getTX = async function getTX(hash) {
  const meta = await this.getMeta(hash);

  if (!meta)
    return null;

  return meta.tx;
};

/**
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.hasTX = async function hasTX(hash) {
  if (!this.options.indexTX)
    return false;

  return await this.db.has(layout.t(hash));
};

/**
 * Get all coins pertinent to an address.
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link Coin}[].
 */

ChainDB.prototype.getCoinsByAddress = async function getCoinsByAddress(addrs) {
  if (!this.options.indexAddress)
    return [];

  if (!Array.isArray(addrs))
    addrs = [addrs];

  const coins = [];

  for (const addr of addrs) {
    const hash = Address.getHash(addr);

    const keys = await this.db.keys({
      gte: layout.C(hash, encoding.ZERO_HASH, 0),
      lte: layout.C(hash, encoding.MAX_HASH, 0xffffffff),
      parse: layout.Cc
    });

    for (const [hash, index] of keys) {
      const coin = await this.getCoin(hash, index);
      assert(coin);
      coins.push(coin);
    }
  }

  return coins;
};

/**
 * Get all transaction hashes to an address.
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link Hash}[].
 */

ChainDB.prototype.getHashesByAddress = async function getHashesByAddress(addrs) {
  if (!this.options.indexTX || !this.options.indexAddress)
    return [];

  const hashes = Object.create(null);

  for (const addr of addrs) {
    const hash = Address.getHash(addr);

    await this.db.keys({
      gte: layout.T(hash, encoding.ZERO_HASH),
      lte: layout.T(hash, encoding.MAX_HASH),
      parse: (key) => {
        const hash = layout.Tt(key);
        hashes[hash] = true;
      }
    });
  }

  return Object.keys(hashes);
};

/**
 * Get all transactions pertinent to an address.
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link TX}[].
 */

ChainDB.prototype.getTXByAddress = async function getTXByAddress(addrs) {
  const mtxs = await this.getMetaByAddress(addrs);
  const out = [];

  for (const mtx of mtxs)
    out.push(mtx.tx);

  return out;
};

/**
 * Get all transactions pertinent to an address.
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link TXMeta}[].
 */

ChainDB.prototype.getMetaByAddress = async function getMetaByAddress(addrs) {
  if (!this.options.indexTX || !this.options.indexAddress)
    return [];

  if (!Array.isArray(addrs))
    addrs = [addrs];

  const hashes = await this.getHashesByAddress(addrs);
  const txs = [];

  for (const hash of hashes) {
    const tx = await this.getMeta(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Scan the blockchain for transactions containing specified address hashes.
 * @param {Hash} start - Block hash to start at.
 * @param {Bloom} filter - Bloom filter containing tx and address hashes.
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

ChainDB.prototype.scan = async function scan(start, filter, iter) {
  if (start == null)
    start = this.network.genesis.hash;

  if (typeof start === 'number')
    this.logger.info('Scanning from height %d.', start);
  else
    this.logger.info('Scanning from block %s.', util.revHex(start));

  let entry = await this.getEntry(start);

  if (!entry)
    return;

  if (!await this.isMainChain(entry))
    throw new Error('Cannot rescan an alternate chain.');

  let total = 0;

  while (entry) {
    const block = await this.getBlock(entry.hash);
    const txs = [];

    total++;

    if (!block) {
      if (!this.options.spv && !this.options.prune)
        throw new Error('Block not found.');
      await iter(entry, txs);
      entry = await this.getNext(entry);
      continue;
    }

    this.logger.info(
      'Scanning block %s (%d).',
      entry.rhash(), entry.height);

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
};

/**
 * Save an entry to the database and optionally
 * connect it as the tip. Note that this method
 * does _not_ perform any verification which is
 * instead performed in {@link Chain#add}.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view - Will not connect if null.
 * @returns {Promise}
 */

ChainDB.prototype.save = async function save(entry, block, view) {
  this.start();
  try {
    await this._save(entry, block, view);
  } catch (e) {
    this.drop();
    throw e;
  }
  await this.commit();
};

/**
 * Save an entry without a batch.
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view
 * @returns {Promise}
 */

ChainDB.prototype._save = async function _save(entry, block, view) {
  const hash = block.hash();

  // Hash->height index.
  this.put(layout.h(hash), U32(entry.height));

  // Entry data.
  this.put(layout.e(hash), entry.toRaw());
  this.cacheHash.push(entry.hash, entry);

  // Tip index.
  this.del(layout.p(entry.prevBlock));
  this.put(layout.p(hash), null);

  // Update state caches.
  this.saveUpdates();

  if (!view) {
    // Save block data.
    await this.saveBlock(entry, block);
    return;
  }

  // Hash->next-block index.
  if (!entry.isGenesis())
    this.put(layout.n(entry.prevBlock), hash);

  // Height->hash index.
  this.put(layout.H(entry.height), hash);
  this.cacheHeight.push(entry.height, entry);

  // Connect block and save data.
  await this.saveBlock(entry, block, view);

  // Commit new chain state.
  this.put(layout.R, this.pending.commit(hash));
};

/**
 * Reconnect the block to the chain.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise}
 */

ChainDB.prototype.reconnect = async function reconnect(entry, block, view) {
  this.start();
  try {
    await this._reconnect(entry, block, view);
  } catch (e) {
    this.drop();
    throw e;
  }
  await this.commit();
};

/**
 * Reconnect block without a batch.
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise}
 */

ChainDB.prototype._reconnect = async function _reconnect(entry, block, view) {
  const hash = block.hash();

  assert(!entry.isGenesis());

  // We can now add a hash->next-block index.
  this.put(layout.n(entry.prevBlock), hash);

  // We can now add a height->hash index.
  this.put(layout.H(entry.height), hash);
  this.cacheHeight.push(entry.height, entry);

  // Re-insert into cache.
  this.cacheHash.push(entry.hash, entry);

  // Update state caches.
  this.saveUpdates();

  // Connect inputs.
  await this.connectBlock(entry, block, view);

  // Update chain state.
  this.put(layout.R, this.pending.commit(hash));
};

/**
 * Disconnect block from the chain.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise}
 */

ChainDB.prototype.disconnect = async function disconnect(entry, block) {
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
};

/**
 * Disconnect block without a batch.
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype._disconnect = async function _disconnect(entry, block) {
  // Remove hash->next-block index.
  this.del(layout.n(entry.prevBlock));

  // Remove height->hash index.
  this.del(layout.H(entry.height));
  this.cacheHeight.unpush(entry.height);

  // Update state caches.
  this.saveUpdates();

  // Disconnect inputs.
  const view = await this.disconnectBlock(entry, block);

  // Revert chain state to previous tip.
  this.put(layout.R, this.pending.commit(entry.prevBlock));

  return view;
};

/**
 * Save state cache updates.
 * @private
 */

ChainDB.prototype.saveUpdates = function saveUpdates() {
  const updates = this.stateCache.updates;

  if (updates.length === 0)
    return;

  this.logger.info('Saving %d state cache updates.', updates.length);

  for (const update of updates) {
    const {bit, hash} = update;
    this.put(layout.v(bit, hash), update.toRaw());
  }
};

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

ChainDB.prototype.reset = async function reset(block) {
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

  this.logger.debug('Resetting main chain to: %s', entry.rhash());

  for (;;) {
    this.start();

    // Stop once we hit our target tip.
    if (tip.hash === entry.hash) {
      this.put(layout.R, this.pending.commit(tip.hash));
      await this.commit();
      break;
    }

    assert(!tip.isGenesis());

    // Revert the tip index.
    this.del(layout.p(tip.hash));
    this.put(layout.p(tip.prevBlock), null);

    // Remove all records (including
    // main-chain-only records).
    this.del(layout.H(tip.height));
    this.del(layout.h(tip.hash));
    this.del(layout.e(tip.hash));
    this.del(layout.n(tip.prevBlock));

    // Disconnect and remove block data.
    try {
      await this.removeBlock(tip);
    } catch (e) {
      this.drop();
      throw e;
    }

    // Revert chain state to previous tip.
    this.put(layout.R, this.pending.commit(tip.prevBlock));

    await this.commit();

    // Update caches _after_ successful commit.
    this.cacheHeight.remove(tip.height);
    this.cacheHash.remove(tip.hash);

    tip = await this.getPrevious(tip);
    assert(tip);
  }

  return tip;
};

/**
 * Remove all alternate chains.
 * @returns {Promise}
 */

ChainDB.prototype.removeChains = async function removeChains() {
  const tips = await this.getTips();

  // Note that this has to be
  // one giant atomic write!
  this.start();

  try {
    for (const tip of tips)
      await this._removeChain(tip);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();
};

/**
 * Remove an alternate chain.
 * @private
 * @param {Hash} hash - Alternate chain tip.
 * @returns {Promise}
 */

ChainDB.prototype._removeChain = async function _removeChain(hash) {
  let tip = await this.getEntryByHash(hash);

  if (!tip)
    throw new Error('Alternate chain tip not found.');

  this.logger.debug('Removing alternate chain: %s.', tip.rhash());

  for (;;) {
    if (await this.isMainChain(tip))
      break;

    assert(!tip.isGenesis());

    // Remove all non-main-chain records.
    this.del(layout.p(tip.hash));
    this.del(layout.h(tip.hash));
    this.del(layout.e(tip.hash));
    this.del(layout.b(tip.hash));

    // Queue up hash to be removed
    // on successful write.
    this.cacheHash.unpush(tip.hash);

    tip = await this.getPrevious(tip);
    assert(tip);
  }
};

/**
 * Save a block (not an entry) to the
 * database and potentially connect the inputs.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.saveBlock = async function saveBlock(entry, block, view) {
  const hash = block.hash();

  if (this.options.spv)
    return;

  // Write actual block data (this may be
  // better suited to flat files in the future).
  this.put(layout.b(hash), block.toRaw());

  if (!view)
    return;

  await this.connectBlock(entry, block, view);
};

/**
 * Remove a block (not an entry) to the database.
 * Disconnect inputs.
 * @param {ChainEntry} entry
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.removeBlock = async function removeBlock(entry) {
  if (this.options.spv)
    return new CoinView();

  const block = await this.getBlock(entry.hash);

  if (!block)
    throw new Error('Block not found.');

  this.del(layout.b(block.hash()));

  return await this.disconnectBlock(entry, block);
};

/**
 * Commit coin view to database.
 * @private
 * @param {CoinView} view
 */

ChainDB.prototype.saveView = function saveView(view) {
  for (const [hash, coins] of view.map) {
    for (const [index, coin] of coins.outputs) {
      if (coin.spent) {
        this.del(layout.c(hash, index));
        this.coinCache.unpush(hash + index);
        continue;
      }

      const raw = coin.toRaw();

      this.put(layout.c(hash, index), raw);
      this.coinCache.push(hash + index, raw);
    }
  }
};

/**
 * Connect block inputs.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.connectBlock = async function connectBlock(entry, block, view) {
  if (this.options.spv)
    return;

  const hash = block.hash();

  this.pending.connect(block);

  // Genesis block's coinbase is unspendable.
  if (entry.isGenesis())
    return;

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

    // Index the transaction if enabled.
    this.indexTX(tx, view, entry, i);
  }

  // Commit new coin state.
  this.saveView(view);

  // Write undo coins (if there are any).
  if (!view.undo.isEmpty())
    this.put(layout.u(hash), view.undo.commit());

  // Prune height-288 if pruning is enabled.
  await this.pruneBlock(entry);
};

/**
 * Disconnect block inputs.
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.disconnectBlock = async function disconnectBlock(entry, block) {
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

    // Remove from transaction index.
    this.unindexTX(tx, view);
  }

  // Undo coins should be empty.
  assert(undo.isEmpty(), 'Undo coins data inconsistency.');

  // Commit new coin state.
  this.saveView(view);

  // Remove undo coins.
  this.del(layout.u(hash));

  return view;
};

/**
 * Prune a block from the chain and
 * add current block to the prune queue.
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

ChainDB.prototype.pruneBlock = async function pruneBlock(entry) {
  if (this.options.spv)
    return;

  if (!this.options.prune)
    return;

  const height = entry.height - this.network.block.keepBlocks;

  if (height <= this.network.block.pruneAfterHeight)
    return;

  const hash = await this.getHash(height);

  if (!hash)
    return;

  this.del(layout.b(hash));
  this.del(layout.u(hash));
};

/**
 * Save database options.
 * @returns {Promise}
 */

ChainDB.prototype.saveFlags = function saveFlags() {
  const flags = ChainFlags.fromOptions(this.options);
  const batch = this.db.batch();
  batch.put(layout.O, flags.toRaw());
  return batch.write();
};

/**
 * Index a transaction by txid and address.
 * @private
 * @param {TX} tx
 * @param {CoinView} view
 * @param {ChainEntry} entry
 * @param {Number} index
 */

ChainDB.prototype.indexTX = function indexTX(tx, view, entry, index) {
  const hash = tx.hash();

  if (this.options.indexTX) {
    const meta = TXMeta.fromTX(tx, entry, index);

    this.put(layout.t(hash), meta.toRaw());

    if (this.options.indexAddress) {
      const hashes = tx.getHashes(view);
      for (const addr of hashes)
        this.put(layout.T(addr, hash), null);
    }
  }

  if (!this.options.indexAddress)
    return;

  if (!tx.isCoinbase()) {
    for (const {prevout} of tx.inputs) {
      const addr = view.getOutput(prevout).getHash();

      if (!addr)
        continue;

      this.del(layout.C(addr, prevout.hash, prevout.index));
    }
  }

  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    const addr = output.getHash();

    if (!addr)
      continue;

    this.put(layout.C(addr, hash, i), null);
  }
};

/**
 * Remove transaction from index.
 * @private
 * @param {TX} tx
 * @param {CoinView} view
 */

ChainDB.prototype.unindexTX = function unindexTX(tx, view) {
  const hash = tx.hash();

  if (this.options.indexTX) {
    this.del(layout.t(hash));
    if (this.options.indexAddress) {
      const hashes = tx.getHashes(view);
      for (const addr of hashes)
        this.del(layout.T(addr, hash));
    }
  }

  if (!this.options.indexAddress)
    return;

  if (!tx.isCoinbase()) {
    for (const {prevout} of tx.inputs) {
      const addr = view.getOutput(prevout).getHash();

      if (!addr)
        continue;

      this.put(layout.C(addr, prevout.hash, prevout.index), null);
    }
  }

  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    const addr = output.getHash();

    if (!addr)
      continue;

    this.del(layout.C(addr, hash, i));
  }
};

/**
 * Chain Flags
 * @alias module:blockchain.ChainFlags
 * @constructor
 */

function ChainFlags(options) {
  if (!(this instanceof ChainFlags))
    return new ChainFlags(options);

  this.network = Network.primary;
  this.spv = false;
  this.witness = true;
  this.bip91 = false;
  this.bip148 = false;
  this.prune = false;
  this.indexTX = false;
  this.indexAddress = false;

  if (options)
    this.fromOptions(options);
}

ChainFlags.prototype.fromOptions = function fromOptions(options) {
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

  if (options.indexTX != null) {
    assert(typeof options.indexTX === 'boolean');
    this.indexTX = options.indexTX;
  }

  if (options.indexAddress != null) {
    assert(typeof options.indexAddress === 'boolean');
    this.indexAddress = options.indexAddress;
  }

  return this;
};

ChainFlags.fromOptions = function fromOptions(data) {
  return new ChainFlags().fromOptions(data);
};

ChainFlags.prototype.toRaw = function toRaw() {
  const bw = new StaticWriter(12);
  let flags = 0;

  if (this.spv)
    flags |= 1 << 0;

  if (this.witness)
    flags |= 1 << 1;

  if (this.prune)
    flags |= 1 << 2;

  if (this.indexTX)
    flags |= 1 << 3;

  if (this.indexAddress)
    flags |= 1 << 4;

  if (this.bip91)
    flags |= 1 << 5;

  if (this.bip148)
    flags |= 1 << 6;

  bw.writeU32(this.network.magic);
  bw.writeU32(flags);
  bw.writeU32(0);

  return bw.render();
};

ChainFlags.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);

  this.network = Network.fromMagic(br.readU32());

  const flags = br.readU32();

  this.spv = (flags & 1) !== 0;
  this.witness = (flags & 2) !== 0;
  this.prune = (flags & 4) !== 0;
  this.indexTX = (flags & 8) !== 0;
  this.indexAddress = (flags & 16) !== 0;
  this.bip91 = (flags & 32) !== 0;
  this.bip148 = (flags & 64) !== 0;

  return this;
};

ChainFlags.fromRaw = function fromRaw(data) {
  return new ChainFlags().fromRaw(data);
};

/**
 * Chain State
 * @alias module:blockchain.ChainState
 * @constructor
 */

function ChainState() {
  this.tip = encoding.NULL_HASH;
  this.tx = 0;
  this.coin = 0;
  this.value = 0;
  this.committed = false;
}

ChainState.prototype.rhash = function rhash() {
  return util.revHex(this.tip);
};

ChainState.prototype.clone = function clone() {
  const state = new ChainState();
  state.tip = this.tip;
  state.tx = this.tx;
  state.coin = this.coin;
  state.value = this.value;
  return state;
};

ChainState.prototype.connect = function connect(block) {
  this.tx += block.txs.length;
};

ChainState.prototype.disconnect = function disconnect(block) {
  this.tx -= block.txs.length;
};

ChainState.prototype.add = function add(coin) {
  this.coin++;
  this.value += coin.value;
};

ChainState.prototype.spend = function spend(coin) {
  this.coin--;
  this.value -= coin.value;
};

ChainState.prototype.commit = function commit(hash) {
  if (typeof hash !== 'string')
    hash = hash.toString('hex');
  this.tip = hash;
  this.committed = true;
  return this.toRaw();
};

ChainState.prototype.toRaw = function toRaw() {
  const bw = new StaticWriter(56);
  bw.writeHash(this.tip);
  bw.writeU64(this.tx);
  bw.writeU64(this.coin);
  bw.writeU64(this.value);
  return bw.render();
};

ChainState.fromRaw = function fromRaw(data) {
  const state = new ChainState();
  const br = new BufferReader(data);
  state.tip = br.readHash('hex');
  state.tx = br.readU64();
  state.coin = br.readU64();
  state.value = br.readU64();
  return state;
};

/**
 * StateCache
 * @alias module:blockchain.StateCache
 * @constructor
 */

function StateCache(network) {
  this.network = network;
  this.bits = [];
  this.updates = [];
  this._init();
}

StateCache.prototype._init = function _init() {
  for (let i = 0; i < 32; i++)
    this.bits.push(null);

  for (const {bit} of this.network.deploys) {
    assert(!this.bits[bit]);
    this.bits[bit] = new Map();
  }
};

StateCache.prototype.set = function set(bit, entry, state) {
  const cache = this.bits[bit];

  assert(cache);

  if (cache.get(entry.hash) !== state) {
    cache.set(entry.hash, state);
    this.updates.push(new CacheUpdate(bit, entry.hash, state));
  }
};

StateCache.prototype.get = function get(bit, entry) {
  const cache = this.bits[bit];

  assert(cache);

  const state = cache.get(entry.hash);

  if (state == null)
    return -1;

  return state;
};

StateCache.prototype.commit = function commit() {
  this.updates.length = 0;
};

StateCache.prototype.drop = function drop() {
  for (const {bit, hash} of this.updates) {
    const cache = this.bits[bit];
    assert(cache);
    cache.delete(hash);
  }

  this.updates.length = 0;
};

StateCache.prototype.insert = function insert(bit, hash, state) {
  const cache = this.bits[bit];
  assert(cache);
  cache.set(hash, state);
};

/**
 * CacheUpdate
 * @constructor
 * @ignore
 */

function CacheUpdate(bit, hash, state) {
  this.bit = bit;
  this.hash = hash;
  this.state = state;
}

CacheUpdate.prototype.toRaw = function toRaw() {
  return U8(this.state);
};

/*
 * Helpers
 */

function getSize(value) {
  return value.length + 80;
}

/*
 * Expose
 */

module.exports = ChainDB;
