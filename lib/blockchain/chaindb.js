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
const Coins = require('../coins/coins');
const UndoCoins = require('../coins/undocoins');
const LDB = require('../db/ldb');
const layout = require('./layout');
const LRU = require('../utils/lru');
const Block = require('../primitives/block');
const Outpoint = require('../primitives/outpoint');
const Address = require('../primitives/address');
const ChainEntry = require('./chainentry');
const TXMeta = require('../primitives/txmeta');
const U8 = encoding.U8;
const U32 = encoding.U32;
const DUMMY = Buffer.from([0]);

/**
 * The database backend for the {@link Chain} object.
 * @alias module:blockchain.ChainDB
 * @constructor
 * @param {Chain} chain
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

function ChainDB(chain) {
  if (!(this instanceof ChainDB))
    return new ChainDB(chain);

  this.chain = chain;
  this.options = chain.options;
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
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.open = async function open() {
  let state;

  this.logger.info('Opening ChainDB...');

  await this.db.open();
  await this.db.checkVersion('V', 2);

  state = await this.getState();

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
  let batch = this.current;

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
 * @method
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
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns Number.
 */

ChainDB.prototype.getHeight = async function getHeight(hash) {
  let entry, height;

  if (typeof hash === 'number')
    return hash;

  assert(typeof hash === 'string');

  if (hash === encoding.NULL_HASH)
    return -1;

  entry = this.cacheHash.get(hash);

  if (entry)
    return entry.height;

  height = await this.db.get(layout.h(hash));

  if (!height)
    return -1;

  return height.readUInt32LE(0, true);
};

/**
 * Get the hash of a block by height. Note that this
 * will only return hashes in the main chain.
 * @method
 * @param {Number} height
 * @returns {Promise} - Returns {@link Hash}.
 */

ChainDB.prototype.getHash = async function getHash(height) {
  let entry, hash;

  if (typeof height === 'string')
    return height;

  assert(typeof height === 'number');

  if (height < 0)
    return;

  entry = this.cacheHeight.get(height);

  if (entry)
    return entry.hash;

  hash = await this.db.get(layout.H(height));

  if (!hash)
    return;

  return hash.toString('hex');
};

/**
 * Retrieve a chain entry by height.
 * @method
 * @param {Number} height
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntryByHeight = async function getEntryByHeight(height) {
  let state, entry, hash;

  assert(typeof height === 'number');

  if (height < 0)
    return;

  entry = this.cacheHeight.get(height);

  if (entry)
    return entry;

  hash = await this.db.get(layout.H(height));

  if (!hash)
    return;

  hash = hash.toString('hex');
  state = this.chain.state;

  entry = await this.getEntryByHash(hash);

  if (!entry)
    return;

  // By the time getEntry has completed,
  // a reorg may have occurred. This entry
  // may not be on the main chain anymore.
  if (this.chain.state === state)
    this.cacheHeight.set(entry.height, entry);

  return entry;
};

/**
 * Retrieve a chain entry by hash.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntryByHash = async function getEntryByHash(hash) {
  let entry, raw;

  assert(typeof hash === 'string');

  if (hash === encoding.NULL_HASH)
    return;

  entry = this.cacheHash.get(hash);

  if (entry)
    return entry;

  raw = await this.db.get(layout.e(hash));

  if (!raw)
    return;

  entry = ChainEntry.fromRaw(this.chain, raw);

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
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.hasEntry = async function hasEntry(hash) {
  let height = await this.getHeight(hash);
  return height !== -1;
};

/**
 * Retrieve the tip entry from the tip record.
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getTip = function getTip() {
  return this.getEntry(this.state.hash());
};

/**
 * Retrieve the tip entry from the tip record.
 * @method
 * @returns {Promise} - Returns {@link ChainState}.
 */

ChainDB.prototype.getState = async function getState() {
  let data = await this.db.get(layout.R);

  if (!data)
    return;

  return ChainState.fromRaw(data);
};

/**
 * Write genesis block to database.
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.saveGenesis = async function saveGenesis() {
  let genesis = this.network.genesisBlock;
  let block = Block.fromRaw(genesis, 'hex');
  let entry = ChainEntry.fromBlock(this.chain, block);

  this.logger.info('Writing genesis block to ChainDB.');

  await this.save(entry, block, new CoinView());
};

/**
 * Retrieve the database flags.
 * @method
 * @returns {Promise} - Returns {@link ChainFlags}.
 */

ChainDB.prototype.getFlags = async function getFlags() {
  let data = await this.db.get(layout.O);

  if (!data)
    return;

  return ChainFlags.fromRaw(data);
};

/**
 * Verify current options against db options.
 * @method
 * @param {ChainState} state
 * @returns {Promise}
 */

ChainDB.prototype.verifyFlags = async function verifyFlags(state) {
  let options = this.options;
  let flags = await this.getFlags();
  let needsWitness = false;
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
    if (!options.forceWitness)
      throw new Error('Cannot retroactively enable witness.');
    needsWitness = true;
  }

  if (options.prune && !flags.prune) {
    if (!options.forcePrune)
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

  if (needsWitness) {
    await this.logger.info('Writing witness bit to chain flags.');
    await this.saveFlags();
  }

  if (needsPrune) {
    await this.logger.info('Retroactively pruning chain.');
    await this.prune(state.hash());
  }
};

/**
 * Get state caches.
 * @method
 * @returns {Promise} - Returns {@link StateCache}.
 */

ChainDB.prototype.getStateCache = async function getStateCache() {
  let stateCache = new StateCache(this.network);

  let items = await this.db.range({
    gte: layout.v(0, encoding.ZERO_HASH),
    lte: layout.v(255, encoding.MAX_HASH),
    values: true
  });

  for (let item of items) {
    let [bit, hash] = layout.vv(item.key);
    let state = item.value[0];
    stateCache.insert(bit, hash, state);
  }

  return stateCache;
};

/**
 * Save deployment table.
 * @returns {Promise}
 */

ChainDB.prototype.saveDeployments = function saveDeployments() {
  let batch = this.db.batch();
  this.writeDeployments(batch);
  return batch.write();
};

/**
 * Save deployment table.
 * @returns {Promise}
 */

ChainDB.prototype.writeDeployments = function writeDeployments(batch) {
  let bw = new StaticWriter(1 + 9 * this.network.deploys.length);

  bw.writeU8(this.network.deploys.length);

  for (let deployment of this.network.deploys) {
    bw.writeU8(deployment.bit);
    bw.writeU32(deployment.startTime);
    bw.writeU32(deployment.timeout);
  }

  batch.put(layout.V, bw.render());
};

/**
 * Check for outdated deployments.
 * @method
 * @private
 * @returns {Promise}
 */

ChainDB.prototype.checkDeployments = async function checkDeployments() {
  let raw = await this.db.get(layout.V);
  let invalid = [];
  let br, count;

  assert(raw, 'No deployment table found.');

  br = new BufferReader(raw);
  count = br.readU8();

  for (let i = 0; i < count; i++) {
    let bit = br.readU8();
    let start = br.readU32();
    let timeout = br.readU32();
    let deployment = this.network.byBit(bit);

    if (deployment
        && start === deployment.startTime
        && timeout === deployment.timeout) {
      continue;
    }

    invalid.push(bit);
  }

  return invalid;
};

/**
 * Potentially invalidate state cache.
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.verifyDeployments = async function verifyDeployments() {
  let invalid = await this.checkDeployments();
  let batch;

  if (invalid.length === 0)
    return true;

  batch = this.db.batch();

  for (let bit of invalid) {
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
 * @method
 * @private
 * @returns {Promise}
 */

ChainDB.prototype.invalidateCache = async function invalidateCache(bit, batch) {
  let keys = await this.db.keys({
    gte: layout.v(bit, encoding.ZERO_HASH),
    lte: layout.v(bit, encoding.MAX_HASH)
  });

  for (let key of keys)
    batch.del(key);
};

/**
 * Retroactively prune the database.
 * @method
 * @param {Hash} tip
 * @returns {Promise}
 */

ChainDB.prototype.prune = async function prune(tip) {
  let options = this.options;
  let keepBlocks = this.network.block.keepBlocks;
  let pruneAfter = this.network.block.pruneAfterHeight;
  let flags = await this.getFlags();
  let height = await this.getHeight(tip);
  let start, end, batch;

  if (flags.prune)
    throw new Error('Chain is already pruned.');

  if (height <= pruneAfter + keepBlocks)
    return false;

  start = pruneAfter + 1;
  end = height - keepBlocks;
  batch = this.db.batch();

  for (let i = start; i <= end; i++) {
    let hash = await this.getHash(i);

    if (!hash)
      throw new Error(`Cannot find hash for ${i}.`);

    batch.del(layout.b(hash));
    batch.del(layout.u(hash));
  }

  try {
    options.prune = true;

    flags = ChainFlags.fromOptions(options);
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
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Hash}.
 */

ChainDB.prototype.getNextHash = async function getNextHash(hash) {
  let data = await this.db.get(layout.n(hash));

  if (!data)
    return;

  return data.toString('hex');
};

/**
 * Check to see if a block is on the main chain.
 * @method
 * @param {ChainEntry|Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.isMainChain = async function isMainChain(hash) {
  let entry;

  assert(typeof hash === 'string');

  if (hash === this.chain.tip.hash
      || hash === this.network.genesis.hash) {
    return true;
  }

  if (hash === encoding.NULL_HASH)
    return false;

  entry = this.cacheHash.get(hash);

  if (entry) {
    entry = this.cacheHeight.get(entry.height);
    if (entry)
      return entry.hash === hash;
  }

  if (await this.getNextHash(hash))
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
    parse: value => ChainEntry.fromRaw(this.chain, value)
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
 * @method
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

ChainDB.prototype.getCoin = async function getCoin(hash, index) {
  let state = this.state;
  let raw;

  if (this.options.spv)
    return;

  raw = this.coinCache.get(hash);

  if (raw)
    return Coins.parseCoin(raw, hash, index);

  raw = await this.db.get(layout.c(hash));

  if (!raw)
    return;

  if (state === this.state)
    this.coinCache.set(hash, raw);

  return Coins.parseCoin(raw, hash, index);
};

/**
 * Get coins (unspents only).
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Coins}.
 */

ChainDB.prototype.getCoins = async function getCoins(hash) {
  let raw;

  if (this.options.spv)
    return;

  raw = this.coinCache.get(hash);

  if (raw)
    return Coins.fromRaw(raw, hash);

  raw = await this.db.get(layout.c(hash));

  if (!raw)
    return;

  return Coins.fromRaw(raw, hash);
};

/**
 * Check whether coins are still unspent. Necessary for bip30.
 * @see https://bitcointalk.org/index.php?topic=67738.0
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.hasCoins = function hasCoins(hash) {
  return this.db.has(layout.c(hash));
};

/**
 * Get coin viewpoint.
 * @method
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getCoinView = async function getCoinView(tx) {
  let view = new CoinView();
  let prevout = tx.getPrevout();

  for (let hash of prevout) {
    let coins = await this.getCoins(hash);

    if (!coins) {
      coins = new Coins();
      coins.hash = hash;
      view.add(coins);
      continue;
    }

    view.add(coins);
  }

  return view;
};

/**
 * Get coin viewpoint (historical).
 * @method
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getSpentView = async function getSpentView(tx) {
  let view = await this.getCoinView(tx);

  for (let coins of view.map.values()) {
    let meta;

    if (!coins.isEmpty())
      continue;

    meta = await this.getMeta(coins.hash);

    if (!meta)
      continue;

    view.addTX(meta.tx, meta.height);
  }

  return view;
};

/**
 * Get coins necessary to be resurrected during a reorg.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Coin}[].
 */

ChainDB.prototype.getUndoCoins = async function getUndoCoins(hash) {
  let data = await this.db.get(layout.u(hash));
  if (!data)
    return new UndoCoins();
  return UndoCoins.fromRaw(data);
};

/**
 * Retrieve a block from the database (not filled with coins).
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getBlock = async function getBlock(hash) {
  let data = await this.getRawBlock(hash);

  if (!data)
    return;

  return Block.fromRaw(data);
};

/**
 * Retrieve a block from the database (not filled with coins).
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getRawBlock = async function getRawBlock(block) {
  let hash;

  if (this.options.spv)
    return;

  hash = await this.getHash(block);

  if (!hash)
    return;

  return await this.db.get(layout.b(hash));
};

/**
 * Get a historical block coin viewpoint.
 * @method
 * @param {Block} hash
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getBlockView = async function getBlockView(block) {
  let view = new CoinView();
  let undo = await this.getUndoCoins(block.hash());

  if (undo.isEmpty())
    return view;

  for (let i = block.txs.length - 1; i > 0; i--) {
    let tx = block.txs[i];

    for (let j = tx.inputs.length - 1; j >= 0; j--) {
      let input = tx.inputs[j];
      let prev = input.prevout.hash;

      if (!view.has(prev)) {
        assert(!undo.isEmpty());

        if (undo.top().height === -1) {
          let coins = new Coins();
          coins.hash = prev;
          coins.coinbase = false;
          view.add(coins);
        }
      }

      undo.apply(view, input.prevout);
    }
  }

  // Undo coins should be empty.
  assert(undo.isEmpty(), 'Undo coins data inconsistency.');

  return view;
};

/**
 * Get a transaction with metadata.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXMeta}.
 */

ChainDB.prototype.getMeta = async function getMeta(hash) {
  let data;

  if (!this.options.indexTX)
    return;

  data = await this.db.get(layout.t(hash));

  if (!data)
    return;

  return TXMeta.fromRaw(data);
};

/**
 * Retrieve a transaction.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

ChainDB.prototype.getTX = async function getTX(hash) {
  let meta = await this.getMeta(hash);
  if (!meta)
    return;
  return meta.tx;
};

/**
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.hasTX = function hasTX(hash) {
  if (!this.options.indexTX)
    return Promise.resolve();

  return this.db.has(layout.t(hash));
};

/**
 * Get all coins pertinent to an address.
 * @method
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link Coin}[].
 */

ChainDB.prototype.getCoinsByAddress = async function getCoinsByAddress(addrs) {
  let coins = [];

  if (!this.options.indexAddress)
    return coins;

  if (!Array.isArray(addrs))
    addrs = [addrs];

  for (let addr of addrs) {
    let hash = Address.getHash(addr);

    let keys = await this.db.keys({
      gte: layout.C(hash, encoding.ZERO_HASH, 0),
      lte: layout.C(hash, encoding.MAX_HASH, 0xffffffff),
      parse: layout.Cc
    });

    for (let [hash, index] of keys) {
      let coin = await this.getCoin(hash, index);
      assert(coin);
      coins.push(coin);
    }
  }

  return coins;
};

/**
 * Get all transaction hashes to an address.
 * @method
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link Hash}[].
 */

ChainDB.prototype.getHashesByAddress = async function getHashesByAddress(addrs) {
  let hashes = {};

  if (!this.options.indexTX || !this.options.indexAddress)
    return [];

  for (let addr of addrs) {
    let hash = Address.getHash(addr);

    await this.db.keys({
      gte: layout.T(hash, encoding.ZERO_HASH),
      lte: layout.T(hash, encoding.MAX_HASH),
      parse: (key) => {
        let hash = layout.Tt(key);
        hashes[hash] = true;
      }
    });
  }

  return Object.keys(hashes);
};

/**
 * Get all transactions pertinent to an address.
 * @method
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link TX}[].
 */

ChainDB.prototype.getTXByAddress = async function getTXByAddress(addrs) {
  let mtxs = await this.getMetaByAddress(addrs);
  let out = [];

  for (let mtx of mtxs)
    out.push(mtx.tx);

  return out;
};

/**
 * Get all transactions pertinent to an address.
 * @method
 * @param {Address[]} addrs
 * @returns {Promise} - Returns {@link TXMeta}[].
 */

ChainDB.prototype.getMetaByAddress = async function getTXByAddress(addrs) {
  let txs = [];
  let hashes;

  if (!this.options.indexTX || !this.options.indexAddress)
    return txs;

  if (!Array.isArray(addrs))
    addrs = [addrs];

  hashes = await this.getHashesByAddress(addrs);

  for (let hash of hashes) {
    let tx = await this.getMeta(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Scan the blockchain for transactions containing specified address hashes.
 * @method
 * @param {Hash} start - Block hash to start at.
 * @param {Bloom} filter - Bloom filter containing tx and address hashes.
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

ChainDB.prototype.scan = async function scan(start, filter, iter) {
  let total = 0;
  let entry;

  if (start == null)
    start = this.network.genesis.hash;

  if (typeof start === 'number')
    this.logger.info('Scanning from height %d.', start);
  else
    this.logger.info('Scanning from block %s.', util.revHex(start));

  entry = await this.getEntry(start);

  if (!entry)
    return;

  if (!(await entry.isMainChain()))
    throw new Error('Cannot rescan an alternate chain.');

  while (entry) {
    let block = await this.getBlock(entry.hash);
    let txs = [];
    total++;

    if (!block) {
      if (!this.options.spv && !this.options.prune)
        throw new Error('Block not found.');
      await iter(entry, txs);
      entry = await entry.getNext();
      continue;
    }

    this.logger.info(
      'Scanning block %s (%d).',
      entry.rhash(), entry.height);

    for (let tx of block.txs) {
      let found = false;

      for (let i = 0; i < tx.outputs.length; i++) {
        let output = tx.outputs[i];
        let hash = output.getHash();

        if (!hash)
          continue;

        if (filter.test(hash)) {
          let prevout = Outpoint.fromTX(tx, i);
          filter.add(prevout.toRaw());
          found = true;
        }
      }

      if (found) {
        txs.push(tx);
        continue;
      }

      if (tx.isCoinbase())
        continue;

      for (let input of tx.inputs) {
        let prevout = input.prevout;

        if (filter.test(prevout.toRaw())) {
          txs.push(tx);
          break;
        }
      }
    }

    await iter(entry, txs);

    entry = await entry.getNext();
  }

  this.logger.info('Finished scanning %d blocks.', total);
};

/**
 * Save an entry to the database and optionally
 * connect it as the tip. Note that this method
 * does _not_ perform any verification which is
 * instead performed in {@link Chain#add}.
 * @method
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
 * @method
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view
 * @returns {Promise}
 */

ChainDB.prototype._save = async function save(entry, block, view) {
  let hash = block.hash();

  // Hash->height index.
  this.put(layout.h(hash), U32(entry.height));

  // Entry data.
  this.put(layout.e(hash), entry.toRaw());
  this.cacheHash.push(entry.hash, entry);

  // Tip index.
  this.del(layout.p(entry.prevBlock));
  this.put(layout.p(hash), DUMMY);

  // Update state caches.
  this.saveUpdates();

  if (!view) {
    // Save block data.
    await this.saveBlock(entry, block);
    return;
  }

  // Hash->next-block index.
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
 * @method
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
 * @method
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise}
 */

ChainDB.prototype._reconnect = async function reconnect(entry, block, view) {
  let hash = block.hash();

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
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise}
 */

ChainDB.prototype.disconnect = async function disconnect(entry, block) {
  let view;

  this.start();

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
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype._disconnect = async function disconnect(entry, block) {
  let view;

  // Remove hash->next-block index.
  this.del(layout.n(entry.prevBlock));

  // Remove height->hash index.
  this.del(layout.H(entry.height));
  this.cacheHeight.unpush(entry.height);

  // Update state caches.
  this.saveUpdates();

  // Disconnect inputs.
  view = await this.disconnectBlock(entry, block);

  // Revert chain state to previous tip.
  this.put(layout.R, this.pending.commit(entry.prevBlock));

  return view;
};

/**
 * Save state cache updates.
 * @private
 */

ChainDB.prototype.saveUpdates = function saveUpdates() {
  let updates = this.stateCache.updates;

  if (updates.length === 0)
    return;

  this.logger.info('Saving %d state cache updates.', updates.length);

  for (let update of updates)
    this.put(layout.v(update.bit, update.hash), update.toRaw());
};

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @method
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

ChainDB.prototype.reset = async function reset(block) {
  let entry = await this.getEntry(block);
  let tip;

  if (!entry)
    throw new Error('Block not found.');

  if (!(await entry.isMainChain()))
    throw new Error('Cannot reset on alternate chain.');

  if (this.options.prune)
    throw new Error('Cannot reset when pruned.');

  // We need to remove all alternate
  // chains first. This is ugly, but
  // it's the only safe way to reset
  // the chain.
  await this.removeChains();

  tip = await this.getTip();
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
    this.put(layout.p(tip.prevBlock), DUMMY);

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

    tip = await this.getEntry(tip.prevBlock);
    assert(tip);
  }

  return tip;
};

/**
 * Remove all alternate chains.
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.removeChains = async function removeChains() {
  let tips = await this.getTips();

  // Note that this has to be
  // one giant atomic write!
  this.start();

  try {
    for (let tip of tips)
      await this._removeChain(tip);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();
};

/**
 * Remove an alternate chain.
 * @method
 * @private
 * @param {Hash} hash - Alternate chain tip.
 * @returns {Promise}
 */

ChainDB.prototype._removeChain = async function removeChain(hash) {
  let tip = await this.getEntry(hash);

  if (!tip)
    throw new Error('Alternate chain tip not found.');

  this.logger.debug('Removing alternate chain: %s.', tip.rhash());

  for (;;) {
    if (await tip.isMainChain())
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

    tip = await this.getEntry(tip.prevBlock);
    assert(tip);
  }
};

/**
 * Save a block (not an entry) to the
 * database and potentially connect the inputs.
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.saveBlock = async function saveBlock(entry, block, view) {
  let hash = block.hash();

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
 * @method
 * @param {ChainEntry} entry
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.removeBlock = async function removeBlock(entry) {
  let block;

  if (this.options.spv)
    return;

  block = await this.getBlock(entry.hash);

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
  for (let coins of view.map.values()) {
    if (coins.isEmpty()) {
      this.del(layout.c(coins.hash));
      this.coinCache.unpush(coins.hash);
    } else {
      let raw = coins.toRaw();
      this.put(layout.c(coins.hash), raw);
      this.coinCache.push(coins.hash, raw);
    }
  }
};

/**
 * Connect block inputs.
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.connectBlock = async function connectBlock(entry, block, view) {
  let hash = block.hash();

  if (this.options.spv)
    return;

  this.pending.connect(block);

  // Genesis block's coinbase is unspendable.
  if (this.chain.isGenesis(block))
    return;

  // Update chain state value.
  for (let i = 0; i < block.txs.length; i++) {
    let tx = block.txs[i];

    if (!tx.isCoinbase()) {
      for (let input of tx.inputs)
        this.pending.spend(view.getOutput(input));
    }

    for (let output of tx.outputs) {
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
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.disconnectBlock = async function disconnectBlock(entry, block) {
  let view = new CoinView();
  let hash = block.hash();
  let undo;

  if (this.options.spv)
    return view;

  undo = await this.getUndoCoins(hash);

  this.pending.disconnect(block);

  // Disconnect all transactions.
  for (let i = block.txs.length - 1; i >= 0; i--) {
    let tx = block.txs[i];

    if (!tx.isCoinbase()) {
      await view.ensureInputs(this, tx);

      for (let j = tx.inputs.length - 1; j >= 0; j--) {
        let input = tx.inputs[j];
        undo.apply(view, input.prevout);
        this.pending.add(view.getOutput(input));
      }
    }

    // Remove any created coins.
    view.removeTX(tx, entry.height);

    for (let j = tx.outputs.length - 1; j >= 0; j--) {
      let output = tx.outputs[j];

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
 * @method
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

ChainDB.prototype.pruneBlock = async function pruneBlock(entry) {
  let height, hash;

  if (this.options.spv)
    return;

  if (!this.options.prune)
    return;

  height = entry.height - this.network.block.keepBlocks;

  if (height <= this.network.block.pruneAfterHeight)
    return;

  hash = await this.getHash(height);

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
  let flags = ChainFlags.fromOptions(this.options);
  return this.db.put(layout.O, flags.toRaw());
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
  let hash = tx.hash();

  if (this.options.indexTX) {
    let meta = TXMeta.fromTX(tx, entry, index);

    this.put(layout.t(hash), meta.toRaw());

    if (this.options.indexAddress) {
      let hashes = tx.getHashes(view);
      for (let addr of hashes)
        this.put(layout.T(addr, hash), DUMMY);
    }
  }

  if (!this.options.indexAddress)
    return;

  if (!tx.isCoinbase()) {
    for (let input of tx.inputs) {
      let prevout = input.prevout;
      let addr = view.getOutput(input).getHash();

      if (!addr)
        continue;

      this.del(layout.C(addr, prevout.hash, prevout.index));
    }
  }

  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let addr = output.getHash();

    if (!addr)
      continue;

    this.put(layout.C(addr, hash, i), DUMMY);
  }
};

/**
 * Remove transaction from index.
 * @private
 * @param {TX} tx
 * @param {CoinView} view
 */

ChainDB.prototype.unindexTX = function unindexTX(tx, view) {
  let hash = tx.hash();

  if (this.options.indexTX) {
    this.del(layout.t(hash));
    if (this.options.indexAddress) {
      let hashes = tx.getHashes(view);
      for (let addr of hashes)
        this.del(layout.T(addr, hash));
    }
  }

  if (!this.options.indexAddress)
    return;

  if (!tx.isCoinbase()) {
    for (let input of tx.inputs) {
      let prevout = input.prevout;
      let addr = view.getOutput(input).getHash();

      if (!addr)
        continue;

      this.put(layout.C(addr, prevout.hash, prevout.index), DUMMY);
    }
  }

  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let addr = output.getHash();

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
  let bw = new StaticWriter(12);
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

  bw.writeU32(this.network.magic);
  bw.writeU32(flags);
  bw.writeU32(0);

  return bw.render();
};

ChainFlags.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  let flags;

  this.network = Network.fromMagic(br.readU32());

  flags = br.readU32();

  this.spv = (flags & 1) !== 0;
  this.witness = (flags & 2) !== 0;
  this.prune = (flags & 4) !== 0;
  this.indexTX = (flags & 8) !== 0;
  this.indexAddress = (flags & 16) !== 0;

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
  this.tip = encoding.ZERO_HASH;
  this.tx = 0;
  this.coin = 0;
  this.value = 0;
  this.committed = false;
}

ChainState.prototype.hash = function hash() {
  return this.tip.toString('hex');
};

ChainState.prototype.rhash = function rhash() {
  return util.revHex(this.hash());
};

ChainState.prototype.clone = function clone() {
  let state = new ChainState();
  state.tip = this.tip;
  state.tx = this.tx;
  state.coin = this.coin;
  state.value = this.value;
  return state;
};

ChainState.prototype.connect = function connect(block) {
  this.tx += block.txs.length;
};

ChainState.prototype.disconnect = function connect(block) {
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
  if (typeof hash === 'string')
    hash = Buffer.from(hash, 'hex');
  this.tip = hash;
  this.committed = true;
  return this.toRaw();
};

ChainState.prototype.toRaw = function toRaw() {
  let bw = new StaticWriter(56);
  bw.writeHash(this.tip);
  bw.writeU64(this.tx);
  bw.writeU64(this.coin);
  bw.writeU64(this.value);
  return bw.render();
};

ChainState.fromRaw = function fromRaw(data) {
  let state = new ChainState();
  let br = new BufferReader(data);
  state.tip = br.readHash();
  state.tx = br.readU53();
  state.coin = br.readU53();
  state.value = br.readU53();
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

  for (let deployment of this.network.deploys) {
    assert(!this.bits[deployment.bit]);
    this.bits[deployment.bit] = new Map();
  }
};

StateCache.prototype.set = function set(bit, entry, state) {
  let cache = this.bits[bit];

  assert(cache);

  if (cache.get(entry.hash) !== state) {
    cache.set(entry.hash, state);
    this.updates.push(new CacheUpdate(bit, entry.hash, state));
  }
};

StateCache.prototype.get = function get(bit, entry) {
  let cache = this.bits[bit];
  let state;

  assert(cache);

  state = cache.get(entry.hash);

  if (state == null)
    return -1;

  return state;
};

StateCache.prototype.commit = function commit() {
  this.updates.length = 0;
};

StateCache.prototype.drop = function drop() {
  let update, cache;

  for (update of this.updates) {
    cache = this.bits[update.bit];
    assert(cache);
    cache.delete(update.hash);
  }

  this.updates.length = 0;
};

StateCache.prototype.insert = function insert(bit, hash, state) {
  let cache = this.bits[bit];
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
