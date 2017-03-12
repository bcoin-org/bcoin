/*!
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');
var Amount = require('../btc/amount');
var encoding = require('../utils/encoding');
var co = require('../utils/co');
var Network = require('../protocol/network');
var CoinView = require('../coins/coinview');
var Coins = require('../coins/coins');
var UndoCoins = require('../coins/undocoins');
var LDB = require('../db/ldb');
var layout = require('./layout');
var LRU = require('../utils/lru');
var Block = require('../primitives/block');
var Outpoint = require('../primitives/outpoint');
var Address = require('../primitives/address');
var ChainEntry = require('./chainentry');
var TXMeta = require('../primitives/txmeta');
var U8 = encoding.U8;
var U32 = encoding.U32;
var DUMMY = new Buffer([0]);

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

ChainDB.prototype.open = co(function* open() {
  var state;

  this.logger.info('Opening ChainDB...');

  yield this.db.open();
  yield this.db.checkVersion('V', 2);

  state = yield this.getState();

  if (state) {
    // Verify options have not changed.
    yield this.verifyFlags();

    // Verify deployment params have not changed.
    yield this.verifyDeployments();

    // Load state caches.
    this.stateCache = yield this.getStateCache();

    // Grab the chainstate if we have one.
    this.state = state;

    this.logger.info('ChainDB successfully loaded.');
  } else {
    // Database is fresh.
    // Write initial state.
    yield this.saveFlags();
    yield this.saveDeployments();
    yield this.saveGenesis();

    this.logger.info('ChainDB successfully initialized.');
  }

  this.logger.info(
    'Chain State: hash=%s tx=%d coin=%d value=%s.',
    this.state.rhash(),
    this.state.tx,
    this.state.coin,
    Amount.btc(this.state.value));
});

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
  var batch = this.current;

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

ChainDB.prototype.commit = co(function* commit() {
  assert(this.current);
  assert(this.pending);

  try {
    yield this.current.write();
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
});

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
 * Get an entry directly from the LRU cache. This is
 * useful for optimization if we don't want to wait on a
 * nextTick during a `get()` call.
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

ChainDB.prototype.getHeight = co(function* getHeight(hash) {
  var entry, height;

  if (typeof hash === 'number')
    return hash;

  assert(typeof hash === 'string');

  if (hash === encoding.NULL_HASH)
    return -1;

  entry = this.cacheHash.get(hash);

  if (entry)
    return entry.height;

  height = yield this.db.get(layout.h(hash));

  if (!height)
    return -1;

  return height.readUInt32LE(0, true);
});

/**
 * Get the hash of a block by height. Note that this
 * will only return hashes in the main chain.
 * @method
 * @param {Number} height
 * @returns {Promise} - Returns {@link Hash}.
 */

ChainDB.prototype.getHash = co(function* getHash(height) {
  var entry, hash;

  if (typeof height === 'string')
    return height;

  assert(typeof height === 'number');

  if (height < 0)
    return;

  entry = this.cacheHeight.get(height);

  if (entry)
    return entry.hash;

  hash = yield this.db.get(layout.H(height));

  if (!hash)
    return;

  return hash.toString('hex');
});

/**
 * Retrieve a chain entry by height.
 * @method
 * @param {Number} height
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntryByHeight = co(function* getEntryByHeight(height) {
  var state, entry, hash;

  assert(typeof height === 'number');

  if (height < 0)
    return;

  entry = this.cacheHeight.get(height);

  if (entry)
    return entry;

  hash = yield this.db.get(layout.H(height));

  if (!hash)
    return;

  hash = hash.toString('hex');
  state = this.chain.state;

  entry = yield this.getEntryByHash(hash);

  if (!entry)
    return;

  // By the time getEntry has completed,
  // a reorg may have occurred. This entry
  // may not be on the main chain anymore.
  if (this.chain.state === state)
    this.cacheHeight.set(entry.height, entry);

  return entry;
});

/**
 * Retrieve a chain entry by hash.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntryByHash = co(function* getEntryByHash(hash) {
  var entry, raw;

  assert(typeof hash === 'string');

  if (hash === encoding.NULL_HASH)
    return;

  entry = this.cacheHash.get(hash);

  if (entry)
    return entry;

  raw = yield this.db.get(layout.e(hash));

  if (!raw)
    return;

  entry = ChainEntry.fromRaw(this.chain, raw);

  // There's no efficient way to check whether
  // this is in the main chain or not, so
  // don't add it to the height cache.
  this.cacheHash.set(entry.hash, entry);

  return entry;
});

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

ChainDB.prototype.hasEntry = co(function* hasEntry(hash) {
  var height = yield this.getHeight(hash);
  return height !== -1;
});

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

ChainDB.prototype.getState = co(function* getState() {
  var data = yield this.db.get(layout.R);

  if (!data)
    return;

  return ChainState.fromRaw(data);
});

/**
 * Write genesis block to database.
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.saveGenesis = co(function* saveGenesis() {
  var genesis = this.network.genesisBlock;
  var block = Block.fromRaw(genesis, 'hex');
  var entry = ChainEntry.fromBlock(this.chain, block);

  this.logger.info('Writing genesis block to ChainDB.');

  yield this.save(entry, block, new CoinView());
});

/**
 * Retrieve the database flags.
 * @method
 * @returns {Promise} - Returns {@link ChainFlags}.
 */

ChainDB.prototype.getFlags = co(function* getFlags() {
  var data = yield this.db.get(layout.O);

  if (!data)
    return;

  return ChainFlags.fromRaw(data);
});

/**
 * Verify current options against db options.
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.verifyFlags = co(function* verifyFlags() {
  var flags = yield this.getFlags();

  assert(flags, 'No flags found.');

  flags.verify(this.options);

  if (this.options.forceWitness)
    yield this.saveFlags();
});

/**
 * Get state caches.
 * @method
 * @returns {Promise} - Returns {@link StateCache}.
 */

ChainDB.prototype.getStateCache = co(function* getStateCache() {
  var stateCache = new StateCache(this.network);
  var i, items, item, key, bit, hash, state;

  items = yield this.db.range({
    gte: layout.v(0, encoding.ZERO_HASH),
    lte: layout.v(255, encoding.MAX_HASH),
    values: true
  });

  for (i = 0; i < items.length; i++) {
    item = items[i];
    key = layout.vv(item.key);
    bit = key[0];
    hash = key[1];
    state = item.value[0];
    stateCache.insert(bit, hash, state);
  }

  return stateCache;
});

/**
 * Save deployment table.
 * @returns {Promise}
 */

ChainDB.prototype.saveDeployments = function saveDeployments() {
  var batch = this.db.batch();
  this.writeDeployments(batch);
  return batch.write();
};

/**
 * Save deployment table.
 * @returns {Promise}
 */

ChainDB.prototype.writeDeployments = function writeDeployments(batch) {
  var bw = new StaticWriter(1 + 9 * this.network.deploys.length);
  var i, deployment;

  bw.writeU8(this.network.deploys.length);

  for (i = 0; i < this.network.deploys.length; i++) {
    deployment = this.network.deploys[i];
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

ChainDB.prototype.checkDeployments = co(function* checkDeployments() {
  var raw = yield this.db.get(layout.V);
  var invalid = [];
  var i, br, count, deployment;
  var bit, start, timeout;

  assert(raw, 'No deployment table found.');

  br = new BufferReader(raw);

  count = br.readU8();

  for (i = 0; i < count; i++) {
    bit = br.readU8();
    start = br.readU32();
    timeout = br.readU32();
    deployment = this.network.byBit(bit);

    if (deployment
        && start === deployment.startTime
        && timeout === deployment.timeout) {
      continue;
    }

    invalid.push(bit);
  }

  return invalid;
});

/**
 * Potentially invalidate state cache.
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.verifyDeployments = co(function* verifyDeployments() {
  var invalid = yield this.checkDeployments();
  var i, bit, batch;

  if (invalid.length === 0)
    return true;

  batch = this.db.batch();

  for (i = 0; i < invalid.length; i++) {
    bit = invalid[i];
    this.logger.warning('Versionbit deployment params modified.');
    this.logger.warning('Invalidating cache for bit %d.', bit);
    yield this.invalidateCache(bit, batch);
  }

  this.writeDeployments(batch);

  yield batch.write();

  return false;
});

/**
 * Invalidate state cache.
 * @method
 * @private
 * @returns {Promise}
 */

ChainDB.prototype.invalidateCache = co(function* invalidateCache(bit, batch) {
  var i, keys, key;

  keys = yield this.db.keys({
    gte: layout.v(bit, encoding.ZERO_HASH),
    lte: layout.v(bit, encoding.MAX_HASH)
  });

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    batch.del(key);
  }
});

/**
 * Get the _next_ block hash (does not work by height).
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Hash}.
 */

ChainDB.prototype.getNextHash = co(function* getNextHash(hash) {
  var data = yield this.db.get(layout.n(hash));

  if (!data)
    return;

  return data.toString('hex');
});

/**
 * Check to see if a block is on the main chain.
 * @method
 * @param {ChainEntry|Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.isMainChain = co(function* isMainChain(hash) {
  var entry;

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

  if (yield this.getNextHash(hash))
    return true;

  return false;
});

/**
 * Get all entries.
 * @returns {Promise} - Returns {@link ChainEntry}[].
 */

ChainDB.prototype.getEntries = function getEntries() {
  var self = this;
  return this.db.values({
    gte: layout.e(encoding.ZERO_HASH),
    lte: layout.e(encoding.MAX_HASH),
    parse: function(value) {
      return ChainEntry.fromRaw(self.chain, value);
    }
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

ChainDB.prototype.getCoin = co(function* getCoin(hash, index) {
  var state = this.state;
  var raw;

  if (this.options.spv)
    return;

  raw = this.coinCache.get(hash);

  if (raw)
    return Coins.parseCoin(raw, hash, index);

  raw = yield this.db.get(layout.c(hash));

  if (!raw)
    return;

  if (state === this.state)
    this.coinCache.set(hash, raw);

  return Coins.parseCoin(raw, hash, index);
});

/**
 * Get coins (unspents only).
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Coins}.
 */

ChainDB.prototype.getCoins = co(function* getCoins(hash) {
  var raw;

  if (this.options.spv)
    return;

  raw = this.coinCache.get(hash);

  if (raw)
    return Coins.fromRaw(raw, hash);

  raw = yield this.db.get(layout.c(hash));

  if (!raw)
    return;

  return Coins.fromRaw(raw, hash);
});

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

ChainDB.prototype.getCoinView = co(function* getCoinView(tx) {
  var view = new CoinView();
  var prevout = tx.getPrevout();
  var i, hash, coins;

  for (i = 0; i < prevout.length; i++) {
    hash = prevout[i];
    coins = yield this.getCoins(hash);

    if (!coins) {
      coins = new Coins();
      coins.hash = hash;
      view.add(coins);
      continue;
    }

    view.add(coins);
  }

  return view;
});

/**
 * Get coin viewpoint (historical).
 * @method
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getSpentView = co(function* getSpentView(tx) {
  var view = yield this.getCoinView(tx);
  var entries = view.toArray();
  var i, coins, meta;

  for (i = 0; i < entries.length; i++) {
    coins = entries[i];

    if (!coins.isEmpty())
      continue;

    meta = yield this.getMeta(coins.hash);

    if (!meta)
      continue;

    view.addTX(meta.tx, meta.height);
  }

  return view;
});

/**
 * Get coins necessary to be resurrected during a reorg.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Coin}[].
 */

ChainDB.prototype.getUndoCoins = co(function* getUndoCoins(hash) {
  var data = yield this.db.get(layout.u(hash));
  if (!data)
    return new UndoCoins();
  return UndoCoins.fromRaw(data);
});

/**
 * Retrieve a block from the database (not filled with coins).
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getBlock = co(function* getBlock(hash) {
  var data = yield this.getRawBlock(hash);

  if (!data)
    return;

  return Block.fromRaw(data);
});

/**
 * Retrieve a block from the database (not filled with coins).
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getRawBlock = co(function* getRawBlock(block) {
  var hash;

  if (this.options.spv)
    return;

  hash = yield this.getHash(block);

  if (!hash)
    return;

  return yield this.db.get(layout.b(hash));
});

/**
 * Get a historical block coin viewpoint.
 * @method
 * @param {Block} hash
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getBlockView = co(function* getBlockView(block) {
  var view = new CoinView();
  var undo = yield this.getUndoCoins(block.hash());
  var i, j, tx, input, prev, coins;

  if (undo.isEmpty())
    return view;

  for (i = block.txs.length - 1; i > 0; i--) {
    tx = block.txs[i];

    for (j = tx.inputs.length - 1; j >= 0; j--) {
      input = tx.inputs[j];
      prev = input.prevout.hash;

      if (!view.has(prev)) {
        assert(!undo.isEmpty());

        if (undo.top().height === -1) {
          coins = new Coins();
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
});

/**
 * Get a transaction with metadata.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXMeta}.
 */

ChainDB.prototype.getMeta = co(function* getMeta(hash) {
  var data;

  if (!this.options.indexTX)
    return;

  data = yield this.db.get(layout.t(hash));

  if (!data)
    return;

  return TXMeta.fromRaw(data);
});

/**
 * Retrieve a transaction.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

ChainDB.prototype.getTX = co(function* getTX(hash) {
  var meta = yield this.getMeta(hash);
  if (!meta)
    return;
  return meta.tx;
});

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
 * @param {Address[]} addresses
 * @returns {Promise} - Returns {@link Coin}[].
 */

ChainDB.prototype.getCoinsByAddress = co(function* getCoinsByAddress(addresses) {
  var coins = [];
  var i, j, address, hash, keys, key, coin;

  if (!this.options.indexAddress)
    return coins;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    hash = Address.getHash(address);

    if (!hash)
      continue;

    keys = yield this.db.keys({
      gte: layout.C(hash, encoding.ZERO_HASH, 0),
      lte: layout.C(hash, encoding.MAX_HASH, 0xffffffff),
      parse: layout.Cc
    });

    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      coin = yield this.getCoin(key[0], key[1]);

      if (coin)
        coins.push(coin);
    }
  }

  return coins;
});

/**
 * Get all transaction hashes to an address.
 * @method
 * @param {Address[]} addresses
 * @returns {Promise} - Returns {@link Hash}[].
 */

ChainDB.prototype.getHashesByAddress = co(function* getHashesByAddress(addresses) {
  var hashes = {};
  var i, address, hash;

  if (!this.options.indexTX || !this.options.indexAddress)
    return [];

  for (i = 0; i < addresses.length; i++) {
    address = addresses[i];
    hash = Address.getHash(address);

    if (!hash)
      continue;

    yield this.db.keys({
      gte: layout.T(hash, encoding.ZERO_HASH),
      lte: layout.T(hash, encoding.MAX_HASH),
      parse: function(key) {
        var hash = layout.Tt(key);
        hashes[hash] = true;
      }
    });
  }

  return Object.keys(hashes);
});

/**
 * Get all transactions pertinent to an address.
 * @method
 * @param {Address[]} addresses
 * @returns {Promise} - Returns {@link TX}[].
 */

ChainDB.prototype.getTXByAddress = co(function* getTXByAddress(addresses) {
  var mtxs = yield this.getMetaByAddress(addresses);
  var out = [];
  var i, mtx;

  for (i = 0; i < mtxs.length; i++) {
    mtx = mtxs[i];
    out.push(mtx.tx);
  }

  return out;
});

/**
 * Get all transactions pertinent to an address.
 * @method
 * @param {Address[]} addresses
 * @returns {Promise} - Returns {@link TXMeta}[].
 */

ChainDB.prototype.getMetaByAddress = co(function* getTXByAddress(addresses) {
  var txs = [];
  var i, hashes, hash, tx;

  if (!this.options.indexTX || !this.options.indexAddress)
    return txs;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  hashes = yield this.getHashesByAddress(addresses);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    tx = yield this.getMeta(hash);
    if (tx)
      txs.push(tx);
  }

  return txs;
});

/**
 * Scan the blockchain for transactions containing specified address hashes.
 * @method
 * @param {Hash} start - Block hash to start at.
 * @param {Bloom} filter - Bloom filter containing tx and address hashes.
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

ChainDB.prototype.scan = co(function* scan(start, filter, iter) {
  var total = 0;
  var i, j, entry, hash, tx, txs, block;
  var found, input, output, prevout;

  if (start == null)
    start = this.network.genesis.hash;

  if (typeof start === 'number')
    this.logger.info('Scanning from height %d.', start);
  else
    this.logger.info('Scanning from block %s.', util.revHex(start));

  entry = yield this.getEntry(start);

  if (!entry)
    return;

  if (!(yield entry.isMainChain()))
    throw new Error('Cannot rescan an alternate chain.');

  while (entry) {
    block = yield this.getBlock(entry.hash);
    txs = [];
    total++;

    if (!block) {
      if (!this.options.spv && !this.options.prune)
        throw new Error('Block not found.');
      yield iter(entry, txs);
      entry = yield entry.getNext();
      continue;
    }

    this.logger.info(
      'Scanning block %s (%d).',
      entry.rhash(), entry.height);

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      found = false;

      for (j = 0; j < tx.outputs.length; j++) {
        output = tx.outputs[j];
        hash = output.getHash();

        if (!hash)
          continue;

        if (filter.test(hash)) {
          prevout = Outpoint.fromTX(tx, j);
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

      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        prevout = input.prevout;

        if (filter.test(prevout.toRaw())) {
          txs.push(tx);
          break;
        }
      }
    }

    yield iter(entry, txs);

    entry = yield entry.getNext();
  }

  this.logger.info('Finished scanning %d blocks.', total);
});

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

ChainDB.prototype.save = co(function* save(entry, block, view) {
  this.start();
  try {
    yield this._save(entry, block, view);
  } catch (e) {
    this.drop();
    throw e;
  }
  yield this.commit();
});

/**
 * Save an entry without a batch.
 * @method
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view
 * @returns {Promise}
 */

ChainDB.prototype._save = co(function* save(entry, block, view) {
  var hash = block.hash();

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
    yield this.saveBlock(entry, block);
    return;
  }

  // Hash->next-block index.
  this.put(layout.n(entry.prevBlock), hash);

  // Height->hash index.
  this.put(layout.H(entry.height), hash);
  this.cacheHeight.push(entry.height, entry);

  // Connect block and save data.
  yield this.saveBlock(entry, block, view);

  // Commit new chain state.
  this.put(layout.R, this.pending.commit(hash));
});

/**
 * Reconnect the block to the chain.
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise}
 */

ChainDB.prototype.reconnect = co(function* reconnect(entry, block, view) {
  this.start();
  try {
    yield this._reconnect(entry, block, view);
  } catch (e) {
    this.drop();
    throw e;
  }
  yield this.commit();
});

/**
 * Reconnect block without a batch.
 * @method
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise}
 */

ChainDB.prototype._reconnect = co(function* reconnect(entry, block, view) {
  var hash = block.hash();

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
  yield this.connectBlock(entry, block, view);

  // Update chain state.
  this.put(layout.R, this.pending.commit(hash));
});

/**
 * Disconnect block from the chain.
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise}
 */

ChainDB.prototype.disconnect = co(function* disconnect(entry, block) {
  var view;

  this.start();

  try {
    view = yield this._disconnect(entry, block);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return view;
});

/**
 * Disconnect block without a batch.
 * @private
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype._disconnect = co(function* disconnect(entry, block) {
  var view;

  // Remove hash->next-block index.
  this.del(layout.n(entry.prevBlock));

  // Remove height->hash index.
  this.del(layout.H(entry.height));
  this.cacheHeight.unpush(entry.height);

  // Update state caches.
  this.saveUpdates();

  // Disconnect inputs.
  view = yield this.disconnectBlock(entry, block);

  // Revert chain state to previous tip.
  this.put(layout.R, this.pending.commit(entry.prevBlock));

  return view;
});

/**
 * Save state cache updates.
 * @private
 */

ChainDB.prototype.saveUpdates = function saveUpdates() {
  var updates = this.stateCache.updates;
  var i, update;

  if (updates.length === 0)
    return;

  this.logger.info('Saving %d state cache updates.', updates.length);

  for (i = 0; i < updates.length; i++) {
    update = updates[i];
    this.put(layout.v(update.bit, update.hash), update.toRaw());
  }
};

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @method
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

ChainDB.prototype.reset = co(function* reset(block) {
  var entry = yield this.getEntry(block);
  var tip;

  if (!entry)
    throw new Error('Block not found.');

  if (!(yield entry.isMainChain()))
    throw new Error('Cannot reset on alternate chain.');

  if (this.options.prune)
    throw new Error('Cannot reset when pruned.');

  // We need to remove all alternate
  // chains first. This is ugly, but
  // it's the only safe way to reset
  // the chain.
  yield this.removeChains();

  tip = yield this.getTip();
  assert(tip);

  this.logger.debug('Resetting main chain to: %s', entry.rhash());

  for (;;) {
    this.start();

    // Stop once we hit our target tip.
    if (tip.hash === entry.hash) {
      this.put(layout.R, this.pending.commit(tip.hash));
      yield this.commit();
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
      yield this.removeBlock(tip);
    } catch (e) {
      this.drop();
      throw e;
    }

    // Revert chain state to previous tip.
    this.put(layout.R, this.pending.commit(tip.prevBlock));

    yield this.commit();

    // Update caches _after_ successful commit.
    this.cacheHeight.remove(tip.height);
    this.cacheHash.remove(tip.hash);

    tip = yield this.getEntry(tip.prevBlock);
    assert(tip);
  }

  return tip;
});

/**
 * Remove all alternate chains.
 * @method
 * @returns {Promise}
 */

ChainDB.prototype.removeChains = co(function* removeChains() {
  var tips = yield this.getTips();
  var i;

  // Note that this has to be
  // one giant atomic write!
  this.start();

  try {
    for (i = 0; i < tips.length; i++)
      yield this._removeChain(tips[i]);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();
});

/**
 * Remove an alternate chain.
 * @method
 * @private
 * @param {Hash} hash - Alternate chain tip.
 * @returns {Promise}
 */

ChainDB.prototype._removeChain = co(function* removeChain(hash) {
  var tip = yield this.getEntry(hash);

  if (!tip)
    throw new Error('Alternate chain tip not found.');

  this.logger.debug('Removing alternate chain: %s.', tip.rhash());

  for (;;) {
    if (yield tip.isMainChain())
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

    tip = yield this.getEntry(tip.prevBlock);
    assert(tip);
  }
});

/**
 * Save a block (not an entry) to the
 * database and potentially connect the inputs.
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.saveBlock = co(function* saveBlock(entry, block, view) {
  var hash = block.hash();

  if (this.options.spv)
    return;

  // Write actual block data (this may be
  // better suited to flat files in the future).
  this.put(layout.b(hash), block.toRaw());

  if (!view)
    return;

  yield this.connectBlock(entry, block, view);
});

/**
 * Remove a block (not an entry) to the database.
 * Disconnect inputs.
 * @method
 * @param {ChainEntry} entry
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.removeBlock = co(function* removeBlock(entry) {
  var block;

  if (this.options.spv)
    return;

  block = yield this.getBlock(entry.hash);

  if (!block)
    throw new Error('Block not found.');

  this.del(layout.b(block.hash()));

  return yield this.disconnectBlock(entry, block);
});

/**
 * Commit coin view to database.
 * @private
 * @param {CoinView} view
 */

ChainDB.prototype.saveView = function saveView(view) {
  var i, coins, raw;

  view = view.toArray();

  for (i = 0; i < view.length; i++) {
    coins = view[i];
    if (coins.isEmpty()) {
      this.del(layout.c(coins.hash));
      this.coinCache.unpush(coins.hash);
    } else {
      raw = coins.toRaw();
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

ChainDB.prototype.connectBlock = co(function* connectBlock(entry, block, view) {
  var hash = block.hash();
  var i, j, tx, input, output;

  if (this.options.spv)
    return;

  this.pending.connect(block);

  // Genesis block's coinbase is unspendable.
  if (this.chain.isGenesis(block))
    return;

  // Update chain state value.
  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    if (i > 0) {
      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        this.pending.spend(view.getOutput(input));
      }
    }

    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];

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
  yield this.pruneBlock(entry);
});

/**
 * Disconnect block inputs.
 * @method
 * @param {ChainEntry} entry
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.disconnectBlock = co(function* disconnectBlock(entry, block) {
  var view = new CoinView();
  var hash = block.hash();
  var i, j, undo, tx, input, output;

  if (this.options.spv)
    return view;

  undo = yield this.getUndoCoins(hash);

  this.pending.disconnect(block);

  // Disconnect all transactions.
  for (i = block.txs.length - 1; i >= 0; i--) {
    tx = block.txs[i];

    if (i > 0) {
      yield view.ensureInputs(this, tx);

      for (j = tx.inputs.length - 1; j >= 0; j--) {
        input = tx.inputs[j];
        undo.apply(view, input.prevout);
        this.pending.add(view.getOutput(input));
      }
    }

    // Remove any created coins.
    view.removeTX(tx, entry.height);

    for (j = tx.outputs.length - 1; j >= 0; j--) {
      output = tx.outputs[j];

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
});

/**
 * Prune a block from the chain and
 * add current block to the prune queue.
 * @method
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

ChainDB.prototype.pruneBlock = co(function* pruneBlock(entry) {
  var height, hash;

  if (this.options.spv)
    return;

  if (!this.options.prune)
    return;

  height = entry.height - this.network.block.keepBlocks;

  if (height <= this.network.block.pruneAfterHeight)
    return;

  hash = yield this.getHash(height);

  if (!hash)
    return;

  this.del(layout.b(hash));
  this.del(layout.u(hash));
});

/**
 * Save database options.
 * @returns {Promise}
 */

ChainDB.prototype.saveFlags = function saveFlags() {
  var flags = ChainFlags.fromOptions(this.options);
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
  var hash = tx.hash();
  var i, meta, input, output;
  var prevout, hashes, addr;

  if (this.options.indexTX) {
    meta = TXMeta.fromTX(tx, entry, index);

    this.put(layout.t(hash), meta.toRaw());

    if (this.options.indexAddress) {
      hashes = tx.getHashes(view);
      for (i = 0; i < hashes.length; i++) {
        addr = hashes[i];
        this.put(layout.T(addr, hash), DUMMY);
      }
    }
  }

  if (!this.options.indexAddress)
    return;

  if (!tx.isCoinbase()) {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      addr = view.getOutput(input).getHash();

      if (!addr)
        continue;

      this.del(layout.C(addr, prevout.hash, prevout.index));
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    addr = output.getHash();

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
  var hash = tx.hash();
  var i, input, output, prevout, hashes, addr;

  if (this.options.indexTX) {
    this.del(layout.t(hash));
    if (this.options.indexAddress) {
      hashes = tx.getHashes(view);
      for (i = 0; i < hashes.length; i++) {
        addr = hashes[i];
        this.del(layout.T(addr, hash));
      }
    }
  }

  if (!this.options.indexAddress)
    return;

  if (!tx.isCoinbase()) {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      addr = view.getOutput(input).getHash();

      if (!addr)
        continue;

      this.put(layout.C(addr, prevout.hash, prevout.index), DUMMY);
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    addr = output.getHash();

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

ChainFlags.prototype.verify = function verify(options) {
  if (options.network !== this.network)
    throw new Error('Network mismatch for chain.');

  if (options.spv && !this.spv)
    throw new Error('Cannot retroactively enable SPV.');

  if (!options.spv && this.spv)
    throw new Error('Cannot retroactively disable SPV.');

  if (!options.forceWitness) {
    if (!this.witness)
      throw new Error('Cannot retroactively enable witness.');
  }

  if (options.prune && !this.prune)
    throw new Error('Cannot retroactively prune.');

  if (!options.prune && this.prune)
    throw new Error('Cannot retroactively unprune.');

  if (options.indexTX && !this.indexTX)
    throw new Error('Cannot retroactively enable TX indexing.');

  if (!options.indexTX && this.indexTX)
    throw new Error('Cannot retroactively disable TX indexing.');

  if (options.indexAddress && !this.indexAddress)
    throw new Error('Cannot retroactively enable address indexing.');

  if (!options.indexAddress && this.indexAddress)
    throw new Error('Cannot retroactively disable address indexing.');
};

ChainFlags.prototype.toRaw = function toRaw() {
  var bw = new StaticWriter(12);
  var flags = 0;

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
  var br = new BufferReader(data);
  var flags;

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

ChainState.prototype.hash = function() {
  return this.tip.toString('hex');
};

ChainState.prototype.rhash = function() {
  return util.revHex(this.hash());
};

ChainState.prototype.clone = function clone() {
  var state = new ChainState();
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
    hash = new Buffer(hash, 'hex');
  this.tip = hash;
  this.committed = true;
  return this.toRaw();
};

ChainState.prototype.toRaw = function toRaw() {
  var bw = new StaticWriter(56);
  bw.writeHash(this.tip);
  bw.writeU64(this.tx);
  bw.writeU64(this.coin);
  bw.writeU64(this.value);
  return bw.render();
};

ChainState.fromRaw = function fromRaw(data) {
  var state = new ChainState();
  var br = new BufferReader(data);
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
  var i, deployment;

  for (i = 0; i < 32; i++)
    this.bits.push(null);

  for (i = 0; i < this.network.deploys.length; i++) {
    deployment = this.network.deploys[i];
    assert(!this.bits[deployment.bit]);
    this.bits[deployment.bit] = {};
  }
};

StateCache.prototype.set = function set(bit, entry, state) {
  var cache = this.bits[bit];

  assert(cache);

  if (cache[entry.hash] !== state) {
    cache[entry.hash] = state;
    this.updates.push(new CacheUpdate(bit, entry.hash, state));
  }
};

StateCache.prototype.get = function get(bit, entry) {
  var cache = this.bits[bit];
  var state;

  assert(cache);

  state = cache[entry.hash];

  if (state == null)
    return -1;

  return state;
};

StateCache.prototype.commit = function commit() {
  this.updates.length = 0;
};

StateCache.prototype.drop = function drop() {
  var i, update, cache;

  for (i = 0; i < this.updates.length; i++) {
    update = this.updates[i];
    cache = this.bits[update.bit];
    assert(cache);
    delete cache[update.hash];
  }

  this.updates.length = 0;
};

StateCache.prototype.insert = function insert(bit, hash, state) {
  var cache = this.bits[bit];
  assert(cache);
  cache[hash] = state;
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
