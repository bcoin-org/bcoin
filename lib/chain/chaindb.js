/*!
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var AsyncObject = require('../utils/async');
var constants = require('../protocol/constants');
var utils = require('../utils/utils');
var assert = require('assert');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');
var co = require('../utils/co');
var Network = require('../protocol/network');
var CoinView = require('./coinview');
var Coins = require('./coins');
var ldb = require('../db/ldb');
var LRU = require('../utils/lru');
var Block = require('../primitives/block');
var Coin = require('../primitives/coin');
var Outpoint = require('../primitives/outpoint');
var TX = require('../primitives/tx');
var Address = require('../primitives/address');
var ChainEntry = require('./chainentry');
var U32 = utils.U32;
var DUMMY = new Buffer([0]);

/*
 * Database Layout:
 *   R -> tip hash
 *   O -> chain options
 *   e[hash] -> entry
 *   h[hash] -> height
 *   H[height] -> hash
 *   n[hash] -> next hash
 *   b[hash] -> block
 *   t[hash] -> extended tx
 *   c[hash] -> coins
 *   u[hash] -> undo coins
 *   T[addr-hash][hash] -> dummy (tx by address)
 *   C[addr-hash][hash][index] -> dummy (coin by address)
 *   W+T[witaddr-hash][hash] -> dummy (tx by address)
 *   W+C[witaddr-hash][hash][index] -> dummy (coin by address)
 */

var layout = {
  R: new Buffer([0x52]),
  O: new Buffer([0x4f]),
  e: function e(hash) {
    return pair(0x65, hash);
  },
  h: function h(hash) {
    return pair(0x68, hash);
  },
  H: function H(height) {
    return ipair(0x48, height);
  },
  n: function n(hash) {
    return pair(0x6e, hash);
  },
  b: function b(hash) {
    return pair(0x62, hash);
  },
  t: function t(hash) {
    return pair(0x74, hash);
  },
  c: function c(hash) {
    return pair(0x63, hash);
  },
  u: function u(hash) {
    return pair(0x75, hash);
  },
  T: function T(address, hash) {
    var len = address.length;
    var key;

    if (typeof address === 'string')
      len /= 2;

    if (len === 32) {
      key = new Buffer(65);
      key[0] = 0xab; // W + T
      write(key, address, 1);
      write(key, hash, 33);
    } else {
      key = new Buffer(53);
      key[0] = 0x54; // T
      write(key, address, 1);
      write(key, hash, 21);
    }

    return key;
  },
  C: function C(address, hash, index) {
    var len = address.length;
    var key;

    if (typeof address === 'string')
      len /= 2;

    if (len === 32) {
      key = new Buffer(69);
      key[0] = 0x9a; // W + C
      write(key, address, 1);
      write(key, hash, 33);
      key.writeUInt32BE(index, 65, true);
    } else {
      key = new Buffer(57);
      key[0] = 0x43; // C
      write(key, address, 1);
      write(key, hash, 21);
      key.writeUInt32BE(index, 53, true);
    }

    return key;
  },
  Cc: function Cc(key) {
    var hash, index;

    if (key.length === 69) {
      hash = key.toString('hex', 33, 65);
      index = key.readUInt32BE(65, 0);
    } else {
      hash = key.toString('hex', 21, 53);
      index = key.readUInt32BE(53, 0);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    return key.length === 65
      ? key.toString('hex', 33, 65)
      : key.toString('hex', 21, 53);
  }
};

if (utils.isBrowser)
  layout = require('./browser');

/**
 * The database backend for the {@link Chain} object.
 * @exports ChainDB
 * @constructor
 * @param {Object} options
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

  AsyncObject.call(this);

  this.chain = chain;
  this.logger = chain.logger;
  this.network = chain.network;
  this.options = new ChainOptions(chain.options);

  this.db = ldb({
    location: chain.options.location,
    db: chain.options.db,
    maxOpenFiles: chain.options.maxFiles,
    compression: true,
    cacheSize: 16 << 20,
    writeBufferSize: 8 << 20,
    bufferKeys: !utils.isBrowser
  });

  this.state = new ChainState();
  this.pending = null;
  this.current = null;

  // We want at least 1 retarget interval cached
  // for retargetting, but we need at least two
  // cached for optimal versionbits state checks.
  // We add a padding of 100 for forked chains,
  // reorgs, chain locator creation and the bip34
  // check.
  this.cacheWindow = (this.network.pow.retargetInterval + 1) * 2 + 100;

  // We want to keep the last 5 blocks of unspents in memory.
  this.coinWindow = 25 << 20;

  this.coinCache = new LRU.Nil();
  this.cacheHash = new LRU(this.cacheWindow);
  this.cacheHeight = new LRU(this.cacheWindow);

  if (chain.options.coinCache)
    this.coinCache = new LRU(this.coinWindow, getSize);
}

utils.inherits(ChainDB, AsyncObject);

/**
 * Database layout.
 * @type {Object}
 */

ChainDB.layout = layout;

/**
 * Open the chain db, wait for the database to load.
 * @alias ChainDB#open
 * @returns {Promise}
 */

ChainDB.prototype._open = co(function* open() {
  var state, options, block, entry;

  this.logger.info('Starting chain load.');

  yield this.db.open();

  yield this.db.checkVersion('V', 1);

  state = yield this.getState();
  options = yield this.getOptions();

  if (options) {
    // Verify the options haven't changed.
    this.options.verify(options);
    if (this.options.forceWitness)
      yield this.saveOptions();
  } else {
    yield this.saveOptions();
  }

  if (state) {
    // Grab the chainstate if we have one.
    this.state = state;
  } else {
    // Otherwise write the genesis block.
    // (We assume this database is fresh).
    block = Block.fromRaw(this.network.genesisBlock, 'hex');
    block.setHeight(0);
    entry = ChainEntry.fromBlock(this.chain, block);
    yield this.save(entry, block, new CoinView());
  }

  this.logger.info('Chain successfully loaded.');

  this.logger.info(
    'Chain State: hash=%s tx=%d coin=%d value=%s.',
    this.state.rhash,
    this.state.tx,
    this.state.coin,
    utils.btc(this.state.value));
});

/**
 * Close the chain db, wait for the database to close.
 * @alias ChainDB#close
 * @returns {Promise}
 */

ChainDB.prototype._close = function close() {
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

  batch.clear();
};

/**
 * Commit current batch.
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
});

/**
 * Test the cache for a present entry hash or height.
 * @param {Hash|Number} hash - Hash or height.
 */

ChainDB.prototype.hasCache = function hasCache(hash) {
  checkHash(hash);

  if (typeof hash === 'number')
    return this.cacheHeight.has(hash);

  return this.cacheHash.has(hash);
};

/**
 * Get an entry directly from the LRU cache. This is
 * useful for optimization if we don't want to wait on a
 * nextTick during a `get()` call.
 * @param {Hash|Number} hash - Hash or height.
 */

ChainDB.prototype.getCache = function getCache(hash) {
  checkHash(hash);

  if (typeof hash === 'number')
    return this.cacheHeight.get(hash);

  return this.cacheHash.get(hash);
};

/**
 * Get the height of a block by hash.
 * @param {Hash} hash
 * @returns {Promise} - Returns Number.
 */

ChainDB.prototype.getHeight = co(function* getHeight(hash) {
  var entry, height;

  checkHash(hash);

  if (typeof hash === 'number')
    return hash;

  if (hash === constants.NULL_HASH)
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
 * @param {Number} height
 * @returns {Promise} - Returns {@link Hash}.
 */

ChainDB.prototype.getHash = co(function* getHash(height) {
  var entry, hash;

  checkHash(height);

  if (typeof height === 'string')
    return height;

  entry = this.cacheHeight.get(height);

  if (entry)
    return entry.hash;

  hash = yield this.db.get(layout.H(height));

  if (!hash)
    return;

  return hash.toString('hex');
});

/**
 * Get the current chain height from the tip record.
 * @returns {Promise} - Returns Number.
 */

ChainDB.prototype.getChainHeight = co(function* getChainHeight() {
  var entry = yield this.getTip();

  if (!entry)
    return -1;

  return entry.height;
});

/**
 * Get both hash and height depending on the value passed in.
 * @param {Hash|Number} block - Can be a has or height.
 * @returns {Promise} - Returns {@link Hash}, Number.
 */

ChainDB.prototype.getBoth = co(function* getBoth(block) {
  var hash, height;

  checkHash(block);

  if (typeof block === 'string')
    hash = block;
  else
    height = block;

  if (!hash) {
    hash = yield this.getHash(height);

    if (hash == null)
      height = -1;

    return new BlockPair(hash, height);
  }

  height = yield this.getHeight(hash);

  if (height === -1)
    hash = null;

  return new BlockPair(hash, height);
});

/**
 * Retrieve a chain entry but do _not_ add it to the LRU cache.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getEntry = co(function* getEntry(hash) {
  var entry;

  checkHash(hash);

  hash = yield this.getHash(hash);

  if (!hash)
    return;

  entry = this.cacheHash.get(hash);

  if (entry)
    return entry;

  entry = yield this.db.get(layout.e(hash));

  if (!entry)
    return;

  return ChainEntry.fromRaw(this.chain, entry);
});

/**
 * Retrieve a chain entry and add it to the LRU cache.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.get = co(function* get(hash) {
  var entry = yield this.getEntry(hash);

  if (!entry)
    return;

  // There's no efficient way to check whether
  // this is in the main chain or not, so
  // don't add it to the height cache.
  this.cacheHash.set(entry.hash, entry);

  return entry;
});

/**
 * Test whether the chain contains a block in the
 * main chain or an alternate chain. Alternate chains will only
 * be tested if the lookup is done by hash.
 * @param {Hash|Number} block - Hash or height.
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.has = co(function* has(block) {
  var item = yield this.getBoth(block);
  return item.hash != null;
});

/**
 * Retrieve the tip entry from the tip record.
 * @returns {Promise} - Returns {@link ChainEntry}.
 */

ChainDB.prototype.getTip = function getTip() {
  return this.get(this.state.hash);
};

/**
 * Retrieve the tip entry from the tip record.
 * @returns {Promise} - Returns {@link ChainState}.
 */

ChainDB.prototype.getState = co(function* getState() {
  var data = yield this.db.get(layout.R);

  if (!data)
    return;

  return ChainState.fromRaw(data);
});

/**
 * Retrieve the tip entry from the tip record.
 * @returns {Promise} - Returns {@link ChainOptions}.
 */

ChainDB.prototype.getOptions = co(function* getOptions() {
  var data = yield this.db.get(layout.O);

  if (!data)
    return;

  return ChainOptions.fromRaw(data);
});

/**
 * Get the _next_ block hash (does not work by height).
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
 * @param {ChainEntry|Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

ChainDB.prototype.isMainChain = co(function* isMainChain(hash) {
  assert(typeof hash === 'string');

  if (hash === this.chain.tip.hash
      || hash === this.network.genesis.hash) {
    return true;
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
    gte: layout.e(constants.ZERO_HASH),
    lte: layout.e(constants.MAX_HASH),
    parse: function(key, value) {
      return ChainEntry.fromRaw(self.chain, value);
    }
  });
};

/**
 * Get a coin (unspents only).
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

ChainDB.prototype.getCoin = co(function* getCoin(hash, index) {
  var coins;

  if (this.options.spv)
    return;

  coins = this.coinCache.get(hash);

  if (coins)
    return Coins.parseCoin(coins, hash, index);

  coins = yield this.db.get(layout.c(hash));

  if (!coins)
    return;

  this.coinCache.set(hash, coins);

  return Coins.parseCoin(coins, hash, index);
});

/**
 * Get coins (unspents only).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Coins}.
 */

ChainDB.prototype.getCoins = co(function* getCoins(hash) {
  var coins;

  if (this.options.spv)
    return;

  coins = this.coinCache.get(hash);

  if (coins)
    return Coins.fromRaw(coins, hash);

  coins = yield this.db.get(layout.c(hash));

  if (!coins)
    return;

  this.coinCache.set(hash, coins);

  return Coins.fromRaw(coins, hash);
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
 * Get a view of the existing coins necessary to verify a block.
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getCoinView = co(function* getCoinView(block, callback) {
  var view = new CoinView();
  var prevout = block.getPrevout();
  var i, prev, coins;

  for (i = 0; i < prevout.length; i++) {
    prev = prevout[i];
    coins = yield this.getCoins(prev);
    if (coins)
      view.add(coins);
  }

  return view;
});

/**
 * Get coins necessary to be resurrected during a reorg.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Coin}[].
 */

ChainDB.prototype.getUndoCoins = co(function* getUndoCoins(hash) {
  var data = yield this.db.get(layout.u(hash));
  var p, coins;

  if (!data)
    return;

  p = new BufferReader(data);
  coins = [];

  while (p.left())
    coins.push(Coin.fromRaw(p));

  return coins;
});

/**
 * Get a coin view containing unspent coins as
 * well as the coins to be resurrected for a reorg.
 * (Note: fills block with undo coins).
 * @param {Block} block
 * @returns {Promise} - Returns {@link CoinView}.
 */

ChainDB.prototype.getUndoView = co(function* getUndoView(block) {
  var view = yield this.getCoinView(block);
  var coins = yield this.getUndoCoins(block.hash());
  var i, j, k, tx, input, coin;

  if (!coins)
    return view;

  for (i = 0, k = 0; i < block.txs.length; i++) {
    tx = block.txs[i];

    if (tx.isCoinbase())
      continue;

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      coin = coins[k++];
      coin.hash = input.prevout.hash;
      coin.index = input.prevout.index;
      input.coin = coin;
      view.addCoin(coin);
    }
  }

  return view;
});

/**
 * Retrieve a block from the database (not filled with coins).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getBlock = co(function* getBlock(hash) {
  var item, data, block;

  if (this.options.spv)
    return;

  item = yield this.getBoth(hash);

  if (!item.hash)
    return;

  data = yield this.db.get(layout.b(item.hash));

  if (!data)
    return;

  block = Block.fromRaw(data);
  block.setHeight(item.height);

  return block;
});

/**
 * Retrieve a block from the database (not filled with coins).
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
 * Get a block and fill it with coins (historical).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.getFullBlock = co(function* getFullBlock(hash) {
  var block = yield this.getBlock(hash);

  if (!block)
    return;

  yield this.getUndoView(block);

  return block;
});

/**
 * Fill a transaction with coins (only unspents).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

ChainDB.prototype.fillCoins = co(function* fillCoins(tx) {
  var i, input, prevout, coin;

  if (tx.isCoinbase())
    return;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (input.coin)
      continue;

    coin = yield this.getCoin(prevout.hash, prevout.index);

    if (!coin)
      continue;

    input.coin = coin;
  }
});

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

ChainDB.prototype.fillHistory = co(function* fillHistory(tx) {
  var i, input, prevout, prev;

  if (!this.options.indexTX)
    return;

  if (tx.isCoinbase())
    return;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (input.coin)
      continue;

    prev = yield this.getTX(prevout.hash);

    if (!prev)
      continue;

    if (prevout.index >= prev.outputs.length)
      continue;

    input.coin = Coin.fromTX(prev, prevout.index);
  }
});

/**
 * Retrieve a transaction (not filled with coins).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

ChainDB.prototype.getTX = co(function* getTX(hash) {
  var data;

  if (!this.options.indexTX)
    return;

  data = yield this.db.get(layout.t(hash));

  if (!data)
    return;

  return TX.fromExtended(data);
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
 * Get a transaction and fill it with coins (historical).
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

ChainDB.prototype.getFullTX = co(function* getFullTX(hash) {
  var tx;

  if (!this.options.indexTX)
    return;

  tx = yield this.getTX(hash);

  if (!tx)
    return;

  yield this.fillHistory(tx);

  return tx;
});

/**
 * Get all coins pertinent to an address.
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
      gte: layout.C(hash, constants.ZERO_HASH, 0),
      lte: layout.C(hash, constants.MAX_HASH, 0xffffffff),
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
      gte: layout.T(hash, constants.ZERO_HASH),
      lte: layout.T(hash, constants.MAX_HASH),
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
 * @param {Address[]} addresses
 * @returns {Promise} - Returns {@link TX}[].
 */

ChainDB.prototype.getTXByAddress = co(function* getTXByAddress(addresses) {
  var txs = [];
  var i, hashes, hash, tx;

  if (!this.options.indexTX || !this.options.indexAddress)
    return txs;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  hashes = yield this.getHashesByAddress(addresses);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    tx = yield this.getTX(hash);
    if (tx)
      txs.push(tx);
  }

  return txs;
});

/**
 * Scan the blockchain for transactions containing specified address hashes.
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
    this.logger.info('Scanning from block %s.', utils.revHex(start));

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
      entry.rhash, entry.height);

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
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView?} view
 * @returns {Promise}
 */

ChainDB.prototype._save = co(function* save(entry, block, view) {
  var hash = block.hash();

  this.put(layout.h(hash), U32(entry.height));
  this.put(layout.e(hash), entry.toRaw());

  this.cacheHash.push(entry.hash, entry);

  if (!view) {
    yield this.saveBlock(block);
    return;
  }

  this.cacheHeight.push(entry.height, entry);

  this.put(layout.n(entry.prevBlock), hash);
  this.put(layout.H(entry.height), hash);

  yield this.saveBlock(block, view);

  this.put(layout.R, this.pending.commit(hash));
});

/**
 * Reconnect the block to the chain.
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
 * @private
 * @param {ChainEntry} entry
 * @param {Block} block
 * @param {CoinView} view
 * @returns {Promise}
 */

ChainDB.prototype._reconnect = co(function* reconnect(entry, block, view) {
  var hash = block.hash();

  this.put(layout.n(entry.prevBlock), hash);
  this.put(layout.H(entry.height), hash);

  this.cacheHash.push(entry.hash, entry);
  this.cacheHeight.push(entry.height, entry);

  yield this.connectBlock(block, view);

  this.put(layout.R, this.pending.commit(hash));
});

/**
 * Disconnect block from the chain.
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

ChainDB.prototype.disconnect = co(function* disconnect(entry) {
  var block;

  this.start();

  try {
    block = yield this._disconnect(entry);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return block;
});

/**
 * Disconnect block without a batch.
 * @private
 * @param {ChainEntry} entry
 * @returns {Promise}
 */

ChainDB.prototype._disconnect = co(function* disconnect(entry) {
  var block;

  this.del(layout.n(entry.prevBlock));
  this.del(layout.H(entry.height));

  this.cacheHeight.unpush(entry.height);

  block = yield this.getBlock(entry.hash);

  if (!block)
    throw new Error('Block not found.');

  yield this.disconnectBlock(block);

  this.put(layout.R, this.pending.commit(entry.prevBlock));

  return block;
});

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

ChainDB.prototype.reset = co(function* reset(block) {
  var entry = yield this.get(block);
  var tip;

  if (!entry)
    throw new Error('Block not found.');

  if (!(yield entry.isMainChain()))
    throw new Error('Cannot reset on alternate chain.');

  if (this.options.prune)
    throw new Error('Cannot reset when pruned.');

  tip = yield this.getTip();
  assert(tip);

  this.logger.debug('Resetting main chain to: %s', entry.rhash);

  while (!tip.isGenesis()) {
    this.start();

    if (tip.hash === entry.hash) {
      this.put(layout.R, this.pending.commit(tip.hash));
      return yield this.commit();
    }

    this.del(layout.H(tip.height));
    this.del(layout.h(tip.hash));
    this.del(layout.e(tip.hash));
    this.del(layout.n(tip.prevBlock));

    try {
      yield this.removeBlock(tip.hash);
    } catch (e) {
      this.drop();
      throw e;
    }

    this.put(layout.R, this.pending.commit(tip.prevBlock));

    yield this.commit();

    this.cacheHeight.remove(tip.height);
    this.cacheHash.remove(tip.hash);

    tip = yield this.get(tip.prevBlock);
    assert(tip);
  }
});

/**
 * Reset the chain to a height or hash. Useful for replaying
 * the blockchain download for SPV.
 * @param {Hash|Number} block - hash/height
 * @returns {Promise}
 */

ChainDB.prototype.replay = co(function* replay(block) {
  var entry = yield this.get(block);

  if (!entry)
    throw new Error('Block not found.');

  if (!(yield entry.isMainChain()))
    throw new Error('Cannot reset on alternate chain.');

  if (entry.hash === this.network.genesis.hash)
    return yield this.reset(entry.hash);

  yield this.reset(entry.prevBlock);
});

/**
 * Save a block (not an entry) to the
 * database and potentially connect the inputs.
 * @param {Block} block
 * @param {Boolean} connect - Whether to connect the inputs.
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.saveBlock = co(function* saveBlock(block, view) {
  if (this.options.spv)
    return;

  this.put(layout.b(block.hash()), block.toRaw());

  if (!view)
    return;

  yield this.connectBlock(block, view);
});

/**
 * Remove a block (not an entry) to the database.
 * Disconnect inputs.
 * @param {Block|Hash} block - {@link Block} or hash.
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.removeBlock = co(function* removeBlock(hash) {
  var block;

  if (this.options.spv)
    return;

  block = yield this.getBlock(hash);

  if (!block)
    throw new Error('Block not found.');

  this.del(layout.b(block.hash()));

  return yield this.disconnectBlock(block);
});

/**
 * Connect block inputs.
 * @param {Block} block
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.connectBlock = co(function* connectBlock(block, view) {
  var undo = new BufferWriter();
  var i, j, tx, input, output, prev;
  var hashes, address, hash, coins, raw;

  if (this.options.spv)
    return;

  // Genesis block's coinbase is unspendable.
  if (this.chain.isGenesis(block)) {
    this.pending.connect(block);
    return;
  }

  this.pending.connect(block);

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    hash = tx.hash();

    if (this.options.indexTX) {
      this.put(layout.t(hash), tx.toExtended());
      if (this.options.indexAddress) {
        hashes = tx.getHashes();
        for (j = 0; j < hashes.length; j++) {
          address = hashes[j];
          this.put(layout.T(address, hash), DUMMY);
        }
      }
    }

    if (!tx.isCoinbase()) {
      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];

        assert(input.coin);

        if (this.options.indexAddress) {
          address = input.getHash();
          if (address) {
            prev = input.prevout;
            this.del(layout.C(address, prev.hash, prev.index));
          }
        }

        // Add coin to set of undo
        // coins for the block.
        input.coin.toRaw(undo);

        this.pending.spend(input.coin);
      }
    }

    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];

      if (output.script.isUnspendable())
        continue;

      if (this.options.indexAddress) {
        address = output.getHash();
        if (address)
          this.put(layout.C(address, hash, j), DUMMY);
      }

      this.pending.add(output);
    }
  }

  // Commit new coin state.
  view = view.toArray();

  for (i = 0; i < view.length; i++) {
    coins = view[i];
    raw = coins.toRaw();
    if (!raw) {
      this.del(layout.c(coins.hash));
      this.coinCache.unpush(coins.hash);
    } else {
      this.put(layout.c(coins.hash), raw);
      this.coinCache.push(coins.hash, raw);
    }
  }

  // Write undo coins (if there are any).
  if (undo.written > 0)
    this.put(layout.u(block.hash()), undo.render());

  yield this.pruneBlock(block);
});

/**
 * Disconnect block inputs.
 * @param {Block|Hash} block - {@link Block} or hash.
 * @returns {Promise} - Returns {@link Block}.
 */

ChainDB.prototype.disconnectBlock = co(function* disconnectBlock(block) {
  var i, j, tx, input, output, prev, view;
  var hashes, address, hash, coins, raw;

  if (this.options.spv)
    return;

  view = yield this.getUndoView(block);

  this.pending.disconnect(block);

  for (i = block.txs.length - 1; i >= 0; i--) {
    tx = block.txs[i];
    hash = tx.hash('hex');

    if (this.options.indexTX) {
      this.del(layout.t(hash));
      if (this.options.indexAddress) {
        hashes = tx.getHashes();
        for (j = 0; j < hashes.length; j++) {
          address = hashes[j];
          this.del(layout.T(address, hash));
        }
      }
    }

    if (!tx.isCoinbase()) {
      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];

        assert(input.coin);

        if (this.options.indexAddress) {
          address = input.getHash();
          if (address) {
            prev = input.prevout;
            this.put(layout.C(address, prev.hash, prev.index), DUMMY);
          }
        }

        this.pending.add(input.coin);
      }
    }

    // Add all of the coins we are about to
    // remove. This is to ensure they appear
    // in the view array below.
    view.addTX(tx);

    for (j = 0; j < tx.outputs.length; j++) {
      output = tx.outputs[j];

      if (output.script.isUnspendable())
        continue;

      if (this.options.indexAddress) {
        address = output.getHash();
        if (address)
          this.del(layout.C(address, hash, j));
      }

      // Spend added coin.
      view.spend(hash, j);

      this.pending.spend(output);
    }
  }

  // Commit new coin state.
  view = view.toArray();

  for (i = 0; i < view.length; i++) {
    coins = view[i];
    raw = coins.toRaw();
    if (!raw) {
      this.del(layout.c(coins.hash));
      this.coinCache.unpush(coins.hash);
    } else {
      this.put(layout.c(coins.hash), raw);
      this.coinCache.push(coins.hash, raw);
    }
  }

  this.del(layout.u(block.hash()));
});

/**
 * Prune a block from the chain and
 * add current block to the prune queue.
 * @private
 * @param {Block}
 * @returns {Promise}
 */

ChainDB.prototype.pruneBlock = co(function* pruneBlock(block) {
  var height, hash;

  if (this.options.spv)
    return;

  if (!this.options.prune)
    return;

  height = block.height - this.network.block.keepBlocks;

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

ChainDB.prototype.saveOptions = function saveOptions() {
  return this.db.put(layout.O, this.options.toRaw());
};

/**
 * Chain Options
 * @constructor
 */

function ChainOptions(options) {
  if (!(this instanceof ChainOptions))
    return new ChainOptions(options);

  this.network = Network.primary;
  this.spv = false;
  this.witness = false;
  this.prune = false;
  this.indexTX = false;
  this.indexAddress = false;

  this.forceWitness = false;

  if (options)
    this.fromOptions(options);
}

ChainOptions.prototype.fromOptions = function fromOptions(options) {
  this.network = Network.get(options.network);

  if (options.spv != null) {
    assert(typeof options.spv === 'boolean');
    this.spv = options.spv;
  }

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
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

  if (options.forceWitness != null) {
    assert(typeof options.forceWitness === 'boolean');
    this.forceWitness = options.forceWitness;
  }

  return this;
};

ChainOptions.fromOptions = function fromOptions(data) {
  return new ChainOptions().fromOptions(data);
};

ChainOptions.prototype.verify = function verify(options) {
  if (this.network !== options.network)
    throw new Error('Network mismatch for chain.');

  if (this.spv && !options.spv)
    throw new Error('Cannot retroactively enable SPV.');

  if (!this.spv && options.spv)
    throw new Error('Cannot retroactively disable SPV.');

  if (!this.forceWitness) {
    if (this.witness && !options.witness)
      throw new Error('Cannot retroactively enable witness.');

    if (!this.witness && options.witness)
      throw new Error('Cannot retroactively disable witness.');
  }

  if (this.prune && !options.prune)
    throw new Error('Cannot retroactively prune.');

  if (!this.prune && options.prune)
    throw new Error('Cannot retroactively unprune.');

  if (this.indexTX && !options.indexTX)
    throw new Error('Cannot retroactively enable TX indexing.');

  if (!this.indexTX && options.indexTX)
    throw new Error('Cannot retroactively disable TX indexing.');

  if (this.indexAddress && !options.indexAddress)
    throw new Error('Cannot retroactively enable address indexing.');

  if (!this.indexAddress && options.indexAddress)
    throw new Error('Cannot retroactively disable address indexing.');
};

ChainOptions.prototype.toRaw = function toRaw() {
  var p = new BufferWriter();
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

  p.writeU32(this.network.magic);
  p.writeU32(flags);
  p.writeU32(0);

  return p.render();
};

ChainOptions.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  var flags;

  this.network = Network.fromMagic(p.readU32());

  flags = p.readU32();

  this.spv = (flags & 1) !== 0;
  this.witness = (flags & 2) !== 0;
  this.prune = (flags & 4) !== 0;
  this.indexTX = (flags & 8) !== 0;
  this.indexAddress = (flags & 16) !== 0;

  return this;
};

ChainOptions.fromRaw = function fromRaw(data) {
  return new ChainOptions().fromRaw(data);
};

/**
 * Chain State
 * @constructor
 */

function ChainState() {
  this.tip = constants.ZERO_HASH;
  this.tx = 0;
  this.coin = 0;
  this.value = 0;
  this.committed = false;
}

ChainState.prototype.__defineGetter__('hash', function() {
  return this.tip.toString('hex');
});

ChainState.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash);
});

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
  var p = new BufferWriter();
  p.writeHash(this.tip);
  p.writeU64(this.tx);
  p.writeU64(this.coin);
  p.writeU64(this.value);
  return p.render();
};

ChainState.fromRaw = function fromRaw(data) {
  var state = new ChainState();
  var p = new BufferReader(data);
  state.tip = p.readHash();
  state.tx = p.readU53();
  state.coin = p.readU53();
  state.value = p.readU53();
  return state;
};

/*
 * Helpers
 */

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  data.write(str, off, 'hex');
}

function pair(prefix, hash) {
  var key = new Buffer(33);
  key[0] = prefix;
  write(key, hash, 1);
  return key;
}

function ipair(prefix, num) {
  var key = new Buffer(5);
  key[0] = prefix;
  key.writeUInt32BE(num, 1, true);
  return key;
}

function getSize(value) {
  return 80 + value.length;
}

function checkHash(hash) {
  assert(typeof hash === 'string' || typeof hash === 'number',
    'Must pass in height or hash.');
}

function BlockPair(hash, height) {
  this.hash = hash;
  this.height = height;
}

/*
 * Expose
 */

module.exports = ChainDB;
