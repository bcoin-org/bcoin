/*!
 * mempool.js - mempool for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var AsyncObject = require('../utils/asyncobject');
var common = require('../blockchain/common');
var policy = require('../protocol/policy');
var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var errors = require('../protocol/errors');
var Bloom = require('../utils/bloom');
var Address = require('../primitives/address');
var Coin = require('../primitives/coin');
var Script = require('../script/script');
var Outpoint = require('../primitives/outpoint');
var TX = require('../primitives/tx');
var Coin = require('../primitives/coin');
var TXMeta = require('../primitives/txmeta');
var MempoolEntry = require('./mempoolentry');
var Network = require('../protocol/network');
var encoding = require('../utils/encoding');
var layout = require('./layout');
var LDB = require('../db/ldb');
var Fees = require('./fees');
var Map = require('../utils/map');
var CoinView = require('../coins/coinview');
var Coins = require('../coins/coins');
var Heap = require('../utils/heap');
var VerifyError = errors.VerifyError;
var VerifyResult = errors.VerifyResult;

/**
 * Represents a mempool.
 * @alias module:mempool.Mempool
 * @constructor
 * @param {Object} options
 * @param {String?} options.name - Database name.
 * @param {String?} options.location - Database file location.
 * @param {String?} options.db - Database backend (`"memory"` by default).
 * @param {Boolean?} options.limitFree
 * @param {Number?} options.limitFreeRelay
 * @param {Number?} options.maxSize - Max pool size (default ~300mb).
 * @param {Boolean?} options.relayPriority
 * @param {Boolean?} options.requireStandard
 * @param {Boolean?} options.rejectAbsurdFees
 * @param {Boolean?} options.relay
 * @property {Boolean} loaded
 * @property {Object} db
 * @property {Number} size
 * @property {Number} totalOrphans
 * @property {Lock} locker
 * @property {Number} freeCount
 * @property {Number} lastTime
 * @property {Number} maxSize
 * @property {Rate} minRelayFee
 * @emits Mempool#open
 * @emits Mempool#error
 * @emits Mempool#tx
 * @emits Mempool#add tx
 * @emits Mempool#remove tx
 */

function Mempool(options) {
  if (!(this instanceof Mempool))
    return new Mempool(options);

  AsyncObject.call(this);

  this.options = new MempoolOptions(options);

  this.network = this.options.network;
  this.logger = this.options.logger.context('mempool');
  this.chain = this.options.chain;
  this.fees = this.options.fees;

  this.locker = this.chain.locker;

  this.cache = new MempoolCache(this.options);

  this.size = 0;
  this.totalOrphans = 0;
  this.totalTX = 0;
  this.freeCount = 0;
  this.lastTime = 0;
  this.lastFlush = 0;
  this.tip = this.network.genesis.hash;

  this.waiting = {};
  this.orphans = {};
  this.map = {};
  this.spents = {};
  this.rejects = new Bloom.Rolling(120000, 0.000001);

  this.coinIndex = new CoinIndex();
  this.txIndex = new TXIndex();
}

util.inherits(Mempool, AsyncObject);

/**
 * Open the chain, wait for the database to load.
 * @method
 * @alias Mempool#open
 * @returns {Promise}
 */

Mempool.prototype._open = co(function* open() {
  var size = (this.options.maxSize / 1024).toFixed(2);
  var i, entries, entry, view, fees;

  yield this.chain.open();
  yield this.cache.open();

  if (this.options.persistent) {
    entries = yield this.cache.getEntries();

    for (i = 0; i < entries.length; i++) {
      entry = entries[i];
      this.trackEntry(entry);
    }

    for (i = 0; i < entries.length; i++) {
      entry = entries[i];

      this.updateAncestors(entry, addFee);

      if (this.options.indexAddress) {
        view = yield this.getCoinView(entry.tx);
        this.indexEntry(entry, view);
      }
    }

    this.logger.info(
      'Loaded mempool from disk (%d entries).',
      entries.length);

    if (this.fees) {
      fees = yield this.cache.getFees();

      if (fees) {
        this.fees.inject(fees);
        this.logger.info(
          'Loaded mempool fee data (rate=%d).',
          this.fees.estimateFee());
      }
    }
  }

  this.tip = this.chain.tip.hash;

  this.logger.info('Mempool loaded (maxsize=%dkb).', size);
});

/**
 * Close the chain, wait for the database to close.
 * @alias Mempool#close
 * @returns {Promise}
 */

Mempool.prototype._close = co(function* close() {
  yield this.cache.close();
});

/**
 * Notify the mempool that a new block has come
 * in (removes all transactions contained in the
 * block from the mempool).
 * @method
 * @param {ChainEntry} block
 * @param {TX[]} txs
 * @returns {Promise}
 */

Mempool.prototype.addBlock = co(function* addBlock(block, txs) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._addBlock(block, txs);
  } finally {
    unlock();
  }
});

/**
 * Notify the mempool that a new block
 * has come without a lock.
 * @private
 * @param {ChainEntry} block
 * @param {TX[]} txs
 * @returns {Promise}
 */

Mempool.prototype._addBlock = co(function* addBlock(block, txs) {
  var i, entries, entry, tx, hash;

  if (this.totalTX === 0) {
    this.tip = block.hash;
    return;
  }

  entries = [];

  for (i = txs.length - 1; i >= 1; i--) {
    tx = txs[i];
    hash = tx.hash('hex');
    entry = this.getEntry(hash);

    if (!entry) {
      this.removeOrphan(hash);
      this.resolveOrphans(tx);
      this.removeDoubleSpends(tx);
      continue;
    }

    this.removeEntry(entry);

    this.emit('confirmed', tx, block);

    entries.push(entry);
  }

  // We need to reset the rejects filter periodically.
  // There may be a locktime in a TX that is now valid.
  this.rejects.reset();

  if (this.fees) {
    this.fees.processBlock(block.height, entries, this.chain.synced);
    this.cache.writeFees(this.fees);
  }

  this.cache.sync(block.hash);

  yield this.cache.flush();

  this.tip = block.hash;

  if (entries.length === 0)
    return;

  this.logger.debug(
    'Removed %d txs from mempool for block %d.',
    entries.length, block.height);
});

/**
 * Notify the mempool that a block has been disconnected
 * from the main chain (reinserts transactions into the mempool).
 * @method
 * @param {ChainEntry} block
 * @param {TX[]} txs
 * @returns {Promise}
 */

Mempool.prototype.removeBlock = co(function* removeBlock(block, txs) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._removeBlock(block, txs);
  } finally {
    unlock();
  }
});

/**
 * Notify the mempool that a block
 * has been disconnected without a lock.
 * @method
 * @private
 * @param {ChainEntry} block
 * @param {TX[]} txs
 * @returns {Promise}
 */

Mempool.prototype._removeBlock = co(function* removeBlock(block, txs) {
  var total = 0;
  var i, tx, hash;

  if (this.totalTX === 0) {
    this.tip = block.prevBlock;
    return;
  }

  for (i = 1; i < txs.length; i++) {
    tx = txs[i];
    hash = tx.hash('hex');

    if (this.hasEntry(hash))
      continue;

    try {
      yield this.insertTX(tx);
      total++;
    } catch (e) {
      this.emit('error', e);
      continue;
    }

    this.emit('unconfirmed', tx, block);
  }

  this.rejects.reset();

  this.cache.sync(block.prevBlock);

  yield this.cache.flush();

  this.tip = block.prevBlock;

  if (total === 0)
    return;

  this.logger.debug(
    'Added %d txs back into the mempool for block %d.',
    total, block.height);
});

/**
 * Reset the mempool.
 * @method
 * @returns {Promise}
 */

Mempool.prototype.reset = co(function* reset() {
  var unlock = yield this.locker.lock();
  try {
    return yield this._reset();
  } finally {
    unlock();
  }
});

/**
 * Reset the mempool without a lock.
 * @private
 */

Mempool.prototype._reset = co(function* reset() {
  this.logger.info('Mempool reset (%d txs removed).', this.totalTX);

  this.size = 0;
  this.totalOrphans = 0;
  this.totalTX = 0;

  this.waiting = {};
  this.orphans = {};
  this.map = {};
  this.spents = {};
  this.coinIndex.reset();
  this.txIndex.reset();

  this.freeCount = 0;
  this.lastTime = 0;

  if (this.fees)
    this.fees.reset();

  this.rejects.reset();

  if (this.options.persistent) {
    yield this.cache.wipe();
    this.cache.clear();
  }

  this.tip = this.chain.tip.hash;
});

/**
 * Ensure the size of the mempool stays below `maxSize`.
 * Evicts entries by timestamp and cumulative fee rate.
 * @param {MempoolEntry} added
 * @returns {Promise}
 */

Mempool.prototype.limitSize = function limitSize(added) {
  var maxSize = this.options.maxSize;
  var threshold = maxSize - (maxSize / 10);
  var expiryTime = this.options.expiryTime;
  var now = util.now();
  var i, queue, hashes, hash, entry, start;

  if (this.size <= maxSize)
    return false;

  queue = new Heap(cmpRate);
  hashes = this.getSnapshot();

  start = util.hrtime();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    entry = this.getEntry(hash);

    if (!entry)
      continue;

    if (this.hasDepends(entry.tx))
      continue;

    if (now < entry.ts + expiryTime) {
      queue.insert(entry);
      continue;
    }

    this.logger.debug(
      'Removing package %s from mempool (too old).',
      entry.txid());

    this.evictEntry(entry);
  }

  if (this.size <= threshold)
    return !this.hasEntry(added);

  this.logger.debug(
    '(bench) Heap mempool traversal: %d.',
    util.hrtime(start));

  start = util.hrtime();

  this.logger.debug(
    '(bench) Heap mempool queue size: %d.',
    queue.size());

  while (queue.size() > 0) {
    entry = queue.shift();
    hash = entry.hash('hex');

    assert(this.hasEntry(hash));

    this.logger.debug(
      'Removing package %s from mempool (low fee).',
      entry.txid());

    this.evictEntry(entry);

    if (this.size <= threshold)
      break;
  }

  this.logger.debug(
    '(bench) Heap mempool map removal: %d.',
    util.hrtime(start));

  return !this.hasEntry(added);
};

/**
 * Purge orphan transactions from the mempool.
 */

Mempool.prototype.limitOrphans = function limitOrphans() {
  var orphans = Object.keys(this.orphans);
  var i, hash;

  while (this.totalOrphans > this.options.maxOrphans) {
    i = crypto.randomRange(0, orphans.length);
    hash = orphans[i];
    orphans.splice(i, 1);

    this.logger.spam('Removing orphan %s from mempool.', util.revHex(hash));

    this.removeOrphan(hash);
  }
};

/**
 * Retrieve a transaction from the mempool.
 * @param {Hash} hash
 * @returns {TX}
 */

Mempool.prototype.getTX = function getTX(hash) {
  var entry = this.map[hash];
  if (!entry)
    return;
  return entry.tx;
};

/**
 * Retrieve a transaction from the mempool.
 * @param {Hash} hash
 * @returns {MempoolEntry}
 */

Mempool.prototype.getEntry = function getEntry(hash) {
  return this.map[hash];
};

/**
 * Retrieve a coin from the mempool (unspents only).
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

Mempool.prototype.getCoin = function getCoin(hash, index) {
  var entry = this.map[hash];

  if (!entry)
    return;

  if (this.isSpent(hash, index))
    return;

  if (index >= entry.tx.outputs.length)
    return;

  return Coin.fromTX(entry.tx, index, -1);
};

/**
 * Check to see if a coin has been spent. This differs from
 * {@link ChainDB#isSpent} in that it actually maintains a
 * map of spent coins, whereas ChainDB may return `true`
 * for transaction outputs that never existed.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Boolean}
 */

Mempool.prototype.isSpent = function isSpent(hash, index) {
  var key = Outpoint.toKey(hash, index);
  return this.spents[key] != null;
};

/**
 * Get an output's spender entry.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {MempoolEntry}
 */

Mempool.prototype.getSpent = function getSpent(hash, index) {
  var key = Outpoint.toKey(hash, index);
  return this.spents[key];
};

/**
 * Get an output's spender transaction.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {MempoolEntry}
 */

Mempool.prototype.getSpentTX = function getSpentTX(hash, index) {
  var key = Outpoint.toKey(hash, index);
  var entry = this.spents[key];

  if (!entry)
    return;

  return entry.tx;
};

/**
 * Find all coins pertaining to a certain address.
 * @param {Address[]} addresses
 * @returns {Coin[]}
 */

Mempool.prototype.getCoinsByAddress = function getCoinsByAddress(addresses) {
  var coins = [];
  var i, j, coin, hash;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  for (i = 0; i < addresses.length; i++) {
    hash = Address.getHash(addresses[i], 'hex');

    if (!hash)
      continue;

    coin = this.coinIndex.get(hash);

    for (j = 0; j < coin.length; j++)
      coins.push(coin[j]);
  }

  return coins;
};

/**
 * Find all transactions pertaining to a certain address.
 * @param {Address[]} addresses
 * @returns {TX[]}
 */

Mempool.prototype.getTXByAddress = function getTXByAddress(addresses) {
  var txs = [];
  var i, j, tx, hash;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  for (i = 0; i < addresses.length; i++) {
    hash = Address.getHash(addresses[i], 'hex');

    if (!hash)
      continue;

    tx = this.txIndex.get(hash);

    for (j = 0; j < tx.length; j++)
      txs.push(tx[j]);
  }

  return txs;
};

/**
 * Find all transactions pertaining to a certain address.
 * @param {Address[]} addresses
 * @returns {TXMeta[]}
 */

Mempool.prototype.getMetaByAddress = function getMetaByAddress(addresses) {
  var txs = [];
  var i, j, tx, hash;

  if (!Array.isArray(addresses))
    addresses = [addresses];

  for (i = 0; i < addresses.length; i++) {
    hash = Address.getHash(addresses[i], 'hex');

    if (!hash)
      continue;

    tx = this.txIndex.getMeta(hash);

    for (j = 0; j < tx.length; j++)
      txs.push(tx[j]);
  }

  return txs;
};

/**
 * Retrieve a transaction from the mempool.
 * @param {Hash} hash
 * @returns {TXMeta}
 */

Mempool.prototype.getMeta = function getMeta(hash) {
  var entry = this.getEntry(hash);
  var meta;

  if (!entry)
    return;

  meta = TXMeta.fromTX(entry.tx);
  meta.ps = entry.ts;

  return meta;
};

/**
 * Test the mempool to see if it contains a transaction.
 * @param {Hash} hash
 * @returns {Boolean}
 */

Mempool.prototype.hasEntry = function hasEntry(hash) {
  return this.map[hash] != null;
};

/**
 * Test the mempool to see if it
 * contains a transaction or an orphan.
 * @param {Hash} hash
 * @returns {Boolean}
 */

Mempool.prototype.has = function has(hash) {
  if (this.locker.has(hash))
    return true;

  if (this.hasOrphan(hash))
    return true;

  return this.hasEntry(hash);
};

/**
 * Test the mempool to see if it
 * contains a transaction or an orphan.
 * @private
 * @param {Hash} hash
 * @returns {Boolean}
 */

Mempool.prototype.exists = function exists(hash) {
  if (this.locker.hasPending(hash))
    return true;

  if (this.hasOrphan(hash))
    return true;

  return this.hasEntry(hash);
};

/**
 * Test the mempool to see if it
 * contains a recent reject.
 * @param {Hash} hash
 * @returns {Boolean}
 */

Mempool.prototype.hasReject = function hasReject(hash) {
  return this.rejects.test(hash, 'hex');
};

/**
 * Add a transaction to the mempool. Note that this
 * will lock the mempool until the transaction is
 * fully processed.
 * @method
 * @param {TX} tx
 * @returns {Promise}
 */

Mempool.prototype.addTX = co(function* addTX(tx) {
  var hash = tx.hash('hex');
  var unlock = yield this.locker.lock(hash);
  try {
    return yield this._addTX(tx);
  } finally {
    unlock();
  }
});

/**
 * Add a transaction to the mempool without a lock.
 * @method
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

Mempool.prototype._addTX = co(function* _addTX(tx) {
  var missing;

  try {
    missing = yield this.insertTX(tx);
  } catch (err) {
    if (err.type === 'VerifyError') {
      if (!tx.hasWitness() && !err.malleated)
        this.rejects.add(tx.hash());
    }
    throw err;
  }

  if (util.now() - this.lastFlush > 10) {
    yield this.cache.flush();
    this.lastFlush = util.now();
  }

  return missing;
});

/**
 * Add a transaction to the mempool without a lock.
 * @method
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

Mempool.prototype.insertTX = co(function* insertTX(tx) {
  var lockFlags = common.lockFlags.STANDARD_LOCKTIME_FLAGS;
  var hash = tx.hash('hex');
  var ret = new VerifyResult();
  var entry, view, missing;

  assert(!tx.mutable, 'Cannot add mutable TX to mempool.');

  // Basic sanity checks.
  // This is important because it ensures
  // other functions will be overflow safe.
  if (!tx.isSane(ret)) {
    throw new VerifyError(tx,
      'invalid',
      ret.reason,
      ret.score);
  }

  // Coinbases are an insta-ban.
  // Why? Who knows.
  if (tx.isCoinbase()) {
    throw new VerifyError(tx,
      'invalid',
      'coinbase',
      100);
  }

  // Do not allow CSV until it's activated.
  if (this.options.requireStandard) {
    if (!this.chain.state.hasCSV() && tx.version >= 2) {
      throw new VerifyError(tx,
        'nonstandard',
        'premature-version2-tx',
        0);
    }
  }

  // Do not allow segwit until it's activated.
  if (!this.chain.state.hasWitness() && !this.options.prematureWitness) {
    if (tx.hasWitness()) {
      throw new VerifyError(tx,
        'nonstandard',
        'no-witness-yet',
        0,
        true);
    }
  }

  // Non-contextual standardness checks.
  if (this.options.requireStandard) {
    if (!tx.isStandard(ret)) {
      throw new VerifyError(tx,
        'nonstandard',
        ret.reason,
        ret.score);
    }
    if (!this.options.replaceByFee) {
      if (tx.isRBF()) {
        throw new VerifyError(tx,
          'nonstandard',
          'replace-by-fee',
          0);
      }
    }
  }

  // Verify transaction finality (see isFinal()).
  if (!(yield this.verifyFinal(tx, lockFlags))) {
    throw new VerifyError(tx,
      'nonstandard',
      'non-final',
      0);
  }

  // We can maybe ignore this.
  if (this.exists(hash)) {
    throw new VerifyError(tx,
      'alreadyknown',
      'txn-already-in-mempool',
      0);
  }

  // We can test whether this is an
  // non-fully-spent transaction on
  // the chain.
  if (yield this.chain.db.hasCoins(hash)) {
    throw new VerifyError(tx,
      'alreadyknown',
      'txn-already-known',
      0);
  }

  // Quick and dirty test to verify we're
  // not double-spending an output in the
  // mempool.
  if (this.isDoubleSpend(tx)) {
    this.emit('conflict', tx);
    throw new VerifyError(tx,
      'duplicate',
      'bad-txns-inputs-spent',
      0);
  }

  // Get coin viewpoint as it
  // pertains to the mempool.
  view = yield this.getCoinView(tx);

  // Find missing outpoints.
  missing = this.findMissing(tx, view);

  // Maybe store as an orphan.
  if (missing)
    return this.storeOrphan(tx, missing);

  // Create a new mempool entry
  // at current chain height.
  entry = MempoolEntry.fromTX(tx, view, this.chain.height);

  // Contextual verification.
  yield this.verify(entry, view);

  // Add and index the entry.
  yield this.addEntry(entry, view);

  // Trim size if we're too big.
  if (this.limitSize(hash)) {
    throw new VerifyError(tx,
      'insufficientfee',
      'mempool full',
      0);
  }
});

/**
 * Verify a transaction with mempool standards.
 * @method
 * @param {TX} tx
 * @param {CoinView} view
 * @returns {Promise}
 */

Mempool.prototype.verify = co(function* verify(entry, view) {
  var height = this.chain.height + 1;
  var lockFlags = common.lockFlags.STANDARD_LOCKTIME_FLAGS;
  var flags = Script.flags.STANDARD_VERIFY_FLAGS;
  var ret = new VerifyResult();
  var tx = entry.tx;
  var now, minFee, result;

  // Verify sequence locks.
  if (!(yield this.verifyLocks(tx, view, lockFlags))) {
    throw new VerifyError(tx,
      'nonstandard',
      'non-BIP68-final',
      0);
  }

  // Check input an witness standardness.
  if (this.options.requireStandard) {
    if (!tx.hasStandardInputs(view)) {
      throw new VerifyError(tx,
        'nonstandard',
        'bad-txns-nonstandard-inputs',
        0);
    }
    if (this.chain.state.hasWitness()) {
      if (!tx.hasStandardWitness(view)) {
        throw new VerifyError(tx,
          'nonstandard',
          'bad-witness-nonstandard',
          0,
          true);
      }
    }
  }

  // Annoying process known as sigops counting.
  if (entry.sigops > policy.MAX_TX_SIGOPS_COST) {
    throw new VerifyError(tx,
      'nonstandard',
      'bad-txns-too-many-sigops',
      0);
  }

  // Make sure this guy gave a decent fee.
  minFee = policy.getMinFee(entry.size, this.options.minRelay);

  if (this.options.relayPriority && entry.fee < minFee) {
    if (!entry.isFree(height)) {
      throw new VerifyError(tx,
        'insufficientfee',
        'insufficient priority',
        0);
    }
  }

  // Continuously rate-limit free (really, very-low-fee)
  // transactions. This mitigates 'penny-flooding'.
  if (this.options.limitFree && entry.fee < minFee) {
    now = util.now();

    // Use an exponentially decaying ~10-minute window.
    this.freeCount *= Math.pow(1 - 1 / 600, now - this.lastTime);
    this.lastTime = now;

    // The limitFreeRelay unit is thousand-bytes-per-minute
    // At default rate it would take over a month to fill 1GB.
    if (this.freeCount > this.options.limitFreeRelay * 10 * 1000) {
      throw new VerifyError(tx,
        'insufficientfee',
        'rate limited free transaction',
        0);
    }

    this.freeCount += entry.size;
  }

  // Important safety feature.
  if (this.options.rejectAbsurdFees && entry.fee > minFee * 10000)
    throw new VerifyError(tx, 'highfee', 'absurdly-high-fee', 0);

  // Why do we have this here? Nested transactions are cool.
  if (this.countAncestors(entry) + 1 > this.options.maxAncestors) {
    throw new VerifyError(tx,
      'nonstandard',
      'too-long-mempool-chain',
      0);
  }

  // Contextual sanity checks.
  if (!tx.checkInputs(view, height, ret))
    throw new VerifyError(tx, 'invalid', ret.reason, ret.score);

  // Script verification.
  try {
    yield this.verifyInputs(tx, view, flags);
  } catch (err) {
    if (tx.hasWitness())
      throw err;

    // Try without segwit and cleanstack.
    flags &= ~Script.flags.VERIFY_WITNESS;
    flags &= ~Script.flags.VERIFY_CLEANSTACK;
    result = yield this.verifyResult(tx, view, flags);

    // If it failed, the first verification
    // was the only result we needed.
    if (!result)
      throw err;

    // If it succeeded, segwit may be causing the
    // failure. Try with segwit but without cleanstack.
    flags |= Script.flags.VERIFY_CLEANSTACK;
    result = yield this.verifyResult(tx, view, flags);

    // Cleanstack was causing the failure.
    if (result)
      throw err;

    // Do not insert into reject cache.
    err.malleated = true;
    throw err;
  }

  // Paranoid checks.
  if (this.options.paranoidChecks) {
    flags = Script.flags.MANDATORY_VERIFY_FLAGS;
    result = yield this.verifyResult(tx, view, flags);
    assert(result, 'BUG: Verify failed for mandatory but not standard.');
  }
});

/**
 * Verify inputs, return a boolean
 * instead of an error based on success.
 * @method
 * @param {TX} tx
 * @param {CoinView} view
 * @param {VerifyFlags} flags
 * @returns {Promise}
 */

Mempool.prototype.verifyResult = co(function* verifyResult(tx, view, flags) {
  try {
    yield this.verifyInputs(tx, view, flags);
  } catch (err) {
    if (err.type === 'VerifyError')
      return false;
    throw err;
  }
  return true;
});

/**
 * Verify inputs for standard
 * _and_ mandatory flags on failure.
 * @method
 * @param {TX} tx
 * @param {CoinView} view
 * @param {VerifyFlags} flags
 * @returns {Promise}
 */

Mempool.prototype.verifyInputs = co(function* verifyInputs(tx, view, flags) {
  if (yield tx.verifyAsync(view, flags))
    return;

  if (flags & Script.flags.ONLY_STANDARD_VERIFY_FLAGS) {
    flags &= ~Script.flags.ONLY_STANDARD_VERIFY_FLAGS;

    if (yield tx.verifyAsync(view, flags)) {
      throw new VerifyError(tx,
        'nonstandard',
        'non-mandatory-script-verify-flag',
        0);
    }
  }

  throw new VerifyError(tx,
    'nonstandard',
    'mandatory-script-verify-flag',
    100);
});

/**
 * Add a transaction to the mempool without performing any
 * validation. Note that this method does not lock the mempool
 * and may lend itself to race conditions if used unwisely.
 * This function will also resolve orphans if possible (the
 * resolved orphans _will_ be validated).
 * @method
 * @param {MempoolEntry} entry
 * @param {CoinView} view
 * @returns {Promise}
 */

Mempool.prototype.addEntry = co(function* addEntry(entry, view) {
  var tx = entry.tx;

  this.trackEntry(entry, view);

  this.updateAncestors(entry, addFee);

  this.emit('tx', tx, view);
  this.emit('add entry', entry);

  if (this.fees)
    this.fees.processTX(entry, this.chain.synced);

  this.logger.debug(
    'Added %s to mempool (txs=%d).',
    tx.txid(), this.totalTX);

  this.cache.save(entry);

  yield this.handleOrphans(tx);
});

/**
 * Remove a transaction from the mempool.
 * Generally only called when a new block
 * is added to the main chain.
 * @param {MempoolEntry} entry
 */

Mempool.prototype.removeEntry = function removeEntry(entry) {
  var tx = entry.tx;
  var hash = tx.hash('hex');

  this.untrackEntry(entry);

  if (this.fees)
    this.fees.removeTX(hash);

  this.cache.remove(tx.hash());

  this.emit('remove entry', entry);
};

/**
 * Remove a transaction from the mempool.
 * Recursively remove its spenders.
 * @param {MempoolEntry} entry
 */

Mempool.prototype.evictEntry = function evictEntry(entry) {
  this.removeSpenders(entry);
  this.updateAncestors(entry, removeFee);
  this.removeEntry(entry);
};

/**
 * Recursively remove spenders of a transaction.
 * @private
 * @param {MempoolEntry} entry
 */

Mempool.prototype.removeSpenders = function removeSpenders(entry) {
  var tx = entry.tx;
  var hash = tx.hash('hex');
  var i, spender;

  for (i = 0; i < tx.outputs.length; i++) {
    spender = this.getSpent(hash, i);

    if (!spender)
      continue;

    this.removeSpenders(spender);
    this.removeEntry(spender);
  }
};

/**
 * Count the highest number of
 * ancestors a transaction may have.
 * @param {MempoolEntry} entry
 * @returns {Number}
 */

Mempool.prototype.countAncestors = function countAncestors(entry) {
  return this._countAncestors(entry, 0, {}, entry, nop);
};

/**
 * Count the highest number of
 * ancestors a transaction may have.
 * Update descendant fees and size.
 * @param {MempoolEntry} entry
 * @param {Function} map
 * @returns {Number}
 */

Mempool.prototype.updateAncestors = function updateAncestors(entry, map) {
  return this._countAncestors(entry, 0, {}, entry, map);
};

/**
 * Traverse ancestors and count.
 * @private
 * @param {MempoolEntry} entry
 * @param {Number} count
 * @param {Object} set
 * @param {MempoolEntry} child
 * @param {Function} map
 * @returns {Number}
 */

Mempool.prototype._countAncestors = function countAncestors(entry, count, set, child, map) {
  var tx = entry.tx;
  var i, input, hash, parent;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    hash = input.prevout.hash;
    parent = this.getEntry(hash);

    if (!parent)
      continue;

    if (set[hash])
      continue;

    set[hash] = true;
    count += 1;

    map(parent, child);

    if (count > this.options.maxAncestors)
      break;

    count = this._countAncestors(parent, count, set, child, map);

    if (count > this.options.maxAncestors)
      break;
  }

  return count;
};

/**
 * Count the highest number of
 * descendants a transaction may have.
 * @param {MempoolEntry} entry
 * @returns {Number}
 */

Mempool.prototype.countDescendants = function countDescendants(entry) {
  return this._countDescendants(entry, 0, {});
};

/**
 * Count the highest number of
 * descendants a transaction may have.
 * @private
 * @param {MempoolEntry} entry
 * @param {Number} count
 * @param {Object} set
 * @returns {Number}
 */

Mempool.prototype._countDescendants = function countDescendants(entry, count, set) {
  var tx = entry.tx;
  var hash = tx.hash('hex');
  var i, child, next;

  for (i = 0; i < tx.outputs.length; i++) {
    child = this.getSpent(hash, i);

    if (!child)
      continue;

    next = child.hash('hex');

    if (set[next])
      continue;

    set[next] = true;
    count += 1;

    count = this._countDescendants(child, count, set);
  }

  return count;
};

/**
 * Get all transaction ancestors.
 * @param {MempoolEntry} entry
 * @returns {MempoolEntry[]}
 */

Mempool.prototype.getAncestors = function getAncestors(entry) {
  return this._getAncestors(entry, [], {});
};

/**
 * Get all transaction ancestors.
 * @private
 * @param {MempoolEntry} entry
 * @param {MempoolEntry[]} entries
 * @param {Object} set
 * @returns {MempoolEntry[]}
 */

Mempool.prototype._getAncestors = function getAncestors(entry, entries, set) {
  var tx = entry.tx;
  var i, hash, input, parent;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    hash = input.prevout.hash;
    parent = this.getEntry(hash);

    if (!parent)
      continue;

    if (set[hash])
      continue;

    set[hash] = true;
    entries.push(parent);

    this._getAncestors(parent, entries, set);
  }

  return entries;
};

/**
 * Get all a transaction descendants.
 * @param {MempoolEntry} entry
 * @returns {MempoolEntry[]}
 */

Mempool.prototype.getDescendants = function getDescendants(entry) {
  return this._getDescendants(entry, [], {});
};

/**
 * Get all a transaction descendants.
 * @param {MempoolEntry} entry
 * @param {MempoolEntry[]} entries
 * @param {Object} set
 * @returns {MempoolEntry[]}
 */

Mempool.prototype._getDescendants = function getDescendants(entry, entries, set) {
  var tx = entry.tx;
  var hash = tx.hash('hex');
  var i, child, next;

  for (i = 0; i < tx.outputs.length; i++) {
    child = this.getSpent(hash, i);

    if (!child)
      continue;

    next = child.hash('hex');

    if (set[next])
      continue;

    set[next] = true;
    entries.push(child);

    this._getDescendants(child, entries, set);
  }

  return entries;
};

/**
 * Find a unconfirmed transactions that
 * this transaction depends on.
 * @param {TX} tx
 * @returns {Hash[]}
 */

Mempool.prototype.getDepends = function getDepends(tx) {
  var prevout = tx.getPrevout();
  var depends = [];
  var i, hash;

  for (i = 0; i < prevout.length; i++) {
    hash = prevout[i];
    if (this.hasEntry(hash))
      depends.push(hash);
  }

  return depends;
};

/**
 * Test whether a transaction has dependencies.
 * @param {TX} tx
 * @returns {Boolean}
 */

Mempool.prototype.hasDepends = function hasDepends(tx) {
  var i, input, hash;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    hash = input.prevout.hash;
    if (this.hasEntry(hash))
      return true;
  }

  return false;
};

/**
 * Return the full balance of all unspents in the mempool
 * (not very useful in practice, only used for testing).
 * @returns {Amount}
 */

Mempool.prototype.getBalance = function getBalance() {
  var hashes = this.getSnapshot();
  var total = 0;
  var i, j, tx, hash, coin;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    tx = this.getTX(hash);

    if (!tx)
      continue;

    hash = tx.hash('hex');

    for (j = 0; j < tx.outputs.length; j++) {
      coin = this.getCoin(hash, j);
      if (coin)
        total += coin.value;
    }
  }

  return total;
};

/**
 * Retrieve _all_ transactions from the mempool.
 * @returns {TX[]}
 */

Mempool.prototype.getHistory = function getHistory() {
  var hashes = this.getSnapshot();
  var txs = [];
  var i, hash, tx;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    tx = this.getTX(hash);

    if (!tx)
      continue;

    txs.push(tx);
  }

  return txs;
};

/**
 * Retrieve an orphan transaction.
 * @param {Hash} hash
 * @returns {TX}
 */

Mempool.prototype.getOrphan = function getOrphan(hash) {
  return this.orphans[hash];
};

/**
 * @param {Hash} hash
 * @returns {Boolean}
 */

Mempool.prototype.hasOrphan = function hasOrphan(hash) {
  return this.orphans[hash] != null;
};

/**
 * Store an orphaned transaction.
 * @param {TX} tx
 */

Mempool.prototype.storeOrphan = function storeOrphan(tx, missing) {
  var hash = tx.hash('hex');
  var i, prev;

  if (tx.getWeight() > policy.MAX_TX_WEIGHT) {
    this.logger.debug('Ignoring large orphan: %s', tx.txid());
    if (!tx.hasWitness())
      this.rejects.add(tx.hash());
    return [];
  }

  for (i = 0; i < missing.length; i++) {
    prev = missing[i];
    if (this.hasReject(prev)) {
      this.logger.debug('Not storing orphan %s (rejected parents).', tx.txid());
      this.rejects.add(tx.hash());
      return [];
    }
  }

  for (i = 0; i < missing.length; i++) {
    prev = missing[i];

    if (!this.waiting[prev])
      this.waiting[prev] = [];

    this.waiting[prev].push(hash);
  }

  this.orphans[hash] = new Orphan(tx, missing.length);
  this.totalOrphans++;

  this.logger.debug('Added orphan %s to mempool.', tx.txid());

  this.emit('add orphan', tx);

  this.limitOrphans();

  return missing;
};

/**
 * Resolve orphans and attempt to add to mempool.
 * @method
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}[].
 */

Mempool.prototype.handleOrphans = co(function* handleOrphans(tx) {
  var resolved = this.resolveOrphans(tx);
  var i, orphan;

  for (i = 0; i < resolved.length; i++) {
    orphan = resolved[i];

    try {
      yield this.insertTX(orphan);
    } catch (err) {
      if (err.type === 'VerifyError') {
        this.logger.debug(
          'Could not resolve orphan %s: %s.',
          orphan.txid(), err.message);

        if (!orphan.hasWitness() && !err.malleated)
          this.rejects.add(orphan.hash());

        continue;
      }
      throw err;
    }

    this.logger.debug(
      'Resolved orphan %s in mempool (txs=%d).',
      orphan.txid(), this.totalTX);
  }

  return resolved;
});

/**
 * Potentially resolve any transactions
 * that redeem the passed-in transaction.
 * Deletes all orphan entries and
 * returns orphan hashes.
 * @param {TX} tx
 * @returns {TX[]} Resolved
 */

Mempool.prototype.resolveOrphans = function resolveOrphans(tx) {
  var hash = tx.hash('hex');
  var resolved = [];
  var hashes = this.waiting[hash];
  var i, orphanHash, orphan;

  if (!hashes)
    return resolved;

  for (i = 0; i < hashes.length; i++) {
    orphanHash = hashes[i];
    orphan = this.getOrphan(orphanHash);

    if (!orphan)
      continue;

    if (--orphan.missing === 0) {
      delete this.orphans[orphanHash];
      this.totalOrphans--;
      try {
        resolved.push(orphan.toTX());
      } catch (e) {
        this.logger.warning('%s %s',
          'Warning: possible memory corruption.',
          'Orphan failed deserialization.');
      }
    }
  }

  delete this.waiting[hash];

  return resolved;
};

/**
 * Remove a transaction from the mempool.
 * @param {Hash} tx
 */

Mempool.prototype.removeOrphan = function removeOrphan(hash) {
  var orphan = this.getOrphan(hash);
  var i, j, tx, hashes, prevout, prev;

  if (!orphan)
    return;

  try {
    tx = orphan.toTX();
  } catch (e) {
    delete this.orphans[hash];
    this.totalOrphans--;
    this.logger.warning('%s %s',
      'Warning: possible memory corruption.',
      'Orphan failed deserialization.');
    return;
  }

  prevout = tx.getPrevout();

  for (i = 0; i < prevout.length; i++) {
    prev = prevout[i];
    hashes = this.waiting[prev];

    if (!hashes)
      continue;

    j = hashes.indexOf(hash);

    if (j === -1)
      continue;

    hashes.splice(j, 1);

    if (hashes.length === 0)
      delete this.waiting[prev];
  }

  delete this.orphans[hash];
  this.totalOrphans--;

  this.emit('remove orphan', tx);
};

/**
 * Test all of a transactions outpoints to see if they are doublespends.
 * Note that this will only test against the mempool spents, not the
 * blockchain's. The blockchain spents are not checked against because
 * the blockchain does not maintain a spent list. The transaction will
 * be seen as an orphan rather than a double spend.
 * @param {TX} tx
 * @returns {Promise} - Returns Boolean.
 */

Mempool.prototype.isDoubleSpend = function isDoubleSpend(tx) {
  var i, input, prevout;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    if (this.isSpent(prevout.hash, prevout.index))
      return true;
  }

  return false;
};

/**
 * Get coin viewpoint (lock).
 * @method
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

Mempool.prototype.getSpentView = co(function* getSpentView(tx) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.getCoinView(tx);
  } finally {
    unlock();
  }
});

/**
 * Get coin viewpoint (no lock).
 * @method
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

Mempool.prototype.getCoinView = co(function* getCoinView(tx) {
  var view = new CoinView();
  var prevout = tx.getPrevout();
  var i, hash, entry, coins;

  for (i = 0; i < prevout.length; i++) {
    hash = prevout[i];
    entry = this.getEntry(hash);

    if (entry) {
      view.addTX(entry.tx, -1);
      continue;
    }

    coins = yield this.chain.db.getCoins(hash);

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
 * Find missing outpoints.
 * @param {TX} tx
 * @param {CoinView} view
 * @returns {Hash[]}
 */

Mempool.prototype.findMissing = function findMissing(tx, view) {
  var missing = [];
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (view.hasEntry(input))
      continue;

    missing.push(input.prevout.hash);
  }

  if (missing.length === 0)
    return;

  return missing;
};

/**
 * Get a snapshot of all transaction hashes in the mempool. Used
 * for generating INV packets in response to MEMPOOL packets.
 * @returns {Hash[]}
 */

Mempool.prototype.getSnapshot = function getSnapshot() {
  return Object.keys(this.map);
};

/**
 * Check sequence locks on a transaction against the current tip.
 * @param {TX} tx
 * @param {CoinView} view
 * @param {LockFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

Mempool.prototype.verifyLocks = function verifyLocks(tx, view, flags) {
  return this.chain.verifyLocks(this.chain.tip, tx, view, flags);
};

/**
 * Check locktime on a transaction against the current tip.
 * @param {TX} tx
 * @param {LockFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

Mempool.prototype.verifyFinal = function verifyFinal(tx, flags) {
  return this.chain.verifyFinal(this.chain.tip, tx, flags);
};

/**
 * Map a transaction to the mempool.
 * @private
 * @param {MempoolEntry} entry
 * @param {CoinView} view
 */

Mempool.prototype.trackEntry = function trackEntry(entry, view) {
  var tx = entry.tx;
  var hash = tx.hash('hex');
  var i, input, key;

  assert(!this.map[hash]);
  this.map[hash] = entry;

  assert(!tx.isCoinbase());

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    key = input.prevout.toKey();
    this.spents[key] = entry;
  }

  if (this.options.indexAddress && view)
    this.indexEntry(entry, view);

  this.size += entry.memUsage();
  this.totalTX++;
};

/**
 * Unmap a transaction from the mempool.
 * @private
 * @param {MempoolEntry} entry
 */

Mempool.prototype.untrackEntry = function untrackEntry(entry) {
  var tx = entry.tx;
  var hash = tx.hash('hex');
  var i, input, key;

  assert(this.map[hash]);
  delete this.map[hash];

  assert(!tx.isCoinbase());

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    key = input.prevout.toKey();
    delete this.spents[key];
  }

  if (this.options.indexAddress)
    this.unindexEntry(entry);

  this.size -= entry.memUsage();
  this.totalTX--;
};

/**
 * Index an entry by address.
 * @private
 * @param {MempoolEntry} entry
 * @param {CoinView} view
 */

Mempool.prototype.indexEntry = function indexEntry(entry, view) {
  var tx = entry.tx;
  var i, input, prev;

  this.txIndex.insert(entry, view);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prev = input.prevout;
    this.coinIndex.remove(prev.hash, prev.index);
  }

  for (i = 0; i < tx.outputs.length; i++)
    this.coinIndex.insert(tx, i);
};

/**
 * Unindex an entry by address.
 * @private
 * @param {MempoolEntry} entry
 */

Mempool.prototype.unindexEntry = function unindexEntry(entry) {
  var tx = entry.tx;
  var hash = tx.hash('hex');
  var i, input, prevout, prev;

  this.txIndex.remove(hash);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout.hash;
    prev = this.getTX(prevout.hash);

    if (!prev)
      continue;

    this.coinIndex.insert(prev, prevout.index);
  }

  for (i = 0; i < tx.outputs.length; i++)
    this.coinIndex.remove(hash, i);
};

/**
 * Recursively remove double spenders
 * of a mined transaction's outpoints.
 * @private
 * @param {TX} tx
 */

Mempool.prototype.removeDoubleSpends = function removeDoubleSpends(tx) {
  var i, input, prevout, spent;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    spent = this.getSpent(prevout.hash, prevout.index);

    if (!spent)
      continue;

    this.logger.debug(
      'Removing double spender from mempool: %s.',
      spent.txid());

    this.evictEntry(spent);

    this.emit('double spend', spent);
  }
};

/**
 * Calculate the memory usage of the entire mempool.
 * @see DynamicMemoryUsage()
 * @returns {Number} Usage in bytes.
 */

Mempool.prototype.getSize = function getSize() {
  return this.size;
};

/**
 * Prioritise transaction.
 * @param {MempoolEntry} entry
 * @param {Number} pri
 * @param {Amount} fee
 */

Mempool.prototype.prioritise = function _prioritise(entry, pri, fee) {
  if (-pri > entry.priority)
    pri = -entry.priority;

  entry.priority += pri;

  if (-fee > entry.deltaFee)
    fee = -entry.deltaFee;

  if (fee === 0)
    return;

  this.updateAncestors(entry, preprioritise);

  entry.deltaFee += fee;
  entry.descFee += fee;

  this.updateAncestors(entry, prioritise);
};

/**
 * MempoolOptions
 * @alias module:mempool.MempoolOptions
 * @constructor
 * @param {Object}
 */

function MempoolOptions(options) {
  if (!(this instanceof MempoolOptions))
    return new MempoolOptions(options);

  this.network = Network.primary;
  this.chain = null;
  this.logger = null;
  this.fees = null;

  this.limitFree = true;
  this.limitFreeRelay = 15;
  this.relayPriority = true;
  this.requireStandard = this.network.requireStandard;
  this.rejectAbsurdFees = true;
  this.prematureWitness = false;
  this.paranoidChecks = false;
  this.replaceByFee = false;

  this.maxSize = policy.MEMPOOL_MAX_SIZE;
  this.maxOrphans = policy.MEMPOOL_MAX_ORPHANS;
  this.maxAncestors = policy.MEMPOOL_MAX_ANCESTORS;
  this.expiryTime = policy.MEMPOOL_EXPIRY_TIME;
  this.minRelay = this.network.minRelay;

  this.prefix = null;
  this.location = null;
  this.db = 'memory';
  this.maxFiles = 64;
  this.cacheSize = 32 << 20;
  this.compression = true;
  this.bufferKeys = layout.binary;

  this.persistent = false;

  this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {MempoolOptions}
 */

MempoolOptions.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Mempool requires options.');
  assert(options.chain && typeof options.chain === 'object',
    'Mempool requires a blockchain.');

  this.chain = options.chain;
  this.network = options.chain.network;
  this.logger = options.chain.logger;

  this.requireStandard = this.network.requireStandard;
  this.minRelay = this.network.minRelay;

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.fees != null) {
    assert(typeof options.fees === 'object');
    this.fees = options.fees;
  }

  if (options.limitFree != null) {
    assert(typeof options.limitFree === 'boolean');
    this.limitFree = options.limitFree;
  }

  if (options.limitFreeRelay != null) {
    assert(util.isNumber(options.limitFreeRelay));
    this.limitFreeRelay = options.limitFreeRelay;
  }

  if (options.relayPriority != null) {
    assert(typeof options.relayPriority === 'boolean');
    this.relayPriority = options.relayPriority;
  }

  if (options.requireStandard != null) {
    assert(typeof options.requireStandard === 'boolean');
    this.requireStandard = options.requireStandard;
  }

  if (options.rejectAbsurdFees != null) {
    assert(typeof options.rejectAbsurdFees === 'boolean');
    this.rejectAbsurdFees = options.rejectAbsurdFees;
  }

  if (options.prematureWitness != null) {
    assert(typeof options.prematureWitness === 'boolean');
    this.prematureWitness = options.prematureWitness;
  }

  if (options.paranoidChecks != null) {
    assert(typeof options.paranoidChecks === 'boolean');
    this.paranoidChecks = options.paranoidChecks;
  }

  if (options.replaceByFee != null) {
    assert(typeof options.replaceByFee === 'boolean');
    this.replaceByFee = options.replaceByFee;
  }

  if (options.maxSize != null) {
    assert(util.isNumber(options.maxSize));
    this.maxSize = options.maxSize;
  }

  if (options.maxOrphans != null) {
    assert(util.isNumber(options.maxOrphans));
    this.maxOrphans = options.maxOrphans;
  }

  if (options.maxAncestors != null) {
    assert(util.isNumber(options.maxAncestors));
    this.maxAncestors = options.maxAncestors;
  }

  if (options.expiryTime != null) {
    assert(util.isNumber(options.expiryTime));
    this.expiryTime = options.expiryTime;
  }

  if (options.minRelay != null) {
    assert(util.isNumber(options.minRelay));
    this.minRelay = options.minRelay;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = options.prefix;
    this.location = this.prefix + '/mempool';
  }

  if (options.location != null) {
    assert(typeof options.location === 'string');
    this.location = options.location;
  }

  if (options.db != null) {
    assert(typeof options.db === 'string');
    this.db = options.db;
  }

  if (options.maxFiles != null) {
    assert(util.isNumber(options.maxFiles));
    this.maxFiles = options.maxFiles;
  }

  if (options.cacheSize != null) {
    assert(util.isNumber(options.cacheSize));
    this.cacheSize = options.cacheSize;
  }

  if (options.compression != null) {
    assert(typeof options.compression === 'boolean');
    this.compression = options.compression;
  }

  if (options.persistent != null) {
    assert(typeof options.persistent === 'boolean');
    this.persistent = options.persistent;
  }

  return this;
};

/**
 * Instantiate mempool options from object.
 * @param {Object} options
 * @returns {MempoolOptions}
 */

MempoolOptions.fromOptions = function fromOptions(options) {
  return new MempoolOptions().fromOptions(options);
};

/**
 * TX Address Index
 * @constructor
 * @ignore
 */

function TXIndex() {
  // Map of addr->entries.
  this.index = {};

  // Map of txid->addrs.
  this.map = {};
}

TXIndex.prototype.reset = function reset() {
  this.index = {};
  this.map = {};
};

TXIndex.prototype.get = function get(addr) {
  var items = this.index[addr];
  var out = [];
  var i, keys, entry;

  if (!items)
    return out;

  keys = items.keys();

  for (i = 0; i < keys.length; i++) {
    entry = items.get(keys[i]);
    out.push(entry.tx);
  }

  return out;
};

TXIndex.prototype.getMeta = function getMeta(addr) {
  var items = this.index[addr];
  var out = [];
  var i, entry, keys, meta;

  if (!items)
    return out;

  keys = items.keys();

  for (i = 0; i < keys.length; i++) {
    entry = items.get(keys[i]);
    meta = TXMeta.fromTX(entry.tx);
    meta.ps = entry.ts;
    out.push(meta);
  }

  return out;
};

TXIndex.prototype.insert = function insert(entry, view) {
  var tx = entry.tx;
  var hash = tx.hash('hex');
  var addrs = tx.getHashes(view, 'hex');
  var i, addr, items;

  if (addrs.length === 0)
    return;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];
    items = this.index[addr];

    if (!items) {
      items = new Map();
      this.index[addr] = items;
    }

    assert(!items.has(hash));
    items.set(hash, entry);
  }

  this.map[hash] = addrs;
};

TXIndex.prototype.remove = function remove(hash) {
  var addrs = this.map[hash];
  var i, addr, items;

  if (!addrs)
    return;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];
    items = this.index[addr];

    assert(items);
    assert(items.has(hash));

    items.remove(hash);

    if (items.size === 0)
      delete this.index[addr];
  }

  delete this.map[hash];
};

/**
 * Coin Address Index
 * @constructor
 * @ignore
 */

function CoinIndex() {
  // Map of addr->coins.
  this.index = {};

  // Map of outpoint->addr.
  this.map = {};
}

CoinIndex.prototype.reset = function reset() {
  this.index = {};
  this.map = {};
};

CoinIndex.prototype.get = function get(addr) {
  var items = this.index[addr];
  var out = [];
  var i, keys, coin;

  if (!items)
    return out;

  keys = items.keys();

  for (i = 0; i < keys.length; i++) {
    coin = items.get(keys[i]);
    assert(coin);
    out.push(coin.toCoin());
  }

  return out;
};

CoinIndex.prototype.insert = function insert(tx, index) {
  var output = tx.outputs[index];
  var hash = tx.hash('hex');
  var addr = output.getHash('hex');
  var items, key;

  if (!addr)
    return;

  items = this.index[addr];

  if (!items) {
    items = new Map();
    this.index[addr] = items;
  }

  key = Outpoint.toKey(hash, index);

  assert(!items.has(key));
  items.set(key, new IndexedCoin(tx, index));

  this.map[key] = addr;
};

CoinIndex.prototype.remove = function remove(hash, index) {
  var key = Outpoint.toKey(hash, index);
  var addr = this.map[key];
  var items;

  if (!addr)
    return;

  items = this.index[addr];

  assert(items);
  assert(items.has(key));
  items.remove(key);

  if (items.size === 0)
    delete this.index[addr];

  delete this.map[key];
};

/**
 * IndexedCoin
 * @constructor
 * @ignore
 * @param {TX} tx
 * @param {Number} index
 */

function IndexedCoin(tx, index) {
  this.tx = tx;
  this.index = index;
}

IndexedCoin.prototype.toCoin = function toCoin() {
  return Coin.fromTX(this.tx, this.index, -1);
};

/**
 * Orphan
 * @constructor
 * @ignore
 * @param {TX} tx
 * @param {Hash[]} missing
 */

function Orphan(tx, missing) {
  this.raw = tx.toRaw();
  this.missing = missing;
}

Orphan.prototype.toTX = function toTX() {
  return TX.fromRaw(this.raw);
};

/**
 * Mempool Cache
 * @ignore
 * @constructor
 * @param {Object} options
 */

function MempoolCache(options) {
  if (!(this instanceof MempoolCache))
    return new MempoolCache(options);

  this.logger = options.logger;
  this.chain = options.chain;
  this.network = options.network;
  this.db = null;
  this.batch = null;

  if (options.persistent)
    this.db = LDB(options);
}

MempoolCache.VERSION = 2;

MempoolCache.prototype.getVersion = co(function* getVersion() {
  var data = yield this.db.get(layout.V);

  if (!data)
    return -1;

  return data.readUInt32LE(0, true);
});

MempoolCache.prototype.getTip = co(function* getTip() {
  var hash = yield this.db.get(layout.R);

  if (!hash)
    return;

  return hash.toString('hex');
});

MempoolCache.prototype.getFees = co(function* getFees() {
  var data = yield this.db.get(layout.F);
  var fees;

  if (!data)
    return;

  try {
    fees = Fees.fromRaw(data);
  } catch (e) {
    this.logger.warning(
      'Fee data failed deserialization: %s.',
      e.message);
  }

  return fees;
});

MempoolCache.prototype.getEntries = function getEntries() {
  return this.db.values({
    gte: layout.e(encoding.ZERO_HASH),
    lte: layout.e(encoding.MAX_HASH),
    parse: MempoolEntry.fromRaw
  });
};

MempoolCache.prototype.getKeys = function getKeys() {
  return this.db.keys({
    gte: layout.e(encoding.ZERO_HASH),
    lte: layout.e(encoding.MAX_HASH)
  });
};

MempoolCache.prototype.open = co(function* open() {
  if (!this.db)
    return;

  yield this.db.open();
  yield this.verify();

  this.batch = this.db.batch();
});

MempoolCache.prototype.close = co(function* close() {
  if (!this.db)
    return;

  yield this.db.close();

  this.batch = null;
});

MempoolCache.prototype.save = function save(entry) {
  if (!this.db)
    return;

  this.batch.put(layout.e(entry.tx.hash()), entry.toRaw());
};

MempoolCache.prototype.remove = function remove(hash) {
  if (!this.db)
    return;

  this.batch.del(layout.e(hash));
};

MempoolCache.prototype.sync = function sync(hash) {
  if (!this.db)
    return;

  this.batch.put(layout.R, new Buffer(hash, 'hex'));
};

MempoolCache.prototype.writeFees = function writeFees(fees) {
  if (!this.db)
    return;

  this.batch.put(layout.F, fees.toRaw());
};

MempoolCache.prototype.clear = function clear() {
  this.batch.clear();
  this.batch = this.db.batch();
};

MempoolCache.prototype.flush = co(function* flush() {
  if (!this.db)
    return;

  yield this.batch.write();

  this.batch = this.db.batch();
});

MempoolCache.prototype.init = co(function* init(hash) {
  var batch = this.db.batch();
  batch.put(layout.V, encoding.U32(MempoolCache.VERSION));
  batch.put(layout.R, new Buffer(hash, 'hex'));
  yield batch.write();
});

MempoolCache.prototype.verify = co(function* verify() {
  var version = yield this.getVersion();
  var tip;

  if (version === -1) {
    version = MempoolCache.VERSION;
    tip = this.chain.tip.hash;

    this.logger.info(
      'Mempool cache is empty. Writing tip %s.',
      util.revHex(tip));

    yield this.init(tip);
  }

  if (version !== MempoolCache.VERSION) {
    this.logger.warning(
      'Mempool cache version mismatch (%d != %d)!',
      version,
      MempoolCache.VERSION);
    this.logger.warning('Invalidating mempool cache.');
    yield this.wipe();
    return false;
  }

  tip = yield this.getTip();

  if (tip !== this.chain.tip.hash) {
    this.logger.warning(
      'Mempool tip not consistent with chain tip (%s != %s)!',
      util.revHex(tip),
      this.chain.tip.rhash());
    this.logger.warning('Invalidating mempool cache.');
    yield this.wipe();
    return false;
  }

  return true;
});

MempoolCache.prototype.wipe = co(function* wipe() {
  var batch = this.db.batch();
  var keys = yield this.getKeys();
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    batch.del(key);
  }

  batch.put(layout.V, encoding.U32(MempoolCache.VERSION));
  batch.put(layout.R, new Buffer(this.chain.tip.hash, 'hex'));
  batch.del(layout.F);

  yield batch.write();

  this.logger.info('Removed %d mempool entries from disk.', keys.length);
});

/*
 * Helpers
 */

function nop(parent, child) {
  ;
}

function addFee(parent, child) {
  parent.descFee += child.deltaFee;
  parent.descSize += child.size;
}

function removeFee(parent, child) {
  parent.descFee -= child.descFee;
  parent.descSize -= child.descSize;
}

function preprioritise(parent, child) {
  parent.descFee -= child.deltaFee;
}

function prioritise(parent, child) {
  parent.descFee += child.deltaFee;
}

function cmpRate(a, b) {
  var xf = a.deltaFee;
  var xs = a.size;
  var yf = b.deltaFee;
  var ys = b.size;
  var x, y;

  if (useDesc(a)) {
    xf = a.descFee;
    xs = a.descSize;
  }

  if (useDesc(b)) {
    yf = b.descFee;
    ys = b.descSize;
  }

  x = xf * ys;
  y = xs * yf;

  if (x === y) {
    x = a.ts;
    y = b.ts;
  }

  return x - y;
}

function useDesc(a) {
  var x = a.deltaFee * a.descSize;
  var y = a.descFee * a.size;
  return y > x;
}

/*
 * Expose
 */

module.exports = Mempool;
