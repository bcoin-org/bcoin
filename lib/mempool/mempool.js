/*!
 * mempool.js - mempool for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var AsyncObject = require('../utils/async');
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
var Locker = require('../utils/locker');
var Outpoint = require('../primitives/outpoint');
var TX = require('../primitives/tx');
var Coin = require('../primitives/coin');
var TXMeta = require('../primitives/txmeta');
var MempoolEntry = require('./mempoolentry');
var CoinView = require('../coins/coinview');
var Coins = require('../coins/coins');
var VerifyError = errors.VerifyError;
var VerifyResult = errors.VerifyResult;

/**
 * Represents a mempool.
 * @exports Mempool
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
 * @property {Locker} locker
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

  if (!options)
    options = {};

  this.options = options;
  this.chain = options.chain;
  this.fees = options.fees;

  assert(this.chain, 'Mempool requires a blockchain.');

  this.network = this.chain.network;
  this.logger = options.logger || this.chain.logger;
  this.loaded = false;

  this.locker = new Locker(true);

  this.size = 0;
  this.totalOrphans = 0;
  this.totalTX = 0;

  this.waiting = {};
  this.orphans = {};
  this.map = {};
  this.spents = {};
  this.coinIndex = new CoinIndex(this);
  this.txIndex = new TXIndex(this);

  this.rejects = new Bloom.Rolling(120000, 0.000001);

  this.freeCount = 0;
  this.lastTime = 0;

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

  this._initOptions(options);
}

util.inherits(Mempool, AsyncObject);

/**
 * Initialize options.
 * @param {Object} options
 * @private
 */

Mempool.prototype._initOptions = function _initOptions(options) {
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
};

/**
 * Open the chain, wait for the database to load.
 * @alias Mempool#open
 * @returns {Promise}
 */

Mempool.prototype._open = co(function* open() {
  var size = (this.maxSize / 1024).toFixed(2);
  yield this.chain.open();
  this.logger.info('Mempool loaded (maxsize=%dkb).', size);
});

/**
 * Close the chain, wait for the database to close.
 * @alias Mempool#close
 * @returns {Promise}
 */

Mempool.prototype._close = function close() {
  return Promise.resolve();
};

/**
 * Notify the mempool that a new block has come
 * in (removes all transactions contained in the
 * block from the mempool).
 * @param {ChainEntry} block
 * @param {TX[]} txs
 * @returns {Promise}
 */

Mempool.prototype.addBlock = co(function* addBlock(block, txs) {
  var unlock = yield this.locker.lock();
  try {
    return this._addBlock(block, txs);
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

Mempool.prototype._addBlock = function addBlock(block, txs) {
  var entries = [];
  var i, entry, tx, hash;

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

  if (this.fees)
    this.fees.processBlock(block.height, entries, this.chain.isFull());

  // We need to reset the rejects filter periodically.
  // There may be a locktime in a TX that is now valid.
  this.rejects.reset();

  if (entries.length === 0)
    return;

  this.logger.debug(
    'Removed %d txs from mempool for block %d.',
    entries.length, block.height);
};

/**
 * Notify the mempool that a block has been disconnected
 * from the main chain (reinserts transactions into the mempool).
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
 * @private
 * @param {ChainEntry} block
 * @param {TX[]} txs
 * @returns {Promise}
 */

Mempool.prototype._removeBlock = co(function* removeBlock(block, txs) {
  var total = 0;
  var i, tx, hash;

  for (i = 1; i < txs.length; i++) {
    tx = txs[i];
    hash = tx.hash('hex');

    if (this.hasTX(hash))
      continue;

    try {
      yield this._addTX(tx);
      total++;
    } catch (e) {
      this.emit('error', e);
      continue;
    }

    this.emit('unconfirmed', tx, block);
  }

  this.rejects.reset();

  if (total === 0)
    return;

  this.logger.debug(
    'Added %d txs back into the mempool for block %d.',
    total, block.height);
});

/**
 * Reset the mempool.
 * @returns {Promise}
 */

Mempool.prototype.reset = co(function* reset() {
  var unlock = yield this.locker.lock();
  try {
    return this._reset();
  } finally {
    unlock();
  }
});

/**
 * Reset the mempool without a lock.
 * @private
 */

Mempool.prototype._reset = function reset() {
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
};

/**
 * Ensure the size of the mempool stays below 300mb.
 * @param {Hash} entryHash - TX that initiated the trim.
 * @returns {Promise}
 */

Mempool.prototype.limitSize = function limitSize(entryHash) {
  var trimmed = false;
  var i, hashes, hash, end, entry;

  if (this.getSize() <= this.maxSize)
    return trimmed;

  hashes = this.getSnapshot();
  end = util.now() - this.expiryTime;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    entry = this.getEntry(hash);

    if (!entry)
      continue;

    if (entry.ts >= end)
      continue;

    if (!trimmed && hash === entryHash)
      trimmed = true;

    this.removeEntry(entry, true);

    if (this.getSize() <= this.maxSize)
      return trimmed;
  }

  hashes = this.getSnapshot();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    entry = this.getEntry(hash);

    if (!entry)
      continue;

    if (!trimmed && hash === entryHash)
      trimmed = true;

    this.removeEntry(entry, true);

    if (this.getSize() <= this.maxSize)
      return trimmed;
  }

  return trimmed;
};

/**
 * Purge orphan transactions from the mempool.
 */

Mempool.prototype.limitOrphans = function limitOrphans() {
  var orphans = Object.keys(this.orphans);
  var i, hash;

  while (this.totalOrphans > this.maxOrphans) {
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

Mempool.prototype.hasTX = function hasTX(hash) {
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

  return this.hasTX(hash);
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

  return this.hasTX(hash);
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
 * @param {TX} tx
 * @returns {Promise}
 */

Mempool.prototype.addTX = co(function* addTX(tx) {
  var hash = tx.hash('hex');
  var unlock = yield this.locker.lock(hash);
  try {
    return yield this._addTX(tx);
  } catch (err) {
    if (err.type === 'VerifyError') {
      if (!tx.hasWitness() && !err.malleated)
        this.rejects.add(tx.hash());
    }
    throw err;
  } finally {
    unlock();
  }
});

/**
 * Add a transaction to the mempool without a lock.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

Mempool.prototype._addTX = co(function* _addTX(tx) {
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
  if (this.requireStandard) {
    if (!this.chain.state.hasCSV() && tx.version >= 2) {
      throw new VerifyError(tx,
        'nonstandard',
        'premature-version2-tx',
        0);
    }
  }

  // Do not allow segwit until it's activated.
  if (!this.chain.state.hasWitness() && !this.prematureWitness) {
    if (tx.hasWitness()) {
      throw new VerifyError(tx,
        'nonstandard',
        'no-witness-yet',
        0);
    }
  }

  // Non-contextual standardness checks.
  if (this.requireStandard) {
    if (!tx.isStandard(ret)) {
      throw new VerifyError(tx,
        'nonstandard',
        ret.reason,
        ret.score);
    }
    if (!this.replaceByFee) {
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
  if (this.requireStandard) {
    if (!tx.hasStandardInputs(view)) {
      throw new VerifyError(tx,
        'nonstandard',
        'bad-txns-nonstandard-inputs',
        0);
    }
    if (this.chain.state.hasWitness()) {
      if (!tx.hasStandardWitness(view, ret)) {
        ret = new VerifyError(tx,
          'nonstandard',
          ret.reason,
          ret.score);
        ret.malleated = ret.score > 0;
        throw ret;
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
  minFee = tx.getMinFee(entry.size, this.minRelay);

  if (this.relayPriority && entry.fee < minFee) {
    if (!entry.isFree(height)) {
      throw new VerifyError(tx,
        'insufficientfee',
        'insufficient priority',
        0);
    }
  }

  // Continuously rate-limit free (really, very-low-fee)
  // transactions. This mitigates 'penny-flooding'.
  if (this.limitFree && entry.fee < minFee) {
    now = util.now();

    // Use an exponentially decaying ~10-minute window.
    this.freeCount *= Math.pow(1 - 1 / 600, now - this.lastTime);
    this.lastTime = now;

    // The limitFreeRelay unit is thousand-bytes-per-minute
    // At default rate it would take over a month to fill 1GB.
    if (this.freeCount > this.limitFreeRelay * 10 * 1000) {
      throw new VerifyError(tx,
        'insufficientfee',
        'rate limited free transaction',
        0);
    }

    this.freeCount += entry.size;
  }

  // Important safety feature.
  if (this.rejectAbsurdFees && entry.fee > minFee * 10000)
    throw new VerifyError(tx, 'highfee', 'absurdly-high-fee', 0);

  // Why do we have this here? Nested transactions are cool.
  if (this.countAncestors(tx) > this.maxAncestors) {
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
  if (this.paranoidChecks) {
    flags = Script.flags.MANDATORY_VERIFY_FLAGS;
    result = yield this.verifyResult(tx, view, flags);
    assert(result, 'BUG: Verify failed for mandatory but not standard.');
  }
});

/**
 * Verify inputs, return a boolean
 * instead of an error based on success.
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
 * @param {MempoolEntry} entry
 * @param {CoinView} view
 * @returns {Promise}
 */

Mempool.prototype.addEntry = co(function* addEntry(entry, view) {
  var tx = entry.tx;

  this.trackEntry(entry, view);

  this.emit('tx', tx, view);
  this.emit('add entry', entry);

  if (this.fees)
    this.fees.processTX(entry, this.chain.isFull());

  this.logger.debug('Added tx %s to mempool.', tx.txid());

  yield this.handleOrphans(tx);
});

/**
 * Remove a transaction from the mempool. Generally
 * only called when a new block is added to the main chain.
 * @param {MempoolEntry} entry
 * @param {Boolean} limit
 */

Mempool.prototype.removeEntry = function removeEntry(entry, limit) {
  var tx = entry.tx;
  var hash = tx.hash('hex');

  // We do not remove spenders if this is
  // being removed for a block. The spenders
  // are still spending valid coins (which
  // now exist on the blockchain).
  if (limit) {
    this.removeSpenders(entry);
    this.logger.debug('Evicting %s from the mempool.', tx.txid());
  } else {
    this.logger.spam('Removing block tx %s from mempool.', tx.txid());
  }

  this.untrackEntry(entry);

  if (this.fees)
    this.fees.removeTX(hash);

  this.emit('remove entry', entry);
};

/**
 * Count the highest number of
 * ancestors a transaction may have.
 * @param {TX} tx
 * @returns {Number}
 */

Mempool.prototype.countAncestors = function countAncestors(tx) {
  return this._countAncestors(tx, 0, {});
};

/**
 * Traverse ancestors and count.
 * @private
 * @param {TX} tx
 * @param {Number} count
 * @param {Object} set
 * @returns {Number}
 */

Mempool.prototype._countAncestors = function countAncestors(tx, count, set) {
  var i, input, hash, prev;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    hash = input.prevout.hash;
    prev = this.getTX(hash);

    if (!prev)
      continue;

    if (set[hash])
      continue;

    set[hash] = true;
    count += 1;

    if (count > this.maxAncestors)
      break;

    count = this._countAncestors(prev, count, set);

    if (count > this.maxAncestors)
      break;
  }

  return count;
};

/**
 * Count the highest number of
 * descendants a transaction may have.
 * @param {TX} tx
 * @returns {Number}
 */

Mempool.prototype.countDescendants = function countDescendants(tx) {
  return this._countDescendants(tx, 0, {});
};

/**
 * Count the highest number of
 * descendants a transaction may have.
 * @private
 * @param {TX} tx
 * @param {Number} count
 * @param {Object} set
 * @returns {Number}
 */

Mempool.prototype._countDescendants = function countDescendants(tx, count, set) {
  var hash = tx.hash('hex');
  var i, next, nhash;

  for (i = 0; i < tx.outputs.length; i++) {
    next = this.getSpentTX(hash, i);

    if (!next)
      continue;

    nhash = next.hash('hex');

    if (set[nhash])
      continue;

    set[nhash] = true;
    count += 1;

    count = this._countDescendants(next, count, set);
  }

  return count;
};

/**
 * Get all transaction ancestors.
 * @param {TX} tx
 * @returns {MempoolEntry[]}
 */

Mempool.prototype.getAncestors = function getAncestors(tx) {
  return this._getAncestors(tx, [], {});
};

/**
 * Get all transaction ancestors.
 * @private
 * @param {TX} tx
 * @param {MempoolEntry[]} entries
 * @param {Object} set
 * @returns {MempoolEntry[]}
 */

Mempool.prototype._getAncestors = function getAncestors(tx, entries, set) {
  var i, hash, input, prev;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    hash = input.prevout.hash;
    prev = this.getTX(hash);

    if (!prev)
      continue;

    if (set[hash])
      continue;

    set[hash] = true;
    entries.push(prev);

    this._getAncestors(prev, entries, set);
  }

  return entries;
};

/**
 * Get all a transaction descendants.
 * @param {TX} tx
 * @returns {MempoolEntry[]}
 */

Mempool.prototype.getDescendants = function getDescendants(tx) {
  return this._getDescendants(tx, [], {});
};

/**
 * Get all a transaction descendants.
 * @param {TX} tx
 * @param {MempoolEntry[]} entries
 * @param {Object} set
 * @returns {MempoolEntry[]}
 */

Mempool.prototype._getDescendants = function getDescendants(tx, entries, set) {
  var hash = tx.hash('hex');
  var i, next, nhash;

  for (i = 0; i < tx.outputs.length; i++) {
    next = this.getSpentTX(hash, i);

    if (!next)
      continue;

    nhash = next.hash('hex');

    if (set[nhash])
      continue;

    set[nhash] = true;
    entries.push(next);

    this._getDescendants(next, entries, set);
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
    hash = prevout[i].hash;
    if (this.hasTX(hash))
      depends.push(hash);
  }

  return depends;
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
    return;
  }

  for (i = 0; i < missing.length; i++) {
    prev = missing[i];
    if (this.hasReject(prev)) {
      this.logger.debug('Not storing orphan %s (rejected parents).', tx.txid());
      this.rejects.add(tx.hash());
      return;
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
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}[].
 */

Mempool.prototype.handleOrphans = co(function* handleOrphans(tx) {
  var resolved = this.resolveOrphans(tx);
  var i, orphan;

  for (i = 0; i < resolved.length; i++) {
    orphan = resolved[i];

    try {
      yield this._addTX(orphan);
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

    this.logger.debug('Resolved orphan %s in mempool.', orphan.txid());
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
 * Get coin viewpoint (no lock).
 * @param {TX} tx
 * @param {CoinView} view
 * @returns {Promise} - Returns {@link CoinView}.
 */

Mempool.prototype.getCoinView = co(function* getCoinView(tx) {
  var state = this.chain.state;
  var view = new CoinView();
  var prevout = tx.getPrevout();
  var i, entry, hash, coins;

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

  if (state !== this.chain.state)
    throw new Error('Chain state changed while getting coins.');

  return view;
});

/**
 * Get coin viewpoint (lock).
 * @param {TX} tx
 * @param {CoinView} view
 * @returns {Promise} - Returns {@link CoinView}.
 */

Mempool.prototype._getCoinView = co(function* getCoinView(tx) {
  var state = this.chain.state;
  var view = yield this.chain.db.getCoinView(tx);
  var items = view.toArray();
  var i, coins, entry;

  for (i = 0; i < items.length; i++) {
    coins = items[i];

    if (!coins.isEmpty())
      continue;

    entry = this.getEntry(coins.hash);

    if (!entry)
      continue;

    view.addTX(entry.tx, -1);
  }

  if (state !== this.chain.state)
    throw new Error('Chain state changed while getting coins.');

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

  if (this.options.indexAddress)
    this.indexEntry(entry, view);

  this.size += this.memUsage(tx);
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

  this.size -= this.memUsage(tx);
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
  var i, input;

  this.txIndex.insert(tx, view);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    this.coinIndex.remove(input.prevout);
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
  var i, input, prevout, prev;

  this.txIndex.remove(tx);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout.hash;
    prev = this.getTX(prevout.hash);

    if (!prev)
      continue;

    this.coinIndex.insert(prev, prevout.index);
  }

  for (i = 0; i < tx.outputs.length; i++) {
    prevout = Outpoint.fromTX(tx, i);
    this.coinIndex.remove(prevout);
  }
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

    this.removeEntry(spender, true);
  }
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
      spent.tx.rhash());

    this.removeEntry(spent, true);
  }
};

/**
 * Calculate the memory usage of a transaction.
 * Note that this only calculates the JS heap
 * size. Sizes of buffers are ignored (the v8
 * heap is what we care most about). All numbers
 * are based on the output of v8 heap snapshots
 * of TX objects.
 * @param {TX} tx
 * @returns {Number} Usage in bytes.
 */

Mempool.prototype.memUsage = function memUsage(tx) {
  var mem = 0;
  var i, j, input, output, op;

  mem += 272; // tx
  mem += 80; // _hash
  mem += 88; // _hhash
  mem += 80; // _raw
  mem += 80; // _whash

  mem += 32; // input array

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    mem += 144; // input
    mem += 104; // prevout
    mem += 88; // prevout hash

    mem += 40; // script
    mem += 80; // script raw buffer
    mem += 32; // script code array
    mem += input.script.code.length * 40; // opcodes

    for (j = 0; j < input.script.code.length; j++) {
      op = input.script.code[j];
      if (op.data)
        mem += 80; // op buffers
    }

    mem += 96; // witness
    mem += 32; // witness items
    mem += input.witness.items.length * 80; // witness buffers
  }

  mem += 32; // output array

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    mem += 120; // output
    mem += 40; // script
    mem += 80; // script raw buffer
    mem += 32; // script code array
    mem += output.script.code.length * 40; // opcodes

    for (j = 0; j < output.script.code.length; j++) {
      op = output.script.code[j];
      if (op.data)
        mem += 80; // op buffers
    }
  }

  mem += 152; // mempool entry

  return mem;
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
 * TX Address Index
 */

function TXIndex(mempool) {
  this.mempool = mempool;

  // Map of addr->txids.
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
  var i, hash, tx;

  if (!items)
    return out;

  for (i = 0; i < items.length; i++) {
    hash = items[i].toString('hex');
    tx = this.mempool.getTX(hash);
    assert(tx);
    out.push(tx);
  }

  return out;
};

TXIndex.prototype.getMeta = function getMeta(addr) {
  var items = this.index[addr];
  var out = [];
  var i, hash, tx;

  if (!items)
    return out;

  for (i = 0; i < items.length; i++) {
    hash = items[i].toString('hex');
    tx = this.mempool.getMeta(hash);
    assert(tx);
    out.push(tx);
  }

  return out;
};

TXIndex.prototype.insert = function insert(tx, view) {
  var key = tx.hash('hex');
  var addrs = tx.getHashes(view, 'hex');
  var i, addr, items;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];
    items = this.index[addr];

    if (!items) {
      items = [];
      this.index[addr] = items;
    }

    util.binaryInsert(items, tx.hash(), util.cmp);
  }

  this.map[key] = addrs;
};

TXIndex.prototype.remove = function remove(tx) {
  var key = tx.hash('hex');
  var addrs = this.map[key];
  var i, addr, items;

  if (!addrs)
    return;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];
    items = this.index[addr];

    if (!items)
      continue;

    util.binaryRemove(items, tx.hash(), util.cmp);

    if (items.length === 0)
      delete this.index[addr];
  }

  delete this.map[key];
};

/**
 * Coin Address Index
 */

function CoinIndex(mempool) {
  this.mempool = mempool;

  // Map of addr->outpoints.
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
  var i, item, outpoint, coin;

  if (!items)
    return out;

  for (i = 0; i < items.length; i++) {
    item = items[i];
    outpoint = Outpoint.fromRaw(item);
    coin = this.mempool.getCoin(outpoint.hash, outpoint.index);
    assert(coin);
    out.push(coin);
  }

  return out;
};

CoinIndex.prototype.insert = function insert(tx, i) {
  var output = tx.outputs[i];
  var addr = output.getHash('hex');
  var items, outpoint, key;

  if (!addr)
    return;

  items = this.index[addr];

  if (!items) {
    items = [];
    this.index[addr] = items;
  }

  outpoint = Outpoint.fromTX(tx, i);
  key = outpoint.toKey();

  util.binaryInsert(items, outpoint.toRaw(), util.cmp);

  this.map[key] = addr;
};

CoinIndex.prototype.remove = function remove(outpoint) {
  var key = outpoint.toKey();
  var addr = this.map[key];
  var items;

  if (!addr)
    return;

  items = this.index[addr];

  if (!items)
    return;

  util.binaryRemove(items, outpoint.toRaw(), util.cmp);

  if (items.length === 0)
    delete this.index[addr];

  delete this.map[key];
};

/*
 * Helpers
 */

function Orphan(tx, missing) {
  this.raw = tx.toRaw();
  this.missing = missing;
}

Orphan.prototype.toTX = function toTX() {
  return TX.fromRaw(this.raw);
};

/*
 * Expose
 */

module.exports = Mempool;
