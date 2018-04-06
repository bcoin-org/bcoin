/*!
 * mempool.js - mempool for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const EventEmitter = require('events');
const bdb = require('bdb');
const {RollingFilter} = require('bfilter');
const Heap = require('bheep');
const common = require('../blockchain/common');
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');
const util = require('../utils/util');
const random = require('bcrypto/lib/random');
const {VerifyError} = require('../protocol/errors');
const Address = require('../primitives/address');
const Script = require('../script/script');
const Outpoint = require('../primitives/outpoint');
const TX = require('../primitives/tx');
const Coin = require('../primitives/coin');
const TXMeta = require('../primitives/txmeta');
const MempoolEntry = require('./mempoolentry');
const Network = require('../protocol/network');
const layout = require('./layout');
const Fees = require('./fees');
const CoinView = require('../coins/coinview');

/**
 * Mempool
 * Represents a mempool.
 * @extends EventEmitter
 * @alias module:mempool.Mempool
 */

class Mempool extends EventEmitter {
  /**
   * Create a mempool.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.opened = false;
    this.options = new MempoolOptions(options);

    this.network = this.options.network;
    this.logger = this.options.logger.context('mempool');
    this.workers = this.options.workers;
    this.chain = this.options.chain;
    this.fees = this.options.fees;

    this.locker = this.chain.locker;

    this.cache = new MempoolCache(this.options);

    this.size = 0;
    this.freeCount = 0;
    this.lastTime = 0;
    this.lastFlush = 0;
    this.tip = this.network.genesis.hash;

    this.waiting = new Map();
    this.orphans = new Map();
    this.map = new Map();
    this.spents = new Map();
    this.rejects = new RollingFilter(120000, 0.000001);

    this.coinIndex = new CoinIndex();
    this.txIndex = new TXIndex();
  }

  /**
   * Open the chain, wait for the database to load.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'Mempool is already open.');
    this.opened = true;

    await this.cache.open();

    if (this.options.persistent) {
      const entries = await this.cache.getEntries();

      for (const entry of entries)
        this.trackEntry(entry);

      for (const entry of entries) {
        this.updateAncestors(entry, addFee);

        if (this.options.indexAddress) {
          const view = await this.getCoinView(entry.tx);
          this.indexEntry(entry, view);
        }
      }

      this.logger.info(
        'Loaded mempool from disk (%d entries).',
        entries.length);

      if (this.fees) {
        const fees = await this.cache.getFees();

        if (fees) {
          this.fees.inject(fees);
          this.logger.info(
            'Loaded mempool fee data (rate=%d).',
            this.fees.estimateFee());
        }
      }
    }

    this.tip = this.chain.tip.hash;

    const size = (this.options.maxSize / 1024).toFixed(2);

    this.logger.info('Mempool loaded (maxsize=%dkb).', size);
  }

  /**
   * Close the chain, wait for the database to close.
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'Mempool is not open.');
    this.opened = false;
    return this.cache.close();
  }

  /**
   * Notify the mempool that a new block has come
   * in (removes all transactions contained in the
   * block from the mempool).
   * @method
   * @param {ChainEntry} block
   * @param {TX[]} txs
   * @returns {Promise}
   */

  async addBlock(block, txs) {
    const unlock = await this.locker.lock();
    try {
      return await this._addBlock(block, txs);
    } finally {
      unlock();
    }
  }

  /**
   * Notify the mempool that a new block
   * has come without a lock.
   * @private
   * @param {ChainEntry} block
   * @param {TX[]} txs
   * @returns {Promise}
   */

  async _addBlock(block, txs) {
    if (this.map.size === 0) {
      this.tip = block.hash;
      return;
    }

    const entries = [];

    for (let i = txs.length - 1; i >= 1; i--) {
      const tx = txs[i];
      const hash = tx.hash('hex');
      const entry = this.getEntry(hash);

      if (!entry) {
        this.removeOrphan(hash);
        this.removeDoubleSpends(tx);
        if (this.waiting.has(hash))
          await this.handleOrphans(tx);
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

    await this.cache.flush();

    this.tip = block.hash;

    if (entries.length === 0)
      return;

    this.logger.debug(
      'Removed %d txs from mempool for block %d.',
      entries.length, block.height);
  }

  /**
   * Notify the mempool that a block has been disconnected
   * from the main chain (reinserts transactions into the mempool).
   * @method
   * @param {ChainEntry} block
   * @param {TX[]} txs
   * @returns {Promise}
   */

  async removeBlock(block, txs) {
    const unlock = await this.locker.lock();
    try {
      return await this._removeBlock(block, txs);
    } finally {
      unlock();
    }
  }

  /**
   * Notify the mempool that a block
   * has been disconnected without a lock.
   * @method
   * @private
   * @param {ChainEntry} block
   * @param {TX[]} txs
   * @returns {Promise}
   */

  async _removeBlock(block, txs) {
    if (this.map.size === 0) {
      this.tip = block.prevBlock;
      return;
    }

    let total = 0;

    for (let i = 1; i < txs.length; i++) {
      const tx = txs[i];
      const hash = tx.hash('hex');

      if (this.hasEntry(hash))
        continue;

      try {
        await this.insertTX(tx, -1);
        total++;
      } catch (e) {
        this.emit('error', e);
        continue;
      }

      this.emit('unconfirmed', tx, block);
    }

    this.rejects.reset();

    this.cache.sync(block.prevBlock);

    await this.cache.flush();

    this.tip = block.prevBlock;

    if (total === 0)
      return;

    this.logger.debug(
      'Added %d txs back into the mempool for block %d.',
      total, block.height);
  }

  /**
   * Sanitize the mempool after a reorg.
   * @private
   * @returns {Promise}
   */

  async _handleReorg() {
    const height = this.chain.height + 1;
    const mtp = await this.chain.getMedianTime(this.chain.tip);
    const remove = [];

    for (const [hash, entry] of this.map) {
      const {tx} = entry;

      if (!tx.isFinal(height, mtp)) {
        remove.push(hash);
        continue;
      }

      if (tx.version > 1) {
        let hasLocks = false;

        for (const {sequence} of tx.inputs) {
          if (!(sequence & consensus.SEQUENCE_DISABLE_FLAG)) {
            hasLocks = true;
            break;
          }
        }

        if (hasLocks) {
          remove.push(hash);
          continue;
        }
      }

      if (entry.coinbase)
        remove.push(hash);
    }

    for (const hash of remove) {
      const entry = this.getEntry(hash);

      if (!entry)
        continue;

      this.evictEntry(entry);
    }
  }

  /**
   * Reset the mempool.
   * @method
   * @returns {Promise}
   */

  async reset() {
    const unlock = await this.locker.lock();
    try {
      return await this._reset();
    } finally {
      unlock();
    }
  }

  /**
   * Reset the mempool without a lock.
   * @private
   */

  async _reset() {
    this.logger.info('Mempool reset (%d txs removed).', this.map.size);

    this.size = 0;

    this.waiting.clear();
    this.orphans.clear();
    this.map.clear();
    this.spents.clear();
    this.coinIndex.reset();
    this.txIndex.reset();

    this.freeCount = 0;
    this.lastTime = 0;

    if (this.fees)
      this.fees.reset();

    this.rejects.reset();

    if (this.options.persistent) {
      await this.cache.wipe();
      this.cache.clear();
    }

    this.tip = this.chain.tip.hash;
  }

  /**
   * Ensure the size of the mempool stays below `maxSize`.
   * Evicts entries by timestamp and cumulative fee rate.
   * @param {MempoolEntry} added
   * @returns {Promise}
   */

  limitSize(added) {
    const maxSize = this.options.maxSize;

    if (this.size <= maxSize)
      return false;

    const threshold = maxSize - (maxSize / 10);
    const expiryTime = this.options.expiryTime;

    const now = util.now();
    let start = util.bench();
    const queue = new Heap(cmpRate);

    for (const entry of this.map.values()) {
      if (this.hasDepends(entry.tx))
        continue;

      if (now < entry.time + expiryTime) {
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
      util.bench(start));

    start = util.bench();

    this.logger.debug(
      '(bench) Heap mempool queue size: %d.',
      queue.size());

    while (queue.size() > 0) {
      const entry = queue.shift();
      const hash = entry.hash('hex');

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
      util.bench(start));

    return !this.hasEntry(added);
  }

  /**
   * Retrieve a transaction from the mempool.
   * @param {Hash} hash
   * @returns {TX}
   */

  getTX(hash) {
    const entry = this.map.get(hash);

    if (!entry)
      return null;

    return entry.tx;
  }

  /**
   * Retrieve a transaction from the mempool.
   * @param {Hash} hash
   * @returns {MempoolEntry}
   */

  getEntry(hash) {
    return this.map.get(hash);
  }

  /**
   * Retrieve a coin from the mempool (unspents only).
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Coin}
   */

  getCoin(hash, index) {
    const entry = this.map.get(hash);

    if (!entry)
      return null;

    if (this.isSpent(hash, index))
      return null;

    if (index >= entry.tx.outputs.length)
      return null;

    return Coin.fromTX(entry.tx, index, -1);
  }

  /**
   * Check to see if a coin has been spent. This differs from
   * {@link ChainDB#isSpent} in that it actually maintains a
   * map of spent coins, whereas ChainDB may return `true`
   * for transaction outputs that never existed.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Boolean}
   */

  isSpent(hash, index) {
    const key = Outpoint.toKey(hash, index);
    return this.spents.has(key);
  }

  /**
   * Get an output's spender entry.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {MempoolEntry}
   */

  getSpent(hash, index) {
    const key = Outpoint.toKey(hash, index);
    return this.spents.get(key);
  }

  /**
   * Get an output's spender transaction.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {MempoolEntry}
   */

  getSpentTX(hash, index) {
    const key = Outpoint.toKey(hash, index);
    const entry = this.spents.get(key);

    if (!entry)
      return null;

    return entry.tx;
  }

  /**
   * Find all coins pertaining to a certain address.
   * @param {Address[]} addrs
   * @returns {Coin[]}
   */

  getCoinsByAddress(addrs) {
    if (!Array.isArray(addrs))
      addrs = [addrs];

    const out = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr, 'hex');
      const coins = this.coinIndex.get(hash);

      for (const coin of coins)
        out.push(coin);
    }

    return out;
  }

  /**
   * Find all transactions pertaining to a certain address.
   * @param {Address[]} addrs
   * @returns {TX[]}
   */

  getTXByAddress(addrs) {
    if (!Array.isArray(addrs))
      addrs = [addrs];

    const out = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr, 'hex');
      const txs = this.txIndex.get(hash);

      for (const tx of txs)
        out.push(tx);
    }

    return out;
  }

  /**
   * Find all transactions pertaining to a certain address.
   * @param {Address[]} addrs
   * @returns {TXMeta[]}
   */

  getMetaByAddress(addrs) {
    if (!Array.isArray(addrs))
      addrs = [addrs];

    const out = [];

    for (const addr of addrs) {
      const hash = Address.getHash(addr, 'hex');
      const txs = this.txIndex.getMeta(hash);

      for (const tx of txs)
        out.push(tx);
    }

    return out;
  }

  /**
   * Retrieve a transaction from the mempool.
   * @param {Hash} hash
   * @returns {TXMeta}
   */

  getMeta(hash) {
    const entry = this.getEntry(hash);

    if (!entry)
      return null;

    const meta = TXMeta.fromTX(entry.tx);
    meta.mtime = entry.time;

    return meta;
  }

  /**
   * Test the mempool to see if it contains a transaction.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  hasEntry(hash) {
    return this.map.has(hash);
  }

  /**
   * Test the mempool to see if it
   * contains a transaction or an orphan.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  has(hash) {
    if (this.locker.has(hash))
      return true;

    if (this.hasOrphan(hash))
      return true;

    return this.hasEntry(hash);
  }

  /**
   * Test the mempool to see if it
   * contains a transaction or an orphan.
   * @private
   * @param {Hash} hash
   * @returns {Boolean}
   */

  exists(hash) {
    if (this.locker.pending(hash))
      return true;

    if (this.hasOrphan(hash))
      return true;

    return this.hasEntry(hash);
  }

  /**
   * Test the mempool to see if it
   * contains a recent reject.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  hasReject(hash) {
    return this.rejects.test(hash, 'hex');
  }

  /**
   * Add a transaction to the mempool. Note that this
   * will lock the mempool until the transaction is
   * fully processed.
   * @method
   * @param {TX} tx
   * @param {Number?} id
   * @returns {Promise}
   */

  async addTX(tx, id) {
    const hash = tx.hash('hex');
    const unlock = await this.locker.lock(hash);
    try {
      return await this._addTX(tx, id);
    } finally {
      unlock();
    }
  }

  /**
   * Add a transaction to the mempool without a lock.
   * @method
   * @private
   * @param {TX} tx
   * @param {Number?} id
   * @returns {Promise}
   */

  async _addTX(tx, id) {
    if (id == null)
      id = -1;

    let missing;
    try {
      missing = await this.insertTX(tx, id);
    } catch (err) {
      if (err.type === 'VerifyError') {
        if (!tx.hasWitness() && !err.malleated)
          this.rejects.add(tx.hash());
      }
      throw err;
    }

    if (util.now() - this.lastFlush > 10) {
      await this.cache.flush();
      this.lastFlush = util.now();
    }

    return missing;
  }

  /**
   * Add a transaction to the mempool without a lock.
   * @method
   * @private
   * @param {TX} tx
   * @param {Number?} id
   * @returns {Promise}
   */

  async insertTX(tx, id) {
    assert(!tx.mutable, 'Cannot add mutable TX to mempool.');

    const lockFlags = common.lockFlags.STANDARD_LOCKTIME_FLAGS;
    const height = this.chain.height;
    const hash = tx.hash('hex');

    // Basic sanity checks.
    // This is important because it ensures
    // other functions will be overflow safe.
    const [valid, reason, score] = tx.checkSanity();

    if (!valid)
      throw new VerifyError(tx, 'invalid', reason, score);

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
      const [valid, reason, score] = tx.checkStandard();

      if (!valid)
        throw new VerifyError(tx, 'nonstandard', reason, score);

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
    if (!await this.verifyFinal(tx, lockFlags)) {
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
    if (await this.chain.hasCoins(tx)) {
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
    const view = await this.getCoinView(tx);

    // Maybe store as an orphan.
    const missing = this.maybeOrphan(tx, view, id);

    // Return missing outpoint hashes.
    if (missing)
      return missing;

    // Create a new mempool entry
    // at current chain height.
    const entry = MempoolEntry.fromTX(tx, view, height);

    // Contextual verification.
    await this.verify(entry, view);

    // Add and index the entry.
    await this.addEntry(entry, view);

    // Trim size if we're too big.
    if (this.limitSize(hash)) {
      throw new VerifyError(tx,
        'insufficientfee',
        'mempool full',
        0);
    }

    return null;
  }

  /**
   * Verify a transaction with mempool standards.
   * @method
   * @param {TX} tx
   * @param {CoinView} view
   * @returns {Promise}
   */

  async verify(entry, view) {
    const height = this.chain.height + 1;
    const lockFlags = common.lockFlags.STANDARD_LOCKTIME_FLAGS;
    const tx = entry.tx;

    // Verify sequence locks.
    if (!await this.verifyLocks(tx, view, lockFlags)) {
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
    const minFee = policy.getMinFee(entry.size, this.options.minRelay);

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
      const now = util.now();

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
    const [fee, reason, score] = tx.checkInputs(view, height);

    if (fee === -1)
      throw new VerifyError(tx, 'invalid', reason, score);

    // Script verification.
    let flags = Script.flags.STANDARD_VERIFY_FLAGS;
    try {
      await this.verifyInputs(tx, view, flags);
    } catch (err) {
      if (tx.hasWitness())
        throw err;

      // Try without segwit and cleanstack.
      flags &= ~Script.flags.VERIFY_WITNESS;
      flags &= ~Script.flags.VERIFY_CLEANSTACK;

      // If it failed, the first verification
      // was the only result we needed.
      if (!await this.verifyResult(tx, view, flags))
        throw err;

      // If it succeeded, segwit may be causing the
      // failure. Try with segwit but without cleanstack.
      flags |= Script.flags.VERIFY_CLEANSTACK;

      // Cleanstack was causing the failure.
      if (await this.verifyResult(tx, view, flags))
        throw err;

      // Do not insert into reject cache.
      err.malleated = true;
      throw err;
    }

    // Paranoid checks.
    if (this.options.paranoidChecks) {
      const flags = Script.flags.MANDATORY_VERIFY_FLAGS;
      assert(await this.verifyResult(tx, view, flags),
        'BUG: Verify failed for mandatory but not standard.');
    }
  }

  /**
   * Verify inputs, return a boolean
   * instead of an error based on success.
   * @method
   * @param {TX} tx
   * @param {CoinView} view
   * @param {VerifyFlags} flags
   * @returns {Promise}
   */

  async verifyResult(tx, view, flags) {
    try {
      await this.verifyInputs(tx, view, flags);
    } catch (err) {
      if (err.type === 'VerifyError')
        return false;
      throw err;
    }
    return true;
  }

  /**
   * Verify inputs for standard
   * _and_ mandatory flags on failure.
   * @method
   * @param {TX} tx
   * @param {CoinView} view
   * @param {VerifyFlags} flags
   * @returns {Promise}
   */

  async verifyInputs(tx, view, flags) {
    if (await tx.verifyAsync(view, flags, this.workers))
      return;

    if (flags & Script.flags.ONLY_STANDARD_VERIFY_FLAGS) {
      flags &= ~Script.flags.ONLY_STANDARD_VERIFY_FLAGS;

      if (await tx.verifyAsync(view, flags, this.workers)) {
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
  }

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

  async addEntry(entry, view) {
    const tx = entry.tx;

    this.trackEntry(entry, view);

    this.updateAncestors(entry, addFee);

    this.emit('tx', tx, view);
    this.emit('add entry', entry);

    if (this.fees)
      this.fees.processTX(entry, this.chain.synced);

    this.logger.debug(
      'Added %s to mempool (txs=%d).',
      tx.txid(), this.map.size);

    this.cache.save(entry);

    await this.handleOrphans(tx);
  }

  /**
   * Remove a transaction from the mempool.
   * Generally only called when a new block
   * is added to the main chain.
   * @param {MempoolEntry} entry
   */

  removeEntry(entry) {
    const tx = entry.tx;
    const hash = tx.hash('hex');

    this.untrackEntry(entry);

    if (this.fees)
      this.fees.removeTX(hash);

    this.cache.remove(tx.hash());

    this.emit('remove entry', entry);
  }

  /**
   * Remove a transaction from the mempool.
   * Recursively remove its spenders.
   * @param {MempoolEntry} entry
   */

  evictEntry(entry) {
    this.removeSpenders(entry);
    this.updateAncestors(entry, removeFee);
    this.removeEntry(entry);
  }

  /**
   * Recursively remove spenders of a transaction.
   * @private
   * @param {MempoolEntry} entry
   */

  removeSpenders(entry) {
    const tx = entry.tx;
    const hash = tx.hash('hex');

    for (let i = 0; i < tx.outputs.length; i++) {
      const spender = this.getSpent(hash, i);

      if (!spender)
        continue;

      this.removeSpenders(spender);
      this.removeEntry(spender);
    }
  }

  /**
   * Count the highest number of
   * ancestors a transaction may have.
   * @param {MempoolEntry} entry
   * @returns {Number}
   */

  countAncestors(entry) {
    return this._countAncestors(entry, new Set(), entry, nop);
  }

  /**
   * Count the highest number of
   * ancestors a transaction may have.
   * Update descendant fees and size.
   * @param {MempoolEntry} entry
   * @param {Function} map
   * @returns {Number}
   */

  updateAncestors(entry, map) {
    return this._countAncestors(entry, new Set(), entry, map);
  }

  /**
   * Traverse ancestors and count.
   * @private
   * @param {MempoolEntry} entry
   * @param {Object} set
   * @param {MempoolEntry} child
   * @param {Function} map
   * @returns {Number}
   */

  _countAncestors(entry, set, child, map) {
    const tx = entry.tx;

    for (const {prevout} of tx.inputs) {
      const hash = prevout.hash;
      const parent = this.getEntry(hash);

      if (!parent)
        continue;

      if (set.has(hash))
        continue;

      set.add(hash);

      map(parent, child);

      if (set.size > this.options.maxAncestors)
        break;

      this._countAncestors(parent, set, child, map);

      if (set.size > this.options.maxAncestors)
        break;
    }

    return set.size;
  }

  /**
   * Count the highest number of
   * descendants a transaction may have.
   * @param {MempoolEntry} entry
   * @returns {Number}
   */

  countDescendants(entry) {
    return this._countDescendants(entry, new Set());
  }

  /**
   * Count the highest number of
   * descendants a transaction may have.
   * @private
   * @param {MempoolEntry} entry
   * @param {Object} set
   * @returns {Number}
   */

  _countDescendants(entry, set) {
    const tx = entry.tx;
    const hash = tx.hash('hex');

    for (let i = 0; i < tx.outputs.length; i++) {
      const child = this.getSpent(hash, i);

      if (!child)
        continue;

      const next = child.hash('hex');

      if (set.has(next))
        continue;

      set.add(next);

      this._countDescendants(child, set);
    }

    return set.size;
  }

  /**
   * Get all transaction ancestors.
   * @param {MempoolEntry} entry
   * @returns {MempoolEntry[]}
   */

  getAncestors(entry) {
    return this._getAncestors(entry, [], new Set());
  }

  /**
   * Get all transaction ancestors.
   * @private
   * @param {MempoolEntry} entry
   * @param {MempoolEntry[]} entries
   * @param {Object} set
   * @returns {MempoolEntry[]}
   */

  _getAncestors(entry, entries, set) {
    const tx = entry.tx;

    for (const {prevout} of tx.inputs) {
      const hash = prevout.hash;
      const parent = this.getEntry(hash);

      if (!parent)
        continue;

      if (set.has(hash))
        continue;

      set.add(hash);
      entries.push(parent);

      this._getAncestors(parent, entries, set);
    }

    return entries;
  }

  /**
   * Get all a transaction descendants.
   * @param {MempoolEntry} entry
   * @returns {MempoolEntry[]}
   */

  getDescendants(entry) {
    return this._getDescendants(entry, [], new Set());
  }

  /**
   * Get all a transaction descendants.
   * @param {MempoolEntry} entry
   * @param {MempoolEntry[]} entries
   * @param {Object} set
   * @returns {MempoolEntry[]}
   */

  _getDescendants(entry, entries, set) {
    const tx = entry.tx;
    const hash = tx.hash('hex');

    for (let i = 0; i < tx.outputs.length; i++) {
      const child = this.getSpent(hash, i);

      if (!child)
        continue;

      const next = child.hash('hex');

      if (set.has(next))
        continue;

      set.add(next);
      entries.push(child);

      this._getDescendants(child, entries, set);
    }

    return entries;
  }

  /**
   * Find a unconfirmed transactions that
   * this transaction depends on.
   * @param {TX} tx
   * @returns {Hash[]}
   */

  getDepends(tx) {
    const prevout = tx.getPrevout();
    const depends = [];

    for (const hash of prevout) {
      if (this.hasEntry(hash))
        depends.push(hash);
    }

    return depends;
  }

  /**
   * Test whether a transaction has dependencies.
   * @param {TX} tx
   * @returns {Boolean}
   */

  hasDepends(tx) {
    for (const {prevout} of tx.inputs) {
      if (this.hasEntry(prevout.hash))
        return true;
    }
    return false;
  }

  /**
   * Return the full balance of all unspents in the mempool
   * (not very useful in practice, only used for testing).
   * @returns {Amount}
   */

  getBalance() {
    let total = 0;

    for (const [hash, entry] of this.map) {
      const tx = entry.tx;
      for (let i = 0; i < tx.outputs.length; i++) {
        const coin = this.getCoin(hash, i);
        if (coin)
          total += coin.value;
      }
    }

    return total;
  }

  /**
   * Retrieve _all_ transactions from the mempool.
   * @returns {TX[]}
   */

  getHistory() {
    const txs = [];

    for (const entry of this.map.values())
      txs.push(entry.tx);

    return txs;
  }

  /**
   * Retrieve an orphan transaction.
   * @param {Hash} hash
   * @returns {TX}
   */

  getOrphan(hash) {
    return this.orphans.get(hash);
  }

  /**
   * @param {Hash} hash
   * @returns {Boolean}
   */

  hasOrphan(hash) {
    return this.orphans.has(hash);
  }

  /**
   * Maybe store an orphaned transaction.
   * @param {TX} tx
   * @param {CoinView} view
   * @param {Number} id
   */

  maybeOrphan(tx, view, id) {
    const hashes = new Set();
    const missing = [];

    for (const {prevout} of tx.inputs) {
      if (view.hasEntry(prevout))
        continue;

      if (this.hasReject(prevout.hash)) {
        this.logger.debug(
          'Not storing orphan %s (rejected parents).',
          tx.txid());
        this.rejects.add(tx.hash());
        return missing;
      }

      if (this.hasEntry(prevout.hash)) {
        this.logger.debug(
          'Not storing orphan %s (non-existent output).',
          tx.txid());
        this.rejects.add(tx.hash());
        return missing;
      }

      hashes.add(prevout.hash);
    }

    // Not an orphan.
    if (hashes.size === 0)
      return null;

    // Weight limit for orphans.
    if (tx.getWeight() > policy.MAX_TX_WEIGHT) {
      this.logger.debug('Ignoring large orphan: %s', tx.txid());
      if (!tx.hasWitness())
        this.rejects.add(tx.hash());
      return missing;
    }

    if (this.options.maxOrphans === 0)
      return missing;

    this.limitOrphans();

    const hash = tx.hash('hex');

    for (const prev of hashes.keys()) {
      if (!this.waiting.has(prev))
        this.waiting.set(prev, new Set());

      this.waiting.get(prev).add(hash);

      missing.push(prev);
    }

    this.orphans.set(hash, new Orphan(tx, missing.length, id));

    this.logger.debug('Added orphan %s to mempool.', tx.txid());

    this.emit('add orphan', tx);

    return missing;
  }

  /**
   * Resolve orphans and attempt to add to mempool.
   * @method
   * @param {TX} parent
   * @returns {Promise} - Returns {@link TX}[].
   */

  async handleOrphans(parent) {
    const resolved = this.resolveOrphans(parent);

    for (const orphan of resolved) {
      let tx, missing;

      try {
        tx = orphan.toTX();
      } catch (e) {
        this.logger.warning('%s %s',
          'Warning: possible memory corruption.',
          'Orphan failed deserialization.');
        continue;
      }

      try {
        missing = await this.insertTX(tx, orphan.id);
      } catch (err) {
        if (err.type === 'VerifyError') {
          this.logger.debug(
            'Could not resolve orphan %s: %s.',
            tx.txid(), err.message);

          if (!tx.hasWitness() && !err.malleated)
            this.rejects.add(tx.hash());

          this.emit('bad orphan', err, orphan.id);

          continue;
        }
        throw err;
      }

      // Can happen if an existing parent is
      // evicted in the interim between fetching
      // the non-present parents.
      if (missing && missing.length > 0) {
        this.logger.debug(
          'Transaction %s was double-orphaned in mempool.',
          tx.txid());
        this.removeOrphan(tx.hash('hex'));
        continue;
      }

      this.logger.debug('Resolved orphan %s in mempool.', tx.txid());
    }
  }

  /**
   * Potentially resolve any transactions
   * that redeem the passed-in transaction.
   * Deletes all orphan entries and
   * returns orphan objects.
   * @param {TX} parent
   * @returns {Orphan[]}
   */

  resolveOrphans(parent) {
    const hash = parent.hash('hex');
    const set = this.waiting.get(hash);

    if (!set)
      return [];

    assert(set.size > 0);

    const resolved = [];

    for (const hash of set.keys()) {
      const orphan = this.getOrphan(hash);

      assert(orphan);

      if (--orphan.missing === 0) {
        this.orphans.delete(hash);
        resolved.push(orphan);
      }
    }

    this.waiting.delete(hash);

    return resolved;
  }

  /**
   * Remove a transaction from the mempool.
   * @param {Hash} tx
   * @returns {Boolean}
   */

  removeOrphan(hash) {
    const orphan = this.getOrphan(hash);

    if (!orphan)
      return false;

    let tx;
    try {
      tx = orphan.toTX();
    } catch (e) {
      this.orphans.delete(hash);
      this.logger.warning('%s %s',
        'Warning: possible memory corruption.',
        'Orphan failed deserialization.');
      return false;
    }

    for (const prev of tx.getPrevout()) {
      const set = this.waiting.get(prev);

      if (!set)
        continue;

      assert(set.has(hash));

      set.delete(hash);

      if (set.size === 0)
        this.waiting.delete(prev);
    }

    this.orphans.delete(hash);

    this.emit('remove orphan', tx);

    return true;
  }

  /**
   * Remove a random orphan transaction from the mempool.
   * @returns {Boolean}
   */

  limitOrphans() {
    if (this.orphans.size < this.options.maxOrphans)
      return false;

    let index = random.randomRange(0, this.orphans.size);

    let hash;
    for (hash of this.orphans.keys()) {
      if (index === 0)
        break;
      index--;
    }

    assert(hash);

    this.logger.debug('Removing orphan %s from mempool.',
      util.revHex(hash));

    this.removeOrphan(hash);

    return true;
  }

  /**
   * Test all of a transactions outpoints to see if they are doublespends.
   * Note that this will only test against the mempool spents, not the
   * blockchain's. The blockchain spents are not checked against because
   * the blockchain does not maintain a spent list. The transaction will
   * be seen as an orphan rather than a double spend.
   * @param {TX} tx
   * @returns {Promise} - Returns Boolean.
   */

  isDoubleSpend(tx) {
    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      if (this.isSpent(hash, index))
        return true;
    }

    return false;
  }

  /**
   * Get coin viewpoint (lock).
   * @method
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getSpentView(tx) {
    const unlock = await this.locker.lock();
    try {
      return await this.getCoinView(tx);
    } finally {
      unlock();
    }
  }

  /**
   * Get coin viewpoint (no lock).
   * @method
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getCoinView(tx) {
    const view = new CoinView();

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      const tx = this.getTX(hash);

      if (tx) {
        if (index < tx.outputs.length)
          view.addIndex(tx, index, -1);
        continue;
      }

      const coin = await this.chain.readCoin(prevout);

      if (coin)
        view.addEntry(prevout, coin);
    }

    return view;
  }

  /**
   * Get a snapshot of all transaction hashes in the mempool. Used
   * for generating INV packets in response to MEMPOOL packets.
   * @returns {Hash[]}
   */

  getSnapshot() {
    const keys = [];

    for (const hash of this.map.keys())
      keys.push(hash);

    return keys;
  }

  /**
   * Check sequence locks on a transaction against the current tip.
   * @param {TX} tx
   * @param {CoinView} view
   * @param {LockFlags} flags
   * @returns {Promise} - Returns Boolean.
   */

  verifyLocks(tx, view, flags) {
    return this.chain.verifyLocks(this.chain.tip, tx, view, flags);
  }

  /**
   * Check locktime on a transaction against the current tip.
   * @param {TX} tx
   * @param {LockFlags} flags
   * @returns {Promise} - Returns Boolean.
   */

  verifyFinal(tx, flags) {
    return this.chain.verifyFinal(this.chain.tip, tx, flags);
  }

  /**
   * Map a transaction to the mempool.
   * @private
   * @param {MempoolEntry} entry
   * @param {CoinView} view
   */

  trackEntry(entry, view) {
    const tx = entry.tx;
    const hash = tx.hash('hex');

    assert(!this.map.has(hash));
    this.map.set(hash, entry);

    assert(!tx.isCoinbase());

    for (const {prevout} of tx.inputs) {
      const key = prevout.toKey();
      this.spents.set(key, entry);
    }

    if (this.options.indexAddress && view)
      this.indexEntry(entry, view);

    this.size += entry.memUsage();
  }

  /**
   * Unmap a transaction from the mempool.
   * @private
   * @param {MempoolEntry} entry
   */

  untrackEntry(entry) {
    const tx = entry.tx;
    const hash = tx.hash('hex');

    assert(this.map.has(hash));
    this.map.delete(hash);

    assert(!tx.isCoinbase());

    for (const {prevout} of tx.inputs) {
      const key = prevout.toKey();
      this.spents.delete(key);
    }

    if (this.options.indexAddress)
      this.unindexEntry(entry);

    this.size -= entry.memUsage();
  }

  /**
   * Index an entry by address.
   * @private
   * @param {MempoolEntry} entry
   * @param {CoinView} view
   */

  indexEntry(entry, view) {
    const tx = entry.tx;

    this.txIndex.insert(entry, view);

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      this.coinIndex.remove(hash, index);
    }

    for (let i = 0; i < tx.outputs.length; i++)
      this.coinIndex.insert(tx, i);
  }

  /**
   * Unindex an entry by address.
   * @private
   * @param {MempoolEntry} entry
   */

  unindexEntry(entry) {
    const tx = entry.tx;
    const hash = tx.hash('hex');

    this.txIndex.remove(hash);

    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      const prev = this.getTX(hash);

      if (!prev)
        continue;

      this.coinIndex.insert(prev, index);
    }

    for (let i = 0; i < tx.outputs.length; i++)
      this.coinIndex.remove(hash, i);
  }

  /**
   * Recursively remove double spenders
   * of a mined transaction's outpoints.
   * @private
   * @param {TX} tx
   */

  removeDoubleSpends(tx) {
    for (const {prevout} of tx.inputs) {
      const {hash, index} = prevout;
      const spent = this.getSpent(hash, index);

      if (!spent)
        continue;

      this.logger.debug(
        'Removing double spender from mempool: %s.',
        spent.txid());

      this.evictEntry(spent);

      this.emit('double spend', spent);
    }
  }

  /**
   * Calculate the memory usage of the entire mempool.
   * @see DynamicMemoryUsage()
   * @returns {Number} Usage in bytes.
   */

  getSize() {
    return this.size;
  }

  /**
   * Prioritise transaction.
   * @param {MempoolEntry} entry
   * @param {Number} pri
   * @param {Amount} fee
   */

  prioritise(entry, pri, fee) {
    if (-pri > entry.priority)
      pri = -entry.priority;

    entry.priority += pri;

    if (-fee > entry.deltaFee)
      fee = -entry.deltaFee;

    if (fee === 0)
      return;

    this.updateAncestors(entry, prePrioritise);

    entry.deltaFee += fee;
    entry.descFee += fee;

    this.updateAncestors(entry, postPrioritise);
  }
}

/**
 * Mempool Options
 * @alias module:mempool.MempoolOptions
 */

class MempoolOptions {
  /**
   * Create mempool options.
   * @constructor
   * @param {Object}
   */

  constructor(options) {
    this.network = Network.primary;
    this.chain = null;
    this.logger = null;
    this.workers = null;
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
    this.memory = true;
    this.maxFiles = 64;
    this.cacheSize = 32 << 20;
    this.compression = true;

    this.persistent = false;

    this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {MempoolOptions}
   */

  fromOptions(options) {
    assert(options, 'Mempool requires options.');
    assert(options.chain && typeof options.chain === 'object',
      'Mempool requires a blockchain.');

    this.chain = options.chain;
    this.network = options.chain.network;
    this.logger = options.chain.logger;
    this.workers = options.chain.workers;

    this.requireStandard = this.network.requireStandard;
    this.minRelay = this.network.minRelay;

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.workers != null) {
      assert(typeof options.workers === 'object');
      this.workers = options.workers;
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
      assert((options.limitFreeRelay >>> 0) === options.limitFreeRelay);
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
      assert((options.maxSize >>> 0) === options.maxSize);
      this.maxSize = options.maxSize;
    }

    if (options.maxOrphans != null) {
      assert((options.maxOrphans >>> 0) === options.maxOrphans);
      this.maxOrphans = options.maxOrphans;
    }

    if (options.maxAncestors != null) {
      assert((options.maxAncestors >>> 0) === options.maxAncestors);
      this.maxAncestors = options.maxAncestors;
    }

    if (options.expiryTime != null) {
      assert((options.expiryTime >>> 0) === options.expiryTime);
      this.expiryTime = options.expiryTime;
    }

    if (options.minRelay != null) {
      assert((options.minRelay >>> 0) === options.minRelay);
      this.minRelay = options.minRelay;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.location = path.join(this.prefix, 'mempool');
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
      assert(Number.isSafeInteger(options.cacheSize));
      assert(options.cacheSize >= 0);
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

    if (options.indexAddress != null) {
      assert(typeof options.indexAddress === 'boolean');
      this.indexAddress = options.indexAddress;
    }

    return this;
  }

  /**
   * Instantiate mempool options from object.
   * @param {Object} options
   * @returns {MempoolOptions}
   */

  static fromOptions(options) {
    return new MempoolOptions().fromOptions(options);
  }
}

/**
 * TX Address Index
 * @ignore
 */

class TXIndex {
  /**
   * Create TX address index.
   * @constructor
   */

  constructor() {
    // Map of addr->entries.
    this.index = new Map();

    // Map of txid->addrs.
    this.map = new Map();
  }

  reset() {
    this.index.clear();
    this.map.clear();
  }

  get(addr) {
    const items = this.index.get(addr);

    if (!items)
      return [];

    const out = [];

    for (const entry of items.values())
      out.push(entry.tx);

    return out;
  }

  getMeta(addr) {
    const items = this.index.get(addr);

    if (!items)
      return [];

    const out = [];

    for (const entry of items.values()) {
      const meta = TXMeta.fromTX(entry.tx);
      meta.mtime = entry.time;
      out.push(meta);
    }

    return out;
  }

  insert(entry, view) {
    const tx = entry.tx;
    const hash = tx.hash('hex');
    const addrs = tx.getHashes(view, 'hex');

    if (addrs.length === 0)
      return;

    for (const addr of addrs) {
      let items = this.index.get(addr);

      if (!items) {
        items = new Map();
        this.index.set(addr, items);
      }

      assert(!items.has(hash));
      items.set(hash, entry);
    }

    this.map.set(hash, addrs);
  }

  remove(hash) {
    const addrs = this.map.get(hash);

    if (!addrs)
      return;

    for (const addr of addrs) {
      const items = this.index.get(addr);

      assert(items);
      assert(items.has(hash));

      items.delete(hash);

      if (items.size === 0)
        this.index.delete(addr);
    }

    this.map.delete(hash);
  }
}

/**
 * Coin Address Index
 * @ignore
 */

class CoinIndex {
  /**
   * Create coin address index.
   * @constructor
   */

  constructor() {
    // Map of addr->coins.
    this.index = new Map();

    // Map of outpoint->addr.
    this.map = new Map();
  }

  reset() {
    this.index.clear();
    this.map.clear();
  }

  get(addr) {
    const items = this.index.get(addr);

    if (!items)
      return [];

    const out = [];

    for (const coin of items.values())
      out.push(coin.toCoin());

    return out;
  }

  insert(tx, index) {
    const output = tx.outputs[index];
    const hash = tx.hash('hex');
    const addr = output.getHash('hex');

    if (!addr)
      return;

    let items = this.index.get(addr);

    if (!items) {
      items = new Map();
      this.index.set(addr, items);
    }

    const key = Outpoint.toKey(hash, index);

    assert(!items.has(key));
    items.set(key, new IndexedCoin(tx, index));

    this.map.set(key, addr);
  }

  remove(hash, index) {
    const key = Outpoint.toKey(hash, index);
    const addr = this.map.get(key);

    if (!addr)
      return;

    const items = this.index.get(addr);

    assert(items);
    assert(items.has(key));
    items.delete(key);

    if (items.size === 0)
      this.index.delete(addr);

    this.map.delete(key);
  }
}

/**
 * Indexed Coin
 * @ignore
 */

class IndexedCoin {
  /**
   * Create an indexed coin.
   * @constructor
   * @param {TX} tx
   * @param {Number} index
   */

  constructor(tx, index) {
    this.tx = tx;
    this.index = index;
  }

  toCoin() {
    return Coin.fromTX(this.tx, this.index, -1);
  }
}

/**
 * Orphan
 * @ignore
 */

class Orphan {
  /**
   * Create an orphan.
   * @constructor
   * @param {TX} tx
   * @param {Hash[]} missing
   * @param {Number} id
   */

  constructor(tx, missing, id) {
    this.raw = tx.toRaw();
    this.missing = missing;
    this.id = id;
  }

  toTX() {
    return TX.fromRaw(this.raw);
  }
}

/**
 * Mempool Cache
 * @ignore
 */

class MempoolCache {
  /**
   * Create a mempool cache.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.logger = options.logger;
    this.chain = options.chain;
    this.network = options.network;
    this.db = null;
    this.batch = null;

    if (options.persistent)
      this.db = bdb.create(options);
  }

  async getVersion() {
    const data = await this.db.get(layout.v.build());

    if (!data)
      return -1;

    return data.readUInt32LE(0, true);
  }

  async getTip() {
    const hash = await this.db.get(layout.R.build());

    if (!hash)
      return null;

    return hash.toString('hex');
  }

  async getFees() {
    const data = await this.db.get(layout.F.build());

    if (!data)
      return null;

    let fees = null;

    try {
      fees = Fees.fromRaw(data);
    } catch (e) {
      this.logger.warning(
        'Fee data failed deserialization: %s.',
        e.message);
    }

    return fees;
  }

  getEntries() {
    return this.db.values({
      gte: layout.e.min(),
      lte: layout.e.max(),
      parse: data => MempoolEntry.fromRaw(data)
    });
  }

  getKeys() {
    return this.db.keys({
      gte: layout.e.min(),
      lte: layout.e.max()
    });
  }

  async open() {
    if (!this.db)
      return;

    await this.db.open();
    await this.db.verify(layout.V.build(), 'mempool', 0);

    await this.verify();

    this.batch = this.db.batch();
  }

  async close() {
    if (!this.db)
      return;

    await this.db.close();

    this.batch = null;
  }

  save(entry) {
    if (!this.db)
      return;

    this.batch.put(layout.e.build(entry.hash()), entry.toRaw());
  }

  remove(hash) {
    if (!this.db)
      return;

    this.batch.del(layout.e.build(hash));
  }

  sync(tip) {
    if (!this.db)
      return;

    this.batch.put(layout.R.build(), Buffer.from(tip, 'hex'));
  }

  writeFees(fees) {
    if (!this.db)
      return;

    this.batch.put(layout.F.build(), fees.toRaw());
  }

  clear() {
    this.batch.clear();
    this.batch = this.db.batch();
  }

  async flush() {
    if (!this.db)
      return;

    await this.batch.write();

    this.batch = this.db.batch();
  }

  async init(hash) {
    const batch = this.db.batch();
    batch.put(layout.v.build(), fromU32(MempoolCache.VERSION));
    batch.put(layout.R.build(), Buffer.from(hash, 'hex'));
    await batch.write();
  }

  async verify() {
    let version = await this.getVersion();
    let tip;

    if (version === -1) {
      version = MempoolCache.VERSION;
      tip = this.chain.tip.hash;

      this.logger.info(
        'Mempool cache is empty. Writing tip %s.',
        util.revHex(tip));

      await this.init(tip);
    }

    if (version !== MempoolCache.VERSION) {
      this.logger.warning(
        'Mempool cache version mismatch (%d != %d)!',
        version,
        MempoolCache.VERSION);
      this.logger.warning('Invalidating mempool cache.');
      await this.wipe();
      return false;
    }

    tip = await this.getTip();

    if (tip !== this.chain.tip.hash) {
      this.logger.warning(
        'Mempool tip not consistent with chain tip (%s != %s)!',
        util.revHex(tip),
        this.chain.tip.rhash());
      this.logger.warning('Invalidating mempool cache.');
      await this.wipe();
      return false;
    }

    return true;
  }

  async wipe() {
    const batch = this.db.batch();
    const keys = await this.getKeys();

    for (const key of keys)
      batch.del(key);

    batch.put(layout.v.build(), fromU32(MempoolCache.VERSION));
    batch.put(layout.R.build(), Buffer.from(this.chain.tip.hash, 'hex'));
    batch.del(layout.F.build());

    await batch.write();

    this.logger.info('Removed %d mempool entries from disk.', keys.length);
  }
}

MempoolCache.VERSION = 2;

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

function prePrioritise(parent, child) {
  parent.descFee -= child.deltaFee;
}

function postPrioritise(parent, child) {
  parent.descFee += child.deltaFee;
}

function cmpRate(a, b) {
  let xf = a.deltaFee;
  let xs = a.size;
  let yf = b.deltaFee;
  let ys = b.size;
  let x, y;

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
    x = a.time;
    y = b.time;
  }

  return x - y;
}

function useDesc(a) {
  const x = a.deltaFee * a.descSize;
  const y = a.descFee * a.size;
  return y > x;
}

function fromU32(num) {
  const data = Buffer.allocUnsafe(4);
  data.writeUInt32LE(num, 0, true);
  return data;
}

/*
 * Expose
 */

module.exports = Mempool;
