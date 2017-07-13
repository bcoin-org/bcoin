/*!
 * txdb.js - persistent transaction pool
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const LRU = require('../utils/lru');
const assert = require('assert');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const Amount = require('../btc/amount');
const CoinView = require('../coins/coinview');
const Coin = require('../primitives/coin');
const Outpoint = require('../primitives/outpoint');
const records = require('./records');
const layout = require('./layout').txdb;
const encoding = require('../utils/encoding');
const policy = require('../protocol/policy');
const Script = require('../script/script');
const BlockMapRecord = records.BlockMapRecord;
const OutpointMapRecord = records.OutpointMapRecord;
const TXRecord = records.TXRecord;

/**
 * TXDB
 * @alias module:wallet.TXDB
 * @constructor
 * @param {Wallet} wallet
 */

function TXDB(wallet) {
  if (!(this instanceof TXDB))
    return new TXDB(wallet);

  this.wallet = wallet;
  this.walletdb = wallet.db;
  this.db = wallet.db.db;
  this.logger = wallet.db.logger;
  this.network = wallet.db.network;
  this.options = wallet.db.options;
  this.coinCache = new LRU(10000);

  this.locked = new Set();
  this.state = null;
  this.pending = null;
  this.events = [];
}

/**
 * Database layout.
 * @type {Object}
 */

TXDB.layout = layout;

/**
 * Open TXDB.
 * @returns {Promise}
 */

TXDB.prototype.open = async function open() {
  let state = await this.getState();

  if (state) {
    this.state = state;
    this.logger.info('TXDB loaded for %s.', this.wallet.id);
  } else {
    this.state = new TXDBState(this.wallet.wid, this.wallet.id);
    this.logger.info('TXDB created for %s.', this.wallet.id);
  }

  this.logger.info('TXDB State: tx=%d coin=%s.',
    this.state.tx, this.state.coin);

  this.logger.info(
    'Balance: unconfirmed=%s confirmed=%s.',
    Amount.btc(this.state.unconfirmed),
    Amount.btc(this.state.confirmed));
};

/**
 * Start batch.
 * @private
 */

TXDB.prototype.start = function start() {
  this.pending = this.state.clone();
  this.coinCache.start();
  return this.wallet.start();
};

/**
 * Drop batch.
 * @private
 */

TXDB.prototype.drop = function drop() {
  this.pending = null;
  this.events.length = 0;
  this.coinCache.drop();
  return this.wallet.drop();
};

/**
 * Clear batch.
 * @private
 */

TXDB.prototype.clear = function clear() {
  this.pending = this.state.clone();
  this.events.length = 0;
  this.coinCache.clear();
  return this.wallet.clear();
};

/**
 * Save batch.
 * @returns {Promise}
 */

TXDB.prototype.commit = async function commit() {
  try {
    await this.wallet.commit();
  } catch (e) {
    this.pending = null;
    this.events.length = 0;
    this.coinCache.drop();
    throw e;
  }

  // Overwrite the entire state
  // with our new committed state.
  if (this.pending.committed) {
    this.state = this.pending;

    // Emit buffered events now that
    // we know everything is written.
    for (let [event, data, details] of this.events) {
      this.walletdb.emit(event, this.wallet.id, data, details);
      this.wallet.emit(event, data, details);
    }
  }

  this.pending = null;
  this.events.length = 0;
  this.coinCache.commit();
};

/**
 * Emit transaction event.
 * @private
 * @param {String} event
 * @param {Object} data
 * @param {Details} details
 */

TXDB.prototype.emit = function emit(event, data, details) {
  this.events.push([event, data, details]);
};

/**
 * Prefix a key.
 * @param {Buffer} key
 * @returns {Buffer} Prefixed key.
 */

TXDB.prototype.prefix = function prefix(key) {
  assert(this.wallet.wid);
  return layout.prefix(this.wallet.wid, key);
};

/**
 * Put key and value to current batch.
 * @param {String} key
 * @param {Buffer} value
 */

TXDB.prototype.put = function put(key, value) {
  assert(this.wallet.current);
  this.wallet.current.put(this.prefix(key), value);
};

/**
 * Delete key from current batch.
 * @param {String} key
 */

TXDB.prototype.del = function del(key) {
  assert(this.wallet.current);
  this.wallet.current.del(this.prefix(key));
};

/**
 * Get.
 * @param {String} key
 */

TXDB.prototype.get = function get(key) {
  return this.db.get(this.prefix(key));
};

/**
 * Has.
 * @param {String} key
 */

TXDB.prototype.has = function has(key) {
  return this.db.has(this.prefix(key));
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.range = function range(options) {
  if (options.gte)
    options.gte = this.prefix(options.gte);
  if (options.lte)
    options.lte = this.prefix(options.lte);
  return this.db.range(options);
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.keys = function keys(options) {
  if (options.gte)
    options.gte = this.prefix(options.gte);
  if (options.lte)
    options.lte = this.prefix(options.lte);
  return this.db.keys(options);
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.values = function values(options) {
  if (options.gte)
    options.gte = this.prefix(options.gte);
  if (options.lte)
    options.lte = this.prefix(options.lte);
  return this.db.values(options);
};

/**
 * Get wallet path for output.
 * @param {Output} output
 * @returns {Promise} - Returns {@link Path}.
 */

TXDB.prototype.getPath = function getPath(output) {
  let addr = output.getAddress();

  if (!addr)
    return Promise.resolve();

  return this.wallet.getPath(addr);
};

/**
 * Test whether path exists for output.
 * @param {Output} output
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasPath = function hasPath(output) {
  let addr = output.getAddress();

  if (!addr)
    return Promise.resolve(false);

  return this.wallet.hasPath(addr);
};

/**
 * Save credit.
 * @param {Credit} credit
 * @param {Path} path
 */

TXDB.prototype.saveCredit = async function saveCredit(credit, path) {
  let coin = credit.coin;
  let key = coin.toKey();
  let raw = credit.toRaw();

  await this.addOutpointMap(coin.hash, coin.index);

  this.put(layout.c(coin.hash, coin.index), raw);
  this.put(layout.C(path.account, coin.hash, coin.index), null);

  this.coinCache.push(key, raw);
};

/**
 * Remove credit.
 * @param {Credit} credit
 * @param {Path} path
 */

TXDB.prototype.removeCredit = async function removeCredit(credit, path) {
  let coin = credit.coin;
  let key = coin.toKey();

  await this.removeOutpointMap(coin.hash, coin.index);

  this.del(layout.c(coin.hash, coin.index));
  this.del(layout.C(path.account, coin.hash, coin.index));

  this.coinCache.unpush(key);
};

/**
 * Spend credit.
 * @param {Credit} credit
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.spendCredit = function spendCredit(credit, tx, index) {
  let prevout = tx.inputs[index].prevout;
  let spender = Outpoint.fromTX(tx, index);
  this.put(layout.s(prevout.hash, prevout.index), spender.toRaw());
  this.put(layout.d(spender.hash, spender.index), credit.coin.toRaw());
};

/**
 * Unspend credit.
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.unspendCredit = function unspendCredit(tx, index) {
  let prevout = tx.inputs[index].prevout;
  let spender = Outpoint.fromTX(tx, index);
  this.del(layout.s(prevout.hash, prevout.index));
  this.del(layout.d(spender.hash, spender.index));
};

/**
 * Write input record.
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.writeInput = function writeInput(tx, index) {
  let prevout = tx.inputs[index].prevout;
  let spender = Outpoint.fromTX(tx, index);
  this.put(layout.s(prevout.hash, prevout.index), spender.toRaw());
};

/**
 * Remove input record.
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.removeInput = function removeInput(tx, index) {
  let prevout = tx.inputs[index].prevout;
  this.del(layout.s(prevout.hash, prevout.index));
};

/**
 * Resolve orphan input.
 * @param {TX} tx
 * @param {Number} index
 * @param {Number} height
 * @param {Path} path
 * @returns {Boolean}
 */

TXDB.prototype.resolveInput = async function resolveInput(tx, index, height, path, own) {
  let hash = tx.hash('hex');
  let spent = await this.getSpent(hash, index);
  let stx, credit;

  if (!spent)
    return false;

  // If we have an undo coin, we
  // already knew about this input.
  if (await this.hasSpentCoin(spent))
    return false;

  // Get the spending transaction so
  // we can properly add the undo coin.
  stx = await this.getTX(spent.hash);
  assert(stx);

  // Crete the credit and add the undo coin.
  credit = Credit.fromTX(tx, index, height);
  credit.own = own;

  this.spendCredit(credit, stx.tx, spent.index);

  // If the spender is unconfirmed, save
  // the credit as well, and mark it as
  // unspent in the mempool. This is the
  // same behavior `insert` would have
  // done for inputs. We're just doing
  // it retroactively.
  if (stx.height === -1) {
    credit.spent = true;
    await this.saveCredit(credit, path);
    if (height !== -1)
      this.pending.confirmed += credit.coin.value;
  }

  return true;
};

/**
 * Test an entire transaction to see
 * if any of its outpoints are a double-spend.
 * @param {TX} tx
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.isDoubleSpend = async function isDoubleSpend(tx) {
  for (let input of tx.inputs) {
    let prevout = input.prevout;
    let spent = await this.isSpent(prevout.hash, prevout.index);
    if (spent)
      return true;
  }

  return false;
};

/**
 * Test an entire transaction to see
 * if any of its outpoints are replace by fee.
 * @param {TX} tx
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.isRBF = async function isRBF(tx) {
  if (tx.isRBF())
    return true;

  for (let input of tx.inputs) {
    let prevout = input.prevout;
    if (await this.has(layout.r(prevout.hash)))
      return true;
  }

  return false;
};

/**
 * Test a whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.getSpent = async function getSpent(hash, index) {
  let data = await this.get(layout.s(hash, index));

  if (!data)
    return;

  return Outpoint.fromRaw(data);
};

/**
 * Test a whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.isSpent = function isSpent(hash, index) {
  return this.has(layout.s(hash, index));
};

/**
 * Append to the global unspent record.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise}
 */

TXDB.prototype.addOutpointMap = async function addOutpointMap(hash, i) {
  let map = await this.walletdb.getOutpointMap(hash, i);

  if (!map)
    map = new OutpointMapRecord(hash, i);

  if (!map.add(this.wallet.wid))
    return;

  this.walletdb.writeOutpointMap(this.wallet, hash, i, map);
};

/**
 * Remove from the global unspent record.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise}
 */

TXDB.prototype.removeOutpointMap = async function removeOutpointMap(hash, i) {
  let map = await this.walletdb.getOutpointMap(hash, i);

  if (!map)
    return;

  if (!map.remove(this.wallet.wid))
    return;

  if (map.wids.length === 0) {
    this.walletdb.unwriteOutpointMap(this.wallet, hash, i);
    return;
  }

  this.walletdb.writeOutpointMap(this.wallet, hash, i, map);
};

/**
 * Append to the global block record.
 * @param {Hash} hash
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.addBlockMap = async function addBlockMap(hash, height) {
  let block = await this.walletdb.getBlockMap(height);

  if (!block)
    block = new BlockMapRecord(height);

  if (!block.add(hash, this.wallet.wid))
    return;

  this.walletdb.writeBlockMap(this.wallet, height, block);
};

/**
 * Remove from the global block record.
 * @param {Hash} hash
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.removeBlockMap = async function removeBlockMap(hash, height) {
  let block = await this.walletdb.getBlockMap(height);

  if (!block)
    return;

  if (!block.remove(hash, this.wallet.wid))
    return;

  if (block.txs.length === 0) {
    this.walletdb.unwriteBlockMap(this.wallet, height);
    return;
  }

  this.walletdb.writeBlockMap(this.wallet, height, block);
};

/**
 * List block records.
 * @returns {Promise}
 */

TXDB.prototype.getBlocks = function getBlocks() {
  return this.keys({
    gte: layout.b(0),
    lte: layout.b(0xffffffff),
    parse: key => layout.bb(key)
  });
};

/**
 * Get block record.
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.getBlock = async function getBlock(height) {
  let data = await this.get(layout.b(height));

  if (!data)
    return;

  return BlockRecord.fromRaw(data);
};

/**
 * Append to the global block record.
 * @param {Hash} hash
 * @param {BlockMeta} meta
 * @returns {Promise}
 */

TXDB.prototype.addBlock = async function addBlock(hash, meta) {
  let key = layout.b(meta.height);
  let data = await this.get(key);
  let block, size;

  if (!data) {
    block = BlockRecord.fromMeta(meta);
    data = block.toRaw();
  }

  block = Buffer.allocUnsafe(data.length + 32);
  data.copy(block, 0);

  size = block.readUInt32LE(40, true);
  block.writeUInt32LE(size + 1, 40, true);
  hash.copy(block, data.length);

  this.put(key, block);
};

/**
 * Remove from the global block record.
 * @param {Hash} hash
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.removeBlock = async function removeBlock(hash, height) {
  let key = layout.b(height);
  let data = await this.get(key);
  let block, size;

  if (!data)
    return;

  size = data.readUInt32LE(40, true);

  assert(size > 0);
  assert(data.slice(-32).equals(hash));

  if (size === 1) {
    this.del(key);
    return;
  }

  block = data.slice(0, -32);
  block.writeUInt32LE(size - 1, 40, true);

  this.put(key, block);
};

/**
 * Append to the global block record.
 * @param {Hash} hash
 * @param {BlockMeta} meta
 * @returns {Promise}
 */

TXDB.prototype.addBlockSlow = async function addBlockSlow(hash, meta) {
  let block = await this.getBlock(meta.height);

  if (!block)
    block = BlockRecord.fromMeta(meta);

  if (!block.add(hash))
    return;

  this.put(layout.b(meta.height), block.toRaw());
};

/**
 * Remove from the global block record.
 * @param {Hash} hash
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.removeBlockSlow = async function removeBlockSlow(hash, height) {
  let block = await this.getBlock(height);

  if (!block)
    return;

  if (!block.remove(hash))
    return;

  if (block.hashes.length === 0) {
    this.del(layout.b(height));
    return;
  }

  this.put(layout.b(height), block.toRaw());
};

/**
 * Add transaction, potentially runs
 * `confirm()` and `removeConflicts()`.
 * @param {TX} tx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

TXDB.prototype.add = async function add(tx, block) {
  let result;

  this.start();

  try {
    result = await this._add(tx, block);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();

  return result;
};

/**
 * Add transaction without a batch.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype._add = async function add(tx, block) {
  let hash = tx.hash('hex');
  let existing = await this.getTX(hash);
  let wtx;

  assert(!tx.mutable, 'Cannot add mutable TX to wallet.');

  if (existing) {
    // Existing tx is already confirmed. Ignore.
    if (existing.height !== -1)
      return;

    // The incoming tx won't confirm the
    // existing one anyway. Ignore.
    if (!block)
      return;

    // Confirm transaction.
    return await this._confirm(existing, block);
  }

  wtx = TXRecord.fromTX(tx, block);

  if (!block) {
    // We ignore any unconfirmed txs
    // that are replace-by-fee.
    if (await this.isRBF(tx)) {
      // We need to index every spender
      // hash to detect "passive"
      // replace-by-fee.
      this.put(layout.r(hash), null);
      return;
    }

    // Potentially remove double-spenders.
    // Only remove if they're not confirmed.
    if (!(await this.removeConflicts(tx, true)))
      return;
  } else {
    // Potentially remove double-spenders.
    await this.removeConflicts(tx, false);

    // Delete the replace-by-fee record.
    this.del(layout.r(hash));
  }

  // Finally we can do a regular insertion.
  return await this.insert(wtx, block);
};

/**
 * Insert transaction.
 * @private
 * @param {TXRecord} wtx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

TXDB.prototype.insert = async function insert(wtx, block) {
  let tx = wtx.tx;
  let hash = wtx.hash;
  let height = block ? block.height : -1;
  let details = new Details(this, wtx, block);
  let own = false;
  let updated = false;

  if (!tx.isCoinbase()) {
    // We need to potentially spend some coins here.
    for (let i = 0; i < tx.inputs.length; i++) {
      let input = tx.inputs[i];
      let prevout = input.prevout;
      let credit = await this.getCredit(prevout.hash, prevout.index);
      let coin, path;

      if (!credit) {
        // Maintain an stxo list for every
        // spent input (even ones we don't
        // recognize). This is used for
        // detecting double-spends (as best
        // we can), as well as resolving
        // inputs we didn't know were ours
        // at the time. This built-in error
        // correction is not technically
        // necessary assuming no messages
        // are ever missed from the mempool,
        // but shit happens.
        this.writeInput(tx, i);
        continue;
      }

      coin = credit.coin;

      // Do some verification.
      if (!block) {
        if (!(await this.verifyInput(tx, i, coin))) {
          this.clear();
          return;
        }
      }

      path = await this.getPath(coin);
      assert(path);

      // Build the tx details object
      // as we go, for speed.
      details.setInput(i, path, coin);

      // Write an undo coin for the credit
      // and add it to the stxo set.
      this.spendCredit(credit, tx, i);

      // Unconfirmed balance should always
      // be updated as it reflects the on-chain
      // balance _and_ mempool balance assuming
      // everything in the mempool were to confirm.
      this.pending.coin--;
      this.pending.unconfirmed -= coin.value;

      if (!block) {
        // If the tx is not mined, we do not
        // disconnect the coin, we simply mark
        // a `spent` flag on the credit. This
        // effectively prevents the mempool
        // from altering our utxo state
        // permanently. It also makes it
        // possible to compare the on-chain
        // state vs. the mempool state.
        credit.spent = true;
        await this.saveCredit(credit, path);
      } else {
        // If the tx is mined, we can safely
        // remove the coin being spent. This
        // coin will be indexed as an undo
        // coin so it can be reconnected
        // later during a reorg.
        this.pending.confirmed -= coin.value;
        await this.removeCredit(credit, path);
      }

      updated = true;
      own = true;
    }
  }

  // Potentially add coins to the utxo set.
  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let path = await this.getPath(output);
    let credit;

    if (!path)
      continue;

    details.setOutput(i, path);

    // Attempt to resolve an input we
    // did not know was ours at the time.
    if (await this.resolveInput(tx, i, height, path, own)) {
      updated = true;
      continue;
    }

    credit = Credit.fromTX(tx, i, height);
    credit.own = own;

    this.pending.coin++;
    this.pending.unconfirmed += output.value;

    if (block)
      this.pending.confirmed += output.value;

    await this.saveCredit(credit, path);

    updated = true;
  }

  // If this didn't update any coins,
  // it's not our transaction.
  if (!updated) {
    // Clear the spent list inserts.
    this.clear();
    return;
  }

  // Save and index the transaction record.
  this.put(layout.t(hash), wtx.toRaw());
  this.put(layout.m(wtx.ps, hash), null);

  if (!block)
    this.put(layout.p(hash), null);
  else
    this.put(layout.h(height, hash), null);

  // Do some secondary indexing for account-based
  // queries. This saves us a lot of time for
  // queries later.
  for (let account of details.accounts) {
    this.put(layout.T(account, hash), null);
    this.put(layout.M(account, wtx.ps, hash), null);

    if (!block)
      this.put(layout.P(account, hash), null);
    else
      this.put(layout.H(account, height, hash), null);
  }

  // Update block records.
  if (block) {
    await this.addBlockMap(hash, height);
    await this.addBlock(tx.hash(), block);
  }

  // Update the transaction counter and
  // commit the new state. This state will
  // only overwrite the best state once
  // the batch has actually been written
  // to disk.
  this.pending.tx++;
  this.put(layout.R, this.pending.commit());

  // This transaction may unlock some
  // coins now that we've seen it.
  this.unlockTX(tx);

  // Emit events for potential local and
  // websocket listeners. Note that these
  // will only be emitted if the batch is
  // successfully written to disk.
  this.emit('tx', tx, details);
  this.emit('balance', this.pending.toBalance(), details);

  return details;
};

/**
 * Attempt to confirm a transaction.
 * @private
 * @param {TX} tx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

TXDB.prototype.confirm = async function confirm(hash, block) {
  let wtx = await this.getTX(hash);
  let details;

  if (!wtx)
    return;

  if (wtx.height !== -1)
    throw new Error('TX is already confirmed.');

  assert(block);

  this.start();

  try {
    details = await this._confirm(wtx, block);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();

  return details;
};

/**
 * Attempt to confirm a transaction.
 * @private
 * @param {TXRecord} wtx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

TXDB.prototype._confirm = async function confirm(wtx, block) {
  let tx = wtx.tx;
  let hash = wtx.hash;
  let height = block.height;
  let details = new Details(this, wtx, block);

  wtx.setBlock(block);

  if (!tx.isCoinbase()) {
    let credits = await this.getSpentCredits(tx);

    // Potentially spend coins. Now that the tx
    // is mined, we can actually _remove_ coins
    // from the utxo state.
    for (let i = 0; i < tx.inputs.length; i++) {
      let input = tx.inputs[i];
      let prevout = input.prevout;
      let credit = credits[i];
      let coin, path;

      // There may be new credits available
      // that we haven't seen yet.
      if (!credit) {
        credit = await this.getCredit(prevout.hash, prevout.index);

        if (!credit)
          continue;

        // Add a spend record and undo coin
        // for the coin we now know is ours.
        // We don't need to remove the coin
        // since it was never added in the
        // first place.
        this.spendCredit(credit, tx, i);

        this.pending.coin--;
        this.pending.unconfirmed -= credit.coin.value;
      }

      coin = credit.coin;

      assert(coin.height !== -1);

      path = await this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      // We can now safely remove the credit
      // entirely, now that we know it's also
      // been removed on-chain.
      this.pending.confirmed -= coin.value;

      await this.removeCredit(credit, path);
    }
  }

  // Update credit heights, including undo coins.
  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let path = await this.getPath(output);
    let credit, coin;

    if (!path)
      continue;

    details.setOutput(i, path);

    credit = await this.getCredit(hash, i);
    assert(credit);

    // Credits spent in the mempool add an
    // undo coin for ease. If this credit is
    // spent in the mempool, we need to
    // update the undo coin's height.
    if (credit.spent)
      await this.updateSpentCoin(tx, i, height);

    // Update coin height and confirmed
    // balance. Save once again.
    coin = credit.coin;
    coin.height = height;

    this.pending.confirmed += output.value;

    await this.saveCredit(credit, path);
  }

  // Remove the RBF index if we have one.
  this.del(layout.r(hash));

  // Save the new serialized transaction as
  // the block-related properties have been
  // updated. Also reindex for height.
  this.put(layout.t(hash), wtx.toRaw());
  this.del(layout.p(hash));
  this.put(layout.h(height, hash), null);

  // Secondary indexing also needs to change.
  for (let account of details.accounts) {
    this.del(layout.P(account, hash));
    this.put(layout.H(account, height, hash), null);
  }

  if (block) {
    await this.addBlockMap(hash, height);
    await this.addBlock(tx.hash(), block);
  }

  // Commit the new state. The balance has updated.
  this.put(layout.R, this.pending.commit());

  this.unlockTX(tx);

  this.emit('confirmed', tx, details);
  this.emit('balance', this.pending.toBalance(), details);

  return details;
};

/**
 * Recursively remove a transaction
 * from the database.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.remove = async function remove(hash) {
  let wtx = await this.getTX(hash);

  if (!wtx)
    return;

  return await this.removeRecursive(wtx);
};

/**
 * Remove a transaction from the
 * database. Disconnect inputs.
 * @private
 * @param {TXRecord} wtx
 * @returns {Promise}
 */

TXDB.prototype.erase = async function erase(wtx, block) {
  let tx = wtx.tx;
  let hash = wtx.hash;
  let height = block ? block.height : -1;
  let details = new Details(this, wtx, block);

  if (!tx.isCoinbase()) {
    // We need to undo every part of the
    // state this transaction ever touched.
    // Start by getting the undo coins.
    let credits = await this.getSpentCredits(tx);

    for (let i = 0; i < tx.inputs.length; i++) {
      let credit = credits[i];
      let coin, path;

      if (!credit) {
        // This input never had an undo
        // coin, but remove it from the
        // stxo set.
        this.removeInput(tx, i);
        continue;
      }

      coin = credit.coin;
      path = await this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      // Recalculate the balance, remove
      // from stxo set, remove the undo
      // coin, and resave the credit.
      this.pending.coin++;
      this.pending.unconfirmed += coin.value;

      if (block)
        this.pending.confirmed += coin.value;

      this.unspendCredit(tx, i);
      await this.saveCredit(credit, path);
    }
  }

  // We need to remove all credits
  // this transaction created.
  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let path = await this.getPath(output);
    let credit;

    if (!path)
      continue;

    details.setOutput(i, path);

    credit = Credit.fromTX(tx, i, height);

    this.pending.coin--;
    this.pending.unconfirmed -= output.value;

    if (block)
      this.pending.confirmed -= output.value;

    await this.removeCredit(credit, path);
  }

  // Remove the RBF index if we have one.
  this.del(layout.r(hash));

  // Remove the transaction data
  // itself as well as unindex.
  this.del(layout.t(hash));
  this.del(layout.m(wtx.ps, hash));

  if (!block)
    this.del(layout.p(hash));
  else
    this.del(layout.h(height, hash));

  // Remove all secondary indexing.
  for (let account of details.accounts) {
    this.del(layout.T(account, hash));
    this.del(layout.M(account, wtx.ps, hash));

    if (!block)
      this.del(layout.P(account, hash));
    else
      this.del(layout.H(account, height, hash));
  }

  // Update block records.
  if (block) {
    await this.removeBlockMap(hash, height);
    await this.removeBlockSlow(hash, height);
  }

  // Update the transaction counter
  // and commit new state due to
  // balance change.
  this.pending.tx--;
  this.put(layout.R, this.pending.commit());

  this.emit('remove tx', tx, details);
  this.emit('balance', this.pending.toBalance(), details);

  return details;
};

/**
 * Remove a transaction and recursively
 * remove all of its spenders.
 * @private
 * @param {TXRecord} wtx
 * @returns {Promise}
 */

TXDB.prototype.removeRecursive = async function removeRecursive(wtx) {
  let tx = wtx.tx;
  let hash = wtx.hash;
  let details;

  for (let i = 0; i < tx.outputs.length; i++) {
    let spent = await this.getSpent(hash, i);
    let stx;

    if (!spent)
      continue;

    // Remove all of the spender's spenders first.
    stx = await this.getTX(spent.hash);

    assert(stx);

    await this.removeRecursive(stx);
  }

  this.start();

  // Remove the spender.
  details = await this.erase(wtx, wtx.getBlock());

  assert(details);

  await this.commit();

  return details;
};

/**
 * Unconfirm a transaction. Necessary after a reorg.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.unconfirm = async function unconfirm(hash) {
  let details;

  this.start();

  try {
    details = await this._unconfirm(hash);
  } catch (e) {
    this.drop();
    throw e;
  }

  await this.commit();

  return details;
};

/**
 * Unconfirm a transaction without a batch.
 * @private
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype._unconfirm = async function unconfirm(hash) {
  let wtx = await this.getTX(hash);

  if (!wtx)
    return;

  if (wtx.height === -1)
    return;

  return await this.disconnect(wtx, wtx.getBlock());
};

/**
 * Unconfirm a transaction. Necessary after a reorg.
 * @param {TXRecord} wtx
 * @returns {Promise}
 */

TXDB.prototype.disconnect = async function disconnect(wtx, block) {
  let tx = wtx.tx;
  let hash = wtx.hash;
  let height = block.height;
  let details = new Details(this, wtx, block);

  assert(block);

  wtx.unsetBlock();

  if (!tx.isCoinbase()) {
    // We need to reconnect the coins. Start
    // by getting all of the undo coins we know
    // about.
    let credits = await this.getSpentCredits(tx);

    for (let i = 0; i < tx.inputs.length; i++) {
      let credit = credits[i];
      let path, coin;

      if (!credit)
        continue;

      coin = credit.coin;

      assert(coin.height !== -1);

      path = await this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      this.pending.confirmed += coin.value;

      // Resave the credit and mark it
      // as spent in the mempool instead.
      credit.spent = true;
      await this.saveCredit(credit, path);
    }
  }

  // We need to remove heights on
  // the credits and undo coins.
  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let path = await this.getPath(output);
    let credit, coin;

    if (!path)
      continue;

    credit = await this.getCredit(hash, i);

    // Potentially update undo coin height.
    if (!credit) {
      await this.updateSpentCoin(tx, i, height);
      continue;
    }

    if (credit.spent)
      await this.updateSpentCoin(tx, i, height);

    details.setOutput(i, path);

    // Update coin height and confirmed
    // balance. Save once again.
    coin = credit.coin;
    coin.height = -1;

    this.pending.confirmed -= output.value;

    await this.saveCredit(credit, path);
  }

  await this.removeBlockMap(hash, height);
  await this.removeBlock(tx.hash(), height);

  // We need to update the now-removed
  // block properties and reindex due
  // to the height change.
  this.put(layout.t(hash), wtx.toRaw());
  this.put(layout.p(hash), null);
  this.del(layout.h(height, hash));

  // Secondary indexing also needs to change.
  for (let account of details.accounts) {
    this.put(layout.P(account, hash), null);
    this.del(layout.H(account, height, hash));
  }

  // Commit state due to unconfirmed
  // vs. confirmed balance change.
  this.put(layout.R, this.pending.commit());

  this.emit('unconfirmed', tx, details);
  this.emit('balance', this.pending.toBalance(), details);

  return details;
};

/**
 * Remove spenders that have not been confirmed. We do this in the
 * odd case of stuck transactions or when a coin is double-spent
 * by a newer transaction. All previously-spending transactions
 * of that coin that are _not_ confirmed will be removed from
 * the database.
 * @private
 * @param {Hash} hash
 * @param {TX} ref - Reference tx, the tx that double-spent.
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.removeConflict = async function removeConflict(wtx) {
  let tx = wtx.tx;
  let details;

  this.logger.warning('Handling conflicting tx: %s.', tx.txid());

  this.drop();

  details = await this.removeRecursive(wtx);

  this.start();

  this.logger.warning('Removed conflict: %s.', tx.txid());

  // Emit the _removed_ transaction.
  this.emit('conflict', tx, details);

  return details;
};

/**
 * Retrieve coins for own inputs, remove
 * double spenders, and verify inputs.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.removeConflicts = async function removeConflicts(tx, conf) {
  let hash = tx.hash('hex');
  let spends = [];

  if (tx.isCoinbase())
    return true;

  // Gather all spent records first.
  for (let i = 0; i < tx.inputs.length; i++) {
    let input = tx.inputs[i];
    let prevout = input.prevout;
    let spent, spender, block;

    // Is it already spent?
    spent = await this.getSpent(prevout.hash, prevout.index);

    if (!spent)
      continue;

    // Did _we_ spend it?
    if (spent.hash === hash)
      continue;

    spender = await this.getTX(spent.hash);
    assert(spender);
    block = spender.getBlock();

    if (conf && block)
      return false;

    spends[i] = spender;
  }

  // Once we know we're not going to
  // screw things up, remove the double
  // spenders.
  for (let spender of spends) {
    if (!spender)
      continue;

    // Remove the double spender.
    await this.removeConflict(spender);
  }

  return true;
};

/**
 * Attempt to verify an input.
 * @private
 * @param {TX} tx
 * @param {Number} index
 * @param {Coin} coin
 * @returns {Promise}
 */

TXDB.prototype.verifyInput = async function verifyInput(tx, index, coin) {
  let flags = Script.flags.MANDATORY_VERIFY_FLAGS;
  if (!this.options.verify)
    return true;
  return await tx.verifyInputAsync(index, coin, flags);
};

/**
 * Lock all coins in a transaction.
 * @param {TX} tx
 */

TXDB.prototype.lockTX = function lockTX(tx) {
  if (tx.isCoinbase())
    return;

  for (let input of tx.inputs)
    this.lockCoin(input.prevout);
};

/**
 * Unlock all coins in a transaction.
 * @param {TX} tx
 */

TXDB.prototype.unlockTX = function unlockTX(tx) {
  if (tx.isCoinbase())
    return;

  for (let input of tx.inputs)
    this.unlockCoin(input.prevout);
};

/**
 * Lock a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.lockCoin = function lockCoin(coin) {
  let key = coin.toKey();
  this.locked.add(key);
};

/**
 * Unlock a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.unlockCoin = function unlockCoin(coin) {
  let key = coin.toKey();
  return this.locked.delete(key);
};

/**
 * Test locked status of a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.isLocked = function isLocked(coin) {
  let key = coin.toKey();
  return this.locked.has(key);
};

/**
 * Filter array of coins or outpoints
 * for only unlocked ones.
 * @param {Coin[]|Outpoint[]}
 * @returns {Array}
 */

TXDB.prototype.filterLocked = function filterLocked(coins) {
  let out = [];

  for (let coin of coins) {
    if (!this.isLocked(coin))
      out.push(coin);
  }

  return out;
};

/**
 * Return an array of all locked outpoints.
 * @returns {Outpoint[]}
 */

TXDB.prototype.getLocked = function getLocked() {
  let outpoints = [];

  for (let key of this.locked.keys())
    outpoints.push(Outpoint.fromKey(key));

  return outpoints;
};

/**
 * Get hashes of all transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountHistoryHashes = function getHistoryHashes(account) {
  return this.keys({
    gte: layout.T(account, encoding.NULL_HASH),
    lte: layout.T(account, encoding.HIGH_HASH),
    parse: (key) => {
      let [, hash] = layout.Tt(key);
      return hash;
    }
  });
};

/**
 * Get hashes of all transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHistoryHashes = function getHistoryHashes(account) {
  if (account != null)
    return this.getAccountHistoryHashes(account);

  return this.keys({
    gte: layout.t(encoding.NULL_HASH),
    lte: layout.t(encoding.HIGH_HASH),
    parse: key => layout.tt(key)
  });
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountPendingHashes = function getAccountPendingHashes(account) {
  return this.keys({
    gte: layout.P(account, encoding.NULL_HASH),
    lte: layout.P(account, encoding.HIGH_HASH),
    parse: (key) => {
      let [, hash] = layout.Pp(key);
      return hash;
    }
  });
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getPendingHashes = function getPendingHashes(account) {
  if (account != null)
    return this.getAccountPendingHashes(account);

  return this.keys({
    gte: layout.p(encoding.NULL_HASH),
    lte: layout.p(encoding.HIGH_HASH),
    parse: key => layout.pp(key)
  });
};

/**
 * Get all coin hashes in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountOutpoints = function getAccountOutpoints(account) {
  return this.keys({
    gte: layout.C(account, encoding.NULL_HASH, 0),
    lte: layout.C(account, encoding.HIGH_HASH, 0xffffffff),
    parse: (key) => {
      let [, hash, index] = layout.Cc(key);
      return new Outpoint(hash, index);
    }
  });
};

/**
 * Get all coin hashes in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getOutpoints = function getOutpoints(account) {
  if (account != null)
    return this.getAccountOutpoints(account);

  return this.keys({
    gte: layout.c(encoding.NULL_HASH, 0),
    lte: layout.c(encoding.HIGH_HASH, 0xffffffff),
    parse: (key) => {
      let [hash, index] = layout.cc(key);
      return new Outpoint(hash, index);
    }
  });
};

/**
 * Get TX hashes by height range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountHeightRangeHashes = function getAccountHeightRangeHashes(account, options) {
  let start = options.start || 0;
  let end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.H(account, start, encoding.NULL_HASH),
    lte: layout.H(account, end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      let [,, hash] = layout.Hh(key);
      return hash;
    }
  });
};

/**
 * Get TX hashes by height range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHeightRangeHashes = function getHeightRangeHashes(account, options) {
  let start, end;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  if (account != null)
    return this.getAccountHeightRangeHashes(account, options);

  start = options.start || 0;
  end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.h(start, encoding.NULL_HASH),
    lte: layout.h(end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      let [, hash] = layout.hh(key);
      return hash;
    }
  });
};

/**
 * Get TX hashes by height.
 * @param {Number} height
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHeightHashes = function getHeightHashes(height) {
  return this.getHeightRangeHashes({ start: height, end: height });
};

/**
 * Get TX hashes by timestamp range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountRangeHashes = function getAccountRangeHashes(account, options) {
  let start = options.start || 0;
  let end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.M(account, start, encoding.NULL_HASH),
    lte: layout.M(account, end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      let [,, hash] = layout.Mm(key);
      return hash;
    }
  });
};

/**
 * Get TX hashes by timestamp range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getRangeHashes = function getRangeHashes(account, options) {
  let start, end;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  if (account != null)
    return this.getAccountRangeHashes(account, options);

  start = options.start || 0;
  end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.m(start, encoding.NULL_HASH),
    lte: layout.m(end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      let [, hash] = layout.mm(key);
      return hash;
    }
  });
};

/**
 * Get transactions by timestamp range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start time.
 * @param {Number} options.end - End time.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getRange = async function getRange(account, options) {
  let txs = [];
  let hashes;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  hashes = await this.getRangeHashes(account, options);

  for (let hash of hashes) {
    let tx = await this.getTX(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Get last N transactions.
 * @param {Number?} account
 * @param {Number} limit - Max number of transactions.
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getLast = function getLast(account, limit) {
  return this.getRange(account, {
    start: 0,
    end: 0xffffffff,
    reverse: true,
    limit: limit || 10
  });
};

/**
 * Get all transactions.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getHistory = function getHistory(account) {
  // Slow case
  if (account != null)
    return this.getAccountHistory(account);

  // Fast case
  return this.values({
    gte: layout.t(encoding.NULL_HASH),
    lte: layout.t(encoding.HIGH_HASH),
    parse: TXRecord.fromRaw
  });
};

/**
 * Get all account transactions.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getAccountHistory = async function getAccountHistory(account) {
  let hashes = await this.getHistoryHashes(account);
  let txs = [];

  for (let hash of hashes) {
    let tx = await this.getTX(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Get unconfirmed transactions.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getPending = async function getPending(account) {
  let hashes = await this.getPendingHashes(account);
  let txs = [];

  for (let hash of hashes) {
    let tx = await this.getTX(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Get coins.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getCredits = function getCredits(account) {
  // Slow case
  if (account != null)
    return this.getAccountCredits(account);

  // Fast case
  return this.range({
    gte: layout.c(encoding.NULL_HASH, 0x00000000),
    lte: layout.c(encoding.HIGH_HASH, 0xffffffff),
    parse: (key, value) => {
      let [hash, index] = layout.cc(key);
      let credit = Credit.fromRaw(value);
      let ckey = Outpoint.toKey(hash, index);
      credit.coin.hash = hash;
      credit.coin.index = index;
      this.coinCache.set(ckey, value);
      return credit;
    }
  });
};

/**
 * Get coins by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCredits = async function getAccountCredits(account) {
  let outpoints = await this.getOutpoints(account);
  let credits = [];

  for (let prevout of outpoints) {
    let credit = await this.getCredit(prevout.hash, prevout.index);
    assert(credit);
    credits.push(credit);
  }

  return credits;
};

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.getSpentCredits = async function getSpentCredits(tx) {
  let credits = [];
  let hash;

  for (let i = 0; i < tx.inputs.length; i++)
    credits.push(null);

  if (tx.isCoinbase())
    return credits;

  hash = tx.hash('hex');

  await this.range({
    gte: layout.d(hash, 0x00000000),
    lte: layout.d(hash, 0xffffffff),
    parse: (key, value) => {
      let [, index] = layout.dd(key);
      let coin = Coin.fromRaw(value);
      let input = tx.inputs[index];
      assert(input);
      coin.hash = input.prevout.hash;
      coin.index = input.prevout.index;
      credits[index] = new Credit(coin);
    }
  });

  return credits;
};

/**
 * Get coins.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getCoins = async function getCoins(account) {
  let credits = await this.getCredits(account);
  let coins = [];

  for (let credit of credits) {
    if (credit.spent)
      continue;

    coins.push(credit.coin);
  }

  return coins;
};

/**
 * Get coins by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCoins = async function getAccountCoins(account) {
  let credits = await this.getAccountCredits(account);
  let coins = [];

  for (let credit of credits) {
    if (credit.spent)
      continue;

    coins.push(credit.coin);
  }

  return coins;
};

/**
 * Get historical coins for a transaction.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.getSpentCoins = async function getSpentCoins(tx) {
  let coins = [];
  let credits;

  if (tx.isCoinbase())
    return coins;

  credits = await this.getSpentCredits(tx);

  for (let credit of credits) {
    if (!credit) {
      coins.push(null);
      continue;
    }

    coins.push(credit.coin);
  }

  return coins;
};

/**
 * Get a coin viewpoint.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

TXDB.prototype.getCoinView = async function getCoinView(tx) {
  let view = new CoinView();

  if (tx.isCoinbase())
    return view;

  for (let input of tx.inputs) {
    let prevout = input.prevout;
    let coin = await this.getCoin(prevout.hash, prevout.index);

    if (!coin)
      continue;

    view.addCoin(coin);
  }

  return view;
};

/**
 * Get historical coin viewpoint.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link CoinView}.
 */

TXDB.prototype.getSpentView = async function getSpentView(tx) {
  let view = new CoinView();
  let coins;

  if (tx.isCoinbase())
    return view;

  coins = await this.getSpentCoins(tx);

  for (let coin of coins) {
    if (!coin)
      continue;

    view.addCoin(coin);
  }

  return view;
};

/**
 * Get TXDB state.
 * @returns {Promise}
 */

TXDB.prototype.getState = async function getState() {
  let data = await this.get(layout.R);

  if (!data)
    return;

  return TXDBState.fromRaw(this.wallet.wid, this.wallet.id, data);
};

/**
 * Get transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.getTX = async function getTX(hash) {
  let raw = await this.get(layout.t(hash));

  if (!raw)
    return;

  return TXRecord.fromRaw(raw);
};

/**
 * Get transaction details.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXDetails}.
 */

TXDB.prototype.getDetails = async function getDetails(hash) {
  let wtx = await this.getTX(hash);

  if (!wtx)
    return;

  return await this.toDetails(wtx);
};

/**
 * Convert transaction to transaction details.
 * @param {TXRecord[]} wtxs
 * @returns {Promise}
 */

TXDB.prototype.toDetails = async function toDetails(wtxs) {
  let out = [];

  if (!Array.isArray(wtxs))
    return await this._toDetails(wtxs);

  for (let wtx of wtxs) {
    let details = await this._toDetails(wtx);

    if (!details)
      continue;

    out.push(details);
  }

  return out;
};

/**
 * Convert transaction to transaction details.
 * @private
 * @param {TXRecord} wtx
 * @returns {Promise}
 */

TXDB.prototype._toDetails = async function _toDetails(wtx) {
  let tx = wtx.tx;
  let block = wtx.getBlock();
  let details = new Details(this, wtx, block);
  let coins = await this.getSpentCoins(tx);

  for (let i = 0; i < tx.inputs.length; i++) {
    let coin = coins[i];
    let path = null;

    if (coin)
      path = await this.getPath(coin);

    details.setInput(i, path, coin);
  }

  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];
    let path = await this.getPath(output);
    details.setOutput(i, path);
  }

  return details;
};

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasTX = function hasTX(hash) {
  return this.has(layout.t(hash));
};

/**
 * Get coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getCoin = async function getCoin(hash, index) {
  let credit = await this.getCredit(hash, index);

  if (!credit)
    return;

  return credit.coin;
};

/**
 * Get coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getCredit = async function getCredit(hash, index) {
  let state = this.state;
  let key = Outpoint.toKey(hash, index);
  let data = this.coinCache.get(key);
  let credit;

  if (data) {
    credit = Credit.fromRaw(data);
    credit.coin.hash = hash;
    credit.coin.index = index;
    return credit;
  }

  data = await this.get(layout.c(hash, index));

  if (!data)
    return;

  credit = Credit.fromRaw(data);
  credit.coin.hash = hash;
  credit.coin.index = index;

  if (state === this.state)
    this.coinCache.set(key, data);

  return credit;
};

/**
 * Get spender coin.
 * @param {Outpoint} spent
 * @param {Outpoint} prevout
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getSpentCoin = async function getSpentCoin(spent, prevout) {
  let data = await this.get(layout.d(spent.hash, spent.index));
  let coin;

  if (!data)
    return;

  coin = Coin.fromRaw(data);
  coin.hash = prevout.hash;
  coin.index = prevout.index;

  return coin;
};

/**
 * Test whether the database has a spent coin.
 * @param {Outpoint} spent
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.hasSpentCoin = function hasSpentCoin(spent) {
  return this.has(layout.d(spent.hash, spent.index));
};

/**
 * Update spent coin height in storage.
 * @param {TX} tx - Sending transaction.
 * @param {Number} index
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.updateSpentCoin = async function updateSpentCoin(tx, index, height) {
  let prevout = Outpoint.fromTX(tx, index);
  let spent = await this.getSpent(prevout.hash, prevout.index);
  let coin;

  if (!spent)
    return;

  coin = await this.getSpentCoin(spent, prevout);

  if (!coin)
    return;

  coin.height = height;

  this.put(layout.d(spent.hash, spent.index), coin.toRaw());
};

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasCoin = function hasCoin(hash, index) {
  let key = Outpoint.toKey(hash, index);

  if (this.coinCache.has(key))
    return Promise.resolve(true);

  return this.has(layout.c(hash, index));
};

/**
 * Calculate balance.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getBalance = async function getBalance(account) {
  // Slow case
  if (account != null)
    return await this.getAccountBalance(account);

  // Fast case
  return this.state.toBalance();
};

/**
 * Calculate balance.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getWalletBalance = async function getWalletBalance() {
  let credits = await this.getCredits();
  let balance = new Balance(this.wallet.wid, this.wallet.id, -1);

  for (let credit of credits) {
    let coin = credit.coin;

    if (coin.height !== -1)
      balance.confirmed += coin.value;

    if (!credit.spent)
      balance.unconfirmed += coin.value;
  }

  return balance;
};

/**
 * Calculate balance by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getAccountBalance = async function getAccountBalance(account) {
  let credits = await this.getAccountCredits(account);
  let balance = new Balance(this.wallet.wid, this.wallet.id, account);

  for (let credit of credits) {
    let coin = credit.coin;

    if (coin.height !== -1)
      balance.confirmed += coin.value;

    if (!credit.spent)
      balance.unconfirmed += coin.value;
  }

  return balance;
};

/**
 * Zap pending transactions older than `age`.
 * @param {Number?} account
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @returns {Promise}
 */

TXDB.prototype.zap = async function zap(account, age) {
  let hashes = [];
  let now = util.now();
  let txs;

  assert(util.isUInt32(age));

  txs = await this.getRange(account, {
    start: 0,
    end: now - age
  });

  for (let wtx of txs) {
    if (wtx.height !== -1)
      continue;

    assert(now - wtx.ps >= age);

    this.logger.debug('Zapping TX: %s (%s)',
      wtx.tx.txid(), this.wallet.id);

    await this.remove(wtx.hash);

    hashes.push(wtx.hash);
  }

  return hashes;
};

/**
 * Abandon transaction.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.abandon = async function abandon(hash) {
  let result = await this.has(layout.p(hash));

  if (!result)
    throw new Error('TX not eligible.');

  return await this.remove(hash);
};

/**
 * Balance
 * @alias module:wallet.Balance
 * @constructor
 * @param {WalletID} wid
 * @param {String} id
 * @param {Number} account
 */

function Balance(wid, id, account) {
  if (!(this instanceof Balance))
    return new Balance(wid, id, account);

  this.wid = wid;
  this.id = id;
  this.account = account;
  this.unconfirmed = 0;
  this.confirmed = 0;
}

/**
 * Test whether a balance is equal.
 * @param {Balance} balance
 * @returns {Boolean}
 */

Balance.prototype.equal = function equal(balance) {
  return this.wid === balance.wid
    && this.confirmed === balance.confirmed
    && this.unconfirmed === balance.unconfirmed;
};

/**
 * Convert balance to a more json-friendly object.
 * @param {Boolean?} minimal
 * @returns {Object}
 */

Balance.prototype.toJSON = function toJSON(minimal) {
  return {
    wid: !minimal ? this.wid : undefined,
    id: !minimal ? this.id : undefined,
    account: !minimal ? this.account : undefined,
    unconfirmed: this.unconfirmed,
    confirmed: this.confirmed
  };
};

/**
 * Convert balance to human-readable string.
 * @returns {String}
 */

Balance.prototype.toString = function toString() {
  return '<Balance'
    + ` unconfirmed=${Amount.btc(this.unconfirmed)}`
    + ` confirmed=${Amount.btc(this.confirmed)}`
    + '>';
};

/**
 * Inspect balance.
 * @param {String}
 */

Balance.prototype.inspect = function inspect() {
  return this.toString();
};

/**
 * Chain State
 * @alias module:wallet.ChainState
 * @constructor
 * @param {WalletID} wid
 * @param {String} id
 */

function TXDBState(wid, id) {
  this.wid = wid;
  this.id = id;
  this.tx = 0;
  this.coin = 0;
  this.unconfirmed = 0;
  this.confirmed = 0;
  this.committed = false;
}

/**
 * Clone the state.
 * @returns {TXDBState}
 */

TXDBState.prototype.clone = function clone() {
  let state = new TXDBState(this.wid, this.id);
  state.tx = this.tx;
  state.coin = this.coin;
  state.unconfirmed = this.unconfirmed;
  state.confirmed = this.confirmed;
  return state;
};

/**
 * Commit and serialize state.
 * @returns {Buffer}
 */

TXDBState.prototype.commit = function commit() {
  this.committed = true;
  return this.toRaw();
};

/**
 * Convert state to a balance object.
 * @returns {Balance}
 */

TXDBState.prototype.toBalance = function toBalance() {
  let balance = new Balance(this.wid, this.id, -1);
  balance.unconfirmed = this.unconfirmed;
  balance.confirmed = this.confirmed;
  return balance;
};

/**
 * Serialize state.
 * @returns {Buffer}
 */

TXDBState.prototype.toRaw = function toRaw() {
  let bw = new StaticWriter(32);

  bw.writeU64(this.tx);
  bw.writeU64(this.coin);
  bw.writeU64(this.unconfirmed);
  bw.writeU64(this.confirmed);

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {TXDBState}
 */

TXDBState.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  this.tx = br.readU53();
  this.coin = br.readU53();
  this.unconfirmed = br.readU53();
  this.confirmed = br.readU53();
  return this;
};

/**
 * Instantiate txdb state from serialized data.
 * @param {Buffer} data
 * @returns {TXDBState}
 */

TXDBState.fromRaw = function fromRaw(wid, id, data) {
  return new TXDBState(wid, id).fromRaw(data);
};

/**
 * Convert state to a more json-friendly object.
 * @param {Boolean?} minimal
 * @returns {Object}
 */

TXDBState.prototype.toJSON = function toJSON(minimal) {
  return {
    wid: !minimal ? this.wid : undefined,
    id: !minimal ? this.id : undefined,
    tx: this.tx,
    coin: this.coin,
    unconfirmed: this.unconfirmed,
    confirmed: this.confirmed
  };
};

/**
 * Inspect the state.
 * @returns {Object}
 */

TXDBState.prototype.inspect = function inspect() {
  return this.toJSON();
};

/**
 * Credit (wrapped coin)
 * @alias module:wallet.Credit
 * @constructor
 * @param {Coin} coin
 * @param {Boolean?} spent
 * @property {Coin} coin
 * @property {Boolean} spent
 */

function Credit(coin, spent) {
  if (!(this instanceof Credit))
    return new Credit(coin, spent);

  this.coin = coin || new Coin();
  this.spent = spent || false;
  this.own = false;
}

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Credit.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  this.coin.fromReader(br);
  this.spent = br.readU8() === 1;
  this.own = true;

  // Note: soft-fork
  if (br.left() > 0)
    this.own = br.readU8() === 1;

  return this;
};

/**
 * Instantiate credit from serialized data.
 * @param {Buffer} data
 * @returns {Credit}
 */

Credit.fromRaw = function fromRaw(data) {
  return new Credit().fromRaw(data);
};

/**
 * Get serialization size.
 * @returns {Number}
 */

Credit.prototype.getSize = function getSize() {
  return this.coin.getSize() + 2;
};

/**
 * Serialize credit.
 * @returns {Buffer}
 */

Credit.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);
  this.coin.toWriter(bw);
  bw.writeU8(this.spent ? 1 : 0);
  bw.writeU8(this.own ? 1 : 0);
  return bw.render();
};

/**
 * Inject properties from tx object.
 * @private
 * @param {TX} tx
 * @param {Number} index
 * @returns {Credit}
 */

Credit.prototype.fromTX = function fromTX(tx, index, height) {
  this.coin.fromTX(tx, index, height);
  this.spent = false;
  this.own = false;
  return this;
};

/**
 * Instantiate credit from transaction.
 * @param {TX} tx
 * @param {Number} index
 * @returns {Credit}
 */

Credit.fromTX = function fromTX(tx, index, height) {
  return new Credit().fromTX(tx, index, height);
};

/**
 * Transaction Details
 * @alias module:wallet.Details
 * @constructor
 * @param {TXDB} txdb
 * @param {TX} tx
 */

function Details(txdb, wtx, block) {
  if (!(this instanceof Details))
    return new Details(txdb, wtx, block);

  this.wallet = txdb.wallet;
  this.network = this.wallet.network;
  this.wid = this.wallet.wid;
  this.id = this.wallet.id;

  this.chainHeight = txdb.walletdb.state.height;

  this.hash = wtx.hash;
  this.tx = wtx.tx;
  this.ps = wtx.ps;
  this.size = this.tx.getSize();
  this.vsize = this.tx.getVirtualSize();

  this.block = null;
  this.height = -1;
  this.ts = 0;
  this.index = -1;

  if (block) {
    this.block = block.hash;
    this.height = block.height;
    this.ts = block.ts;
  }

  this.inputs = [];
  this.outputs = [];
  this.accounts = [];

  this.init();
}

/**
 * Initialize transaction details.
 * @private
 */

Details.prototype.init = function init() {
  for (let input of this.tx.inputs) {
    let member = new DetailsMember();
    member.address = input.getAddress();
    this.inputs.push(member);
  }

  for (let output of this.tx.outputs) {
    let member = new DetailsMember();
    member.value = output.value;
    member.address = output.getAddress();
    this.outputs.push(member);
  }
};

/**
 * Add necessary info to input member.
 * @param {Number} i
 * @param {Path} path
 * @param {Coin} coin
 */

Details.prototype.setInput = function setInput(i, path, coin) {
  let member = this.inputs[i];

  if (coin) {
    member.value = coin.value;
    member.address = coin.getAddress();
  }

  if (path) {
    member.path = path;
    util.binaryInsert(this.accounts, path.account, cmp, true);
  }
};

/**
 * Add necessary info to output member.
 * @param {Number} i
 * @param {Path} path
 */

Details.prototype.setOutput = function setOutput(i, path) {
  let member = this.outputs[i];

  if (path) {
    member.path = path;
    util.binaryInsert(this.accounts, path.account, cmp, true);
  }
};

/**
 * Calculate confirmations.
 * @returns {Number}
 */

Details.prototype.getDepth = function getDepth() {
  let depth;

  if (this.height === -1)
    return 0;

  depth = this.chainHeight - this.height;

  if (depth < 0)
    return 0;

  return depth + 1;
};

/**
 * Calculate fee. Only works if wallet
 * owns all inputs. Returns 0 otherwise.
 * @returns {Amount}
 */

Details.prototype.getFee = function getFee() {
  let inputValue = 0;
  let outputValue = 0;

  for (let input of this.inputs) {
    if (!input.path)
      return 0;

    inputValue += input.value;
  }

  for (let output of this.outputs)
    outputValue += output.value;

  return inputValue - outputValue;
};

/**
 * Calculate fee rate. Only works if wallet
 * owns all inputs. Returns 0 otherwise.
 * @param {Amount} fee
 * @returns {Rate}
 */

Details.prototype.getRate = function getRate(fee) {
  return policy.getRate(this.vsize, fee);
};

/**
 * Convert details to a more json-friendly object.
 * @returns {Object}
 */

Details.prototype.toJSON = function toJSON() {
  let fee = this.getFee();
  let rate = this.getRate(fee);

  // Rate can exceed 53 bits in testing.
  if (!util.isSafeInteger(rate))
    rate = 0;

  return {
    wid: this.wid,
    id: this.id,
    hash: util.revHex(this.hash),
    height: this.height,
    block: this.block ? util.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    date: util.date(this.ts || this.ps),
    index: this.index,
    size: this.size,
    virtualSize: this.vsize,
    fee: fee,
    rate: rate,
    confirmations: this.getDepth(),
    inputs: this.inputs.map((input) => {
      return input.getJSON(this.network);
    }),
    outputs: this.outputs.map((output) => {
      return output.getJSON(this.network);
    }),
    tx: this.tx.toRaw().toString('hex')
  };
};

/**
 * Transaction Details Member
 * @alias module:wallet.DetailsMember
 * @constructor
 * @property {Number} value
 * @property {Address} address
 * @property {Path} path
 */

function DetailsMember() {
  if (!(this instanceof DetailsMember))
    return new DetailsMember();

  this.value = 0;
  this.address = null;
  this.path = null;
}

/**
 * Convert the member to a more json-friendly object.
 * @returns {Object}
 */

DetailsMember.prototype.toJSON = function toJSON() {
  return this.getJSON();
};

/**
 * Convert the member to a more json-friendly object.
 * @param {Network} network
 * @returns {Object}
 */

DetailsMember.prototype.getJSON = function getJSON(network) {
  return {
    value: this.value,
    address: this.address
      ? this.address.toString(network)
      : null,
    path: this.path
      ? this.path.toJSON()
      : null
  };
};

/**
 * Block Record
 * @alias module:wallet.BlockRecord
 * @constructor
 * @param {Hash} hash
 * @param {Number} height
 * @param {Number} ts
 */

function BlockRecord(hash, height, ts) {
  if (!(this instanceof BlockRecord))
    return new BlockRecord(hash, height, ts);

  this.hash = hash || encoding.NULL_HASH;
  this.height = height != null ? height : -1;
  this.ts = ts || 0;
  this.hashes = [];
  this.index = {};
}

/**
 * Add transaction to block record.
 * @param {Hash} hash
 * @returns {Boolean}
 */

BlockRecord.prototype.add = function add(hash) {
  if (this.index[hash])
    return false;

  this.index[hash] = true;
  this.hashes.push(hash);

  return true;
};

/**
 * Remove transaction from block record.
 * @param {Hash} hash
 * @returns {Boolean}
 */

BlockRecord.prototype.remove = function remove(hash) {
  let index;

  if (!this.index[hash])
    return false;

  delete this.index[hash];

  // Fast case
  if (this.hashes[this.hashes.length - 1] === hash) {
    this.hashes.pop();
    return true;
  }

  index = this.hashes.indexOf(hash);

  assert(index !== -1);

  this.hashes.splice(index, 1);

  return true;
};

/**
 * Instantiate wallet block from serialized tip data.
 * @private
 * @param {Buffer} data
 */

BlockRecord.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  let count;

  this.hash = br.readHash('hex');
  this.height = br.readU32();
  this.ts = br.readU32();

  count = br.readU32();

  for (let i = 0; i < count; i++) {
    let hash = br.readHash('hex');
    this.index[hash] = true;
    this.hashes.push(hash);
  }

  return this;
};

/**
 * Instantiate wallet block from serialized data.
 * @param {Buffer} data
 * @returns {BlockRecord}
 */

BlockRecord.fromRaw = function fromRaw(data) {
  return new BlockRecord().fromRaw(data);
};

/**
 * Get serialization size.
 * @returns {Number}
 */

BlockRecord.prototype.getSize = function getSize() {
  return 44 + this.hashes.length * 32;
};

/**
 * Serialize the wallet block as a tip (hash and height).
 * @returns {Buffer}
 */

BlockRecord.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  bw.writeHash(this.hash);
  bw.writeU32(this.height);
  bw.writeU32(this.ts);

  bw.writeU32(this.hashes.length);

  for (let hash of this.hashes)
    bw.writeHash(hash);

  return bw.render();
};

/**
 * Convert the block to a more json-friendly object.
 * @returns {Object}
 */

BlockRecord.prototype.toJSON = function toJSON() {
  return {
    hash: util.revHex(this.hash),
    height: this.height,
    ts: this.ts,
    hashes: this.hashes.map(util.revHex)
  };
};

/**
 * Instantiate wallet block from block meta.
 * @private
 * @param {BlockMeta} block
 */

BlockRecord.prototype.fromMeta = function fromMeta(block) {
  this.hash = block.hash;
  this.height = block.height;
  this.ts = block.ts;
  return this;
};

/**
 * Instantiate wallet block from block meta.
 * @param {BlockMeta} block
 * @returns {BlockRecord}
 */

BlockRecord.fromMeta = function fromMeta(block) {
  return new BlockRecord().fromMeta(block);
};

/*
 * Helpers
 */

function cmp(a, b) {
  return a - b;
}

/*
 * Expose
 */

module.exports = TXDB;
