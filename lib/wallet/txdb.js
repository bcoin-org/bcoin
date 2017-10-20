/*!
 * txdb.js - persistent transaction pool
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
const CoinView = require('../coins/coinview');
const Coin = require('../primitives/coin');
const Outpoint = require('../primitives/outpoint');
const records = require('./records');
const layout = require('./layout').txdb;
const encoding = require('../utils/encoding');
const policy = require('../protocol/policy');
const TXRecord = records.TXRecord;

/**
 * TXDB
 * @alias module:wallet.TXDB
 * @constructor
 * @param {WalletDB} wdb
 */

function TXDB(wdb, wid) {
  if (!(this instanceof TXDB))
    return new TXDB(wdb);

  this.wdb = wdb;
  this.db = wdb.db;
  this.logger = wdb.logger;

  this.wid = wid || 0;
  this.prefix = layout.prefix(this.wid);
  this.wallet = null;
  this.locked = new Set();
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

TXDB.prototype.open = async function open(wallet) {
  this.wid = wallet.wid;
  this.prefix = layout.prefix(this.wid);
  this.wallet = wallet;
};

/**
 * Emit transaction event.
 * @private
 * @param {String} event
 * @param {Object} data
 * @param {Details} details
 */

TXDB.prototype.emit = function emit(event, data, details) {
  this.wdb.emit(event, this.wallet, data, details);
  this.wallet.emit(event, data, details);
};

/**
 * Bucket
 * @returns {Bucket}
 */

TXDB.prototype.bucket = function bucket() {
  return this.db.bucket(this.prefix);
};

/**
 * Get.
 * @param {String} key
 */

TXDB.prototype.get = function get(key) {
  return this.bucket().get(key);
};

/**
 * Has.
 * @param {String} key
 */

TXDB.prototype.has = function has(key) {
  return this.bucket().has(key);
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.range = function range(options) {
  return this.bucket().range(options);
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.keys = function keys(options) {
  return this.bucket().keys(options);
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.values = function values(options) {
  return this.bucket().values(options);
};

/**
 * Get wallet path for output.
 * @param {Output} output
 * @returns {Promise} - Returns {@link Path}.
 */

TXDB.prototype.getPath = function getPath(output) {
  const hash = output.getHash('hex');

  if (!hash)
    return null;

  return this.wdb.getPath(this.wid, hash);
};

/**
 * Test whether path exists for output.
 * @param {Output} output
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasPath = function hasPath(output) {
  const hash = output.getHash('hex');

  if (!hash)
    return false;

  return this.wdb.hasPath(this.wid, hash);
};

/**
 * Save credit.
 * @param {Credit} credit
 * @param {Path} path
 */

TXDB.prototype.saveCredit = async function saveCredit(b, credit, path) {
  const {coin} = credit;

  b.put(layout.c(coin.hash, coin.index), credit.toRaw());
  b.put(layout.C(path.account, coin.hash, coin.index), null);

  return this.addOutpointMap(b, coin.hash, coin.index);
};

/**
 * Remove credit.
 * @param {Credit} credit
 * @param {Path} path
 */

TXDB.prototype.removeCredit = async function removeCredit(b, credit, path) {
  const {coin} = credit;

  b.del(layout.c(coin.hash, coin.index));
  b.del(layout.C(path.account, coin.hash, coin.index));

  return this.removeOutpointMap(b, coin.hash, coin.index);
};

/**
 * Spend credit.
 * @param {Credit} credit
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.spendCredit = function spendCredit(b, credit, tx, index) {
  const prevout = tx.inputs[index].prevout;
  const spender = Outpoint.fromTX(tx, index);
  b.put(layout.s(prevout.hash, prevout.index), spender.toRaw());
  b.put(layout.d(spender.hash, spender.index), credit.coin.toRaw());
};

/**
 * Unspend credit.
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.unspendCredit = function unspendCredit(b, tx, index) {
  const prevout = tx.inputs[index].prevout;
  const spender = Outpoint.fromTX(tx, index);
  b.del(layout.s(prevout.hash, prevout.index));
  b.del(layout.d(spender.hash, spender.index));
};

/**
 * Write input record.
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.writeInput = async function writeInput(b, tx, index) {
  const prevout = tx.inputs[index].prevout;
  const spender = Outpoint.fromTX(tx, index);
  b.put(layout.s(prevout.hash, prevout.index), spender.toRaw());
  return this.addOutpointMap(b, prevout.hash, prevout.index);
};

/**
 * Remove input record.
 * @param {TX} tx
 * @param {Number} index
 */

TXDB.prototype.removeInput = async function removeInput(b, tx, index) {
  const prevout = tx.inputs[index].prevout;
  b.del(layout.s(prevout.hash, prevout.index));
  return this.removeOutpointMap(b, prevout.hash, prevout.index);
};

/**
 * Update wallet balance.
 * @param {BalanceDelta} state
 */

TXDB.prototype.updateBalance = async function updateBalance(b, state) {
  const balance = await this.getWalletBalance();
  state.applyTo(balance);
  b.put(layout.R, balance.toRaw());
  return balance;
};

/**
 * Update account balance.
 * @param {Number} acct
 * @param {Balance} delta
 */

TXDB.prototype.updateAccountBalance = async function updateAccountBalance(b, acct, delta) {
  const balance = await this.getAccountBalance(acct);
  delta.applyTo(balance);
  b.put(layout.r(acct), balance.toRaw());
  return balance;
};

/**
 * Test a whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.getSpent = async function getSpent(hash, index) {
  const data = await this.get(layout.s(hash, index));

  if (!data)
    return null;

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
 * Append to global map.
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.addBlockMap = function addBlockMap(b, height) {
  return this.wdb.addBlockMap(b.batch, height, this.wid);
};

/**
 * Remove from global map.
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.removeBlockMap = function removeBlockMap(b, height) {
  return this.wdb.removeBlockMap(b.batch, height, this.wid);
};

/**
 * Append to global map.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.addTXMap = function addTXMap(b, hash) {
  return this.wdb.addTXMap(b.batch, hash, this.wid);
};

/**
 * Remove from global map.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.removeTXMap = function removeTXMap(b, hash) {
  return this.wdb.removeTXMap(b.batch, hash, this.wid);
};

/**
 * Append to global map.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise}
 */

TXDB.prototype.addOutpointMap = function addOutpointMap(b, hash, index) {
  return this.wdb.addOutpointMap(b.batch, hash, index, this.wid);
};

/**
 * Remove from global map.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise}
 */

TXDB.prototype.removeOutpointMap = function removeOutpointMap(b, hash, index) {
  return this.wdb.removeOutpointMap(b.batch, hash, index, this.wid);
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
  const data = await this.get(layout.b(height));

  if (!data)
    return null;

  return BlockRecord.fromRaw(data);
};

/**
 * Append to the global block record.
 * @param {Hash} hash
 * @param {BlockMeta} block
 * @returns {Promise}
 */

TXDB.prototype.addBlock = async function addBlock(b, hash, block) {
  const key = layout.b(block.height);
  const data = await this.get(key);

  if (!data) {
    const blk = BlockRecord.fromMeta(block);
    blk.add(hash);
    b.put(key, blk.toRaw());
    return;
  }

  const raw = Buffer.allocUnsafe(data.length + 32);
  data.copy(raw, 0);

  const size = raw.readUInt32LE(40, true);
  raw.writeUInt32LE(size + 1, 40, true);
  hash.copy(raw, data.length);

  b.put(key, raw);
};

/**
 * Remove from the global block record.
 * @param {Hash} hash
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.removeBlock = async function removeBlock(b, hash, height) {
  const key = layout.b(height);
  const data = await this.get(key);

  if (!data)
    return;

  const size = data.readUInt32LE(40, true);

  assert(size > 0);
  assert(data.slice(-32).equals(hash));

  if (size === 1) {
    b.del(key);
    return;
  }

  const raw = data.slice(0, -32);
  raw.writeUInt32LE(size - 1, 40, true);

  b.put(key, raw);
};

/**
 * Remove from the global block record.
 * @param {Hash} hash
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.spliceBlock = async function spliceBlock(b, hash, height) {
  const block = await this.getBlock(height);

  if (!block)
    return;

  if (!block.remove(hash))
    return;

  if (block.hashes.size === 0) {
    b.del(layout.b(height));
    return;
  }

  b.put(layout.b(height), block.toRaw());
};

/**
 * Add transaction without a batch.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.add = async function add(tx, block) {
  const hash = tx.hash('hex');
  const existing = await this.getTX(hash);

  assert(!tx.mutable, 'Cannot add mutable TX to wallet.');

  if (existing) {
    // Existing tx is already confirmed. Ignore.
    if (existing.height !== -1)
      return null;

    // The incoming tx won't confirm the
    // existing one anyway. Ignore.
    if (!block)
      return null;

    // Confirm transaction.
    return this.confirm(existing, block);
  }

  const wtx = TXRecord.fromTX(tx, block);

  if (!block) {
    // Potentially remove double-spenders.
    // Only remove if they're not confirmed.
    if (!await this.removeConflicts(tx, true))
      return null;
  } else {
    // Potentially remove double-spenders.
    await this.removeConflicts(tx, false);
  }

  // Finally we can do a regular insertion.
  return this.insert(wtx, block);
};

/**
 * Insert transaction.
 * @private
 * @param {TXRecord} wtx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

TXDB.prototype.insert = async function insert(wtx, block) {
  const b = this.bucket();
  const {tx, hash} = wtx;
  const height = block ? block.height : -1;
  const details = new Details(wtx, block);
  const state = new BalanceDelta();

  let own = false;

  if (!tx.isCoinbase()) {
    // We need to potentially spend some coins here.
    for (let i = 0; i < tx.inputs.length; i++) {
      const input = tx.inputs[i];
      const {hash, index} = input.prevout;
      const credit = await this.getCredit(hash, index);

      if (!credit) {
        // Watch all inputs for incoming txs.
        // This allows us to check for double spends.
        if (!block)
          await this.writeInput(b, tx, i);
        continue;
      }

      const coin = credit.coin;
      const path = await this.getPath(coin);
      assert(path);

      // Build the tx details object
      // as we go, for speed.
      details.setInput(i, path, coin);

      // Write an undo coin for the credit
      // and add it to the stxo set.
      this.spendCredit(b, credit, tx, i);

      // Unconfirmed balance should always
      // be updated as it reflects the on-chain
      // balance _and_ mempool balance assuming
      // everything in the mempool were to confirm.
      state.tx(path, 1);
      state.coin(path, -1);
      state.unconfirmed(path, -coin.value);

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
        await this.saveCredit(b, credit, path);
      } else {
        // If the tx is mined, we can safely
        // remove the coin being spent. This
        // coin will be indexed as an undo
        // coin so it can be reconnected
        // later during a reorg.
        state.confirmed(path, -coin.value);
        await this.removeCredit(b, credit, path);
      }

      own = true;
    }
  }

  // Potentially add coins to the utxo set.
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    const path = await this.getPath(output);

    if (!path)
      continue;

    details.setOutput(i, path);

    const credit = Credit.fromTX(tx, i, height);
    credit.own = own;

    state.tx(path, 1);
    state.coin(path, 1);
    state.unconfirmed(path, output.value);

    if (block)
      state.confirmed(path, output.value);

    await this.saveCredit(b, credit, path);
  }

  // If this didn't update any coins,
  // it's not our transaction.
  if (!state.updated())
    return null;

  // Save and index the transaction record.
  b.put(layout.t(hash), wtx.toRaw());
  b.put(layout.m(wtx.mtime, hash), null);

  if (!block)
    b.put(layout.p(hash), null);
  else
    b.put(layout.h(height, hash), null);

  // Do some secondary indexing for account-based
  // queries. This saves us a lot of time for
  // queries later.
  for (const [acct, delta] of state.accounts) {
    await this.updateAccountBalance(b, acct, delta);

    b.put(layout.T(acct, hash), null);
    b.put(layout.M(acct, wtx.mtime, hash), null);

    if (!block)
      b.put(layout.P(acct, hash), null);
    else
      b.put(layout.H(acct, height, hash), null);
  }

  // Update block records.
  if (block) {
    await this.addBlockMap(b, height);
    await this.addBlock(b, tx.hash(), block);
  } else {
    await this.addTXMap(b, hash);
  }

  // Commit the new state.
  const balance = await this.updateBalance(b, state);

  await b.write();

  // This transaction may unlock some
  // coins now that we've seen it.
  this.unlockTX(tx);

  // Emit events for potential local and
  // websocket listeners. Note that these
  // will only be emitted if the batch is
  // successfully written to disk.
  this.emit('tx', tx, details);
  this.emit('balance', balance);

  return details;
};

/**
 * Attempt to confirm a transaction.
 * @private
 * @param {TXRecord} wtx
 * @param {BlockMeta} block
 * @returns {Promise}
 */

TXDB.prototype.confirm = async function confirm(wtx, block) {
  const b = this.bucket();
  const {tx, hash} = wtx;
  const height = block.height;
  const details = new Details(wtx, block);
  const state = new BalanceDelta();

  wtx.setBlock(block);

  if (!tx.isCoinbase()) {
    const credits = await this.getSpentCredits(tx);

    // Potentially spend coins. Now that the tx
    // is mined, we can actually _remove_ coins
    // from the utxo state.
    for (let i = 0; i < tx.inputs.length; i++) {
      const input = tx.inputs[i];
      const {hash, index} = input.prevout;

      let resolved = false;

      // There may be new credits available
      // that we haven't seen yet.
      if (!credits[i]) {
        await this.removeInput(b, tx, i);

        const credit = await this.getCredit(hash, index);

        if (!credit)
          continue;

        // Add a spend record and undo coin
        // for the coin we now know is ours.
        // We don't need to remove the coin
        // since it was never added in the
        // first place.
        this.spendCredit(b, credit, tx, i);

        credits[i] = credit;
        resolved = true;
      }

      const credit = credits[i];
      const coin = credit.coin;

      assert(coin.height !== -1);

      const path = await this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      if (resolved) {
        state.coin(path, -1);
        state.unconfirmed(path, -coin.value);
      }

      // We can now safely remove the credit
      // entirely, now that we know it's also
      // been removed on-chain.
      state.confirmed(path, -coin.value);

      await this.removeCredit(b, credit, path);
    }
  }

  // Update credit heights, including undo coins.
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    const path = await this.getPath(output);

    if (!path)
      continue;

    details.setOutput(i, path);

    const credit = await this.getCredit(hash, i);
    assert(credit);

    // Credits spent in the mempool add an
    // undo coin for ease. If this credit is
    // spent in the mempool, we need to
    // update the undo coin's height.
    if (credit.spent)
      await this.updateSpentCoin(b, tx, i, height);

    // Update coin height and confirmed
    // balance. Save once again.
    state.confirmed(path, output.value);
    credit.coin.height = height;

    await this.saveCredit(b, credit, path);
  }

  // Save the new serialized transaction as
  // the block-related properties have been
  // updated. Also reindex for height.
  b.put(layout.t(hash), wtx.toRaw());
  b.del(layout.p(hash));
  b.put(layout.h(height, hash), null);

  // Secondary indexing also needs to change.
  for (const [acct, delta] of state.accounts) {
    await this.updateAccountBalance(b, acct, delta);
    b.del(layout.P(acct, hash));
    b.put(layout.H(acct, height, hash), null);
  }

  await this.removeTXMap(b, hash);
  await this.addBlockMap(b, height);
  await this.addBlock(b, tx.hash(), block);

  // Commit the new state. The balance has updated.
  const balance = await this.updateBalance(b, state);

  await b.write();

  this.unlockTX(tx);

  this.emit('confirmed', tx, details);
  this.emit('balance', balance);

  return details;
};

/**
 * Recursively remove a transaction
 * from the database.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.remove = async function remove(hash) {
  const wtx = await this.getTX(hash);

  if (!wtx)
    return null;

  return this.removeRecursive(wtx);
};

/**
 * Remove a transaction from the
 * database. Disconnect inputs.
 * @private
 * @param {TXRecord} wtx
 * @returns {Promise}
 */

TXDB.prototype.erase = async function erase(wtx, block) {
  const b = this.bucket();
  const {tx, hash} = wtx;
  const height = block ? block.height : -1;
  const details = new Details(wtx, block);
  const state = new BalanceDelta();

  if (!tx.isCoinbase()) {
    // We need to undo every part of the
    // state this transaction ever touched.
    // Start by getting the undo coins.
    const credits = await this.getSpentCredits(tx);

    for (let i = 0; i < tx.inputs.length; i++) {
      const credit = credits[i];

      if (!credit) {
        if (!block)
          await this.removeInput(b, tx, i);
        continue;
      }

      const coin = credit.coin;
      const path = await this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      // Recalculate the balance, remove
      // from stxo set, remove the undo
      // coin, and resave the credit.
      state.tx(path, -1);
      state.coin(path, 1);
      state.unconfirmed(path, coin.value);

      if (block)
        state.confirmed(path, coin.value);

      this.unspendCredit(b, tx, i);

      credit.spent = false;
      await this.saveCredit(b, credit, path);
    }
  }

  // We need to remove all credits
  // this transaction created.
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    const path = await this.getPath(output);

    if (!path)
      continue;

    details.setOutput(i, path);

    const credit = Credit.fromTX(tx, i, height);

    state.tx(path, -1);
    state.coin(path, -1);
    state.unconfirmed(path, -output.value);

    if (block)
      state.confirmed(path, -output.value);

    await this.removeCredit(b, credit, path);
  }

  // Remove the transaction data
  // itself as well as unindex.
  b.del(layout.t(hash));
  b.del(layout.m(wtx.mtime, hash));

  if (!block)
    b.del(layout.p(hash));
  else
    b.del(layout.h(height, hash));

  // Remove all secondary indexing.
  for (const [acct, delta] of state.accounts) {
    await this.updateAccountBalance(b, acct, delta);

    b.del(layout.T(acct, hash));
    b.del(layout.M(acct, wtx.mtime, hash));

    if (!block)
      b.del(layout.P(acct, hash));
    else
      b.del(layout.H(acct, height, hash));
  }

  // Update block records.
  if (block) {
    await this.removeBlockMap(b, height);
    await this.spliceBlock(b, hash, height);
  } else {
    await this.removeTXMap(b, hash);
  }

  // Update the transaction counter
  // and commit new state due to
  // balance change.
  const balance = await this.updateBalance(b, state);

  await b.write();

  this.emit('remove tx', tx, details);
  this.emit('balance', balance);

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
  const {tx, hash} = wtx;

  for (let i = 0; i < tx.outputs.length; i++) {
    const spent = await this.getSpent(hash, i);

    if (!spent)
      continue;

    // Remove all of the spender's spenders first.
    const stx = await this.getTX(spent.hash);

    assert(stx);

    await this.removeRecursive(stx);
  }

  // Remove the spender.
  return this.erase(wtx, wtx.getBlock());
};

/**
 * Revert a block.
 * @param {Number} height
 * @returns {Promise}
 */

TXDB.prototype.revert = async function revert(height) {
  const block = await this.getBlock(height);

  if (!block)
    return 0;

  const hashes = block.toArray();

  for (let i = hashes.length - 1; i >= 0; i--) {
    const hash = hashes[i];
    await this.unconfirm(hash);
  }

  return block.hashes.length;
};

/**
 * Unconfirm a transaction without a batch.
 * @private
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.unconfirm = async function unconfirm(hash) {
  const wtx = await this.getTX(hash);

  if (!wtx)
    return null;

  if (wtx.height === -1)
    return null;

  return this.disconnect(wtx, wtx.getBlock());
};

/**
 * Unconfirm a transaction. Necessary after a reorg.
 * @param {TXRecord} wtx
 * @returns {Promise}
 */

TXDB.prototype.disconnect = async function disconnect(wtx, block) {
  const b = this.bucket();
  const {tx, hash, height} = wtx;
  const details = new Details(wtx, block);
  const state = new BalanceDelta();

  assert(block);

  wtx.unsetBlock();

  if (!tx.isCoinbase()) {
    // We need to reconnect the coins. Start
    // by getting all of the undo coins we know
    // about.
    const credits = await this.getSpentCredits(tx);

    for (let i = 0; i < tx.inputs.length; i++) {
      const credit = credits[i];

      if (!credit) {
        await this.writeInput(b, tx, i);
        continue;
      }

      const coin = credit.coin;

      assert(coin.height !== -1);

      const path = await this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      state.confirmed(path, coin.value);

      // Resave the credit and mark it
      // as spent in the mempool instead.
      credit.spent = true;
      await this.saveCredit(b, credit, path);
    }
  }

  // We need to remove heights on
  // the credits and undo coins.
  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    const path = await this.getPath(output);

    if (!path)
      continue;

    const credit = await this.getCredit(hash, i);

    // Potentially update undo coin height.
    if (!credit) {
      await this.updateSpentCoin(b, tx, i, height);
      continue;
    }

    if (credit.spent)
      await this.updateSpentCoin(b, tx, i, height);

    details.setOutput(i, path);

    // Update coin height and confirmed
    // balance. Save once again.
    credit.coin.height = -1;

    state.confirmed(path, -output.value);

    await this.saveCredit(b, credit, path);
  }

  await this.addTXMap(b, hash);
  await this.removeBlockMap(b, height);
  await this.removeBlock(b, tx.hash(), height);

  // We need to update the now-removed
  // block properties and reindex due
  // to the height change.
  b.put(layout.t(hash), wtx.toRaw());
  b.put(layout.p(hash), null);
  b.del(layout.h(height, hash));

  // Secondary indexing also needs to change.
  for (const [acct, delta] of state.accounts) {
    await this.updateAccountBalance(b, acct, delta);
    b.put(layout.P(acct, hash), null);
    b.del(layout.H(acct, height, hash));
  }

  // Commit state due to unconfirmed
  // vs. confirmed balance change.
  const balance = await this.updateBalance(b, state);

  await b.write();

  this.emit('unconfirmed', tx, details);
  this.emit('balance', balance);

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
  const tx = wtx.tx;

  this.logger.warning('Handling conflicting tx: %s.', tx.txid());

  const details = await this.removeRecursive(wtx);

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
  if (tx.isCoinbase())
    return true;

  const txid = tx.hash('hex');
  const spends = [];

  // Gather all spent records first.
  for (const {prevout} of tx.inputs) {
    const {hash, index} = prevout;

    // Is it already spent?
    const spent = await this.getSpent(hash, index);

    if (!spent)
      continue;

    // Did _we_ spend it?
    if (spent.hash === txid)
      continue;

    const spender = await this.getTX(spent.hash);
    assert(spender);

    if (conf && spender.height !== -1)
      return false;

    spends.push(spender);
  }

  // Once we know we're not going to
  // screw things up, remove the double
  // spenders.
  for (const spender of spends) {
    // Remove the double spender.
    await this.removeConflict(spender);
  }

  return true;
};

/**
 * Lock all coins in a transaction.
 * @param {TX} tx
 */

TXDB.prototype.lockTX = function lockTX(tx) {
  if (tx.isCoinbase())
    return;

  for (const input of tx.inputs)
    this.lockCoin(input.prevout);
};

/**
 * Unlock all coins in a transaction.
 * @param {TX} tx
 */

TXDB.prototype.unlockTX = function unlockTX(tx) {
  if (tx.isCoinbase())
    return;

  for (const input of tx.inputs)
    this.unlockCoin(input.prevout);
};

/**
 * Lock a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.lockCoin = function lockCoin(coin) {
  const key = coin.toKey();
  this.locked.add(key);
};

/**
 * Unlock a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.unlockCoin = function unlockCoin(coin) {
  const key = coin.toKey();
  return this.locked.delete(key);
};

/**
 * Test locked status of a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.isLocked = function isLocked(coin) {
  const key = coin.toKey();
  return this.locked.has(key);
};

/**
 * Filter array of coins or outpoints
 * for only unlocked ones.
 * @param {Coin[]|Outpoint[]}
 * @returns {Array}
 */

TXDB.prototype.filterLocked = function filterLocked(coins) {
  const out = [];

  for (const coin of coins) {
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
  const outpoints = [];

  for (const key of this.locked.keys())
    outpoints.push(Outpoint.fromKey(key));

  return outpoints;
};

/**
 * Get hashes of all transactions in the database.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountHistoryHashes = function getAccountHistoryHashes(acct) {
  assert(typeof acct === 'number');
  return this.keys({
    gte: layout.T(acct, encoding.NULL_HASH),
    lte: layout.T(acct, encoding.HIGH_HASH),
    parse: (key) => {
      const [, hash] = layout.Tt(key);
      return hash;
    }
  });
};

/**
 * Get hashes of all transactions in the database.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHistoryHashes = function getHistoryHashes(acct) {
  assert(typeof acct === 'number');

  if (acct !== -1)
    return this.getAccountHistoryHashes(acct);

  return this.keys({
    gte: layout.t(encoding.NULL_HASH),
    lte: layout.t(encoding.HIGH_HASH),
    parse: key => layout.tt(key)
  });
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountPendingHashes = function getAccountPendingHashes(acct) {
  assert(typeof acct === 'number');
  return this.keys({
    gte: layout.P(acct, encoding.NULL_HASH),
    lte: layout.P(acct, encoding.HIGH_HASH),
    parse: (key) => {
      const [, hash] = layout.Pp(key);
      return hash;
    }
  });
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getPendingHashes = function getPendingHashes(acct) {
  assert(typeof acct === 'number');

  if (acct !== -1)
    return this.getAccountPendingHashes(acct);

  return this.keys({
    gte: layout.p(encoding.NULL_HASH),
    lte: layout.p(encoding.HIGH_HASH),
    parse: key => layout.pp(key)
  });
};

/**
 * Get all coin hashes in the database.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountOutpoints = function getAccountOutpoints(acct) {
  assert(typeof acct === 'number');
  return this.keys({
    gte: layout.C(acct, encoding.NULL_HASH, 0),
    lte: layout.C(acct, encoding.HIGH_HASH, 0xffffffff),
    parse: (key) => {
      const [, hash, index] = layout.Cc(key);
      return new Outpoint(hash, index);
    }
  });
};

/**
 * Get all coin hashes in the database.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getOutpoints = function getOutpoints(acct) {
  assert(typeof acct === 'number');

  if (acct !== -1)
    return this.getAccountOutpoints(acct);

  return this.keys({
    gte: layout.c(encoding.NULL_HASH, 0),
    lte: layout.c(encoding.HIGH_HASH, 0xffffffff),
    parse: (key) => {
      const [hash, index] = layout.cc(key);
      return new Outpoint(hash, index);
    }
  });
};

/**
 * Get TX hashes by height range.
 * @param {Number} acct
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountHeightRangeHashes = function getAccountHeightRangeHashes(acct, options) {
  assert(typeof acct === 'number');

  const start = options.start || 0;
  const end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.H(acct, start, encoding.NULL_HASH),
    lte: layout.H(acct, end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      const [,, hash] = layout.Hh(key);
      return hash;
    }
  });
};

/**
 * Get TX hashes by height range.
 * @param {Number} acct
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHeightRangeHashes = function getHeightRangeHashes(acct, options) {
  assert(typeof acct === 'number');

  if (acct !== -1)
    return this.getAccountHeightRangeHashes(acct, options);

  const start = options.start || 0;
  const end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.h(start, encoding.NULL_HASH),
    lte: layout.h(end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      const [, hash] = layout.hh(key);
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
 * @param {Number} acct
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountRangeHashes = function getAccountRangeHashes(acct, options) {
  assert(typeof acct === 'number');

  const start = options.start || 0;
  const end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.M(acct, start, encoding.NULL_HASH),
    lte: layout.M(acct, end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      const [,, hash] = layout.Mm(key);
      return hash;
    }
  });
};

/**
 * Get TX hashes by timestamp range.
 * @param {Number} acct
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getRangeHashes = function getRangeHashes(acct, options) {
  assert(typeof acct === 'number');

  if (acct !== -1)
    return this.getAccountRangeHashes(acct, options);

  const start = options.start || 0;
  const end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.m(start, encoding.NULL_HASH),
    lte: layout.m(end, encoding.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: (key) => {
      const [, hash] = layout.mm(key);
      return hash;
    }
  });
};

/**
 * Get transactions by timestamp range.
 * @param {Number} acct
 * @param {Object} options
 * @param {Number} options.start - Start time.
 * @param {Number} options.end - End time.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getRange = async function getRange(acct, options) {
  const hashes = await this.getRangeHashes(acct, options);
  const txs = [];

  for (const hash of hashes) {
    const tx = await this.getTX(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Get last N transactions.
 * @param {Number} acct
 * @param {Number} limit - Max number of transactions.
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getLast = function getLast(acct, limit) {
  return this.getRange(acct, {
    start: 0,
    end: 0xffffffff,
    reverse: true,
    limit: limit || 10
  });
};

/**
 * Get all transactions.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getHistory = function getHistory(acct) {
  assert(typeof acct === 'number');

  // Slow case
  if (acct !== -1)
    return this.getAccountHistory(acct);

  // Fast case
  return this.values({
    gte: layout.t(encoding.NULL_HASH),
    lte: layout.t(encoding.HIGH_HASH),
    parse: TXRecord.fromRaw
  });
};

/**
 * Get all acct transactions.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getAccountHistory = async function getAccountHistory(acct) {
  const hashes = await this.getHistoryHashes(acct);
  const txs = [];

  for (const hash of hashes) {
    const tx = await this.getTX(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Get unconfirmed transactions.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getPending = async function getPending(acct) {
  const hashes = await this.getPendingHashes(acct);
  const txs = [];

  for (const hash of hashes) {
    const tx = await this.getTX(hash);
    assert(tx);
    txs.push(tx);
  }

  return txs;
};

/**
 * Get coins.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getCredits = function getCredits(acct) {
  assert(typeof acct === 'number');

  // Slow case
  if (acct !== -1)
    return this.getAccountCredits(acct);

  // Fast case
  return this.range({
    gte: layout.c(encoding.NULL_HASH, 0x00000000),
    lte: layout.c(encoding.HIGH_HASH, 0xffffffff),
    parse: (key, value) => {
      const [hash, index] = layout.cc(key);
      const credit = Credit.fromRaw(value);
      credit.coin.hash = hash;
      credit.coin.index = index;
      return credit;
    }
  });
};

/**
 * Get coins by account.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCredits = async function getAccountCredits(acct) {
  const outpoints = await this.getOutpoints(acct);
  const credits = [];

  for (const {hash, index} of outpoints) {
    const credit = await this.getCredit(hash, index);
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
  if (tx.isCoinbase())
    return [];

  const hash = tx.hash('hex');
  const credits = [];

  for (let i = 0; i < tx.inputs.length; i++)
    credits.push(null);

  await this.range({
    gte: layout.d(hash, 0x00000000),
    lte: layout.d(hash, 0xffffffff),
    parse: (key, value) => {
      const [, index] = layout.dd(key);
      const coin = Coin.fromRaw(value);
      const input = tx.inputs[index];
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
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getCoins = async function getCoins(acct) {
  const credits = await this.getCredits(acct);
  const coins = [];

  for (const credit of credits) {
    if (credit.spent)
      continue;

    coins.push(credit.coin);
  }

  return coins;
};

/**
 * Get coins by account.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCoins = async function getAccountCoins(acct) {
  const credits = await this.getAccountCredits(acct);
  const coins = [];

  for (const credit of credits) {
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
  if (tx.isCoinbase())
    return [];

  const credits = await this.getSpentCredits(tx);
  const coins = [];

  for (const credit of credits) {
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
  const view = new CoinView();

  if (tx.isCoinbase())
    return view;

  for (const {prevout} of tx.inputs) {
    const {hash, index} = prevout;
    const coin = await this.getCoin(hash, index);

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
  const view = new CoinView();

  if (tx.isCoinbase())
    return view;

  const coins = await this.getSpentCoins(tx);

  for (const coin of coins) {
    if (!coin)
      continue;

    view.addCoin(coin);
  }

  return view;
};

/**
 * Get transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.getTX = async function getTX(hash) {
  const raw = await this.get(layout.t(hash));

  if (!raw)
    return null;

  return TXRecord.fromRaw(raw);
};

/**
 * Get transaction details.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXDetails}.
 */

TXDB.prototype.getDetails = async function getDetails(hash) {
  const wtx = await this.getTX(hash);

  if (!wtx)
    return null;

  return this.toDetails(wtx);
};

/**
 * Convert transaction to transaction details.
 * @param {TXRecord[]} wtxs
 * @returns {Promise}
 */

TXDB.prototype.toDetails = async function toDetails(wtxs) {
  const out = [];

  if (!Array.isArray(wtxs))
    return this._toDetails(wtxs);

  for (const wtx of wtxs) {
    const details = await this._toDetails(wtx);

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
  const tx = wtx.tx;
  const block = wtx.getBlock();
  const details = new Details(wtx, block);
  const coins = await this.getSpentCoins(tx);

  for (let i = 0; i < tx.inputs.length; i++) {
    const coin = coins[i];
    let path = null;

    if (coin)
      path = await this.getPath(coin);

    details.setInput(i, path, coin);
  }

  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];
    const path = await this.getPath(output);
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
  const credit = await this.getCredit(hash, index);

  if (!credit)
    return null;

  return credit.coin;
};

/**
 * Get coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getCredit = async function getCredit(hash, index) {
  const data = await this.get(layout.c(hash, index));

  if (!data)
    return null;

  const credit = Credit.fromRaw(data);
  credit.coin.hash = hash;
  credit.coin.index = index;

  return credit;
};

/**
 * Get spender coin.
 * @param {Outpoint} spent
 * @param {Outpoint} prevout
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getSpentCoin = async function getSpentCoin(spent, prevout) {
  const data = await this.get(layout.d(spent.hash, spent.index));

  if (!data)
    return null;

  const coin = Coin.fromRaw(data);
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

TXDB.prototype.updateSpentCoin = async function updateSpentCoin(b, tx, index, height) {
  const prevout = Outpoint.fromTX(tx, index);
  const spent = await this.getSpent(prevout.hash, prevout.index);

  if (!spent)
    return;

  const coin = await this.getSpentCoin(spent, prevout);

  if (!coin)
    return;

  coin.height = height;

  b.put(layout.d(spent.hash, spent.index), coin.toRaw());
};

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasCoin = async function hasCoin(hash, index) {
  return this.has(layout.c(hash, index));
};

/**
 * Calculate balance.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getBalance = async function getBalance(acct) {
  assert(typeof acct === 'number');

  if (acct !== -1)
    return this.getAccountBalance(acct);

  return this.getWalletBalance();
};

/**
 * Calculate balance.
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getWalletBalance = async function getWalletBalance() {
  const data = await this.get(layout.R);

  if (!data)
    return new Balance();

  return Balance.fromRaw(-1, data);
};

/**
 * Calculate balance by account.
 * @param {Number} acct
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getAccountBalance = async function getAccountBalance(acct) {
  const data = await this.get(layout.r(acct));

  if (!data)
    return new Balance(acct);

  return Balance.fromRaw(acct, data);
};

/**
 * Zap pending transactions older than `age`.
 * @param {Number} acct
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @returns {Promise}
 */

TXDB.prototype.zap = async function zap(acct, age) {
  assert(util.isU32(age));

  const now = util.now();

  const txs = await this.getRange(acct, {
    start: 0,
    end: now - age
  });

  const hashes = [];

  for (const wtx of txs) {
    if (wtx.height !== -1)
      continue;

    assert(now - wtx.mtime >= age);

    this.logger.debug('Zapping TX: %s (%d)',
      wtx.tx.txid(), this.wid);

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
  const result = await this.has(layout.p(hash));

  if (!result)
    throw new Error('TX not eligible.');

  return this.remove(hash);
};

/**
 * Balance
 * @alias module:wallet.Balance
 * @constructor
 * @param {Number} account
 */

function Balance(acct = -1) {
  if (!(this instanceof Balance))
    return new Balance(acct);

  assert(typeof acct === 'number');

  this.account = acct;
  this.tx = 0;
  this.coin = 0;
  this.unconfirmed = 0;
  this.confirmed = 0;
}

/**
 * Apply delta.
 * @param {Balance} balance
 */

Balance.prototype.applyTo = function applyTo(balance) {
  balance.tx += this.tx;
  balance.coin += this.coin;
  balance.unconfirmed += this.unconfirmed;
  balance.confirmed += this.confirmed;

  assert(balance.tx >= 0);
  assert(balance.coin >= 0);
  assert(balance.unconfirmed >= 0);
  assert(balance.confirmed >= 0);
};

/**
 * Serialize balance.
 * @returns {Buffer}
 */

Balance.prototype.toRaw = function toRaw() {
  const bw = new StaticWriter(32);

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

Balance.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);
  this.tx = br.readU64();
  this.coin = br.readU64();
  this.unconfirmed = br.readU64();
  this.confirmed = br.readU64();
  return this;
};

/**
 * Instantiate balance from serialized data.
 * @param {Number} acct
 * @param {Buffer} data
 * @returns {TXDBState}
 */

Balance.fromRaw = function fromRaw(acct, data) {
  return new Balance(acct).fromRaw(data);
};

/**
 * Convert balance to a more json-friendly object.
 * @param {Boolean?} minimal
 * @returns {Object}
 */

Balance.prototype.toJSON = function toJSON(minimal) {
  return {
    account: !minimal ? this.account : undefined,
    tx: this.tx,
    coin: this.coin,
    unconfirmed: this.unconfirmed,
    confirmed: this.confirmed
  };
};

/**
 * Inspect balance.
 * @param {String}
 */

Balance.prototype.inspect = function inspect() {
  return '<Balance'
    + ` tx=${this.tx}`
    + ` coin=${this.coin}`
    + ` unconfirmed=${Amount.btc(this.unconfirmed)}`
    + ` confirmed=${Amount.btc(this.confirmed)}`
    + '>';
};

/**
 * Balance Delta
 * @constructor
 * @ignore
 */

function BalanceDelta() {
  this.wallet = new Balance();
  this.accounts = new Map();
}

BalanceDelta.prototype.updated = function updated() {
  return this.wallet.tx !== 0;
};

BalanceDelta.prototype.applyTo = function applyTo(balance) {
  this.wallet.applyTo(balance);
};

BalanceDelta.prototype.get = function get(path) {
  if (!this.accounts.has(path.account))
    this.accounts.set(path.account, new Balance());

  return this.accounts.get(path.account);
};

BalanceDelta.prototype.tx = function tx(path, value) {
  const account = this.get(path);
  account.tx = value;
  this.wallet.tx = value;
};

BalanceDelta.prototype.coin = function coin(path, value) {
  const account = this.get(path);
  account.coin += value;
  this.wallet.coin += value;
};

BalanceDelta.prototype.unconfirmed = function unconfirmed(path, value) {
  const account = this.get(path);
  account.unconfirmed += value;
  this.wallet.unconfirmed += value;
};

BalanceDelta.prototype.confirmed = function confirmed(path, value) {
  const account = this.get(path);
  account.confirmed += value;
  this.wallet.confirmed += value;
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
  const br = new BufferReader(data);
  this.coin.fromReader(br);
  this.spent = br.readU8() === 1;
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
  const size = this.getSize();
  const bw = new StaticWriter(size);
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

function Details(wtx, block) {
  if (!(this instanceof Details))
    return new Details(wtx, block);

  this.hash = wtx.hash;
  this.tx = wtx.tx;
  this.mtime = wtx.mtime;
  this.size = this.tx.getSize();
  this.vsize = this.tx.getVirtualSize();

  this.block = null;
  this.height = -1;
  this.time = 0;

  if (block) {
    this.block = block.hash;
    this.height = block.height;
    this.time = block.time;
  }

  this.inputs = [];
  this.outputs = [];

  this.init();
}

/**
 * Initialize transaction details.
 * @private
 */

Details.prototype.init = function init() {
  for (const input of this.tx.inputs) {
    const member = new DetailsMember();
    member.address = input.getAddress();
    this.inputs.push(member);
  }

  for (const output of this.tx.outputs) {
    const member = new DetailsMember();
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
  const member = this.inputs[i];

  if (coin) {
    member.value = coin.value;
    member.address = coin.getAddress();
  }

  if (path)
    member.path = path;
};

/**
 * Add necessary info to output member.
 * @param {Number} i
 * @param {Path} path
 */

Details.prototype.setOutput = function setOutput(i, path) {
  const member = this.outputs[i];

  if (path)
    member.path = path;
};

/**
 * Calculate confirmations.
 * @returns {Number}
 */

Details.prototype.getDepth = function getDepth(height) {
  if (this.height === -1)
    return 0;

  if (height == null)
    return 0;

  const depth = height - this.height;

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

  for (const input of this.inputs) {
    if (!input.path)
      return 0;

    inputValue += input.value;
  }

  for (const output of this.outputs)
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

Details.prototype.toJSON = function toJSON(network, height) {
  const fee = this.getFee();
  const rate = this.getRate(fee);

  return {
    hash: util.revHex(this.hash),
    height: this.height,
    block: this.block ? util.revHex(this.block) : null,
    time: this.time,
    mtime: this.mtime,
    date: util.date(this.time),
    mdate: util.date(this.mtime),
    size: this.size,
    virtualSize: this.vsize,
    fee: fee,
    rate: rate,
    confirmations: this.getDepth(height),
    inputs: this.inputs.map((input) => {
      return input.getJSON(network);
    }),
    outputs: this.outputs.map((output) => {
      return output.getJSON(network);
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
 * @param {Number} time
 */

function BlockRecord(hash, height, time) {
  if (!(this instanceof BlockRecord))
    return new BlockRecord(hash, height, time);

  this.hash = hash || encoding.NULL_HASH;
  this.height = height != null ? height : -1;
  this.time = time || 0;
  this.hashes = new Set();
}

/**
 * Add transaction to block record.
 * @param {Hash} hash
 * @returns {Boolean}
 */

BlockRecord.prototype.add = function add(hash) {
  if (this.hashes.has(hash))
    return false;

  this.hashes.add(hash);

  return true;
};

/**
 * Remove transaction from block record.
 * @param {Hash} hash
 * @returns {Boolean}
 */

BlockRecord.prototype.remove = function remove(hash) {
  return this.hashes.delete(hash);
};

/**
 * Instantiate wallet block from serialized tip data.
 * @private
 * @param {Buffer} data
 */

BlockRecord.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);

  this.hash = br.readHash('hex');
  this.height = br.readU32();
  this.time = br.readU32();

  const count = br.readU32();

  for (let i = 0; i < count; i++) {
    const hash = br.readHash('hex');
    this.hashes.add(hash);
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
  return 44 + this.hashes.size * 32;
};

/**
 * Serialize the wallet block as a tip (hash and height).
 * @returns {Buffer}
 */

BlockRecord.prototype.toRaw = function toRaw() {
  const size = this.getSize();
  const bw = new StaticWriter(size);

  bw.writeHash(this.hash);
  bw.writeU32(this.height);
  bw.writeU32(this.time);

  bw.writeU32(this.hashes.size);

  for (const hash of this.hashes)
    bw.writeHash(hash);

  return bw.render();
};

/**
 * Convert hashes set to an array.
 * @returns {Hash[]}
 */

BlockRecord.prototype.toArray = function toArray() {
  const hashes = [];
  for (const hash of this.hashes)
    hashes.push(hash);
  return hashes;
};

/**
 * Convert the block to a more json-friendly object.
 * @returns {Object}
 */

BlockRecord.prototype.toJSON = function toJSON() {
  return {
    hash: util.revHex(this.hash),
    height: this.height,
    time: this.time,
    hashes: this.toArray().map(util.revHex)
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
  this.time = block.time;
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
 * Expose
 */

module.exports = TXDB;
