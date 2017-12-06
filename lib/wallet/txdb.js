/*!
 * txdb.js - persistent transaction pool
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const util = require('../utils/util');
const Amount = require('../btc/amount');
const CoinView = require('../coins/coinview');
const Coin = require('../primitives/coin');
const Outpoint = require('../primitives/outpoint');
const records = require('./records');
const layout = require('./layout').txdb;
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');
const {TXRecord} = records;

/**
 * TXDB
 * @alias module:wallet.TXDB
 */

class TXDB {
  /**
   * Create a TXDB.
   * @constructor
   * @param {WalletDB} wdb
   */

  constructor(wdb, wid) {
    this.wdb = wdb;
    this.db = wdb.db;
    this.logger = wdb.logger;

    this.wid = wid || 0;
    this.bucket = null;
    this.wallet = null;
    this.locked = new Set();
  }

  /**
   * Open TXDB.
   * @returns {Promise}
   */

  async open(wallet) {
    const prefix = layout.prefix.build(wallet.wid);

    this.wid = wallet.wid;
    this.bucket = this.db.bucket(prefix);
    this.wallet = wallet;
  }

  /**
   * Emit transaction event.
   * @private
   * @param {String} event
   * @param {Object} data
   * @param {Details} details
   */

  emit(event, data, details) {
    this.wdb.emit(event, this.wallet, data, details);
    this.wallet.emit(event, data, details);
  }

  /**
   * Get wallet path for output.
   * @param {Output} output
   * @returns {Promise} - Returns {@link Path}.
   */

  getPath(output) {
    const hash = output.getHash('hex');

    if (!hash)
      return null;

    return this.wdb.getPath(this.wid, hash);
  }

  /**
   * Test whether path exists for output.
   * @param {Output} output
   * @returns {Promise} - Returns Boolean.
   */

  hasPath(output) {
    const hash = output.getHash('hex');

    if (!hash)
      return false;

    return this.wdb.hasPath(this.wid, hash);
  }

  /**
   * Save credit.
   * @param {Credit} credit
   * @param {Path} path
   */

  async saveCredit(b, credit, path) {
    const {coin} = credit;

    b.put(layout.c.build(coin.hash, coin.index), credit.toRaw());
    b.put(layout.C.build(path.account, coin.hash, coin.index), null);

    return this.addOutpointMap(b, coin.hash, coin.index);
  }

  /**
   * Remove credit.
   * @param {Credit} credit
   * @param {Path} path
   */

  async removeCredit(b, credit, path) {
    const {coin} = credit;

    b.del(layout.c.build(coin.hash, coin.index));
    b.del(layout.C.build(path.account, coin.hash, coin.index));

    return this.removeOutpointMap(b, coin.hash, coin.index);
  }

  /**
   * Spend credit.
   * @param {Credit} credit
   * @param {TX} tx
   * @param {Number} index
   */

  spendCredit(b, credit, tx, index) {
    const prevout = tx.inputs[index].prevout;
    const spender = Outpoint.fromTX(tx, index);
    b.put(layout.s.build(prevout.hash, prevout.index), spender.toRaw());
    b.put(layout.d.build(spender.hash, spender.index), credit.coin.toRaw());
  }

  /**
   * Unspend credit.
   * @param {TX} tx
   * @param {Number} index
   */

  unspendCredit(b, tx, index) {
    const prevout = tx.inputs[index].prevout;
    const spender = Outpoint.fromTX(tx, index);
    b.del(layout.s.build(prevout.hash, prevout.index));
    b.del(layout.d.build(spender.hash, spender.index));
  }

  /**
   * Write input record.
   * @param {TX} tx
   * @param {Number} index
   */

  async writeInput(b, tx, index) {
    const prevout = tx.inputs[index].prevout;
    const spender = Outpoint.fromTX(tx, index);
    b.put(layout.s.build(prevout.hash, prevout.index), spender.toRaw());
    return this.addOutpointMap(b, prevout.hash, prevout.index);
  }

  /**
   * Remove input record.
   * @param {TX} tx
   * @param {Number} index
   */

  async removeInput(b, tx, index) {
    const prevout = tx.inputs[index].prevout;
    b.del(layout.s.build(prevout.hash, prevout.index));
    return this.removeOutpointMap(b, prevout.hash, prevout.index);
  }

  /**
   * Update wallet balance.
   * @param {BalanceDelta} state
   */

  async updateBalance(b, state) {
    const balance = await this.getWalletBalance();
    state.applyTo(balance);
    b.put(layout.R.build(), balance.toRaw());
    return balance;
  }

  /**
   * Update account balance.
   * @param {Number} acct
   * @param {Balance} delta
   */

  async updateAccountBalance(b, acct, delta) {
    const balance = await this.getAccountBalance(acct);
    delta.applyTo(balance);
    b.put(layout.r.build(acct), balance.toRaw());
    return balance;
  }

  /**
   * Test a whether a coin has been spent.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns Boolean.
   */

  async getSpent(hash, index) {
    const data = await this.bucket.get(layout.s.build(hash, index));

    if (!data)
      return null;

    return Outpoint.fromRaw(data);
  }

  /**
   * Test a whether a coin has been spent.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns Boolean.
   */

  isSpent(hash, index) {
    return this.bucket.has(layout.s.build(hash, index));
  }

  /**
   * Append to global map.
   * @param {Number} height
   * @returns {Promise}
   */

  addBlockMap(b, height) {
    return this.wdb.addBlockMap(b.root(), height, this.wid);
  }

  /**
   * Remove from global map.
   * @param {Number} height
   * @returns {Promise}
   */

  removeBlockMap(b, height) {
    return this.wdb.removeBlockMap(b.root(), height, this.wid);
  }

  /**
   * Append to global map.
   * @param {Hash} hash
   * @returns {Promise}
   */

  addTXMap(b, hash) {
    return this.wdb.addTXMap(b.root(), hash, this.wid);
  }

  /**
   * Remove from global map.
   * @param {Hash} hash
   * @returns {Promise}
   */

  removeTXMap(b, hash) {
    return this.wdb.removeTXMap(b.root(), hash, this.wid);
  }

  /**
   * Append to global map.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise}
   */

  addOutpointMap(b, hash, index) {
    return this.wdb.addOutpointMap(b.root(), hash, index, this.wid);
  }

  /**
   * Remove from global map.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise}
   */

  removeOutpointMap(b, hash, index) {
    return this.wdb.removeOutpointMap(b.root(), hash, index, this.wid);
  }

  /**
   * List block records.
   * @returns {Promise}
   */

  getBlocks() {
    return this.bucket.keys({
      gte: layout.b.min(),
      lte: layout.b.max(),
      parse: key => layout.b.parse(key)
    });
  }

  /**
   * Get block record.
   * @param {Number} height
   * @returns {Promise}
   */

  async getBlock(height) {
    const data = await this.bucket.get(layout.b.build(height));

    if (!data)
      return null;

    return BlockRecord.fromRaw(data);
  }

  /**
   * Append to the global block record.
   * @param {Hash} hash
   * @param {BlockMeta} block
   * @returns {Promise}
   */

  async addBlock(b, hash, block) {
    const key = layout.b.build(block.height);
    const data = await this.bucket.get(key);

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
  }

  /**
   * Remove from the global block record.
   * @param {Hash} hash
   * @param {Number} height
   * @returns {Promise}
   */

  async removeBlock(b, hash, height) {
    const key = layout.b.build(height);
    const data = await this.bucket.get(key);

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
  }

  /**
   * Remove from the global block record.
   * @param {Hash} hash
   * @param {Number} height
   * @returns {Promise}
   */

  async spliceBlock(b, hash, height) {
    const block = await this.getBlock(height);

    if (!block)
      return;

    if (!block.remove(hash))
      return;

    if (block.hashes.size === 0) {
      b.del(layout.b.build(height));
      return;
    }

    b.put(layout.b.build(height), block.toRaw());
  }

  /**
   * Add transaction without a batch.
   * @private
   * @param {TX} tx
   * @returns {Promise}
   */

  async add(tx, block) {
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
  }

  /**
   * Insert transaction.
   * @private
   * @param {TXRecord} wtx
   * @param {BlockMeta} block
   * @returns {Promise}
   */

  async insert(wtx, block) {
    const b = this.bucket.batch();
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
    b.put(layout.t.build(hash), wtx.toRaw());
    b.put(layout.m.build(wtx.mtime, hash), null);

    if (!block)
      b.put(layout.p.build(hash), null);
    else
      b.put(layout.h.build(height, hash), null);

    // Do some secondary indexing for account-based
    // queries. This saves us a lot of time for
    // queries later.
    for (const [acct, delta] of state.accounts) {
      await this.updateAccountBalance(b, acct, delta);

      b.put(layout.T.build(acct, hash), null);
      b.put(layout.M.build(acct, wtx.mtime, hash), null);

      if (!block)
        b.put(layout.P.build(acct, hash), null);
      else
        b.put(layout.H.build(acct, height, hash), null);
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
  }

  /**
   * Attempt to confirm a transaction.
   * @private
   * @param {TXRecord} wtx
   * @param {BlockMeta} block
   * @returns {Promise}
   */

  async confirm(wtx, block) {
    const b = this.bucket.batch();
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
    b.put(layout.t.build(hash), wtx.toRaw());
    b.del(layout.p.build(hash));
    b.put(layout.h.build(height, hash), null);

    // Secondary indexing also needs to change.
    for (const [acct, delta] of state.accounts) {
      await this.updateAccountBalance(b, acct, delta);
      b.del(layout.P.build(acct, hash));
      b.put(layout.H.build(acct, height, hash), null);
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
  }

  /**
   * Recursively remove a transaction
   * from the database.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async remove(hash) {
    const wtx = await this.getTX(hash);

    if (!wtx)
      return null;

    return this.removeRecursive(wtx);
  }

  /**
   * Remove a transaction from the
   * database. Disconnect inputs.
   * @private
   * @param {TXRecord} wtx
   * @returns {Promise}
   */

  async erase(wtx, block) {
    const b = this.bucket.batch();
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
    b.del(layout.t.build(hash));
    b.del(layout.m.build(wtx.mtime, hash));

    if (!block)
      b.del(layout.p.build(hash));
    else
      b.del(layout.h.build(height, hash));

    // Remove all secondary indexing.
    for (const [acct, delta] of state.accounts) {
      await this.updateAccountBalance(b, acct, delta);

      b.del(layout.T.build(acct, hash));
      b.del(layout.M.build(acct, wtx.mtime, hash));

      if (!block)
        b.del(layout.P.build(acct, hash));
      else
        b.del(layout.H.build(acct, height, hash));
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
  }

  /**
   * Remove a transaction and recursively
   * remove all of its spenders.
   * @private
   * @param {TXRecord} wtx
   * @returns {Promise}
   */

  async removeRecursive(wtx) {
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
  }

  /**
   * Revert a block.
   * @param {Number} height
   * @returns {Promise}
   */

  async revert(height) {
    const block = await this.getBlock(height);

    if (!block)
      return 0;

    const hashes = block.toArray();

    for (let i = hashes.length - 1; i >= 0; i--) {
      const hash = hashes[i];
      await this.unconfirm(hash);
    }

    return hashes.length;
  }

  /**
   * Unconfirm a transaction without a batch.
   * @private
   * @param {Hash} hash
   * @returns {Promise}
   */

  async unconfirm(hash) {
    const wtx = await this.getTX(hash);

    if (!wtx)
      return null;

    if (wtx.height === -1)
      return null;

    return this.disconnect(wtx, wtx.getBlock());
  }

  /**
   * Unconfirm a transaction. Necessary after a reorg.
   * @param {TXRecord} wtx
   * @returns {Promise}
   */

  async disconnect(wtx, block) {
    const b = this.bucket.batch();
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
    b.put(layout.t.build(hash), wtx.toRaw());
    b.put(layout.p.build(hash), null);
    b.del(layout.h.build(height, hash));

    // Secondary indexing also needs to change.
    for (const [acct, delta] of state.accounts) {
      await this.updateAccountBalance(b, acct, delta);
      b.put(layout.P.build(acct, hash), null);
      b.del(layout.H.build(acct, height, hash));
    }

    // Commit state due to unconfirmed
    // vs. confirmed balance change.
    const balance = await this.updateBalance(b, state);

    await b.write();

    this.emit('unconfirmed', tx, details);
    this.emit('balance', balance);

    return details;
  }

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

  async removeConflict(wtx) {
    const tx = wtx.tx;

    this.logger.warning('Handling conflicting tx: %s.', tx.txid());

    const details = await this.removeRecursive(wtx);

    this.logger.warning('Removed conflict: %s.', tx.txid());

    // Emit the _removed_ transaction.
    this.emit('conflict', tx, details);

    return details;
  }

  /**
   * Retrieve coins for own inputs, remove
   * double spenders, and verify inputs.
   * @private
   * @param {TX} tx
   * @returns {Promise}
   */

  async removeConflicts(tx, conf) {
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
  }

  /**
   * Lock all coins in a transaction.
   * @param {TX} tx
   */

  lockTX(tx) {
    if (tx.isCoinbase())
      return;

    for (const input of tx.inputs)
      this.lockCoin(input.prevout);
  }

  /**
   * Unlock all coins in a transaction.
   * @param {TX} tx
   */

  unlockTX(tx) {
    if (tx.isCoinbase())
      return;

    for (const input of tx.inputs)
      this.unlockCoin(input.prevout);
  }

  /**
   * Lock a single coin.
   * @param {Coin|Outpoint} coin
   */

  lockCoin(coin) {
    const key = coin.toKey();
    this.locked.add(key);
  }

  /**
   * Unlock a single coin.
   * @param {Coin|Outpoint} coin
   */

  unlockCoin(coin) {
    const key = coin.toKey();
    return this.locked.delete(key);
  }

  /**
   * Test locked status of a single coin.
   * @param {Coin|Outpoint} coin
   */

  isLocked(coin) {
    const key = coin.toKey();
    return this.locked.has(key);
  }

  /**
   * Filter array of coins or outpoints
   * for only unlocked ones.
   * @param {Coin[]|Outpoint[]}
   * @returns {Array}
   */

  filterLocked(coins) {
    const out = [];

    for (const coin of coins) {
      if (!this.isLocked(coin))
        out.push(coin);
    }

    return out;
  }

  /**
   * Return an array of all locked outpoints.
   * @returns {Outpoint[]}
   */

  getLocked() {
    const outpoints = [];

    for (const key of this.locked.keys())
      outpoints.push(Outpoint.fromKey(key));

    return outpoints;
  }

  /**
   * Get hashes of all transactions in the database.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getAccountHistoryHashes(acct) {
    assert(typeof acct === 'number');
    return this.bucket.keys({
      gte: layout.T.min(acct),
      lte: layout.T.max(acct),
      parse: (key) => {
        const [, hash] = layout.T.parse(key);
        return hash;
      }
    });
  }

  /**
   * Get hashes of all transactions in the database.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getHistoryHashes(acct) {
    assert(typeof acct === 'number');

    if (acct !== -1)
      return this.getAccountHistoryHashes(acct);

    return this.bucket.keys({
      gte: layout.t.min(),
      lte: layout.t.max(),
      parse: key => layout.t.parse(key)
    });
  }

  /**
   * Get hashes of all unconfirmed transactions in the database.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getAccountPendingHashes(acct) {
    assert(typeof acct === 'number');
    return this.bucket.keys({
      gte: layout.P.min(acct),
      lte: layout.P.max(acct),
      parse: (key) => {
        const [, hash] = layout.P.parse(key);
        return hash;
      }
    });
  }

  /**
   * Get hashes of all unconfirmed transactions in the database.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getPendingHashes(acct) {
    assert(typeof acct === 'number');

    if (acct !== -1)
      return this.getAccountPendingHashes(acct);

    return this.bucket.keys({
      gte: layout.p.min(),
      lte: layout.p.max(),
      parse: key => layout.p.parse(key)
    });
  }

  /**
   * Get all coin hashes in the database.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getAccountOutpoints(acct) {
    assert(typeof acct === 'number');
    return this.bucket.keys({
      gte: layout.C.min(acct),
      lte: layout.C.max(acct),
      parse: (key) => {
        const [, hash, index] = layout.C.parse(key);
        return new Outpoint(hash, index);
      }
    });
  }

  /**
   * Get all coin hashes in the database.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getOutpoints(acct) {
    assert(typeof acct === 'number');

    if (acct !== -1)
      return this.getAccountOutpoints(acct);

    return this.bucket.keys({
      gte: layout.c.min(),
      lte: layout.c.max(),
      parse: (key) => {
        const [hash, index] = layout.c.parse(key);
        return new Outpoint(hash, index);
      }
    });
  }

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

  getAccountHeightRangeHashes(acct, options) {
    assert(typeof acct === 'number');

    const start = options.start || 0;
    const end = options.end || 0xffffffff;

    return this.bucket.keys({
      gte: layout.H.min(acct, start),
      lte: layout.H.max(acct, end),
      limit: options.limit,
      reverse: options.reverse,
      parse: (key) => {
        const [,, hash] = layout.H.parse(key);
        return hash;
      }
    });
  }

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

  getHeightRangeHashes(acct, options) {
    assert(typeof acct === 'number');

    if (acct !== -1)
      return this.getAccountHeightRangeHashes(acct, options);

    const start = options.start || 0;
    const end = options.end || 0xffffffff;

    return this.bucket.keys({
      gte: layout.h.min(start),
      lte: layout.h.max(end),
      limit: options.limit,
      reverse: options.reverse,
      parse: (key) => {
        const [, hash] = layout.h.parse(key);
        return hash;
      }
    });
  }

  /**
   * Get TX hashes by height.
   * @param {Number} height
   * @returns {Promise} - Returns {@link Hash}[].
   */

  getHeightHashes(height) {
    return this.getHeightRangeHashes({ start: height, end: height });
  }

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

  getAccountRangeHashes(acct, options) {
    assert(typeof acct === 'number');

    const start = options.start || 0;
    const end = options.end || 0xffffffff;

    return this.bucket.keys({
      gte: layout.M.min(acct, start),
      lte: layout.M.max(acct, end),
      limit: options.limit,
      reverse: options.reverse,
      parse: (key) => {
        const [,, hash] = layout.M.parse(key);
        return hash;
      }
    });
  }

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

  getRangeHashes(acct, options) {
    assert(typeof acct === 'number');

    if (acct !== -1)
      return this.getAccountRangeHashes(acct, options);

    const start = options.start || 0;
    const end = options.end || 0xffffffff;

    return this.bucket.keys({
      gte: layout.m.min(start),
      lte: layout.m.max(end),
      limit: options.limit,
      reverse: options.reverse,
      parse: (key) => {
        const [, hash] = layout.m.parse(key);
        return hash;
      }
    });
  }

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

  async getRange(acct, options) {
    const hashes = await this.getRangeHashes(acct, options);
    const txs = [];

    for (const hash of hashes) {
      const tx = await this.getTX(hash);
      assert(tx);
      txs.push(tx);
    }

    return txs;
  }

  /**
   * Get last N transactions.
   * @param {Number} acct
   * @param {Number} limit - Max number of transactions.
   * @returns {Promise} - Returns {@link TX}[].
   */

  getLast(acct, limit) {
    return this.getRange(acct, {
      start: 0,
      end: 0xffffffff,
      reverse: true,
      limit: limit || 10
    });
  }

  /**
   * Get all transactions.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link TX}[].
   */

  getHistory(acct) {
    assert(typeof acct === 'number');

    // Slow case
    if (acct !== -1)
      return this.getAccountHistory(acct);

    // Fast case
    return this.bucket.values({
      gte: layout.t.min(),
      lte: layout.t.max(),
      parse: data => TXRecord.fromRaw(data)
    });
  }

  /**
   * Get all acct transactions.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getAccountHistory(acct) {
    const hashes = await this.getHistoryHashes(acct);
    const txs = [];

    for (const hash of hashes) {
      const tx = await this.getTX(hash);
      assert(tx);
      txs.push(tx);
    }

    return txs;
  }

  /**
   * Get unconfirmed transactions.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link TX}[].
   */

  async getPending(acct) {
    const hashes = await this.getPendingHashes(acct);
    const txs = [];

    for (const hash of hashes) {
      const tx = await this.getTX(hash);
      assert(tx);
      txs.push(tx);
    }

    return txs;
  }

  /**
   * Get coins.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Coin}[].
   */

  getCredits(acct) {
    assert(typeof acct === 'number');

    // Slow case
    if (acct !== -1)
      return this.getAccountCredits(acct);

    // Fast case
    return this.bucket.range({
      gte: layout.c.min(),
      lte: layout.c.max(),
      parse: (key, value) => {
        const [hash, index] = layout.c.parse(key);
        const credit = Credit.fromRaw(value);
        credit.coin.hash = hash;
        credit.coin.index = index;
        return credit;
      }
    });
  }

  /**
   * Get coins by account.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getAccountCredits(acct) {
    const outpoints = await this.getOutpoints(acct);
    const credits = [];

    for (const {hash, index} of outpoints) {
      const credit = await this.getCredit(hash, index);
      assert(credit);
      credits.push(credit);
    }

    return credits;
  }

  /**
   * Fill a transaction with coins (all historical coins).
   * @param {TX} tx
   * @returns {Promise} - Returns {@link TX}.
   */

  async getSpentCredits(tx) {
    if (tx.isCoinbase())
      return [];

    const hash = tx.hash('hex');
    const credits = [];

    for (let i = 0; i < tx.inputs.length; i++)
      credits.push(null);

    await this.bucket.range({
      gte: layout.d.min(hash),
      lte: layout.d.max(hash),
      parse: (key, value) => {
        const [, index] = layout.d.parse(key);
        const coin = Coin.fromRaw(value);
        const input = tx.inputs[index];
        assert(input);
        coin.hash = input.prevout.hash;
        coin.index = input.prevout.index;
        credits[index] = new Credit(coin);
      }
    });

    return credits;
  }

  /**
   * Get coins.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getCoins(acct) {
    const credits = await this.getCredits(acct);
    const coins = [];

    for (const credit of credits) {
      if (credit.spent)
        continue;

      coins.push(credit.coin);
    }

    return coins;
  }

  /**
   * Get coins by account.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Coin}[].
   */

  async getAccountCoins(acct) {
    const credits = await this.getAccountCredits(acct);
    const coins = [];

    for (const credit of credits) {
      if (credit.spent)
        continue;

      coins.push(credit.coin);
    }

    return coins;
  }

  /**
   * Get historical coins for a transaction.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link TX}.
   */

  async getSpentCoins(tx) {
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
  }

  /**
   * Get a coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getCoinView(tx) {
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
  }

  /**
   * Get historical coin viewpoint.
   * @param {TX} tx
   * @returns {Promise} - Returns {@link CoinView}.
   */

  async getSpentView(tx) {
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
  }

  /**
   * Get transaction.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TX}.
   */

  async getTX(hash) {
    const raw = await this.bucket.get(layout.t.build(hash));

    if (!raw)
      return null;

    return TXRecord.fromRaw(raw);
  }

  /**
   * Get transaction details.
   * @param {Hash} hash
   * @returns {Promise} - Returns {@link TXDetails}.
   */

  async getDetails(hash) {
    const wtx = await this.getTX(hash);

    if (!wtx)
      return null;

    return this.toDetails(wtx);
  }

  /**
   * Convert transaction to transaction details.
   * @param {TXRecord[]} wtxs
   * @returns {Promise}
   */

  async toDetails(wtxs) {
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
  }

  /**
   * Convert transaction to transaction details.
   * @private
   * @param {TXRecord} wtx
   * @returns {Promise}
   */

  async _toDetails(wtx) {
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
  }

  /**
   * Test whether the database has a transaction.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  hasTX(hash) {
    return this.bucket.has(layout.t.build(hash));
  }

  /**
   * Get coin.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  async getCoin(hash, index) {
    const credit = await this.getCredit(hash, index);

    if (!credit)
      return null;

    return credit.coin;
  }

  /**
   * Get coin.
   * @param {Hash} hash
   * @param {Number} index
   * @returns {Promise} - Returns {@link Coin}.
   */

  async getCredit(hash, index) {
    const data = await this.bucket.get(layout.c.build(hash, index));

    if (!data)
      return null;

    const credit = Credit.fromRaw(data);
    credit.coin.hash = hash;
    credit.coin.index = index;

    return credit;
  }

  /**
   * Get spender coin.
   * @param {Outpoint} spent
   * @param {Outpoint} prevout
   * @returns {Promise} - Returns {@link Coin}.
   */

  async getSpentCoin(spent, prevout) {
    const data = await this.bucket.get(layout.d.build(spent.hash, spent.index));

    if (!data)
      return null;

    const coin = Coin.fromRaw(data);
    coin.hash = prevout.hash;
    coin.index = prevout.index;

    return coin;
  }

  /**
   * Test whether the database has a spent coin.
   * @param {Outpoint} spent
   * @returns {Promise} - Returns {@link Coin}.
   */

  hasSpentCoin(spent) {
    return this.bucket.has(layout.d.build(spent.hash, spent.index));
  }

  /**
   * Update spent coin height in storage.
   * @param {TX} tx - Sending transaction.
   * @param {Number} index
   * @param {Number} height
   * @returns {Promise}
   */

  async updateSpentCoin(b, tx, index, height) {
    const prevout = Outpoint.fromTX(tx, index);
    const spent = await this.getSpent(prevout.hash, prevout.index);

    if (!spent)
      return;

    const coin = await this.getSpentCoin(spent, prevout);

    if (!coin)
      return;

    coin.height = height;

    b.put(layout.d.build(spent.hash, spent.index), coin.toRaw());
  }

  /**
   * Test whether the database has a transaction.
   * @param {Hash} hash
   * @returns {Promise} - Returns Boolean.
   */

  async hasCoin(hash, index) {
    return this.bucket.has(layout.c.build(hash, index));
  }

  /**
   * Calculate balance.
   * @param {Number?} account
   * @returns {Promise} - Returns {@link Balance}.
   */

  async getBalance(acct) {
    assert(typeof acct === 'number');

    if (acct !== -1)
      return this.getAccountBalance(acct);

    return this.getWalletBalance();
  }

  /**
   * Calculate balance.
   * @returns {Promise} - Returns {@link Balance}.
   */

  async getWalletBalance() {
    const data = await this.bucket.get(layout.R.build());

    if (!data)
      return new Balance();

    return Balance.fromRaw(-1, data);
  }

  /**
   * Calculate balance by account.
   * @param {Number} acct
   * @returns {Promise} - Returns {@link Balance}.
   */

  async getAccountBalance(acct) {
    const data = await this.bucket.get(layout.r.build(acct));

    if (!data)
      return new Balance(acct);

    return Balance.fromRaw(acct, data);
  }

  /**
   * Zap pending transactions older than `age`.
   * @param {Number} acct
   * @param {Number} age - Age delta.
   * @returns {Promise}
   */

  async zap(acct, age) {
    assert((age >>> 0) === age);

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
  }

  /**
   * Abandon transaction.
   * @param {Hash} hash
   * @returns {Promise}
   */

  async abandon(hash) {
    const result = await this.bucket.has(layout.p.build(hash));

    if (!result)
      throw new Error('TX not eligible.');

    return this.remove(hash);
  }
}

/**
 * Balance
 * @alias module:wallet.Balance
 */

class Balance {
  /**
   * Create a balance.
   * @constructor
   * @param {Number} account
   */

  constructor(acct = -1) {
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

  applyTo(balance) {
    balance.tx += this.tx;
    balance.coin += this.coin;
    balance.unconfirmed += this.unconfirmed;
    balance.confirmed += this.confirmed;

    assert(balance.tx >= 0);
    assert(balance.coin >= 0);
    assert(balance.unconfirmed >= 0);
    assert(balance.confirmed >= 0);
  }

  /**
   * Serialize balance.
   * @returns {Buffer}
   */

  toRaw() {
    const bw = bio.write(32);

    bw.writeU64(this.tx);
    bw.writeU64(this.coin);
    bw.writeU64(this.unconfirmed);
    bw.writeU64(this.confirmed);

    return bw.render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   * @returns {TXDBState}
   */

  fromRaw(data) {
    const br = bio.read(data);
    this.tx = br.readU64();
    this.coin = br.readU64();
    this.unconfirmed = br.readU64();
    this.confirmed = br.readU64();
    return this;
  }

  /**
   * Instantiate balance from serialized data.
   * @param {Number} acct
   * @param {Buffer} data
   * @returns {TXDBState}
   */

  static fromRaw(acct, data) {
    return new this(acct).fromRaw(data);
  }

  /**
   * Convert balance to a more json-friendly object.
   * @param {Boolean?} minimal
   * @returns {Object}
   */

  toJSON(minimal) {
    return {
      account: !minimal ? this.account : undefined,
      tx: this.tx,
      coin: this.coin,
      unconfirmed: this.unconfirmed,
      confirmed: this.confirmed
    };
  }

  /**
   * Inspect balance.
   * @param {String}
   */

  inspect() {
    return '<Balance'
      + ` tx=${this.tx}`
      + ` coin=${this.coin}`
      + ` unconfirmed=${Amount.btc(this.unconfirmed)}`
      + ` confirmed=${Amount.btc(this.confirmed)}`
      + '>';
  }
}

/**
 * Balance Delta
 * @ignore
 */

class BalanceDelta {
  /**
   * Create a balance delta.
   * @constructor
   */

  constructor() {
    this.wallet = new Balance();
    this.accounts = new Map();
  }

  updated() {
    return this.wallet.tx !== 0;
  }

  applyTo(balance) {
    this.wallet.applyTo(balance);
  }

  get(path) {
    if (!this.accounts.has(path.account))
      this.accounts.set(path.account, new Balance());

    return this.accounts.get(path.account);
  }

  tx(path, value) {
    const account = this.get(path);
    account.tx = value;
    this.wallet.tx = value;
  }

  coin(path, value) {
    const account = this.get(path);
    account.coin += value;
    this.wallet.coin += value;
  }

  unconfirmed(path, value) {
    const account = this.get(path);
    account.unconfirmed += value;
    this.wallet.unconfirmed += value;
  }

  confirmed(path, value) {
    const account = this.get(path);
    account.confirmed += value;
    this.wallet.confirmed += value;
  }
}

/**
 * Credit (wrapped coin)
 * @alias module:wallet.Credit
 * @property {Coin} coin
 * @property {Boolean} spent
 */

class Credit {
  /**
   * Create a credit.
   * @constructor
   * @param {Coin} coin
   * @param {Boolean?} spent
   */

  constructor(coin, spent) {
    this.coin = coin || new Coin();
    this.spent = spent || false;
    this.own = false;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);
    this.coin.fromReader(br);
    this.spent = br.readU8() === 1;
    this.own = br.readU8() === 1;
    return this;
  }

  /**
   * Instantiate credit from serialized data.
   * @param {Buffer} data
   * @returns {Credit}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.coin.getSize() + 2;
  }

  /**
   * Serialize credit.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);
    this.coin.toWriter(bw);
    bw.writeU8(this.spent ? 1 : 0);
    bw.writeU8(this.own ? 1 : 0);
    return bw.render();
  }

  /**
   * Inject properties from tx object.
   * @private
   * @param {TX} tx
   * @param {Number} index
   * @returns {Credit}
   */

  fromTX(tx, index, height) {
    this.coin.fromTX(tx, index, height);
    this.spent = false;
    this.own = false;
    return this;
  }

  /**
   * Instantiate credit from transaction.
   * @param {TX} tx
   * @param {Number} index
   * @returns {Credit}
   */

  static fromTX(tx, index, height) {
    return new this().fromTX(tx, index, height);
  }
}

/**
 * Transaction Details
 * @alias module:wallet.Details
 */

class Details {
  /**
   * Create transaction details.
   * @constructor
   * @param {TXRecord} wtx
   * @param {BlockMeta} block
   */

  constructor(wtx, block) {
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

  init() {
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
  }

  /**
   * Add necessary info to input member.
   * @param {Number} i
   * @param {Path} path
   * @param {Coin} coin
   */

  setInput(i, path, coin) {
    const member = this.inputs[i];

    if (coin) {
      member.value = coin.value;
      member.address = coin.getAddress();
    }

    if (path)
      member.path = path;
  }

  /**
   * Add necessary info to output member.
   * @param {Number} i
   * @param {Path} path
   */

  setOutput(i, path) {
    const member = this.outputs[i];

    if (path)
      member.path = path;
  }

  /**
   * Calculate confirmations.
   * @returns {Number}
   */

  getDepth(height) {
    if (this.height === -1)
      return 0;

    if (height == null)
      return 0;

    const depth = height - this.height;

    if (depth < 0)
      return 0;

    return depth + 1;
  }

  /**
   * Calculate fee. Only works if wallet
   * owns all inputs. Returns 0 otherwise.
   * @returns {Amount}
   */

  getFee() {
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
  }

  /**
   * Calculate fee rate. Only works if wallet
   * owns all inputs. Returns 0 otherwise.
   * @param {Amount} fee
   * @returns {Rate}
   */

  getRate(fee) {
    return policy.getRate(this.vsize, fee);
  }

  /**
   * Convert details to a more json-friendly object.
   * @returns {Object}
   */

  toJSON(network, height) {
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
  }
}

/**
 * Transaction Details Member
 * @property {Number} value
 * @property {Address} address
 * @property {Path} path
 */

class DetailsMember {
  /**
   * Create details member.
   * @constructor
   */

  constructor() {
    this.value = 0;
    this.address = null;
    this.path = null;
  }

  /**
   * Convert the member to a more json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return this.getJSON();
  }

  /**
   * Convert the member to a more json-friendly object.
   * @param {Network} network
   * @returns {Object}
   */

  getJSON(network) {
    return {
      value: this.value,
      address: this.address
        ? this.address.toString(network)
        : null,
      path: this.path
        ? this.path.toJSON()
        : null
    };
  }
}

/**
 * Block Record
 * @alias module:wallet.BlockRecord
 */

class BlockRecord {
  /**
   * Create a block record.
   * @constructor
   * @param {Hash} hash
   * @param {Number} height
   * @param {Number} time
   */

  constructor(hash, height, time) {
    this.hash = hash || consensus.NULL_HASH;
    this.height = height != null ? height : -1;
    this.time = time || 0;
    this.hashes = new Set();
  }

  /**
   * Add transaction to block record.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  add(hash) {
    if (this.hashes.has(hash))
      return false;

    this.hashes.add(hash);

    return true;
  }

  /**
   * Remove transaction from block record.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  remove(hash) {
    return this.hashes.delete(hash);
  }

  /**
   * Instantiate wallet block from serialized tip data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);

    this.hash = br.readHash('hex');
    this.height = br.readU32();
    this.time = br.readU32();

    const count = br.readU32();

    for (let i = 0; i < count; i++) {
      const hash = br.readHash('hex');
      this.hashes.add(hash);
    }

    return this;
  }

  /**
   * Instantiate wallet block from serialized data.
   * @param {Buffer} data
   * @returns {BlockRecord}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 44 + this.hashes.size * 32;
  }

  /**
   * Serialize the wallet block as a tip (hash and height).
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    const bw = bio.write(size);

    bw.writeHash(this.hash);
    bw.writeU32(this.height);
    bw.writeU32(this.time);

    bw.writeU32(this.hashes.size);

    for (const hash of this.hashes)
      bw.writeHash(hash);

    return bw.render();
  }

  /**
   * Convert hashes set to an array.
   * @returns {Hash[]}
   */

  toArray() {
    const hashes = [];
    for (const hash of this.hashes)
      hashes.push(hash);
    return hashes;
  }

  /**
   * Convert the block to a more json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return {
      hash: util.revHex(this.hash),
      height: this.height,
      time: this.time,
      hashes: this.toArray().map(util.revHex)
    };
  }

  /**
   * Instantiate wallet block from block meta.
   * @private
   * @param {BlockMeta} block
   */

  fromMeta(block) {
    this.hash = block.hash;
    this.height = block.height;
    this.time = block.time;
    return this;
  }

  /**
   * Instantiate wallet block from block meta.
   * @param {BlockMeta} block
   * @returns {BlockRecord}
   */

  static fromMeta(block) {
    return new this().fromMeta(block);
  }
}

/*
 * Expose
 */

module.exports = TXDB;
