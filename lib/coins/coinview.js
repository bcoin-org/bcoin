/*!
 * coinview.js - coin viewpoint object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Coins = require('./coins');
const UndoCoins = require('./undocoins');
const CoinEntry = require('./coinentry');

/**
 * Coin View
 * Represents a coin viewpoint:
 * a snapshot of {@link Coins} objects.
 * @alias module:coins.CoinView
 * @property {Object} map
 * @property {UndoCoins} undo
 */

class CoinView {
  /**
   * Create a coin view.
   * @constructor
   */

  constructor() {
    this.map = new Map();
    this.undo = new UndoCoins();
  }

  /**
   * Get coins.
   * @param {Hash} hash
   * @returns {Coins} coins
   */

  get(hash) {
    return this.map.get(hash);
  }

  /**
   * Test whether the view has an entry.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  has(hash) {
    return this.map.has(hash);
  }

  /**
   * Add coins to the collection.
   * @param {Hash} hash
   * @param {Coins} coins
   * @returns {Coins}
   */

  add(hash, coins) {
    this.map.set(hash, coins);
    return coins;
  }

  /**
   * Ensure existence of coins object in the collection.
   * @param {Hash} hash
   * @returns {Coins}
   */

  ensure(hash) {
    const coins = this.map.get(hash);

    if (coins)
      return coins;

    return this.add(hash, new Coins());
  }

  /**
   * Remove coins from the collection.
   * @param {Coins} coins
   * @returns {Coins|null}
   */

  remove(hash) {
    const coins = this.map.get(hash);

    if (!coins)
      return null;

    this.map.delete(hash);

    return coins;
  }

  /**
   * Add a tx to the collection.
   * @param {TX} tx
   * @param {Number} height
   * @returns {Coins}
   */

  addTX(tx, height) {
    const hash = tx.hash('hex');
    const coins = Coins.fromTX(tx, height);
    return this.add(hash, coins);
  }

  /**
   * Remove a tx from the collection.
   * @param {TX} tx
   * @param {Number} height
   * @returns {Coins}
   */

  removeTX(tx, height) {
    const hash = tx.hash('hex');
    const coins = Coins.fromTX(tx, height);

    for (const coin of coins.outputs.values())
      coin.spent = true;

    return this.add(hash, coins);
  }

  /**
   * Add an entry to the collection.
   * @param {Outpoint} prevout
   * @param {CoinEntry} coin
   * @returns {CoinEntry|null}
   */

  addEntry(prevout, coin) {
    const {hash, index} = prevout;
    const coins = this.ensure(hash);
    return coins.add(index, coin);
  }

  /**
   * Add a coin to the collection.
   * @param {Coin} coin
   * @returns {CoinEntry|null}
   */

  addCoin(coin) {
    const coins = this.ensure(coin.hash);
    return coins.addCoin(coin);
  }

  /**
   * Add an output to the collection.
   * @param {Outpoint} prevout
   * @param {Output} output
   * @returns {CoinEntry|null}
   */

  addOutput(prevout, output) {
    const {hash, index} = prevout;
    const coins = this.ensure(hash);
    return coins.addOutput(index, output);
  }

  /**
   * Add an output to the collection by output index.
   * @param {TX} tx
   * @param {Number} index
   * @param {Number} height
   * @returns {CoinEntry|null}
   */

  addIndex(tx, index, height) {
    const hash = tx.hash('hex');
    const coins = this.ensure(hash);
    return coins.addIndex(tx, index, height);
  }

  /**
   * Spend an output.
   * @param {Outpoint} prevout
   * @returns {CoinEntry|null}
   */

  spendEntry(prevout) {
    const {hash, index} = prevout;
    const coins = this.get(hash);

    if (!coins)
      return null;

    const coin = coins.spend(index);

    if (!coin)
      return null;

    this.undo.push(coin);

    return coin;
  }

  /**
   * Remove an output.
   * @param {Outpoint} prevout
   * @returns {CoinEntry|null}
   */

  removeEntry(prevout) {
    const {hash, index} = prevout;
    const coins = this.get(hash);

    if (!coins)
      return null;

    return coins.remove(index);
  }

  /**
   * Test whether the view has an entry by prevout.
   * @param {Outpoint} prevout
   * @returns {Boolean}
   */

  hasEntry(prevout) {
    const {hash, index} = prevout;
    const coins = this.get(hash);

    if (!coins)
      return false;

    return coins.has(index);
  }

  /**
   * Get a single entry by prevout.
   * @param {Outpoint} prevout
   * @returns {CoinEntry|null}
   */

  getEntry(prevout) {
    const {hash, index} = prevout;
    const coins = this.get(hash);

    if (!coins)
      return null;

    return coins.get(index);
  }

  /**
   * Test whether an entry has been spent by prevout.
   * @param {Outpoint} prevout
   * @returns {Boolean}
   */

  isUnspent(prevout) {
    const {hash, index} = prevout;
    const coins = this.get(hash);

    if (!coins)
      return false;

    return coins.isUnspent(index);
  }

  /**
   * Get a single coin by prevout.
   * @param {Outpoint} prevout
   * @returns {Coin|null}
   */

  getCoin(prevout) {
    const coins = this.get(prevout.hash);

    if (!coins)
      return null;

    return coins.getCoin(prevout);
  }

  /**
   * Get a single output by prevout.
   * @param {Outpoint} prevout
   * @returns {Output|null}
   */

  getOutput(prevout) {
    const {hash, index} = prevout;
    const coins = this.get(hash);

    if (!coins)
      return null;

    return coins.getOutput(index);
  }

  /**
   * Get coins height by prevout.
   * @param {Outpoint} prevout
   * @returns {Number}
   */

  getHeight(prevout) {
    const coin = this.getEntry(prevout);

    if (!coin)
      return -1;

    return coin.height;
  }

  /**
   * Get coins coinbase flag by prevout.
   * @param {Outpoint} prevout
   * @returns {Boolean}
   */

  isCoinbase(prevout) {
    const coin = this.getEntry(prevout);

    if (!coin)
      return false;

    return coin.coinbase;
  }

  /**
   * Test whether the view has an entry by input.
   * @param {Input} input
   * @returns {Boolean}
   */

  hasEntryFor(input) {
    return this.hasEntry(input.prevout);
  }

  /**
   * Get a single entry by input.
   * @param {Input} input
   * @returns {CoinEntry|null}
   */

  getEntryFor(input) {
    return this.getEntry(input.prevout);
  }

  /**
   * Test whether an entry has been spent by input.
   * @param {Input} input
   * @returns {Boolean}
   */

  isUnspentFor(input) {
    return this.isUnspent(input.prevout);
  }

  /**
   * Get a single coin by input.
   * @param {Input} input
   * @returns {Coin|null}
   */

  getCoinFor(input) {
    return this.getCoin(input.prevout);
  }

  /**
   * Get a single output by input.
   * @param {Input} input
   * @returns {Output|null}
   */

  getOutputFor(input) {
    return this.getOutput(input.prevout);
  }

  /**
   * Get coins height by input.
   * @param {Input} input
   * @returns {Number}
   */

  getHeightFor(input) {
    return this.getHeight(input.prevout);
  }

  /**
   * Get coins coinbase flag by input.
   * @param {Input} input
   * @returns {Boolean}
   */

  isCoinbaseFor(input) {
    return this.isCoinbase(input.prevout);
  }

  /**
   * Retrieve coins from database.
   * @method
   * @param {ChainDB} db
   * @param {Outpoint} prevout
   * @returns {Promise} - Returns {@link CoinEntry}.
   */

  async readCoin(db, prevout) {
    const cache = this.getEntry(prevout);

    if (cache)
      return cache;

    const coin = await db.readCoin(prevout);

    if (!coin)
      return null;

    return this.addEntry(prevout, coin);
  }

  /**
   * Read all input coins into unspent map.
   * @method
   * @param {ChainDB} db
   * @param {TX} tx
   * @returns {Promise} - Returns {Boolean}.
   */

  async readInputs(db, tx) {
    let found = true;

    for (const {prevout} of tx.inputs) {
      if (!await this.readCoin(db, prevout))
        found = false;
    }

    return found;
  }

  /**
   * Spend coins for transaction.
   * @method
   * @param {ChainDB} db
   * @param {TX} tx
   * @returns {Promise} - Returns {Boolean}.
   */

  async spendInputs(db, tx) {
    let i = 0;

    while (i < tx.inputs.length) {
      const len = Math.min(i + 4, tx.inputs.length);
      const jobs = [];

      for (; i < len; i++) {
        const {prevout} = tx.inputs[i];
        jobs.push(this.readCoin(db, prevout));
      }

      const coins = await Promise.all(jobs);

      for (const coin of coins) {
        if (!coin || coin.spent)
          return false;

        coin.spent = true;
        this.undo.push(coin);
      }
    }

    return true;
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize(tx) {
    let size = 0;

    size += tx.inputs.length;

    for (const {prevout} of tx.inputs) {
      const coin = this.getEntry(prevout);

      if (!coin)
        continue;

      size += coin.getSize();
    }

    return size;
  }

  /**
   * Write coin data to buffer writer
   * as it pertains to a transaction.
   * @param {BufferWriter} bw
   * @param {TX} tx
   */

  toWriter(bw, tx) {
    for (const {prevout} of tx.inputs) {
      const coin = this.getEntry(prevout);

      if (!coin) {
        bw.writeU8(0);
        continue;
      }

      bw.writeU8(1);
      coin.toWriter(bw);
    }

    return bw;
  }

  /**
   * Read serialized view data from a buffer
   * reader as it pertains to a transaction.
   * @private
   * @param {BufferReader} br
   * @param {TX} tx
   */

  fromReader(br, tx) {
    for (const {prevout} of tx.inputs) {
      if (br.readU8() === 0)
        continue;

      const coin = CoinEntry.fromReader(br);

      this.addEntry(prevout, coin);
    }

    return this;
  }

  /**
   * Read serialized view data from a buffer
   * reader as it pertains to a transaction.
   * @param {BufferReader} br
   * @param {TX} tx
   * @returns {CoinView}
   */

  static fromReader(br, tx) {
    return new this().fromReader(br, tx);
  }
}

/*
 * Expose
 */

module.exports = CoinView;
