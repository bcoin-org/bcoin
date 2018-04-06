/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const CoinEntry = require('./coinentry');

/**
 * Coins
 * Represents the outputs for a single transaction.
 * @alias module:coins.Coins
 * @property {Map[]} outputs - Coins.
 */

class Coins {
  /**
   * Create coins.
   * @constructor
   */

  constructor() {
    this.outputs = new Map();
  }

  /**
   * Add a single entry to the collection.
   * @param {Number} index
   * @param {CoinEntry} coin
   * @returns {CoinEntry}
   */

  add(index, coin) {
    assert((index >>> 0) === index);
    assert(coin);
    this.outputs.set(index, coin);
    return coin;
  }

  /**
   * Add a single output to the collection.
   * @param {Number} index
   * @param {Output} output
   * @returns {CoinEntry}
   */

  addOutput(index, output) {
    return this.add(index, CoinEntry.fromOutput(output));
  }

  /**
   * Add an output to the collection by output index.
   * @param {TX} tx
   * @param {Number} index
   * @param {Number} height
   * @returns {CoinEntry}
   */

  addIndex(tx, index, height) {
    return this.add(index, CoinEntry.fromTX(tx, index, height));
  }

  /**
   * Add a single coin to the collection.
   * @param {Coin} coin
   * @returns {CoinEntry}
   */

  addCoin(coin) {
    return this.add(coin.index, CoinEntry.fromCoin(coin));
  }

  /**
   * Test whether the collection has a coin.
   * @param {Number} index
   * @returns {Boolean}
   */

  has(index) {
    return this.outputs.has(index);
  }

  /**
   * Test whether the collection has an unspent coin.
   * @param {Number} index
   * @returns {Boolean}
   */

  isUnspent(index) {
    const coin = this.outputs.get(index);

    if (!coin || coin.spent)
      return false;

    return true;
  }

  /**
   * Get a coin entry.
   * @param {Number} index
   * @returns {CoinEntry|null}
   */

  get(index) {
    return this.outputs.get(index) || null;
  }

  /**
   * Get an output.
   * @param {Number} index
   * @returns {Output|null}
   */

  getOutput(index) {
    const coin = this.outputs.get(index);

    if (!coin)
      return null;

    return coin.output;
  }

  /**
   * Get a coin.
   * @param {Outpoint} prevout
   * @returns {Coin|null}
   */

  getCoin(prevout) {
    const coin = this.outputs.get(prevout.index);

    if (!coin)
      return null;

    return coin.toCoin(prevout);
  }

  /**
   * Spend a coin entry and return it.
   * @param {Number} index
   * @returns {CoinEntry|null}
   */

  spend(index) {
    const coin = this.get(index);

    if (!coin || coin.spent)
      return null;

    coin.spent = true;

    return coin;
  }

  /**
   * Remove a coin entry and return it.
   * @param {Number} index
   * @returns {CoinEntry|null}
   */

  remove(index) {
    const coin = this.get(index);

    if (!coin)
      return null;

    this.outputs.delete(index);

    return coin;
  }

  /**
   * Test whether the coins are fully spent.
   * @returns {Boolean}
   */

  isEmpty() {
    return this.outputs.size === 0;
  }

  /**
   * Inject properties from tx.
   * @private
   * @param {TX} tx
   * @param {Number} height
   * @returns {Coins}
   */

  fromTX(tx, height) {
    assert(typeof height === 'number');

    for (let i = 0; i < tx.outputs.length; i++) {
      const output = tx.outputs[i];

      if (output.script.isUnspendable())
        continue;

      const entry = CoinEntry.fromTX(tx, i, height);

      this.outputs.set(i, entry);
    }

    return this;
  }

  /**
   * Instantiate a coins object from a transaction.
   * @param {TX} tx
   * @param {Number} height
   * @returns {Coins}
   */

  static fromTX(tx, height) {
    return new this().fromTX(tx, height);
  }
}

/*
 * Expose
 */

module.exports = Coins;
