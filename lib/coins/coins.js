/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const CoinEntry = require('./coinentry');

/**
 * Represents the outputs for a single transaction.
 * @alias module:coins.Coins
 * @constructor
 * @property {Hash} hash - Transaction hash.
 * @property {CoinEntry[]} outputs - Coins.
 */

function Coins(options) {
  if (!(this instanceof Coins))
    return new Coins(options);

  this.outputs = new Map();
}

/**
 * Add a single entry to the collection.
 * @param {Number} index
 * @param {CoinEntry} coin
 */

Coins.prototype.add = function add(index, coin) {
  assert(index >= 0);

  assert(!this.outputs.has(index));

  this.outputs.set(index, coin);
};

/**
 * Add a single output to the collection.
 * @param {Number} index
 * @param {Output} output
 */

Coins.prototype.addOutput = function addOutput(index, output) {
  assert(!output.script.isUnspendable());
  this.add(index, CoinEntry.fromOutput(output));
};

/**
 * Add a single coin to the collection.
 * @param {Coin} coin
 */

Coins.prototype.addCoin = function addCoin(coin) {
  assert(!coin.script.isUnspendable());
  this.add(coin.index, CoinEntry.fromCoin(coin));
};

/**
 * Test whether the collection has a coin.
 * @param {Number} index
 * @returns {Boolean}
 */

Coins.prototype.has = function has(index) {
  return this.outputs.has(index);
};

/**
 * Test whether the collection has an unspent coin.
 * @param {Number} index
 * @returns {Boolean}
 */

Coins.prototype.isUnspent = function isUnspent(index) {
  let coin = this.outputs.get(index);

  if (!coin || coin.spent)
    return false;

  return true;
};

/**
 * Get a coin entry.
 * @param {Number} index
 * @returns {CoinEntry}
 */

Coins.prototype.get = function get(index) {
  return this.outputs.get(index);
};

/**
 * Get an output.
 * @param {Number} index
 * @returns {Output}
 */

Coins.prototype.getOutput = function getOutput(index) {
  let coin = this.outputs.get(index);

  if (!coin)
    return;

  return coin.output;
};

/**
 * Get a coin.
 * @param {Outpoint} prevout
 * @returns {Coin}
 */

Coins.prototype.getCoin = function getCoin(prevout) {
  let coin = this.outputs.get(prevout.index);

  if (!coin)
    return;

  return coin.toCoin(prevout);
};

/**
 * Spend a coin entry and return it.
 * @param {Number} index
 * @returns {CoinEntry}
 */

Coins.prototype.spend = function spend(index) {
  let coin = this.get(index);

  if (!coin || coin.spent)
    return;

  coin.spent = true;

  return coin;
};

/**
 * Remove a coin entry and return it.
 * @param {Number} index
 * @returns {CoinEntry}
 */

Coins.prototype.remove = function remove(index) {
  let coin = this.get(index);

  if (!coin)
    return false;

  this.outputs.delete(index);

  return coin;
};

/**
 * Calculate unspent length of coins.
 * @returns {Number}
 */

Coins.prototype.length = function length() {
  let len = -1;

  for (let [index, coin] of this.outputs) {
    if (!coin.spent) {
      if (index > len)
        len = index;
    }
  }

  return len + 1;
};

/**
 * Test whether the coins are fully spent.
 * @returns {Boolean}
 */

Coins.prototype.isEmpty = function isEmpty() {
  return this.outputs.size === 0;
};

/**
 * Inject properties from tx.
 * @private
 * @param {TX} tx
 * @param {Number} height
 */

Coins.prototype.fromTX = function fromTX(tx, height) {
  assert(typeof height === 'number');

  for (let i = 0; i < tx.outputs.length; i++) {
    let output = tx.outputs[i];

    if (output.script.isUnspendable())
      continue;

    this.outputs.set(i, CoinEntry.fromTX(tx, i, height));
  }

  return this;
};

/**
 * Instantiate a coins object from a transaction.
 * @param {TX} tx
 * @param {Number} height
 * @returns {Coins}
 */

Coins.fromTX = function fromTX(tx, height) {
  return new Coins().fromTX(tx, height);
};

/*
 * Expose
 */

module.exports = Coins;
