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
 * @property {Map[]} outputs - Coins.
 */

function Coins() {
  if (!(this instanceof Coins))
    return new Coins();

  this.outputs = new Map();
}

/**
 * Add a single entry to the collection.
 * @param {Number} index
 * @param {CoinEntry} coin
 * @returns {CoinEntry}
 */

Coins.prototype.add = function add(index, coin) {
  assert(index >= 0);
  assert(!this.outputs.has(index));

  this.outputs.set(index, coin);

  return coin;
};

/**
 * Add a single output to the collection.
 * @param {Number} index
 * @param {Output} output
 * @returns {CoinEntry}
 */

Coins.prototype.addOutput = function addOutput(index, output) {
  assert(!output.script.isUnspendable());
  return this.add(index, CoinEntry.fromOutput(output));
};

/**
 * Add a single coin to the collection.
 * @param {Coin} coin
 * @returns {CoinEntry}
 */

Coins.prototype.addCoin = function addCoin(coin) {
  assert(!coin.script.isUnspendable());
  return this.add(coin.index, CoinEntry.fromCoin(coin));
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
  const coin = this.outputs.get(index);

  if (!coin || coin.spent)
    return false;

  return true;
};

/**
 * Get a coin entry.
 * @param {Number} index
 * @returns {CoinEntry|null}
 */

Coins.prototype.get = function get(index) {
  return this.outputs.get(index) || null;
};

/**
 * Get an output.
 * @param {Number} index
 * @returns {Output|null}
 */

Coins.prototype.getOutput = function getOutput(index) {
  const coin = this.outputs.get(index);

  if (!coin)
    return null;

  return coin.output;
};

/**
 * Get a coin.
 * @param {Outpoint} prevout
 * @returns {Coin|null}
 */

Coins.prototype.getCoin = function getCoin(prevout) {
  const coin = this.outputs.get(prevout.index);

  if (!coin)
    return null;

  return coin.toCoin(prevout);
};

/**
 * Spend a coin entry and return it.
 * @param {Number} index
 * @returns {CoinEntry|null}
 */

Coins.prototype.spend = function spend(index) {
  const coin = this.get(index);

  if (!coin || coin.spent)
    return null;

  coin.spent = true;

  return coin;
};

/**
 * Remove a coin entry and return it.
 * @param {Number} index
 * @returns {CoinEntry|null}
 */

Coins.prototype.remove = function remove(index) {
  const coin = this.get(index);

  if (!coin)
    return null;

  this.outputs.delete(index);

  return coin;
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
 * @returns {Coins}
 */

Coins.prototype.fromTX = function fromTX(tx, height) {
  assert(typeof height === 'number');

  for (let i = 0; i < tx.outputs.length; i++) {
    const output = tx.outputs[i];

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
