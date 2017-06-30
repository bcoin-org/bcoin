/*!
 * coinview.js - coinview object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Coins = require('./coins-old');

/**
 * A collections of {@link Coins} objects.
 * @exports CoinView
 * @constructor
 * @param {Object} coins - A hash-to-coins map.
 * @property {Object} coins
 */

function CoinView(coins) {
  if (!(this instanceof CoinView))
    return new CoinView(coins);

  this.coins = coins || {};
}

/**
 * Add coins to the collection.
 * @param {Coins} coins
 */

CoinView.prototype.add = function add(coins) {
  this.coins[coins.hash] = coins;
};

/**
 * Add a coin to the collection.
 * @param {Coin} coin
 */

CoinView.prototype.addCoin = function addCoin(coin) {
  assert(typeof coin.hash === 'string');
  if (!this.coins[coin.hash])
    this.coins[coin.hash] = new Coins();
  this.coins[coin.hash].add(coin);
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 */

CoinView.prototype.addTX = function addTX(tx) {
  this.add(Coins.fromTX(tx));
};

/**
 * Get a coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.get = function get(hash, index) {
  let coins = this.coins[hash];

  if (!coins)
    return;

  return coins.get(index);
};

/**
 * Test whether the collection has a coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Boolean}
 */

CoinView.prototype.has = function has(hash, index) {
  let coins = this.coins[hash];

  if (!coins)
    return false;

  return coins.has(index);
};

/**
 * Remove a coin and return it.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.spend = function spend(hash, index) {
  let coins = this.coins[hash];

  if (!coins)
    return;

  return coins.spend(index);
};

/**
 * Fill transaction(s) with coins.
 * @param {TX} tx
 * @returns {Boolean} True if all inputs were filled.
 */

CoinView.prototype.fillCoins = function fillCoins(tx) {
  let i, input, prevout;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    input.coin = this.spend(prevout.hash, prevout.index);
    if (!input.coin)
      return false;
  }

  return true;
};

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.prototype.toArray = function toArray() {
  let keys = Object.keys(this.coins);
  let out = [];
  let i, hash;

  for (i = 0; i < keys.length; i++) {
    hash = keys[i];
    out.push(this.coins[hash]);
  }

  return out;
};

/*
 * Expose
 */

module.exports = CoinView;
