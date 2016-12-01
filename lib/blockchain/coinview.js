/*!
 * coinview.js - coinview object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var Coins = require('./coins');
var UndoCoins = require('./undocoins');

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
  this.undo = new UndoCoins();
  this.coinDelta = 0;
  this.valueDelta = 0;
}

/**
 * Add coins to the collection.
 * @param {Coins} coins
 */

CoinView.prototype.add = function add(coins) {
  this.coins[coins.hash] = coins;
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 */

CoinView.prototype.addTX = function addTX(tx) {
  var coins = Coins.fromTX(tx);
  var i, entry;

  this.coinDelta += coins.outputs.length;

  for (i = 0; i < coins.outputs.length; i++) {
    entry = coins.outputs[i];

    if (!entry)
      continue;

    this.valueDelta += entry.output.value;
  }

  this.add(coins);
};

/**
 * Get a coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.get = function get(hash, index) {
  var coins = this.coins[hash];
  var entry;

  if (!coins)
    return;

  entry = coins.get(index);

  if (!entry)
    return;

  return entry.toCoin(coins, index);
};

/**
 * Test whether the collection has a coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Boolean}
 */

CoinView.prototype.has = function has(hash, index) {
  var coins = this.coins[hash];

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
  var coins = this.coins[hash];
  var entry, undo, coin;

  if (!coins)
    return;

  entry = coins.spend(index);

  if (!entry)
    return;

  this.undo.push(entry);

  if (coins.isEmpty()) {
    undo = this.undo.top();
    undo.height = coins.height;
    undo.coinbase = coins.coinbase;
    undo.version = coins.version;
  }

  coin = entry.toCoin(coins, index);

  this.coinDelta -= 1;
  this.valueDelta -= coin.value;

  return coin;
};

/**
 * Fill transaction(s) with coins.
 * @param {TX} tx
 * @returns {Boolean} True if all inputs were filled.
 */

CoinView.prototype.fillCoins = function fillCoins(tx) {
  var i, input, prevout;

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
  var keys = Object.keys(this.coins);
  var out = [];
  var i, hash;

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
