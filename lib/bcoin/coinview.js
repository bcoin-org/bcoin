/*!
 * coinview.js - coinview object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

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
 * Add a coin to the collection.
 * @param {Coins|TX} tx/coins
 * @param {Number?} index
 */

CoinView.prototype.add = function add(tx, i) {
  var coin, hash;

  if (i == null) {
    coin = tx;
    this.coins[coin.hash] = coin;
    return;
  }

  hash = tx.hash('hex');

  if (!this.coins[hash]) {
    this.coins[hash] = Object.create(bcoin.coins.prototype);
    this.coins[hash].version = tx.version;
    this.coins[hash].height = tx.height;
    this.coins[hash].coinbase = tx.isCoinbase();
    this.coins[hash].hash = hash;
    this.coins[hash].outputs = new Array(tx.outputs.length);
  }

  this.coins[hash].add(tx, i);
};

/**
 * Get a coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.get = function get(hash, index) {
  if (!this.coins[hash])
    return;

  return this.coins[hash].get(index);
};

/**
 * Count number of available coins.
 * @param {Hash} hash
 * @returns {Number} Total.
 */

CoinView.prototype.count = function count(hash) {
  if (!this.coins[hash])
    return 0;

  return this.coins[hash].count();
};

/**
 * Test whether the collection has a coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Boolean}
 */

CoinView.prototype.has = function has(hash, index) {
  if (!this.coins[hash])
    return false;

  return this.coins[hash].has(index);
};

/**
 * Remove a coin.
 * @param {Hash} hash
 * @param {Number} index
 */

CoinView.prototype.remove = function remove(hash, index) {
  if (!this.coins[hash])
    return;

  return this.coins[hash].remove(index);
};

/**
 * Remove a coin and return it.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.spend = function spend(hash, index) {
  if (!this.coins[hash])
    return;

  return this.coins[hash].spend(index);
};

/**
 * Fill transaction(s) with coins.
 * @param {TX|TX[]} tx
 * @param {Boolean?} spend - Whether the coins should
 * be spent when filling.
 * @returns {Boolean} True if any inputs were filled.
 */

CoinView.prototype.fill = function fill(obj, spend) {
  var keys = Object.keys(this.coins);
  var res = true;
  var i;

  for (i = 0; i < keys.length; i++) {
    if (!this.coins[keys[i]].fill(obj, spend))
      res = false;
  }

  return res;
};

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.prototype.toArray = function toArray() {
  return Object.keys(this.coins).map(function(hash) {
    return this.coins[hash];
  }, this);
};

return CoinView;
};
