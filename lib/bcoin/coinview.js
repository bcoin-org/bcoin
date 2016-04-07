/**
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
 * CoinView
 */

function CoinView(coins) {
  if (!(this instanceof CoinView))
    return new CoinView(coins);

  this.coins = coins || {};
}

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

CoinView.prototype.get = function get(hash, index) {
  if (!this.coins[hash])
    return;

  return this.coins[hash].get(index);
};

CoinView.prototype.count = function count(hash) {
  if (!this.coins[hash])
    return 0;

  return this.coins[hash].count();
};

CoinView.prototype.has = function has(hash, index) {
  if (!this.coins[hash])
    return;

  return this.coins[hash].has(index);
};

CoinView.prototype.remove = function remove(hash, index) {
  if (!this.coins[hash])
    return;

  return this.coins[hash].remove(index);
};

CoinView.prototype.spend = function spend(hash, index) {
  if (!this.coins[hash])
    return;

  return this.coins[hash].spend(index);
};

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

CoinView.prototype.toArray = function toArray() {
  return Object.keys(this.coins).map(function(hash) {
    return this.coins[hash];
  }, this);
};

/**
 * Expose
 */

return CoinView;
};
