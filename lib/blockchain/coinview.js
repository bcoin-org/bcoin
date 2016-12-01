/*!
 * coinview.js - coinview object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var co = require('../utils/co');
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
}

/**
 * Add coins to the collection.
 * @param {Coins} coins
 */

CoinView.prototype.add = function add(coins) {
  this.coins[coins.hash] = coins;
  return coins;
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 */

CoinView.prototype.addTX = function addTX(tx) {
  return this.add(Coins.fromTX(tx));
};

/**
 * Remove a tx from the collection.
 * @param {TX} tx
 */

CoinView.prototype.removeTX = function removeTX(tx) {
  var coins = this.addTX(tx);
  coins.outputs.length = 0;
  return coins;
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
  var entry, undo;

  if (!coins)
    return null;

  entry = coins.spend(index);

  if (!entry)
    return null;

  this.undo.push(entry);

  if (coins.isEmpty()) {
    undo = this.undo.top();
    undo.height = coins.height;
    undo.coinbase = coins.coinbase;
    undo.version = coins.version;
  }

  return entry.toCoin(coins, index);
};

/**
 * Retrieve coins from database.
 * @param {TX} tx
 * @returns {Promise}
 */

CoinView.prototype.getCoins = co(function* getCoins(db, hash) {
  var coins = this.coins[hash];

  if (!coins) {
    coins = yield db.getCoins(hash);

    if (!coins)
      return;

    this.coins[hash] = coins;
  }

  return coins;
});

/**
 * Test whether all inputs are available.
 * @param {ChainDB} db
 * @param {TX} tx
 * @returns {Boolean} True if all inputs are available.
 */

CoinView.prototype.hasInputs = co(function* hasInputs(db, tx) {
  var i, input, prevout, coins;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    coins = yield this.getCoins(db, prevout.hash);

    if (!coins)
      return false;

    if (!coins.has(prevout.index))
      return false;
  }

  return true;
});

/**
 * Spend coins for transaction.
 * @param {TX} tx
 * @throws on missing coin
 */

CoinView.prototype.spendCoins = function spendCoins(tx) {
  var i, input, prevout;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    input.coin = this.spend(prevout.hash, prevout.index);
    assert(input.coin, 'Not all coins available.');
  }
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
