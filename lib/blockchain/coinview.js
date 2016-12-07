/*!
 * coinview.js - coinview object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

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

function CoinView() {
  if (!(this instanceof CoinView))
    return new CoinView();

  this.unspent = {};
  this.undo = new UndoCoins();
}

/**
 * Add coins to the collection.
 * @param {Coins} coins
 */

CoinView.prototype.addCoins = function addCoins(coins) {
  this.unspent[coins.hash] = coins;
  return coins;
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 */

CoinView.prototype.addTX = function addTX(tx, height) {
  var coins = Coins.fromTX(tx, height);
  return this.addCoins(coins);
};

/**
 * Remove a tx from the collection.
 * @param {TX} tx
 */

CoinView.prototype.removeTX = function removeTX(tx, height) {
  var coins = Coins.fromTX(tx, height);
  coins.outputs.length = 0;
  return this.addCoins(coins);
};

/**
 * Get a coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.get = function get(hash, index) {
  var coins = this.unspent[hash];
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
  var coins = this.unspent[hash];

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
  var coins = this.unspent[hash];

  if (!coins)
    return null;

  return this.spendFrom(coins, index);
};

/**
 * Remove a coin and return it.
 * @param {Coins} coins
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.spendFrom = function spendFrom(coins, index) {
  var entry = coins.spend(index);
  var undo;

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
  var coins = this.unspent[hash];

  if (!coins) {
    coins = yield db.getCoins(hash);

    if (!coins)
      return;

    this.unspent[hash] = coins;
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
 * Read all input coins into unspent map.
 * @param {ChainDB} db
 * @param {TX} tx
 */

CoinView.prototype.ensureInputs = co(function* ensureInputs(db, tx) {
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    yield this.getCoins(db, input.prevout.hash);
  }
});

/**
 * Spend coins for transaction.
 * @param {TX} tx
 * @returns {Boolean}
 */

CoinView.prototype.spendCoins = function spendCoins(tx) {
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
 * Spend coins for transaction.
 * @param {TX} tx
 * @returns {Boolean}
 */

CoinView.prototype.spendInputs = co(function* spendInputs(db, tx) {
  var i, input, prevout, coins;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    coins = yield this.getCoins(db, prevout.hash);

    if (!coins)
      return false;

    input.coin = this.spendFrom(coins, prevout.index);

    if (!input.coin)
      return false;
  }

  return true;
});

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.prototype.toArray = function toArray() {
  var keys = Object.keys(this.unspent);
  var out = [];
  var i, hash;

  for (i = 0; i < keys.length; i++) {
    hash = keys[i];
    out.push(this.unspent[hash]);
  }

  return out;
};

/*
 * Expose
 */

module.exports = CoinView;
