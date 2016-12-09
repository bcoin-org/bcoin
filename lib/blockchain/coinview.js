/*!
 * coinview.js - coinview object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var co = require('../utils/co');
var Coins = require('./coins');
var UndoCoins = require('./undocoins');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

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
 * Get coins.
 * @param {Hash} hash
 * @returns {Coins} coins
 */

CoinView.prototype.get = function get(hash) {
  return this.unspent[hash];
};

/**
 * Test whether the view has an entry.
 * @param {Hash} hash
 * @returns {Boolean}
 */

CoinView.prototype.has = function has(hash) {
  return this.unspent[hash] != null;
};

/**
 * Add coins to the collection.
 * @param {Coins} coins
 */

CoinView.prototype.add = function add(coins) {
  this.unspent[coins.hash] = coins;
  return coins;
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 * @param {Number} height
 */

CoinView.prototype.addTX = function addTX(tx, height) {
  var coins = Coins.fromTX(tx, height);
  return this.add(coins);
};

/**
 * Remove a tx from the collection.
 * @param {TX} tx
 * @param {Number} height
 */

CoinView.prototype.removeTX = function removeTX(tx, height) {
  var coins = Coins.fromTX(tx, height);
  coins.outputs.length = 0;
  return this.add(coins);
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 * @param {Number} height
 */

CoinView.prototype.addCoin = function addCoin(coin) {
  var coins = this.get(coin.hash);

  if (!coins) {
    coins = new Coins();
    coins.hash = coin.hash;
    coins.height = coin.height;
    coins.coinbase = coin.coinbase;
    this.add(coins);
  }

  if (!coins.has(coin.index))
    coins.addCoin(coin);
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 * @param {Number} height
 */

CoinView.prototype.addOutput = function addOutput(hash, index, output) {
  var coins = this.get(hash);

  if (!coins) {
    coins = new Coins();
    coins.hash = hash;
    coins.height = -1;
    coins.coinbase = false;
    this.add(coins);
  }

  if (!coins.has(index))
    coins.addOutput(index, output);
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
    return false;

  this.undo.push(entry);

  if (coins.isEmpty()) {
    undo = this.undo.top();
    undo.height = coins.height;
    undo.coinbase = coins.coinbase;
    undo.version = coins.version;
  }

  return true;
};

/**
 * Get a single coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.getCoin = function getCoin(input) {
  var coins = this.get(input.prevout.hash);

  if (!coins)
    return;

  return coins.getCoin(input.prevout.index);
};

/**
 * Get a single coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.getHeight = function getHeight(input) {
  var coins = this.get(input.prevout.hash);

  if (!coins)
    return -1;

  return coins.height;
};

/**
 * Get a single coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

CoinView.prototype.getOutput = function getOutput(input) {
  var coins = this.get(input.prevout.hash);

  if (!coins)
    return;

  return coins.getOutput(input.prevout.index);
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

CoinView.prototype.spendInputs = co(function* spendInputs(db, tx) {
  var i, input, prevout, coins;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    coins = yield this.getCoins(db, prevout.hash);

    if (!coins)
      return false;

    if (!this.spendFrom(coins, prevout.index))
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

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.prototype.toPrevWriter = function toPrevWriter(bw, tx) {
  var i, input, coins, entry;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    coins = this.get(input.prevout.hash);

    if (!coins) {
      bw.writeU8(0);
      continue;
    }

    entry = coins.get(input.prevout.index);

    if (!entry) {
      bw.writeU8(0);
      continue;
    }

    bw.writeU8(1);
    entry.toWriter(bw);
  }

  return bw;
};

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.prototype.toPrev = function toPrev(tx) {
  return this.toPrevWriter(new BufferWriter()).render();
};

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.prototype.fromPrevReader = function fromPrevReader(br, tx) {
  var i, input, coins, entry;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    coins = this.get(input.prevout.hash);

    if (!coins) {
      coins = new Coins();
      coins.hash = input.prevout.hash;
      coins.coinbase = false;
      this.add(coins);
    }

    if (br.readU8() === 1) {
      entry = Coins.CoinEntry.fromReader(br);
      coins.add(input.prevout.index, entry);
    }
  }

  return this;
};

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.fromPrevReader = function fromPrevReader(br, tx) {
  return new CoinView().fromPrevReader(br, tx);
};

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.fromPrev = function fromPrev(data, tx) {
  return new CoinView().fromPrevReader(new BufferReader(data), tx);
};

/*
 * Expose
 */

module.exports = CoinView;
