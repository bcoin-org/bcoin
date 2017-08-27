/*!
 * coinview.js - coin viewpoint object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint-disable */

'use strict';

const assert = require('assert');
const Coins = require('./coins');
const UndoCoins = require('./undocoins');
const CoinEntry = Coins.CoinEntry;

/**
 * Represents a coin viewpoint:
 * a snapshot of {@link Coins} objects.
 * @alias module:coins.CoinView
 * @constructor
 * @property {Object} map
 * @property {UndoCoins} undo
 */

function CoinView() {
  if (!(this instanceof CoinView))
    return new CoinView();

  this.map = new Map();
  this.undo = new UndoCoins();
}

/**
 * Get coins.
 * @param {Hash} hash
 * @returns {Coins} coins
 */

CoinView.prototype.get = function get(hash) {
  return this.map.get(hash);
};

/**
 * Test whether the view has an entry.
 * @param {Hash} hash
 * @returns {Boolean}
 */

CoinView.prototype.has = function has(hash) {
  return this.map.has(hash);
};

/**
 * Add coins to the collection.
 * @param {Coins} coins
 */

CoinView.prototype.add = function add(coins) {
  this.map.set(coins.hash, coins);
  return coins;
};

/**
 * Remove coins from the collection.
 * @param {Coins} coins
 * @returns {Boolean}
 */

CoinView.prototype.remove = function remove(hash) {
  if (!this.map.has(hash))
    return false;

  this.map.delete(hash);

  return true;
};

/**
 * Add a tx to the collection.
 * @param {TX} tx
 * @param {Number} height
 */

CoinView.prototype.addTX = function addTX(tx, height) {
  const coins = Coins.fromTX(tx, height);
  return this.add(coins);
};

/**
 * Remove a tx from the collection.
 * @param {TX} tx
 * @param {Number} height
 */

CoinView.prototype.removeTX = function removeTX(tx, height) {
  const coins = Coins.fromTX(tx, height);
  coins.outputs.length = 0;
  return this.add(coins);
};

/**
 * Add a coin to the collection.
 * @param {Coin} coin
 */

CoinView.prototype.addCoin = function addCoin(coin) {
  let coins = this.get(coin.hash);

  if (!coins) {
    coins = new Coins();
    coins.hash = coin.hash;
    coins.height = coin.height;
    coins.coinbase = coin.coinbase;
    this.add(coins);
  }

  if (coin.script.isUnspendable())
    return;

  if (!coins.has(coin.index))
    coins.addCoin(coin);
};

/**
 * Add an output to the collection.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Output} output
 */

CoinView.prototype.addOutput = function addOutput(hash, index, output) {
  let coins = this.get(hash);

  if (!coins) {
    coins = new Coins();
    coins.hash = hash;
    coins.height = -1;
    coins.coinbase = false;
    this.add(coins);
  }

  if (output.script.isUnspendable())
    return;

  if (!coins.has(index))
    coins.addOutput(index, output);
};

/**
 * Spend an output.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Boolean}
 */

CoinView.prototype.spendOutput = function spendOutput(hash, index) {
  const coins = this.get(hash);

  if (!coins)
    return false;

  return this.spendFrom(coins, index);
};

/**
 * Remove an output.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Boolean}
 */

CoinView.prototype.removeOutput = function removeOutput(hash, index) {
  const coins = this.get(hash);

  if (!coins)
    return false;

  return coins.remove(index);
};

/**
 * Spend a coin from coins object.
 * @param {Coins} coins
 * @param {Number} index
 * @returns {Boolean}
 */

CoinView.prototype.spendFrom = function spendFrom(coins, index) {
  const entry = coins.spend(index);

  if (!entry)
    return false;

  this.undo.push(entry);

  if (coins.isEmpty()) {
    const undo = this.undo.top();
    undo.height = coins.height;
    undo.coinbase = coins.coinbase;
    undo.version = coins.version;
    assert(undo.height !== -1);
  }

  return true;
};

/**
 * Get a single coin by input.
 * @param {Input} input
 * @returns {Coin}
 */

CoinView.prototype.getCoin = function getCoin(input) {
  const coins = this.get(input.prevout.hash);

  if (!coins)
    return;

  return coins.getCoin(input.prevout.index);
};

/**
 * Get a single output by input.
 * @param {Input} input
 * @returns {Output}
 */

CoinView.prototype.getOutput = function getOutput(input) {
  const coins = this.get(input.prevout.hash);

  if (!coins)
    return;

  return coins.getOutput(input.prevout.index);
};

/**
 * Get a single entry by input.
 * @param {Input} input
 * @returns {CoinEntry}
 */

CoinView.prototype.getEntry = function getEntry(input) {
  const coins = this.get(input.prevout.hash);

  if (!coins)
    return;

  return coins.get(input.prevout.index);
};

/**
 * Test whether the view has an entry by input.
 * @param {Input} input
 * @returns {Boolean}
 */

CoinView.prototype.hasEntry = function hasEntry(input) {
  const coins = this.get(input.prevout.hash);

  if (!coins)
    return false;

  return coins.has(input.prevout.index);
};

/**
 * Get coins height by input.
 * @param {Input} input
 * @returns {Number}
 */

CoinView.prototype.getHeight = function getHeight(input) {
  const coins = this.get(input.prevout.hash);

  if (!coins)
    return -1;

  return coins.height;
};

/**
 * Get coins coinbase flag by input.
 * @param {Input} input
 * @returns {Boolean}
 */

CoinView.prototype.isCoinbase = function isCoinbase(input) {
  const coins = this.get(input.prevout.hash);

  if (!coins)
    return false;

  return coins.coinbase;
};

/**
 * Retrieve coins from database.
 * @method
 * @param {ChainDB} db
 * @param {TX} tx
 * @returns {Promise} - Returns {@link Coins}.
 */

CoinView.prototype.readCoins = async function readCoins(db, hash) {
  let coins = this.map.get(hash);

  if (!coins) {
    coins = await db.getCoins(hash);

    if (!coins)
      return;

    this.map.set(hash, coins);
  }

  return coins;
};

/**
 * Read all input coins into unspent map.
 * @method
 * @param {ChainDB} db
 * @param {TX} tx
 * @returns {Promise} - Returns {Boolean}.
 */

CoinView.prototype.ensureInputs = async function ensureInputs(db, tx) {
  let found = true;

  for (const input of tx.inputs) {
    if (!await this.readCoins(db, input.prevout.hash))
      found = false;
  }

  return found;
};

/**
 * Spend coins for transaction.
 * @method
 * @param {ChainDB} db
 * @param {TX} tx
 * @returns {Promise} - Returns {Boolean}.
 */

CoinView.prototype.spendInputs = async function spendInputs(db, tx) {
  for (const input of tx.inputs) {
    const prevout = input.prevout;
    const coins = await this.readCoins(db, prevout.hash);

    if (!coins)
      return false;

    if (!this.spendFrom(coins, prevout.index))
      return false;
  }

  return true;
};

/**
 * Convert collection to an array.
 * @returns {Coins[]}
 */

CoinView.prototype.toArray = function toArray() {
  const out = [];

  for (const coins of this.map.values())
    out.push(coins);

  return out;
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

CoinView.prototype.getSize = function getSize(tx) {
  let size = 0;

  size += tx.inputs.length;

  for (const input of tx.inputs) {
    const entry = this.getEntry(input);

    if (!entry)
      continue;

    size += entry.getSize();
  }

  return size;
};

/**
 * Write coin data to buffer writer
 * as it pertains to a transaction.
 * @param {BufferWriter} bw
 * @param {TX} tx
 */

CoinView.prototype.toWriter = function toWriter(bw, tx) {
  for (const input of tx.inputs) {
    const prevout = input.prevout;
    const coins = this.get(prevout.hash);

    if (!coins) {
      bw.writeU8(0);
      continue;
    }

    const entry = coins.get(prevout.index);

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
 * Read serialized view data from a buffer
 * reader as it pertains to a transaction.
 * @private
 * @param {BufferReader} br
 * @param {TX} tx
 */

CoinView.prototype.fromReader = function fromReader(br, tx) {
  for (const input of tx.inputs) {
    const prevout = input.prevout;

    if (br.readU8() === 0)
      continue;

    let coins = this.get(prevout.hash);

    if (!coins) {
      coins = new Coins();
      coins.hash = prevout.hash;
      coins.coinbase = false;
      this.add(coins);
    }

    const entry = CoinEntry.fromReader(br);
    coins.add(prevout.index, entry);
  }

  return this;
};

/**
 * Read serialized view data from a buffer
 * reader as it pertains to a transaction.
 * @param {BufferReader} br
 * @param {TX} tx
 * @returns {CoinView}
 */

CoinView.fromReader = function fromReader(br, tx) {
  return new CoinView().fromReader(br, tx);
};

/*
 * Expose
 */

module.exports = CoinView;
