/*!
 * coinview.js - coin viewpoint object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var co = require('../utils/co');
var Coins = require('./coins');
var UndoCoins = require('./undocoins');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var CoinEntry = Coins.CoinEntry;

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

  this.map = {};
  this.undo = new UndoCoins();
}

/**
 * Get coins.
 * @param {Hash} hash
 * @returns {Coins} coins
 */

CoinView.prototype.get = function get(hash) {
  return this.map[hash];
};

/**
 * Test whether the view has an entry.
 * @param {Hash} hash
 * @returns {Boolean}
 */

CoinView.prototype.has = function has(hash) {
  return this.map[hash] != null;
};

/**
 * Add coins to the collection.
 * @param {Coins} coins
 */

CoinView.prototype.add = function add(coins) {
  this.map[coins.hash] = coins;
  return coins;
};

/**
 * Remove coins from the collection.
 * @param {Coins} coins
 * @returns {Boolean}
 */

CoinView.prototype.remove = function remove(hash) {
  if (!this.map[hash])
    return false;

  delete this.map[hash];

  return true;
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
 * Add a coin to the collection.
 * @param {Coin} coin
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
  var coins = this.get(hash);

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
  var coins = this.get(hash);

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
  var coins = this.get(hash);

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
  var coins = this.get(input.prevout.hash);

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
  var coins = this.get(input.prevout.hash);

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
  var coins = this.get(input.prevout.hash);

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
  var coins = this.get(input.prevout.hash);

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
  var coins = this.get(input.prevout.hash);

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
  var coins = this.get(input.prevout.hash);

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

CoinView.prototype.readCoins = co(function* readCoins(db, hash) {
  var coins = this.map[hash];

  if (!coins) {
    coins = yield db.getCoins(hash);

    if (!coins)
      return;

    this.map[hash] = coins;
  }

  return coins;
});

/**
 * Read all input coins into unspent map.
 * @method
 * @param {ChainDB} db
 * @param {TX} tx
 * @returns {Promise} - Returns {Boolean}.
 */

CoinView.prototype.ensureInputs = co(function* ensureInputs(db, tx) {
  var found = true;
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!(yield this.readCoins(db, input.prevout.hash)))
      found = false;
  }

  return found;
});

/**
 * Spend coins for transaction.
 * @method
 * @param {ChainDB} db
 * @param {TX} tx
 * @returns {Promise} - Returns {Boolean}.
 */

CoinView.prototype.spendInputs = co(function* spendInputs(db, tx) {
  var i, input, prevout, coins;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    coins = yield this.readCoins(db, prevout.hash);

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
  var keys = Object.keys(this.map);
  var out = [];
  var i, hash;

  for (i = 0; i < keys.length; i++) {
    hash = keys[i];
    out.push(this.map[hash]);
  }

  return out;
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

CoinView.prototype.getFastSize = function getFastSize(tx) {
  var size = 0;
  var i, input, entry;

  size += tx.inputs.length;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    entry = this.getEntry(input);

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

CoinView.prototype.toFast = function toFast(bw, tx) {
  var i, input, prevout, coins, entry;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    coins = this.get(prevout.hash);

    if (!coins) {
      bw.writeU8(0);
      continue;
    }

    entry = coins.get(prevout.index);

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

CoinView.prototype.fromFast = function fromFast(br, tx) {
  var i, input, prevout, coins, entry;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (br.readU8() === 0)
      continue;

    coins = this.get(prevout.hash);

    if (!coins) {
      coins = new Coins();
      coins.hash = prevout.hash;
      coins.coinbase = false;
      this.add(coins);
    }

    entry = CoinEntry.fromReader(br);
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

CoinView.fromFast = function fromFast(br, tx) {
  return new CoinView().fromFast(br, tx);
};

/**
 * Write coin data to buffer writer
 * as it pertains to a transaction.
 * @param {BufferWriter} bw
 * @param {TX} tx
 */

CoinView.prototype.toWriter = function toWriter(bw, tx) {
  var map = {};
  var i, input, prevout, coins, entry, height;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    coins = this.get(prevout.hash);

    if (!coins) {
      bw.writeU8(0);
      continue;
    }

    entry = coins.get(prevout.index);

    if (!entry) {
      bw.writeU8(0);
      continue;
    }

    bw.writeU8(1);

    if (!map[prevout.hash]) {
      height = coins.height;
      if (height === -1)
        height = 0;
      bw.writeVarint(height * 2 + (coins.coinbase ? 1 : 0));
      bw.writeVarint(coins.version);
      map[prevout.hash] = true;
    }

    entry.toWriter(bw);
  }

  return bw;
};

/**
 * Serialize coin data to as it
 * pertains to a transaction.
 * @param {TX} tx
 * @returns {Buffer}
 */

CoinView.prototype.toRaw = function toRaw(tx) {
  return this.toWriter(new BufferWriter()).render();
};

/**
 * Read serialized view data from a buffer
 * reader as it pertains to a transaction.
 * @private
 * @param {BufferReader} br
 * @param {TX} tx
 */

CoinView.prototype.fromReader = function fromReader(br, tx) {
  var i, input, prevout, coins, entry, height;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (br.readU8() === 0)
      continue;

    coins = this.get(prevout.hash);

    if (!coins) {
      coins = new Coins();
      coins.hash = prevout.hash;
      height = br.readVarint();
      coins.coinbase = (height & 1) !== 0;
      height = height / 2 | 0;
      if (height === 0)
        height = -1;
      coins.height = height;
      coins.version = br.readVarint();
      this.add(coins);
    }

    entry = CoinEntry.fromReader(br);
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

/**
 * Read serialized view data from a buffer
 * as it pertains to a transaction.
 * @param {Buffer} data
 * @param {TX} tx
 * @returns {CoinView}
 */

CoinView.fromRaw = function fromRaw(data, tx) {
  return new CoinView().fromReader(new BufferReader(data), tx);
};

/*
 * Expose
 */

module.exports = CoinView;
