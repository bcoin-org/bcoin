/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

/**
 * Represents the outputs for a single transaction.
 * @exports Coins
 * @constructor
 * @param {TX|Object} tx/options - TX or options object.
 * @param {Hash|Buffer} hash - Transaction hash.
 * @property {Hash} hash - Transaction hash.
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {Coin[]} outputs - Coins.
 */

function Coins(options, hash) {
  if (!(this instanceof Coins))
    return new Coins(options, hash);

  this.version = options.version;
  this.height = options.height;

  this.coinbase = options.isCoinbase
    ? options.isCoinbase()
    : options.coinbase;

  this.hash = hash;

  this.outputs = options.outputs.map(function(coin, i) {
    if (!coin)
      return null;

    if (coin instanceof bcoin.coin)
      return coin;

    coin = utils.merge({}, coin);
    coin.version = options.version;
    coin.height = options.height;
    coin.hash = hash;
    coin.index = i;
    coin.coinbase = this.coinbase;

    return new bcoin.coin(coin);
  }, this);
}

/**
 * Add a coin to the collection.
 * @param {Coin|TX} tx/coin
 * @param {Number?} index
 */

Coins.prototype.add = function add(tx, i) {
  var coin;

  if (i == null) {
    coin = tx;
    this.outputs[coin.index] = coin;
    return;
  }

  this.outputs[i] = new bcoin.coin(tx, i);
};

/**
 * Test whether the collection has a coin.
 * @param {Number} index
 * @returns {Boolean}
 */

Coins.prototype.has = function has(index) {
  return this.outputs[index] != null;
};

/**
 * Get a coin.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.get = function get(index) {
  return this.outputs[index];
};

/**
 * Remove a coin.
 * @param {Number} index
 */

Coins.prototype.remove = function remove(index) {
  if (index < this.outputs.length)
    this.outputs[index] = null;
};

/**
 * Remove a coin and return it.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.spend = function spend(index) {
  var coin = this.get(index);
  this.remove(index);
  return coin;
};

/**
 * Fill transaction(s) with coins.
 * @param {TX|TX[]} tx
 * @param {Boolean?} spend - Whether the coins should
 * be spent when filling.
 * @returns {Boolean} True if any inputs were filled.
 */

Coins.prototype.fill = function fill(tx, spend) {
  var res = true;
  var i, input;

  if (tx.txs)
    tx = tx.txs;

  if (Array.isArray(tx)) {
    for (i = 0; i < tx.length; i++) {
      if (!this.fill(tx[i]))
        res = false;
    }
    return res;
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    if (input.prevout.hash !== this.hash)
      continue;

    if (!input.coin) {
      if (spend)
        input.coin = this.spend(input.prevout.index);
      else
        input.coin = this.get(input.prevout.index);

      if (!input.coin)
        res = false;
    }
  }

  return res;
};

/**
 * Count number of available coins.
 * @returns {Number} Total.
 */

Coins.prototype.count = function count() {
  return this.outputs.reduce(function(total, output) {
    if (!output)
      return total;
    return total + 1;
  }, 0);
};

/**
 * Convert collection to an array.
 * @returns {Coin[]}
 */

Coins.prototype.toArray = function toArray() {
  return this.outputs.filter(Boolean);
};

/**
 * Serialize the coins object.
 * @returns {Buffer}
 */

Coins.prototype.toRaw = function toRaw() {
  return Coins.toRaw(this);
};

/**
 * Instantiate a coins object from a transaction.
 * @param {TX} tx
 * @returns {Coins}
 */

Coins.fromTX = function fromTX(tx) {
  return new Coins(tx, tx.hash('hex'));
};

/**
 * Serialize the coins object.
 * @param {TX|Coins} tx
 * @returns {Buffer}
 */

Coins.toRaw = function toRaw(tx) {
  var p = new BufferWriter();
  var height = tx.height;

  if (height === -1)
    height = 0x7fffffff;

  p.writeU32(tx.version);
  p.writeU32(height);
  p.writeU8(tx.coinbase ? 1 : 0);
  p.writeVarint(tx.outputs.length);

  tx.outputs.forEach(function(output) {
    if (!output) {
      p.writeVarint(0);
      return;
    }
    p.writeVarBytes(bcoin.protocol.framer.output(output));
  });

  return p.render();
};

/**
 * Parse serialized coins.
 * @param {Buffer} buf
 * @returns {Object} A "naked" coins object.
 */

Coins.parseRaw = function parseRaw(buf) {
  var tx = { outputs: [] };
  var p = new BufferReader(buf);
  var coinCount, i, coin;

  tx.version = p.readU32();
  tx.height = p.readU32();
  tx.coinbase = p.readU8() === 1;

  if (tx.height === 0x7fffffff)
    tx.height = -1;

  coinCount = p.readVarint();
  for (i = 0; i < coinCount; i++) {
    coin = p.readVarBytes();
    if (coin.length === 0) {
      tx.outputs.push(null);
      continue;
    }
    coin = bcoin.protocol.parser.parseOutput(coin);
    tx.outputs.push(coin);
  }

  return tx;
};

/**
 * Instantiate coins from a serialized Buffer.
 * @param {Buffer} data
 * @param {Hash|Buffer} hash - Transaction hash.
 * @returns {Coins}
 */

Coins.fromRaw = function fromRaw(buf, hash) {
  return new Coins(Coins.parseRaw(buf), hash);
};

return Coins;
};
