/**
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

/**
 * Coins
 */

function Coins(options, hash) {
  if (!(this instanceof Coins))
    return new Coins(options, hash);

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);

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

Coins.prototype.add = function add(tx, i) {
  var coin;

  if (i == null) {
    coin = tx;
    this.outputs[coin.index] = coin;
    return;
  }

  this.outputs[i] = new bcoin.coin(tx, i);
};

Coins.prototype.has = function has(index) {
  return this.outputs[index] != null;
};

Coins.prototype.get = function get(index) {
  return this.outputs[index];
};

Coins.prototype.remove = function remove(index) {
  if (index < this.outputs.length)
    this.outputs[index] = null;
};

Coins.prototype.spend = function spend(hash, index) {
  var coin = this.get(hash, index);
  this.remove(hash, index);
  return coin;
};

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

    if (!input.output) {
      if (spend)
        input.output = this.spend(input.prevout.index);
      else
        input.output = this.get(input.prevout.index);

      if (!input.output)
        res = false;
    }
  }

  return res;
};

Coins.prototype.count = function count(index) {
  return this.outputs.reduce(function(total, output) {
    if (!output)
      return total;
    return total + 1;
  }, 0);
};

Coins.prototype.forEach = function forEach(callback, context) {
  this.outputs.forEach(function(output, i) {
    callback.call(context || this, output, i);
  }, this);
};

Coins.prototype.toRaw = function toRaw() {
  return Coins.toRaw(this);
};

Coins.fromTX = function fromTX(tx) {
  return new Coins(tx, tx.hash('hex'));
};

Coins.toRaw = function toRaw(tx) {
  var p = new BufferWriter();
  var height = tx.height;

  if (height === -1)
    height = 0x7fffffff;

  p.writeU32(tx.version);
  p.writeU32(height);
  p.writeU8(tx.coinbase ? 1 : 0);
  p.writeUIntv(tx.outputs.length);

  tx.outputs.forEach(function(output) {
    if (!output) {
      p.writeUIntv(0);
      return;
    }
    p.writeVarBytes(bcoin.protocol.framer.output(output));
  });

  return p.render();
};

Coins._fromRaw = function _fromRaw(buf) {
  var tx = { outputs: [] };
  var p = new BufferReader(buf);
  var coinCount, i, coin;

  tx.version = p.readU32();
  tx.height = p.readU32();
  tx.coinbase = p.readU8() === 1;

  if (tx.height === 0x7fffffff)
    tx.height = -1;

  coinCount = p.readUIntv();
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

Coins.fromRaw = function fromRaw(buf, hash) {
  return new Coins(Coins._fromRaw(buf), hash);
};

/**
 * Expose
 */

module.exports = Coins;
