/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
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
 * @property {Hash} hash - Transaction hash.
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {Coin[]} outputs - Coins.
 */

function Coins(options) {
  var i, coin;

  if (!(this instanceof Coins))
    return new Coins(options);

  if (!options)
    options = {};

  this.version = options.version != null ? options.version : -1;
  this.hash = options.hash || null;
  this.height = options.height != null ? options.height : -1;
  this.coinbase = options.coinbase || false;
  this.outputs = options.outputs || [];
}

/**
 * Add a single coin to the collection.
 * @param {Coin} coin
 */

Coins.prototype.add = function add(coin) {
  if (this.version === -1) {
    this.version = coin.version;
    this.hash = coin.hash;
    this.height = coin.height;
    this.coinbase = coin.coinbase;
  }

  if (coin.script.isUnspendable()) {
    this.outputs[coin.index] = null;
    return;
  }

  this.outputs[coin.index] = coin;
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
 * Count unspent coins.
 * @returns {Number}
 */

Coins.prototype.count = function count(index) {
  var total = 0;
  var i;

  for (i = 0; i < this.outputs.length; i++) {
    if (this.outputs[i])
      total++;
  }

  return total;
};

/**
 * Remove a coin and return it.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.spend = function spend(index) {
  var coin = this.get(index);
  this.outputs[index] = null;
  return coin;
};

/**
 * Fill transaction(s) with coins.
 * @param {TX} tx
 * @param {Boolean?} spend - Whether the coins should
 * be spent when filling.
 * @returns {Boolean} True if all inputs were filled.
 */

Coins.prototype.fill = function fill(tx) {
  var res = true;
  var i, input, prevout;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    if (prevout.hash !== this.hash)
      continue;
    input.coin = this.spend(prevout.index);
    if (!input.coin)
      res = false;
  }

  return res;
};

/**
 * Convert collection to an array.
 * @returns {Coin[]}
 */

Coins.prototype.toArray = function toArray() {
  var out = [];
  var i;

  for (i = 0; i < this.outputs.length; i++) {
    if (this.outputs[i])
      out.push(this.outputs[i]);
  }

  return out;
};

/**
 * Serialize the coins object.
 * @param {TX|Coins} tx
 * @returns {Buffer}
 */

Coins.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var height = this.height;
  var i, output, prefix, hash, coinbase, mask;

  if (height === -1)
    height = 0x7fffffff;

  coinbase = this.coinbase;

  mask = (height << 1) | (coinbase ? 1 : 0);

  p.writeVarint(this.version);
  p.writeU32(mask >>> 0);

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];

    if (!output) {
      p.writeU8(0xff);
      continue;
    }

    prefix = 0;

    // Saves up to 7 bytes.
    if (isPubkeyhash(output.script)) {
      prefix = 1;
      hash = output.script.code[2];
    } else if (isScripthash(output.script)) {
      prefix = 2;
      hash = output.script.code[1];
    }

    // p.writeU8(((output.spent ? 1 : 0) << 2) | prefix);
    p.writeU8(prefix);

    if (prefix)
      p.writeBytes(hash);
    else
      bcoin.protocol.framer.script(output.script, p);

    p.writeVarint(output.value);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Parse serialized coins.
 * @param {Buffer} data
 * @param {Hash} hash
 * @returns {Object} A "naked" coins object.
 */

Coins.parseRaw = function parseRaw(data, hash) {
  var coins = {};
  var p = new BufferReader(data);
  var i = 0;
  var coin, mask, prefix;

  coins.version = p.readVarint();
  coins.height = p.readU32();
  coins.hash = hash;
  coins.coinbase = (coins.height & 1) !== 0;
  coins.height >>>= 1;
  coins.outputs = [];

  if (coins.height === 0x7fffffff)
    coins.height = -1;

  while (p.left()) {
    mask = p.readU8();

    if (mask === 0xff) {
      coins.outputs.push(null);
      i++;
      continue;
    }

    coin = {};
    coin.version = coins.version;
    coin.coinbase = coins.coinbase;
    coin.height = coins.height;
    coin.hash = coins.hash;
    coin.index = i++;

    // coin.spent = (mask & 4) !== 0;
    prefix = mask & 3;

    if (prefix === 0)
      coin.script = new bcoin.script(bcoin.protocol.parser.parseScript(p));
    else if (prefix === 1)
      coin.script = bcoin.script.createPubkeyhash(p.readBytes(20));
    else if (prefix === 2)
      coin.script = bcoin.script.createScripthash(p.readBytes(20));
    else
      assert(false, 'Bad prefix.');

    coin.value = p.readVarint();

    coins.outputs.push(new bcoin.coin(coin));
  }

  return coins;
};

/**
 * Parse a single serialized coin.
 * @param {Buffer} data
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

Coins.parseCoin = function parseCoin(data, hash, index) {
  var p = new BufferReader(data);
  var i = 0;
  var mask, prefix, version, height, coinbase, spent, script, value;

  version = p.readVarint();
  height = p.readU32();
  coinbase = (height & 1) !== 0;
  height >>>= 1;

  if (height === 0x7fffffff)
    height = -1;

  while (p.left()) {
    mask = p.readU8();

    if (mask === 0xff) {
      if (i === index)
        break;
      i++;
      continue;
    }

    // spent = (mask & 4) !== 0;
    prefix = mask & 3;

    if (i !== index) {
      if (prefix === 0)
        p.seek(p.readVarint());
      else if (prefix <= 2)
        p.seek(20);
      else
        assert(false, 'Bad prefix.');
      p.readVarint();
      i++;
      continue;
    }

    if (prefix === 0)
      script = new bcoin.script(bcoin.protocol.parser.parseScript(p));
    else if (prefix === 1)
      script = bcoin.script.createPubkeyhash(p.readBytes(20));
    else if (prefix === 2)
      script = bcoin.script.createScripthash(p.readBytes(20));
    else
      assert(false, 'Bad prefix.');

    value = p.readVarint();

    return new bcoin.coin({
      version: version,
      coinbase: coinbase,
      height: height,
      hash: hash,
      index: i,
      // spent: spent,
      script: script,
      value: value
    });
  }

  assert(false, 'No coin.');
};

/**
 * Instantiate coins from a serialized Buffer.
 * @param {Buffer} data
 * @param {Hash} hash - Transaction hash.
 * @returns {Coins}
 */

Coins.fromRaw = function fromRaw(data, hash) {
  return new Coins(Coins.parseRaw(data, hash));
};

/**
 * Instantiate a coins object from a transaction.
 * @param {TX} tx
 * @returns {Coins}
 */

Coins.fromTX = function fromTX(tx) {
  var outputs = [];
  var i;

  for (i = 0; i < tx.outputs.length; i++) {
    if (tx.outputs[i].script.isUnspendable()) {
      outputs.push(null);
      continue;
    }
    outputs.push(bcoin.coin.fromTX(tx, i));
  }

  return new Coins({
    version: tx.version,
    hash: tx.hash('hex'),
    height: tx.height,
    coinbase: tx.isCoinbase(),
    outputs: outputs
  });
};

/*
 * Helpers
 */

function isPubkeyhash(script) {
  return script.isPubkeyhash() && bcoin.script.checkMinimal(script.code[2]);
}

function isScripthash(script) {
  return script.isScripthash() && bcoin.script.checkMinimal(script.code[1]);
}

/*
 * Expose
 */

module.exports = Coins;
