/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var bcoin = require('./env');
var utils = bcoin.utils;
var assert = utils.assert;
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
  var coin = this.outputs[index];
  if (!coin)
    return;

  if (coin instanceof DeferredCoin)
    coin = coin.toCoin(this, index);

  return coin;
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

    if (output instanceof DeferredCoin) {
      p.writeBytes(output.toRaw());
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

Coins.parseRaw = function parseRaw(data, hash, index) {
  var p = new BufferReader(data);
  var i = 0;
  var version, height, coins, mask, prefix, offset, size;

  version = p.readVarint();
  height = p.readU32();

  coins = {
    version: version,
    height: height >>> 1,
    hash: hash,
    coinbase: (height & 1) !== 0,
    outputs: []
  };

  if (coins.height === 0x7fffffff)
    coins.height = -1;

  while (p.left()) {
    offset = p.start();
    mask = p.readU8();

    if (mask === 0xff) {
      if (index != null) {
        if (i === index)
          return;
        i++;
        continue;
      }
      coins.outputs.push(null);
      i++;
      continue;
    }

    prefix = mask & 3;

    if (prefix === 0)
      p.seek(p.readVarint());
    else if (prefix <= 2)
      p.seek(20);
    else
      assert(false, 'Bad prefix.');

    p.readVarint();

    size = p.end();

    if (index != null && i !== index) {
      i++;
      continue;
    }

    coins.outputs.push(new DeferredCoin(offset, size, data));

    if (index != null)
      return coins.outputs[0].toCoin(coins, i);

    i++;
  }

  assert(index == null, 'Bad index.');

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
  assert(index != null, 'Bad index.');
  return Coins.parseRaw(data, hash, index);
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

/**
 * A "deferred" coin is an object which defers
 * parsing of a compressed coin. Say there is
 * a transaction with 100 outputs. When block
 * comes in, there may only be _one_ input in
 * that entire block which redeems an output
 * from that transaction. When parsing the
 * Coins, there is no sense to get _all_ of
 * them into their abstract form. A "deferred"
 * coin is just a pointer to that coin in the
 * Coins buffer, as well as a size. Parsing
 * is done only if that coin is being redeemed.
 * @exposes DeferredCoin
 * @constructor
 * @private
 * @param {Number} offset
 * @param {Number} size
 * @param {Buffer} raw
 */

function DeferredCoin(offset, size, raw) {
  this.offset = offset;
  this.size = size;
  this.raw = raw;
}

DeferredCoin.prototype.toCoin = function toCoin(coins, index) {
  var p = new BufferReader(this.raw);
  var prefix, script, value;

  p.seek(this.offset);

  prefix = p.readU8() & 3;

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
    version: coins.version,
    coinbase: coins.coinbase,
    height: coins.height,
    hash: coins.hash,
    index: index,
    script: script,
    value: value
  });
};

DeferredCoin.prototype.toRaw = function toRaw() {
  return this.raw.slice(this.offset, this.offset + this.size);
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
