/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

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
  if (!(this instanceof Coins))
    return new Coins(options);

  this.version = 1;
  this.hash = constants.NULL_HASH;
  this.height = -1;
  this.coinbase = true;
  this.outputs = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Coins.prototype.fromOptions = function fromOptions(options) {
  if (options.version != null)
    this.version = options.version;

  if (options.hash)
    this.hash = options.hash;

  if (options.height != null)
    this.height = options.height;

  if (options.coinbase != null)
    this.coinbase = options.coinbase;

  if (options.outputs)
    this.outputs = options.outputs;

  return this;
};

/**
 * Instantiate coins from options object.
 * @param {Object} options
 * @returns {Coins}
 */

Coins.fromOptions = function fromOptions(options) {
  return new Coins().fromOptions(options);
};

/**
 * Add a single coin to the collection.
 * @param {Coin} coin
 */

Coins.prototype.add = function add(coin) {
  if (this.outputs.length === 0) {
    this.version = coin.version;
    this.hash = coin.hash;
    this.height = coin.height;
    this.coinbase = coin.coinbase;
  }

  while (this.outputs.length <= coin.index)
    this.outputs.push(null);

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

  if (coin instanceof CompressedCoin)
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
 * Count up to the last available index.
 * @returns {Number}
 */

Coins.prototype.getLength = function getLength() {
  var last = -1;
  var i;

  for (i = 0; i < this.outputs.length; i++) {
    if (this.outputs[i])
      last = i;
  }

  return last + 1;
};

/*
 * Coins serialization:
 * version: varint
 * bits: varint ((height << 1) | coinbase-flag)
 * outputs (repeated):
 *   prefix: 0xff = spent
 *           0x00 = varint size | raw script
 *           0x01 = 20 byte pubkey hash
 *           0x02 = 20 byte script hash
 *           0x03 = 33 byte compressed key
 *   data: the data mentioned above
 *   value: varint
 */

/**
 * Serialize the coins object.
 * @param {TX|Coins} tx
 * @returns {Buffer}
 */

Coins.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var height = this.height;
  var length = this.getLength();
  var i, output, prefix, data, bits;

  // Unfortunately, we don't have a compact
  // way to store unconfirmed height.
  if (height === -1)
    height = 0x7fffffff;

  bits = height << 1;

  if (this.coinbase)
    bits |= 1;

  if (bits < 0)
    bits += 0x100000000;

  p.writeVarint(this.version);
  p.writeVarint(bits);

  for (i = 0; i < length; i++) {
    output = this.outputs[i];

    if (!output) {
      p.writeU8(0xff);
      continue;
    }

    if (output instanceof CompressedCoin) {
      p.writeBytes(output.toRaw());
      continue;
    }

    prefix = 0;

    // Attempt to compress the output scripts.
    // We can _only_ ever compress them if
    // they are serialized as minimaldata, as
    // we need to recreate them when we read
    // them.
    if (output.script.isPubkeyhash(true)) {
      prefix = 1;
      data = output.script.code[2].data;
    } else if (output.script.isScripthash()) {
      prefix = 2;
      data = output.script.code[1].data;
    } else if (output.script.isPubkey(true)) {
      prefix = 3;
      data = output.script.code[0].data;

      // Try to compress the key.
      data = bcoin.ec.compress(data);

      // If we can't compress it,
      // just store the script.
      if (!data)
        prefix = 0;
    }

    p.writeU8(prefix);

    if (prefix === 0)
      p.writeVarBytes(output.script.toRaw());
    else
      p.writeBytes(data);

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

Coins.prototype.fromRaw = function fromRaw(data, hash, index) {
  var p = new BufferReader(data);
  var i = 0;
  var bits, coin, prefix, offset, size;

  this.version = p.readVarint();

  bits = p.readVarint();

  this.height = bits >>> 1;
  this.hash = hash;
  this.coinbase = (bits & 1) !== 0;

  if (this.height === 0x7fffffff)
    this.height = -1;

  while (p.left()) {
    offset = p.start();
    prefix = p.readU8();

    // Already spent.
    if (prefix === 0xff) {
      p.end();

      // Don't bother pushing outputs on if
      // we're seeking to a specific index.
      if (index != null) {
        if (i === index)
          return;
        i++;
        continue;
      }

      this.outputs.push(null);
      i++;
      continue;
    }

    // Skip past the compressed scripts.
    switch (prefix & 3) {
      case 0:
        p.seek(p.readVarint());
        break;
      case 1:
      case 2:
        p.seek(20);
        break;
      case 3:
        p.seek(33);
        break;
      default:
        assert(false, 'Bad prefix.');
    }

    // Skip past the value.
    p.readVarint();

    size = p.end();

    // Keep going if we're seeking
    // to a specific index.
    if (index != null && i !== index) {
      i++;
      continue;
    }

    // Store the offset and size
    // in the compressed coin object.
    coin = new CompressedCoin(offset, size, data);

    // We found our coin.
    if (index != null)
      return coin.toCoin(this, i);

    this.outputs.push(coin);
    i++;
  }

  // We couldn't find our coin.
  if (index != null)
    return;

  return this;
};

/**
 * Parse a single serialized coin.
 * @param {Buffer} data
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

Coins.parseCoin = function parseCoin(data, hash, index) {
  assert(index != null, 'Bad coin index.');
  return new Coins().fromRaw(data, hash, index);
};

/**
 * Instantiate coins from a serialized Buffer.
 * @param {Buffer} data
 * @param {Hash} hash - Transaction hash.
 * @returns {Coins}
 */

Coins.fromRaw = function fromRaw(data, hash) {
  return new Coins().fromRaw(data, hash);
};

/**
 * Inject properties from tx.
 * @private
 * @param {TX} tx
 */

Coins.prototype.fromTX = function fromTX(tx) {
  var i;

  this.version = tx.version;
  this.hash = tx.hash('hex');
  this.height = tx.height;
  this.coinbase = tx.isCoinbase();

  for (i = 0; i < tx.outputs.length; i++) {
    if (tx.outputs[i].script.isUnspendable()) {
      this.outputs.push(null);
      continue;
    }
    this.outputs.push(bcoin.coin.fromTX(tx, i));
  }

  return this;
};

/**
 * Instantiate a coins object from a transaction.
 * @param {TX} tx
 * @returns {Coins}
 */

Coins.fromTX = function fromTX(tx) {
  return new Coins().fromTX(tx);
};

/**
 * A compressed coin is an object which defers
 * parsing of a coin. Say there is a transaction
 * with 100 outputs. When a block comes in,
 * there may only be _one_ input in that entire
 * block which redeems an output from that
 * transaction. When parsing the Coins, there
 * is no sense to get _all_ of them into their
 * abstract form. A compressed coin is just a
 * pointer to that coin in the Coins buffer, as
 * well as a size. Parsing is done only if that
 * coin is being redeemed.
 * @constructor
 * @private
 * @param {Number} offset
 * @param {Number} size
 * @param {Buffer} raw
 */

function CompressedCoin(offset, size, raw) {
  if (!(this instanceof CompressedCoin))
    return new CompressedCoin(offset, size, raw);

  this.offset = offset;
  this.size = size;
  this.raw = raw;
}

/**
 * Parse the deferred data and return a Coin.
 * @param {Coins} coins
 * @param {Number} index
 * @returns {Coin}
 */

CompressedCoin.prototype.toCoin = function toCoin(coins, index) {
  var p = new BufferReader(this.raw);
  var coin = new bcoin.coin();
  var prefix, key;

  // Load in all necessary properties
  // from the parent Coins object.
  coin.version = coins.version;
  coin.coinbase = coins.coinbase;
  coin.height = coins.height;
  coin.hash = coins.hash;
  coin.index = index;

  // Seek to the coin's offset.
  p.seek(this.offset);

  prefix = p.readU8();

  // Decompress the script.
  switch (prefix & 3) {
    case 0:
      coin.script.fromRaw(p.readVarBytes());
      break;
    case 1:
      coin.script.fromPubkeyhash(p.readBytes(20));
      break;
    case 2:
      coin.script.fromScripthash(p.readBytes(20));
      break;
    case 3:
      // Decompress the key. If this fails,
      // we have database corruption!
      key = bcoin.ec.decompress(p.readBytes(33));
      coin.script.fromPubkey(key);
      break;
    default:
      assert(false, 'Bad prefix.');
  }

  coin.value = p.readVarint();

  return coin;
};

/**
 * Slice off the part of the buffer
 * relevant to this particular coin.
 * @returns {Buffer}
 */

CompressedCoin.prototype.toRaw = function toRaw() {
  return this.raw.slice(this.offset, this.offset + this.size);
};

/*
 * Expose
 */

module.exports = Coins;
