/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var assert = utils.assert;
var constants = require('../protocol/constants');
var Coin = require('../primitives/coin');
var ec = require('../crypto/ec');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

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
  if (options.version != null) {
    assert(utils.isNumber(options.version));
    this.version = options.version;
  }

  if (options.hash) {
    assert(typeof options.hash === 'string');
    this.hash = options.hash;
  }

  if (options.height != null) {
    assert(utils.isNumber(options.height));
    this.height = options.height;
  }

  if (options.coinbase != null) {
    assert(typeof options.coinbase === 'boolean');
    this.coinbase = options.coinbase;
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs));
    this.outputs = options.outputs;
  }

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
  if (!coin)
    return;

  this.outputs[index] = null;
  return coin;
};

/**
 * Count up to the last available index.
 * @returns {Number}
 */

Coins.prototype.size = function size() {
  var index = -1;
  var i;

  for (i = this.outputs.length - 1; i >= 0; i--) {
    if (this.outputs[i]) {
      index = i;
      break;
    }
  }

  return index + 1;
};

/*
 * Coins serialization:
 * version: varint
 * bits: uint32 (31-bit height | 1-bit coinbase-flag)
 * spent-field: varint size | bitfield (0=unspent, 1=spent)
 * outputs (repeated):
 *   compressed-script:
 *     prefix: 0x00 = varint size | raw script
 *             0x01 = 20 byte pubkey hash
 *             0x02 = 20 byte script hash
 *             0x03 = 33 byte compressed key
 *     data: script data, dictated by the prefix
 *   value: varint
 *
 * The compression below sacrifices some cpu in exchange
 * for reduced size, but in some cases the use of varints
 * actually increases speed (varint versions and values
 * for example). We do as much compression as possible
 * without sacrificing too much cpu. Value compression
 * is intentionally excluded for now as it seems to be
 * too much of a perf hit. Maybe when v8 optimizes
 * non-smi arithmetic better we can enable it.
 */

/**
 * Serialize the coins object.
 * @param {TX|Coins} tx
 * @returns {Buffer}
 */

Coins.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter();
  var height = this.height;
  var length = this.size();
  var i, output, bits, fstart, flen, bit, oct;

  // Return nothing if we're fully spent.
  if (length === 0)
    return writer;

  // Varint version: hopefully some smartass
  // miner doesn't start mining `-1` versions.
  p.writeVarint(this.version);

  // Unfortunately, we don't have a compact
  // way to store unconfirmed height.
  if (height === -1)
    height = 0x7fffffff;

  // Create the `bits` value:
  // (height | coinbase-flag).
  bits = height << 1;

  if (this.coinbase)
    bits |= 1;

  if (bits < 0)
    bits += 0x100000000;

  // Making this a varint would actually
  // make 99% of coins bigger. Varints
  // are really only useful up until
  // 0x10000, but since we're also
  // storing the coinbase flag on the
  // lo bit, varints are useless (and
  // actually harmful) after height
  // 32767 (0x7fff).
  p.writeU32(bits);

  // Fill the spent field with zeroes to avoid
  // allocating a buffer. We mark the spents
  // after rendering the final buffer.
  flen = Math.ceil(length / 8);
  p.writeVarint(flen);
  fstart = p.written;
  p.fill(0, flen);

  for (i = 0; i < length; i++) {
    output = this.outputs[i];

    if (!output)
      continue;

    // If we read this coin from the db and
    // didn't use it, it's still in its
    // compressed form. Just write it back
    // as a buffer for speed.
    if (output instanceof CompressedCoin) {
      p.writeBytes(output.toRaw());
      continue;
    }

    compressScript(output.script, p);
    p.writeVarint(output.value);
  }

  // Render the buffer with all
  // zeroes in the spent field.
  p = p.render();

  // Mark the spents in the spent field.
  // This is essentially a NOP for new coins.
  for (i = 0; i < length; i++) {
    if (this.outputs[i])
      continue;
    bit = i % 8;
    oct = (i - bit) / 8;
    p[fstart + oct] |= 1 << (7 - bit);
  }

  if (writer) {
    writer.writeBytes(p);
    return writer;
  }

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
  var bits, coin, offset, size, fstart, flen, bit, oct, spent;

  this.version = p.readVarint();

  bits = p.readU32();

  this.height = bits >>> 1;
  this.hash = hash;
  this.coinbase = (bits & 1) !== 0;

  if (this.height === 0x7fffffff)
    this.height = -1;

  // Mark the start of the spent field and
  // seek past it to avoid reading a buffer.
  flen = p.readVarint();
  fstart = p.offset;
  p.seek(flen);

  while (p.left()) {
    // Read a single bit out of the spent field.
    bit = i % 8;
    oct = (i - bit) / 8;
    spent = (p.data[fstart + oct] >>> (7 - bit)) & 1;

    // Already spent.
    if (spent) {
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

    offset = p.offset;

    // Skip past the compressed scripts.
    switch (p.readU8()) {
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
        throw new Error('Bad prefix.');
    }

    // Skip past the value.
    p.readVarint();

    size = p.offset - offset;

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
    this.outputs.push(Coin.fromTX(tx, i));
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
  var coin = new Coin();

  // Load in all necessary properties
  // from the parent Coins object.
  coin.version = coins.version;
  coin.coinbase = coins.coinbase;
  coin.height = coins.height;
  coin.hash = coins.hash;
  coin.index = index;

  // Seek to the coin's offset.
  p.seek(this.offset);

  decompressScript(p, coin.script);

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
 * Compression
 */

/**
 * Compress a script, write directly to the buffer.
 * @param {Script} script
 * @param {BufferWriter} p
 */

function compressScript(script, p) {
  var prefix = 0;
  var data;

  // Attempt to compress the output scripts.
  // We can _only_ ever compress them if
  // they are serialized as minimaldata, as
  // we need to recreate them when we read
  // them.
  if (script.isPubkeyhash(true)) {
    prefix = 1;
    data = script.code[2].data;
  } else if (script.isScripthash()) {
    prefix = 2;
    data = script.code[1].data;
  } else if (script.isPubkey(true)) {
    prefix = 3;
    data = script.code[0].data;

    // Try to compress the key.
    data = compressKey(data);

    // If we can't compress it,
    // just store the script.
    if (!data)
      prefix = 0;
  }

  p.writeU8(prefix);

  if (prefix === 0)
    p.writeVarBytes(script.toRaw());
  else
    p.writeBytes(data);
}

/**
 * Decompress a script from buffer reader.
 * @param {BufferReader} p
 * @param {Script} script
 */

function decompressScript(p, script) {
  var key;

  // Decompress the script.
  switch (p.readU8()) {
    case 0:
      script.fromRaw(p.readVarBytes());
      break;
    case 1:
      script.fromPubkeyhash(p.readBytes(20));
      break;
    case 2:
      script.fromScripthash(p.readBytes(20));
      break;
    case 3:
      // Decompress the key. If this fails,
      // we have database corruption!
      key = decompressKey(p.readBytes(33));
      script.fromPubkey(key);
      break;
    default:
      throw new Error('Bad prefix.');
  }
}

/**
 * Compress value using an exponent. Takes advantage of
 * the fact that many bitcoin values are divisible by 10.
 * @see https://github.com/btcsuite/btcd/blob/master/blockchain/compress.go
 * @param {Amount} value
 * @returns {Number}
 */

function compressValue(value) {
  var exp, last;

  if (value === 0)
    return 0;

  exp = 0;
  while (value % 10 === 0 && exp < 9) {
    value /= 10;
    exp++;
  }

  if (exp < 9) {
    last = value % 10;
    value = (value - last) / 10;
    return 1 + 10 * (9 * value + last - 1) + exp;
  }

  return 10 + 10 * (value - 1);
}

/**
 * Decompress value.
 * @param {Number} value - Compressed value.
 * @returns {Amount} value
 */

function decompressValue(value) {
  var exp, n, last;

  if (value === 0)
    return 0;

  value--;

  exp = value % 10;
  value = (value - exp) / 10;

  if (exp < 9) {
    last = value % 9;
    value = (value - last) / 9;
    n = value * 10 + last + 1;
  } else {
    n = value + 1;
  }

  while (exp > 0) {
    n *= 10;
    exp--;
  }

  return n;
}

/**
 * Compress a public key to coins compression format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function compressKey(key) {
  var out;

  // We can't compress it if it's not valid.
  if (!ec.publicKeyVerify(key))
    return;

  switch (key[0]) {
    case 0x02:
    case 0x03:
      // Key is already compressed.
      out = key;
      break;
    case 0x04:
    case 0x06:
    case 0x07:
      // Compress the key normally.
      out = ec.publicKeyConvert(key, true);
      // Store the original format (which
      // may be a hybrid byte) in the hi
      // 3 bits so we can restore it later.
      // The hi bits being set also lets us
      // know that this key was originally
      // decompressed.
      out[0] |= key[0] << 2;
      break;
    default:
      throw new Error('Bad point format.');
  }

  assert(out.length === 33);

  return out;
}

/**
 * Decompress a public key from the coins compression format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function decompressKey(key) {
  var format = key[0] >>> 2;
  var out;

  assert(key.length === 33);

  // Hi bits are not set. This key
  // is not meant to be decompressed.
  if (format === 0)
    return key;

  // Decompress the key, and off the
  // low bits so publicKeyConvert
  // actually understands it.
  key[0] &= 0x03;
  out = ec.publicKeyConvert(key, false);

  // Reset the hi bits so as not to
  // mutate the original buffer.
  key[0] |= format << 2;

  // Set the original format, which
  // may have been a hybrid prefix byte.
  out[0] = format;

  return out;
}

/*
 * Expose
 */

exports = Coins;

exports.compress = {
  script: compressScript,
  value: compressValue,
  key: compressKey
};

exports.decompress = {
  script: decompressScript,
  value: decompressValue,
  key: decompressKey
};

module.exports = exports;
