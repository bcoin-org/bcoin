/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var assert = require('assert');
var constants = require('../protocol/constants');
var Coin = require('../primitives/coin');
var Output = require('../primitives/output');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var compressor = require('./compress');
var compress = compressor.compress;
var decompress = compressor.decompress;

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
    assert(util.isNumber(options.version));
    this.version = options.version;
  }

  if (options.hash) {
    assert(typeof options.hash === 'string');
    this.hash = options.hash;
  }

  if (options.height != null) {
    assert(util.isNumber(options.height));
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

  if (coin.script.isUnspendable())
    return;

  while (this.outputs.length <= coin.index)
    this.outputs.push(null);

  this.outputs[coin.index] = CoinEntry.fromCoin(coin);
};

/**
 * Test whether the collection has a coin.
 * @param {Number} index
 * @returns {Boolean}
 */

Coins.prototype.has = function has(index) {
  if (index >= this.outputs.length)
    return false;

  return this.outputs[index] != null;
};

/**
 * Get a coin.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.get = function get(index) {
  var coin;

  if (index >= this.outputs.length)
    return;

  coin = this.outputs[index];

  if (!coin)
    return;

  return coin.toCoin(this, index);
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
  this.cleanup();

  return coin;
};

/**
 * Get a coin.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.get2 = function get2(index) {
  var coin;

  if (index >= this.outputs.length)
    return;

  coin = this.outputs[index];

  if (!coin)
    return;

  return coin.toCoin2(this, index);
};

/**
 * Remove a coin and return it.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.spend2 = function spend2(index) {
  var coin = this.get2(index);

  if (!coin)
    return;

  this.outputs[index] = null;
  this.cleanup();

  return coin;
};

/**
 * Cleanup spent outputs.
 */

Coins.prototype.cleanup = function cleanup() {
  var len = this.outputs.length;

  while (len > 0 && !this.outputs[len - 1])
    len--;

  this.outputs.length = len;
};

/**
 * Count up to the last available index.
 * @returns {Number}
 */

Coins.prototype.size = function size() {
  var index = -1;
  var i, output;

  for (i = this.outputs.length - 1; i >= 0; i--) {
    output = this.outputs[i];
    if (output) {
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

Coins.prototype.toRaw = function toRaw() {
  var bw = new BufferWriter();
  var length = this.size();
  var len = Math.ceil(length / 8);
  var i, output, bits, start, bit, oct, data;

  // Return nothing if we're fully spent.
  if (length === 0)
    return;

  // Varint version: hopefully we
  // never run into `-1` versions.
  bw.writeVarint(this.version);

  // Create the `bits` value:
  // (height | coinbase-flag).
  bits = this.height << 1;

  // Append the coinbase bit.
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
  bw.writeU32(bits);

  // Fill the spent field with zeroes to avoid
  // allocating a buffer. We mark the spents
  // after rendering the final buffer.
  bw.writeVarint(len);
  start = bw.written;
  bw.fill(0, len);

  // Write the compressed outputs.
  for (i = 0; i < length; i++) {
    output = this.outputs[i];

    if (!output)
      continue;

    output.toWriter(bw);
  }

  // Render the buffer with all
  // zeroes in the spent field.
  data = bw.render();

  // Mark the spents in the spent field.
  // This is essentially a NOP for new coins.
  for (i = 0; i < length; i++) {
    output = this.outputs[i];

    if (output)
      continue;

    bit = i % 8;
    oct = (i - bit) / 8;
    oct += start;

    data[oct] |= 1 << (7 - bit);
  }

  return data;
};

/**
 * Parse serialized coins.
 * @param {Buffer} data
 * @param {Hash} hash
 * @returns {Object} A "naked" coins object.
 */

Coins.prototype.fromRaw = function fromRaw(data, hash) {
  var br = new BufferReader(data);
  var pos = 0;
  var bits, len, start, bit, oct, spent, coin;

  this.version = br.readVarint();

  bits = br.readU32();

  this.height = bits >>> 1;
  this.hash = hash;
  this.coinbase = (bits & 1) !== 0;

  // Mark the start of the spent field and
  // seek past it to avoid reading a buffer.
  len = br.readVarint();
  start = br.offset;
  br.seek(len);

  while (br.left()) {
    bit = pos % 8;
    oct = (pos - bit) / 8;
    oct += start;

    // Read a single bit out of the spent field.
    spent = data[oct] >>> (7 - bit);
    spent &= 1;

    // Already spent.
    if (spent) {
      this.outputs.push(null);
      pos++;
      continue;
    }

    // Store the offset and size
    // in the compressed coin object.
    coin = CoinEntry.fromReader(br);

    this.outputs.push(coin);
    pos++;
  }

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
  var br = new BufferReader(data);
  var coin = new Coin();
  var pos = 0;
  var bits, len, start, bit, oct, spent;

  coin.version = br.readVarint();

  bits = br.readU32();

  coin.hash = hash;
  coin.index = index;
  coin.height = bits >>> 1;
  coin.hash = hash;
  coin.coinbase = (bits & 1) !== 0;

  // Mark the start of the spent field and
  // seek past it to avoid reading a buffer.
  len = br.readVarint();
  start = br.offset;
  br.seek(len);

  while (br.left()) {
    bit = pos % 8;
    oct = (pos - bit) / 8;
    oct += start;

    // Read a single bit out of the spent field.
    spent = data[oct] >>> (7 - bit);
    spent &= 1;

    // We found our coin.
    if (pos === index) {
      if (spent)
        return;
      decompress.script(coin.script, br);
      coin.value = br.readVarint();
      return coin;
    }

    // Already spent.
    if (spent) {
      pos++;
      continue;
    }

    // Skip past the compressed coin.
    decompress.skip(br);
    pos++;
  }
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
 * Serialize the coins object.
 * @param {TX|Coins} tx
 * @returns {Buffer}
 */

Coins.prototype.toRaw2 = function toRaw2() {
  var bw = new BufferWriter();
  var len = this.outputs.length;
  var first = len > 0 && this.outputs[0];
  var second = len > 1 && this.outputs[1];
  var size = 0;
  var nonzero = 0;
  var i, j, code, ch, output;

  // Return nothing if we're fully spent.
  if (len === 0)
    return;

  // Calculate number of unspents and spent field size.
  // size = number of bytes required for the bit field.
  // nonzero = number of non-zero bytes required.
  for (i = 0; 2 + i * 8 < len; i++) {
    for (j = 0; j < 8 && 2 + i * 8 + j < len; j++) {
      if (this.outputs[2 + i * 8 + j]) {
        size = i + 1;
        nonzero++;
        break;
      }
    }
  }

  if (!first && !second)
    nonzero -= 1;

  // Calculate header code.
  code = 8 * nonzero;

  if (this.coinbase)
    code += 1;

  if (first)
    code += 2;

  if (second)
    code += 4;

  // Write headers.
  bw.writeVarint(this.version);
  bw.writeU32(this.height);
  bw.writeVarint(code);

  // Write the spent field.
  for (i = 0; i < size; i++) {
    ch = 0;
    for (j = 0; j < 8 && 2 + i * 8 + j < len; j++) {
      if (this.outputs[2 + i * 8 + j])
        ch |= 1 << j;
    }
    bw.writeU8(ch);
  }

  // Write the compressed outputs.
  for (i = 0; i < len; i++) {
    output = this.outputs[i];

    if (!output)
      continue;

    output.toWriter2(bw);
  }

  return bw.render();
};

/**
 * Parse serialized coins.
 * @param {Buffer} data
 * @param {Hash} hash
 * @returns {Object} A "naked" coins object.
 */

Coins.prototype.fromRaw2 = function fromRaw2(data, hash) {
  var br = new BufferReader(data);
  var i, code, field, nonzero, ch, unspent, coin;

  this.hash = hash;

  // Read headers.
  this.version = br.readVarint();
  this.height = br.readU32();
  code = br.readVarint();
  this.coinbase = (code & 1) !== 0;

  // Setup spent field.
  field = [
    (code & 2) !== 0,
    (code & 4) !== 0
  ];

  // Recalculate number of non-zero bytes.
  nonzero = code / 8 | 0;

  if ((code & 6) === 0)
    nonzero += 1;

  // Read spent field.
  while (nonzero > 0) {
    ch = br.readU8();
    for (i = 0; i < 8; i++) {
      unspent = (ch & (1 << i)) !== 0;
      field.push(unspent);
    }
    if (ch !== 0)
      nonzero--;
  }

  // Read outputs.
  for (i = 0; i < field.length; i++) {
    if (!field[i]) {
      this.outputs.push(null);
      continue;
    }

    // Store the offset and size
    // in the compressed coin object.
    coin = CoinEntry.fromReader2(br);

    this.outputs.push(coin);
  }

  this.cleanup();

  return this;
};

/**
 * Parse a single serialized coin.
 * @param {Buffer} data
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Coin}
 */

Coins.parseCoin2 = function parseCoin2(data, hash, index) {
  var br = new BufferReader(data);
  var coin = new Coin();
  var i, code, field, nonzero, ch, unspent;

  coin.hash = hash;
  coin.index = index;

  // Read headers.
  coin.version = br.readVarint();
  coin.height = br.readU32();
  code = br.readVarint();
  coin.coinbase = (code & 1) !== 0;

  // Setup spent field.
  field = [
    (code & 2) !== 0,
    (code & 4) !== 0
  ];

  // Recalculate number of non-zero bytes.
  nonzero = code / 8 | 0;

  if ((code & 6) === 0)
    nonzero += 1;

  // Read spent field.
  while (nonzero > 0 && field.length <= index) {
    ch = br.readU8();
    for (i = 0; i < 8; i++) {
      unspent = (ch & (1 << i)) !== 0;
      field.push(unspent);
    }
    if (ch !== 0)
      nonzero--;
  }

  if (field.length <= index)
    return;

  while (nonzero > 0) {
    if (br.readU8() !== 0)
      nonzero--;
  }

  // Read outputs.
  for (i = 0; i < field.length; i++) {
    if (i === index) {
      if (!field[i])
        return;

      // Read compressed output.
      decompress.output2(coin, br);

      break;
    }

    if (!field[i])
      continue;

    decompress.skip2(br);
  }

  return coin;
};

/**
 * Instantiate coins from a serialized Buffer.
 * @param {Buffer} data
 * @param {Hash} hash - Transaction hash.
 * @returns {Coins}
 */

Coins.fromRaw2 = function fromRaw2(data, hash) {
  return new Coins().fromRaw2(data, hash);
};

/**
 * Inject properties from tx.
 * @private
 * @param {TX} tx
 */

Coins.prototype.fromTX = function fromTX(tx) {
  var i, output;

  this.version = tx.version;
  this.hash = tx.hash('hex');
  this.height = tx.height;
  this.coinbase = tx.isCoinbase();

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    if (output.script.isUnspendable()) {
      this.outputs.push(null);
      continue;
    }

    this.outputs.push(CoinEntry.fromTX(tx, i));
  }

  this.cleanup();

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

function CoinEntry() {
  this.offset = 0;
  this.size = 0;
  this.raw = null;
  this.output = null;
}

/**
 * Parse the deferred data and return a Coin.
 * @param {Coins} coins
 * @param {Number} index
 * @returns {Coin}
 */

CoinEntry.prototype.toCoin = function toCoin(coins, index) {
  var coin = new Coin();
  var br;

  // Load in all necessary properties
  // from the parent Coins object.
  coin.version = coins.version;
  coin.coinbase = coins.coinbase;
  coin.height = coins.height;
  coin.hash = coins.hash;
  coin.index = index;

  if (this.output) {
    coin.script = this.output.script;
    coin.value = this.output.value;
    return coin;
  }

  br = new BufferReader(this.raw);

  // Seek to the coin's offset.
  br.seek(this.offset);

  decompress.output(coin, br);

  return coin;
};

/**
 * Parse the deferred data and return a Coin.
 * @param {Coins} coins
 * @param {Number} index
 * @returns {Coin}
 */

CoinEntry.prototype.toCoin2 = function toCoin2(coins, index) {
  var coin = new Coin();
  var br;

  // Load in all necessary properties
  // from the parent Coins object.
  coin.version = coins.version;
  coin.coinbase = coins.coinbase;
  coin.height = coins.height;
  coin.hash = coins.hash;
  coin.index = index;

  if (this.output) {
    coin.script = this.output.script;
    coin.value = this.output.value;
    return coin;
  }

  br = new BufferReader(this.raw);

  // Seek to the coin's offset.
  br.seek(this.offset);

  decompress.output2(coin, br);

  return coin;
};

/**
 * Slice off the part of the buffer
 * relevant to this particular coin.
 */

CoinEntry.prototype.toWriter = function toWriter(bw) {
  var raw;

  if (this.output) {
    compress.output(this.output, bw);
    return;
  }

  assert(this.raw);

  // If we read this coin from the db and
  // didn't use it, it's still in its
  // compressed form. Just write it back
  // as a buffer for speed.
  raw = this.raw.slice(this.offset, this.offset + this.size);

  bw.writeBytes(raw);
};

/**
 * Slice off the part of the buffer
 * relevant to this particular coin.
 */

CoinEntry.prototype.toWriter2 = function toWriter2(bw) {
  var raw;

  if (this.output) {
    compress.output2(this.output, bw);
    return;
  }

  assert(this.raw);

  // If we read this coin from the db and
  // didn't use it, it's still in its
  // compressed form. Just write it back
  // as a buffer for speed.
  raw = this.raw.slice(this.offset, this.offset + this.size);

  bw.writeBytes(raw);
};

/**
 * Instantiate compressed coin from reader.
 * @param {BufferReader} br
 * @returns {CoinEntry}
 */

CoinEntry.fromReader = function fromReader(br) {
  var entry = new CoinEntry();
  entry.offset = br.offset;
  entry.size = decompress.skip(br);
  entry.raw = br.data;
  return entry;
};

/**
 * Instantiate compressed coin from reader.
 * @param {BufferReader} br
 * @returns {CoinEntry}
 */

CoinEntry.fromReader2 = function fromReader2(br) {
  var entry = new CoinEntry();
  entry.offset = br.offset;
  entry.size = decompress.skip2(br);
  entry.raw = br.data;
  return entry;
};

/**
 * Instantiate compressed coin from tx.
 * @param {TX} tx
 * @param {Number} index
 * @returns {CoinEntry}
 */

CoinEntry.fromTX = function fromTX(tx, index) {
  var entry = new CoinEntry();
  entry.output = tx.outputs[index];
  return entry;
};

/**
 * Instantiate compressed coin from coin.
 * @param {Coin} coin
 * @returns {CoinEntry}
 */

CoinEntry.fromCoin = function fromCoin(coin) {
  var entry = new CoinEntry();
  entry.output = new Output();
  entry.output.script = coin.script;
  entry.output.value = coin.value;
  return entry;
};

/*
 * Expose
 */

module.exports = Coins;
