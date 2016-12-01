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
 * Add a single output to the collection.
 * @param {Number} index
 * @param {Output} output
 */

Coins.prototype.add = function add(index, output) {
  assert(!output.script.isUnspendable());

  while (this.outputs.length <= index)
    this.outputs.push(null);

  assert(!this.outputs[index]);

  this.outputs[index] = CoinEntry.fromOutput(output);
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
 * Get a coin entry.
 * @param {Number} index
 * @returns {CoinEntry}
 */

Coins.prototype.get = function get(index) {
  if (index >= this.outputs.length)
    return;

  return this.outputs[index];
};

/**
 * Get a coin.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.getCoin = function getCoin(index) {
  var entry = this.get(index);

  if (!entry)
    return;

  return entry.toCoin(this, index);
};

/**
 * Remove a coin entry and return it.
 * @param {Number} index
 * @returns {CoinEntry}
 */

Coins.prototype.spend = function spend(index) {
  var entry = this.get(index);

  if (!entry)
    return;

  this.outputs[index] = null;
  this.cleanup();

  return entry;
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
 * Test whether the coins are fully spent.
 * @returns {Boolean}
 */

Coins.prototype.isEmpty = function isEmpty() {
  return this.outputs.length === 0;
};

/*
 * Coins serialization:
 * version: varint
 * height: uint32
 * header-code: varint (31-bit fields | 1-bit coinbase-flag)
 * spent-field: bitfield (0=spent, 1=unspent)
 * outputs (repeated):
 *   value: varint
 *   compressed-script:
 *     prefix:
 *             0x00 = 20 byte pubkey hash
 *             0x01 = 20 byte script hash
 *             0x02-0x05 = 32 byte ec-key x-value
 *             >=0x06 = varint-size + 10 | raw script
 *     data: script data, dictated by the prefix
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
 * @returns {Buffer}
 */

Coins.prototype.toRaw = function toRaw() {
  var bw = new BufferWriter();
  var len = this.outputs.length;
  var first = len > 0 && this.outputs[0];
  var second = len > 1 && this.outputs[1];
  var size = 0;
  var nonzero = 0;
  var i, j, code, ch, output;

  // Throw if we're fully spent.
  assert(len !== 0, 'Cannot serialize fully-spent coins.');

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

  // First and second bits
  // have a double meaning.
  if (!first && !second) {
    assert(nonzero !== 0);
    nonzero -= 1;
  }

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

    output.toWriter(bw);
  }

  return bw.render();
};

/**
 * Inject data from serialized coins.
 * @private
 * @param {Buffer} data
 * @param {Hash} hash
 * @returns {Coins}
 */

Coins.prototype.fromRaw = function fromRaw(data, hash) {
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
    coin = CoinEntry.fromReader(br);

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

Coins.parseCoin = function parseCoin(data, hash, index) {
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
      decompress.coin(coin, br);

      break;
    }

    if (!field[i])
      continue;

    decompress.skip(br);
  }

  return coin;
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

    this.outputs.push(CoinEntry.fromOutput(output));
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
 * Instantiate a reader at the correct offset.
 * @private
 * @returns {BufferReader}
 */

CoinEntry.prototype.reader = function reader() {
  var br;

  assert(this.raw);

  br = new BufferReader(this.raw);
  br.offset = this.offset;

  return br;
};

/**
 * Parse the deferred data and return a Coin.
 * @param {Coins} coins
 * @param {Number} index
 * @returns {Coin}
 */

CoinEntry.prototype.toCoin = function toCoin(coins, index) {
  var coin = new Coin();

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
  } else {
    decompress.coin(coin, this.reader());
  }

  return coin;
};

/**
 * Parse the deferred data and return an Output.
 * @returns {Output}
 */

CoinEntry.prototype.toOutput = function toOutput() {
  if (this.output)
    return this.output;
  return decompress.output(new Output(), this.reader());
};

/**
 * Slice off the part of the buffer
 * relevant to this particular coin.
 */

CoinEntry.prototype.toWriter = function toWriter(bw) {
  var raw;

  if (!this.raw) {
    assert(this.output);
    compress.output(this.output, bw);
    return bw;
  }

  // If we read this coin from the db and
  // didn't use it, it's still in its
  // compressed form. Just write it back
  // as a buffer for speed.
  raw = this.raw.slice(this.offset, this.offset + this.size);

  bw.writeBytes(raw);

  return bw;
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
 * Instantiate compressed coin from coin.
 * @param {Output} output
 * @returns {CoinEntry}
 */

CoinEntry.fromOutput = function fromOutput(output) {
  var entry = new CoinEntry();
  entry.output = output;
  return entry;
};

/*
 * Expose
 */

module.exports = Coins;
