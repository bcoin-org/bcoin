/*!
 * coins.js - coins object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint-disable */

'use strict';

const assert = require('assert');
const util = require('../../lib/utils/util');
const Coin = require('../../lib/primitives/coin');
const Output = require('../../lib/primitives/output');
const BufferReader = require('../../lib/utils/reader');
const StaticWriter = require('../../lib/utils/staticwriter');
const encoding = require('../../lib/utils/encoding');
const compressor = require('./compress');
const compress = compressor.compress;
const decompress = compressor.decompress;

/**
 * Represents the outputs for a single transaction.
 * @alias module:coins.Coins
 * @constructor
 * @param {Object?} options - Options object.
 * @property {Hash} hash - Transaction hash.
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {CoinEntry[]} outputs - Coins.
 */

function Coins(options) {
  if (!(this instanceof Coins))
    return new Coins(options);

  this.version = 1;
  this.hash = encoding.NULL_HASH;
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
    assert((options.version >>> 0) === options.version);
    this.version = options.version;
  }

  if (options.hash) {
    assert(typeof options.hash === 'string');
    this.hash = options.hash;
  }

  if (options.height != null) {
    assert(Number.isSafeInteger(options.height));
    this.height = options.height;
  }

  if (options.coinbase != null) {
    assert(typeof options.coinbase === 'boolean');
    this.coinbase = options.coinbase;
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs));
    this.outputs = options.outputs;
    this.cleanup();
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
 * Add a single entry to the collection.
 * @param {Number} index
 * @param {CoinEntry} entry
 */

Coins.prototype.add = function add(index, entry) {
  assert(index >= 0);

  while (this.outputs.length <= index)
    this.outputs.push(null);

  assert(!this.outputs[index]);

  this.outputs[index] = entry;
};

/**
 * Add a single output to the collection.
 * @param {Number} index
 * @param {Output} output
 */

Coins.prototype.addOutput = function addOutput(index, output) {
  assert(!output.script.isUnspendable());
  this.add(index, CoinEntry.fromOutput(output));
};

/**
 * Add a single coin to the collection.
 * @param {Coin} coin
 */

Coins.prototype.addCoin = function addCoin(coin) {
  assert(!coin.script.isUnspendable());
  this.add(coin.index, CoinEntry.fromCoin(coin));
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
 * Test whether the collection
 * has an unspent coin.
 * @param {Number} index
 * @returns {Boolean}
 */

Coins.prototype.isUnspent = function isUnspent(index) {
  if (index >= this.outputs.length)
    return false;

  const output = this.outputs[index];

  if (!output || output.spent)
    return false;

  return true;
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
 * Get an output.
 * @param {Number} index
 * @returns {Output}
 */

Coins.prototype.getOutput = function getOutput(index) {
  const entry = this.get(index);

  if (!entry)
    return;

  return entry.toOutput();
};

/**
 * Get a coin.
 * @param {Number} index
 * @returns {Coin}
 */

Coins.prototype.getCoin = function getCoin(index) {
  const entry = this.get(index);

  if (!entry)
    return;

  return entry.toCoin(this, index);
};

/**
 * Spend a coin entry and return it.
 * @param {Number} index
 * @returns {CoinEntry}
 */

Coins.prototype.spend = function spend(index) {
  const entry = this.get(index);

  if (!entry || entry.spent)
    return;

  entry.spent = true;

  return entry;
};

/**
 * Remove a coin entry and return it.
 * @param {Number} index
 * @returns {CoinEntry}
 */

Coins.prototype.remove = function remove(index) {
  const entry = this.get(index);

  if (!entry)
    return false;

  this.outputs[index] = null;
  this.cleanup();

  return entry;
};

/**
 * Calculate unspent length of coins.
 * @returns {Number}
 */

Coins.prototype.length = function length() {
  let len = this.outputs.length;

  while (len > 0 && !this.isUnspent(len - 1))
    len--;

  return len;
};

/**
 * Cleanup spent outputs (remove pruned).
 */

Coins.prototype.cleanup = function cleanup() {
  let len = this.outputs.length;

  while (len > 0 && !this.outputs[len - 1])
    len--;

  this.outputs.length = len;
};

/**
 * Test whether the coins are fully spent.
 * @returns {Boolean}
 */

Coins.prototype.isEmpty = function isEmpty() {
  return this.length() === 0;
};

/*
 * Coins serialization:
 * version: varint
 * height: uint32
 * header-code: varint
 *   bit 1: coinbase
 *   bit 2: first output unspent
 *   bit 3: second output unspent
 *   bit 4-32: spent-field size
 * spent-field: bitfield (0=spent, 1=unspent)
 * outputs (repeated):
 *   value: varint
 *   compressed-script:
 *     prefix: 0x00 = 20 byte pubkey hash
 *             0x01 = 20 byte script hash
 *             0x02-0x05 = 32 byte ec-key x-value
 *             0x06-0x09 = reserved
 *             >=0x10 = varint-size + 10 | raw script
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
 * Calculate header code.
 * @param {Number} len
 * @param {Number} size
 * @returns {Number}
 */

Coins.prototype.header = function header(len, size) {
  const first = this.isUnspent(0);
  const second = this.isUnspent(1);
  let offset = 0;

  // Throw if we're fully spent.
  assert(len !== 0, 'Cannot serialize fully-spent coins.');

  // First and second bits
  // have a double meaning.
  if (!first && !second) {
    assert(size !== 0);
    offset = 1;
  }

  // Calculate header code.
  let code = 8 * (size - offset);

  if (this.coinbase)
    code += 1;

  if (first)
    code += 2;

  if (second)
    code += 4;

  return code;
};

/**
 * Serialize the coins object.
 * @returns {Buffer}
 */

Coins.prototype.toRaw = function toRaw() {
  const len = this.length();
  const size = Math.floor((len + 5) / 8);
  const code = this.header(len, size);
  const total = this.getSize(len, size, code);
  const bw = new StaticWriter(total);

  // Write headers.
  bw.writeVarint(this.version);
  bw.writeU32(this.height);
  bw.writeVarint(code);

  // Write the spent field.
  for (let i = 0; i < size; i++) {
    let ch = 0;
    for (let j = 0; j < 8 && 2 + i * 8 + j < len; j++) {
      if (this.isUnspent(2 + i * 8 + j))
        ch |= 1 << j;
    }
    bw.writeU8(ch);
  }

  // Write the compressed outputs.
  for (let i = 0; i < len; i++) {
    const output = this.outputs[i];

    if (!output || output.spent)
      continue;

    output.toWriter(bw);
  }

  return bw.render();
};

/**
 * Calculate coins size.
 * @param {Number} code
 * @param {Number} size
 * @param {Number} len
 * @returns {Number}
 */

Coins.prototype.getSize = function getSize(len, size, code) {
  let total = 0;

  total += encoding.sizeVarint(this.version);
  total += 4;
  total += encoding.sizeVarint(code);
  total += size;

  // Write the compressed outputs.
  for (let i = 0; i < len; i++) {
    const output = this.outputs[i];

    if (!output || output.spent)
      continue;

    total += output.getSize();
  }

  return total;
};

/**
 * Inject data from serialized coins.
 * @private
 * @param {Buffer} data
 * @param {Hash} hash
 * @returns {Coins}
 */

Coins.prototype.fromRaw = function fromRaw(data, hash) {
  const br = new BufferReader(data);
  let first = null;
  let second = null;

  // Inject hash (passed by caller).
  this.hash = hash;

  // Read headers.
  this.version = br.readVarint();
  this.height = br.readU32();
  const code = br.readVarint();
  this.coinbase = (code & 1) !== 0;

  // Recalculate size.
  let size = code / 8 | 0;

  if ((code & 6) === 0)
    size += 1;

  // Setup spent field.
  let offset = br.offset;
  br.seek(size);

  // Read first two outputs.
  if ((code & 2) !== 0)
    first = CoinEntry.fromReader(br);

  if ((code & 4) !== 0)
    second = CoinEntry.fromReader(br);

  this.outputs.push(first);
  this.outputs.push(second);

  // Read outputs.
  for (let i = 0; i < size; i++) {
    const ch = br.data[offset++];
    for (let j = 0; j < 8; j++) {
      if ((ch & (1 << j)) === 0) {
        this.outputs.push(null);
        continue;
      }
      this.outputs.push(CoinEntry.fromReader(br));
    }
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
  const br = new BufferReader(data);
  const coin = new Coin();

  // Inject outpoint (passed by caller).
  coin.hash = hash;
  coin.index = index;

  // Read headers.
  coin.version = br.readVarint();
  coin.height = br.readU32();
  const code = br.readVarint();
  coin.coinbase = (code & 1) !== 0;

  // Recalculate size.
  let size = code / 8 | 0;

  if ((code & 6) === 0)
    size += 1;

  if (index >= 2 + size * 8)
    return;

  // Setup spent field.
  let offset = br.offset;
  br.seek(size);

  // Read first two outputs.
  for (let i = 0; i < 2; i++) {
    if ((code & (2 << i)) !== 0) {
      if (index === 0) {
        decompress.coin(coin, br);
        return coin;
      }
      decompress.skip(br);
    } else {
      if (index === 0)
        return;
    }
    index -= 1;
  }

  // Read outputs.
  for (let i = 0; i < size; i++) {
    const ch = br.data[offset++];
    for (let j = 0; j < 8; j++) {
      if ((ch & (1 << j)) !== 0) {
        if (index === 0) {
          decompress.coin(coin, br);
          return coin;
        }
        decompress.skip(br);
      } else {
        if (index === 0)
          return;
      }
      index -= 1;
    }
  }
};

/**
 * Instantiate coins from a buffer.
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
 * @param {Number} height
 */

Coins.prototype.fromTX = function fromTX(tx, height) {
  assert(typeof height === 'number');

  this.version = tx.version;
  this.hash = tx.hash('hex');
  this.height = height;
  this.coinbase = tx.isCoinbase();

  for (const output of tx.outputs) {
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
 * @param {Number} height
 * @returns {Coins}
 */

Coins.fromTX = function fromTX(tx, height) {
  return new Coins().fromTX(tx, height);
};

/**
 * A coin entry is an object which defers
 * parsing of a coin. Say there is a transaction
 * with 100 outputs. When a block comes in,
 * there may only be _one_ input in that entire
 * block which redeems an output from that
 * transaction. When parsing the Coins, there
 * is no sense to get _all_ of them into their
 * abstract form. A coin entry is just a
 * pointer to that coin in the Coins buffer, as
 * well as a size. Parsing and decompression
 * is done only if that coin is being redeemed.
 * @alias module:coins.CoinEntry
 * @constructor
 * @property {Number} offset
 * @property {Number} size
 * @property {Buffer} raw
 * @property {Output|null} output
 * @property {Boolean} spent
 */

function CoinEntry() {
  this.offset = 0;
  this.size = 0;
  this.raw = null;
  this.output = null;
  this.spent = false;
}

/**
 * Instantiate a reader at the correct offset.
 * @private
 * @returns {BufferReader}
 */

CoinEntry.prototype.reader = function reader() {
  assert(this.raw);

  const br = new BufferReader(this.raw);
  br.offset = this.offset;

  return br;
};

/**
 * Parse the deferred data and return a coin.
 * @param {Coins} coins
 * @param {Number} index
 * @returns {Coin}
 */

CoinEntry.prototype.toCoin = function toCoin(coins, index) {
  const coin = new Coin();
  const output = this.toOutput();

  // Load in all necessary properties
  // from the parent Coins object.
  coin.version = coins.version;
  coin.coinbase = coins.coinbase;
  coin.height = coins.height;
  coin.hash = coins.hash;
  coin.index = index;
  coin.script = output.script;
  coin.value = output.value;

  return coin;
};

/**
 * Parse the deferred data and return an output.
 * @returns {Output}
 */

CoinEntry.prototype.toOutput = function toOutput() {
  if (!this.output) {
    this.output = new Output();
    decompress.output(this.output, this.reader());
  }
  return this.output;
};

/**
 * Calculate coin entry size.
 * @returns {Number}
 */

CoinEntry.prototype.getSize = function getSize() {
  if (!this.raw)
    return compress.size(this.output);

  return this.size;
};

/**
 * Slice off the part of the buffer
 * relevant to this particular coin.
 */

CoinEntry.prototype.toWriter = function toWriter(bw) {
  if (!this.raw) {
    assert(this.output);
    compress.output(this.output, bw);
    return bw;
  }

  // If we read this coin from the db and
  // didn't use it, it's still in its
  // compressed form. Just write it back
  // as a buffer for speed.
  bw.copy(this.raw, this.offset, this.offset + this.size);

  return bw;
};

/**
 * Instantiate coin entry from reader.
 * @param {BufferReader} br
 * @returns {CoinEntry}
 */

CoinEntry.fromReader = function fromReader(br) {
  const entry = new CoinEntry();
  entry.offset = br.offset;
  entry.size = decompress.skip(br);
  entry.raw = br.data;
  return entry;
};

/**
 * Instantiate coin entry from output.
 * @param {Output} output
 * @returns {CoinEntry}
 */

CoinEntry.fromOutput = function fromOutput(output) {
  const entry = new CoinEntry();
  entry.output = output;
  return entry;
};

/**
 * Instantiate coin entry from coin.
 * @param {Coin} coin
 * @returns {CoinEntry}
 */

CoinEntry.fromCoin = function fromCoin(coin) {
  const entry = new CoinEntry();
  const output = new Output();
  output.value = coin.value;
  output.script = coin.script;
  entry.output = output;
  return entry;
};

/*
 * Expose
 */

exports = Coins;
exports.Coins = Coins;
exports.CoinEntry = CoinEntry;

module.exports = exports;
