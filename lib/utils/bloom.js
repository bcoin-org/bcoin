/*!
 * bloom.js - bloom filter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const murmur3 = require('./murmur3');
const BufferReader = require('./reader');
const StaticWriter = require('./staticwriter');
const encoding = require('./encoding');
const sum32 = murmur3.sum32;
const mul32 = murmur3.mul32;
const DUMMY = Buffer.alloc(0);

/*
 * Constants
 */

const LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455;
const LN2 = 0.6931471805599453094172321214581765680755001343602552;

/**
 * Bloom Filter
 * @alias module:utils.Bloom
 * @constructor
 * @param {Number} size - Filter size in bits.
 * @param {Number} n - Number of hash functions.
 * @param {Number} tweak - Seed value.
 * @param {Number|String} - Update type.
 * @property {Buffer} filter
 * @property {Number} size
 * @property {Number} n
 * @property {Number} tweak
 * @property {Number} update - Update flag (see {@link Bloom.flags}).
 */

function Bloom(size, n, tweak, update) {
  if (!(this instanceof Bloom))
    return new Bloom(size, n, tweak, update);

  this.filter = DUMMY;
  this.size = 0;
  this.n = 0;
  this.tweak = 0;
  this.update = Bloom.flags.NONE;

  if (size != null)
    this.fromOptions(size, n, tweak, update);
}

/**
 * Max bloom filter size.
 * @const {Number}
 * @default
 */

Bloom.MAX_BLOOM_FILTER_SIZE = 36000;

/**
 * Max number of hash functions.
 * @const {Number}
 * @default
 */

Bloom.MAX_HASH_FUNCS = 50;

/**
 * Bloom filter update flags.
 * @enum {Number}
 * @default
 */

Bloom.flags = {
  /**
   * Never update the filter with outpoints.
   */

  NONE: 0,

  /**
   * Always update the filter with outpoints.
   */

  ALL: 1,

  /**
   * Only update the filter with outpoints if it is
   * "asymmetric" in terms of addresses (pubkey/multisig).
   */

  PUBKEY_ONLY: 2
};

/**
 * Bloom filter update flags by value.
 * @const {RevMap}
 */

Bloom.flagsByVal = {
  0: 'NONE',
  1: 'ALL',
  2: 'PUBKEY_ONLY'
};

/**
 * Inject properties from options.
 * @private
 * @param {Number} size - Filter size in bits.
 * @param {Number} n - Number of hash functions.
 * @param {Number} tweak - Seed value.
 * @param {Number|String} - Update type.
 * @returns {Bloom}
 */

Bloom.prototype.fromOptions = function fromOptions(size, n, tweak, update) {
  let filter;

  assert(typeof size === 'number', '`size` must be a number.');
  assert(size > 0, '`size` must be greater than zero.');
  assert(size % 1 === 0, '`size` must be an integer.');

  size -= size % 8;

  filter = Buffer.allocUnsafe(size / 8);
  filter.fill(0);

  if (tweak == null || tweak === -1)
    tweak = (Math.random() * 0x100000000) >>> 0;

  if (update == null || update === -1)
    update = Bloom.flags.NONE;

  if (typeof update === 'string') {
    update = Bloom.flags[update.toUpperCase()];
    assert(update != null, 'Unknown update flag.');
  }

  assert(size > 0, '`size` must be greater than zero.');
  assert(n > 0, '`n` must be greater than zero.');
  assert(n % 1 === 0, '`n` must be an integer.');
  assert(typeof tweak === 'number', '`tweak` must be a number.');
  assert(tweak % 1 === 0, '`tweak` must be an integer.');
  assert(Bloom.flagsByVal[update], 'Unknown update flag.');

  this.filter = filter;
  this.size = size;
  this.n = n;
  this.tweak = tweak;
  this.update = update;

  return this;
};

/**
 * Instantiate bloom filter from options.
 * @param {Number} size - Filter size in bits.
 * @param {Number} n - Number of hash functions.
 * @param {Number} tweak - Seed value.
 * @param {Number|String} - Update type.
 * @returns {Bloom}
 */

Bloom.fromOptions = function fromOptions(size, n, tweak, update) {
  return new Bloom().fromOptions(size, n, tweak, update);
};

/**
 * Perform the mumur3 hash on data.
 * @param {Buffer} val
 * @param {Number} n
 * @returns {Number}
 */

Bloom.prototype.hash = function hash(val, n) {
  return murmur3(val, sum32(mul32(n, 0xfba4c795), this.tweak)) % this.size;
};

/**
 * Reset the filter.
 */

Bloom.prototype.reset = function reset() {
  this.filter.fill(0);
};

/**
 * Add data to the filter.
 * @param {Buffer|String}
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 */

Bloom.prototype.add = function add(val, enc) {
  if (typeof val === 'string')
    val = Buffer.from(val, enc);

  for (let i = 0; i < this.n; i++) {
    let index = this.hash(val, i);
    this.filter[index >>> 3] |= 1 << (7 & index);
  }
};

/**
 * Test whether data is present in the filter.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean}
 */

Bloom.prototype.test = function test(val, enc) {
  if (typeof val === 'string')
    val = Buffer.from(val, enc);

  for (let i = 0; i < this.n; i++) {
    let index = this.hash(val, i);
    if ((this.filter[index >>> 3] & (1 << (7 & index))) === 0)
      return false;
  }

  return true;
};

/**
 * Test whether data is present in the
 * filter and potentially add data.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean} Whether data was added.
 */

Bloom.prototype.added = function added(val, enc) {
  let ret = false;

  if (typeof val === 'string')
    val = Buffer.from(val, enc);

  for (let i = 0; i < this.n; i++) {
    let index = this.hash(val, i);
    if (!ret && (this.filter[index >>> 3] & (1 << (7 & index))) === 0)
      ret = true;
    this.filter[index >>> 3] |= 1 << (7 & index);
  }

  return ret;
};

/**
 * Create a filter from a false positive rate.
 * @param {Number} items - Expected number of items.
 * @param {Number} rate - False positive rate (0.0-1.0).
 * @param {Number|String} update
 * @example
 * Bloom.fromRate(800000, 0.0001, 'none');
 * @returns {Boolean}
 */

Bloom.fromRate = function fromRate(items, rate, update) {
  let size, n;

  assert(typeof items === 'number', '`items` must be a number.');
  assert(items > 0, '`items` must be greater than zero.');
  assert(items % 1 === 0, '`items` must be an integer.');
  assert(typeof rate === 'number', '`rate` must be a number.');
  assert(rate >= 0 && rate <= 1, '`rate` must be between 0.0 and 1.0.');

  size = (-1 / LN2SQUARED * items * Math.log(rate)) | 0;
  size = Math.max(8, size);

  if (update !== -1) {
    assert(size <= Bloom.MAX_BLOOM_FILTER_SIZE * 8,
      'Bloom filter size violates policy limits!');
  }

  n = Math.max(1, (size / items * LN2) | 0);

  if (update !== -1) {
    assert(n <= Bloom.MAX_HASH_FUNCS,
      'Bloom filter size violates policy limits!');
  }

  return new Bloom(size, n, -1, update);
};

/**
 * Ensure the filter is within the size limits.
 * @returns {Boolean}
 */

Bloom.prototype.isWithinConstraints = function isWithinConstraints() {
  if (this.size > Bloom.MAX_BLOOM_FILTER_SIZE * 8)
    return false;

  if (this.n > Bloom.MAX_HASH_FUNCS)
    return false;

  return true;
};

/**
 * Get serialization size.
 * @returns {Number}
 */

Bloom.prototype.getSize = function getSize() {
  return encoding.sizeVarBytes(this.filter) + 9;
};

/**
 * Write filter to buffer writer.
 * @param {BufferWriter} bw
 */

Bloom.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.filter);
  bw.writeU32(this.n);
  bw.writeU32(this.tweak);
  bw.writeU8(this.update);
  return bw;
};

/**
 * Serialize bloom filter.
 * @returns {Buffer}
 */

Bloom.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

Bloom.prototype.fromReader = function fromReader(br) {
  this.filter = br.readVarBytes();
  this.n = br.readU32();
  this.tweak = br.readU32();
  this.update = br.readU8();
  assert(Bloom.flagsByVal[this.update] != null, 'Unknown update flag.');
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Bloom.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate bloom filter from buffer reader.
 * @param {BufferReader} br
 * @returns {Bloom}
 */

Bloom.fromReader = function fromReader(br) {
  return new Bloom().fromReader(br);
};

/**
 * Instantiate bloom filter from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {Bloom}
 */

Bloom.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new Bloom().fromRaw(data);
};

/*
 * Expose
 */

module.exports = Bloom;
