/*!
 * bloom.js - bloom filter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {enforce} = require('bsert');
const bio = require('bufio');
const murmur3 = require('mrmr');

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455;
const LN2 = 0.6931471805599453094172321214581765680755001343602552;

/**
 * Bloom Filter
 */

class BloomFilter extends bio.Struct {
  /**
   * Create a bloom filter.
   * @constructor
   * @param {Number} size - Filter size in bits.
   * @param {Number} n - Number of hash functions.
   * @param {Number} tweak - Seed value.
   * @param {Number|String} - Update type.
   * @property {Buffer} filter
   * @property {Number} size
   * @property {Number} n
   * @property {Number} tweak
   * @property {Number} update - Update flag (see {@link BloomFilter.flags}).
   */

  constructor(size, n, tweak, update) {
    super();

    this.filter = DUMMY;
    this.size = 0;
    this.n = 0;
    this.tweak = 0;
    this.update = BloomFilter.flags.NONE;

    if (size != null)
      this.fromOptions(size, n, tweak, update);
  }

  /**
   * Inject properties from options.
   * @private
   * @param {Number} size - Filter size in bits.
   * @param {Number} n - Number of hash functions.
   * @param {Number} tweak - Seed value.
   * @param {Number|String} - Update type.
   * @returns {BloomFilter}
   */

  fromOptions(size, n, tweak, update) {
    if (tweak == null || tweak === -1)
      tweak = (Math.random() * 0x100000000) >>> 0;

    if (update == null || update === -1)
      update = BloomFilter.flags.NONE;

    if (typeof update === 'string') {
      update = BloomFilter.flags[update.toUpperCase()];
      enforce(update != null, 'update', 'flag');
    }

    enforce(Number.isSafeInteger(size) && size >= 0, 'size', 'integer');
    enforce(Number.isSafeInteger(n) && n >= 0, 'n', 'integer');
    enforce((tweak >>> 0) === tweak, 'tweak', 'integer');
    enforce((update >>> 0) === update, 'update', 'integer');
    enforce(update <= 2, 'update', 'range between 0 and 2');

    if (size < 8)
      size = 8;

    if (n === 0)
      n = 1;

    size -= size & 7;

    this.filter = Buffer.alloc(size / 8, 0x00);
    this.size = size;
    this.n = n;
    this.tweak = tweak;
    this.update = update;

    return this;
  }

  /**
   * Instantiate bloom filter from options.
   * @param {Number} size - Filter size in bits.
   * @param {Number} n - Number of hash functions.
   * @param {Number} tweak - Seed value.
   * @param {Number|String} - Update type.
   * @returns {BloomFilter}
   */

  static fromOptions(size, n, tweak, update) {
    return new this().fromOptions(size, n, tweak, update);
  }

  /**
   * Perform the mumur3 hash on data.
   * @param {Buffer} value
   * @param {Number} n
   * @returns {Number}
   */

  hash(value, n) {
    return murmur3.tweak(value, n, this.tweak) % this.size;
  }

  /**
   * Reset the filter.
   */

  reset() {
    this.filter.fill(0);
  }

  /**
   * Add data to the filter.
   * @param {Buffer|String}
   * @param {String?} enc - Can be any of the Buffer object's encodings.
   */

  add(value, enc) {
    const val = toBuffer(value, enc);

    for (let i = 0; i < this.n; i++) {
      const index = this.hash(val, i);
      this.filter[index >>> 3] |= 1 << (7 & index);
    }
  }

  /**
   * Test whether data is present in the filter.
   * @param {Buffer|String} value
   * @param {String?} enc - Can be any of the Buffer object's encodings.
   * @returns {Boolean}
   */

  test(value, enc) {
    const val = toBuffer(value, enc);

    for (let i = 0; i < this.n; i++) {
      const index = this.hash(val, i);
      if ((this.filter[index >>> 3] & (1 << (7 & index))) === 0)
        return false;
    }

    return true;
  }

  /**
   * Test whether data is present in the
   * filter and potentially add data.
   * @param {Buffer|String} value
   * @param {String?} enc - Can be any of the Buffer object's encodings.
   * @returns {Boolean} Whether data was added.
   */

  added(value, enc) {
    const val = toBuffer(value, enc);

    let ret = false;

    for (let i = 0; i < this.n; i++) {
      const index = this.hash(val, i);
      if (!ret && (this.filter[index >>> 3] & (1 << (7 & index))) === 0)
        ret = true;
      this.filter[index >>> 3] |= 1 << (7 & index);
    }

    return ret;
  }

  /**
   * Create a filter from a false positive rate.
   * @param {Number} items - Expected number of items.
   * @param {Number} rate - False positive rate (0.0-1.0).
   * @param {Number|String} update
   * @example
   * BloomFilter.fromRate(800000, 0.0001, 'none');
   * @returns {Boolean}
   */

  static fromRate(items, rate, update) {
    enforce(Number.isSafeInteger(items) && items > 0, 'items', 'integer');
    enforce(typeof rate === 'number' && isFinite(rate), 'rate', 'number');
    enforce(rate >= 0 && rate <= 1, 'rate', 'range between 0.1 and 1.0.');

    const bits = (-1 / LN2SQUARED * items * Math.log(rate)) | 0;
    const size = Math.max(8, bits);

    if (update !== -1) {
      if (size > BloomFilter.MAX_BLOOM_FILTER_SIZE * 8)
        throw new Error('Bloom filter size violates policy limits!');
    }

    const n = Math.max(1, (size / items * LN2) | 0);

    if (update !== -1) {
      if (n > BloomFilter.MAX_HASH_FUNCS)
        throw new Error('Bloom filter size violates policy limits!');
    }

    return new this(size, n, -1, update);
  }

  /**
   * Ensure the filter is within the size limits.
   * @returns {Boolean}
   */

  isWithinConstraints() {
    if (this.size > BloomFilter.MAX_BLOOM_FILTER_SIZE * 8)
      return false;

    if (this.n > BloomFilter.MAX_HASH_FUNCS)
      return false;

    return true;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return bio.sizeVarBytes(this.filter) + 9;
  }

  /**
   * Write filter to buffer writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeVarBytes(this.filter);
    bw.writeU32(this.n);
    bw.writeU32(this.tweak);
    bw.writeU8(this.update);
    return bw;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    this.filter = br.readVarBytes();
    this.size = this.filter.length * 8;
    this.n = br.readU32();
    this.tweak = br.readU32();
    this.update = br.readU8();

    if (this.update > 2)
      throw new Error('Invalid update flag.');

    return this;
  }
}

/**
 * Max bloom filter size.
 * @const {Number}
 * @default
 */

BloomFilter.MAX_BLOOM_FILTER_SIZE = 36000;

/**
 * Max number of hash functions.
 * @const {Number}
 * @default
 */

BloomFilter.MAX_HASH_FUNCS = 50;

/**
 * Bloom filter update flags.
 * @enum {Number}
 * @default
 */

BloomFilter.flags = {
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

BloomFilter.flagsByVal = [
  'NONE',
  'ALL',
  'PUBKEY_ONLY'
];

/*
 * Helpers
 */

function toBuffer(value, enc) {
  if (typeof value !== 'string') {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');
    return value;
  }

  enforce(typeof enc === 'string', 'enc', 'string');

  return Buffer.from(value, enc);
}

/*
 * Expose
 */

module.exports = BloomFilter;
