/*!
 * bloom.js - bloom filter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var constants = require('../protocol/constants');
var murmur3 = require('./murmur3');
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var sum32 = murmur3.sum32;
var mul32 = murmur3.mul32;

/*
 * Constants
 */

var LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455;
var LN2 = 0.6931471805599453094172321214581765680755001343602552;

/**
 * Bloom Filter
 * @exports Bloom
 * @constructor
 * @param {Number|Bufer} size - Filter size in bits, or filter itself.
 * @param {Number} n - Number of hash functions.
 * @param {Number} tweak - Seed value.
 * @property {Buffer} filter
 * @property {Number} size
 * @property {Number} n
 * @property {Number} tweak
 * @property {Number} update - Update flag (see {@link constants.filterFlags}).
 */

function Bloom(size, n, tweak, update) {
  if (!(this instanceof Bloom))
    return new Bloom(size, n, tweak, update);

  if (Buffer.isBuffer(size)) {
    this.filter = size;
    this.size = this.filter.length * 8;
  } else {
    this.size = size - (size % 8);
    this.filter = new Buffer(this.size / 8);
    this.reset();
  }

  if (tweak == null || tweak === -1)
    tweak = (Math.random() * 0x100000000) >>> 0;

  if (update == null || update === -1)
    update = constants.filterFlags.NONE;

  if (typeof update === 'string')
    update = constants.filterFlags[update.toUpperCase()];

  this.n = n;
  this.tweak = tweak;
  this.update = update;
}

/**
 * Perform the mumur3 hash on data.
 * @param {Buffer} val
 * @param {Number} seed
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
  var i, index;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    index = this.hash(val, i);
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
  var i, index;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    index = this.hash(val, i);
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
  var ret = false;
  var i, index;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    index = this.hash(val, i);
    if (!ret && (this.filter[index >>> 3] & (1 << (7 & index))) === 0)
      ret = true;
    this.filter[index >>> 3] |= 1 << (7 & index);
  }

  return ret;
};

/**
 * Create a filter from a false positive rate.
 * @param {Number} items - Expeected number of items.
 * @param {Number} rate - False positive rate (0.0-1.0).
 * @param {Number|String} update
 * @example
 * bcoin.bloom.fromRate(800000, 0.01, 'none');
 * @returns {Boolean}
 */

Bloom.fromRate = function fromRate(items, rate, update) {
  var size, n;

  size = (-1 / LN2SQUARED * items * Math.log(rate)) | 0;

  if (update !== -1)
    size = Math.min(size, constants.bloom.MAX_BLOOM_FILTER_SIZE * 8);

  n = (size / items * LN2) | 0;

  if (update !== -1)
    n = Math.min(n, constants.bloom.MAX_HASH_FUNCS);

  return new Bloom(size, n, -1, update);
};

/**
 * Serialize bloom filter.
 * @returns {Buffer}
 */

Bloom.prototype.toRaw = function toRaw(writer) {
  var bw = BufferWriter(writer);

  bw.writeVarBytes(this.filter);
  bw.writeU32(this.n);
  bw.writeU32(this.tweak);
  bw.writeU8(this.update);

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Bloom.prototype.fromRaw = function fromRaw(data) {
  var br = BufferReader(data);

  this.filter = br.readVarBytes();
  this.n = br.readU32();
  this.tweak = br.readU32();
  this.update = br.readU8();

  assert(constants.filterFlagsByVal[this.update] != null, 'Bad filter flag.');

  return this;
};

/**
 * Instantiate bloom filter from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {Bloom}
 */

Bloom.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new Bloom().fromRaw(data);
};

/**
 * A rolling bloom filter used internally
 * (do not relay this on the p2p network).
 * @exports RollingFilter
 * @constructor
 * @param {Number} items - Expected number of items.
 * @param {Number} rate - False positive rate (0.0-1.0).
 */

function RollingFilter(items, rate) {
  var logRate, max;

  if (!(this instanceof RollingFilter))
    return new RollingFilter(items, rate);

  logRate = Math.log(rate);

  this.entries = 0;
  this.generation = 1;

  this.n = Math.max(1, Math.min(Math.round(logRate / Math.log(0.5)), 50));
  this.limit = (items + 1) / 2 | 0;

  max = this.limit * 3;
  this.size = -1 * this.n * max / Math.log(1.0 - Math.exp(logRate / this.n));
  this.size = Math.ceil(this.size);

  this.items = ((this.size + 63) / 64 | 0) << 1;

  this.tweak = (Math.random() * 0x100000000) >>> 0;

  this.filter = new Buffer(this.items * 8);
  this.filter.fill(0);
}

/**
 * Perform the mumur3 hash on data.
 * @param {Buffer} val
 * @param {Number} seed
 * @returns {Number}
 */

RollingFilter.prototype.hash = function hash(val, n) {
  return murmur3(val, sum32(mul32(n, 0xfba4c795), this.tweak));
};

/**
 * Reset the filter.
 */

RollingFilter.prototype.reset = function reset() {
  if (this.entries === 0)
    return;

  this.entries = 0;
  this.generation = 1;
  this.filter.fill(0);
};

/**
 * Add data to the filter.
 * @param {Buffer|String}
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 */

RollingFilter.prototype.add = function add(val, enc) {
  var i, hash, bits, pos, pos1, pos2, bit, oct;
  var m1, m2, v1, v2, mhi, mlo;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  if (this.entries === this.limit) {
    this.entries = 0;
    this.generation += 1;

    if (this.generation === 4)
      this.generation = 1;

    m1 = (this.generation & 1) * 0xffffffff;
    m2 = (this.generation >>> 1) * 0xffffffff;

    for (i = 0; i < this.items; i += 2) {
      pos1 = i * 8;
      pos2 = (i + 1) * 8;
      v1 = read(this.filter, pos1);
      v2 = read(this.filter, pos2);
      mhi = (v1.hi ^ m1) | (v2.hi ^ m2);
      mlo = (v1.lo ^ m1) | (v2.lo ^ m2);
      v1.hi &= mhi;
      v1.lo &= mlo;
      v2.hi &= mhi;
      v2.lo &= mlo;
      write(this.filter, v1, pos1);
      write(this.filter, v2, pos2);
    }
  }

  this.entries += 1;

  for (i = 0; i < this.n; i++) {
    hash = this.hash(val, i);
    bits = hash & 0x3f;
    pos = (hash >>> 6) % this.items;
    pos1 = (pos & ~1) * 8;
    pos2 = (pos | 1) * 8;

    bit = bits % 8;
    oct = (bits - bit) / 8;
    pos1 += oct;
    pos2 += oct;

    this.filter[pos1] &= ~(1 << bit);
    this.filter[pos1] |= (this.generation & 1) << bit;

    this.filter[pos2] &= ~(1 << bit);
    this.filter[pos2] |= (this.generation >>> 1) << bit;
  }
};

/**
 * Test whether data is present in the filter.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean}
 */

RollingFilter.prototype.test = function test(val, enc) {
  var i, hash, bits, pos, pos1, pos2, bit, oct;

  if (this.entries === 0)
    return false;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    hash = this.hash(val, i);
    bits = hash & 0x3f;
    pos = (hash >>> 6) % this.items;
    pos1 = (pos & ~1) * 8;
    pos2 = (pos | 1) * 8;

    bit = bits % 8;
    oct = (bits - bit) / 8;
    pos1 += oct;
    pos2 += oct;

    bits = (this.filter[pos1] >>> bit) & 1;
    bits |= (this.filter[pos2] >>> bit) & 1;

    if (bits === 0)
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

RollingFilter.prototype.added = function added(val, enc) {
  if (typeof val === 'string')
    val = new Buffer(val, enc);

  if (!this.test(val)) {
    this.add(val);
    return true;
  }

  return false;
};

/*
 * Helpers
 */

function U64(hi, lo) {
  this.hi = hi;
  this.lo = lo;
}

function read(data, off) {
  var hi = data.readUInt32LE(off + 4, true);
  var lo = data.readUInt32LE(off, true);
  return new U64(hi, lo);
}

function write(data, value, off) {
  data.writeUInt32LE(value.hi, off + 4, true);
  data.writeUInt32LE(value.lo, off, true);
}

/*
 * Expose
 */

exports = Bloom;
exports.murmur3 = murmur3;
exports.Rolling = RollingFilter;

module.exports = exports;
