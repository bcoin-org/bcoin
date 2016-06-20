/*!
 * bloom.js - bloom filter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('./protocol/constants');
var assert = require('assert');
var BufferReader = require('./reader');
var BufferWriter = require('./writer');

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
 * Ensure the filter is within the size limits.
 * @returns {Boolean}
 */

Bloom.prototype.isWithinConstraints = function isWithinConstraints() {
  if (this.filter.length > constants.bloom.MAX_BLOOM_FILTER_SIZE)
    return false;

  if (this.n > constants.bloom.MAX_HASH_FUNCS)
    return false;

  return true;
};

/**
 * Serialize the filter in `filterload` packet format.
 * @returns {Buffer}
 */

Bloom.prototype.toRaw = function toRaw(writer) {
  var p = BufferWriter(writer);

  p.writeVarBytes(this.filter);
  p.writeU32(this.n);
  p.writeU32(this.tweak);
  p.writeU8(this.update);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Instantiate bloom filter from
 * serialized data (filterload).
 * @param {Buffer}
 * @param {String?} enc
 * @returns {Bloom}
 */

Bloom.fromRaw = function fromRaw(data, enc) {
  var p, filter, n, tweak, update;

  if (typeof data === 'string')
    data = new Buffer(data, enc);

  p = BufferReader(data);

  filter = p.readVarBytes();
  n = p.readU32();
  tweak = p.readU32();
  update = p.readU8();

  assert(constants.filterFlagsByVal[update] != null, 'Bad filter flag.');

  return new Bloom(filter, n, tweak, update);
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

/**
 * Murmur3 hash.
 * @memberof Bloom
 * @param {Buffer} data
 * @param {Number} seed
 * @returns {Number}
 */

function murmur3(data, seed) {
  var tail = data.length - (data.length % 4);
  var c1 = 0xcc9e2d51;
  var c2 = 0x1b873593;
  var h1 = seed;
  var i, k1;

  for (i = 0; i < tail; i += 4) {
    k1 = (data[i + 3] << 24)
      | (data[i + 2] << 16)
      | (data[i + 1] << 8)
      | data[i];
    k1 = mul32(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = mul32(k1, c2);
    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = sum32(mul32(h1, 5), 0xe6546b64);
  }

  k1 = 0;
  switch (data.length & 3) {
    case 3:
      k1 ^= data[tail + 2] << 16;
    case 2:
      k1 ^= data[tail + 1] << 8;
    case 1:
      k1 ^= data[tail + 0];
      k1 = mul32(k1, c1);
      k1 = rotl32(k1, 15);
      k1 = mul32(k1, c2);
      h1 ^= k1;
  }

  h1 ^= data.length;
  h1 ^= h1 >>> 16;
  h1 = mul32(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = mul32(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  if (h1 < 0)
    h1 += 0x100000000;

  return h1;
}

function mul32(a, b) {
  var alo = a & 0xffff;
  var blo = b & 0xffff;
  var ahi = a >>> 16;
  var bhi = b >>> 16;
  var r, lo, hi;

  lo = alo * blo;
  hi = (ahi * blo + bhi * alo) & 0xffff;

  hi += lo >>> 16;
  lo &= 0xffff;
  r = (hi << 16) | lo;

  if (r < 0)
    r += 0x100000000;

  return r;
}

function sum32(a, b) {
  var r = (a + b) & 0xffffffff;

  if (r < 0)
    r += 0x100000000;

  return r;
}

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function read(data, off) {
  return {
    hi: data.readUInt32LE(off + 4, true),
    lo: data.readUInt32LE(off, true)
  };
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
exports.rolling = RollingFilter;

module.exports = exports;
