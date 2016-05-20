/*!
 * bloom.js - bloom filter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var assert = utils.assert;
var constants = require('./protocol/constants');

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
    this.filter = new Buffer(Math.ceil(size / 8));
    this.size = size;
    this.reset();
  }

  if (tweak == null)
    tweak = (Math.random() * 0x100000000) >>> 0;

  if (update == null)
    update = constants.filterFlags.NONE;

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
  return murmur(val, sum32(mul32(n, 0xfba4c795), this.tweak)) % this.size;
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
  var i, bit, pos, shift;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    bit = this.hash(val, i);
    pos = 1 << (bit & 0x1f);
    shift = bit >>> 5;
    shift *= 4;

    this.filter.writeUInt32LE(
      this.filter.readUInt32LE(shift, true) | pos,
      shift,
      true);
  }
};

/**
 * Test whether data is present in the filter.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean}
 */

Bloom.prototype.test = function test(val, enc) {
  var i, bit, pos, shift;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    bit = this.hash(val, i);
    pos = 1 << (bit & 0x1f);
    shift = bit >>> 5;
    shift *= 4;

    if ((this.filter.readUInt32LE(shift, true) & pos) === 0)
      return false;
  }

  return true;
};

/**
 * Return a Buffer representing the filter,
 * suitable for transmission on the network.
 * @returns {Buffer}
 */

Bloom.prototype.toBuffer = function toBuffer() {
  return this.filter;
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
 * Create a filter from a false positive rate.
 * @param {Number} items - Expeected number of items.
 * @param {Number} rate - False positive rate (0.0-1.0).
 * @param {Number} tweak
 * @param {Number} update
 * @example
 * bcoin.bloom.fromRate(800000, 0.01, 0xdeadbeef);
 * @returns {Boolean}
 */

Bloom.fromRate = function fromRate(items, rate, tweak, update) {
  var size, n;

  size = (-1 / LN2SQUARED * items * Math.log(rate)) | 0;
  size = Math.min(size, constants.bloom.MAX_BLOOM_FILTER_SIZE * 8);

  n = (size / items * LN2) | 0;
  n = Math.min(n, constants.bloom.MAX_HASH_FUNCS);

  return new Bloom(size, n, tweak, update);
};

/**
 * A bloom filter that will reset itself
 * once the max number of items is reached.
 * @exports RollingFilter
 * @constructor
 * @param {Number} items - Expected number of items.
 * @param {Number} rate - False positive rate.
 * @property {Bloom} filter
 * @property {Number} items
 */

function RollingFilter(items, rate) {
  if (!(this instanceof RollingFilter))
    return new RollingFilter(items, rate);

  this.count = 0;
  this.items = items;

  this.filter = Bloom.fromRate(items, rate);
}

/**
 * Reset the filter.
 */

RollingFilter.prototype.reset = function reset() {
  if (this.count === 0)
    return;

  this.count = 0;

  return this.filter.reset();
};

/**
 * Add data to the filter.
 * @param {Buffer|String}
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 */

RollingFilter.prototype.add = function add(val, enc) {
  if (this.count >= this.items)
    this.reset();

  this.count++;

  return this.filter.add(val, enc);
};

/**
 * Test whether data is present in the filter.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean}
 */

RollingFilter.prototype.test = function test(val, enc) {
  if (this.count === 0)
    return false;

  return this.filter.test(val, enc);
};

/**
 * Test whether data is present in the filter, add it if not.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean}
 */

RollingFilter.prototype.added = function added(val, enc) {
  if (typeof val === 'string')
    val = new Buffer(val, enc);

  if (!this.filter.test(val)) {
    this.filter.add(val);
    return true;
  }

  return false;
};

/*
 * Murmur
 */

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

function murmur(data, seed) {
  var c1 = 0xcc9e2d51;
  var c2 = 0x1b873593;
  var r1 = 15;
  var r2 = 13;
  var m = 5;
  var n = 0xe6546b64;
  var hash = seed;
  var i, w, r, j;

  assert(Buffer.isBuffer(data));

  for (i = 0; i + 4 <= data.length; i += 4) {
    w = data[i]
      | (data[i + 1] << 8)
      | (data[i + 2] << 16)
      | (data[i + 3] << 24);

    w = mul32(w, c1);
    w = rotl32(w, r1);
    w = mul32(w, c2);

    hash ^= w;
    hash = rotl32(hash, r2);
    hash = mul32(hash, m);
    hash = sum32(hash, n);
  }

  if (i !== data.length) {
    r = 0;
    for (j = data.length - 1; j >= i; j--)
      r = (r << 8) | data[j];

    r = mul32(r, c1);
    r = rotl32(r, r1);
    if (r < 0)
      r += 0x100000000;
    r = mul32(r, c2);

    hash ^= r;
  }

  hash ^= data.length;
  hash ^= hash >>> 16;
  hash = mul32(hash, 0x85ebca6b);
  hash ^= hash >>> 13;
  hash = mul32(hash, 0xc2b2ae35);
  hash ^= hash >>> 16;

  if (hash < 0)
    hash += 0x100000000;

  return hash;
}

/**
 * Murmur3 hash.
 * @static
 * @function
 * @param {Buffer} data
 * @param {Number} seed
 * @returns {Number}
 */

Bloom.hash = murmur;

Bloom.rolling = RollingFilter;

/*
 * Expose
 */

module.exports = Bloom;
