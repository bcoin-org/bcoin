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

  if (tweak == null || tweak == -1)
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
  var i, bits, pos, bit;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    bits = this.hash(val, i);
    pos = (bits >>> 5) * 4;
    bits &= 0x1f;
    bit = bits % 8;
    pos += (bits - bit) / 8;
    this.filter[pos] |= 1 << bit;
  }
};

/**
 * Test whether data is present in the filter.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean}
 */

Bloom.prototype.test = function test(val, enc) {
  var i, bits, pos, bit, oct;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    bits = this.hash(val, i);
    pos = (bits >>> 5) * 4;
    bits &= 0x1f;
    bit = bits % 8;
    pos += (bits - bit) / 8;
    if ((this.filter[pos] & (1 << bit)) === 0)
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
  var i, bits, pos, bit, oct;

  if (typeof val === 'string')
    val = new Buffer(val, enc);

  for (i = 0; i < this.n; i++) {
    bits = this.hash(val, i);
    pos = (bits >>> 5) * 4;
    bits &= 0x1f;
    bit = bits % 8;
    pos += (bits - bit) / 8;
    if (!ret && (this.filter[pos] & (1 << bit)) === 0)
      ret = true;
    this.filter[pos] |= 1 << bit;
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
  var i, j, hash, bits, pos, pos1, pos2, bit, oct;
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
 * An object which uses a hash table initially, but
 * switches to a bloom filter once a limit is reached.
 * @exports HashFilter
 * @constructor
 * @param {Number} items - Expected number of items.
 * @param {Number} rate - False positive rate (0.0-1.0).
 * @param {Number} [limit=5000] - Threshold at which
 * to switch to a bloom filter.
 */

function HashFilter(items, rate, limit) {
  if (!(this instanceof HashFilter))
    return new HashFilter(items, rate, limit);

  this.items = items;
  this.rate = rate;
  this.limit = limit || 5000;

  this.filter = null;
  this.table = {};
  this.count = 0;
}

/**
 * Reset the filter.
 */

HashFilter.prototype.reset = function reset() {
  if (this.filter)
    return this.filter.reset();

  this.table = {};
  this.count = 0;
};

/**
 * Add data to the filter.
 * @param {Buffer|String}
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 */

HashFilter.prototype.add = function add(val, enc) {
  var i, keys;

  if (this.filter)
    return this.filter.add(val, enc);

  if (Buffer.isBuffer(val))
    val = val.toString('hex');

  if (this.table[val])
    return false;

  this.table[val] = true;
  this.count++;

  if (this.count > this.limit) {
    this.filter = new RollingFilter(this.items, this.rate);

    keys = Object.keys(this.table);

    for (i = 0; i < keys.length; i++)
      this.filter.add(keys[i], 'hex');

    this.table = {};
    this.count = 0;
  }

  return true;
};

/**
 * Test whether data is present in the filter.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean}
 */

HashFilter.prototype.test = function test(val, enc) {
  if (this.filter)
    return this.filter.test(val, enc);

  if (Buffer.isBuffer(val))
    val = val.toString('hex');

  return this.table[val] === true;
};

/**
 * Test whether data is present in the
 * filter and potentially add data.
 * @param {Buffer|String} val
 * @param {String?} enc - Can be any of the Buffer object's encodings.
 * @returns {Boolean} Whether data was added.
 */

HashFilter.prototype.added = function added(val, enc) {
  if (this.filter)
    return this.filter.added(val, enc);

  return this.add(val, enc);
};

/*
 * Murmur3
 */

/**
 * Murmur3 hash.
 * @memberof Bloom
 * @param {Buffer} data
 * @param {Number} seed
 * @returns {Number}
 */

function murmur3(data, seed) {
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
exports.hash = HashFilter;

module.exports = Bloom;
