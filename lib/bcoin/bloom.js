/**
 * bloom.js - bloom filter for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');

/**
 * Bloom
 */

function Bloom(size, n, tweak) {
  if (!(this instanceof Bloom))
    return new Bloom(size, n, tweak);

  this.filter = new Buffer(Math.ceil(size / 8));
  this.size = size;
  this.n = n;
  this.tweak = tweak;

  this.reset();
}

Bloom.prototype.hash = function hash(val, n) {
  return murmur(val, sum32(mul32(n, 0xfba4c795), this.tweak)) % this.size;
};

Bloom.prototype.reset = function reset() {
  this.filter.fill(0);
};

Bloom.prototype.add = function add(val, enc) {
  var i, bit, pos, shift;

  val = utils.toBuffer(val, enc);

  for (i = 0; i < this.n; i++) {
    bit = this.hash(val, i);
    pos = 1 << (bit & 0x1f);
    shift = bit >> 5;
    shift *= 4;

    utils.writeU32(this.filter, utils.readU32(this.filter, shift) | pos, shift);
  }
};

Bloom.prototype.test = function test(val, enc) {
  var i, bit, pos, shift;

  val = utils.toBuffer(val, enc);

  for (i = 0; i < this.n; i++) {
    bit = this.hash(val, i);
    pos = 1 << (bit & 0x1f);
    shift = bit >> 5;
    shift *= 4;

    if ((utils.readU32(this.filter, shift) & pos) === 0)
      return false;
  }

  return true;
};

Bloom.prototype.toBuffer = function toBuffer() {
  return this.filter;
};

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

  data = utils.toBuffer(data);

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

Bloom.hash = murmur;

/**
 * Expose
 */

module.exports = Bloom;
