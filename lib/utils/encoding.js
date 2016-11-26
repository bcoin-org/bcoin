/*!
 * encoding.js - encoding utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var BN = require('bn.js');
var encoding = exports;

/**
 * UINT32_MAX
 * @const {BN}
 */

encoding.U32_MAX = new BN(0xffffffff);

/**
 * UINT64_MAX
 * @const {BN}
 */

encoding.U64_MAX = new BN('ffffffffffffffff', 'hex');

/**
 * Read uint64le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

encoding.readU64 = function readU64(data, off) {
  var num;
  off = off >>> 0;
  num = data.slice(off, off + 8);
  return new BN(num, 'le');
};

/**
 * Read uint64be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

encoding.readU64BE = function readU64BE(data, off) {
  var num;
  off = off >>> 0;
  num = data.slice(off, off + 8);
  return new BN(num, 'be');
};

/**
 * Read int64le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

encoding.read64 = function read64(data, off) {
  var num;

  off = off >>> 0;

  num = data.slice(off, off + 8);

  if (num[num.length - 1] & 0x80)
    return new BN(num, 'le').notn(64).addn(1).neg();

  return new BN(num, 'le');
};

/**
 * Read int64be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

encoding.read64BE = function read64BE(data, off) {
  var num;

  off = off >>> 0;

  num = data.slice(off, off + 8);

  if (num[0] & 0x80)
    return new BN(num, 'be').notn(64).addn(1).neg();

  return new BN(num, 'be');
};

/**
 * Write uint64le.
 * @param {BN|Number} value
 */

encoding.writeU64 = function writeU64(dst, num, off) {
  return encoding.write64(dst, num, off);
};

/**
 * Write uint64be.
 * @param {BN|Number} value
 */

encoding.writeU64BE = function writeU64BE(dst, num, off) {
  return encoding.write64BE(dst, num, off);
};

/**
 * Write a javascript number as a uint64le (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.writeU64N = function writeU64N(dst, num, off) {
  return encoding.write64N(dst, num, off);
};

/**
 * Write a javascript number as a uint64be (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.writeU64NBE = function writeU64NBE(dst, num, off) {
  return encoding.write64NBE(dst, num, off);
};

/**
 * Max safe integer (53 bits).
 * @const {Number}
 * @default
 */

encoding.MAX_SAFE_INTEGER = 0x1fffffffffffff;

/**
 * Max 52 bit integer (safe for additions).
 * `(MAX_SAFE_INTEGER - 1) / 2`
 * @const {Number}
 * @default
 */

encoding.MAX_SAFE_ADDITION = 0xfffffffffffff;

/**
 * Write a javascript number as an int64le (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.write64N = function write64N(dst, num, off, be) {
  var negative, hi, lo;

  assert(typeof num === 'number');

  off = off >>> 0;

  negative = num < 0;

  if (negative) {
    num = -num;
    num -= 1;
  }

  assert(num <= encoding.MAX_SAFE_INTEGER, 'Number exceeds 2^53-1');

  lo = num % 0x100000000;
  hi = (num - lo) / 0x100000000;

  if (negative) {
    hi = ~hi >>> 0;
    lo = ~lo >>> 0;
  }

  if (be) {
    dst[off + 0] = (hi >>> 24) & 0xff;
    dst[off + 1] = (hi >>> 16) & 0xff;
    dst[off + 2] = (hi >>> 8) & 0xff;
    dst[off + 3] = (hi >>> 0) & 0xff;
    dst[off + 4] = (lo >>> 24) & 0xff;
    dst[off + 5] = (lo >>> 16) & 0xff;
    dst[off + 6] = (lo >>> 8) & 0xff;
    dst[off + 7] = (lo >>> 0) & 0xff;
  } else {
    dst[off + 0] = (lo >>> 0) & 0xff;
    dst[off + 1] = (lo >>> 8) & 0xff;
    dst[off + 2] = (lo >>> 16) & 0xff;
    dst[off + 3] = (lo >>> 24) & 0xff;
    dst[off + 4] = (hi >>> 0) & 0xff;
    dst[off + 5] = (hi >>> 8) & 0xff;
    dst[off + 6] = (hi >>> 16) & 0xff;
    dst[off + 7] = (hi >>> 24) & 0xff;
  }

  return off + 8;
};

/**
 * Write a javascript number as an int64be (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.write64NBE = function write64NBE(dst, num, off) {
  return encoding.write64N(dst, num, off, true);
};

/**
 * Read uint64le as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.readU64N = function readU64N(data, off, force53, be) {
  var hi, lo;

  off = off >>> 0;

  if (be) {
    hi = data.readUInt32BE(off, true);
    lo = data.readUInt32BE(off + 4, true);
  } else {
    hi = data.readUInt32LE(off + 4, true);
    lo = data.readUInt32LE(off, true);
  }

  if (force53)
    hi &= 0x1fffff;

  assert((hi & 0xffe00000) === 0, 'Number exceeds 2^53-1');

  return (hi * 0x100000000) + lo;
};

/**
 * Read uint64be as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.readU64NBE = function readU64NBE(data, off, force53) {
  return encoding.readU64N(data, off, force53, true);
};

/**
 * Read int64le as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.read64N = function read64N(data, off, force53, be) {
  var hi, lo;

  off = off >>> 0;

  if (be) {
    hi = data.readUInt32BE(off, true);
    lo = data.readUInt32BE(off + 4, true);
  } else {
    hi = data.readUInt32LE(off + 4, true);
    lo = data.readUInt32LE(off, true);
  }

  if (hi & 0x80000000) {
    hi = ~hi >>> 0;
    lo = ~lo >>> 0;

    if (force53)
      hi &= 0x1fffff;

    assert((hi & 0xffe00000) === 0, 'Number exceeds 2^53-1');

    return -(hi * 0x100000000 + lo + 1);
  }

  if (force53)
    hi &= 0x1fffff;

  assert((hi & 0xffe00000) === 0, 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
};

/**
 * Read int64be as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

encoding.read64NBE = function read64NBE(data, off, force53) {
  return encoding.read64N(data, off, force53, true);
};

/**
 * Write int64le.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

encoding.write64 = function write64(dst, num, off) {
  var i;

  if (typeof num === 'number')
    return encoding.write64N(dst, num, off);

  off = off >>> 0;

  if (num.isNeg())
    num = num.neg().inotn(64).iaddn(1);

  if (num.bitLength() > 64)
    num = num.uand(encoding.U64_MAX);

  num = num.toArray('le', 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i];

  return off;
};

/**
 * Write int64be.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

encoding.write64BE = function write64BE(dst, num, off) {
  var i;

  if (typeof num === 'number')
    return encoding.write64NBE(dst, num, off);

  off = off >>> 0;

  if (num.isNeg())
    num = num.neg().inotn(64).iaddn(1);

  if (num.bitLength() > 64)
    num = num.uand(encoding.U64_MAX);

  num = num.toArray('be', 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i];

  return off;
};

/**
 * Read a varint.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean?} big - Whether to read as a big number.
 * @returns {Object}
 */

encoding.readVarint = function readVarint(data, off, big) {
  var value, size;

  off = off >>> 0;

  assert(off < data.length);

  switch (data[off]) {
    case 0xff:
      size = 9;
      assert(off + size <= data.length);
      if (big) {
        value = encoding.readU64(data, off + 1);
        assert(value.bitLength() > 32);
      } else {
        value = encoding.readU64N(data, off + 1);
        assert(value > 0xffffffff);
      }
      break;
    case 0xfe:
      size = 5;
      assert(off + size <= data.length);
      value = data.readUInt32LE(off + 1, true);
      assert(value > 0xffff);
      if (big)
        value = new BN(value);
      break;
    case 0xfd:
      size = 3;
      assert(off + size <= data.length);
      value = data[off + 1] | (data[off + 2] << 8);
      assert(value >= 0xfd);
      if (big)
        value = new BN(value);
      break;
    default:
      size = 1;
      value = data[off];
      if (big)
        value = new BN(value);
      break;
  }

  return { size: size, value: value };
};

/**
 * Read a varint size.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

encoding.skipVarint = function skipVarint(data, off) {
  off = off >>> 0;

  assert(off < data.length);

  switch (data[off]) {
    case 0xff:
      return 9;
    case 0xfe:
      return 5;
    case 0xfd:
      return 3;
    default:
      return 1;
  }
};

/**
 * Write a varint.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

encoding.writeVarint = function writeVarint(dst, num, off) {
  off = off >>> 0;

  if (BN.isBN(num)) {
    if (num.bitLength() > 32) {
      dst[off] = 0xff;
      encoding.writeU64(dst, num, off + 1);
      return off + 9;
    }
    num = num.toNumber();
  }

  num = +num;

  if (num < 0xfd) {
    dst[off] = num & 0xff;
    return off + 1;
  }

  if (num <= 0xffff) {
    dst[off] = 0xfd;
    dst[off + 1] = num & 0xff;
    dst[off + 2] = (num >>> 8) & 0xff;
    return off + 3;
  }

  if (num <= 0xffffffff) {
    dst[off] = 0xfe;
    dst[off + 1] = num & 0xff;
    dst[off + 2] = (num >>> 8) & 0xff;
    dst[off + 3] = (num >>> 16) & 0xff;
    dst[off + 4] = (num >>> 24) & 0xff;
    return off + 5;
  }

  dst[off] = 0xff;
  encoding.writeU64N(dst, num, off + 1);

  return off + 9;
};

/**
 * Calculate size of varint.
 * @param {BN|Number} num
 * @returns {Number} size
 */

encoding.sizeVarint = function sizeVarint(num) {
  if (BN.isBN(num)) {
    if (num.bitLength() > 32)
      return 9;
    num = num.toNumber();
  }

  if (num < 0xfd)
    return 1;

  if (num <= 0xffff)
    return 3;

  if (num <= 0xffffffff)
    return 5;

  return 9;
};

/**
 * Read a varint (type 2).
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean?} big - Whether to read as a big number.
 * @returns {Object}
 */

encoding.readVarint2 = function readVarint2(data, off, big) {
  var num = 0;
  var size = 0;
  var bnum, ch;

  off = off >>> 0;

  for (;;) {
    assert(off < data.length);

    ch = data[off++];
    size++;

    if (num >= 0x3fffffffffff) {
      assert(big, 'Number exceeds 2^53-1.');
      bnum = new BN(num);
      num = 0;
    }

    if (bnum) {
      assert(bnum.bitLength() <= 256);
      bnum.iushln(7).iaddn(ch & 0x7f);
      if ((ch & 0x80) === 0)
        break;
      bnum.iaddn(1);
      continue;
    }

    num = (num * 0x80) + (ch & 0x7f);
    if ((ch & 0x80) === 0)
      break;
    num++;
  }

  if (bnum)
    return { size: size, value: bnum };

  if (big)
    num = new BN(num);

  return { size: size, value: num };
};

/**
 * Write a varint (type 2).
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

encoding.writeVarint2 = function writeVarint2(dst, num, off) {
  var tmp = [];
  var len = 0;

  if (BN.isBN(num)) {
    if (num.bitLength() > 53) {
      for (;;) {
        tmp[len] = (num.words[0] & 0x7f) | (len ? 0x80 : 0x00);
        if (num.cmpn(0x7f) <= 0)
          break;
        num.iushrn(7).isubn(1);
        len++;
      }

      assert(off + len <= dst.length);

      do {
        dst[off++] = tmp[len];
      } while (len--);

      return off;
    }

    num = num.toNumber();
  }

  off = off >>> 0;
  num = +num;

  for (;;) {
    tmp[len] = (num & 0x7f) | (len ? 0x80 : 0x00);
    if (num <= 0x7f)
      break;
    num = ((num - (num % 0x80)) / 0x80) - 1;
    len++;
  }

  assert(off + len <= dst.length);

  do {
    dst[off++] = tmp[len];
  } while (len--);

  return off;
};

/**
 * Calculate size of varint (type 2).
 * @param {BN|Number} num
 * @returns {Number} size
 */

encoding.sizeVarint2 = function sizeVarint2(num) {
  var size = 0;

  if (BN.isBN(num)) {
    if (num.bitLength() > 53) {
      num = num.clone();

      for (;;) {
        size++;
        if (num.cmpn(0x7f) <= 0)
          break;
        num.iushrn(7).isubn(1);
      }

      return size;
    }

    num = num.toNumber();
  }

  num = +num;

  for (;;) {
    size++;
    if (num <= 0x7f)
      break;
    num = ((num - (num % 0x80)) / 0x80) - 1;
  }

  return size;
};

/**
 * Serialize number as a u8.
 * @param {Number} num
 * @returns {Buffer}
 */

encoding.U8 = function U8(num) {
  var data = new Buffer(1);
  data[0] = num >>> 0;
  return data;
};

/**
 * Serialize number as a u32le.
 * @param {Number} num
 * @returns {Buffer}
 */

encoding.U32 = function U32(num) {
  var data = new Buffer(4);
  data.writeUInt32LE(num, 0, true);
  return data;
};
