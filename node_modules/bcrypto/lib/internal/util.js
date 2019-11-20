/*!
 * utils.js - utils for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

/* eslint spaced-comment: "off" */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const ZERO = Buffer.alloc(1, 0x00);
const cache = [];

/*
 * Util
 */

function countBits(buf) {
  assert(Buffer.isBuffer(buf));

  let i = 0;

  for (; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      break;
  }

  let bits = (buf.length - i) * 8;

  if (bits === 0)
    return 0;

  bits -= 8;

  let oct = buf[i];

  while (oct) {
    bits += 1;
    oct >>>= 1;
  }

  return bits;
}

function trimZeroes(buf) {
  if (buf == null)
    return ZERO;

  assert(Buffer.isBuffer(buf));

  if (buf.length === 0)
    return ZERO;

  if (buf[0] !== 0x00)
    return buf;

  for (let i = 1; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      return buf.slice(i);
  }

  return buf.slice(-1);
}

function getZero(size) {
  assert((size >>> 0) === size);
  assert(size <= 128);

  while (cache.length < size)
    cache.push(null);

  let zero = cache[size];

  if (!zero) {
    zero = Buffer.alloc(size, 0x00);
    cache[size] = zero;
  }

  return zero;
}

function leftPad(val, size) {
  if (val == null)
    return getZero(size);

  assert(Buffer.isBuffer(val));
  assert((size >>> 0) === size);

  if (val.length > size)
    val = trimZeroes(val);

  assert(val.length <= size);

  if (val.length === size)
    return val;

  const buf = Buffer.allocUnsafe(size);
  const pos = size - val.length;

  buf.fill(0x00, 0, pos);
  val.copy(buf, pos);

  return buf;
}

function *lines(str) {
  assert(typeof str === 'string');

  let i = 0;
  let j = 0;

  if (str.length > 0) {
    if (str.charCodeAt(0) === 0xfeff) {
      i += 1;
      j += 1;
    }
  }

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x0d /*'\r'*/:
      case 0x0a /*'\n'*/: {
        if (j !== i) {
          const line = trimRight(str.substring(j, i));

          if (line.length > 0)
            yield line;
        }

        if (ch === 0x0d && i + 1 < str.length) {
          if (str.charCodeAt(i + 1) === 0x0a)
            i += 1;
        }

        j = i + 1;

        break;
      }
    }
  }

  if (j !== i) {
    const line = trimRight(str.substring(j, i));

    if (line.length > 0)
      yield line;
  }
}

function trimRight(str) {
  assert(typeof str === 'string');

  for (let i = str.length - 1; i >= 0; i--) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x09 /*'\t'*/:
      case 0x0b /*'\v'*/:
      case 0x20 /*' '*/:
        continue;
    }

    return str.substring(0, i + 1);
  }

  return str;
}

/*
 * Expose
 */

exports.countBits = countBits;
exports.trimZeroes = trimZeroes;
exports.getZero = getZero;
exports.leftPad = leftPad;
exports.lines = lines;
