/*!
 * bech32.js - bech32 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on "bech32".
 * https://github.com/sipa/bech32
 *
 * Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

'use strict';

/**
 * @module utils/bech32
 */

var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
var TABLE = {};
var GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
var ZERO6 = new Buffer('000000000000', 'hex');
var POOL6 = new Buffer(6);
var POOL10 = new Buffer(10);
var i;

for (i = 0; i < CHARSET.length; i++)
  TABLE[CHARSET[i]] = i;

/**
 * Allocate a buffer from the pool.
 * @ignore
 * @param {Number} size
 * @returns {Buffer}
 */

function alloc(size) {
  if (size > 10)
    return new Buffer(size);
  return POOL10.slice(0, size);
}

/**
 * Update checksum.
 * @ignore
 * @param {Buffer} values
 * @param {Number} chk
 * @returns {Number}
 */

function polymod(values, chk) {
  var i, j, top;

  for (i = 0; i < values.length; i++) {
    top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ values[i];

    for (j = 0; j < 5; j++) {
      if ((top >> j) & 1)
        chk ^= GENERATOR[j];
    }
  }

  return chk;
}

/**
 * Expand human readable part.
 * @ignore
 * @param {String} hrp
 * @returns {Buffer}
 */

function expand(hrp) {
  var ret = alloc(hrp.length * 2 + 1);
  var p = 0;
  var i;

  for (i = 0; i < hrp.length; i++)
    ret[p++] = hrp.charCodeAt(i) >> 5;

  ret[p++] = 0;

  for (i = 0; i < hrp.length; i++)
    ret[p++] = hrp.charCodeAt(i) & 31;

  return ret;
}

/**
 * Verify checksum against hrp and data.
 * @ignore
 * @param {String} hrp
 * @param {Buffer} data
 * @returns {Boolean}
 */

function verify(hrp, data) {
  var chk = 1;

  chk = polymod(expand(hrp), chk);
  chk = polymod(data, chk);

  return chk === 1;
}

/**
 * Create checksum from hrp and data.
 * @ignore
 * @param {String} hrp
 * @param {Buffer} data
 * @returns {Buffer}
 */

function checksum(hrp, data) {
  var chk = 1;
  var ret = POOL6;
  var p = 0;
  var i, mod;

  chk = polymod(expand(hrp), chk);
  chk = polymod(data, chk);
  chk = polymod(ZERO6, chk);

  mod = chk ^ 1;

  for (i = 0; i < 6; i++)
    ret[p++] = (mod >> 5 * (5 - i)) & 31;

  return ret;
}

/**
 * Encode hrp and data as a bech32 string.
 * @ignore
 * @param {String} hrp
 * @param {Buffer} data
 * @returns {String}
 */

function encode(hrp, data) {
  var chk = checksum(hrp, data);
  var str = hrp + '1';
  var i;

  for (i = 0; i < data.length; i++)
    str += CHARSET[data[i]];

  for (i = 0; i < chk.length; i++)
    str += CHARSET[chk[i]];

  return str;
}

/**
 * Decode a bech32 string.
 * @param {String} str
 * @returns {Bech32Result}
 */

function decode(str) {
  var lower = false;
  var upper = false;
  var p = 0;
  var i, ch, pos, hrp, data;

  for (i = 0; i < str.length; i++) {
    ch = str.charCodeAt(i);

    if (ch < 33 || ch > 126)
      throw new Error('Bech32 character out of range.');

    if (ch >= 97 && ch <= 122)
      lower = true;

    if (ch >= 65 && ch <= 90)
      upper = true;
  }

  if (lower && upper)
    throw new Error('Invalid bech32 casing.');

  str = str.toLowerCase();

  pos = str.lastIndexOf('1');

  if (pos < 1 || pos + 7 > str.length || str.length > 90)
    throw new Error('Invalid bech32 data section.');

  hrp = str.substring(0, pos);
  data = new Buffer(str.length - (pos + 1));

  for (i = pos + 1; i < str.length; i++) {
    ch = TABLE[str[i]];

    if (ch == null)
      throw new Error('Invalid bech32 character.');

    data[p++] = ch;
  }

  if (!verify(hrp, data))
    throw new Error('Invalid bech32 checksum.');

  return new Bech32Result(hrp, data.slice(0, -6));
}

/**
 * Convert serialized data to bits,
 * suitable to be serialized as bech32.
 * @param {Buffer} data
 * @param {Number} size
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Number} pad
 * @param {Number} off
 * @returns {Buffer}
 */

function bitsify(data, size, frombits, tobits, pad, off) {
  var acc = 0;
  var bits = 0;
  var maxv = (1 << tobits) - 1;
  var ret = new Buffer(size);
  var p = 0;
  var i, value;

  if (pad !== -1)
    ret[p++] = pad;

  for (i = off; i < data.length; i++) {
    value = data[i];

    if ((value >> frombits) !== 0)
      throw new Error('Invalid value in bech32 bits.');

    acc = (acc << frombits) | value;
    bits += frombits;

    while (bits >= tobits) {
      bits -= tobits;
      ret[p++] = (acc >> bits) & maxv;
    }
  }

  if (pad !== -1) {
    if (bits > 0)
      ret[p++] = (acc << (tobits - bits)) & maxv;
  } else {
    if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
      throw new Error('Bad bech32 bits.');
  }

  return ret.slice(0, p);
}

/**
 * Bech32Result
 * @constructor
 * @private
 * @param {String} hrp
 * @param {Buffer} data
 * @property {String} hrp
 * @property {Buffer} data
 */

function Bech32Result(hrp, data) {
  this.hrp = hrp;
  this.data = data;
}

/*
 * Expose
 */

exports.decode = decode;
exports.encode = encode;
exports.bitsify = bitsify;
