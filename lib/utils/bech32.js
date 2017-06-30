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

const native = require('../native').binding;

/**
 * @module utils/bech32
 */

const POOL65 = Buffer.allocUnsafe(65);
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];

/**
 * Update checksum.
 * @ignore
 * @param {Number} chk
 * @returns {Number}
 */

function polymod(pre) {
  let b = pre >>> 25;
  return ((pre & 0x1ffffff) << 5)
    ^ (-((b >> 0) & 1) & 0x3b6a57b2)
    ^ (-((b >> 1) & 1) & 0x26508e6d)
    ^ (-((b >> 2) & 1) & 0x1ea119fa)
    ^ (-((b >> 3) & 1) & 0x3d4233dd)
    ^ (-((b >> 4) & 1) & 0x2a1462b3);
}

/**
 * Encode hrp and data as a bech32 string.
 * @ignore
 * @param {String} hrp
 * @param {Buffer} data
 * @returns {String}
 */

function serialize(hrp, data) {
  let str = '';
  let chk = 1;
  let i, ch;

  for (i = 0; i < hrp.length; i++) {
    ch = hrp.charCodeAt(i);

    if ((ch >> 5) === 0)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ (ch >> 5);
  }

  if (i + 7 + data.length > 90)
    throw new Error('Invalid bech32 data length.');

  chk = polymod(chk);

  for (i = 0; i < hrp.length; i++) {
    ch = hrp.charCodeAt(i);
    chk = polymod(chk) ^ (ch & 0x1f);
    str += hrp[i];
  }

  str += '1';

  for (i = 0; i < data.length; i++) {
    ch = data[i];

    if ((ch >> 5) !== 0)
      throw new Error('Invalid bech32 value.');

    chk = polymod(chk) ^ ch;
    str += CHARSET[ch];
  }

  for (i = 0; i < 6; i++)
    chk = polymod(chk);

  chk ^= 1;

  for (i = 0; i < 6; i++)
    str += CHARSET[(chk >>> ((5 - i) * 5)) & 0x1f];

  return str;
}

/**
 * Decode a bech32 string.
 * @param {String} str
 * @returns {Array} [hrp, data]
 */

function deserialize(str) {
  let chk = 1;
  let lower = false;
  let upper = false;
  let hrp = '';
  let dlen = 0;
  let i, hlen, ch, v, data;

  if (str.length < 8 || str.length > 90)
    throw new Error('Invalid bech32 string length.');

  while (dlen < str.length && str[(str.length - 1) - dlen] !== '1')
    dlen++;

  hlen = str.length - (1 + dlen);

  if (hlen < 1 || dlen < 6)
    throw new Error('Invalid bech32 data length.');

  dlen -= 6;
  data = Buffer.allocUnsafe(dlen);

  for (i = 0; i < hlen; i++) {
    ch = str.charCodeAt(i);

    if (ch < 0x21 || ch > 0x7e)
      throw new Error('Invalid bech32 character.');

    if (ch >= 0x61 && ch <= 0x7a) {
      lower = true;
    } else if (ch >= 0x41 && ch <= 0x5a) {
      upper = true;
      ch = (ch - 0x41) + 0x61;
    }

    hrp += String.fromCharCode(ch);
    chk = polymod(chk) ^ (ch >> 5);
  }

  chk = polymod(chk);

  for (i = 0; i < hlen; i++)
    chk = polymod(chk) ^ (str.charCodeAt(i) & 0x1f);

  i++;

  while (i < str.length) {
    ch = str.charCodeAt(i);
    v = (ch & 0x80) ? -1 : TABLE[ch];

    if (ch >= 0x61 && ch <= 0x7a)
      lower = true;
    else if (ch >= 0x41 && ch <= 0x5a)
      upper = true;

    if (v === -1)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ v;

    if (i + 6 < str.length)
      data[i - (1 + hlen)] = v;

    i++;
  }

  if (lower && upper)
    throw new Error('Invalid bech32 casing.');

  if (chk !== 1)
    throw new Error('Invalid bech32 checksum.');

  return [hrp, data.slice(0, dlen)];
}

/**
 * Convert serialized data to bits,
 * suitable to be serialized as bech32.
 * @param {Buffer} data
 * @param {Buffer} output
 * @param {Number} frombits
 * @param {Number} tobits
 * @param {Number} pad
 * @param {Number} off
 * @returns {Buffer}
 */

function convert(data, output, frombits, tobits, pad, off) {
  let acc = 0;
  let bits = 0;
  let maxv = (1 << tobits) - 1;
  let j = 0;
  let i, value;

  if (pad !== -1)
    output[j++] = pad;

  for (i = off; i < data.length; i++) {
    value = data[i];

    if ((value >> frombits) !== 0)
      throw new Error('Invalid bech32 bits.');

    acc = (acc << frombits) | value;
    bits += frombits;

    while (bits >= tobits) {
      bits -= tobits;
      output[j++] = (acc >>> bits) & maxv;
    }
  }

  if (pad !== -1) {
    if (bits > 0)
      output[j++] = (acc << (tobits - bits)) & maxv;
  } else {
    if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
      throw new Error('Invalid bech32 bits.');
  }

  return output.slice(0, j);
}

/**
 * Serialize data to bech32 address.
 * @param {String} hrp
 * @param {Number} version
 * @param {Buffer} hash
 * @returns {String}
 */

function encode(hrp, version, hash) {
  let output = POOL65;
  let data;

  if (version < 0 || version > 16)
    throw new Error('Invalid bech32 version.');

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  data = convert(hash, output, 8, 5, version, 0);

  return serialize(hrp, data);
}

if (native)
  encode = native.toBech32;

/**
 * Deserialize data from bech32 address.
 * @param {String} str
 * @returns {Object}
 */

function decode(str) {
  let [hrp, data] = deserialize(str);
  let version, hash, output;

  if (data.length === 0 || data.length > 65)
    throw new Error('Invalid bech32 data length.');

  if (data[0] > 16)
    throw new Error('Invalid bech32 version.');

  version = data[0];
  output = data;
  hash = convert(data, output, 5, 8, -1, 1);

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  return new AddrResult(hrp, version, hash);
}

if (native)
  decode = native.fromBech32;

/**
 * AddrResult
 * @constructor
 * @private
 * @param {String} hrp
 * @param {Number} version
 * @param {Buffer} hash
 * @property {String} hrp
 * @property {Number} version
 * @property {Buffer} hash
 */

function AddrResult(hrp, version, hash) {
  this.hrp = hrp;
  this.version = version;
  this.hash = hash;
}

/*
 * Expose
 */

exports.deserialize = deserialize;
exports.serialize = serialize;
exports.convert = convert;
exports.encode = encode;
exports.decode = decode;
