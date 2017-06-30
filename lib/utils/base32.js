/*!
 * base32.js - base32 for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module utils/base32
 */

const base32 = 'abcdefghijklmnopqrstuvwxyz234567';
const padding = [0, 6, 4, 3, 1];
const unbase32 = {};

for (let i = 0; i < base32.length; i++)
  unbase32[base32[i]] = i;

/**
 * Encode a base32 string.
 * @param {Buffer} data
 * @returns {String}
 */

exports.encode = function encode(data) {
  let str = '';
  let mode = 0;
  let left = 0;
  let i, ch;

  for (i = 0; i < data.length; i++) {
    ch = data[i];
    switch (mode) {
      case 0:
        str += base32[ch >>> 3];
        left = (ch & 7) << 2;
        mode = 1;
        break;
      case 1:
        str += base32[left | (ch >>> 6)];
        str += base32[(ch >>> 1) & 31];
        left = (ch & 1) << 4;
        mode = 2;
        break;
      case 2:
        str += base32[left | (ch >>> 4)];
        left = (ch & 15) << 1;
        mode = 3;
        break;
      case 3:
        str += base32[left | (ch >>> 7)];
        str += base32[(ch >>> 2) & 31];
        left = (ch & 3) << 3;
        mode = 4;
        break;
      case 4:
        str += base32[left | (ch >>> 5)];
        str += base32[ch & 31];
        mode = 0;
        break;
    }
  }

  if (mode > 0) {
    str += base32[left];
    for (i = 0; i < padding[mode]; i++)
      str += '=';
  }

  return str;
};

/**
 * Decode a base32 string.
 * @param {String} str
 * @returns {Buffer}
 */

exports.decode = function decode(str) {
  let data = Buffer.allocUnsafe(str.length * 5 / 8 | 0);
  let mode = 0;
  let left = 0;
  let j = 0;
  let i, ch;

  for (i = 0; i < str.length; i++) {
    ch = unbase32[str[i]];

    if (ch == null)
      break;

    switch (mode) {
      case 0:
        left = ch;
        mode = 1;
        break;
      case 1:
        data[j++] = (left << 3) | (ch >>> 2);
        left = ch & 3;
        mode = 2;
        break;
      case 2:
        left = left << 5 | ch;
        mode = 3;
        break;
      case 3:
        data[j++] = (left << 1) | (ch >>> 4);
        left = ch & 15;
        mode = 4;
        break;
      case 4:
        data[j++] = (left << 4) | (ch >>> 1);
        left = ch & 1;
        mode = 5;
        break;
      case 5:
        left = left << 5 | ch;
        mode = 6;
        break;
      case 6:
        data[j++] = (left << 2) | (ch >>> 3);
        left = ch & 7;
        mode = 7;
        break;
      case 7:
        data[j++] = (left << 5) | ch;
        mode = 0;
        break;
    }
  }

  switch (mode) {
    case 0:
      break;
    case 1:
    case 3:
    case 6:
      throw new Error('Invalid base32 string.');
    case 2:
      if (left > 0)
        throw new Error('Invalid padding.');

      if (str.slice(i, i + 6) !== '======')
        throw new Error('Invalid base32 character.');

      if (unbase32[str[i + 6]] != null)
        throw new Error('Invalid padding.');

      break;
    case 4:
      if (left > 0)
        throw new Error('Invalid padding.');

      if (str.slice(i, i + 4) !== '====')
        throw new Error('Invalid base32 character.');

      if (unbase32[str[i + 4]] != null)
        throw new Error('Invalid padding.');

      break;
    case 5:
      if (left > 0)
        throw new Error('Invalid padding.');

      if (str.slice(i, i + 3) !== '===')
        throw new Error('Invalid base32 character.');

      if (unbase32[str[i + 3]] != null)
        throw new Error('Invalid padding.');

      break;
    case 7:
      if (left > 0)
        throw new Error('Invalid padding.');

      if (str[i] !== '=')
        throw new Error('Invalid base32 character.');

      if (unbase32[str[i + 1]] != null)
        throw new Error('Invalid padding.');

      break;
  }

  return data.slice(0, j);
};
