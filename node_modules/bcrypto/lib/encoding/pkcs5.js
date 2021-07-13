/*!
 * pkcs5.js - PKCS5 padding for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/PKCS
 *   https://tools.ietf.org/html/rfc2898
 *   https://tools.ietf.org/html/rfc8018
 */

'use strict';

const assert = require('../internal/assert');

/*
 * PKCS5
 */

const pkcs5 = {
  pad(pt, size) {
    assert(Buffer.isBuffer(pt));
    assert((size >>> 0) === size);
    assert(size > 0 && size < 256);

    const left = size - (pt.length % size);
    const out = Buffer.alloc(pt.length + left);

    pt.copy(out, 0);

    for (let i = pt.length; i < out.length; i++)
      out[i] = left;

    return out;
  },

  unpad(pt, size) {
    assert(Buffer.isBuffer(pt));
    assert((size >>> 0) === size);
    assert(size > 0 && size < 256);

    if (pt.length < size || (pt.length % size) !== 0)
      throw new Error('Invalid block.');

    let left = pt[pt.length - 1];
    let res = 1;

    // left != 0
    res &= ((left - 1) >>> 31) ^ 1;

    // left <= size
    res &= (left - size - 1) >>> 31;

    // left = 0 if left == 0 or left > size
    left &= -res;

    // Verify padding in constant time.
    const end = size - left;

    for (let i = 0; i < size; i++) {
      const ch = pt[i];

      // i < end or ch == left
      res &= ((i - end) >>> 31) | (((ch ^ left) - 1) >>> 31);
    }

    if (!res)
      throw new Error('Invalid padding.');

    return pt.slice(0, end);
  }
};

/*
 * Expose
 */

module.exports = pkcs5;
