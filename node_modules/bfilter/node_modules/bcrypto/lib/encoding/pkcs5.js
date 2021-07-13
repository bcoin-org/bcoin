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
    const out = Buffer.allocUnsafe(pt.length + left);
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
      throw new Error('Invalid padding.');

    const left = pt[pt.length - 1];

    if (left === 0 || left > size)
      throw new Error('Invalid padding.');

    for (let i = pt.length - left; i < pt.length; i++) {
      if (pt[i] !== left)
        throw new Error('Invalid padding.');
    }

    return pt.slice(0, -left);
  }
};

/*
 * Expose
 */

module.exports = pkcs5;
