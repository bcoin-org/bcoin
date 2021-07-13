/*!
 * arc4.js - ARC4 for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RC4
 *   http://cypherpunks.venona.com/archive/1994/09/msg00304.html
 *   https://web.archive.org/web/20080207125928/http://cypherpunks.venona.com/archive/1994/09/msg00304.html
 *   https://tools.ietf.org/html/rfc4345
 *   https://tools.ietf.org/html/rfc6229
 *   https://github.com/golang/go/blob/master/src/crypto/rc4/rc4.go
 */

'use strict';

const assert = require('../internal/assert');

/**
 * ARC4
 */

class ARC4 {
  constructor() {
    this.s = new Uint32Array(256);
    this.i = -1;
    this.j = -1;
  }

  init(key) {
    assert(Buffer.isBuffer(key));

    const k = key.length;

    if (k < 1 || k > 256)
      throw new Error('Invalid key size.');

    const s = this.s;

    for (let i = 0; i < 256; i++)
      s[i] = i;

    let j = 0;

    for (let i = 0; i < 256; i++) {
      j += s[i] + key[i % k];
      j &= 0xff;

      [s[i], s[j]] = [s[j], s[i]];
    }

    this.i = 0;
    this.j = 0;

    return this;
  }

  encrypt(data) {
    assert(Buffer.isBuffer(data));

    if (this.i === -1)
      throw new Error('Context is not initialized.');

    const s = this.s;

    let {i, j} = this;
    let x, y;

    for (let k = 0; k < data.length; k++) {
      i = (i + 1) & 0xff;
      x = s[i];

      j = (j + x) & 0xff;
      y = s[j];

      s[i] = y;
      s[j] = x;

      data[k] ^= s[(x + y) & 0xff];
    }

    this.i = i;
    this.j = j;

    return data;
  }

  destroy() {
    for (let i = 0; i < 256; i++)
      this.s[i] = 0;

    this.i = -1;
    this.j = -1;

    return this;
  }
}

/*
 * Static
 */

ARC4.native = 0;

/*
 * Expose
 */

module.exports = ARC4;
