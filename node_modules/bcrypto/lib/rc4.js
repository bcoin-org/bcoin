/*!
 * rc4.js - RC4 for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   http://cypherpunks.venona.com/archive/1994/09/msg00304.html
 *   https://web.archive.org/web/20080207125928/http://cypherpunks.venona.com/archive/1994/09/msg00304.html
 *   https://tools.ietf.org/html/rfc4345
 *   https://tools.ietf.org/html/rfc6229
 *   https://github.com/golang/go/blob/master/src/crypto/rc4/rc4.go
 */

'use strict';

const assert = require('bsert');

/**
 * RC4
 */

class RC4 {
  constructor() {
    this.s = new Uint32Array(256);
    this.i = 0;
    this.j = 0;
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

    return this;
  }

  encrypt(data) {
    return this.crypt(data, data);
  }

  crypt(input, output) {
    assert(Buffer.isBuffer(input));
    assert(Buffer.isBuffer(output));

    if (output.length < input.length)
      throw new Error('Invalid output size.');

    const s = this.s;

    let {i, j} = this;
    let x, y;

    for (let k = 0; k < input.length; k++) {
      i += 1;
      i &= 0xff;
      x = s[i];

      j += x;
      j &= 0xff;
      y = s[j];

      s[i] = y;
      s[j] = x;

      output[k] = input[k] ^ s[(x + y) & 0xff];
    }

    this.i = i;
    this.j = j;

    return output;
  }

  destroy() {
    for (let i = 0; i < 256; i++)
      this.s[i] = 0;

    return this;
  }
}

RC4.native = 0;

/*
 * Expose
 */

module.exports = RC4;
