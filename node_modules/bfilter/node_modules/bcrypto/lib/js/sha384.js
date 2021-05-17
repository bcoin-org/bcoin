/*!
 * sha384.js - SHA384 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hash.js:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/hash.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 *   https://github.com/indutny/hash.js/blob/master/lib/hash/sha/384.js
 */

'use strict';

const assert = require('../internal/assert');
const SHA512 = require('./sha512');
const HMAC = require('../internal/hmac');

/**
 * SHA384
 */

class SHA384 extends SHA512 {
  constructor() {
    super();
  }

  init() {
    this.state[0] = 0xcbbb9d5d;
    this.state[1] = 0xc1059ed8;
    this.state[2] = 0x629a292a;
    this.state[3] = 0x367cd507;
    this.state[4] = 0x9159015a;
    this.state[5] = 0x3070dd17;
    this.state[6] = 0x152fecd8;
    this.state[7] = 0xf70e5939;
    this.state[8] = 0x67332667;
    this.state[9] = 0xffc00b31;
    this.state[10] = 0x8eb44a87;
    this.state[11] = 0x68581511;
    this.state[12] = 0xdb0c2e0d;
    this.state[13] = 0x64f98fa7;
    this.state[14] = 0x47b5481d;
    this.state[15] = 0xbefa4fa4;
    this.size = 0;
    return this;
  }

  final() {
    return super.final().slice(0, 48);
  }

  static hash() {
    return new SHA384();
  }

  static hmac() {
    return new HMAC(SHA384, 128);
  }

  static digest(data) {
    return SHA384.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 48);
    assert(Buffer.isBuffer(right) && right.length === 48);
    return SHA384.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = SHA384;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return SHA384.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

SHA384.native = 0;
SHA384.id = 'SHA384';
SHA384.size = 48;
SHA384.bits = 384;
SHA384.blockSize = 128;
SHA384.zero = Buffer.alloc(48, 0x00);
SHA384.ctx = new SHA384();

/*
 * Expose
 */

module.exports = SHA384;
