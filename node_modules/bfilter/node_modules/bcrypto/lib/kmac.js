/*!
 * kmac.js - KMAC implementation for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 *   https://github.com/XKCP/XKCP/blob/8f447eb/lib/high/Keccak/SP800-185/SP800-185.inc
 *   https://github.com/XKCP/XKCP/blob/8f447eb/lib/high/Keccak/SP800-185/SP800-185.c
 *   https://github.com/XKCP/XKCP/blob/8f447eb/tests/UnitTests/testSP800-185.c
 *   https://github.com/emn178/js-sha3/blob/master/src/sha3.js
 */

'use strict';

const assert = require('./internal/assert');
const CSHAKE = require('./cshake');
const HMAC = require('./internal/hmac');

/*
 * Constants
 */

const PREFIX = Buffer.from('KMAC', 'binary');
const EMPTY = Buffer.alloc(0);

/*
 * KMAC
 */

class KMAC extends CSHAKE {
  constructor() {
    super();
  }

  init(bits, key, pers) {
    if (key == null)
      key = EMPTY;

    assert(Buffer.isBuffer(key));

    super.init(bits, PREFIX, pers);
    super.bytePad([key], this.rate / 8);

    return this;
  }

  final(len) {
    if (len == null) {
      const size = this.rate / 8;
      len = 100 - size / 2;
    }

    super.rightEncode(len * 8);

    return super.final(len);
  }

  static hash() {
    return new KMAC();
  }

  static hmac(bits, key, pers, len) {
    if (bits == null)
      bits = 256;

    assert((bits >>> 0) === bits);
    assert(bits === 128 || bits === 256);

    const rate = 1600 - bits * 2;

    return new HMAC(KMAC, rate / 8, [bits, key, pers], [len]);
  }

  static digest(data, bits, key, pers, len) {
    return KMAC.ctx.init(bits, key, pers).update(data).final(len);
  }

  static root(left, right, bits, key, pers, len) {
    if (bits == null)
      bits = 256;

    if (len == null)
      len = 0;

    if (len === 0) {
      assert((bits >>> 0) === bits);
      len = bits >>> 3;
    }

    assert((len >>> 0) === len);
    assert(Buffer.isBuffer(left) && left.length === len);
    assert(Buffer.isBuffer(right) && right.length === len);

    const {ctx} = KMAC;

    ctx.init(bits, key, pers);
    ctx.update(left);
    ctx.update(right);

    return ctx.final(len);
  }

  static multi(x, y, z, bits, key, pers, len) {
    const {ctx} = KMAC;

    ctx.init(bits, key, pers);
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final(len);
  }

  static mac(data, salt, bits, key, pers, len) {
    return KMAC.hmac(bits, key, pers, len).init(salt).update(data).final();
  }
}

/*
 * Static
 */

KMAC.native = CSHAKE.native;
KMAC.id = 'KMAC256';
KMAC.size = 32;
KMAC.bits = 256;
KMAC.blockSize = 136;
KMAC.zero = Buffer.alloc(32, 0x00);
KMAC.ctx = new KMAC();

/*
 * Expose
 */

module.exports = KMAC;
