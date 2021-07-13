/*!
 * cshake.js - cSHAKE implementation for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://keccak.team/specifications.html
 *   https://www.nist.gov/node/1131611
 *   https://doi.org/10.6028/NIST.SP.800-185
 *   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 *   https://github.com/XKCP/XKCP/blob/8f447eb/lib/high/Keccak/SP800-185/SP800-185.inc
 *   https://github.com/XKCP/XKCP/blob/8f447eb/lib/high/Keccak/SP800-185/SP800-185.c
 *   https://github.com/XKCP/XKCP/blob/8f447eb/tests/UnitTests/testSP800-185.c
 *   https://github.com/emn178/js-sha3/blob/master/src/sha3.js
 */

'use strict';

const assert = require('./internal/assert');
const Keccak = require('./keccak');
const HMAC = require('./internal/hmac');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const ZEROES = Buffer.alloc(200, 0x00);

/*
 * CSHAKE
 */

class CSHAKE extends Keccak {
  constructor() {
    super();
    this.pad = 0x04;
    this.rate = 1088;
  }

  init(bits, name, pers) {
    if (bits == null)
      bits = 256;

    if (name == null)
      name = EMPTY;

    if (pers == null)
      pers = EMPTY;

    assert((bits >>> 0) === bits);
    assert(bits === 128 || bits === 256);
    assert(Buffer.isBuffer(name));
    assert(Buffer.isBuffer(pers));

    super.init(bits);

    if (name.length === 0 && pers.length === 0) {
      this.pad = 0x1f;
    } else {
      const rate = 1600 - bits * 2;
      const size = rate / 8;

      this.bytePad([name, pers], size);
      this.rate = rate;
      this.pad = 0x04;
    }

    return this;
  }

  final(len) {
    return super.final(this.pad, len);
  }

  bytePad(items, w) {
    assert(Array.isArray(items));
    assert((w >>> 0) === w);
    assert(w > 0);

    let z = this.leftEncode(w);

    for (const x of items)
      z += this.encodeString(x);

    const left = w - (z % w);

    if (left === w)
      return z;

    z += this.zeroPad(left);

    return z;
  }

  encodeString(s) {
    assert(Buffer.isBuffer(s));

    const n = this.leftEncode(s.length * 8);

    this.update(s);

    return n + s.length;
  }

  zeroPad(size) {
    assert((size >>> 0) === size);
    assert(size <= 200);

    const buf = ZEROES.slice(0, size);

    this.update(buf);

    return buf.length;
  }

  leftEncode(x) {
    assert((x >>> 0) === x);
    assert(x >= 0 && x < 22040);

    let v = x;
    let n = 0;

    while (v && n < 4) {
      n += 1;
      v >>>= 8;
    }

    if (n === 0)
      n = 1;

    const buf = Buffer.alloc(n + 1);

    for (let i = 1; i <= n; i++)
      buf[i] = x >>> (8 * (n - i));

    buf[0] = n;

    this.update(buf);

    return buf.length;
  }

  rightEncode(x) {
    assert((x >>> 0) === x);
    assert(x >= 0 && x < 22040);

    let v = x;
    let n = 0;

    while (v && n < 4) {
      n += 1;
      v >>>= 8;
    }

    if (n === 0)
      n = 1;

    const buf = Buffer.alloc(n + 1);

    for (let i = 1; i <= n; i++)
      buf[i - 1] = x >>> (8 * (n - i));

    buf[n] = n;

    this.update(buf);

    return buf.length;
  }

  static hash() {
    return new CSHAKE();
  }

  static hmac(bits, name, pers, len) {
    if (bits == null)
      bits = 256;

    assert((bits >>> 0) === bits);
    assert(bits === 128 || bits === 256);

    const rate = 1600 - bits * 2;

    return new HMAC(CSHAKE, rate / 8, [bits, name, pers], [len]);
  }

  static digest(data, bits, name, pers, len) {
    return CSHAKE.ctx.init(bits, name, pers).update(data).final(len);
  }

  static root(left, right, bits, name, pers, len) {
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

    const {ctx} = CSHAKE;

    ctx.init(bits, name, pers);
    ctx.update(left);
    ctx.update(right);

    return ctx.final(len);
  }

  static multi(x, y, z, bits, name, pers, len) {
    const {ctx} = CSHAKE;

    ctx.init(bits, name, pers);
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final(len);
  }

  static mac(data, key, bits, name, pers, len) {
    return CSHAKE.hmac(bits, name, pers, len).init(key).update(data).final();
  }
}

/*
 * Static
 */

CSHAKE.native = Keccak.native;
CSHAKE.id = 'CSHAKE256';
CSHAKE.size = 32;
CSHAKE.bits = 256;
CSHAKE.blockSize = 136;
CSHAKE.zero = Buffer.alloc(32, 0x00);
CSHAKE.ctx = new CSHAKE();

/*
 * Expose
 */

module.exports = CSHAKE;
