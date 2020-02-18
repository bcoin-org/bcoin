/*!
 * rsakey.js - RSA keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7517
 *   https://tools.ietf.org/html/rfc7518
 */

'use strict';

const assert = require('bsert');
const base64 = require('../internal/base64');
const {countBits, trimZeroes} = require('./util');
const {custom} = require('./custom');

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const DEFAULT_EXP = 65537;
const MIN_BITS = 512;
const MAX_BITS = 16384;
const MIN_EXP = 3;
const MAX_EXP = (2 ** 33) - 1;
const MIN_EXP_BITS = 2;
const MAX_EXP_BITS = 33;
const ZERO = Buffer.alloc(1, 0x00);

/**
 * RSAKey
 */

class RSAKey {
  constructor() {
    this.n = ZERO; // modulus
    this.e = ZERO; // public exponent
  }

  setN(n) {
    this.n = trimZeroes(n);
    return this;
  }

  setE(e) {
    if (typeof e === 'number')
      e = toU64(e);

    this.e = trimZeroes(e);

    return this;
  }

  bits() {
    return countBits(this.n);
  }

  size() {
    return (this.bits() + 7) >>> 3;
  }

  pad(sig) {
    assert(Buffer.isBuffer(sig));

    const bits = this.bits();

    if (bits < MIN_BITS || bits > MAX_BITS)
      return sig;

    const size = (bits + 7) >>> 3;

    if (sig.length >= size)
      return sig;

    const out = Buffer.allocUnsafe(size);
    const pos = size - sig.length;

    out.fill(0x00, 0, pos);
    sig.copy(out, pos);

    return out;
  }

  toPublic() {
    return this;
  }

  toJSON() {
    return {
      kty: 'RSA',
      n: base64.encodeURL(this.n),
      e: base64.encodeURL(this.e),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'RSA');

    this.n = base64.decodeURL(json.n);
    this.e = base64.decodeURL(json.e);

    return this;
  }

  [custom]() {
    return this.format();
  }

  format() {
    return {
      bits: this.bits(),
      n: this.n.toString('hex'),
      e: this.e.toString('hex')
    };
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * RSAPublicKey
 */

class RSAPublicKey extends RSAKey {
  constructor(n, e) {
    super();
    this.n = trimZeroes(n); // modulus
    this.e = trimZeroes(e); // public exponent
  }
}

/**
 * RSAPrivateKey
 */

class RSAPrivateKey extends RSAKey {
  constructor(n, e, d, p, q, dp, dq, qi) {
    super();
    this.n = trimZeroes(n); // modulus
    this.e = trimZeroes(e); // public exponent
    this.d = trimZeroes(d); // private exponent
    this.p = trimZeroes(p); // prime1
    this.q = trimZeroes(q); // prime2
    this.dp = trimZeroes(dp); // exponent1
    this.dq = trimZeroes(dq); // exponent2
    this.qi = trimZeroes(qi); // coefficient
  }

  setD(d) {
    this.d = trimZeroes(d);
    return this;
  }

  setP(p) {
    this.p = trimZeroes(p);
    return this;
  }

  setQ(q) {
    this.q = trimZeroes(q);
    return this;
  }

  setDP(dp) {
    this.dp = trimZeroes(dp);
    return this;
  }

  setDQ(dq) {
    this.dq = trimZeroes(dq);
    return this;
  }

  setQI(qi) {
    this.qi = trimZeroes(qi);
    return this;
  }

  toPublic() {
    const key = new RSAPublicKey();
    key.n = this.n;
    key.e = this.e;
    return key;
  }

  toJSON() {
    return {
      kty: 'RSA',
      n: base64.encodeURL(this.n),
      e: base64.encodeURL(this.e),
      d: base64.encodeURL(this.d),
      p: base64.encodeURL(this.p),
      q: base64.encodeURL(this.q),
      dp: base64.encodeURL(this.dp),
      dq: base64.encodeURL(this.dq),
      qi: base64.encodeURL(this.qi),
      ext: true
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(json.kty === 'RSA');

    if (json.n != null)
      this.n = base64.decodeURL(json.n);

    if (json.e != null)
      this.e = base64.decodeURL(json.e);

    if (json.d != null)
      this.d = base64.decodeURL(json.d);

    if (json.p != null)
      this.p = base64.decodeURL(json.p);

    if (json.q != null)
      this.q = base64.decodeURL(json.q);

    if (json.dp != null)
      this.dp = base64.decodeURL(json.dp);

    if (json.dq != null)
      this.dq = base64.decodeURL(json.dq);

    if (json.qi != null)
      this.qi = base64.decodeURL(json.qi);

    return this;
  }

  format() {
    return {
      bits: this.bits(),
      n: this.n.toString('hex'),
      e: this.e.toString('hex'),
      d: this.d.toString('hex'),
      p: this.p.toString('hex'),
      q: this.q.toString('hex'),
      dp: this.dp.toString('hex'),
      dq: this.dq.toString('hex'),
      qi: this.qi.toString('hex')
    };
  }
}

/*
 * Helpers
 */

function toU64(n) {
  assert(Number.isSafeInteger(n) && n >= 0);

  const hi = (n * (1 / 0x100000000)) >>> 0;
  const lo = n >>> 0;

  const b = Buffer.allocUnsafe(8);
  b[0] = 0;
  b[1] = 0;
  b[2] = hi >>> 8;
  b[3] = hi;
  b[4] = lo >>> 24;
  b[5] = lo >>> 16;
  b[6] = lo >>> 8;
  b[7] = lo;

  return b;
}

/*
 * Expose
 */

exports.DEFAULT_BITS = DEFAULT_BITS;
exports.DEFAULT_EXP = DEFAULT_EXP;
exports.MIN_BITS = MIN_BITS;
exports.MAX_BITS = MAX_BITS;
exports.MIN_EXP = MIN_EXP;
exports.MAX_EXP = MAX_EXP;
exports.MIN_EXP_BITS = MIN_EXP_BITS;
exports.MAX_EXP_BITS = MAX_EXP_BITS;

exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
