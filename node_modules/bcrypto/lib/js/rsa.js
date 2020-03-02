/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on indutny/miller-rabin:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/miller-rabin
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RSA_(cryptosystem)
 *   https://tools.ietf.org/html/rfc3447
 *   https://tools.ietf.org/html/rfc8017
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_ossl.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_sign.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_oaep.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pss.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pk1.c
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/pkcs1v15.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/pss.go
 *   https://github.com/golang/go/blob/master/src/crypto/subtle/constant_time.go
 *   https://github.com/ARMmbed/mbed-crypto/blob/master/library/rsa.c
 *
 * References:
 *
 *   [RFC8017] PKCS #1: RSA Cryptography Specifications Version 2.2
 *     K. Moriarty, B. Kaliski, J. Jonsson, A. Rusch
 *     https://tools.ietf.org/html/rfc8017
 *
 *   [FIPS186] Federal Information Processing Standards Publication 186-4
 *     National Institute of Standards and Technology
 *     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 */

'use strict';

const assert = require('../internal/assert');
const BN = require('../bn');
const rng = require('../random');
const {randomPrime} = require('../internal/primes');
const base64 = require('../encoding/base64');
const asn1 = require('../internal/asn1');
const safe = require('../safe');

const {
  safeEqual,
  safeEqualByte,
  safeSelect,
  safeLTE
} = safe;

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const DEFAULT_EXP = 65537;
const MIN_BITS = 512;
const MAX_BITS = 16384;
const MIN_EXP = 3;
const MAX_EXP = (2 ** 33) - 1;
const MAX_EXP_BITS = 33;
const SALT_LENGTH_AUTO = 0;
const SALT_LENGTH_HASH = -1;
const PREFIX = Buffer.alloc(8, 0x00);
const EMPTY = Buffer.alloc(0);

/**
 * PKCS1v1.5+ASN.1 DigestInfo prefixes.
 * @see [RFC8017] Page 45, Section 9.2.
 * @see [RFC8017] Page 63, Section B.1.
 * @const {Object}
 */

const digestInfo = {
  __proto__: null,
  BLAKE2B160: Buffer.from('3027300f060b2b060104018d3a0c02010505000414', 'hex'),
  BLAKE2B256: Buffer.from('3033300f060b2b060104018d3a0c02010805000420', 'hex'),
  BLAKE2B384: Buffer.from('3043300f060b2b060104018d3a0c02010c05000430', 'hex'),
  BLAKE2B512: Buffer.from('3053300f060b2b060104018d3a0c02011005000440', 'hex'),
  BLAKE2S128: Buffer.from('3023300f060b2b060104018d3a0c02020405000410', 'hex'),
  BLAKE2S160: Buffer.from('3027300f060b2b060104018d3a0c02020505000414', 'hex'),
  BLAKE2S224: Buffer.from('302f300f060b2b060104018d3a0c0202070500041c', 'hex'),
  BLAKE2S256: Buffer.from('3033300f060b2b060104018d3a0c02020805000420', 'hex'),
  GOST94: Buffer.from('302e300a06062a850302021405000420', 'hex'),
  HASH160: Buffer.from([20]),
  HASH256: Buffer.from([32]),
  KECCAK224: Buffer.from([28]),
  KECCAK256: Buffer.from([32]),
  KECCAK384: Buffer.from([48]),
  KECCAK512: Buffer.from([64]),
  MD2: Buffer.from('3020300c06082a864886f70d020205000410', 'hex'),
  MD4: Buffer.from('3020300c06082a864886f70d020405000410', 'hex'),
  MD5: Buffer.from('3020300c06082a864886f70d020505000410', 'hex'),
  MD5SHA1: Buffer.from([36]),
  RIPEMD160: Buffer.from('3022300a060628cf0603003105000414', 'hex'),
  SHA1: Buffer.from('3021300906052b0e03021a05000414', 'hex'),
  SHA224: Buffer.from('302d300d06096086480165030402040500041c', 'hex'),
  SHA256: Buffer.from('3031300d060960864801650304020105000420', 'hex'),
  SHA384: Buffer.from('3041300d060960864801650304020205000430', 'hex'),
  SHA512: Buffer.from('3051300d060960864801650304020305000440', 'hex'),
  SHA3_224: Buffer.from('302d300d06096086480165030402070500041c', 'hex'),
  SHA3_256: Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  SHA3_384: Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  SHA3_512: Buffer.from('3051300d060960864801650304020a05000440', 'hex'),
  SHAKE128: Buffer.from('3021300d060960864801650304020b05000410', 'hex'),
  SHAKE256: Buffer.from('3031300d060960864801650304020c05000420', 'hex'),
  WHIRLPOOL: Buffer.from('304e300a060628cf0603003705000440', 'hex')
};

/**
 * RSAPublicKey
 */

class RSAPublicKey {
  constructor() {
    this.n = new BN(0);
    this.e = new BN(0);
  }

  bits() {
    return this.n.bitLength();
  }

  size() {
    return this.n.byteLength();
  }

  isSane() {
    return this.n.sign() > 0
        && this.e.sign() > 0
        && this.n.bitLength() <= MAX_BITS
        && this.e.bitLength() <= MAX_EXP_BITS;
  }

  verify() {
    // Sanity checks.
    if (!this.isSane())
      return false;

    // n >= 2^511 and n mod 2 != 0
    if (this.n.bitLength() < MIN_BITS || !this.n.isOdd())
      return false;

    // e >= 3 and e mod 2 != 0
    if (this.e.cmpn(MIN_EXP) < 0 || !this.e.isOdd())
      return false;

    return true;
  }

  encrypt(msg) {
    // [RFC8017] Page 13, Section 5.1.1.
    //           Page 16, Section 5.2.2.
    assert(Buffer.isBuffer(msg));

    const {n, e} = this;
    const m = BN.decode(msg);

    if (m.cmp(n) >= 0)
      throw new Error('Invalid RSA message size.');

    // c = m^e mod n
    const c = m.powm(e, n);

    return c.encode('be', n.byteLength());
  }

  encode() {
    const size = asn1.sizeInt(this.n) + asn1.sizeInt(this.e);
    const out = Buffer.alloc(asn1.sizeSeq(size));

    let pos = 0;

    pos = asn1.writeSeq(out, pos, size);
    pos = asn1.writeInt(out, pos, this.n);
    pos = asn1.writeInt(out, pos, this.e);

    assert(pos === out.length);

    return out;
  }

  decode(data) {
    let pos = 0;

    pos = asn1.readSeq(data, pos);

    [this.n, pos] = asn1.readInt(data, pos);
    [this.e, pos] = asn1.readInt(data, pos);

    if (pos !== data.length)
      throw new Error('Trailing bytes.');

    return this;
  }

  static decode(data) {
    return new RSAPublicKey().decode(data);
  }
}

/**
 * RSAPrivateKey
 */

class RSAPrivateKey extends RSAPublicKey {
  constructor() {
    super();
    this.d = new BN(0);
    this.p = new BN(0);
    this.q = new BN(0);
    this.dp = new BN(0);
    this.dq = new BN(0);
    this.qi = new BN(0);
  }

  isSane() {
    return this.n.sign() > 0
        && this.e.sign() > 0
        && this.d.sign() > 0
        && this.p.sign() > 0
        && this.q.sign() > 0
        && this.dp.sign() > 0
        && this.dq.sign() > 0
        && this.qi.sign() > 0
        && this.n.bitLength() <= MAX_BITS
        && this.e.bitLength() <= MAX_EXP_BITS
        && this.d.bitLength() <= MAX_BITS
        && this.p.bitLength() <= MAX_BITS
        && this.q.bitLength() <= MAX_BITS
        && this.dp.bitLength() <= MAX_BITS
        && this.dq.bitLength() <= MAX_BITS
        && this.qi.bitLength() <= MAX_BITS;
  }

  verify() {
    // Sanity checks.
    if (!this.isSane())
      return false;

    // n >= 2^511 and n mod 2 != 0
    if (this.n.bitLength() < MIN_BITS || !this.n.isOdd())
      return false;

    // e >= 3 and e mod 2 != 0
    if (this.e.cmpn(MIN_EXP) < 0 || !this.e.isOdd())
      return false;

    // p >= 3 and p mod 2 != 0
    if (this.p.cmpn(3) < 0 || !this.p.isOdd())
      return false;

    // q >= 3 and q mod 2 != 0
    if (this.q.cmpn(3) < 0 || !this.q.isOdd())
      return false;

    // phi = (p - 1) * (q - 1)
    const pm1 = this.p.subn(1);
    const qm1 = this.q.subn(1);
    const phi = pm1.mul(qm1);

    // d >= 2 and d < phi
    if (this.d.cmpn(2) < 0 || this.d.cmp(phi) >= 0)
      return false;

    // dp != 0 and dp < p - 1
    if (this.dp.sign() === 0 || this.dp.cmp(pm1) >= 0)
      return false;

    // dq != 0 and dq < q - 1
    if (this.dq.sign() === 0 || this.dq.cmp(qm1) >= 0)
      return false;

    // qi <= 2 and qi < p
    if (this.qi.cmpn(2) < 0 || this.qi.cmp(this.p) >= 0)
      return false;

    // p != q
    if (this.p.cmp(this.q) === 0)
      return false;

    // n == p * q
    if (this.p.mul(this.q).cmp(this.n) !== 0)
      return false;

    // lam = lcm(p - 1, q - 1)
    const lam = phi.div(pm1.gcd(qm1));

    // e * d mod lam
    if (this.e.mul(this.d).imod(lam).cmpn(1) !== 0)
      return false;

    // dp == d mod (p - 1)
    if (this.d.mod(pm1).cmp(this.dp) !== 0)
      return false;

    // dq == d mod (q - 1)
    if (this.d.mod(qm1).cmp(this.dq) !== 0)
      return false;

    // q * qi mod p == 1
    if (this.q.mul(this.qi).imod(this.p).cmpn(1) !== 0)
      return false;

    return true;
  }

  decrypt(msg) {
    // [RFC8017] Page 13, Section 5.1.2.
    //           Page 15, Section 5.2.1.
    assert(Buffer.isBuffer(msg));

    const {n, e, p, q, dp, dq, qi} = this;

    // Decode message.
    const c = BN.decode(msg);

    // Validate params.
    if (c.cmp(n) >= 0)
      throw new Error('Invalid RSA message size.');

    // Generate blinding factor.
    let b, bi;
    for (;;) {
      // s = random integer in [1,n-1]
      const s = BN.random(rng, 1, n);

      // bi = s^-1 mod n
      try {
        bi = s.invert(n);
      } catch (e) {
        continue;
      }

      // b = s^e mod n
      b = s.powm(e, n);

      break;
    }

    // Blind.
    c.imul(b).imod(n);

    // Leverage Chinese Remainder Theorem.
    //
    // Computation:
    //
    //   mp = c^(d mod p-1) mod p
    //   mq = c^(d mod q-1) mod q
    //   md = (mp - mq) / q mod p
    //   m = (md * q + mq) mod n
    const mp = c.powm(dp, p, true);
    const mq = c.powm(dq, q, true);
    const md = mp.sub(mq).mul(qi).imod(p);
    const m = md.mul(q).iadd(mq).imod(n);

    if (m.powm(e, n).cmp(c) !== 0)
      throw new Error('Invalid RSA private key.');

    // Unblind.
    m.imul(bi).imod(n);

    return m.encode('be', n.byteLength());
  }

  generate(bits, exponent) {
    // [RFC8017] Page 9, Section 3.2.
    // [FIPS186] Page 51, Appendix B.3.1
    //           Page 55, Appendix B.3.3
    //
    // There are two methods for choosing `d`.
    // Implementations differ on whether they
    // use Euler's totient or the Carmichael
    // function.
    //
    // The best explanation of Euler's phi vs.
    // Carmichael's lambda I've seen comes from
    // the crypto stackexchange[1].
    //
    // Note that both functions are _equivalent_
    // when used with RSA, however, Carmichael's
    // may lend itself to some perf benefits.
    //
    // [1] https://crypto.stackexchange.com/a/29595
    assert((bits >>> 0) === bits);
    assert(Number.isSafeInteger(exponent) && exponent >= 0);
    assert(bits >= 64);
    assert(exponent >= 3 && (exponent & 1) !== 0);

    const e = new BN(exponent);

    for (;;) {
      const p = randomPrime((bits >>> 1) + (bits & 1));
      const q = randomPrime(bits >>> 1);

      if (p.cmp(q) === 0)
        continue;

      if (p.cmp(q) < 0)
        p.swap(q);

      if (p.sub(q).bitLength() <= (bits >>> 1) - 99)
        continue;

      const n = p.mul(q);

      if (n.bitLength() !== bits)
        continue;

      // Euler's totient: (p - 1) * (q - 1).
      const pm1 = p.subn(1);
      const qm1 = q.subn(1);
      const phi = pm1.mul(qm1);

      if (e.gcd(phi).cmpn(1) !== 0)
        continue;

      // Carmichael's function: lcm(p - 1, q - 1).
      const lam = phi.div(pm1.gcd(qm1));
      const d = e.invert(lam);

      if (d.bitLength() <= ((bits + 1) >>> 1))
        continue;

      const dp = d.mod(pm1);
      const dq = d.mod(qm1);
      const qi = q.invert(p);

      this.n = n;
      this.e = e;
      this.d = d;
      this.p = p;
      this.q = q;
      this.dp = dp;
      this.dq = dq;
      this.qi = qi;

      return this;
    }
  }

  async _generateSubtle(bits, exponent) {
    assert((bits >>> 0) === bits);
    assert(Number.isSafeInteger(exponent) && exponent >= 0);
    assert(bits >= 64);
    assert(exponent >= 3 && (exponent & 1) !== 0);

    const crypto = global.crypto || global.msCrypto;

    if (!crypto)
      throw new Error('Crypto API not available.');

    const {subtle} = crypto;

    if (!subtle || !subtle.generateKey || !subtle.exportKey)
      throw new Error('Subtle API not available.');

    const e = new BN(exponent);

    const algo = {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array(e.toArray('be', 8)),
      hash: { name: 'SHA-256' }
    };

    const ck = await subtle.generateKey(algo, true, ['sign']);
    const jwk = await subtle.exportKey('jwk', ck.privateKey);
    const p = BN.decode(base64.decodeURL(jwk.p));
    const q = BN.decode(base64.decodeURL(jwk.q));

    return this.fromPQE(p, q, e);
  }

  async generateAsync(bits, exponent) {
    try {
      return await this._generateSubtle(bits, exponent);
    } catch (e) {
      return this.generate(bits, exponent);
    }
  }

  fromPQE(p, q, e) {
    assert(p instanceof BN);
    assert(q instanceof BN);
    assert(e instanceof BN);

    if (p.cmp(q) < 0)
      [p, q] = [q, p];

    if (p.cmp(q) === 0)
      throw new Error('Invalid RSA private key.');

    if (p.cmpn(3) < 0 || p.bitLength() > MAX_BITS)
      throw new Error('Invalid RSA private key.');

    if (q.cmpn(3) < 0 || q.bitLength() > MAX_BITS)
      throw new Error('Invalid RSA private key.');

    if (e.cmpn(MIN_EXP) < 0 || e.bitLength() > MAX_EXP_BITS)
      throw new Error('Invalid RSA private key.');

    if (!p.isOdd() || !q.isOdd() || !e.isOdd())
      throw new Error('Invalid RSA private key.');

    const n = p.mul(q);

    assert(n.isOdd());

    if (n.bitLength() < MIN_BITS || n.bitLength() > MAX_BITS)
      throw new Error('Invalid RSA private key.');

    const pm1 = p.subn(1);
    const qm1 = q.subn(1);
    const lam = pm1.lcm(qm1);
    const d = e.invert(lam);
    const dp = d.mod(pm1);
    const dq = d.mod(qm1);
    const qi = q.invert(p);

    this.n = n;
    this.e = e;
    this.d = d;
    this.p = p;
    this.q = q;
    this.dp = dp;
    this.dq = dq;
    this.qi = qi;

    return this;
  }

  fromPQD(p, q, d) {
    assert(p instanceof BN);
    assert(q instanceof BN);
    assert(d instanceof BN);

    if (p.cmpn(3) < 0 || p.bitLength() > MAX_BITS)
      throw new Error('Invalid RSA private key.');

    if (q.cmpn(3) < 0 || q.bitLength() > MAX_BITS)
      throw new Error('Invalid RSA private key.');

    if (!p.isOdd() || !q.isOdd())
      throw new Error('Invalid RSA private key.');

    const pm1 = p.subn(1);
    const qm1 = q.subn(1);
    const phi = pm1.mul(qm1);

    if (d.cmpn(2) < 0 || d.cmp(phi) >= 0)
      throw new Error('Invalid RSA private key.');

    const lam = phi.div(pm1.gcd(qm1));
    const e = d.invert(lam);

    return this.fromPQE(p, q, e);
  }

  fromNED(n, e, d) {
    // Factor an RSA modulus given (n, e, d).
    //
    // This is basically the same logic as the
    // Miller-Rabin primality test[1][2].
    //
    // [1] https://crypto.stackexchange.com/questions/11509
    // [2] https://crypto.stackexchange.com/questions/22374
    assert(n instanceof BN);
    assert(e instanceof BN);
    assert(d instanceof BN);

    if (n.sign() < 0)
      throw new Error('Invalid RSA private key.');

    if (n.bitLength() < MIN_BITS || n.bitLength() > MAX_BITS)
      throw new Error('Invalid RSA private key.');

    if (e.cmpn(MIN_EXP) < 0 || e.bitLength() > MAX_EXP_BITS)
      throw new Error('Invalid RSA private key.');

    if (d.cmpn(2) < 0 || d.bitLength() > MAX_BITS)
      throw new Error('Invalid RSA private key.');

    if (!n.isOdd() || !e.isOdd())
      throw new Error('Invalid RSA private key.');

    const f = e.mul(d).isubn(1);
    const nm1 = n.subn(1);
    const s = f.zeroBits();
    const g = f.ushrn(s);

    for (let i = 0; i < 64; i++) {
      const a = BN.random(rng, 2, nm1);

      let b = a.powm(g, n);

      if (b.cmpn(1) === 0 || b.cmp(nm1) === 0)
        continue;

      for (let j = 1; j < s; j++) {
        const c = b.sqr().imod(n);

        if (c.cmpn(1) === 0) {
          const p = n.gcd(b.subn(1));
          const q = n.gcd(b.addn(1));

          return this.fromPQE(p, q, e);
        }

        if (c.cmp(nm1) === 0)
          break;

        b = c;
      }
    }

    throw new Error('Invalid RSA private key.');
  }

  toPublic() {
    const pub = new RSAPublicKey();

    pub.n = this.n;
    pub.e = this.e;

    return pub;
  }

  encode() {
    let size = 0;

    size += asn1.sizeVersion(0);
    size += asn1.sizeInt(this.n);
    size += asn1.sizeInt(this.e);
    size += asn1.sizeInt(this.d);
    size += asn1.sizeInt(this.p);
    size += asn1.sizeInt(this.q);
    size += asn1.sizeInt(this.dp);
    size += asn1.sizeInt(this.dq);
    size += asn1.sizeInt(this.qi);

    const out = Buffer.alloc(asn1.sizeSeq(size));

    let pos = 0;

    pos = asn1.writeSeq(out, pos, size);
    pos = asn1.writeVersion(out, pos, 0);
    pos = asn1.writeInt(out, pos, this.n);
    pos = asn1.writeInt(out, pos, this.e);
    pos = asn1.writeInt(out, pos, this.d);
    pos = asn1.writeInt(out, pos, this.p);
    pos = asn1.writeInt(out, pos, this.q);
    pos = asn1.writeInt(out, pos, this.dp);
    pos = asn1.writeInt(out, pos, this.dq);
    pos = asn1.writeInt(out, pos, this.qi);

    assert(pos === out.length);

    return out;
  }

  decode(data) {
    let pos = 0;

    pos = asn1.readSeq(data, pos);
    pos = asn1.readVersion(data, pos, 0);

    [this.n, pos] = asn1.readInt(data, pos);
    [this.e, pos] = asn1.readInt(data, pos);
    [this.d, pos] = asn1.readInt(data, pos);
    [this.p, pos] = asn1.readInt(data, pos);
    [this.q, pos] = asn1.readInt(data, pos);
    [this.dp, pos] = asn1.readInt(data, pos);
    [this.dq, pos] = asn1.readInt(data, pos);
    [this.qi, pos] = asn1.readInt(data, pos);

    if (pos !== data.length)
      throw new Error('Trailing bytes.');

    return this;
  }

  static generate(bits, exponent) {
    return new RSAPrivateKey().generate(bits, exponent);
  }

  static async generateAsync(bits, exponent) {
    return new RSAPrivateKey().generateAsync(bits, exponent);
  }

  static fromPQE(p, q, e) {
    return new RSAPrivateKey().fromPQE(p, q, e);
  }

  static fromPQD(p, q, d) {
    return new RSAPrivateKey().fromPQD(p, q, d);
  }

  static fromNED(n, e, d) {
    return new RSAPrivateKey().fromNED(n, e, d);
  }

  static decode(data) {
    return new RSAPrivateKey().decode(data);
  }
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

function privateKeyGenerate(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  const key = RSAPrivateKey.generate(bits, exponent);

  return key.encode();
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

async function privateKeyGenerateAsync(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  const key = await RSAPrivateKey.generateAsync(bits, exponent);

  return key.encode();
}

/**
 * Get a private key's modulus size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function privateKeyBits(key) {
  const k = RSAPrivateKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA private key.');

  return k.bits();
}

/**
 * Verify a private key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = RSAPrivateKey.decode(key);
  } catch (e) {
    return false;
  }

  return k.verify();
}

/**
 * Import a private key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function privateKeyImport(json) {
  // [RFC8017] Page 55, Section A.1.2.
  assert(json && typeof json === 'object');

  let k = new RSAPrivateKey();

  if (json.n != null)
    k.n = BN.decode(json.n);

  if (json.e != null)
    k.e = BN.decode(json.e);

  if (json.d != null)
    k.d = BN.decode(json.d);

  if (json.p != null)
    k.p = BN.decode(json.p);

  if (json.q != null)
    k.q = BN.decode(json.q);

  if (json.dp != null)
    k.dp = BN.decode(json.dp);

  if (json.dq != null)
    k.dq = BN.decode(json.dq);

  if (json.qi != null)
    k.qi = BN.decode(json.qi);

  if (!k.verify()) {
    if (!k.p.isZero() && !k.q.isZero()) {
      if (!k.e.isZero())
        k = RSAPrivateKey.fromPQE(k.p, k.q, k.e);
      else
        k = RSAPrivateKey.fromPQD(k.p, k.q, k.d);
    } else {
      k = RSAPrivateKey.fromNED(k.n, k.e, k.d);
    }
  }

  return k.encode();
}

/**
 * Export a private key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function privateKeyExport(key) {
  // [RFC8017] Page 55, Section A.1.2.
  const k = RSAPrivateKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA private key.');

  return {
    n: k.n.encode(),
    e: k.e.encode(),
    d: k.d.encode(),
    p: k.p.encode(),
    q: k.q.encode(),
    dp: k.dp.encode(),
    dq: k.dq.encode(),
    qi: k.qi.encode()
  };
}

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyCreate(key) {
  const k = RSAPrivateKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA private key.');

  const p = k.toPublic();

  return p.encode();
}

/**
 * Get a public key's modulus size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function publicKeyBits(key) {
  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA public key.');

  return k.bits();
}

/**
 * Verify a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  // [RFC8017] Page 8, Section 3.1.
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = RSAPublicKey.decode(key);
  } catch (e) {
    return false;
  }

  return k.verify();
}

/**
 * Import a public key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function publicKeyImport(json) {
  // [RFC8017] Page 54, Section A.1.1.
  assert(json && typeof json === 'object');

  const k = new RSAPublicKey();

  if (json.n != null)
    k.n = BN.decode(json.n);

  if (json.e != null)
    k.e = BN.decode(json.e);

  if (!k.verify())
    throw new Error('Invalid RSA public key.');

  return k.encode();
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  // [RFC8017] Page 54, Section A.1.1.
  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA public key.');

  return {
    n: k.n.encode(),
    e: k.e.encode()
  };
}

/**
 * Sign a message (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

function sign(hash, msg, key) {
  // [RFC8017] Page 36, Section 8.2.1.
  //           Page 45, Section 9.2.
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(hash == null || typeof hash === 'string');
  assert(Buffer.isBuffer(msg));

  const [prefix, hlen] = getDigestInfo(hash, msg);

  if (!prefix)
    throw new Error('Unknown RSA hash function.');

  if (msg.length !== hlen)
    throw new Error('Invalid RSA message size.');

  const k = RSAPrivateKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA private key.');

  const tlen = prefix.length + hlen;
  const klen = k.size();

  if (klen < tlen + 11)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || 0x01 || PS || 0x00 || T
  const em = Buffer.allocUnsafe(klen);

  em[0] = 0x00;
  em[1] = 0x01;

  for (let i = 2; i < klen - tlen - 1; i++)
    em[i] = 0xff;

  em[klen - tlen - 1] = 0x00;

  prefix.copy(em, klen - tlen);
  msg.copy(em, klen - hlen);

  return k.decrypt(em);
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(hash, msg, sig, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(hash == null || typeof hash === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  try {
    return _verify(hash, msg, sig, key);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (PKCS1v1.5).
 * @private
 * @param {String} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function _verify(hash, msg, sig, key) {
  // [RFC8017] Page 37, Section 8.2.2.
  //           Page 45, Section 9.2.
  const [prefix, hlen] = getDigestInfo(hash, msg);

  if (!prefix)
    return false;

  if (msg.length !== hlen)
    return false;

  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    return false;

  const klen = k.size();

  if (sig.length !== klen)
    return false;

  const tlen = prefix.length + hlen;

  if (klen < tlen + 11)
    return false;

  const em = k.encrypt(sig);

  // EM = 0x00 || 0x01 || PS || 0x00 || T
  let ok = 1;

  ok &= safeEqualByte(em[0], 0x00);
  ok &= safeEqualByte(em[1], 0x01);

  for (let i = 2; i < klen - tlen - 1; i++)
    ok &= safeEqualByte(em[i], 0xff);

  ok &= safeEqualByte(em[klen - tlen - 1], 0x00);
  ok &= safeEqual(em.slice(klen - tlen, klen - hlen), prefix);
  ok &= safeEqual(em.slice(klen - hlen, klen), msg);

  return ok === 1;
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function encrypt(msg, key) {
  // [RFC8017] Page 28, Section 7.2.1.
  assert(Buffer.isBuffer(msg));

  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA public key.');

  const klen = k.size();

  if (msg.length > klen - 11)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || 0x02 || PS || 0x00 || M
  const em = Buffer.allocUnsafe(klen);
  const mlen = msg.length;
  const plen = klen - mlen - 3;

  em[0] = 0x00;
  em[1] = 0x02;

  rng.randomFill(em, 2, plen);

  for (let i = 2; i < 2 + plen; i++) {
    while (em[i] === 0x00)
      rng.randomFill(em, i, 1);
  }

  em[klen - mlen - 1] = 0x00;

  msg.copy(em, klen - mlen);

  return k.encrypt(em);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function decrypt(msg, key) {
  // [RFC8017] Page 29, Section 7.2.2.
  assert(Buffer.isBuffer(msg));

  const k = RSAPrivateKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA private key.');

  const klen = k.size();

  if (klen < 11)
    throw new Error('Invalid RSA private key.');

  if (msg.length !== klen)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || 0x02 || PS || 0x00 || M
  const em = k.decrypt(msg);
  const zero = safeEqualByte(em[0], 0x00);
  const two = safeEqualByte(em[1], 0x02);

  let index = 0;
  let looking = 1;

  for (let i = 2; i < em.length; i++) {
    const equals0 = safeEqualByte(em[i], 0x00);

    index = safeSelect(index, i, looking & equals0);
    looking = safeSelect(looking, 0, equals0);
  }

  const validPS = safeLTE(2 + 8, index);
  const valid = zero & two & (looking ^ 1) & validPS;
  const offset = safeSelect(0, index + 1, valid);

  if (valid === 0)
    throw new Error('Invalid RSA ciphertext.');

  return em.slice(offset);
}

/**
 * Sign a message (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Buffer} PSS-formatted signature.
 */

function signPSS(hash, msg, key, saltLen) {
  // [RFC8017] Page 33, Section 8.1.1.
  if (saltLen == null)
    saltLen = SALT_LENGTH_HASH;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert((saltLen | 0) === saltLen);

  if (msg.length !== hash.size)
    throw new Error('Invalid RSA message size.');

  const k = RSAPrivateKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA private key.');

  const bits = k.bits();
  const klen = (bits + 7) >>> 3;
  const emlen = (bits + 6) >>> 3;

  if (saltLen === SALT_LENGTH_AUTO)
    saltLen = emlen - 2 - hash.size;
  else if (saltLen === SALT_LENGTH_HASH)
    saltLen = hash.size;

  if (saltLen < 0 || saltLen > klen)
    throw new Error('Invalid PSS salt length.');

  const salt = rng.randomBytes(saltLen);
  const em = pssEncode(hash, msg, bits - 1, salt);

  // Note that `em` may be one byte less
  // than the modulus size in the case
  // of (bits - 1) mod 8 == 0.
  return k.decrypt(em);
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {Buffer} key
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Boolean}
 */

function verifyPSS(hash, msg, sig, key, saltLen) {
  if (saltLen == null)
    saltLen = SALT_LENGTH_HASH;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));
  assert((saltLen | 0) === saltLen);

  try {
    return _verifyPSS(hash, msg, sig, key, saltLen);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (PSS).
 * @private
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {Buffer} key
 * @param {Number} saltLen
 * @returns {Boolean}
 */

function _verifyPSS(hash, msg, sig, key, saltLen) {
  // [RFC8017] Page 34, Section 8.1.2.
  if (msg.length !== hash.size)
    return false;

  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    return false;

  const bits = k.bits();
  const klen = (bits + 7) >>> 3;

  if (sig.length !== klen)
    return false;

  if (saltLen === SALT_LENGTH_AUTO)
    saltLen = 0; // Handled in pssVerify.
  else if (saltLen === SALT_LENGTH_HASH)
    saltLen = hash.size;

  if (saltLen < 0 || saltLen > klen)
    return false;

  let em = k.encrypt(sig);

  // Edge case: the encoding crossed a
  // a byte boundary. Our encryption
  // function pads to the modulus size
  // by default, meaning there's one
  // extra zero byte prepended.
  if (((bits - 1) & 7) === 0) {
    if (em[0] !== 0x00)
      return false;

    em = em.slice(1);
  }

  return pssVerify(hash, msg, em, bits - 1, saltLen);
}

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function encryptOAEP(hash, msg, key, label) {
  // [RFC8017] Page 22, Section 7.1.1.
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));

  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA public key.');

  const klen = k.size();
  const mlen = msg.length;
  const hlen = hash.size;

  if (mlen > klen - 2 * hlen - 2)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || (seed) || (Hash(L) || PS || 0x01 || M)
  const em = Buffer.allocUnsafe(klen);
  const lhash = hash.digest(label);
  const seed = em.slice(1, 1 + hlen);
  const db = em.slice(1 + hlen);
  const dlen = db.length;

  em[0] = 0x00;

  rng.randomFill(seed, 0, seed.length);

  lhash.copy(db, 0);
  db.fill(0x00, hlen, dlen - mlen - 1);
  db[dlen - mlen - 1] = 0x01;
  msg.copy(db, dlen - mlen);

  mgf1xor(hash, db, seed);
  mgf1xor(hash, seed, db);

  return k.encrypt(em);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEP(hash, msg, key, label) {
  // [RFC8017] Page 25, Section 7.1.2.
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));

  const k = RSAPrivateKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA private key.');

  const klen = k.size();
  const mlen = msg.length;
  const hlen = hash.size;

  if (klen < hlen * 2 + 2)
    throw new Error('Invalid RSA private key size.');

  if (mlen !== klen)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || (seed) || (Hash(L) || PS || 0x01 || M)
  const em = k.decrypt(msg);
  const expect = hash.digest(label);
  const zero = safeEqualByte(em[0], 0x00);
  const seed = em.slice(1, hlen + 1);
  const db = em.slice(hlen + 1);

  mgf1xor(hash, seed, db);
  mgf1xor(hash, db, seed);

  const lhash = db.slice(0, hlen);
  const lvalid = safeEqual(lhash, expect);
  const rest = db.slice(hlen);

  let looking = 1;
  let index = 0;
  let invalid = 0;

  for (let i = 0; i < rest.length; i++) {
    const equals0 = safeEqualByte(rest[i], 0x00);
    const equals1 = safeEqualByte(rest[i], 0x01);

    index = safeSelect(index, i, looking & equals1);
    looking = safeSelect(looking, 0, equals1);
    invalid = safeSelect(invalid, 1, looking & (equals0 ^ 1));
  }

  const valid = zero & lvalid & (invalid ^ 1) & (looking ^ 1);

  if (valid === 0)
    throw new Error('Invalid RSA ciphertext.');

  return rest.slice(index + 1);
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {Buffer} key
 * @returns {Buffer}
 */

function veil(msg, bits, key) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);

  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA public key.');

  if (msg.length !== k.size())
    throw new Error('Invalid RSA ciphertext.');

  if (bits < k.bits())
    throw new Error('Cannot make ciphertext smaller.');

  const bytes = (bits + 7) >>> 3;
  const c = BN.decode(msg);

  if (c.cmp(k.n) >= 0)
    throw new Error('Invalid RSA ciphertext.');

  const vmax = BN.shift(1, bits);
  const rmax = vmax.sub(c).iadd(k.n).isubn(1).div(k.n);

  assert(rmax.sign() > 0);

  let v = vmax;

  while (v.cmp(vmax) >= 0) {
    const r = BN.random(rng, 0, rmax);

    v = c.add(r.mul(k.n));
  }

  assert(v.mod(k.n).cmp(c) === 0);
  assert(v.bitLength() <= bits);

  return v.encode('be', bytes);
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {Buffer} key
 * @returns {Buffer}
 */

function unveil(msg, bits, key) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);

  const k = RSAPublicKey.decode(key);

  if (!k.verify())
    throw new Error('Invalid RSA public key.');

  const klen = k.size();

  if (msg.length < klen)
    throw new Error('Invalid RSA ciphertext.');

  const v = BN.decode(msg);

  if (bits !== 0 && v.bitLength() > bits)
    throw new Error('Invalid RSA ciphertext.');

  const c = v.imod(k.n);

  return c.encode('be', klen);
}

/*
 * Digest Info
 */

function getDigestInfo(name, msg) {
  // [RFC8017] Page 63, Section B.1.
  assert(name == null || typeof name === 'string');
  assert(Buffer.isBuffer(msg));

  if (name == null)
    return [EMPTY, msg.length];

  const prefix = digestInfo[name];

  if (prefix == null)
    return [null, 0];

  if (prefix.length === 1)
    return [EMPTY, prefix[0]];

  return [
    prefix,
    prefix[prefix.length - 1]
  ];
}

/*
 * MGF1
 */

function mgf1xor(hash, out, seed) {
  // [RFC8017] Page 67, Section B.2.1.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(out));
  assert(Buffer.isBuffer(seed));

  const ctr = Buffer.alloc(4, 0x00);

  let i = 0;

  while (i < out.length) {
    const digest = hash.multi(seed, ctr);

    let j = 0;

    while (i < out.length && j < digest.length)
      out[i++] ^= digest[j++];

    for (j = 3; j >= 0; j--) {
      ctr[j] += 1;

      if (ctr[j] !== 0x00)
        break;
    }
  }
}

/*
 * PSS
 */

function pssEncode(hash, msg, embits, salt) {
  // [RFC8017] Page 42, Section 9.1.1.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert((embits >>> 0) === embits);
  assert(Buffer.isBuffer(salt));

  const hlen = hash.size;
  const slen = salt.length;
  const emlen = (embits + 7) >>> 3;

  if (msg.length !== hlen)
    throw new Error('Invalid RSA message size.');

  if (emlen < hlen + slen + 2)
    throw new Error('Message too long.');

  // EM = (PS || 0x01 || salt) || H || 0xbc
  const em = Buffer.allocUnsafe(emlen);
  const db = em.slice(0, emlen - hlen - 1);
  const h = em.slice(emlen - hlen - 1, emlen - 1);
  const h0 = hash.multi(PREFIX, msg, salt);
  const mask = 0xff >>> (8 * emlen - embits);

  db.fill(0x00, 0, emlen - slen - hlen - 2);
  db[emlen - slen - hlen - 2] = 0x01;
  salt.copy(db, emlen - slen - hlen - 1);
  h0.copy(h, 0);
  em[emlen - 1] = 0xbc;

  mgf1xor(hash, db, h);

  db[0] &= mask;

  return em;
}

function pssVerify(hash, msg, em, embits, slen) {
  // [RFC8017] Page 44, Section 9.1.2.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(em));
  assert((embits >>> 0) === embits);
  assert((slen >>> 0) === slen);

  const hlen = hash.size;
  const emlen = (embits + 7) >>> 3;

  if (msg.length !== hlen)
    return false;

  if (emlen < hlen + slen + 2)
    return false;

  if (em[emlen - 1] !== 0xbc)
    return false;

  // EM = (PS || 0x01 || salt) || H || 0xbc
  const db = em.slice(0, emlen - hlen - 1);
  const h = em.slice(emlen - hlen - 1, emlen - 1);
  const mask = 0xff >>> (8 * emlen - embits);

  if (em[0] & ~mask)
    return false;

  mgf1xor(hash, db, h);

  db[0] &= mask;

  if (slen === 0) { // Auto
    slen = -1;

    for (let i = 0; i < db.length; i++) {
      if (db[i] === 0x00)
        continue;

      if (db[i] === 0x01) {
        slen = db.length - (i + 1);
        break;
      }

      return false;
    }

    if (slen === -1)
      return false;
  } else {
    const len = db.length - slen - 1;

    for (let i = 0; i < len; i++) {
      if (db[i] !== 0x00)
        return false;
    }

    if (db[len] !== 0x01)
      return false;
  }

  const salt = db.slice(db.length - slen);
  const h0 = hash.multi(PREFIX, msg, salt);

  return h0.equals(h);
}

/*
 * Expose
 */

exports.native = 0;
exports.SALT_LENGTH_AUTO = SALT_LENGTH_AUTO;
exports.SALT_LENGTH_HASH = SALT_LENGTH_HASH;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyBits = privateKeyBits;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExport = privateKeyExport;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyBits = publicKeyBits;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExport = publicKeyExport;
exports.sign = sign;
exports.verify = verify;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.signPSS = signPSS;
exports.verifyPSS = verifyPSS;
exports.encryptOAEP = encryptOAEP;
exports.decryptOAEP = decryptOAEP;
exports.veil = veil;
exports.unveil = unveil;
