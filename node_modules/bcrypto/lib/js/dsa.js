/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * References:
 *
 *   [FIPS186] Federal Information Processing Standards Publication
 *     National Institute of Standards and Technology
 *     http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 *
 *   [DSA] Digital Signature Algorithm (wikipedia)
 *     https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
 *
 *   [RFC6979] Deterministic Usage of the Digital Signature
 *             Algorithm (DSA) and Elliptic Curve Digital
 *             Signature Algorithm (ECDSA)
 *     T. Pornin
 *     https://tools.ietf.org/html/rfc6979
 */

'use strict';

const assert = require('../internal/assert');
const BN = require('../bn');
const rng = require('../random');
const HmacDRBG = require('../hmac-drbg');
const SHA256 = require('../sha256');
const {isProbablePrime} = require('../internal/primes');
const asn1 = require('../internal/asn1');

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const MIN_BITS = 512;
const MAX_BITS = 10000;

/**
 * DSAParams
 */

class DSAParams {
  constructor() {
    this.p = new BN(0);
    this.q = new BN(0);
    this.g = new BN(0);
  }

  bits() {
    return this.p.bitLength();
  }

  size() {
    return this.q.byteLength();
  }

  isSane() {
    if (this.p.sign() < 0 || this.q.sign() < 0)
      return false;

    const pbits = this.p.bitLength();
    const qbits = this.q.bitLength();

    if (pbits < MIN_BITS || pbits > MAX_BITS)
      return false;

    if (qbits !== 160 && qbits !== 224 && qbits !== 256)
      return false;

    if (this.g.cmpn(2) < 0 || this.g.cmp(this.p.subn(1)) >= 0)
      return false;

    if (!this.p.isOdd())
      return false;

    if (!this.q.isOdd())
      return false;

    return true;
  }

  verify() {
    return this.g.powm(this.q, this.p).cmpn(1) === 0;
  }

  generate(L, N) {
    // [FIPS186] Page 31, Appendix A.1.
    //           Page 41, Appendix A.2.
    // [DSA] "Parameter generation".
    assert((L >>> 0) === L);
    assert((N >>> 0) === N);

    if (!(L === 1024 && N === 160)
        && !(L === 2048 && N === 224)
        && !(L === 2048 && N === 256)
        && !(L === 3072 && N === 256)) {
      throw new Error('Invalid parameter sizes.');
    }

    if (L < MIN_BITS || L > MAX_BITS || (N & 7) !== 0)
      throw new Error('Invalid parameter sizes.');

    let q = null;
    let p = null;

outer:
    for (;;) {
      q = BN.randomBits(rng, N);
      q.setn(N - 1, 1);
      q.setn(0, 1);

      if (!isProbablePrime(q, 64))
        continue;

      for (let i = 0; i < 4 * L; i++) {
        p = BN.randomBits(rng, L);
        p.setn(L - 1, 1);
        p.setn(0, 1);

        p.isub(p.mod(q).isubn(1));

        const bits = p.bitLength();

        if (bits < L || bits > MAX_BITS)
          continue;

        if (!isProbablePrime(p, 64))
          continue;

        break outer;
      }
    }

    const h = new BN(2);
    const pm1 = p.subn(1);
    const e = pm1.div(q);

    for (;;) {
      const g = h.powm(e, p);

      if (g.cmpn(1) === 0) {
        h.iaddn(1);
        continue;
      }

      this.p = p;
      this.q = q;
      this.g = g;

      return this;
    }
  }

  toParams() {
    const group = new DSAParams();

    group.p = this.p;
    group.q = this.q;
    group.g = this.g;

    return group;
  }

  encode() {
    let size = 0;

    size += asn1.sizeInt(this.p);
    size += asn1.sizeInt(this.q);
    size += asn1.sizeInt(this.g);

    const out = Buffer.alloc(asn1.sizeSeq(size));

    let pos = 0;

    pos = asn1.writeSeq(out, pos, size);
    pos = asn1.writeInt(out, pos, this.p);
    pos = asn1.writeInt(out, pos, this.q);
    pos = asn1.writeInt(out, pos, this.g);

    assert(pos === out.length);

    return out;
  }

  decode(data) {
    assert(Buffer.isBuffer(data));

    let pos = 0;

    pos = asn1.readSeq(data, pos);

    [this.p, pos] = asn1.readInt(data, pos);
    [this.q, pos] = asn1.readInt(data, pos);
    [this.g, pos] = asn1.readInt(data, pos);

    if (pos !== data.length)
      throw new Error('Trailing bytes.');

    return this;
  }

  static generate(L, N) {
    return new DSAParams().generate(L, N);
  }

  static decode(data) {
    return new DSAParams().decode(data);
  }
}

/**
 * DSAPublicKey
 */

class DSAPublicKey extends DSAParams {
  constructor() {
    super();
    this.y = new BN(0);
  }

  isSane() {
    if (!super.isSane())
      return false;

    if (this.y.cmpn(2) < 0 || this.y.cmp(this.p.subn(1)) >= 0)
      return false;

    return true;
  }

  verify() {
    if (!super.verify())
      return false;

    return this.y.powm(this.q, this.p).cmpn(1) === 0;
  }

  encode() {
    let size = 0;

    size += asn1.sizeInt(this.y);
    size += asn1.sizeInt(this.p);
    size += asn1.sizeInt(this.q);
    size += asn1.sizeInt(this.g);

    const out = Buffer.alloc(asn1.sizeSeq(size));

    let pos = 0;

    pos = asn1.writeSeq(out, pos, size);
    pos = asn1.writeInt(out, pos, this.y);
    pos = asn1.writeInt(out, pos, this.p);
    pos = asn1.writeInt(out, pos, this.q);
    pos = asn1.writeInt(out, pos, this.g);

    assert(pos === out.length);

    return out;
  }

  decode(data) {
    assert(Buffer.isBuffer(data));

    let pos = 0;

    pos = asn1.readSeq(data, pos);

    [this.y, pos] = asn1.readInt(data, pos);
    [this.p, pos] = asn1.readInt(data, pos);
    [this.q, pos] = asn1.readInt(data, pos);
    [this.g, pos] = asn1.readInt(data, pos);

    if (pos !== data.length)
      throw new Error('Trailing bytes.');

    return this;
  }

  static decode(data) {
    return new DSAPublicKey().decode(data);
  }
}

/**
 * DSAPrivateKey
 */

class DSAPrivateKey extends DSAPublicKey {
  constructor() {
    super();
    this.x = new BN(0);
  }

  isSane() {
    if (!super.isSane())
      return false;

    if (this.x.sign() <= 0 || this.x.cmp(this.q) >= 0)
      return false;

    return true;
  }

  isSaneCompute() {
    const group = new DSAParams();

    group.p = this.p;
    group.q = this.q;
    group.g = this.g;

    if (!group.isSane())
      return false;

    if (this.x.sign() <= 0 || this.x.cmp(this.q) >= 0)
      return false;

    return true;
  }

  verify() {
    if (!super.verify())
      return false;

    const y = this.g.powm(this.x, this.p);

    return this.y.eq(y);
  }

  toPublic() {
    const pub = new DSAPublicKey();

    pub.p = this.p;
    pub.q = this.q;
    pub.g = this.g;
    pub.y = this.y;

    return pub;
  }

  encode() {
    let size = 0;

    size += asn1.sizeVersion(0);
    size += asn1.sizeInt(this.p);
    size += asn1.sizeInt(this.q);
    size += asn1.sizeInt(this.g);
    size += asn1.sizeInt(this.y);
    size += asn1.sizeInt(this.x);

    const out = Buffer.alloc(asn1.sizeSeq(size));

    let pos = 0;

    pos = asn1.writeSeq(out, pos, size);
    pos = asn1.writeVersion(out, pos, 0);
    pos = asn1.writeInt(out, pos, this.p);
    pos = asn1.writeInt(out, pos, this.q);
    pos = asn1.writeInt(out, pos, this.g);
    pos = asn1.writeInt(out, pos, this.y);
    pos = asn1.writeInt(out, pos, this.x);

    assert(pos === out.length);

    return out;
  }

  decode(data) {
    assert(Buffer.isBuffer(data));

    let pos = 0;

    pos = asn1.readSeq(data, pos);
    pos = asn1.readVersion(data, pos, 0);

    [this.p, pos] = asn1.readInt(data, pos);
    [this.q, pos] = asn1.readInt(data, pos);
    [this.g, pos] = asn1.readInt(data, pos);
    [this.y, pos] = asn1.readInt(data, pos);
    [this.x, pos] = asn1.readInt(data, pos);

    if (pos !== data.length)
      throw new Error('Trailing bytes.');

    return this;
  }

  static decode(data) {
    return new DSAPrivateKey().decode(data);
  }
}

/**
 * DSASignature
 */

class DSASignature {
  constructor() {
    this.r = new BN(0);
    this.s = new BN(0);
  }

  encode() {
    const size = asn1.sizeInt(this.r) + asn1.sizeInt(this.s);
    const out = Buffer.alloc(asn1.sizeSeq(size));

    let pos = 0;

    pos = asn1.writeSeq(out, pos, size);
    pos = asn1.writeInt(out, pos, this.r);
    pos = asn1.writeInt(out, pos, this.s);

    assert(pos === out.length);

    return out;
  }

  decode(data) {
    assert(Buffer.isBuffer(data));

    let pos = 0;

    pos = asn1.readSeq(data, pos);

    [this.r, pos] = asn1.readInt(data, pos);
    [this.s, pos] = asn1.readInt(data, pos);

    if (pos !== data.length)
      throw new Error('Trailing bytes.');

    return this;
  }

  encodeRS(size) {
    assert((size >> 0) === size);

    return Buffer.concat([
      this.r.encode('be', size),
      this.s.encode('be', size)
    ]);
  }

  decodeRS(data, size) {
    assert(Buffer.isBuffer(data));

    if (size == null)
      size = data.length >>> 1;

    assert((size >> 0) === size);
    assert(data.length === size * 2);

    this.r = BN.decode(data.slice(0, size));
    this.s = BN.decode(data.slice(size, size * 2));

    return this;
  }

  static decode(data) {
    return new DSASignature().decode(data);
  }

  static decodeRS(data, size) {
    return new DSASignature().decodeRS(data, size);
  }
}

/**
 * Create params from key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function paramsCreate(key) {
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = DSAPrivateKey.decode(key);
  } catch (e) {
    k = DSAPublicKey.decode(key);
  }

  const group = k.toParams();

  if (!group.isSane())
    throw new Error('Invalid DSA key.');

  return group.encode();
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

function paramsGenerate(bits) {
  if (bits == null)
    bits = DEFAULT_BITS;

  assert((bits >>> 0) === bits);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  // OpenSSL behavior.
  const L = bits;
  const N = bits < 2048 ? 160 : 256;

  return DSAParams.generate(L, N).encode();
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

async function paramsGenerateAsync(bits) {
  return paramsGenerate(bits);
}

/**
 * Get params prime size in bits.
 * @param {Buffer} params
 * @returns {Number}
 */

function paramsBits(params) {
  const group = DSAParams.decode(params);

  if (!group.isSane())
    throw new Error('Invalid DSA params.');

  return group.bits();
}

/**
 * Get params scalar size in bits.
 * @param {Buffer} params
 * @returns {Number}
 */

function paramsScalarBits(params) {
  const group = DSAParams.decode(params);

  if (!group.isSane())
    throw new Error('Invalid DSA params.');

  return group.q.bitLength();
}

/**
 * Verify params.
 * @param {Buffer} params
 * @returns {Boolean}
 */

function paramsVerify(params) {
  assert(Buffer.isBuffer(params));

  let group;
  try {
    group = DSAParams.decode(params);
  } catch (e) {
    return false;
  }

  if (!group.isSane())
    return false;

  return group.verify();
}

/**
 * Import params from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function paramsImport(json) {
  assert(json && typeof json === 'object');

  const group = new DSAParams();

  if (json.p != null)
    group.p = BN.decode(json.p);

  if (json.q != null)
    group.q = BN.decode(json.q);

  if (json.g != null)
    group.g = BN.decode(json.g);

  if (!group.isSane())
    throw new Error('Invalid DSA parameters.');

  return group.encode();
}

/**
 * Export params to an object.
 * @param {Buffer} params
 * @returns {Object}
 */

function paramsExport(params) {
  const group = DSAParams.decode(params);

  if (!group.isSane())
    throw new Error('Invalid DSA parameters.');

  return {
    p: group.p.encode(),
    q: group.q.encode(),
    g: group.g.encode()
  };
}

/**
 * Generate private key from params.
 * @param {Buffer} params
 * @returns {Buffer}
 */

function privateKeyCreate(params) {
  // [FIPS186] Page 46, Appendix B.1.
  // [DSA] "Per-user keys".
  const group = DSAParams.decode(params);

  if (!group.isSane())
    throw new Error('Invalid DSA parameters.');

  const {p, q, g} = group;
  const x = BN.random(rng, 1, q);
  const y = g.powm(x, p);
  const key = new DSAPrivateKey();

  key.p = p;
  key.q = q;
  key.g = g;
  key.x = x;
  key.y = y;

  return key.encode();
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

function privateKeyGenerate(bits) {
  const params = paramsGenerate(bits);
  return privateKeyCreate(params);
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

async function privateKeyGenerateAsync(bits) {
  const params = await paramsGenerateAsync(bits);
  return privateKeyCreate(params);
}

/**
 * Get private key prime size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function privateKeyBits(key) {
  const k = DSAPrivateKey.decode(key);

  if (!k.isSane())
    throw new Error('Invalid DSA private key.');

  return k.bits();
}

/**
 * Get private key scalar size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function privateKeyScalarBits(key) {
  const k = DSAPrivateKey.decode(key);

  if (!k.isSane())
    throw new Error('Invalid DSA private key.');

  return k.q.bitLength();
}

/**
 * Verify a private key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));

  let k;
  try {
    k = DSAPrivateKey.decode(key);
  } catch (e) {
    return false;
  }

  if (!k.isSane())
    return false;

  return k.verify();
}

/**
 * Import a private key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function privateKeyImport(json) {
  assert(json && typeof json === 'object');

  const k = new DSAPrivateKey();

  if (json.p != null)
    k.p = BN.decode(json.p);

  if (json.q != null)
    k.q = BN.decode(json.q);

  if (json.g != null)
    k.g = BN.decode(json.g);

  if (json.y != null)
    k.y = BN.decode(json.y);

  if (json.x != null)
    k.x = BN.decode(json.x);

  if (k.y.isZero()) {
    if (!k.isSaneCompute())
      throw new Error('Invalid DSA private key.');

    k.y = k.g.powm(k.x, k.p);
  } else {
    if (!k.isSane())
      throw new Error('Invalid DSA private key.');
  }

  return k.encode();
}

/**
 * Export a private key in OpenSSL ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  const k = DSAPrivateKey.decode(key);

  if (!k.isSane())
    throw new Error('Invalid RSA private key.');

  return {
    p: k.p.encode(),
    q: k.q.encode(),
    g: k.g.encode(),
    y: k.y.encode(),
    x: k.x.encode()
  };
}

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyCreate(key) {
  const k = DSAPrivateKey.decode(key);

  if (!k.isSane())
    throw new Error('Invalid DSA private key.');

  const p = k.toPublic();

  return p.encode();
}

/**
 * Get public key prime size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function publicKeyBits(key) {
  const k = DSAPublicKey.decode(key);

  if (!k.isSane())
    throw new Error('Invalid DSA public key.');

  return k.bits();
}

/**
 * Get public key scalar size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function publicKeyScalarBits(key) {
  const k = DSAPublicKey.decode(key);

  if (!k.isSane())
    throw new Error('Invalid DSA public key.');

  return k.q.bitLength();
}

/**
 * Verify a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  let k;
  try {
    k = DSAPublicKey.decode(key);
  } catch (e) {
    return false;
  }

  if (!k.isSane())
    return false;

  return k.verify();
}

/**
 * Import a public key to an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function publicKeyImport(json) {
  assert(json && typeof json === 'object');

  const k = new DSAPublicKey();

  if (json.p != null)
    k.p = BN.decode(json.p);

  if (json.q != null)
    k.q = BN.decode(json.q);

  if (json.g != null)
    k.g = BN.decode(json.g);

  if (json.y != null)
    k.y = BN.decode(json.y);

  if (!k.isSane())
    throw new Error('Invalid DSA public key.');

  return k.encode();
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  const k = DSAPublicKey.decode(key);

  if (!k.isSane())
    throw new Error('Invalid DSA public key.');

  return {
    p: k.p.encode(),
    q: k.q.encode(),
    g: k.g.encode(),
    y: k.y.encode()
  };
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} R/S-formatted signature.
 */

function signatureImport(sig, size) {
  const S = DSASignature.decode(sig);
  return S.encodeRS(size);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} DER-formatted signature.
 */

function signatureExport(sig, size) {
  const S = DSASignature.decodeRS(sig, size);
  return S.encode();
}

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  const k = DSAPrivateKey.decode(key);
  const S = _sign(msg, k);
  return S.encodeRS(k.size());
}

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  const k = DSAPrivateKey.decode(key);
  const S = _sign(msg, k);
  return S.encode();
}

/**
 * Sign a message.
 * @private
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Signature}
 */

function _sign(msg, key) {
  // DSA Signing.
  //
  // [FIPS186] Page 19, Section 4.6.
  // [DSA] "Signing".
  // [RFC6979] Page 9, Section 2.4.
  // [RFC6979] Page 10, Section 3.2.
  //
  // Assumptions:
  //
  //   - Let `m` be an integer reduced from bytes.
  //   - Let `x` be a secret non-zero scalar.
  //   - Let `k` be a random non-zero scalar.
  //   - r != 0, s != 0.
  //
  // Computation:
  //
  //   k = random integer in [1,q-1]
  //   r' = g^k mod p
  //   r = r' mod q
  //   s = (r * x + m) / k mod q
  //   S = (r, s)
  //
  // We can blind the scalar arithmetic
  // with a random integer `b` like so:
  //
  //   b = random integer in [1,q-1]
  //   s = (r * (x * b) + m * b) / (k * b) mod q
  //
  // Note that `k` must remain secret,
  // otherwise an attacker can compute:
  //
  //   x = (s * k - m) / r mod q
  //
  // This means that if two signatures
  // share the same `r` value, an attacker
  // can compute:
  //
  //   k = (m1 - m2) / (s1 - s2) mod q
  //   x = (s1 * k - m1) / r mod q
  //
  // Assuming:
  //
  //   s1 = (r * x + m1) / k mod q
  //   s2 = (r * x + m2) / k mod q
  //
  // To mitigate this, `k` can be generated
  // deterministically using the HMAC-DRBG
  // construction described in [RFC6979].
  assert(Buffer.isBuffer(msg));
  assert(key instanceof DSAPrivateKey);

  if (!key.isSane())
    throw new Error('Invalid DSA private key.');

  const {p, q, g, x} = key;
  const bytes = q.byteLength();
  const m = reduce(msg, q);
  const entropy = x.encode('be', bytes);
  const nonce = m.encode('be', bytes);
  const drbg = new HmacDRBG(SHA256, entropy, nonce);

  for (;;) {
    const k = truncate(drbg.generate(bytes), q);

    if (k.isZero() || k.cmp(q) >= 0)
      continue;

    const re = powBlind(g, k, p, q);
    const r = re.mod(q);

    if (r.isZero())
      continue;

    const b = BN.random(rng, 1, q);
    const ki = k.mul(b).fermat(q);
    const bx = x.mul(b).imod(q);
    const bm = m.mul(b).imod(q);
    const sk = r.mul(bx).iadd(bm).imod(q);
    const s = sk.mul(ki).imod(q);

    if (s.isZero())
      continue;

    const S = new DSASignature();

    S.r = r;
    S.s = s;

    return S;
  }
}

/**
 * Verify a signature (R/S).
 * @private
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  let k;
  try {
    k = DSAPublicKey.decode(key);
  } catch (e) {
    return false;
  }

  let S;
  try {
    S = DSASignature.decodeRS(sig, k.size());
  } catch (e) {
    return false;
  }

  try {
    return _verify(msg, S, k);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  let k;
  try {
    k = DSAPublicKey.decode(key);
  } catch (e) {
    return false;
  }

  let S;
  try {
    S = DSASignature.decode(sig);
  } catch (e) {
    return false;
  }

  try {
    return _verify(msg, S, k);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature.
 * @private
 * @param {Buffer} msg
 * @param {Signature} S
 * @param {Buffer} key
 * @returns {Boolean}
 */

function _verify(msg, S, key) {
  // DSA Verification.
  //
  // [FIPS186] Page 19, Section 4.7.
  // [DSA] "Verifying a signature".
  //
  // Assumptions:
  //
  //   - Let `m` be an integer reduced from bytes.
  //   - Let `r` and `s` be signature elements.
  //   - Let `y` be a valid group element.
  //   - r != 0, r < q.
  //   - s != 0, s < q.
  //
  // Computation:
  //
  //   u1 = m / s mod q
  //   u2 = r / s mod q
  //   r' = g^u1 * y^u2 mod p
  //   r == r' mod q
  const {r, s} = S;
  const {p, q, g, y} = key;

  if (!key.isSane())
    return false;

  if (r.isZero() || r.cmp(q) >= 0)
    return false;

  if (s.isZero() || s.cmp(q) >= 0)
    return false;

  const m = reduce(msg, q);
  const si = s.invert(q);
  const u1 = m.mul(si).imod(q);
  const u2 = r.mul(si).imod(q);
  const e1 = g.powm(u1, p);
  const e2 = y.powm(u2, p);
  const re = e1.mul(e2).imod(p);

  return re.imod(q).eq(r);
}

/**
 * Perform a diffie-hellman.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  const k1 = DSAPublicKey.decode(pub);
  const k2 = DSAPrivateKey.decode(priv);

  if (!k1.isSane())
    throw new Error('Invalid DSA public key.');

  if (!k2.isSane())
    throw new Error('Invalid DSA private key.');

  const {p, q, g, x} = k2;
  const {y} = k1;

  if (!k1.p.eq(p) || !k1.q.eq(q) || !k1.g.eq(g))
    throw new Error('Incompatible DSA parameters.');

  if (!k1.verify())
    throw new Error('Invalid DSA public key.');

  const e = powBlind(y, x, p, q);

  return e.encode('be', p.byteLength());
}

/*
 * Helpers
 */

function truncate(msg, q) {
  // Byte array to integer conversion.
  //
  // [FIPS186] Page 68, Appendix C.2.
  //
  // Note that the FIPS186 behavior
  // differs from OpenSSL's behavior.
  // We replicate OpenSSL which takes
  // the left-most ceil(log2(q+1)) bits
  // modulo the order.
  assert(Buffer.isBuffer(msg));
  assert(q instanceof BN);

  const bits = q.bitLength();
  const bytes = (bits + 7) >>> 3;

  if (msg.length > bytes)
    msg = msg.slice(0, bytes);

  const m = BN.decode(msg);
  const d = msg.length * 8 - bits;

  if (d > 0)
    m.iushrn(d);

  return m;
}

function reduce(msg, q) {
  return truncate(msg, q).imod(q);
}

function powBlind(g, x, p, q) {
  // Idea: exponentiate by scalar with a
  // blinding factor, similar to how we
  // blind multiplications in EC. Note
  // that it would be safer if we had the
  // blinding factor pregenerated for each
  // key.
  //
  // Computation:
  //
  //   b = random integer in [1,q-1]
  //   k = (x - b) mod q
  //   e = g^k * g^b mod p
  //
  // In theory, we could also speed up
  // the calculation of `e` with a multi
  // exponentiation algorithm.
  assert(g instanceof BN);
  assert(x instanceof BN);
  assert(p instanceof BN);
  assert(q instanceof BN);

  const G = g.toRed(BN.mont(p));
  const b = BN.random(rng, 1, q);
  const k = x.sub(b).imod(q);
  const e1 = G.redPow(k);
  const e2 = G.redPow(b);
  const e = e1.redMul(e2);

  return e.fromRed();
}

/*
 * Expose
 */

exports.native = 0;
exports.paramsCreate = paramsCreate;
exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.paramsBits = paramsBits;
exports.paramsScalarBits = paramsScalarBits;
exports.paramsVerify = paramsVerify;
exports.paramsImport = paramsImport;
exports.paramsExport = paramsExport;
exports.privateKeyCreate = privateKeyCreate;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyBits = privateKeyBits;
exports.privateKeyScalarBits = privateKeyScalarBits;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExport = privateKeyExport;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyBits = publicKeyBits;
exports.publicKeyScalarBits = publicKeyScalarBits;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExport = publicKeyExport;
exports.signatureImport = signatureImport;
exports.signatureExport = signatureExport;
exports.sign = sign;
exports.signDER = signDER;
exports.verify = verify;
exports.verifyDER = verifyDER;
exports.derive = derive;
