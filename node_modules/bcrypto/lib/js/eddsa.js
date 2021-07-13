/*!
 * eddsa.js - EdDSA for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * References:
 *
 *   [EDDSA] High-speed high-security signatures
 *     D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, B. Yang
 *     https://ed25519.cr.yp.to/ed25519-20110926.pdf
 *
 *   [RFC8032] Edwards-Curve Digital Signature Algorithm (EdDSA)
 *     S. Josefsson, I. Liusvaara
 *     https://tools.ietf.org/html/rfc8032
 *
 * Implementation Notes:
 *
 *   - In contrast to the ECDSA backend, we allow points at
 *     infinity (in all functions).
 *
 *   - Mike Hamburg's Ed448-Goldilocks rejects both infinity as
 *     well as the torsion point (0, -1). We do not replicate
 *     this behavior.
 *
 *   - For Ed25519, we do "cofactor-less" verification by default.
 *     This means torsion components will affect the result of the
 *     verification.
 *
 *   - For Ed448, we do cofactor verification by default to mimic
 *     OpenSSL and Mike Hamburg's Ed448-Goldilocks implementation.
 *
 *   - `verifySingle`/`verifyBatch` do cofactor verification. Do
 *     not use `verifyBatch` expecting the same results as the
 *     regular `verify` call[1]. This will not be the case for
 *     Ed25519.
 *
 *   - All functions are completely unaware of points of small
 *     order and torsion components (in other words, points will
 *     not be explicitly checked for this, anywhere).
 *
 *   - `deriveWithScalar` and `exchangeWithScalar` automatically
 *     clamp scalars before multiplying (meaning torsion components
 *     are removed from the result and points of small order will
 *     be normalized to infinity).
 *
 *   - The HD function, `publicKeyTweakMul`, _does not_ clamp
 *     automatically. It is possible to end up with a torsion
 *     component in the resulting point (assuming the input
 *     point had one).
 *
 *   - Ed448-Goldilocks is 4-isogenous to Curve448. This means
 *     that when converting to Curve448, small order points will
 *     be normalized to (0, 0). When converting back to Ed448,
 *     any small order points will be normalized to infinity,
 *     and any torsion components will be removed completely.
 *     Also note that when converting back, the implementation
 *     needs to divide the point by 4. This is a major perf hit,
 *     so treat `x448.publicKeyConvert` as if it were a point
 *     multiplication.
 *
 *   - Elligators should not be used with Edwards curves. As
 *     Tibouchi notes[2], regular public keys will map to
 *     _distinguishable_ field elements as they are always in
 *     the primary subgroup. Either the Ristretto Elligator[3],
 *     or a prime order curve with an Elligator Squared[2]
 *     construction are suitable alternatives here.
 *
 *   - These notes also spell out why you should avoid using
 *     Edwards curves on a blockchain[4].
 *
 *   [1] https://moderncrypto.org/mail-archive/curves/2016/000836.html
 *   [2] https://eprint.iacr.org/2014/043.pdf
 *   [3] https://ristretto.group/formulas/elligator.html
 *   [4] https://src.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html
 */

'use strict';

const assert = require('../internal/assert');
const BatchRNG = require('./batch-rng');
const BN = require('../bn');
const elliptic = require('./elliptic');
const rng = require('../random');

/*
 * EDDSA
 */

class EDDSA {
  constructor(id, mid, eid, hash, pre) {
    assert(typeof id === 'string');
    assert(!mid || typeof mid === 'string');
    assert(!eid || typeof eid === 'string');
    assert(hash);

    this.id = id;
    this.type = 'eddsa';
    this.mid = mid || null;
    this.eid = eid || null;
    this.hash = hash;
    this.native = 0;

    this._pre = pre || null;
    this._curve = null;
    this._mont = null;
    this._iso = null;
    this._rng = null;
  }

  get curve() {
    if (!this._curve) {
      this._curve = elliptic.curve(this.id, this._pre);
      this._curve.precompute(rng);
      this._pre = null;
    }
    return this._curve;
  }

  get mont() {
    if (this.mid && !this._mont)
      this._mont = elliptic.curve(this.mid);
    return this._mont;
  }

  get iso() {
    if (!this.eid)
      return this.mont;

    if (!this._iso)
      this._iso = elliptic.curve(this.eid);

    return this._iso;
  }

  get rng() {
    if (!this._rng)
      this._rng = new BatchRNG(this.curve);

    return this._rng;
  }

  get size() {
    return this.curve.adjustedSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  hashNonce(prefix, msg, ph, ctx) {
    const hash = new Hash(this);

    hash.init(ph, ctx);
    hash.update(prefix);
    hash.update(msg);

    return hash.final();
  }

  hashChallenge(R, A, m, ph, ctx) {
    const hash = new Hash(this);

    hash.init(ph, ctx);
    hash.update(R);
    hash.update(A);
    hash.update(m);

    return hash.final();
  }

  privateKeyGenerate() {
    return rng.randomBytes(this.curve.adjustedSize);
  }

  scalarGenerate() {
    const scalar = rng.randomBytes(this.curve.scalarSize);
    return this.curve.clamp(scalar);
  }

  privateKeyExpand(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.curve.adjustedSize);

    const hash = this.hash.digest(secret, this.curve.adjustedSize * 2);

    return this.curve.splitHash(hash);
  }

  privateKeyConvert(secret) {
    const [key] = this.privateKeyExpand(secret);
    return key;
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.curve.adjustedSize;
  }

  scalarVerify(scalar) {
    assert(Buffer.isBuffer(scalar));
    return scalar.length === this.curve.scalarSize;
  }

  scalarIsZero(scalar) {
    assert(Buffer.isBuffer(scalar));

    let k;
    try {
      k = this.curve.decodeScalar(scalar).imod(this.curve.n);
    } catch (e) {
      return false;
    }

    return k.isZero();
  }

  scalarClamp(scalar) {
    assert(Buffer.isBuffer(scalar));
    assert(scalar.length === this.curve.scalarSize);

    return this.curve.clamp(Buffer.from(scalar));
  }

  privateKeyExport(secret) {
    const pub = this.publicKeyCreate(secret);
    const {x, y} = this.publicKeyExport(pub);

    return {
      d: Buffer.from(secret),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.d));

    if (json.d.length !== this.curve.adjustedSize)
      throw new Error('Invalid private key.');

    return Buffer.from(json.d);
  }

  scalarTweakAdd(scalar, tweak) {
    const a = this.curve.decodeScalar(scalar);
    const t = this.curve.decodeScalar(tweak);
    const k = a.add(t).imod(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  scalarTweakMul(scalar, tweak) {
    const a = this.curve.decodeScalar(scalar);
    const t = this.curve.decodeScalar(tweak);
    const k = a.mul(t).imod(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  scalarReduce(scalar) {
    const a = this.curve.decodeScalar(scalar);
    const k = a.imod(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  scalarNegate(scalar) {
    const a = this.curve.decodeScalar(scalar).imod(this.curve.n);
    const k = a.neg().imod(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  scalarInvert(scalar) {
    const a = this.curve.decodeScalar(scalar).imod(this.curve.n);

    if (a.isZero())
      return this.curve.encodeScalar(a);

    const k = a.invert(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  publicKeyCreate(secret) {
    const key = this.privateKeyConvert(secret);
    return this.publicKeyFromScalar(key);
  }

  publicKeyFromScalar(scalar) {
    const a = this.curve.decodeScalar(scalar).imod(this.curve.n);
    const A = this.curve.g.mulBlind(a);

    return A.encode();
  }

  publicKeyConvert(key) {
    if (!this.mont)
      throw new Error('No equivalent montgomery curve.');

    const A = this.curve.decodePoint(key);
    const P = this.mont.pointFromEdwards(A);

    return P.encode();
  }

  publicKeyFromUniform(bytes) {
    const u = this.curve.decodeUniform(bytes);
    const A = this.curve.pointFromUniform(u, this.iso);

    return A.encode();
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    const A = this.curve.decodePoint(key);
    const u = this.curve.pointToUniform(A, hint, this.iso);

    return this.curve.encodeUniform(u, hint >>> 8);
  }

  publicKeyFromHash(bytes, pake = false) {
    const A = this.curve.pointFromHash(bytes, pake, this.iso);
    return A.encode();
  }

  publicKeyToHash(key, subgroup = rng.randomInt()) {
    const A = this.curve.decodePoint(key);
    return this.curve.pointToHash(A, subgroup, rng, this.iso);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyIsInfinity(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return A.isInfinity();
  }

  publicKeyIsSmall(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return A.isSmall();
  }

  publicKeyHasTorsion(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return A.hasTorsion();
  }

  publicKeyExport(key) {
    const {x, y} = this.curve.decodePoint(key);

    return {
      x: this.curve.encodeField(x.fromRed()),
      y: this.curve.encodeField(y.fromRed())
    };
  }

  publicKeyImport(json) {
    assert(json && typeof json === 'object');

    let x = null;
    let y = null;
    let A;

    if (json.x != null) {
      x = BN.decode(json.x, this.curve.endian);

      if (x.cmp(this.curve.p) >= 0)
        throw new Error('Invalid point.');
    }

    if (json.y != null) {
      y = BN.decode(json.y, this.curve.endian);

      if (y.cmp(this.curve.p) >= 0)
        throw new Error('Invalid point.');
    }

    if (x && y) {
      A = this.curve.point(x, y);

      if (!A.validate())
        throw new Error('Invalid point.');
    } else if (x) {
      A = this.curve.pointFromX(x, json.sign);
    } else if (y) {
      A = this.curve.pointFromY(y, json.sign);
    } else {
      throw new Error('Invalid point.');
    }

    return A.encode();
  }

  publicKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak).imod(this.curve.n);
    const A = this.curve.decodePoint(key);
    const T = this.curve.g.mul(t);
    const P = T.add(A);

    return P.encode();
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);
    const A = this.curve.decodePoint(key);
    const P = A.mul(t);

    return P.encode();
  }

  publicKeyCombine(keys) {
    assert(Array.isArray(keys));

    let P = this.curve.point();

    for (const key of keys) {
      const A = this.curve.decodePoint(key);

      P = P.add(A);
    }

    return P.encode();
  }

  publicKeyNegate(key) {
    const A = this.curve.decodePoint(key);
    const P = A.neg();

    return P.encode();
  }

  sign(msg, secret, ph, ctx) {
    const [key, prefix] = this.privateKeyExpand(secret);
    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signWithScalar(msg, scalar, prefix, ph, ctx) {
    // EdDSA Signing.
    //
    // [EDDSA] Page 12, Section 4.
    // [RFC8032] Page 8, Section 3.3.
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a byte array of arbitrary size.
    //   - Let `a` be a secret scalar.
    //   - Let `w` be a secret byte array.
    //
    // Computation:
    //
    //   k = H(w, m) mod n
    //   R = G * k
    //   A = G * a
    //   e = H(R, A, m) mod n
    //   s = (k + e * a) mod n
    //   S = (R, s)
    //
    // Note that `k` must remain secret,
    // otherwise an attacker can compute:
    //
    //   a = (s - k) / e mod n
    //
    // The same is true of `w` as `k`
    // can be re-derived as `H(w, m)`.
    if (ctx == null)
      ctx = Buffer.alloc(0);

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(prefix));
    assert(prefix.length === this.curve.adjustedSize);

    const {n} = this.curve;
    const G = this.curve.g;
    const k = this.hashNonce(prefix, msg, ph, ctx);
    const Rraw = G.mulBlind(k).encode();
    const a = this.curve.decodeScalar(scalar);
    const Araw = G.mulBlind(a).encode();
    const e = this.hashChallenge(Rraw, Araw, msg, ph, ctx);
    const s = k.add(e.mul(a)).imod(n);

    return Buffer.concat([Rraw, this.curve.encodeAdjusted(s)]);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    const [key_, prefix_] = this.privateKeyExpand(secret);
    const key = this.scalarTweakAdd(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak, null,
                                     this.curve.adjustedSize * 2);
    const prefix = expanded.slice(0, this.curve.adjustedSize);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    const [key_, prefix_] = this.privateKeyExpand(secret);
    const key = this.scalarTweakMul(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak, null,
                                     this.curve.adjustedSize * 2);
    const prefix = expanded.slice(0, this.curve.adjustedSize);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  verify(msg, sig, key, ph, ctx) {
    if (ctx == null)
      ctx = Buffer.alloc(0);

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(ph == null || typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));

    if (sig.length !== this.curve.adjustedSize * 2)
      return false;

    if (key.length !== this.curve.adjustedSize)
      return false;

    try {
      return this._verify(msg, sig, key, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key, ph, ctx) {
    // EdDSA Verification.
    //
    // [EDDSA] Page 15, Section 5.
    // [RFC8032] Page 8, Section 3.4.
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a byte array of arbitrary size.
    //   - Let `R` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - s < n.
    //
    // Computation:
    //
    //   e = H(R, A, m) mod n
    //   G * s == R + A * e
    //
    // Alternatively, we can compute:
    //
    //   R == G * s - A * e
    //
    // This allows us to make use of a
    // multi-exponentiation algorithm.
    const {n} = this.curve;
    const G = this.curve.g;
    const Rraw = sig.slice(0, this.curve.adjustedSize);
    const sraw = sig.slice(this.curve.adjustedSize);
    const R = this.curve.decodePoint(Rraw);
    const s = this.curve.decodeAdjusted(sraw);
    const A = this.curve.decodePoint(key);

    if (s.cmp(n) >= 0)
      return false;

    const e = this.hashChallenge(Rraw, key, msg, ph, ctx);

    return G.mulAdd(s, A.neg(), e).eq(R);
  }

  verifySingle(msg, sig, key, ph, ctx) {
    if (ctx == null)
      ctx = Buffer.alloc(0);

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(ph == null || typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));

    if (sig.length !== this.curve.adjustedSize * 2)
      return false;

    if (key.length !== this.curve.adjustedSize)
      return false;

    try {
      return this._verifySingle(msg, sig, key, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verifySingle(msg, sig, key, ph, ctx) {
    // EdDSA Verification (with cofactor multiplication).
    //
    // [EDDSA] Page 15, Section 5.
    // [RFC8032] Page 8, Section 3.4.
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a byte array of arbitrary size.
    //   - Let `R` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - s < n.
    //
    // Computation:
    //
    //   e = H(R, A, m) mod n
    //   (G * s) * h == (R + A * e) * h
    //
    // Alternatively, we can compute:
    //
    //   R * h == G * (s * h) - (A * h) * e
    //
    // This allows us to make use of a
    // multi-exponentiation algorithm.
    const {n} = this.curve;
    const G = this.curve.g;
    const Rraw = sig.slice(0, this.curve.adjustedSize);
    const sraw = sig.slice(this.curve.adjustedSize);
    const R = this.curve.decodePoint(Rraw);
    const s = this.curve.decodeAdjusted(sraw);
    const A = this.curve.decodePoint(key);

    if (s.cmp(n) >= 0)
      return false;

    const e = this.hashChallenge(Rraw, key, msg, ph, ctx);
    const sh = this.curve.imulH(s);
    const Ah = A.mulH();
    const Rh = R.mulH();

    return G.mulAdd(sh, Ah.neg(), e).eq(Rh);
  }

  verifyBatch(batch, ph, ctx) {
    if (ctx == null)
      ctx = Buffer.alloc(0);

    assert(Array.isArray(batch));
    assert(ph == null || typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (sig.length !== this.curve.adjustedSize * 2)
        return false;

      if (key.length !== this.curve.adjustedSize)
        return false;
    }

    try {
      return this._verifyBatch(batch, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verifyBatch(batch, ph, ctx) {
    // EdDSA Batch Verification.
    //
    // [EDDSA] Page 16, Section 5.
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `R` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - Let `i` be the batch item index.
    //   - s < n.
    //   - a1 = 1 mod n.
    //
    // Computation:
    //
    //   ei = H(Ri, Ai, mi) mod n
    //   ai = random integer in [1,n-1]
    //   lhs = (si * ai + ...) * h mod n
    //   rhs = (Ri * h) * ai + (Ai * h) * (ei * ai mod n) + ...
    //   G * -lhs + rhs == O
    const {n} = this.curve;
    const G = this.curve.g;
    const points = new Array(1 + batch.length * 2);
    const coeffs = new Array(1 + batch.length * 2);
    const sum = new BN(0);

    this.rng.init(batch);

    points[0] = G;
    coeffs[0] = sum;

    for (let i = 0; i < batch.length; i++) {
      const [msg, sig, key] = batch[i];
      const Rraw = sig.slice(0, this.curve.adjustedSize);
      const sraw = sig.slice(this.curve.adjustedSize);
      const R = this.curve.decodePoint(Rraw);
      const s = this.curve.decodeAdjusted(sraw);
      const A = this.curve.decodePoint(key);

      if (s.cmp(n) >= 0)
        return false;

      const e = this.hashChallenge(Rraw, key, msg, ph, ctx);
      const a = this.rng.generate(i);
      const ea = e.mul(a).imod(n);

      sum.iadd(s.mul(a)).imod(n);

      points[1 + i * 2 + 0] = R.mulH();
      coeffs[1 + i * 2 + 0] = a;
      points[1 + i * 2 + 1] = A.mulH();
      coeffs[1 + i * 2 + 1] = ea;
    }

    this.curve.imulH(sum.ineg());

    return this.curve.mulAll(points, coeffs).isInfinity();
  }

  derive(pub, secret) {
    const scalar = this.privateKeyConvert(secret);
    return this.deriveWithScalar(pub, scalar);
  }

  deriveWithScalar(pub, scalar) {
    const A = this.curve.decodePoint(pub);
    const a = this.curve.decodeClamped(scalar);
    const P = A.mulBlind(a, rng);

    if (P.isInfinity())
      throw new Error('Invalid point.');

    return P.encode();
  }
}

/*
 * Hash
 */

class Hash {
  constructor(eddsa) {
    this.curve = eddsa.curve;
    // eslint-disable-next-line
    this.hash = new eddsa.hash();
  }

  init(ph, ctx) {
    assert(ph == null || typeof ph === 'boolean');
    assert(Buffer.isBuffer(ctx));

    if (ctx.length > 255)
      ctx = ctx.slice(0, 255);

    this.hash.init();

    if (this.curve.context || ph != null || ctx.length > 0) {
      if (this.curve.prefix)
        this.hash.update(this.curve.prefix);

      this.hash.update(byte(ph));
      this.hash.update(byte(ctx.length));
      this.hash.update(ctx);
    }

    return this;
  }

  update(data) {
    this.hash.update(data);
    return this;
  }

  final() {
    const hash = this.hash.final(this.curve.adjustedSize * 2);
    const num = BN.decode(hash, this.curve.endian);

    return num.imod(this.curve.n);
  }
}

/*
 * Helpers
 */

function byte(ch) {
  const buf = Buffer.alloc(1);
  buf[0] = ch & 0xff;
  return buf;
}

/*
 * Expose
 */

module.exports = EDDSA;
