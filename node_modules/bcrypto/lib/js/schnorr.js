/*!
 * schnorr.js - bip340 for bcrypto
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on bips/bip-0340:
 *   Copyright (c) 2018-2020, Pieter Wuille (2-clause BSD License).
 *   https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/bitcoin-core/secp256k1
 *
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 *   https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py
 *   https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
 *
 * References:
 *
 *   [BIP340] Schnorr Signatures for secp256k1
 *     Pieter Wuille, Jonas Nick, Tim Ruffing
 *     https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 */

'use strict';

const assert = require('../internal/assert');
const BatchRNG = require('./batch-rng');
const BN = require('../bn');
const rng = require('../random');
const SHA256 = require('../sha256');
const SHAKE256 = require('../shake256');
const elliptic = require('./elliptic');
const pre = require('./precomputed/secp256k1.json');

/**
 * Schnorr
 */

class Schnorr {
  constructor(name, hash, pre) {
    assert(typeof name === 'string');
    assert(hash);

    this.id = name;
    this.type = 'schnorr';
    this.hash = hash;
    this.native = 0;

    this._pre = pre || null;
    this._curve = null;
    this._rng = null;
    this._auxTag = null;
    this._nonceTag = null;
    this._challengeTag = null;
  }

  get curve() {
    if (!this._curve) {
      this._curve = elliptic.curve(this.id, this._pre);
      this._curve.precompute(rng);
      this._pre = null;
    }

    return this._curve;
  }

  get rng() {
    if (!this._rng)
      this._rng = new BatchRNG(this.curve);

    return this._rng;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  hashInt(...items) {
    // [BIP340] "Specification".
    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const item of items)
      h.update(item);

    let hash = h.final(this.curve.scalarSize);

    if (hash.length > this.curve.scalarSize)
      hash = hash.slice(0, this.curve.scalarSize);

    const num = BN.decode(hash, this.curve.endian);

    num.iumaskn(this.curve.scalarBits);

    return num.imod(this.curve.n);
  }

  hashAux(a, d) {
    assert(Buffer.isBuffer(a));
    assert(Buffer.isBuffer(d));
    assert(a.length === this.curve.scalarSize);
    assert(d.length === 32);

    if (!this._auxTag)
      this._auxTag = createTag(this.hash, 'BIP0340/aux');

    // eslint-disable-next-line
    const h = new this.hash();

    h.init();
    h.update(this._auxTag);
    h.update(d);

    const hash = h.final(this.curve.scalarSize);
    const t = Buffer.alloc(this.curve.scalarSize);

    for (let i = 0; i < this.curve.scalarSize; i++)
      t[i] = a[i] ^ hash[i];

    return t;
  }

  hashNonce(a, A, m, d) {
    if (!this._nonceTag)
      this._nonceTag = createTag(this.hash, 'BIP0340/nonce');

    if (d == null)
      return this.hashInt(this._nonceTag, a, A, m);

    return this.hashInt(this._nonceTag, this.hashAux(a, d), A, m);
  }

  hashChallenge(R, A, m) {
    if (!this._challengeTag)
      this._challengeTag = createTag(this.hash, 'BIP0340/challenge');

    return this.hashInt(this._challengeTag, R, A, m);
  }

  privateKeyGenerate() {
    const a = this.curve.randomScalar(rng);
    return this.curve.encodeScalar(a);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let a;
    try {
      a = this.curve.decodeScalar(key);
    } catch (e) {
      return false;
    }

    return !a.isZero() && a.cmp(this.curve.n) < 0;
  }

  privateKeyExport(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    let A = this.curve.g.mul(a);

    if (!A.isEven()) {
      a.ineg().imod(this.curve.n);
      A = A.neg();
    }

    return {
      d: this.curve.encodeScalar(a),
      x: this.curve.encodeField(A.x.fromRed()),
      y: this.curve.encodeField(A.y.fromRed())
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');

    const a = BN.decode(json.d, this.curve.endian);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(a);
  }

  privateKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mul(a);

    if (!A.isEven())
      a.ineg().imod(this.curve.n);

    const k = a.add(t).imod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(k);
  }

  privateKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.mul(t).imod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(k);
  }

  privateKeyInvert(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.invert(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  publicKeyCreate(key) {
    // [BIP340] "Public Key Generation".
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mulBlind(a);

    return A.encodeX();
  }

  publicKeyFromUniform(bytes) {
    const u = this.curve.decodeUniform(bytes);
    const A = this.curve.pointFromUniform(u);

    return A.encodeX();
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    const A = this.curve.decodeEven(key);
    const u = this.curve.pointToUniform(A, hint);

    return this.curve.encodeUniform(u, hint >>> 8);
  }

  publicKeyFromHash(bytes) {
    const A = this.curve.pointFromHash(bytes);
    return A.encodeX();
  }

  publicKeyToHash(key) {
    const A = this.curve.decodeEven(key);
    return this.curve.pointToHash(A, 0, rng);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodeEven(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyExport(key) {
    const {x, y} = this.curve.decodeEven(key);

    return {
      x: this.curve.encodeField(x.fromRed()),
      y: this.curve.encodeField(y.fromRed())
    };
  }

  publicKeyImport(json) {
    assert(json && typeof json === 'object');

    const x = BN.decode(json.x, this.curve.endian);

    if (x.cmp(this.curve.p) >= 0)
      throw new Error('Invalid point.');

    if (json.y != null) {
      const y = BN.decode(json.y, this.curve.endian);

      if (y.cmp(this.curve.p) >= 0)
        throw new Error('Invalid point.');

      const A = this.curve.point(x, y);

      if (!A.validate())
        throw new Error('Invalid point.');

      return A.encodeX();
    }

    const A = this.curve.pointFromX(x);

    return A.encodeX();
  }

  publicKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodeEven(key);
    const T = this.curve.g.jmul(t);
    const P = T.add(A);

    return P.encodeX();
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodeEven(key);
    const P = A.mul(t);

    return P.encodeX();
  }

  publicKeyTweakSum(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodeEven(key);
    const T = this.curve.g.jmul(t);
    const P = T.add(A);

    return [P.encodeX(), P.isOdd()];
  }

  publicKeyTweakCheck(key, tweak, expect, negated) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(Buffer.isBuffer(expect));
    assert(typeof negated === 'boolean');

    let point, sign;

    try {
      [point, sign] = this.publicKeyTweakSum(key, tweak);
    } catch (e) {
      return false;
    }

    return point.equals(expect) && sign === negated;
  }

  publicKeyCombine(keys) {
    assert(Array.isArray(keys));

    let P = this.curve.jpoint();

    for (const key of keys) {
      const A = this.curve.decodeEven(key);

      P = P.add(A);
    }

    return P.encodeX();
  }

  sign(msg, key, aux = rng.randomBytes(32)) {
    assert(Buffer.isBuffer(msg));

    if (aux != null) {
      assert(Buffer.isBuffer(aux));
      assert(aux.length === 32);
    }

    return this._sign(msg, key, aux);
  }

  _sign(msg, key, aux) {
    // Schnorr Signing.
    //
    // [BIP340] "Default Signing".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `a` be a secret non-zero scalar.
    //   - Let `d` be a 32-byte array.
    //   - k != 0.
    //
    // Computation:
    //
    //   A = G * a
    //   a = -a mod n, if y(A) is not even
    //   x = x(A)
    //   t = a xor H("BIP0340/aux", d)
    //   k = H("BIP0340/nonce", t, x, m) mod n
    //   R = G * k
    //   k = -k mod n, if y(R) is not even
    //   r = x(R)
    //   e = H("BIP0340/challenge", r, x, m) mod n
    //   s = (k + e * a) mod n
    //   S = (r, s)
    //
    // Note that `k` must remain secret,
    // otherwise an attacker can compute:
    //
    //   a = (s - k) / e mod n
    const {n} = this.curve;
    const G = this.curve.g;
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(n) >= 0)
      throw new Error('Invalid private key.');

    const A = G.mulBlind(a);

    if (!A.isEven())
      a.ineg().imod(n);

    const araw = this.curve.encodeScalar(a);
    const Araw = A.encodeX();
    const k = this.hashNonce(araw, Araw, msg, aux);

    if (k.isZero())
      throw new Error('Signing failed (k\' = 0).');

    const R = G.mulBlind(k);

    if (!R.isEven())
      k.ineg().imod(n);

    const Rraw = R.encodeX();
    const e = this.hashChallenge(Rraw, Araw, msg);
    const s = k.add(e.mul(a)).imod(n);

    return Buffer.concat([Rraw, this.curve.encodeScalar(s)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.curve.fieldSize + this.curve.scalarSize)
      return false;

    if (key.length !== this.curve.fieldSize)
      return false;

    try {
      return this._verify(msg, sig, key);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key) {
    // Schnorr Verification.
    //
    // [BIP340] "Verification".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `r` and `s` be signature elements.
    //   - Let `x` be a field element.
    //   - r^3 + a * r + b is square in F(p).
    //   - x^3 + a * x + b is square in F(p).
    //   - sqrt(r^3 + a * r + b) is even in F(p).
    //   - sqrt(x^3 + a * x + b) is even in F(p).
    //   - r < p, s < n, x < p.
    //   - R != O.
    //
    // Computation:
    //
    //   R = (r, sqrt(r^3 + a * r + b))
    //   A = (x, sqrt(x^3 + a * x + b))
    //   e = H("BIP0340/challenge", r, x, m) mod n
    //   R == G * s - A * e
    //
    // We can skip a square root with:
    //
    //   A = (x, sqrt(x^3 + a * x + b))
    //   e = H("BIP0340/challenge", r, x, m) mod n
    //   R = G * s - A * e
    //   y(R) is even
    //   x(R) == r
    const {p, n} = this.curve;
    const G = this.curve.g;
    const Rraw = sig.slice(0, this.curve.fieldSize);
    const sraw = sig.slice(this.curve.fieldSize);
    const r = this.curve.decodeField(Rraw);
    const s = this.curve.decodeScalar(sraw);
    const A = this.curve.decodeEven(key);

    if (r.cmp(p) >= 0 || s.cmp(n) >= 0)
      return false;

    const e = this.hashChallenge(Rraw, key, msg);
    const R = G.mulAdd(s, A, e.ineg().imod(n));

    if (!R.isEven())
      return false;

    if (!R.eqX(r))
      return false;

    return true;
  }

  verifyBatch(batch) {
    assert(Array.isArray(batch));

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (sig.length !== this.curve.fieldSize + this.curve.scalarSize)
        return false;

      if (key.length !== this.curve.fieldSize)
        return false;
    }

    try {
      return this._verifyBatch(batch);
    } catch (e) {
      return false;
    }
  }

  _verifyBatch(batch) {
    // Schnorr Batch Verification.
    //
    // [BIP340] "Batch Verification".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `r` and `s` be signature elements.
    //   - Let `x` be a field element.
    //   - Let `i` be the batch item index.
    //   - r^3 + a * r + b is square in F(p).
    //   - x^3 + a * x + b is square in F(p).
    //   - sqrt(r^3 + a * r + b) is even in F(p).
    //   - sqrt(x^3 + a * x + b) is even in F(p).
    //   - r < p, s < n, x < p.
    //   - a1 = 1 mod n.
    //
    // Computation:
    //
    //   Ri = (ri, sqrt(ri^3 + a * ri + b))
    //   Ai = (xi, sqrt(xi^3 + a * xi + b))
    //   ei = H("BIP0340/challenge", ri, xi, mi) mod n
    //   ai = random integer in [1,n-1]
    //   lhs = si * ai + ... mod n
    //   rhs = Ri * ai + Ai * (ei * ai mod n) + ...
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
      const Rraw = sig.slice(0, this.curve.fieldSize);
      const sraw = sig.slice(this.curve.fieldSize);
      const R = this.curve.decodeEven(Rraw);
      const s = this.curve.decodeScalar(sraw);
      const A = this.curve.decodeEven(key);

      if (s.cmp(n) >= 0)
        return false;

      const e = this.hashChallenge(Rraw, key, msg);
      const a = this.rng.generate(i);
      const ea = e.mul(a).imod(n);

      sum.iadd(s.mul(a)).imod(n);

      points[1 + i * 2 + 0] = R;
      coeffs[1 + i * 2 + 0] = a;
      points[1 + i * 2 + 1] = A;
      coeffs[1 + i * 2 + 1] = ea;
    }

    sum.ineg().imod(n);

    return this.curve.jmulAll(points, coeffs).isInfinity();
  }

  derive(pub, priv) {
    const A = this.curve.decodeEven(pub);
    const a = this.curve.decodeScalar(priv);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const P = A.mulConst(a, rng);

    return P.encodeX();
  }
}

/*
 * Helpers
 */

function createTag(alg, tag) {
  // [BIP340] "Tagged Hashes".
  const raw = Buffer.from(tag, 'binary');

  let hash;

  if (alg.size !== alg.blockSize / 2)
    hash = SHAKE256.digest(raw, alg.blockSize / 2);
  else
    hash = alg.digest(raw);

  return Buffer.concat([hash, hash]);
}

/*
 * Expose
 */

module.exports = new Schnorr('SECP256K1', SHA256, pre);
