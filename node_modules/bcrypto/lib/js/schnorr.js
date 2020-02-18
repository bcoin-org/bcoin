/*!
 * schnorr.js - bip-schnorr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bip-schnorr:
 *   Copyright (c) 2018-2019, Pieter Wuille (2-clause BSD License).
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/ElementsProject/secp256k1-zkp
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/bitcoin-core/secp256k1
 *
 * Resources:
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
 *   https://github.com/bitcoin-core/secp256k1/pull/558
 *   https://github.com/jonasnick/secp256k1/blob/schnorrsig/src/secp256k1.c
 *   https://github.com/jonasnick/secp256k1/blob/schnorrsig/src/modules/schnorrsig/main_impl.h
 *
 * References:
 *
 *   [SCHNORR] Schnorr Signatures for secp256k1
 *     Pieter Wuille
 *     https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 */

'use strict';

const assert = require('../internal/assert');
const BN = require('../bn');
const ChaCha20 = require('../chacha20');
const rng = require('../random');
const SHA256 = require('../sha256');
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
    this._deriveTag = null;
    this._schnorrTag = null;
  }

  get curve() {
    if (!this._curve) {
      this._curve = elliptic.curve(this.id, this._pre);
      this._curve.precompute(rng);
      this._pre = null;

      // Prime must be congruent to 3 mod 4.
      if (this._curve.p.andln(3) !== 3)
        throw new Error(`Schnorr is not supported for ${this.id}.`);
    }

    return this._curve;
  }

  get rng() {
    if (!this._rng)
      this._rng = new RNG(this);

    return this._rng;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  hashInt(...items) {
    // [SCHNORR] "Specification".
    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const item of items)
      h.update(item);

    const hash = h.final();
    const num = BN.decode(hash, this.curve.endian);

    return num.imod(this.curve.n);
  }

  hashDerive(a, m) {
    if (!this._deriveTag)
      this._deriveTag = createTag(this.hash, 'BIPSchnorrDerive');

    const key = this.curve.encodeScalar(a);

    return this.hashInt(this._deriveTag, key, m);
  }

  hashSchnorr(R, A, m) {
    if (!this._schnorrTag)
      this._schnorrTag = createTag(this.hash, 'BIPSchnorr');

    return this.hashInt(this._schnorrTag, R, A, m);
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

    let A = this.curve.g.jmul(a);

    if (!A.hasQuadY()) {
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

    const A = this.curve.g.jmul(a);

    if (!A.hasQuadY())
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

  privateKeyReduce(key) {
    assert(Buffer.isBuffer(key));

    if (key.length > this.curve.scalarSize)
      key = key.slice(0, this.curve.scalarSize);

    const a = BN.decode(key, this.curve.endian).imod(this.curve.n);

    if (a.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(a);
  }

  privateKeyInvert(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.invert(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  publicKeyCreate(key) {
    // [SCHNORR] "Public Key Generation".
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
    const A = this.curve.decodeX(key);
    const u = this.curve.pointToUniform(A, hint);

    return this.curve.encodeUniform(u, rng);
  }

  publicKeyFromHash(bytes) {
    const A = this.curve.pointFromHash(bytes);
    return A.encodeX();
  }

  publicKeyToHash(key) {
    const A = this.curve.decodeX(key);
    return this.curve.pointToHash(A, rng);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyExport(key) {
    const {x, y} = this.curve.decodeX(key);

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

    const A = this.curve.pointFromX(x);

    return A.encodeX();
  }

  publicKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodeX(key);
    const T = this.curve.g.jmul(t);
    const P = T.add(A);

    return P.encodeX();
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodeX(key);
    const P = A.mul(t);

    return P.encodeX();
  }

  publicKeyTweakTest(key, tweak, sign, test) {
    assert(Buffer.isBuffer(tweak));
    assert(typeof sign === 'boolean');

    if (!this.publicKeyVerify(key)
        || !this.publicKeyVerify(test)) {
      return false;
    }

    const P = this.curve.decodeX(key);
    const Q = this.curve.decodeX(test);
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      return false;

    const T = this.curve.g.mul(t);

    let Pt = P.add(T);

    if (sign)
      Pt = Pt.neg();

    return Pt.eq(Q);
  }

  publicKeyCombine(keys) {
    assert(Array.isArray(keys));

    let P = this.curve.jpoint();

    for (const key of keys) {
      const A = this.curve.decodeX(key);

      P = P.add(A);
    }

    return P.encodeX();
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(msg.length === 32);

    return this._sign(msg, key);
  }

  _sign(msg, key) {
    // Schnorr Signing.
    //
    // [SCHNORR] "Default Signing".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `a` be a secret non-zero scalar.
    //   - k != 0.
    //
    // Computation:
    //
    //   A = G * a
    //   a = -a mod n, if y(A) is not square
    //   k = H("BIPSchnorrDerive", a, m) mod n
    //   R = G * k
    //   k = -k mod n, if y(R) is not square
    //   r = x(R)
    //   x = x(A)
    //   e = H("BIPSchnorr", r, x, m) mod n
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

    if (!A.hasQuadY())
      a.ineg().imod(n);

    const k = this.hashDerive(a, msg);

    if (k.isZero())
      throw new Error('Signing failed (k\' = 0).');

    const R = G.mulBlind(k);

    if (!R.hasQuadY())
      k.ineg().imod(n);

    const Rraw = R.encodeX();
    const Araw = A.encodeX();
    const e = this.hashSchnorr(Rraw, Araw, msg);
    const s = k.add(e.mul(a)).imod(n);

    return Buffer.concat([Rraw, this.curve.encodeScalar(s)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (msg.length !== 32)
      return false;

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
    // [SCHNORR] "Verification".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `r` and `s` be signature elements.
    //   - Let `x` be a field element.
    //   - r^3 + a * r + b is square in F(p).
    //   - x^3 + a * x + b is square in F(p).
    //   - r < p, s < n, x < p.
    //   - R != O.
    //
    // Computation:
    //
    //   R = (r, sqrt(r^3 + a * r + b))
    //   A = (x, sqrt(x^3 + a * x + b))
    //   e = H("BIPSchnorr", r, x, m) mod n
    //   R == G * s - A * e
    //
    // We can skip a square root with:
    //
    //   A = (x, sqrt(x^3 + a * x + b))
    //   e = H("BIPSchnorr", r, x, m) mod n
    //   R = G * s - A * e
    //   y(R) is square
    //   x(R) == r
    //
    // We can also avoid affinization by
    // replacing the two assertions with:
    //
    //   (y(R) * z(R) mod p) is square
    //   x(R) == r * z(R)^2 mod p
    //
    // Furthermore, squareness can be calculated
    // with a variable time Jacobi symbol algorithm.
    const {p, n} = this.curve;
    const G = this.curve.g;
    const Rraw = sig.slice(0, this.curve.fieldSize);
    const sraw = sig.slice(this.curve.fieldSize);
    const r = this.curve.decodeField(Rraw);
    const s = this.curve.decodeScalar(sraw);
    const A = this.curve.decodeX(key);

    if (r.cmp(p) >= 0 || s.cmp(n) >= 0)
      return false;

    const e = this.hashSchnorr(Rraw, key, msg);
    const R = G.jmulAdd(s, A, e.ineg().imod(n));

    if (!R.hasQuadY())
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

      if (msg.length !== 32)
        return false;

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
    // [SCHNORR] "Batch Verification".
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
    //   - r < p, s < n, x < p.
    //   - a1 = 1 mod n.
    //
    // Computation:
    //
    //   Ri = (ri, sqrt(ri^3 + a * ri + b))
    //   Ai = (xi, sqrt(xi^3 + a * xi + b))
    //   ei = H("BIPSchnorr", ri, xi, mi) mod n
    //   ai = random integer in [1,n-1]
    //   lhs = si * ai + ... mod n
    //   rhs = Ri * ai + Ai * (ei * ai mod n) + ...
    //   G * -lhs + rhs == O
    const {n} = this.curve;
    const G = this.curve.g;
    const points = new Array(1 + batch.length * 2);
    const coeffs = new Array(1 + batch.length * 2);
    const sum = new BN(0);
    const keys = this.rng.init(batch);

    points[0] = G;
    coeffs[0] = sum;

    for (let i = 0; i < batch.length; i++) {
      const [msg, sig, key] = batch[i];
      const Rraw = sig.slice(0, this.curve.fieldSize);
      const sraw = sig.slice(this.curve.fieldSize);
      const R = this.curve.decodeX(Rraw);
      const s = this.curve.decodeScalar(sraw);
      const A = keys[i];

      if (s.cmp(n) >= 0)
        return false;

      const e = this.hashSchnorr(Rraw, key, msg);
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
    const A = this.curve.decodeX(pub);
    const a = this.curve.decodeScalar(priv);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const P = A.mulConst(a, rng);

    return P.encodeX();
  }
}

/**
 * RNG (designed to mimic the libsecp256k1 CSPRNG)
 * @see https://github.com/jonasnick/secp256k1/blob/1901f3b/src/modules/schnorrsig/main_impl.h#L178
 * @see https://github.com/jonasnick/secp256k1/blob/1901f3b/src/scalar_4x64_impl.h#L965
 * @see https://github.com/jonasnick/secp256k1/blob/1901f3b/src/scalar_8x32_impl.h#L736
 */

class RNG {
  constructor(schnorr) {
    this.curve = schnorr.curve;
    this.hash = schnorr.hash;
    this.chacha = new ChaCha20();
    this.key = Buffer.alloc(32, 0x00);
    this.iv = Buffer.alloc(8, 0x00);
    this.cache = [new BN(1), new BN(1)];
  }

  init(batch) {
    assert(Array.isArray(batch));

    // eslint-disable-next-line
    const h = new this.hash();
    const sign = Buffer.alloc(1);
    const keys = new Array(batch.length);

    h.init();

    for (let i = 0; i < batch.length; i++) {
      const [msg, sig, key] = batch[i];
      const A = this.curve.decodeX(key);

      sign[0] = 0x02 | A.sign();

      h.update(sig);
      h.update(msg);
      h.update(sign);
      h.update(key);

      keys[i] = A;
    }

    let key = h.final();

    if (key.length > 32)
      key = key.slice(0, 32);

    assert(key.length === 32);

    this.key = key;
    this.cache[0] = new BN(1);
    this.cache[1] = new BN(1);

    return keys;
  }

  encrypt(counter) {
    const size = (this.curve.scalarSize * 2 + 3) & -4;
    const data = Buffer.alloc(size, 0x00);
    const left = data.slice(0, this.curve.scalarSize);
    const right = data.slice(this.curve.scalarSize);

    this.chacha.init(this.key, this.iv, counter);
    this.chacha.encrypt(data);

    // Swap endianness of each 32 bit int. This should
    // match the behavior of libsecp256k1 exactly.
    for (let i = 0; i < size; i += 4) {
      [data[i + 0], data[i + 3]] = [data[i + 3], data[i + 0]];
      [data[i + 1], data[i + 2]] = [data[i + 2], data[i + 1]];
    }

    return [
      this.curve.decodeScalar(left),
      this.curve.decodeScalar(right)
    ];
  }

  refresh(counter) {
    let overflow = 0;

    for (;;) {
      // First word is always zero.
      this.iv[4] = overflow;
      this.iv[5] = overflow >>> 8;
      this.iv[6] = overflow >>> 16;
      this.iv[7] = overflow >>> 24;

      overflow += 1;

      const [s1, s2] = this.encrypt(counter);

      if (s1.isZero() || s1.cmp(this.curve.n) >= 0)
        continue;

      if (s2.isZero() || s2.cmp(this.curve.n) >= 0)
        continue;

      this.cache[0] = s1;
      this.cache[1] = s2;

      break;
    }
  }

  generate(index) {
    assert((index >>> 0) === index);

    if (index & 1)
      this.refresh(index >>> 1);

    return this.cache[index & 1];
  }
}

/*
 * Helpers
 */

function createTag(alg, tag) {
  // [SCHNORR] "Tagged Hashes".
  const raw = Buffer.from(tag, 'binary');
  const hash = alg.digest(raw);

  return Buffer.concat([hash, hash]);
}

/*
 * Expose
 */

module.exports = new Schnorr('SECP256K1', SHA256, pre);
