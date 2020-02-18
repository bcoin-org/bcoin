/*!
 * schnorr-legacy.js - legacy bip-schnorr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bip-schnorr:
 *   Copyright (c) 2018-2019, Pieter Wuille (2-clause BSD License).
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/reference.py
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/ElementsProject/secp256k1-zkp
 *
 * Resources:
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/test-vectors.csv
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/11af701/src/modules/schnorrsig
 *   https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/2019-05-15-schnorr.md
 *
 * References:
 *
 *   [SCHNORR] Schnorr Signatures for secp256k1
 *     Pieter Wuille
 *     https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki
 *
 *   [CASH] Schnorr Signature specification
 *     Mark B. Lundeberg
 *     https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/2019-05-15-schnorr.md
 */

'use strict';

const assert = require('../internal/assert');
const BN = require('../bn');
const ChaCha20 = require('../chacha20');

/**
 * Schnorr
 */

class Schnorr {
  constructor(curve, hash) {
    this.curve = curve;
    this.hash = hash;
    this.msgSize = 32;
    this.sigSize = this.curve.fieldSize + this.curve.scalarSize;
    this.supported = this.support();
    this.rng = new RNG(this);
  }

  support() {
    // Support Testing.
    //
    // [SCHNORR] "Footnotes".
    //
    // In order for BIP-Schnorr's quadratic residue trick
    // to work, `-1 mod p` must _not_ be a quadratic residue.
    //
    // Furthermore, BIP-Schnorr also assumes a point's sign is
    // the result of the square root formula: c^((p + 1) / 4),
    // meaning the prime must be congruent to 3 mod 4.
    return this.curve.one.redNeg().redJacobi() === -1
        && this.curve.p.andln(3) === 3;
  }

  check() {
    if (!this.supported)
      throw new Error(`Schnorr is not supported for ${this.curve.id}.`);
  }

  encode(key) {
    assert(Buffer.isBuffer(key));

    // Extra speedy key reserialization.
    // This function assumes the key
    // has already been validated.
    const {fieldSize} = this.curve;

    if (key.length === 1 + fieldSize)
      return key;

    if (key.length !== 1 + fieldSize * 2)
      throw new Error('Invalid point.');

    const out = Buffer.allocUnsafe(1 + fieldSize);

    out[0] = 0x02 | (key[key.length - 1] & 1);
    key.copy(out, 1, 1, 1 + fieldSize);

    return out;
  }

  hashInt(x, y, z) {
    const hash = this.hash.multi(x, y, z);
    const num = BN.decode(hash, this.curve.endian);
    return num.imod(this.curve.n);
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(msg.length === this.msgSize);

    this.check();

    return this._sign(msg, key);
  }

  _sign(msg, key) {
    // Schnorr Signing.
    //
    // [SCHNORR] "Signing".
    // [CASH] "Recommended practices for secure signature generation".
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
    //   k = H(a, m) mod n
    //   R = G * k
    //   k = -k mod n, if y(R) is not square
    //   r = x(R)
    //   e = H(r, A, m) mod n
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
    const k = this.hashInt(key, msg);

    if (k.isZero())
      throw new Error('Signing failed (k\' = 0).');

    const R = G.mulBlind(k);

    if (!R.hasQuadY())
      k.ineg().imod(n);

    const Rraw = R.encodeX();
    const Araw = A.encode();
    const e = this.hashInt(Rraw, Araw, msg);
    const s = k.add(e.mul(a)).imod(n);

    return Buffer.concat([Rraw, this.curve.encodeScalar(s)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    this.check();

    if (msg.length !== this.msgSize)
      return false;

    if (sig.length !== this.sigSize)
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
    // [CASH] "Signature verification algorithm".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `r` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - r^3 + a * r + b is square in F(p).
    //   - r < p, s < n.
    //   - R != O.
    //
    // Computation:
    //
    //   R = (r, sqrt(r^3 + a * r + b))
    //   e = H(r, A, m) mod n
    //   R == G * s - A * e
    //
    // We can skip a square root with:
    //
    //   e = H(r, A, m) mod n
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
    const A = this.curve.decodePoint(key);

    if (r.cmp(p) >= 0 || s.cmp(n) >= 0)
      return false;

    const e = this.hashInt(Rraw, this.encode(key), msg);
    const R = G.jmulAdd(s, A, e.ineg().imod(n));

    if (!R.hasQuadY())
      return false;

    if (!R.eqX(r))
      return false;

    return true;
  }

  verifyBatch(batch) {
    assert(Array.isArray(batch));

    this.check();

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (msg.length !== this.msgSize)
        return false;

      if (sig.length !== this.sigSize)
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
    //   - Let `A` be a valid group element.
    //   - Let `i` be the batch item index.
    //   - r^3 + a * r + b is square in F(p).
    //   - r < p, s < n.
    //   - a1 = 1 mod n.
    //
    // Computation:
    //
    //   Ri = (ri, sqrt(ri^3 + a * ri + b))
    //   ei = H(ri, Ai, mi) mod n
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
      const R = this.curve.decodeX(Rraw);
      const s = this.curve.decodeScalar(sraw);
      const A = this.curve.decodePoint(key);

      if (s.cmp(n) >= 0)
        return false;

      const e = this.hashInt(Rraw, this.encode(key), msg);
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
}

/**
 * RNG (designed to mimic the libsecp256k1-zkp CSPRNG)
 * @see https://github.com/ElementsProject/secp256k1-zkp/blob/11af701/src/modules/schnorrsig/main_impl.h#L166
 * @see https://github.com/ElementsProject/secp256k1-zkp/blob/11af701/src/scalar_4x64_impl.h#L972
 * @see https://github.com/ElementsProject/secp256k1-zkp/blob/11af701/src/scalar_8x32_impl.h#L747
 */

class RNG {
  constructor(schnorr) {
    this.curve = schnorr.curve;
    this.hash = schnorr.hash;
    this.encode = schnorr.encode.bind(schnorr);
    this.chacha = new ChaCha20();
    this.key = Buffer.alloc(32, 0x00);
    this.iv = Buffer.alloc(8, 0x00);
    this.cache = [new BN(1), new BN(1)];
  }

  init(batch) {
    assert(Array.isArray(batch));

    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const [msg, sig, key] of batch) {
      h.update(sig);
      h.update(msg);
      h.update(this.encode(key));
    }

    let key = h.final();

    if (key.length > 32)
      key = key.slice(0, 32);

    assert(key.length === 32);

    this.key = key;
    this.cache[0] = new BN(1);
    this.cache[1] = new BN(1);

    return this;
  }

  encrypt(counter) {
    const size = (this.curve.scalarSize * 2 + 3) & -4;
    const data = Buffer.alloc(size, 0x00);
    const left = data.slice(0, this.curve.scalarSize);
    const right = data.slice(this.curve.scalarSize);

    this.chacha.init(this.key, this.iv, counter);
    this.chacha.encrypt(data);

    // Swap endianness of each 32 bit int. This should
    // match the behavior of libsecp256k1-zkp exactly.
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
 * Expose
 */

module.exports = Schnorr;
