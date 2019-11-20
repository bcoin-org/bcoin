/*!
 * schnorr.js - bip-schnorr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bip-schnorr:
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/schnorrsig
 *
 * Resources:
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
 *   https://github.com/ElementsProject/secp256k1-zkp
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/musig
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/schnorrsig
 */

'use strict';

const assert = require('bsert');
const rng = require('../random');
const BN = require('../bn.js');

/**
 * Schnorr
 */

class Schnorr {
  constructor(curve, hash) {
    this.curve = curve;
    this.hash = hash;
  }

  hashInt(...items) {
    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const item of items)
      h.update(item);

    const hash = h.final();
    const num = BN.decode(hash, this.curve.endian);

    return num.iumod(this.curve.n);
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(msg.length === this.hash.size);
    assert(key.length === this.curve.size);

    const N = this.curve.n;
    const G = this.curve.g;

    // Let k' = int(hash(bytes(d) || m)) mod n
    let k = this.hashInt(key, msg);

    // Fail if k' = 0.
    if (k.isZero())
      throw new Error('Signing failed (k\' = 0).');

    // Let R = k'*G.
    const R = G.mulBlind(k);

    // Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
    if (R.y.redJacobi() !== 1)
      k = N.sub(k).iumod(N);

    // Encode x(R).
    const Rraw = this.curve.encodeInt(R.getX());

    // The secret key d: an integer in the range 1..n-1.
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(N) >= 0)
      throw new Error('Invalid private key.');

    // Encode d*G.
    const Araw = G.mulBlind(a).encode();

    // Let e = int(hash(bytes(x(R)) || bytes(d*G) || m)) mod n.
    const e = this.hashInt(Rraw, Araw, msg);

    // Blinding factor (precomputed).
    const [b, bi] = this.curve.getBlinding();

    // ea := (e * a) mod n (unblinded)
    // ea := (b * a * e) mod n (blinded)
    const ea = b.mul(a).iumod(N)
                .imul(e).iumod(N);

    // s := (k + (e * a)) mod n (unblinded)
    // s := ((b * k + (b * a * e)) * b^-1) mod n (blinded)
    const S = b.mul(k).iumod(N)
               .iadd(ea).iumod(N)
               .imul(bi).iumod(N);

    // The signature is bytes(x(R)) || bytes(k + e*d mod n).
    return Buffer.concat([Rraw, this.curve.encodeScalar(S)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (msg.length !== this.hash.size)
      return false;

    if (sig.length !== this.curve.size * 2)
      return false;

    try {
      return this._verify(msg, sig, key);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    const P = this.curve.p;
    const N = this.curve.n;
    const G = this.curve.g;

    // Let r = int(sig[0:32]); fail if r >= p.
    // Let s = int(sig[32:64]); fail if s >= n.
    // Let P = point(pk); fail if point(pk) fails.
    const Rraw = sig.slice(0, this.curve.size);
    const Sraw = sig.slice(this.curve.size);
    const Rx = this.curve.decodeInt(Rraw);
    const S = this.curve.decodeScalar(Sraw);
    const A = this.curve.decodePoint(key);

    if (Rx.cmp(P) >= 0 || S.cmp(N) >= 0)
      return false;

    // Let e = int(hash(bytes(r) || bytes(P) || m)) mod n.
    const e = this.hashInt(Rraw, A.encode(), msg);

    // In concept, a schnorr sig can be validated with:
    //
    //   s*G == R + e*P
    //
    // But bip-schnorr optimizes for shamir's trick with:
    //
    //   r == x(s*G - e*P)
    //
    // This is even more necessary perf-wise since we only
    // encode the X coordinate as the R value (it avoids us
    // having to recalculate the Y coordinate).
    //
    // Note that we stay in the jacobian space here. This
    // avoids any unnecessary divisions by the Z coordinate.

    // Let R = s*G - e*P.
    // Fail if infinite(R) or jacobi(y(R)) != 1 or x(R) != r.
    const R = G.jmulAdd(S, A, N.sub(e).iumod(N));

    // Check for point at infinity.
    if (R.isInfinity())
      return false;

    // Check for quadratic residue in the jacobian space.
    // Optimized as `jacobi(y(R) * z(R)) == 1`.
    if (!R.hasQuadY())
      return false;

    // Check `x(R) == r` in the jacobian space.
    // Optimized as `x(R) == r * z(R)^2 mod p`.
    if (!R.eqX(Rx))
      return false;

    return true;
  }

  batchVerify(batch) {
    assert(Array.isArray(batch));

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (msg.length !== this.hash.size)
        return false;

      if (sig.length !== this.curve.size * 2)
        return false;
    }

    try {
      return this._batchVerify(batch);
    } catch (e) {
      return false;
    }
  }

  _batchVerify(batch) {
    const P = this.curve.p;
    const N = this.curve.n;
    const G = this.curve.g;
    const points = [];
    const coeffs = [];

    let sum = null;

    for (const [msg, sig, key] of batch) {
      // Let r = int(sigi[0:32]); fail if r >= p.
      // Let si = int(sigi[32:64]); fail if si >= n.
      // Let Pi = point(pki); fail if point(pki) fails.
      const Rraw = sig.slice(0, this.curve.size);
      const Sraw = sig.slice(this.curve.size);
      const Rx = this.curve.decodeInt(Rraw);
      const S = this.curve.decodeScalar(Sraw);
      const A = this.curve.decodePoint(key);

      if (Rx.cmp(P) >= 0 || S.cmp(N) >= 0)
        return false;

      // Let ei = int(hash(bytes(r) || bytes(Pi) || mi)) mod n.
      const e = this.hashInt(Rraw, A.encode(), msg);

      // Let c = (r^3 + 7) mod p.
      // Let y = c^((p+1)/4) mod p.
      // Fail if c != y^2 mod p.
      // Let Ri = (r, y).
      const R = this.curve.pointFromR(Rx);

      // Let lhs = s1 + a2*s2 + ... + au*su.
      // Let rhs = R1 + a2*R2 + ... + au*Ru
      //         + e1*P1 + (a2*e2)P2 + ... + (au*eu)Pu.
      if (sum === null) {
        sum = S;
        points.push(R, A);
        coeffs.push(new BN(1), e);
        continue;
      }

      // Generate u-1 random integers a2...u in the range 1...n-1.
      const a = BN.random(rng, 1, N);
      const ea = e.imul(a).iumod(N);

      sum.iadd(S.imul(a)).iumod(N);
      points.push(R, A);
      coeffs.push(a, ea);
    }

    if (sum === null)
      return true;

    // Fail if lhs*G != rhs.
    const lhs = G.jmul(sum);
    const rhs = this.curve.jmulAll(points, coeffs);

    return lhs.eq(rhs);
  }
}

/*
 * Expose
 */

module.exports = Schnorr;
