/*!
 * ristretto.js - ristretto encoding for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * References:
 *
 *   [DECAF] Decaf: Eliminating cofactors through point compression
 *     Mike Hamburg
 *     https://www.shiftleft.org/papers/decaf/decaf.pdf
 *
 *   [RIST] The Ristretto Group
 *     Henry de Valence, Isis Lovecruft, Tony Arcieri
 *     https://ristretto.group
 *
 *   [RIST255] The ristretto255 Group
 *     H. de Valence, J. Grigg, G. Tankersley, F. Valsorda, I. Lovecruft
 *     https://tools.ietf.org/html/draft-hdevalence-cfrg-ristretto-01
 *
 * Resources:
 *   https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage
 *   https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c
 *   https://git.zx2c4.com/goldilocks/tree/src/per_curve/elligator.tmpl.c
 *   https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs
 *   https://github.com/bwesterb/go-ristretto/blob/9343fcb/edwards25519/elligator.go
 */

'use strict';

const assert = require('../internal/assert');
const BN = require('../bn');

/**
 * Ristretto
 */

class Ristretto {
  constructor(curve) {
    // [RIST] "The Ristretto Group".
    //
    // Assumptions (h = 4):
    //
    //   - p = 3 (mod 4).
    //   - a = 1 mod p.
    //   - d is non-square in F(p).
    //
    // Assumptions (h = 8):
    //
    //   - p = 5 (mod 8).
    //   - a = -1 mod p.
    //   - d is non-square in F(p).
    //
    // No other parameters are acceptable.
    assert(curve != null);
    assert(curve.type === 'edwards');
    assert(curve.h.cmpn(4) === 0 || curve.h.cmpn(8) === 0);
    assert((curve.p.andln(3) === 3) === (curve.h.cmpn(4) === 0));
    assert((curve.p.andln(7) === 5) === (curve.h.cmpn(8) === 0));
    assert((curve.a.cmp(curve.one) === 0) === (curve.h.cmpn(4) === 0));
    assert((curve.a.cmp(curve.one.redNeg()) === 0) === (curve.h.cmpn(8) === 0));

    // Curve.
    this.curve = curve;

    // Point class.
    this.Point = curve.Point;

    // ad = a * d
    this.ad = this.curve._mulA(this.curve.d);

    // amd = a - d
    this.amd = this.curve.a.redSub(this.curve.d);

    // adm1s = sqrt(a * d - 1)
    this.adm1s = this.ad.redSub(this.curve.one).redSqrt();

    // adm1si = 1 / sqrt(a * d - 1)
    this.adm1si = this.adm1s.redInvert();

    // dpa = d + a
    this.dpa = this.curve.d.redAdd(this.curve.a);

    // dma = d - a
    this.dma = this.curve.d.redSub(this.curve.a);

    // dmaddpa = (d - a) / (d + a)
    this.dmaddpa = this.dma.redDiv(this.dpa);

    // h = 8
    if (this.curve.h.cmpn(8) === 0) {
      // qnr = sqrt(a)
      this.qnr = this.curve.a.redSqrt();

      // amdsi = 1 / sqrt(a - d) = 1 / sqrt(a * d - 1)
      this.amdsi = this.adm1si.clone();

      // dmasi = 1 / sqrt(d - a)
      this.dmasi = this.dma.redSqrt().redInvert();
    } else {
      // qnr = non-square in F(p).
      this.qnr = this.curve.z;

      // amdsi = 0 (unused)
      this.amdsi = this.curve.zero;

      // dmasi = 0 (unused)
      this.dmasi = this.curve.zero;
    }

    // qnrds = sqrt(qnr * d)
    this.qnrds = this.curve._mulD(this.qnr).redSqrt();

    // Flip signs.
    this._fix();
  }

  _fix() {
    // We flip some signs to perfectly replicate
    // the reference implementations' elligator
    // behavior.
    if (this.curve.id === 'ED25519'
        || this.curve.id === 'ISO448') {
      this.adm1s = this.adm1s.redNeg();
    }

    if (this.curve.id === 'ED25519'
        || this.curve.id === 'ED448'
        || this.curve.id === 'ED1174'
        || this.curve.id === 'E222'
        || this.curve.id === 'E382'
        || this.curve.id === 'E521'
        || this.curve.id === 'MDC') {
      this.adm1si = this.adm1si.redNeg();
    }
  }

  _invsqrt(v) {
    return this._isqrt(this.curve.one, v);
  }

  _isqrt(u, v) {
    // [RIST] "Extracting an Inverse Square Root".
    // [RIST255] Page 6, Section 3.1.3.
    let ok = true;
    let r;

    // R = sqrt(u / v)
    try {
      r = u.redDivSqrt(v);
    } catch ({result}) {
      r = result.toRed(this.curve.red);
      ok = false;
    }

    // R = -R if R < 0
    if (r.redIsOdd())
      r.redINeg();

    return [ok, r];
  }

  encode(p) {
    // [DECAF] Page 8, Section 4.2.
    //         Page 15, Appendix A.1.
    // [RIST] "Encoding from Extended Coordinates".
    // [RIST255] Page 8, Section 3.2.2.
    //
    // Affine Formula:
    //
    //   If h = 8 and x * y < 0 or x = 0 then (x, y) = (x, y) + Q
    //   If x < 0 or y = -1 then (x, y) = (-x, -y)
    //   s = +sqrt(-a * (1 - y) / (1 + y))
    //
    //   Where Q is a 4-torsion point.
    //
    // Note that the U1 calculation stated in the
    // formula is actually:
    //
    //   U1 = (Z0 + Y0) * (Z0 - Y0)
    //
    // The calculation of S stated in the formula is:
    //
    //   S = sqrt(-a) * (Z0 - Y) * D
    //
    // We move the `sqrt(-a)` in S to U1 with the
    // following modifications:
    //
    //   U1 = -a * (Z0 + Y0) * (Z0 - Y0)
    //   S = (Z0 - Y) * D
    assert(p instanceof this.Point);

    // U1 = -a * (Z0 + Y0) * (Z0 - Y0)
    const u1 = this.curve._mulA(p.y.redAdd(p.z).redMul(p.y.redSub(p.z)));

    // U2 = X0 * Y0
    const u2 = p.x.redMul(p.y);

    // I = 1 / sqrt(U1 * U2^2)
    const [, i] = this._invsqrt(u1.redMul(u2.redSqr()));

    // D1 = U1 * I
    const d1 = u1.redMul(i);

    // D2 = U2 * I
    const d2 = u2.redMul(i);

    // Zinv = D1 * D2 * T0
    const zinv = d1.redMul(d2).redMul(p.t);

    // X = X0
    const x = p.x.clone();

    // Y = Y0
    const y = p.y.clone();

    // D = D2
    const d = d2;

    // h = 8
    if (this.curve.h.cmpn(8) === 0) {
      // rotate = T0 * Zinv < 0
      if (p.t.redMul(zinv).redIsOdd()) {
        // X = Y0 * sqrt(a) if rotate
        x.inject(p.y.redMul(this.qnr));

        // Y = X0 * sqrt(a) if rotate
        y.inject(p.x.redMul(this.qnr));

        // D = D1 / sqrt(a - d) if rotate
        d.inject(d1.redMul(this.amdsi));
      }
    }

    // Y = -Y if X * Zinv < 0
    if (x.redMul(zinv).redIsOdd())
      y.redINeg();

    // S = (Z0 - Y) * D
    const s = d.redMul(p.z.redSub(y));

    // S = -S if S < 0
    if (s.redIsOdd())
      s.redINeg();

    // Return the byte encoding of S.
    return this.curve.encodeField(s.fromRed());
  }

  decode(bytes) {
    // [DECAF] Page 8, Section 4.3.
    //         Page 16, Appendix A.2.
    // [RIST] "Decoding to Extended Coordinates".
    // [RIST255] Page 7, Section 3.2.1.
    //
    // Assumptions:
    //
    //   - Let s be a canonically encoded field element.
    //   - s >= 0.
    //   - (4 * s^2 / (a * d * (1 + w)^2 - (1 - w)^2)) is square in F(p).
    //   - if h = 8 then t >= 0 and y != 0.
    //
    // Affine Formula:
    //
    //   y = (1 + a * s^2) / (1 - a * s^2)
    //   w = a * s^2
    //   x = +sqrt(4 * s^2 / (a * d * (1 + w)^2 - (1 - w)^2))
    const e = this.curve.decodeField(bytes);

    // Check for canonical encoding.
    if (e.cmp(this.curve.p) >= 0)
      throw new Error('Invalid point.');

    // Reduce.
    const s = e.toRed(this.curve.red);

    // Reject if S < 0.
    if (s.redIsOdd())
      throw new Error('Invalid point.');

    // AS2 = a * S^2
    const as2 = this.curve._mulA(s.redSqr());

    // U1 = 1 + a * S^2
    const u1 = this.curve.one.redAdd(as2);

    // U2 = 1 - a * S^2
    const u2 = this.curve.one.redSub(as2);

    // U2U2 = U2^2
    const u2u2 = u2.redSqr();

    // V = a * d * U1^2 - U2^2
    const v = this.ad.redMul(u1.redSqr()).redISub(u2u2);

    // I = 1 / sqrt(V * U2^2)
    const [sqr, i] = this._invsqrt(v.redMul(u2u2));

    // DX = I * U2
    const dx = u2.redMul(i);

    // DY = I * DX * V
    const dy = dx.redMul(v).redMul(i);

    // X = 2 * S * DX
    const x = s.redIAdd(s).redMul(dx);

    // X = -X if X < 0
    if (x.redIsOdd())
      x.redINeg();

    // Y = U1 * DY
    const y = u1.redMul(dy);

    // Z = 1
    const z = this.curve.one;

    // T = X * Y
    const t = x.redMul(y);

    // h = 4
    if (this.curve.h.cmpn(4) === 0) {
      // Reject if V * U2^2 is not square.
      if (!sqr)
        throw new Error('Invalid point.');

      // P = (X : Y : Z: T)
      return this.curve.point(x, y, z, t);
    }

    // Reject if V * U2^2 is not square or T < 0 or Y = 0.
    if (!sqr || t.redIsOdd() || y.isZero())
      throw new Error('Invalid point.');

    // P = (X : Y : Z : T)
    return this.curve.point(x, y, z, t);
  }

  encodeBatch(points) {
    // [DECAF] Page 9, Section 4.7.
    // [RIST] "Batched Double-and-Encode".
    //
    // Affine Formula:
    //
    //   e = 2 * x * y
    //   f = 1 + ((x * y)^2 * d)
    //   g = y^2 - a * x^2
    //   h = 1 - ((x * y)^2 * d)
    //
    //   if h = 8 and e * g / (f * h) < 0
    //     e = g, g = -e
    //     h = f * sqrt(a)
    //     magic = sqrt(a)
    //   else
    //     magic = 1 / sqrt(a - d) if h = 8
    //           = 1 / sqrt(a * d - 1) otherwise
    //
    //   g = -g if h * e / (f * h) < 0
    //   s = +((h - g) * magic * g / (e * g))
    //
    // The trick here is that the inverses can be
    // batched. Every product of (e * g * f * h)
    // can be inverted with montgomery's trick.
    // The necessary inverses can then be retrieved
    // from each value with:
    //
    //   (e * g) / (e * g * f * h) = 1 / (f * h)
    //   (f * h) / (e * g * f * h) = 1 / (e * g)
    assert(Array.isArray(points));

    for (const p of points)
      assert(p instanceof this.Point);

    const states = [];
    const products = [];

    // Set up state.
    for (const p of points) {
      // XX = X0^2
      const xx = p.x.redSqr();

      // YY = Y0^2
      const yy = p.y.redSqr();

      // ZZ = Z0^2
      const zz = p.z.redSqr();

      // DTT = T0^2 * d
      const dtt = p.t.redSqr().redMul(this.curve.d);

      // E = 2 * X0 * Y0
      const e = p.x.redMul(p.y.redAdd(p.y));

      // F = ZZ + DTT
      const f = zz.redAdd(dtt);

      // G = YY - a * XX
      const g = yy.redSub(this.curve._mulA(xx));

      // H = ZZ - DTT
      const h = zz.redSub(dtt);

      // EG = E * G
      const eg = e.redMul(g);

      // FH = F * H
      const fh = f.redMul(h);

      // EFGH = EG * FH
      const efgh = eg.redMul(fh);

      states.push([e, f, g, h, eg, fh]);
      products.push(efgh);
    }

    // Montgomery's trick.
    const invs = this.curve.red.invertAll(products);
    const out = [];

    // Output encoded points.
    for (let i = 0; i < states.length; i++) {
      const [e, f, g, h, eg, fh] = states[i];

      // Zinv = EG / EFGH
      const zinv = eg.redMul(invs[i]);

      // Tinv = FH / EFGH
      const tinv = fh.redMul(invs[i]);

      // magic = 1 / sqrt(a - d)
      const magic = this.amdsi.clone();

      // h = 8
      if (this.curve.h.cmpn(8) === 0) {
        // rotate = EG * Zinv < 0
        if (eg.redMul(zinv).redIsOdd()) {
          // ME = -E
          const me = e.redNeg();

          // FQNR = F * sqrt(a)
          const fqnr = f.redMul(this.qnr);

          // E = G if rotate
          e.inject(g);

          // G = ME if rotate
          g.inject(me);

          // H = FQNR if rotate
          h.inject(fqnr);

          // magic = sqrt(a) if rotate
          magic.inject(this.qnr);
        }
      } else {
        // magic = 1 / sqrt(a * d - 1)
        magic.inject(this.adm1si);
      }

      // G = -G if H * E * Zinv < 0
      if (h.redMul(e).redMul(zinv).redIsOdd())
        g.redINeg();

      // S = (H - G) * magic * G * Tinv
      const s = h.redSub(g).redMul(magic).redMul(g).redMul(tinv);

      // S = -S if S < 0
      if (s.redIsOdd())
        s.redINeg();

      // Output the byte encoding of S.
      out.push(this.curve.encodeField(s.fromRed()));
    }

    return out;
  }

  eq(p, q) {
    // [DECAF] Page 9, Section 4.5.
    // [RIST] "Testing Equality".
    // [RIST255] Page 9, Section 3.2.3.
    //
    // Affine Formula (h = 4):
    //
    //   x1 * y2 = y1 * x2
    //
    // Affine Formula (h = 8):
    //
    //   x1 * y2 = y1 * x2 or
    //   y1 * y2 = -a * x1 * x2
    assert(p instanceof this.Point);
    assert(q instanceof this.Point);

    // XY = X1 * Y2
    const xy = p.x.redMul(q.y);

    // YX = Y1 * X2
    const yx = p.y.redMul(q.x);

    // X1 * Y2 = Y1 * X2
    if (xy.eq(yx))
      return true;

    // h = 8
    if (this.curve.h.cmpn(8) === 0) {
      // YY = Y1 * Y2
      const yy = p.y.redMul(q.y);

      // XX = -a * X1 * X2
      const xx = p.x.redMul(q.x);

      // Y1 * Y2 = -a * X1 * X2
      if (yy.eq(xx))
        return true;
    }

    return false;
  }

  isInfinity(p) {
    // See above for references.
    //
    // Affine Formula (h = 4):
    //
    //   x = 0
    //
    // Affine Formula (h = 8):
    //
    //   x = 0 or y = 0
    assert(p instanceof this.Point);

    // X1 = 0
    if (p.x.isZero())
      return true;

    // h = 8
    if (this.curve.h.cmpn(8) === 0) {
      // Y1 = 0
      if (p.y.isZero())
        return true;
    }

    return false;
  }

  pointFromUniform(r0) {
    // [DECAF] Page 12, Section 6.
    //         Page 19, Appendix C.
    // [RIST] "Elligator in Extended Coordinates".
    // [RIST255] Page 10, Section 3.2.4.
    //
    // Affine Formula:
    //
    //   w = (d * r - a) * (a * r - d)
    //   s = +sqrt((a * (r + 1) * (d + a) * (d - a)) / w
    //   t = +(a * (r - 1) * (d + a)^2) / w - 1
    //
    // Or:
    //
    //   w = (d * r - a) * (a * r - d)
    //   s = -sqrt((a * r * (r + 1) * (d + a) * (d - a)) / w
    //   t = -(a * r * (r - 1) * (d + a)^2) / w - 1
    //
    // Depending on which square root exists, preferring
    // the second when r = 0 or both are square.
    assert(r0 instanceof BN);

    // R = qnr * R0^2
    const r = this.qnr.redMul(r0.redSqr());

    // AR1 = a * (R + 1)
    const ar1 = this.curve._mulA(r.redAdd(this.curve.one));

    // NS = a * (R + 1) * (d + a) * (d - a)
    const ns = ar1.redMul(this.dpa).redMul(this.dma);

    // C = -1
    const c = this.curve.one.redNeg();

    // DRA = d * R - a
    const dra = this.curve._mulD(r).redISub(this.curve.a);

    // ARD = a * R - d
    const ard = this.curve._mulA(r).redISub(this.curve.d);

    // D = (d * R - a) * (a * R - d)
    const d = dra.redMul(ard);

    // S = sqrt(NS / D)
    const [sqr, s] = this._isqrt(ns, d);

    // S' = S * R0
    const sp = s.redMul(r0);

    // S' = -S' if S' >= 0
    if (!sp.redIsOdd())
      sp.redINeg();

    if (!sqr) {
      // S = S' if NS / D is not square
      s.inject(sp);

      // C = R if NS / D is not square
      c.inject(r);
    }

    // DS = (d + a)^2
    const ds = this.dpa.redSqr();

    // NT = C * (R - 1) * (d + a)^2 - D
    const nt = c.redMul(r.redSub(this.curve.one)).redMul(ds).redISub(d);

    // AS2 = a * S^2
    const as2 = this.curve._mulA(s.redSqr());

    // W0 = 2 * S * D
    const w0 = s.redAdd(s).redMul(d);

    // W1 = NT * sqrt(a * d - 1)
    const w1 = nt.redMul(this.adm1s);

    // W2 = 1 + a * S^2
    const w2 = this.curve.one.redAdd(as2);

    // W3 = 1 - a * S^2
    const w3 = this.curve.one.redSub(as2);

    // X = W0 * W3
    const x = w0.redMul(w3);

    // Y = W2 * W1
    const y = w2.redMul(w1);

    // Z = W1 * W3
    const z = w1.redMul(w3);

    // T = W0 * W2
    const t = w0.redMul(w2);

    // P = (X : Y : Z : T)
    return this.curve.point(x, y, z, t);
  }

  pointToUniform(p, hint) {
    // [RIST] "Isogenies".
    //
    // Convert a ristretto group element to a field
    // element by inverting the ristretto-flavored
    // elligator.
    //
    // Hint Layout:
    //
    //   [00000000] 000[0] [0000]
    //        |         |     |
    //        |         |     +-- index for jacobi quartic point
    //        |         +-- sign bit
    //        +-- bits to OR with uniform bytes
    //
    // In order to invert the ristretto elligator, we
    // must first first map the edwards point to an
    // isogenous jacobi quartic curve.
    //
    // Isogeny: E(a,d) -> J(a^2,a-2d)
    //
    // This gives us a maximum of `h` possible points
    // to work with in the jacobi quartic space.
    //
    // After a jacobi quartic point is chosen, it is
    // run through the inverse elligator 2 map, and
    // oddness is set according to the sign in the
    // hint.
    //
    // Note that the upper half of all jacobi quartic
    // points will be the negations of the lower half.
    assert(p instanceof this.Point);
    assert((hint >>> 0) === hint);

    const sign = (hint >>> 4) & 15;
    const index = hint & 15;
    const Q = this._quartic(p);
    const len = Q.length;

    for (let i = 0; i < len; i++) {
      const [s, t] = Q[i];

      Q.push([s.redNeg(), t.redNeg()]);
    }

    const [s, t] = Q[index % Q.length];

    return this._invert(s, t, sign);
  }

  _quartic(p) {
    // [DECAF] Page 7, Section 4.1.
    // [RIST] "Isogenies".
    //
    // Affine Formula:
    //
    //   g = sqrt(y^4 * x^2 * (1 - y^2))
    //
    //   d1 = y^2 / g
    //   s1 = d1 * (1 - y) * x
    //   t1 = 2 * d1 * (1 - y) / sqrt(a * d - 1)
    //   s2 = -d1 * (1 + y) * x
    //   t2 = 2 * d1 * (1 + y) / sqrt(a * d - 1)
    //
    //   if h = 8
    //     d2 = -(1 - y^2) / (g * sqrt(d - a))
    //     s3 = d2 * (sqrt(a) - x) * y
    //     t3 = 2 * d2 * (sqrt(a) - x) * sqrt(a) / sqrt(a * d - 1)
    //     s4 = -d2 * (sqrt(a) + x) * y
    //     t4 = 2 * d2 * (sqrt(a) + x) * sqrt(a) / sqrt(a * d - 1)
    //
    // Undefined for x = 0 or y = 0.
    //
    // The exceptional cases must be handled as:
    //
    //   (s1, t1) = (0, 1)
    //   (s2, t2) = (0, 1)
    //   (s3, t3) = (+1, 2 * sqrt(a) / sqrt(a * d - 1))
    //   (s4, t4) = (-1, 2 * sqrt(a) / sqrt(a * d - 1))
    assert(p instanceof this.Point);

    const {zero, one} = this.curve;
    const {x, y, z} = p;

    // X2 = X0^2
    const x2 = x.redSqr();

    // Y2 = Y0^2
    const y2 = y.redSqr();

    // Y4 = Y2^2
    const y4 = y2.redSqr();

    // Z2 = Z0^2
    const z2 = z.redSqr();

    // Z2MY2 = Z2 - Y2
    const z2my2 = z2.redSub(y2);

    // G = 1 / sqrt(Y4 * X2 * Z2MY2)
    const [, g] = this._invsqrt(y4.redMul(x2).redMul(z2my2));

    // D0 = G * Y0^2
    const d0 = g.redMul(y2);

    // SX = D0 * (Z0 - Y0)
    const sx = d0.redMul(z.redSub(y));

    // SPXP = D0 * (Z0 + Y0)
    const spxp = d0.redMul(z.redAdd(y));

    // S0 = SX * X0
    const s0 = sx.redMul(x);

    // S1 = -SPXP * X0
    const s1 = spxp.redNeg().redMul(x);

    // H0 = 2 * Z0 / sqrt(a * d - 1)
    const h0 = this.adm1si.redMuln(2).redMul(z);

    // T0 = H0 * SX
    const t0 = h0.redMul(sx);

    // T1 = H0 * SPXP
    const t1 = h0.redMul(spxp);

    // X0 = 0 or Y0 = 0
    if (x.isZero() || y.isZero()) {
      // S0 = 0, T0 = 1 if X0 = 0 or Y0 = 0
      s0.inject(zero);
      t0.inject(one);

      // S1 = 0, T1 = 1 if X0 = 0 or Y0 = 0
      s1.inject(zero);
      t1.inject(one);
    }

    // h = 8
    if (this.curve.h.cmpn(8) === 0) {
      // D1 = -Z2MY2 * G / sqrt(d - a)
      const d1 = z2my2.redNeg().redMul(this.dmasi).redMul(g);

      // IZ = sqrt(a) * Z0
      const iz = this.qnr.redMul(z);

      // SY = D1 * (IZ - X0)
      const sy = d1.redMul(iz.redSub(x));

      // SPYP = D1 * (IZ + X0)
      const spyp = d1.redMul(iz.redAdd(x));

      // S2 = SY * Y0
      const s2 = sy.redMul(y);

      // S3 = -SPYP * Y0
      const s3 = spyp.redNeg().redMul(y);

      // H1 = 2 * IZ / sqrt(a * d - 1)
      const h1 = this.adm1si.redMuln(2).redMul(iz);

      // T2 = H1 * SY
      const t2 = h1.redMul(sy);

      // T3 = H1 * SPYP
      const t3 = h1.redMul(spyp);

      // H2 = 2 * sqrt(a) / sqrt(a * d - 1)
      const h2 = this.qnr.redMul(this.adm1si).redIMuln(2);

      // X0 = 0 or Y0 = 0
      if (x.isZero() || y.isZero()) {
        // S2 = 1, T2 = H2 if X0 = 0 or Y0 = 0
        s2.inject(one);
        t2.inject(h2);

        // S3 = -1, T3 = H2 if X0 = 0 or Y0 = 0
        s3.inject(one.redNeg());
        t3.inject(h2);
      }

      // Return ((S0, T0), ...).
      return [[s0, t0],
              [s1, t1],
              [s2, t2],
              [s3, t3]];
    }

    // Return ((S0, T0), ...).
    return [[s0, t0], [s1, t1]];
  }

  _invert(s, t, hint) {
    // [DECAF] Page 13, Section 6.
    //
    // Assumptions:
    //
    //   - qnr * (s^4 - w^2) is square in F(p).
    //   - s != 0, t != +-1.
    //
    // Affine Formula:
    //
    //   w = (t + 1) * (d - a) / (d + a)
    //   r = (w + s^2) / sqrt(qnr * (s^4 - w^2))
    //
    // Undefined for s = 0 and t = +-1.
    //
    // The exceptional cases must be handled as:
    //
    //   (0, +1) -> sqrt(qnr * d)
    //   (0, -1) -> 0
    assert(s instanceof BN);
    assert(t instanceof BN);
    assert((hint >>> 0) === hint);

    // A = (T + 1) * (d - a) / (d + a)
    const a = t.redAdd(this.curve.one).redMul(this.dmaddpa);

    // A2 = A^2
    const a2 = a.redSqr();

    // S2 = S^2
    const s2 = s.redSqr();

    // S4 = S2^2
    const s4 = s2.redSqr();

    // Y = 1 / sqrt(qnr * (S4 - A2))
    const [sqr, y] = this._invsqrt(this.qnr.redMul(s4.redSub(a2)));

    // S2 = -S2 if S < 0
    if (s.redIsOdd())
      s2.redINeg();

    // R = (A + S2) * Y
    const r = a.redAdd(s2).redMul(y);

    // R = sqrt(qnr * d) if S = 0, T = 1
    if (s.isZero() && t.eq(this.curve.one))
      r.inject(this.qnrds);

    // R = 0 if S = 0, T = -1
    if (s.isZero() && !t.eq(this.curve.one))
      r.inject(this.curve.zero);

    // R = -R if R < 0 (or random)
    if (r.redIsOdd() !== Boolean(hint & 1))
      r.redINeg();

    // Fail if (qnr * (S4 - A2)) is not square.
    if (!sqr && !s.isZero())
      throw new Error('Invalid point.');

    return r;
  }

  pointFromHash(bytes) {
    // [RIST] "Hash-to-Group with Elligator".
    // [RIST255] Page 10, Section 3.2.4.
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.curve.fieldSize * 2)
      throw new Error('Invalid hash size.');

    // Random oracle encoding.
    // Ensure a proper distribution.
    const s1 = bytes.slice(0, this.curve.fieldSize);
    const s2 = bytes.slice(this.curve.fieldSize);
    const r1 = this.curve.decodeUniform(s1);
    const r2 = this.curve.decodeUniform(s2);
    const p1 = this.pointFromUniform(r1);
    const p2 = this.pointFromUniform(r2);

    return p1.add(p2);
  }

  pointToHash(p, rng) {
    // [SQUARED] Algorithm 1, Page 8, Section 3.3.
    assert(p instanceof this.Point);

    const p0 = p;

    for (;;) {
      const r1 = this.curve.randomField(rng);
      const p1 = this.pointFromUniform(r1);
      const p2 = p0.sub(p1);
      const hint = randomInt(rng);

      let r2;
      try {
        r2 = this.pointToUniform(p2, hint);
      } catch (e) {
        if (e.message === 'Invalid point.')
          continue;
        throw e;
      }

      const s1 = this.curve.encodeUniform(r1, hint >>> 8);
      const s2 = this.curve.encodeUniform(r2, hint >>> 16);

      return Buffer.concat([s1, s2]);
    }
  }

  randomPoint(rng) {
    const size = this.curve.fieldSize * 2;
    const bytes = randomBytes(rng, size);

    return this.pointFromHash(bytes);
  }
}

/*
 * Helpers
 */

function randomInt(rng) {
  return BN.randomBits(rng, 32).toNumber();
}

function randomBytes(rng, size) {
  const num = BN.randomBits(rng, size * 8);
  return num.encode('be', size);
}

/*
 * Expose
 */

module.exports = Ristretto;
