/*!
 * ristretto.js - ristretto encoding for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://ristretto.group
 *   https://datatracker.ietf.org/doc/draft-hdevalence-cfrg-ristretto
 *   https://git.zx2c4.com/goldilocks
 *   https://github.com/dalek-cryptography/curve25519-dalek
 */

'use strict';

const assert = require('../internal/assert');
const BN = require('../bn');

/**
 * Ristretto
 */

class Ristretto {
  constructor(curve) {
    assert(curve != null);
    assert(curve.type === 'edwards');

    // Curve.
    this.curve = curve;

    // Point class.
    this.Point = curve.Point;

    // AD = a * d
    this.ad = this.curve._mulA(this.curve.d);

    // MA = -a
    this.ma = this.curve.a.redNeg();

    // AMD = a - d
    this.amd = this.curve.a.redSub(this.curve.d);

    // ADM1S = sqrt(a * d - 1)
    this.adm1s = this.ad.redSub(this.curve.one).redSqrt();

    // ADM1SI = 1 / sqrt(a * d - 1)
    this.adm1si = this.adm1s.redInvert();

    // DPA = d + a
    this.dpa = this.curve.d.redAdd(this.curve.a);

    // DMA = d - a
    this.dma = this.curve.d.redSub(this.curve.a);

    // DMADDPA = DMA / DPA
    this.dmaddpa = this.dma.redDiv(this.dpa);

    // if H = 8
    if (this.curve.h.cmpn(8) === 0) {
      // QNR = sqrt(a)
      this.qnr = this.curve.a.redSqrt();

      // MAS = sqrt(-a)
      this.mas = this.ma.redSqrt();

      // AMDSI = 1 / sqrt(a - d)
      this.amdsi = this.amd.redSqrt().redInvert();

      // DMASI = 1 / sqrt(d - a)
      this.dmasi = this.dma.redSqrt().redInvert();
    } else {
      // QNR = non-square in F(p).
      this.qnr = this.curve.z;

      // MAS = 0 (unused)
      this.mas = this.curve.zero;

      // AMDSI = 0 (unused)
      this.amdsi = this.curve.zero;

      // DMASI = 0 (unused)
      this.dmasi = this.curve.zero;
    }

    // QNRDS = sqrt(QNR * D)
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
        || this.curve.id === 'ED448') {
      this.adm1si = this.adm1si.redNeg();
    }
  }

  _invsqrt(v) {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/field.rs#L270
    return this._isqrt(this.curve.one, v);
  }

  _isqrt(u, v) {
    // p mod 4 == 3 (p448)
    if (this.curve.p.andln(3) === 3)
      return this._isqrt3mod4(u, v);

    // p mod 8 == 5 (p25519)
    if (this.curve.p.andln(7) === 5)
      return this._isqrt5mod8(u, v);

    // Compute `r = sqrt(u / v)` slowly.
    return this._isqrt0(u, v);
  }

  _isqrt3mod4(u, v) {
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n48
    // https://git.zx2c4.com/goldilocks/tree/src/p448/f_arithmetic.c
    // Compute sqrt(u / v).
    assert(u instanceof BN);
    assert(v instanceof BN);

    // U2 = U^2
    const u2 = u.redSqr();

    // U3 = U2 * U
    const u3 = u2.redMul(u);

    // U5 = U3 * U2
    const u5 = u3.redMul(u2);

    // V3 = V^2 * V
    const v3 = v.redSqr().redMul(v);

    // E = (p - 3) / 4
    const e = this.curve.p.subn(3).iushrn(2);

    // P = (U5 * V3)^E
    const p = u5.redMul(v3).redPow(e);

    // R = U3 * V * P
    const r = u3.redMul(v).redMul(p);

    // C = V * R^2
    const c = v.redMul(r.redSqr());

    // CSS = C = U
    const css = c.ceq(u);

    // R = -R if R < 0
    r.cinject(r.redNeg(), r.redIsOdd() | 0);

    // Return (CSS, R).
    return [css, r];
  }

  _isqrt5mod8(u, v) {
    // https://ristretto.group/formulas/invsqrt.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/field.rs#L210
    // https://git.zx2c4.com/goldilocks/tree/src/p25519/f_arithmetic.c
    // Compute sqrt(u / v).
    assert(u instanceof BN);
    assert(v instanceof BN);

    // V3 = V^2 * V
    const v3 = v.redSqr().redMul(v);

    // V7 = V3^2 * V
    const v7 = v3.redSqr().redMul(v);

    // E = (p - 5) / 8
    const e = this.curve.p.subn(5).iushrn(3);

    // P = (U * V7)^E
    const p = u.redMul(v7).redPow(e);

    // R = U * V3 * P
    const r = u.redMul(v3).redMul(p);

    // C = V * R^2
    const c = v.redMul(r.redSqr());

    // CSS = C = U
    const css = c.ceq(u);

    // MC = -C
    const mc = c.redINeg();

    // FSS = MC = U
    const fss = mc.ceq(u);

    // FSSI = MC = U * sqrt(-1)
    const fssi = mc.ceq(u.redMul(this.qnr));

    // R = sqrt(-1) * R if FSS = 1 or FSSI = 1
    r.cinject(this.qnr.redMul(r), fss | fssi);

    // R = -R if R < 0
    r.cinject(r.redNeg(), r.redIsOdd() | 0);

    // Return (CSS | FSS, R).
    return [css | fss, r];
  }

  _isqrt0(u, v) {
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n58
    // Compute sqrt(u / v).
    assert(u instanceof BN);
    assert(v instanceof BN);

    // E = p - 2
    const e = this.curve.p.subn(2);

    // X = U / V
    const x = u.redMul(v.redPow(e));

    // CSS = X is square
    const css = x.redIsSquare() | 0;

    // X = X * qnr if CSS != 1
    x.cinject(x.redMul(this.qnr), css ^ 1);

    // R = sqrt(X)
    const r = x.redSqrt();

    // R = -R if R < 0
    r.cinject(r.redNeg(), r.redIsOdd() | 0);

    // Return (CSS, R).
    return [css, r];
  }

  encode(p) {
    assert(p instanceof this.Point);

    // H = 4
    if (this.curve.h.cmpn(4) === 0)
      return this._encode4(p);

    // H = 8
    return this._encode8(p);
  }

  _encode4(p) {
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n176
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c#n233

    // U = -((Z0 + Y0) * (Z0 - Y0))
    const u = p.z.redAdd(p.y).redMul(p.z.redSub(p.y)).redINeg();

    // I = 1 / sqrt(U * Y0^2)
    const [, i] = this._invsqrt(u.redMul(p.y.redSqr()));

    // N = I^2 * U * Y0 * T0
    const n = i.redSqr().redMul(u).redMul(p.y).redMul(p.t);

    // Y = Y0
    const y = p.y.clone();

    // Y = -Y if N < 0
    y.cinject(y.redNeg(), n.redIsOdd() | 0);

    // S = I * Y * (Z0 - Y)
    const s = i.redMul(y).redMul(p.z.redSub(y));

    // S = -S if S < 0
    s.cinject(s.redNeg(), s.redIsOdd() | 0);

    // Return the byte encoding of S.
    return this.curve.encodeField(s.fromRed());
  }

  _encode8(p) {
    // https://ristretto.group/formulas/encoding.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L434
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n176
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c#n233

    // U1 = (Z0 + Y0) * (Z0 - Y0)
    const u1 = p.z.redAdd(p.y).redMul(p.z.redSub(p.y));

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

    // rotate = T0 * Zinv < 0
    const rotate = p.t.redMul(zinv).redIsOdd() | 0;

    // X = Y0 * sqrt(a) if rotate = 1
    x.cinject(p.y.redMul(this.qnr), rotate);

    // Y = X0 * sqrt(a) if rotate = 1
    y.cinject(p.x.redMul(this.qnr), rotate);

    // D = D1 / sqrt(a - d) if rotate = 1
    d.cinject(d1.redMul(this.amdsi), rotate);

    // Y = -Y if X * Zinv < 0
    y.cinject(y.redNeg(), x.redMul(zinv).redIsOdd() | 0);

    // S = sqrt(-a) * (Z - Y) * D
    const s = this.mas.redMul(d.redMul(p.z.redSub(y)));

    // S = -S if S < 0
    s.cinject(s.redNeg(), s.redIsOdd() | 0);

    // Return the byte encoding of S.
    return this.curve.encodeField(s.fromRed());
  }

  decode(bytes) {
    // https://ristretto.group/formulas/decoding.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L251
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n248
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c#n239
    const e = this.curve.decodeField(bytes);

    // Check for canonical encoding.
    if (e.cmp(this.curve.p) >= 0)
      throw new Error('Invalid point.');

    // Reduce.
    const s = e.toRed(this.curve.red);

    // S < 0
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
    x.cinject(x.redNeg(), x.redIsOdd() | 0);

    // Y = U1 * DY
    const y = u1.redMul(dy);

    // Z = 1
    const z = this.curve.one;

    // T = X * Y
    const t = x.redMul(y);

    // if H = 4
    if (this.curve.h.cmpn(4) === 0) {
      // SQR = 0
      if (sqr ^ 1)
        throw new Error('Invalid point.');

      // P = (X : Y : Z)
      return this.curve.point(x, y, z, t);
    }

    // SQR = 0 or T < 0 or Y = 0
    if ((sqr ^ 1) | t.redIsOdd() | y.czero())
      throw new Error('Invalid point.');

    // P = (X : Y : Z : T)
    return this.curve.point(x, y, z, t);
  }

  eq(p, q) {
    // https://ristretto.group/formulas/equality.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L752
    assert(p instanceof this.Point);
    assert(q instanceof this.Point);

    // XY = X1 * Y2
    const xy = p.x.redMul(q.y);

    // YX = Y1 * X2
    const yx = p.y.redMul(q.x);

    // EQ1 = X1 * Y2 = Y1 * X2
    const eq1 = xy.ceq(yx);

    // if H = 4
    if (this.curve.h.cmpn(4) === 0) {
      // Return (EQ1).
      return Boolean(eq1);
    }

    // YY = Y1 * Y2
    const yy = p.y.redMul(q.y);

    // XX = -a * X1 * X2
    const xx = this.ma.redMul(p.x).redMul(q.x);

    // EQ2 = Y1 * Y2 = -a * X1 * X2
    const eq2 = yy.ceq(xx);

    // Return (EQ1 | EQ2).
    return Boolean(eq1 | eq2);
  }

  pointFromUniform(r0) {
    // Distribution: 2/h (1).
    // https://ristretto.group/details/elligator.html
    // https://ristretto.group/details/elligator_in_extended.html
    // https://ristretto.group/formulas/elligator.html
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L592
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n298
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/elligator.tmpl.c#n28
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
    sp.cinject(sp.redNeg(), sp.redIsOdd() ^ 1);

    // S = S' if S^2 != NS / D
    s.cinject(sp, sqr ^ 1);

    // C = R if S^2 != NS / D
    c.cinject(r, sqr ^ 1);

    // DS = (d + a)^2
    const ds = this.dpa.redSqr();

    // NT = C * (R - 1) * (d + a)^2 - D
    const nt = c.redMul(r.redSub(this.curve.one)).redMul(ds).redISub(d);

    // AS2 = A * S^2
    const as2 = this.curve._mulA(s.redSqr());

    // W0 = 2 * S * D
    const w0 = s.redAdd(s).redMul(d);

    // W1 = NT * sqrt(a * d - 1)
    const w1 = nt.redMul(this.adm1s);

    // W2 = 1 + a * s^2
    const w2 = this.curve.one.redAdd(as2);

    // W3 = 1 - a * s^2
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
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/elligator.tmpl.c#n106
    // https://github.com/bwesterb/go-ristretto/blob/9343fcb/edwards25519/elligator.go#L17
    //
    // Notes:
    //   - Each point has a 99%+ chance of mapping to at least one preimage.
    //   - The preimage distribution is even, meaning we can simply randomly
    //     select a preimage without rejection sampling (each preimage has a
    //     ~50% chance of existing).
    assert(p instanceof this.Point);
    assert((hint >>> 0) === hint);

    const R = [];

    for (const [s, t] of this._quartic(p)) {
      const [v0, r0] = this._invert(s, t);
      const [v1, r1] = this._invert(s.redNeg(), t.redNeg());

      if (v0)
        R.push(r0);

      if (v1)
        R.push(r1);
    }

    if (R.length === 0)
      throw new Error('Invalid point.');

    return R[hint % R.length];
  }

  _quartic(p) {
    // https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n351
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/decaf.tmpl.c#n145
    // https://github.com/bwesterb/go-ristretto/blob/9343fcb/edwards25519/elligator.go#L57
    assert(p instanceof this.Point);

    const {zero, one} = this.curve;
    const {x, y, z} = p;

    // XYZ = X0 = 0 or Y0 = 0
    const xyz = x.czero() | y.czero();

    // X2 = X0^2
    const x2 = x.redSqr();

    // Y2 = Y0^2
    const y2 = y.redSqr();

    // Y4 = Y2^2
    const y4 = y2.redSqr();

    // Z2 = Z^2
    const z2 = z.redSqr();

    // Z2MY2 = Z2 - Y2
    const z2my2 = z2.redSub(y2);

    // G = 1 / sqrt(Y4 * X2 * Z2MY2)
    const [, g] = this._invsqrt(y4.redMul(x2).redMul(z2my2));

    // D0 = G * Y0^2
    const d0 = g.redMul(y2);

    // SX = D0 * (Z - Y0)
    const sx = d0.redMul(z.redSub(y));

    // SPXP = D0 * (Z + Y0)
    const spxp = d0.redMul(z.redAdd(y));

    // S0 = SX * X0
    const s0 = sx.redMul(x);

    // S1 = -SPXP * X0
    const s1 = spxp.redNeg().redMul(x);

    // H0 = 2 / sqrt(a * d - 1) * Z
    const h0 = this.adm1si.redMuln(2).redMul(z);

    // T0 = H0 * SX
    const t0 = h0.redMul(sx);

    // T1 = H0 * SPXP
    const t1 = h0.redMul(spxp);

    // S0 = 0, T0 = 1 if XYZ = 1
    s0.cinject(zero, xyz);
    t0.cinject(one, xyz);

    // S0 = 0, T0 = 1 if XYZ = 1
    s1.cinject(zero, xyz);
    t1.cinject(one, xyz);

    // H = 4
    if (this.curve.h.cmpn(4) === 0) {
      // Return ((S0, T0), ...).
      return [[s0, t0], [s1, t1]];
    }

    // D1 = (1 / sqrt(d - a)) * -Z2MY2 * G
    const d1 = z2my2.redNeg().redMul(this.dmasi).redMul(g);

    // IZ = qnr * Z
    const iz = this.qnr.redMul(z);

    // SY = D1 * (IZ - X0)
    const sy = d1.redMul(iz.redSub(x));

    // SPYP = D1 * (IZ + X0)
    const spyp = d1.redMul(iz.redAdd(x));

    // S2 = SY * Y0
    const s2 = sy.redMul(y);

    // S3 = -SPYP * Y0
    const s3 = spyp.redNeg().redMul(y);

    // H1 = (2 / sqrt(a * d - 1)) * IZ
    const h1 = this.adm1si.redMuln(2).redMul(iz);

    // T2 = H1 * SY
    const t2 = h1.redMul(sy);

    // T3 = H1 * SPYP
    const t3 = h1.redMul(spyp);

    // H2 = qnr / sqrt(a * d - 1)
    const h2 = this.qnr.redMul(this.adm1si);

    // S0 = 1, T0 = H2 if XYZ = 1
    s2.cinject(one, xyz);
    t2.cinject(h2, xyz);

    // S0 = -1, T0 = H2 if XYZ = 1
    s3.cinject(one.redNeg(), xyz);
    t3.cinject(h2, xyz);

    // Return ((S0, T0), ...).
    return [[s0, t0],
            [s1, t1],
            [s2, t2],
            [s3, t3]];
  }

  _invert(s, t) {
    // https://github.com/bwesterb/go-ristretto/blob/9343fcb/edwards25519/elligator.go#L151
    assert(s instanceof BN);
    assert(t instanceof BN);

    const {zero, one} = this.curve;

    // TZ = T = 0
    const tz = t.czero();

    // TO = T = 1
    const to = tz & t.ceq(one);

    // A = (T + 1) * ((d - a) / (d + a))
    const a = t.redAdd(one).redMul(this.dmaddpa);

    // A = A^2
    const a2 = a.redSqr();

    // S2 = S^2
    const s2 = s.redSqr();

    // S4 = S2^2
    const s4 = s2.redSqr();

    // Y = 1 / sqrt(qnr * (S4 - A2))
    // SQR = Y^2 = 1 / (qnr * (S4 - A2))
    const [sqr, y] = this._invsqrt(this.qnr.redMul(s4.redSub(a2)));

    // S2 = -S2 if S < 0
    s2.cinject(s2.redNeg(), s.redIsOdd() | 0);

    // R = (A + S2) * Y
    const r = a.redAdd(s2).redMul(y);

    // R = -R if R < 0
    r.cinject(r.redNeg(), r.redIsOdd() | 0);

    // R = 0 if TZ = 1
    r.cinject(zero, tz);

    // R = sqrt(qnr * d) if TO = 1
    r.cinject(this.qnrds, to);

    // Return (SQR | TZ, R).
    return [sqr | tz, r];
  }

  pointFromHash(bytes) {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L713
    // https://git.zx2c4.com/goldilocks/tree/src/per_curve/elligator.tmpl.c#n87
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

    return p1.uadd(p2);
  }

  pointToHash(p, rng) {
    assert(p instanceof this.Point);

    for (;;) {
      const r1 = this.curve.randomField(rng);
      const p1 = this.pointFromUniform(r1);

      // Avoid 2-torsion points.
      if (p1.x.isZero())
        continue;

      const p2 = p.usub(p1);
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
