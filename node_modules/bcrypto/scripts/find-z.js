'use strict';

const assert = require('bsert');
const cp = require('child_process');
const BN = require('../lib/bn');
const elliptic = require('../lib/js/elliptic');

require('../test/util/curves');

function printZ(curve) {
  assert(curve instanceof elliptic.Curve);

  const size = (((curve.fieldBits + 7) >>> 3) + 3) & -4;
  const alg = getAlg(curve);
  const s = tryFindS(curve);
  const z = findZ(curve);

  if (s != null) {
    let str = s.fromRed().toString(16);

    while (str.length < size * 2)
      str = '0' + str;

    console.log('%s S: %s (elligator1)', curve.id, str);
  }

  const n = z.fromRed();

  if (z.redIsHigh())
    n.isub(curve.p);

  const str = n.toString(16);

  console.log('%s Z: %s (%s)', curve.id, str, alg);

  if (alg === 'svdw') {
    const c = z.redSqr().redIMuln(-3).redSqrt();

    let str = c.fromRed().toString(16);

    while (str.length < size * 2)
      str = '0' + str;

    console.log('%s C: %s (%s)', curve.id, str, alg);
  }
}

function getAlg(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'short') {
    if (curve.b.isZero())
      throw new Error('Not implemented.');

    // a != 0, b != 0
    if (!curve.a.isZero()) {
      // p = 2 mod 3
      if (curve.p.modrn(3) === 2)
        return 'icart';
      return 'sswu';
    }

    // p = 1 mod 3, a = 0, b != 0
    if (curve.p.modrn(3) === 1)
      return 'svdw';

    throw new Error('Not implemented.');
  }

  if (curve.type === 'mont' || curve.type === 'edwards')
    return 'elligator2';

  throw new Error('Not implemented.');
}

function findZ(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'short') {
    if (curve.b.isZero())
      throw new Error('Not implemented.');

    // a != 0, b != 0
    if (!curve.a.isZero())
      return findSSWUZ(curve);

    // p = 1 mod 3, a = 0, b != 0
    if (curve.p.modrn(3) === 1)
      return findSVDWZ(curve);

    throw new Error('Not implemented.');
  }

  if (curve.type === 'mont' || curve.type === 'edwards')
    return findElligator2Z(curve);

  throw new Error('Not implemented.');
}

function tryFindS(curve) {
  assert(curve instanceof elliptic.Curve);

  try {
    return findS(curve);
  } catch (e) {
    return null;
  }
}

function findS(curve) {
  assert(curve instanceof elliptic.Curve);

  if (curve.type === 'edwards' && !curve.twisted) {
    if (curve.p.andln(3) === 3 && curve.d.redJacobi() === -1)
      return findElligator1S(curve);
  }

  throw new Error('Not implemented.');
}

function findElligator1S(curve) {
  assert(curve instanceof elliptic.Curve);

  // solve(d == -((2 / s^2) + 1)^2 / ((2 / s^2) - 1)^2, s)
  // s = +-sqrt(2 * d / (d + 1) +- 4 * sqrt(-d) / (d + 1) - 2 / (d + 1))
  const {d, one} = curve;
  const di = d.redAdd(one).redInvert();
  const ds = d.redNeg().redSqrt();
  const t0 = d.redMuln(2).redMul(di);
  const t1 = ds.redMuln(4).redMul(di);
  const t2 = di.redMuln(2);
  const s1 = t0.redAdd(t1).redSub(t2).redSqrt();
  const s2 = s1.redNeg();
  const s3 = t0.redSub(t1).redSub(t2).redSqrt();
  const s4 = s3.redNeg();
  const S = [s1, s2, s3, s4].filter(s => isElligator1S(curve, s));

  if (S.length === 0)
    throw new Error('X is not a square mod P.');

  console.log('Found %d `s` values:', S.length);
  console.log('');

  for (const s of S)
    console.log('  %s', s.fromRed().toString(16));

  console.log('');

  // Use DJB's `s` value.
  if (curve.id === 'ED1174')
    return S[2];

  // Pick the smallest `s`.
  const s = BN.min(...S.map(s => s.fromRed()));

  return s.toRed(curve.red);
}

function isElligator1S(curve, s) {
  assert(curve instanceof elliptic.Curve);
  assert(s instanceof BN);
  assert(s.red === curve.red);

  try {
    getElligator1SCR(curve, s);
    return true;
  } catch (e) {
    return false;
  }
}

function getElligator1SCR(curve, s) {
  assert(curve instanceof elliptic.Curve);
  assert(s instanceof BN);

  // Assumptions:
  //
  //   - Let q be a prime power congruent to 3 mod 4.
  //   - Let s be a nonzero element of F(q) with (s^2 - 2)(s^2 + 2) != 0.
  //   - Let c = 2 / s^2. Then c(c - 1)(c + 1) != 0.
  //   - Let r = c + 1 / c. Then r != 0.
  //   - Let d = -(c + 1)^2 / (c - 1)^2. Then d is not a square.
  const {one, two} = curve;
  const s2 = s.redSqr();
  const lhs = s2.redSub(two);
  const rhs = s2.redAdd(two);
  const k0 = lhs.redMul(rhs);

  if (k0.isZero())
    throw new Error('Invalid S (s^2 - 2)(s^2 + 2) = 0).');

  const c = two.redDiv(s2);
  const cm1 = c.redSub(one);
  const cp1 = c.redAdd(one);
  const k1 = c.redMul(cm1).redMul(cp1);

  if (k1.isZero())
    throw new Error('Invalid C (c(c - 1)(c + 1) = 0).');

  const r = c.redAdd(c.redInvert());

  if (r.isZero())
    throw new Error('Invalid R (c + 1 / c = 0).');

  const dl = c.redAdd(one).redSqr().redINeg();
  const dr = c.redSub(one).redSqr();
  const d = dl.redDiv(dr);

  if (!d.eq(curve.d))
    throw new Error('Invalid D (D != d).');

  if (d.redJacobi() !== -1)
    throw new Error('Invalid D (square).');

  // - If n * r = -2 then x = 2 * s * (c - 1) * f(c) / r.
  // - Let n = (y - 1) / 2 * (y + 1).
  const e0 = curve.p.subn(2);
  const e1 = curve.p.subn(1).iushrn(1);
  const xl = s.redMul(c.redSub(one)).redIMuln(2);
  const xr = c.redPow(e1);
  const x = xl.redMul(xr).redDiv(r);

  let p = null;

  for (const sign of [false, true]) {
    const q = curve.pointFromX(x, sign);
    const n = q.y.redSub(one).redMul(q.y.redAdd(one).redIMuln(2).redPow(e0));
    const nr = n.redMul(r);

    if (nr.eq(two.redNeg())) {
      p = q;
      break;
    }
  }

  if (!p)
    throw new Error('Invalid X (n * r != -2).');

  return [s, c, r, p];
}

function findElligator2Z(curve) {
  assert(curve instanceof elliptic.Curve);

  const ctr = curve.one.clone();

  for (;;) {
    for (const z of [ctr, ctr.redNeg()]) {
      // z must be a non-square in F(p).
      if (z.redIsSquare())
        continue;

      return z;
    }

    ctr.redIAdd(curve.one);
  }
}

function findSSWUZ(curve) {
  assert(curve instanceof elliptic.Curve);

  const {a, b} = curve;
  const ctr = curve.one.clone();

  for (;;) {
    for (const z of [ctr, ctr.redNeg()]) {
      // Criterion 1: z is non-square in F(p).
      if (z.redIsSquare())
        continue;

      // Criterion 2: z != -1 in F(p).
      if (z.eq(curve.one.redNeg()))
        continue;

      // Criterion 3: g(x) - z is irreducible over F(p).
      if (!isIrreducible(curve, z))
        continue;

      // Criterion 4: g(b / (z * a)) is square in F(p).
      const c = b.redDiv(z.redMul(a));

      if (!curve.solveY2(c).redIsSquare())
        continue;

      return z;
    }

    ctr.redIAdd(curve.one);
  }
}

function findSVDWZ(curve) {
  assert(curve instanceof elliptic.Curve);

  const {i2} = curve;
  const ctr = curve.one.clone();

  for (;;) {
    for (const z of [ctr, ctr.redNeg()]) {
      const c = z.redSqr().redIMuln(-3).redSqrt();

      // g((sqrt(-3 * z^2) - z) / 2) must be square in F(p).
      const g = curve.solveY2(c.redSub(z).redMul(i2));

      if (!g.redIsSquare())
        continue;

      return z;
    }

    ctr.redIAdd(curve.one);
  }
}

// See:
// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/pull/172
// eslint-disable-next-line
function findSVDWZNew(curve) {
  assert(curve instanceof elliptic.Curve);

  const {a, i2} = curve;
  const ctr = curve.one.clone();

  for (;;) {
    for (const z of [ctr, ctr.redNeg()]) {
      const gz = curve.solveY2(z);
      const gz2 = curve.solveY2(z.redNeg().redMul(i2));
      const t0 = z.redSqr().redIMuln(3).redIAdd(a.redMuln(4)).redINeg();
      const hz = t0.redDiv(gz.redMuln(4));

      // Criterion 1: g(z) != 0 in F(p).
      if (gz.isZero())
        continue;

      // Criterion 2: -(3 * z^2 + 4 * a) / (4 * g(z)) != 0 in F(p).
      if (hz.isZero())
        continue;

      // Criterion 3: -(3 * z^2 + 4 * a) / (4 * g(z)) is square in F(p).
      if (!hz.redIsSquare())
        continue;

      // Criterion 4: At least one of g(z) and g(-z / 2) is square in F(p).
      if (!gz.redIsSquare() && !gz2.redIsSquare())
        continue;

      return z;
    }

    ctr.redIAdd(curve.one);
  }
}

function isIrreducible(curve, z) {
  assert(curve instanceof elliptic.Curve);
  assert(z instanceof BN);

  const code = `
    F = GF(0x${curve.p.toString(16)})
    A = 0x${curve.a.fromRed().toString(16)}
    B = 0x${curve.b.fromRed().toString(16)}
    Z = F(0x${z.fromRed().toString(16)})
    R.<xx> = F[]
    g = xx ** 3 + F(A) * xx + F(B)
    print((g - Z).is_irreducible())
  `.replace(/^ +/gm, '');

  return sage(code) === 'True';
}

function sage(code) {
  assert(typeof code === 'string');

  const out = cp.execFileSync('sage', ['-c', code], {
    cwd: process.cwd(),
    encoding: 'binary',
    stdio: ['pipe', 'pipe', 'ignore']
  });

  // eslint-disable-next-line
  return out.replace(/\x1b\[[^m]*?m/g, '').trim();
}

function main(argv) {
  if (argv.length < 3) {
    console.error('Must enter a curve ID.');
    process.exit(1);
    return;
  }

  const curve = elliptic.curve(argv[2]);

  printZ(curve);
}

main(process.argv);
