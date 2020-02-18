/*!
 * curves.js - elliptic curves for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 */

'use strict';

const {custom} = require('../internal/custom');
const BN = require('../bn.js');

/*
 * Constants
 */

const jsfIndex = [
  -3, /* -1 -1 */
  -1, /* -1 0 */
  -5, /* -1 1 */
  -7, /* 0 -1 */
  0, /* 0 0 */
  7, /* 0 1 */
  5, /* 1 -1 */
  1, /* 1 0 */
  3  /* 1 1 */
];

/**
 * Curve
 */

class Curve {
  constructor() {
    this.id = null;
    this.type = 'base';
    this.endian = 'be';
    this.hash = null;
    this.prefix = null;
    this.context = false;
    this.p = null;
    this.red = null;
    this.encodingLength = 0;
    this.scalarLength = 0;
    this.signBit = 0;
    this.zero = null;
    this.one = null;
    this.two = null;
    this.n = null;
    this.nh = null;
    this.h = null;
    this.g = null;
    this.mask = null;
    this.maxwellTrick = false;
    this.redN = null;
    this.blinding = null;
    this.zeroRaw = null;
    this.orderRaw = null;
    this.halfRaw = null;
  }

  init(type, conf) {
    assert(typeof type === 'string');
    assert(conf && typeof conf === 'object');
    assert(conf.p != null, 'Must pass a prime.');

    // Meta.
    this.id = conf.id || null;
    this.type = type;
    this.endian = conf.endian || (type === 'short' ? 'be' : 'le');
    this.hash = conf.hash || null;
    this.prefix = conf.prefix ? Buffer.from(conf.prefix, 'binary') : null;
    this.context = conf.context || false;

    // Prime.
    this.p = new BN(conf.p, 16);

    // Use Montgomery, when there is no fast reduction for the prime.
    this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);

    // Precalculate encoding length.
    this.encodingLength = this.p.byteLength();
    this.scalarLength = this.encodingLength;
    this.signBit = this.encodingLength * 8 - 1;

    // Figure out where the sign bit goes on edwards/mont.
    if (this.p.testn(this.signBit)) {
      // If the hi bit is set on our prime, we need an
      // extra byte to encode the sign bit (a la Ed448).
      if (this.type === 'edwards')
        this.encodingLength += 1;

      // Move the sign bit over.
      this.signBit += 8;
    }

    // Useful for many curves.
    this.zero = new BN(0).toRed(this.red);
    this.one = new BN(1).toRed(this.red);
    this.two = new BN(2).toRed(this.red);

    // Curve configuration, optional.
    this.n = conf.n ? new BN(conf.n, 16) : null;
    this.nh = conf.n ? this.n.ushrn(1) : null;
    this.h = conf.h ? new BN(conf.h, 16) : new BN(1);
    this.g = conf.g ? this.pointFromJSON(conf.g) : null;
    this.mask = new Mask(this);

    // Generalized Greg Maxwell's trick.
    if (!this.n || this.p.div(this.n).cmpn(100) > 0) {
      this.maxwellTrick = false;
      this.redN = null;
    } else {
      this.maxwellTrick = true;
      this.redN = this.n.toRed(this.red);
    }

    // Useful for buffer operations.
    this.zeroRaw = this.encodeInt(new BN(0));
    this.orderRaw = this.n ? this.encodeInt(this.n) : null;
    this.halfRaw = this.nh ? this.encodeInt(this.nh) : null;
    this.hRaw = this.h ? this.encodeScalar(this.h) : null;

    return this;
  }

  get size() {
    return this.encodingLength;
  }

  get bits() {
    return this.p.bitLength();
  }

  point() {
    throw new Error('Not implemented.');
  }

  validate() {
    throw new Error('Not implemented.');
  }

  precompute(rng) {
    assert(this.g, 'Must have base point.');
    assert(this.n, 'Must have order.');
    this.g.precompute(this.n.bitLength() + 1, rng);
    this.blinding = this._scalarBlinding(rng);
    return this;
  }

  encodeInt(num) {
    assert(num instanceof BN);
    assert(!num.red);
    return num.encode(this.endian, this.encodingLength);
  }

  decodeInt(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.encodingLength)
      throw new Error('Invalid integer size.');

    return BN.decode(bytes, this.endian);
  }

  encodeScalar(num) {
    assert(num instanceof BN);
    assert(!num.red);
    return num.encode(this.endian, this.scalarLength);
  }

  decodeScalar(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.scalarLength)
      throw new Error('Invalid scalar size.');

    return BN.decode(bytes, this.endian);
  }

  encodePoint(point, compact) {
    assert(point instanceof Point);
    return point.encode(compact);
  }

  decodePoint(bytes) {
    assert(Buffer.isBuffer(bytes));

    const len = this.encodingLength;

    if (bytes.length < 1 + len)
      throw new Error('Not a point.');

    const first = bytes[0];
    const last = bytes[bytes.length - 1];

    switch (first) {
      case 0x02:
      case 0x03: {
        if (bytes.length !== 1 + len)
          throw new Error('Invalid point size for compressed.');

        const x = this.decodeInt(bytes.slice(1, 1 + len));

        if (x.cmp(this.p) >= 0)
          throw new Error('Invalid point.');

        const p = this.pointFromX(x, first === 0x03);

        assert(!p.isInfinity());

        return p;
      }

      case 0x04:
      case 0x06:
      case 0x07: {
        if (bytes.length !== 1 + len * 2)
          throw new Error('Invalid point size for uncompressed.');

        if (first !== 0x04 && (last & 1) !== (first & 1))
          throw new Error('Invalid hybrid encoding.');

        const x = this.decodeInt(bytes.slice(1, 1 + len));
        const y = this.decodeInt(bytes.slice(1 + len, 1 + 2 * len));

        if (x.cmp(this.p) >= 0 || y.cmp(this.p) >= 0)
          throw new Error('Invalid point.');

        const p = this.point(x, y);

        if (!p.validate())
          throw new Error('Invalid point.');

        assert(!p.isInfinity());

        return p;
      }

      default: {
        throw new Error('Unknown point format.');
      }
    }
  }

  splitHash(bytes) {
    return this.mask.splitHash(bytes);
  }

  clamp(bytes) {
    return this.mask.clamp(bytes);
  }

  isClamped(bytes) {
    return this.mask.isClamped(bytes);
  }

  getBlinding() {
    if (!this.blinding)
      return [new BN(1), new BN(1)];

    return [...this.blinding];
  }

  _scalarBlinding(rng) {
    if (!rng)
      return null;

    // We blind scalar multiplications too.
    // Our bigint implementation is only
    // constant time for 235-285 bit ints.
    // This is only effective if an attacker
    // is not able to observe the start up.
    for (;;) {
      const blind = BN.random(rng, 1, this.n);

      try {
        return [blind, blind.invm(this.n)];
      } catch (e) {
        continue;
      }
    }
  }

  _fixedNafMul(p, k, initial, jacobian) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');
    assert(p.precomputed);

    const {step, points} = p._getDoubles(0, 0);
    const naf = getNAF(k, 1);
    const I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3;

    // Translate into more windowed form.
    const repr = [];

    for (let j = 0; j < naf.length; j += step) {
      let nafW = 0;

      for (let k = j + step - 1; k >= j; k--)
        nafW = (nafW << 1) + naf[k];

      repr.push(nafW);
    }

    let a = initial || this.jpoint(null, null, null);
    let b = this.jpoint(null, null, null);

    for (let i = I; i > 0; i--) {
      for (let j = 0; j < repr.length; j++) {
        const nafW = repr[j];

        if (nafW === i)
          b = b.mixedAdd(points[j]);
        else if (nafW === -i)
          b = b.mixedAdd(points[j].neg());
      }

      a = a.add(b);
    }

    if (jacobian)
      return a;

    return a.toP();
  }

  _wnafMul(p, k, initial, jacobian) {
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');

    // Precompute window.
    const nafPoints = p._getNAFPoints(4);
    const w = nafPoints.wnd;
    const wnd = nafPoints.points;

    // Get NAF form.
    const naf = getNAF(k, w);

    // Add `this`*(N+1) for every w-NAF index.
    let acc = this.jpoint(null, null, null);

    for (let i = naf.length - 1; i >= 0; i--) {
      // Count zeroes.
      let k = 0;

      for (; i >= 0 && naf[i] === 0; i--)
        k++;

      if (i >= 0)
        k++;

      acc = acc.dblp(k);

      if (i < 0)
        break;

      const z = naf[i];

      assert(z !== 0);

      if (p.type === 'affine') {
        // J +- P
        if (z > 0)
          acc = acc.mixedAdd(wnd[(z - 1) >> 1]);
        else
          acc = acc.mixedAdd(wnd[(-z - 1) >> 1].neg());
      } else {
        // J +- J
        if (z > 0)
          acc = acc.add(wnd[(z - 1) >> 1]);
        else
          acc = acc.add(wnd[(-z - 1) >> 1].neg());
      }
    }

    if (initial)
      acc = acc.add(initial);

    if (jacobian)
      return acc;

    return p.type === 'affine' ? acc.toP() : acc;
  }

  _wnafMulAdd(defW, points, coeffs, initial, jacobian) {
    assert((defW >>> 0) === defW);
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');
    assert(points.length === coeffs.length);

    const len = points.length;
    const wndWidth = [];
    const wnd = [];
    const naf = [];

    let max = 0;

    // Fill all arrays.
    for (let i = 0; i < len; i++) {
      const point = points[i];

      assert(point instanceof Point);

      const nafPoints = point._getNAFPoints(defW);

      wndWidth[i] = nafPoints.wnd;
      wnd[i] = nafPoints.points;
      naf[i] = null;
    }

    // Comb small window NAFs.
    for (let i = len - 1; i >= 1; i -= 2) {
      const a = i - 1;
      const b = i;

      if (wndWidth[a] !== 1 || wndWidth[b] !== 1) {
        naf[a] = getNAF(coeffs[a], wndWidth[a]);
        naf[b] = getNAF(coeffs[b], wndWidth[b]);
        max = Math.max(naf[a].length, max);
        max = Math.max(naf[b].length, max);
        continue;
      }

      const comb = [
        points[a], /* 1 */
        null, /* 3 */
        null, /* 5 */
        points[b] /* 7 */
      ];

      // Try to avoid Projective points, if possible.
      if (points[a].y.cmp(points[b].y) === 0) {
        comb[1] = points[a].add(points[b]);
        comb[2] = points[a].toJ().mixedAdd(points[b].neg());
      } else if (points[a].y.cmp(points[b].y.redNeg()) === 0) {
        comb[1] = points[a].toJ().mixedAdd(points[b]);
        comb[2] = points[a].add(points[b].neg());
      } else {
        comb[1] = points[a].toJ().mixedAdd(points[b]);
        comb[2] = points[a].toJ().mixedAdd(points[b].neg());
      }

      const jsf = getJSF(coeffs[a], coeffs[b]);

      max = Math.max(jsf[0].length, max);
      naf[a] = [];
      naf[b] = [];

      for (let j = 0; j < max; j++) {
        const ja = jsf[0][j] | 0;
        const jb = jsf[1][j] | 0;

        naf[a].push(jsfIndex[(ja + 1) * 3 + (jb + 1)]);
        naf[b].push(0);
        wnd[a] = comb;
      }
    }

    let acc = this.jpoint(null, null, null);

    const tmp = [];

    for (let i = max; i >= 0; i--) {
      let k = 0;

      while (i >= 0) {
        let zero = true;

        for (let j = 0; j < len; j++) {
          tmp[j] = naf[j][i] | 0;
          if (tmp[j] !== 0)
            zero = false;
        }

        if (!zero)
          break;

        k++;
        i--;
      }

      if (i >= 0)
        k++;

      acc = acc.dblp(k);

      if (i < 0)
        break;

      for (let j = 0; j < len; j++) {
        const z = tmp[j];

        if (z === 0)
          continue;

        let p;

        if (z > 0)
          p = wnd[j][(z - 1) >> 1];
        else if (z < 0)
          p = wnd[j][(-z - 1) >> 1].neg();

        if (p.type === 'affine')
          acc = acc.mixedAdd(p);
        else
          acc = acc.add(p);
      }
    }

    if (initial)
      acc = acc.add(initial);

    if (jacobian)
      return acc;

    return acc.toP();
  }

  mulAll(points, coeffs) {
    return this._mulAll(points, coeffs, null, false);
  }

  jmulAll(points, coeffs) {
    return this._mulAll(points, coeffs, null, true);
  }
}

/**
 * Mask
 */

class Mask {
  constructor(curve) {
    assert(curve instanceof Curve);

    const bytes = curve.p.byteLength();
    const bits = Math.max(8, (bytes - 1) * 8);

    // Our curve.
    this.curve = curve;

    // Cofactor mask (p25519=-8, p448=-4).
    this.h = -curve.h.toNumber() & 0xff;

    // Group order top byte (p25519=0x7f, p448=0xff).
    // In theory we should get this from the
    // _real_ order, not the prime.
    this.n = curve.p.ushrn(bits).toNumber();

    // High bit (p25519=0x40, p448=0x80).
    this.b = (this.n + 1) >>> 1;

    // AND mask (p25519=0x7fff...f8, p448=0xffff...fc).
    this.and = BN.shift(this.n + 1, bits - 8).isubn(1);
    this.and.iushln(8).iuorn(this.h);

    // OR mask (p25519=0x4000..., p448=0x8000...).
    this.or = BN.shift(this.b, bits);

    // Verify clamping constants.
    if (curve.id === 'ed25519' || curve.id === 'x25519') {
      assert(this.h === (-8 & 0xff));
      assert(this.n === 0x7f);
      assert(this.b === 0x40);
    } else if (curve.id === 'ed448' || curve.id === 'x448') {
      assert(this.h === (-4 & 0xff));
      assert(this.n === 0xff);
      assert(this.b === 0x80);
    }
  }

  reduce(num) {
    assert(num instanceof BN);
    num.iuand(this.and);
    num.iuor(this.or);
    return num;
  }

  splitHash(bytes) {
    const {encodingLength, scalarLength} = this.curve;

    assert(Buffer.isBuffer(bytes));
    assert(bytes.length === encodingLength * 2);

    const prefix = bytes.slice(encodingLength);

    let scalar = bytes.slice(0, encodingLength);

    // Protocols like Ed448 ignore the useless byte.
    // This only occurs if the encoding requires a
    // full extra byte to encode the sign bit.
    if (encodingLength === scalarLength + 1) {
      scalar = this.curve.endian === 'le'
        ? scalar.slice(0, -1)
        : scalar.slice(1);
    }

    this.clamp(scalar);

    return [scalar, prefix];
  }

  clamp(bytes) {
    assert(Buffer.isBuffer(bytes));
    assert(bytes.length === this.curve.scalarLength);

    let i = 0;
    let j = this.curve.scalarLength - 1;

    if (this.curve.endian === 'be')
      [i, j] = [j, i];

    // Ensure a multiple of the cofactor.
    bytes[i] &= this.h;

    // Clamp to the group order.
    bytes[j] &= this.n;

    // Set the high bit.
    bytes[j] |= this.b;

    return bytes;
  }

  isClamped(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.curve.scalarLength)
      return false;

    let i = 0;
    let j = this.curve.scalarLength - 1;

    if (this.curve.endian === 'be')
      [i, j] = [j, i];

    // Must be a multiple of the cofactor.
    if (bytes[i] & ~this.h)
      return false;

    // Must be clamped to the group order.
    if (bytes[j] & ~this.n)
      return false;

    // Must have high bit set.
    if (!(bytes[j] & this.b))
      return false;

    return true;
  }
}

/**
 * Point
 */

class Point {
  constructor(curve, type) {
    assert(curve instanceof Curve);
    assert(typeof type === 'string');

    this.curve = curve;
    this.type = type;
    this.precomputed = null;
  }

  eq(point) {
    throw new Error('Not implemented.');
  }

  validate() {
    return this.curve.validate(this);
  }

  encode(compact) {
    if (compact == null)
      compact = true;

    assert(typeof compact === 'boolean');

    const {encodingLength} = this.curve;

    if (compact) {
      const p = Buffer.allocUnsafe(1 + encodingLength);
      const x = this.curve.encodeInt(this.getX());

      p[0] = 0x02 | this.getY().isOdd();
      x.copy(p, 1);

      return p;
    }

    const p = Buffer.allocUnsafe(1 + encodingLength * 2);
    const x = this.curve.encodeInt(this.getX());
    const y = this.curve.encodeInt(this.getY());

    p[0] = 0x04;
    x.copy(p, 1);
    y.copy(p, 1 + encodingLength);

    return p;
  }

  precompute(power, rng) {
    assert((power >>> 0) === power);

    if (!this.precomputed) {
      this.precomputed = {
        naf: null,
        doubles: null,
        beta: null,
        blinding: null
      };
    }

    if (!this.precomputed.naf)
      this.precomputed.naf = this._getNAFPoints(8);

    if (!this.precomputed.doubles)
      this.precomputed.doubles = this._getDoubles(4, power);

    if (!this.precomputed.beta)
      this.precomputed.beta = this._getBeta();

    if (!this.precomputed.blinding)
      this.precomputed.blinding = this._getBlinding(rng);

    return this;
  }

  _hasDoubles(k) {
    assert(k instanceof BN);

    if (!this.precomputed)
      return false;

    const {doubles} = this.precomputed;

    if (!doubles)
      return false;

    const {points, step} = doubles;

    return points.length >= Math.ceil((k.bitLength() + 1) / step);
  }

  _getDoubles(step, power) {
    assert((step >>> 0) === step);
    assert((power >>> 0) === power);

    if (this.precomputed && this.precomputed.doubles)
      return this.precomputed.doubles;

    const points = [this];

    let acc = this;

    for (let i = 0; i < power; i += step) {
      for (let j = 0; j < step; j++)
        acc = acc.dbl();

      points.push(acc);
    }

    return { step, points };
  }

  _getNAFPoints(wnd) {
    assert((wnd >>> 0) === wnd);

    if (this.precomputed && this.precomputed.naf)
      return this.precomputed.naf;

    const points = [this];
    const max = (1 << wnd) - 1;
    const dbl = max === 1 ? null : this.dbl();

    for (let i = 1; i < max; i++)
      points[i] = points[i - 1].add(dbl);

    return { wnd, points };
  }

  _getBeta() {
    return null;
  }

  _getBlinding(rng) {
    if (this.precomputed && this.precomputed.blinding)
      return this.precomputed.blinding;

    if (!rng)
      return null;

    for (;;) {
      const blind = BN.random(rng, 1, this.curve.n);
      const unblind = this.jmul(this.curve.n.sub(blind));

      if (unblind.isInfinity())
        continue;

      return {
        blind,
        unblind
      };
    }
  }

  _mulBlind(k, rng = null, jacobian) {
    assert(k instanceof BN);

    const blinding = this._getBlinding(rng);

    if (!blinding)
      return this._mul(k, null, jacobian);

    const {blind, unblind} = blinding;
    const t = k.add(blind).iumod(this.curve.n);

    if (t.isZero())
      return this._mul(k, null, jacobian);

    return this._mul(t, unblind, jacobian);
  }

  mul(k) {
    return this._mul(k, null, false);
  }

  jmul(k) {
    return this._mul(k, null, true);
  }

  mulAdd(k1, p, k2) {
    return this._mulAdd(k1, p, k2, null, false);
  }

  jmulAdd(k1, p, k2) {
    return this._mulAdd(k1, p, k2, null, true);
  }

  mulBlind(k, rng = null) {
    return this._mulBlind(k, rng, false);
  }

  jmulBlind(k, rng = null) {
    return this._mulBlind(k, rng, true);
  }

  dblp(k) {
    assert((k >>> 0) === k);

    let r = this;

    for (let i = 0; i < k; i++)
      r = r.dbl();

    return r;
  }
}

/**
 * ShortCurve
 */

class ShortCurve extends Curve {
  constructor(conf) {
    super();
    super.init('short', conf);

    this.a = new BN(conf.a, 16).toRed(this.red);
    this.b = new BN(conf.b, 16).toRed(this.red);
    this.tinv = this.two.redInvm();

    this.zeroA = this.a.fromRed().cmpn(0) === 0;
    this.threeA = this.a.fromRed().sub(this.p).cmpn(-3) === 0;

    // If the curve is endomorphic, precalculate beta and lambda.
    this.endo = this._getEndomorphism(conf);
  }

  _getEndomorphism(conf) {
    assert(conf && typeof conf === 'object');

    // No efficient endomorphism.
    if (!this.zeroA || !this.g || !this.n || this.p.modrn(3) !== 1)
      return null;

    // Compute beta and lambda, that lambda * P = (beta * Px; Py).
    let beta;
    let lambda;

    if (conf.beta) {
      beta = new BN(conf.beta, 16).toRed(this.red);
    } else {
      const betas = this._getEndoRoots(this.p);

      // Choose the smallest beta.
      beta = betas[0].cmp(betas[1]) < 0 ? betas[0] : betas[1];
      beta = beta.toRed(this.red);
    }

    if (conf.lambda) {
      lambda = new BN(conf.lambda, 16);
    } else {
      // Choose the lambda that is matching selected beta.
      const lambdas = this._getEndoRoots(this.n);

      if (this.g.mul(lambdas[0]).x.cmp(this.g.x.redMul(beta)) === 0) {
        lambda = lambdas[0];
      } else {
        lambda = lambdas[1];
        assert(this.g.mul(lambda).x.cmp(this.g.x.redMul(beta)) === 0);
      }
    }

    // Get basis vectors, used for balanced length-two representation.
    let basis;
    if (conf.basis) {
      basis = conf.basis.map(({a, b}) => {
        return {
          a: new BN(a, 16),
          b: new BN(b, 16)
        };
      });
    } else {
      basis = this._getEndoBasis(lambda);
    }

    return {
      beta: beta,
      lambda: lambda,
      basis: basis
    };
  }

  _getEndoRoots(num) {
    assert(num instanceof BN);

    // Find roots of for x^2 + x + 1 in F.
    // Root = (-1 +- Sqrt(-3)) / 2
    const red = num === this.p ? this.red : BN.mont(num);
    const tinv = new BN(2).toRed(red).redInvm();
    const ntinv = tinv.redNeg();

    const s = new BN(3).toRed(red).redINeg().redSqrt().redMul(tinv);

    const l1 = ntinv.redAdd(s).fromRed();
    const l2 = ntinv.redISub(s).fromRed();

    return [l1, l2];
  }

  _getEndoBasis(lambda) {
    assert(lambda instanceof BN);

    // aprxSqrt >= sqrt(this.n)
    const aprxSqrt = this.n.ushrn(Math.floor(this.n.bitLength() / 2));

    // 3.74
    // Run EGCD, until r(L + 1) < aprxSqrt.
    let u = lambda;
    let v = this.n.clone();
    let x1 = new BN(1);
    let y1 = new BN(0);
    let x2 = new BN(0);
    let y2 = new BN(1);

    // All vectors are roots of: a + b * lambda = 0 (mod n).
    let a0;
    let b0;

    // First vector.
    let a1;
    let b1;

    // Second vector.
    let a2;
    let b2;

    let prevR;
    let i = 0;
    let r;
    let x;

    while (u.cmpn(0) !== 0) {
      const q = v.div(u);

      r = v.sub(q.mul(u));
      x = x2.sub(q.mul(x1));

      const y = y2.sub(q.mul(y1));

      if (!a1 && r.cmp(aprxSqrt) < 0) {
        a0 = prevR.neg();
        b0 = x1;
        a1 = r.neg();
        b1 = x;
      } else if (a1 && ++i === 2) {
        break;
      }

      prevR = r;

      v = u;
      u = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
    }

    a2 = r.neg();
    b2 = x;

    const len1 = a1.sqr().iadd(b1.sqr());
    const len2 = a2.sqr().iadd(b2.sqr());

    if (len2.cmp(len1) >= 0) {
      a2 = a0;
      b2 = b0;
    }

    // Normalize signs.
    if (a1.isNeg()) {
      a1 = a1.neg();
      b1 = b1.neg();
    }

    if (a2.isNeg()) {
      a2 = a2.neg();
      b2 = b2.neg();
    }

    return [
      { a: a1, b: b1 },
      { a: a2, b: b2 }
    ];
  }

  _endoSplit(k) {
    assert(k instanceof BN);

    const [v1, v2] = this.endo.basis;

    const c1 = v2.b.mul(k).divRound(this.n);
    const c2 = v1.b.neg().imul(k).divRound(this.n);

    const p1 = c1.mul(v1.a);
    const p2 = c2.mul(v2.a);
    const q1 = c1.mul(v1.b);
    const q2 = c2.mul(v2.b);

    // Calculate answer.
    const k1 = k.sub(p1).isub(p2);
    const k2 = q1.add(q2).ineg();

    return [k1, k2];
  }

  pointFromX(x, odd) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    assert(x.red === this.red);

    const ax = this.a.redMul(x);
    const y2 = x.redSqr().redMul(x).redIAdd(ax).redIAdd(this.b);
    const y = y2.redSqrt();

    if (y.redSqr().cmp(y2) !== 0)
      throw new Error('Invalid point.');

    if (y.fromRed().isOdd() !== Boolean(odd))
      y.redINeg();

    return this.point(x, y);
  }

  pointFromR(x) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    assert(x.red === this.red);

    const ax = this.a.redMul(x);
    const y2 = x.redSqr().redMul(x).redIAdd(ax).redIAdd(this.b);
    const y = y2.redSqrt();

    if (y.redSqr().cmp(y2) !== 0)
      throw new Error('Invalid point.');

    return this.point(x, y);
  }

  validate(point) {
    assert(point instanceof Point);

    if (point.inf)
      return true;

    const {x, y} = point;
    const ax = this.a.redMul(x);
    const y2 = x.redSqr().redMul(x).redIAdd(ax).redIAdd(this.b);

    return y.redSqr().cmp(y2) === 0;
  }

  _endoWnafMulAdd(points, coeffs, initial, jacobian) {
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(initial == null || (initial instanceof Point));
    assert(typeof jacobian === 'boolean');
    assert(points.length === coeffs.length);
    assert(this.endo != null);

    const len = points.length;
    const npoints = [];
    const ncoeffs = [];

    for (let i = 0; i < len; i++) {
      const point = points[i];
      const coeff = coeffs[i];

      assert(point instanceof Point);
      assert(point.type === 'affine');

      const [k1, k2] = this._endoSplit(coeff);

      let p = point;
      let beta = p._getBeta();

      assert(beta != null);

      if (k1.isNeg()) {
        k1.ineg();
        p = p.neg(true);
      }

      if (k2.isNeg()) {
        k2.ineg();
        beta = beta.neg(true);
      }

      npoints[i * 2] = p;
      npoints[i * 2 + 1] = beta;
      ncoeffs[i * 2] = k1;
      ncoeffs[i * 2 + 1] = k2;
    }

    return this._wnafMulAdd(1, npoints, ncoeffs, initial, jacobian);
  }

  _mulAll(points, coeffs, initial, jacobian) {
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);

    if (this.endo && points.length > 0 && points[0].type === 'affine')
      return this._endoWnafMulAdd(points, coeffs, initial, jacobian);

    return this._wnafMulAdd(1, points, coeffs, initial, jacobian);
  }

  point(x, y) {
    return new ShortPoint(this, x, y);
  }

  pointFromJSON(json) {
    return ShortPoint.fromJSON(this, json);
  }

  jpoint(x, y, z) {
    return new JPoint(this, x, y, z);
  }
}

/**
 * ShortPoint
 */

class ShortPoint extends Point {
  constructor(curve, x, y) {
    super(curve, 'affine');

    if (x === null && y === null) {
      this.x = null;
      this.y = null;
      this.inf = true;
    } else {
      this.x = new BN(x, 16);
      this.y = new BN(y, 16);

      if (!this.x.red)
        this.x = this.x.toRed(this.curve.red);

      if (!this.y.red)
        this.y = this.y.toRed(this.curve.red);

      this.inf = false;
    }
  }

  _getBeta() {
    if (!this.curve.endo)
      return null;

    const pre = this.precomputed;

    if (pre && pre.beta)
      return pre.beta;

    const beta = this.curve.point(this.x.redMul(this.curve.endo.beta), this.y);

    if (pre) {
      const curve = this.curve;
      const endoMul = p =>
        curve.point(p.x.redMul(curve.endo.beta), p.y);

      pre.beta = beta;

      beta.precomputed = {
        naf: pre.naf && {
          wnd: pre.naf.wnd,
          points: pre.naf.points.map(endoMul)
        },
        doubles: pre.doubles && {
          step: pre.doubles.step,
          points: pre.doubles.points.map(endoMul)
        },
        beta: null,
        blinding: null
      };
    }

    return beta;
  }

  toJSON() {
    const x = this.x.fromRed();
    const y = this.y.fromRed();

    if (!this.precomputed)
      return [x, y];

    return [x, y, {
      naf: this.precomputed.naf && {
        wnd: this.precomputed.naf.wnd,
        points: this.precomputed.naf.points.slice(1)
      },
      doubles: this.precomputed.doubles && {
        step: this.precomputed.doubles.step,
        points: this.precomputed.doubles.points.slice(1)
      }
    }];
  }

  isInfinity() {
    return this.inf;
  }

  add(p) {
    assert(p instanceof Point);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P = 2P
    if (this.eq(p))
      return this.dbl();

    // P + (-P) = O
    if (this.neg().eq(p))
      return this.curve.point(null, null);

    // P + Q = O
    if (this.x.cmp(p.x) === 0)
      return this.curve.point(null, null);

    let c = this.y.redSub(p.y);

    if (c.cmpn(0) !== 0)
      c = c.redMul(this.x.redSub(p.x).redInvm());

    const nx = c.redSqr().redISub(this.x).redISub(p.x);
    const ny = c.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  mixedAdd(p) {
    assert(p instanceof Point);
    return this.add(p.toP());
  }

  dbl() {
    if (this.inf)
      return this;

    // 2P = O
    const ys1 = this.y.redAdd(this.y);

    if (ys1.cmpn(0) === 0)
      return this.curve.point(null, null);

    const a = this.curve.a;

    const x2 = this.x.redSqr();
    const dyinv = ys1.redInvm();
    const c = x2.redAdd(x2).redIAdd(x2).redIAdd(a).redMul(dyinv);

    const nx = c.redSqr().redISub(this.x.redAdd(this.x));
    const ny = c.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  getX() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.x.fromRed();
  }

  getY() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.y.fromRed();
  }

  _mul(k, initial, jacobian) {
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof JPoint));

    if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k, initial, jacobian);

    if (this.curve.endo)
      return this.curve._endoWnafMulAdd([this], [k], initial, jacobian);

    return this.curve._wnafMul(this, k, initial, jacobian);
  }

  _mulAdd(k1, p2, k2, initial, jacobian) {
    assert(k1 instanceof BN);
    assert(p2 instanceof Point);
    assert(k2 instanceof BN);
    assert(initial == null || (initial instanceof JPoint));

    const points = [this, p2];
    const coeffs = [k1, k2];

    if (this.curve.endo)
      return this.curve._endoWnafMulAdd(points, coeffs, initial, jacobian);

    return this.curve._wnafMulAdd(1, points, coeffs, initial, jacobian);
  }

  eq(p) {
    assert(p instanceof Point);

    if (this === p)
      return true;

    if (this.inf !== p.inf)
      return false;

    if (this.inf)
      return true;

    return this.x.cmp(p.x) === 0
        && this.y.cmp(p.y) === 0;
  }

  neg(precomp = false) {
    assert(typeof precomp === 'boolean');

    if (this.inf)
      return this;

    const res = this.curve.point(this.x, this.y.redNeg());

    if (precomp && this.precomputed) {
      const pre = this.precomputed;
      const negate = p => p.neg();

      res.precomputed = {
        naf: pre.naf && {
          wnd: pre.naf.wnd,
          points: pre.naf.points.map(negate)
        },
        doubles: pre.doubles && {
          step: pre.doubles.step,
          points: pre.doubles.points.map(negate)
        },
        beta: null,
        blinding: null
      };
    }

    return res;
  }

  toJ() {
    if (this.inf)
      return this.curve.jpoint(null, null, null);

    return this.curve.jpoint(this.x, this.y, this.curve.one);
  }

  [custom]() {
    if (this.isInfinity())
      return '<ShortPoint: Infinity>';

    return '<ShortPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + '>';
  }

  static fromJSON(curve, json) {
    assert(curve instanceof Curve);
    assert(Array.isArray(json));

    const [x, y, pre] = json;
    const point = curve.point(x, y);

    if (!pre)
      return point;

    const {naf, doubles} = pre;
    const convert = ([x, y]) => curve.point(x, y);

    point.precomputed = {
      naf: naf && {
        wnd: naf.wnd,
        points: [point, ...naf.points.map(convert)]
      },
      doubles: doubles && {
        step: doubles.step,
        points: [point, ...doubles.points.map(convert)]
      },
      beta: null,
      blinding: null
    };

    return point;
  }
}

/**
 * JPoint
 */

class JPoint extends Point {
  constructor(curve, x, y, z) {
    super(curve, 'jacobian');

    if (x === null && y === null && z === null) {
      this.x = this.curve.one;
      this.y = this.curve.one;
      this.z = new BN(0);
    } else {
      this.x = new BN(x, 16);
      this.y = new BN(y, 16);
      this.z = new BN(z, 16);
    }

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one);
  }

  toJ() {
    return this.curve.point(this.x, this.y, this.z);
  }

  toP() {
    if (this.isInfinity())
      return this.curve.point(null, null);

    const zinv = this.z.redInvm();
    const zinv2 = zinv.redSqr();
    const ax = this.x.redMul(zinv2);
    const ay = this.y.redMul(zinv2).redMul(zinv);

    return this.curve.point(ax, ay);
  }

  neg() {
    return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
  }

  add(p) {
    assert(p instanceof Point);

    // O + P = P
    if (this.isInfinity())
      return p;

    // P + O = P
    if (p.isInfinity())
      return this;

    // 12M + 4S + 7A
    const pz2 = p.z.redSqr();
    const z2 = this.z.redSqr();
    const u1 = this.x.redMul(pz2);
    const u2 = p.x.redMul(z2);
    const s1 = this.y.redMul(pz2.redMul(p.z));
    const s2 = p.y.redMul(z2.redMul(this.z));

    const h = u1.redSub(u2);
    const r = s1.redSub(s2);

    if (h.cmpn(0) === 0) {
      if (r.cmpn(0) !== 0)
        return this.curve.jpoint(null, null, null);

      return this.dbl();
    }

    const h2 = h.redSqr();
    const h3 = h2.redMul(h);
    const v = u1.redMul(h2);

    const nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
    const nz = this.z.redMul(p.z).redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  }

  mixedAdd(p) {
    assert(p instanceof Point);

    // O + P = P
    if (this.isInfinity())
      return p.toJ();

    // P + O = P
    if (p.isInfinity())
      return this;

    // 8M + 3S + 7A
    const z2 = this.z.redSqr();
    const u1 = this.x;
    const u2 = p.x.redMul(z2);
    const s1 = this.y;
    const s2 = p.y.redMul(z2).redMul(this.z);

    const h = u1.redSub(u2);
    const r = s1.redSub(s2);

    if (h.cmpn(0) === 0) {
      if (r.cmpn(0) !== 0)
        return this.curve.jpoint(null, null, null);
      return this.dbl();
    }

    const h2 = h.redSqr();
    const h3 = h2.redMul(h);
    const v = u1.redMul(h2);

    const nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v);
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3));
    const nz = this.z.redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  }

  dblp(pow) {
    assert((pow >>> 0) === pow);

    if (pow === 0)
      return this;

    if (this.isInfinity())
      return this;

    if (!pow)
      return this.dbl();

    if (this.curve.zeroA || this.curve.threeA) {
      let r = this;

      for (let i = 0; i < pow; i++)
        r = r.dbl();

      return r;
    }

    // 1M + 2S + 1A + N * (4S + 5M + 8A)
    // N = 1 => 6M + 6S + 9A
    const a = this.curve.a;
    const tinv = this.curve.tinv;

    let jx = this.x;
    const jy = this.y;
    let jz = this.z;
    let jz4 = jz.redSqr().redSqr();

    // Reuse results
    let jyd = jy.redAdd(jy);

    for (let i = 0; i < pow; i++) {
      const jx2 = jx.redSqr();
      const jyd2 = jyd.redSqr();
      const jyd4 = jyd2.redSqr();
      const c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

      const t1 = jx.redMul(jyd2);
      const nx = c.redSqr().redISub(t1.redAdd(t1));
      const t2 = t1.redISub(nx);

      let dny = c.redMul(t2);
      dny = dny.redIAdd(dny).redISub(jyd4);

      const nz = jyd.redMul(jz);

      if (i + 1 < pow)
        jz4 = jz4.redMul(jyd4);

      jx = nx;
      jz = nz;
      jyd = dny;
    }

    return this.curve.jpoint(jx, jyd.redMul(tinv), jz);
  }

  dbl() {
    if (this.isInfinity())
      return this;

    if (this.curve.zeroA)
      return this._zeroDbl();

    if (this.curve.threeA)
      return this._threeDbl();

    return this._dbl();
  }

  _zeroDbl() {
    let nx;
    let ny;
    let nz;

    // Z = 1
    if (this.zOne) {
      // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
      //     #doubling-mdbl-2007-bl
      // 1M + 5S + 14A

      // XX = X1^2
      const xx = this.x.redSqr();

      // YY = Y1^2
      const yy = this.y.redSqr();

      // YYYY = YY^2
      const yyyy = yy.redSqr();

      // S = 2 * ((X1 + YY)^2 - XX - YYYY)
      let s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
      s = s.redIAdd(s);

      // M = 3 * XX + a; a = 0
      const m = xx.redAdd(xx).redIAdd(xx);

      // T = M ^ 2 - 2*S
      const t = m.redSqr().redISub(s).redISub(s);

      // 8 * YYYY
      let yyyy8 = yyyy.redIAdd(yyyy);
      yyyy8 = yyyy8.redIAdd(yyyy8);
      yyyy8 = yyyy8.redIAdd(yyyy8);

      // X3 = T
      nx = t;

      // Y3 = M * (S - T) - 8 * YYYY
      ny = m.redMul(s.redISub(t)).redISub(yyyy8);

      // Z3 = 2*Y1
      nz = this.y.redAdd(this.y);
    } else {
      // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
      //     #doubling-dbl-2009-l
      // 2M + 5S + 13A

      // A = X1^2
      const a = this.x.redSqr();

      // B = Y1^2
      const b = this.y.redSqr();

      // C = B^2
      const c = b.redSqr();

      // D = 2 * ((X1 + B)^2 - A - C)
      let d = this.x.redAdd(b).redSqr().redISub(a).redISub(c);
      d = d.redIAdd(d);

      // E = 3 * A
      const e = a.redAdd(a).redIAdd(a);

      // F = E^2
      const f = e.redSqr();

      // 8 * C
      let c8 = c.redIAdd(c);
      c8 = c8.redIAdd(c8);
      c8 = c8.redIAdd(c8);

      // X3 = F - 2 * D
      nx = f.redISub(d).redISub(d);

      // Y3 = E * (D - X3) - 8 * C
      ny = e.redMul(d.redISub(nx)).redISub(c8);

      // Z3 = 2 * Y1 * Z1
      nz = this.y.redMul(this.z);
      nz = nz.redIAdd(nz);
    }

    return this.curve.jpoint(nx, ny, nz);
  }

  _threeDbl() {
    let nx;
    let ny;
    let nz;

    // Z = 1
    if (this.zOne) {
      // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
      //     #doubling-mdbl-2007-bl
      // 1M + 5S + 15A

      // XX = X1^2
      const xx = this.x.redSqr();

      // YY = Y1^2
      const yy = this.y.redSqr();

      // YYYY = YY^2
      const yyyy = yy.redSqr();

      // S = 2 * ((X1 + YY)^2 - XX - YYYY)
      let s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
      s = s.redIAdd(s);

      // M = 3 * XX + a
      const m = xx.redAdd(xx).redIAdd(xx).redIAdd(this.curve.a);

      // T = M^2 - 2 * S
      const t = m.redSqr().redISub(s).redISub(s);

      // X3 = T
      nx = t;

      // Y3 = M * (S - T) - 8 * YYYY
      let yyyy8 = yyyy.redIAdd(yyyy);
      yyyy8 = yyyy8.redIAdd(yyyy8);
      yyyy8 = yyyy8.redIAdd(yyyy8);
      ny = m.redMul(s.redISub(t)).redISub(yyyy8);

      // Z3 = 2 * Y1
      nz = this.y.redAdd(this.y);
    } else {
      // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
      // 3M + 5S

      // delta = Z1^2
      const delta = this.z.redSqr();

      // gamma = Y1^2
      const gamma = this.y.redSqr();

      // beta = X1 * gamma
      const beta = this.x.redMul(gamma);

      // alpha = 3 * (X1 - delta) * (X1 + delta)
      let alpha = this.x.redSub(delta).redMul(this.x.redAdd(delta));
      alpha = alpha.redAdd(alpha).redIAdd(alpha);

      // X3 = alpha^2 - 8 * beta
      let beta4 = beta.redIAdd(beta);
      beta4 = beta4.redIAdd(beta4);

      const beta8 = beta4.redAdd(beta4);
      nx = alpha.redSqr().redISub(beta8);

      // Z3 = (Y1 + Z1)^2 - gamma - delta
      nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);

      // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
      let ggamma8 = gamma.redSqr();
      ggamma8 = ggamma8.redIAdd(ggamma8);
      ggamma8 = ggamma8.redIAdd(ggamma8);
      ggamma8 = ggamma8.redIAdd(ggamma8);
      ny = alpha.redMul(beta4.redISub(nx)).redISub(ggamma8);
    }

    return this.curve.jpoint(nx, ny, nz);
  }

  _dbl() {
    const a = this.curve.a;

    // 4M + 6S + 10A
    const jx = this.x;
    const jy = this.y;
    const jz = this.z;
    const jz4 = jz.redSqr().redSqr();

    const jx2 = jx.redSqr();
    const jy2 = jy.redSqr();

    const c = jx2.redAdd(jx2).redIAdd(jx2).redIAdd(a.redMul(jz4));

    let jxd4 = jx.redAdd(jx);
    jxd4 = jxd4.redIAdd(jxd4);

    const t1 = jxd4.redMul(jy2);
    const nx = c.redSqr().redISub(t1.redAdd(t1));
    const t2 = t1.redISub(nx);

    let jyd8 = jy2.redSqr();
    jyd8 = jyd8.redIAdd(jyd8);
    jyd8 = jyd8.redIAdd(jyd8);
    jyd8 = jyd8.redIAdd(jyd8);

    const ny = c.redMul(t2).redISub(jyd8);
    const nz = jy.redAdd(jy).redMul(jz);

    return this.curve.jpoint(nx, ny, nz);
  }

  trpl() {
    if (!this.curve.zeroA)
      return this.dbl().add(this);

    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#tripling-tpl-2007-bl
    // 5M + 10S + ...

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // YYYY = YY^2
    const yyyy = yy.redSqr();

    // M = 3 * XX + a * ZZ2; a = 0
    const m = xx.redAdd(xx).redIAdd(xx);

    // MM = M^2
    const mm = m.redSqr();

    // E = 6 * ((X1 + YY)^2 - XX - YYYY) - MM
    let e = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy);
    e = e.redIAdd(e);
    e = e.redAdd(e).redIAdd(e);
    e = e.redISub(mm);

    // EE = E^2
    const ee = e.redSqr();

    // T = 16*YYYY
    let t = yyyy.redIAdd(yyyy);
    t = t.redIAdd(t);
    t = t.redIAdd(t);
    t = t.redIAdd(t);

    // U = (M + E)^2 - MM - EE - T
    const u = m.redIAdd(e).redSqr().redISub(mm).redISub(ee).redISub(t);

    // X3 = 4 * (X1 * EE - 4 * YY * U)
    let yyu4 = yy.redMul(u);
    yyu4 = yyu4.redIAdd(yyu4);
    yyu4 = yyu4.redIAdd(yyu4);

    let nx = this.x.redMul(ee).redISub(yyu4);
    nx = nx.redIAdd(nx);
    nx = nx.redIAdd(nx);

    // Y3 = 8 * Y1 * (U * (T - U) - E * EE)
    let ny = this.y.redMul(u.redMul(t.redISub(u)).redISub(e.redMul(ee)));
    ny = ny.redIAdd(ny);
    ny = ny.redIAdd(ny);
    ny = ny.redIAdd(ny);

    // Z3 = (Z1 + E)^2 - ZZ - EE
    const nz = this.z.redAdd(e).redSqr().redISub(zz).redISub(ee);

    return this.curve.jpoint(nx, ny, nz);
  }

  _mul(k, initial, jacobian) {
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof JPoint));

    return this.curve._wnafMul(this, k, initial, jacobian);
  }

  _mulAdd(k1, p, k2, initial, jacobian) {
    assert(k1 instanceof BN);
    assert(p instanceof Point);
    assert(k2 instanceof BN);
    assert(initial == null || (initial instanceof JPoint));

    return this.curve._wnafMulAdd(1, [this, p], [k1, k2], initial, jacobian);
  }

  eq(p) {
    assert(p instanceof Point);

    if (p.type === 'affine')
      return this.eq(p.toJ());

    if (this === p)
      return true;

    // x1 * z2^2 == x2 * z1^2
    const z2 = this.z.redSqr();
    const pz2 = p.z.redSqr();

    if (this.x.redMul(pz2).redISub(p.x.redMul(z2)).cmpn(0) !== 0)
      return false;

    // y1 * z2^3 == y2 * z1^3
    const z3 = z2.redMul(this.z);
    const pz3 = pz2.redMul(p.z);

    return this.y.redMul(pz3).redISub(p.y.redMul(z3)).cmpn(0) === 0;
  }

  hasQuadY() {
    return this.y.redMul(this.z).redJacobi() === 1;
  }

  eqX(x) {
    assert(x instanceof BN);

    const zs = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redIMul(zs);

    return this.x.cmp(rx) === 0;
  }

  eqXToP(x) {
    assert(x instanceof BN);
    assert(this.curve.redN);

    const zs = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zs);

    if (this.x.cmp(rx) === 0)
      return true;

    const xc = x.clone();
    const t = this.curve.redN.redMul(zs);

    for (;;) {
      xc.iadd(this.curve.n);

      if (xc.cmp(this.curve.p) >= 0)
        return false;

      rx.redIAdd(t);

      if (this.x.cmp(rx) === 0)
        break;
    }

    return true;
  }

  isInfinity() {
    // This code assumes that zero is always zero in red.
    return this.z.cmpn(0) === 0;
  }

  [custom]() {
    if (this.isInfinity())
      return '<JPoint: Infinity>';

    return '<JPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + ' z=' + this.z.fromRed().toString(16, 2)
         + '>';
  }
}

/**
 * MontCurve
 */

class MontCurve extends Curve {
  constructor(conf) {
    super();
    super.init('mont', conf);

    this.a = new BN(conf.a, 16).toRed(this.red);
    this.b = new BN(conf.b, 16).toRed(this.red);
    this.i4 = new BN(4).toRed(this.red).redInvm();
    this.a24 = this.i4.redMul(this.a.redAdd(this.two));
  }

  decodePoint(bytes) {
    const x = this.decodeInt(bytes);

    // We're supposed to ignore the hi bit
    // on montgomery points... I think. If
    // we don't, the X25519 test vectors
    // break, which is pretty convincing
    // evidence. This is a no-op for X448.
    x.setn(this.signBit, 0);

    // Note: montgomery points are meant to be
    // reduced by the prime and do not have to
    // be explicitly validated in order to do
    // the montgomery ladder (see rfc7748,
    // section 5).
    const p = this.point(x, this.one);

    assert(!p.isInfinity());

    return p;
  }

  pointFromEdwards(point) {
    assert(point instanceof EdwardsPoint);

    if (point.isInfinity())
      throw new Error('Invalid point.');

    point.normalize();

    // Edwards point.
    const {x, y, z} = point;

    // Montgomery `u`.
    let u = null;

    if (point.curve.twisted) {
      // Birational maps:
      //   u = (1+y)/(1-y)
      //   v = sqrt(-486664)*u/x
      const lhs = z.redAdd(y);
      const rhs = z.redSub(y);

      u = lhs.redIMul(rhs.redInvm());
    } else {
      // Birational maps:
      //   u = (y-1)/(y+1)
      //   v = sqrt(156324)*u/x
      //
      // 4-isogeny maps:
      //   u = y^2/x^2
      //   v = (2 - x^2 - y^2)*y/x^3
      const lhs = y.redSqr();
      const rhs = x.redSqr();

      u = lhs.redIMul(rhs.redInvm());
    }

    // Montgomery point.
    return this.point(u.fromRed(), this.one);
  }

  validate(point) {
    assert(point instanceof Point);

    const x = point.normalize().x;
    const x2 = x.redSqr();
    const y2 = x2.redMul(x).redIAdd(x2.redMul(this.a)).redIAdd(x);
    const y = y2.redSqrt();

    return y.redSqr().cmp(y2) === 0;
  }

  _mulAll(points, coeffs, initial, jacobian) {
    throw new Error('Not supported on Montgomery curve.');
  }

  point(x, z) {
    return new MontPoint(this, x, z);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point(null, null);
  }

  pointFromJSON(json) {
    return MontPoint.fromJSON(this, json);
  }
}

/**
 * MontPoint
 */

class MontPoint extends Point {
  constructor(curve, x, z) {
    super(curve, 'projective');

    if (x === null && z === null) {
      this.x = this.curve.one;
      this.z = this.curve.zero;
    } else {
      this.x = new BN(x, 16);
      this.z = new BN(z, 16);

      if (!this.x.red)
        this.x = this.x.toRed(this.curve.red);

      if (!this.z.red)
        this.z = this.z.toRed(this.curve.red);
    }
  }

  precompute(power, rng) {
    // No-op.
    return this;
  }

  encode() {
    return this.curve.encodeInt(this.getX());
  }

  isInfinity() {
    // This code assumes that zero is always zero in red.
    return this.z.cmpn(0) === 0;
  }

  dbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
    // 2M + 2S + 4A

    // A = X1 + Z1
    const a = this.x.redAdd(this.z);

    // AA = A^2
    const aa = a.redSqr();

    // B = X1 - Z1
    const b = this.x.redSub(this.z);

    // BB = B^2
    const bb = b.redSqr();

    // C = AA - BB
    const c = aa.redSub(bb);

    // X3 = AA * BB
    const nx = aa.redMul(bb);

    // Z3 = C * (BB + A24 * C)
    const nz = c.redMul(bb.redIAdd(this.curve.a24.redMul(c)));

    return this.curve.point(nx, nz);
  }

  add() {
    throw new Error('Not supported on Montgomery curve.');
  }

  diffAdd(p, diff) {
    assert(p instanceof Point);
    assert(diff instanceof Point);

    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
    // 4M + 2S + 6A

    // A = X2 + Z2
    const a = this.x.redAdd(this.z);

    // B = X2 - Z2
    const b = this.x.redSub(this.z);

    // C = X3 + Z3
    const c = p.x.redAdd(p.z);

    // D = X3 - Z3
    const d = p.x.redSub(p.z);

    // DA = D * A
    const da = d.redMul(a);

    // CB = C * B
    const cb = c.redMul(b);

    // X5 = Z1 * (DA + CB)^2
    const nx = diff.z.redMul(da.redAdd(cb).redSqr());

    // Z5 = X1 * (DA - CB)^2
    const nz = diff.x.redMul(da.redISub(cb).redSqr());

    return this.curve.point(nx, nz);
  }

  _mul(k, initial, jacobian) {
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof MontPoint));

    const s = this.curve.mask.reduce(k.clone());
    const bits = this.curve.p.bitLength();

    let a = this; // (N / 2) * Q + Q
    let b = initial || this.curve.point(null, null); // (N / 2) * Q

    const c = this; // Q

    // Montgomery ladder.
    // https://tools.ietf.org/html/rfc7748#section-5
    for (let i = bits - 1; i >= 0; i--) {
      const bit = s.testn(i) | 0;

      if (bit === 0) {
        // N * Q + Q = ((N / 2) * Q + Q)) + (N / 2) * Q
        a = a.diffAdd(b, c);
        // N * Q = 2 * ((N / 2) * Q + Q))
        b = b.dbl();
      } else {
        // N * Q = ((N / 2) * Q + Q) + ((N / 2) * Q)
        b = b.diffAdd(a, c);
        // N * Q + Q = 2 * ((N / 2) * Q + Q)
        a = a.dbl();
      }
    }

    return b;
  }

  _mulBlind(k, rng = null, jacobian) {
    // Can't do this due to the clamping.
    throw new Error('Not supported on Montgomery curve.');
  }

  _mulAdd(k1, p2, k2, initial, jacobian) {
    throw new Error('Not supported on Montgomery curve.');
  }

  eq(other) {
    assert(other instanceof Point);
    return this.getX().cmp(other.getX()) === 0;
  }

  normalize() {
    this.x = this.x.redMul(this.z.redInvm());
    this.z = this.curve.one;
    return this;
  }

  getX() {
    // Normalize coordinates. This will
    // throw if the point is at infinity
    // (z=0 is not invertible), but do
    // an explicit check anyway.
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  mixedAdd(p) {
    throw new Error('Not supported on Montgomery curve.');
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this.curve.point(this.x, this.z);
  }

  toJSON() {
    return [this.getX()];
  }

  [custom]() {
    if (this.isInfinity())
      return '<MontPoint: Infinity>';

    return '<MontPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }

  static fromJSON(curve, json) {
    assert(curve instanceof Curve);
    assert(Array.isArray(json));

    const [x, z] = json;

    return curve.point(x, z || curve.one);
  }
}

/**
 * EdwardsCurve
 */

class EdwardsCurve extends Curve {
  constructor(conf) {
    assert(conf && typeof conf === 'object');

    super();

    // NOTE: Important as we are creating point in super.init().
    this.twisted = (conf.a | 0) !== 1;
    this.mOneA = this.twisted && (conf.a | 0) === -1;
    this.extended = this.mOneA;

    super.init('edwards', conf);

    this.a = new BN(conf.a, 16).umod(this.p).toRed(this.red);
    this.c = new BN(conf.c, 16).toRed(this.red);
    this.c2 = this.c.redSqr();
    this.d = new BN(conf.d, 16).toRed(this.red);
    this.dd = this.d.redAdd(this.d);

    assert(!this.twisted || this.c.fromRed().cmpn(1) === 0);

    this.oneC = (conf.c | 0) === 1;
  }

  _mulA(num) {
    assert(num instanceof BN);

    if (this.mOneA)
      return num.redNeg();

    return this.a.redMul(num);
  }

  _mulC(num) {
    assert(num instanceof BN);

    if (this.oneC)
      return num;

    return this.c.redMul(num);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point(null, null, null, null);
  }

  pointFromX(x, odd) {
    assert(x instanceof BN);

    if (!x.red)
      x = x.toRed(this.red);

    assert(x.red === this.red);

    const x2 = x.redSqr();
    const lhs = this.c2.redSub(this.a.redMul(x2));
    const rhs = this.one.redSub(this.c2.redMul(this.d).redMul(x2));
    const y2 = lhs.redMul(rhs.redInvm());
    const y = y2.redSqrt();

    if (y.redSqr().cmp(y2) !== 0)
      throw new Error('Invalid point.');

    if (y.fromRed().isOdd() !== Boolean(odd))
      y.redINeg();

    return this.point(x, y);
  }

  pointFromY(y, odd) {
    assert(y instanceof BN);

    if (!y.red)
      y = y.toRed(this.red);

    assert(y.red === this.red);

    // x^2 = (y^2 - c^2) / (c^2 d y^2 - a)
    const y2 = y.redSqr();
    const lhs = y2.redSub(this.c2);
    const rhs = y2.redMul(this.d).redMul(this.c2).redISub(this.a);
    const x2 = lhs.redMul(rhs.redInvm());

    if (x2.cmp(this.zero) === 0) {
      if (odd)
        throw new Error('Invalid point.');
      return this.point(this.zero, y);
    }

    const x = x2.redSqrt();

    if (x.redSqr().cmp(x2) !== 0)
      throw new Error('Invalid point.');

    if (x.fromRed().isOdd() !== Boolean(odd))
      x.redINeg();

    return this.point(x, y);
  }

  pointFromMont(point, odd) {
    assert(point instanceof MontPoint);

    point.normalize();

    // Montgomery point.
    const u = point.x;
    const v = point.z;

    // Edwards `y`.
    let y = null;

    if (this.twisted) {
      // Birational maps:
      //   x = sqrt(-486664)*u/v
      //   y = (u-1)/(u+1)
      const lhs = u.redSub(v);
      const rhs = u.redAdd(v);

      y = lhs.redIMul(rhs.redInvm());
    } else {
      // Birational maps:
      //   x = sqrt(156324)*u/v
      //   y = (1+u)/(1-u)
      //
      // 4-isogeny maps:
      //   x = 4*v*(u^2 - 1)/(u^4 - 2*u^2 + 4*v^2 + 1)
      //   y = -(u^5 - 2*u^3 - 4*u*v^2 + u)/
      //        (u^5 - 2*u^2*v^2 - 2*u^3 - 2*v^2 + u)
      throw new Error('Unimplemented.');
    }

    // Edwards point.
    return this.pointFromY(y.fromRed(), odd);
  }

  validate(point) {
    assert(point instanceof Point);

    if (point.isInfinity())
      return true;

    // Curve: A * X^2 + Y^2 = C^2 * (1 + D * X^2 * Y^2)
    point.normalize();

    const x2 = point.x.redSqr();
    const y2 = point.y.redSqr();
    const lhs = x2.redMul(this.a).redIAdd(y2);
    const rhs = this.c2.redMul(this.one.redAdd(this.d.redMul(x2).redMul(y2)));

    return lhs.cmp(rhs) === 0;
  }

  decodePoint(bytes) {
    const y = this.decodeInt(bytes);
    const xIsOdd = y.testn(this.signBit);

    y.setn(this.signBit, 0);

    if (y.cmp(this.p) >= 0)
      throw new Error('Invalid point.');

    const p = this.pointFromY(y, xIsOdd);

    // Note that it _is_ possible to serialize
    // points at infinity for edwards curves.
    if (p.isInfinity())
      throw new Error('Invalid point.');

    return p;
  }

  _mulAll(points, coeffs, initial, jacobian) {
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);

    return this._wnafMulAdd(1, points, coeffs, initial, jacobian);
  }

  pointFromJSON(json) {
    return EdwardsPoint.fromJSON(this, json);
  }

  point(x, y, z, t) {
    return new EdwardsPoint(this, x, y, z, t);
  }
}

/**
 * EdwardsPoint
 */

class EdwardsPoint extends Point {
  constructor(curve, x, y, z, t) {
    super(curve, 'projective');

    if (x === null && y === null && z === null) {
      this.x = this.curve.zero;
      this.y = this.curve.one;
      this.z = this.curve.one;
      this.t = this.curve.zero;
      this.zOne = true;
    } else {
      this.x = new BN(x, 16);
      this.y = new BN(y, 16);
      this.z = z ? new BN(z, 16) : this.curve.one;
      this.t = t ? new BN(t, 16) : null;

      if (!this.x.red)
        this.x = this.x.toRed(this.curve.red);

      if (!this.y.red)
        this.y = this.y.toRed(this.curve.red);

      if (!this.z.red)
        this.z = this.z.toRed(this.curve.red);

      if (this.t && !this.t.red)
        this.t = this.t.toRed(this.curve.red);

      this.zOne = this.z.eq(this.curve.one);

      // Use extended coordinates.
      if (this.curve.extended && !this.t) {
        this.t = this.x.redMul(this.y);
        if (!this.zOne)
          this.t = this.t.redMul(this.z.redInvm());
      }
    }
  }

  encode() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    const y = this.getY();

    y.setn(this.curve.signBit,
           this.getX().isOdd());

    return this.curve.encodeInt(y);
  }

  isInfinity() {
    // This code assumes that zero is always zero in red.
    if (this.x.cmpn(0) !== 0)
      return false;

    if (this.y.cmp(this.z) === 0)
      return true;

    if (this.zOne && this.y.cmp(this.curve.c) === 0)
      return true;

    return false;
  }

  _extDbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    //     #doubling-dbl-2008-hwcd
    // 4M + 4S

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = 2 * Z1^2
    let c = this.z.redSqr();
    c = c.redIAdd(c);

    // D = a * A
    const d = this.curve._mulA(a);

    // E = (X1 + Y1)^2 - A - B
    const e = this.x.redAdd(this.y).redSqr().redISub(a).redISub(b);

    // G = D + B
    const g = d.redAdd(b);

    // F = G - C
    const f = g.redSub(c);

    // H = D - B
    const h = d.redISub(b);

    // X3 = E * F
    const nx = e.redMul(f);

    // Y3 = G * H
    const ny = g.redMul(h);

    // T3 = E * H
    const nt = e.redMul(h);

    // Z3 = F * G
    const nz = f.redMul(g);

    return this.curve.point(nx, ny, nz, nt);
  }

  _projDbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
    //     #doubling-dbl-2008-bbjlp
    //     #doubling-dbl-2007-bl
    // and others
    // Generally 3M + 4S or 2M + 4S

    // B = (X1 + Y1)^2
    const b = this.x.redAdd(this.y).redSqr();
    // C = X1^2
    const c = this.x.redSqr();
    // D = Y1^2
    const d = this.y.redSqr();

    let nx;
    let ny;
    let nz;

    if (this.curve.twisted) {
      // E = a * C
      const e = this.curve._mulA(c);
      // F = E + D
      const f = e.redAdd(d);

      if (this.zOne) {
        // X3 = (B - C - D) * (F - 2)
        nx = b.redSub(c).redISub(d).redMul(f.redSub(this.curve.two));

        // Y3 = F * (E - D)
        ny = f.redMul(e.redISub(d));

        // Z3 = F^2 - 2 * F
        nz = f.redSqr().redISub(f).redISub(f);
      } else {
        // H = Z1^2
        const h = this.z.redSqr();

        // J = F - 2 * H
        const j = f.redSub(h).redISub(h);

        // X3 = (B-C-D)*J
        nx = b.redISub(c).redISub(d).redMul(j);

        // Y3 = F * (E - D)
        ny = f.redMul(e.redISub(d));

        // Z3 = F * J
        nz = f.redMul(j);
      }
    } else {
      // E = C + D
      const e = c.redAdd(d);

      // H = (c * Z1)^2
      const h = this.curve._mulC(this.z).redSqr();

      // J = E - 2 * H
      const j = e.redSub(h).redISub(h);

      // X3 = c * (B - E) * J
      nx = this.curve._mulC(b.redISub(e)).redMul(j);

      // Y3 = c * E * (C - D)
      ny = this.curve._mulC(e).redMul(c.redISub(d));

      // Z3 = E * J
      nz = e.redMul(j);
    }

    return this.curve.point(nx, ny, nz);
  }

  dbl() {
    if (this.isInfinity())
      return this;

    // Double in extended coordinates
    if (this.curve.extended)
      return this._extDbl();

    return this._projDbl();
  }

  _extAdd(p) {
    assert(p instanceof Point);

    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    //     #addition-add-2008-hwcd-3
    // 8M

    // A = (Y1 - X1) * (Y2 - X2)
    const a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));

    // B = (Y1 + X1) * (Y2 + X2)
    const b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));

    // C = T1 * k * T2
    const c = this.t.redMul(this.curve.dd).redMul(p.t);

    // D = Z1 * 2 * Z2
    const d = this.z.redMul(p.z.redAdd(p.z));

    // E = B - A
    const e = b.redSub(a);

    // F = D - C
    const f = d.redSub(c);

    // G = D + C
    const g = d.redIAdd(c);

    // H = B + A
    const h = b.redIAdd(a);

    // X3 = E * F
    const nx = e.redMul(f);

    // Y3 = G * H
    const ny = g.redMul(h);

    // T3 = E * H
    const nt = e.redMul(h);

    // Z3 = F * G
    const nz = f.redMul(g);

    return this.curve.point(nx, ny, nz, nt);
  }

  _projAdd(p) {
    assert(p instanceof Point);

    // https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
    //     #addition-add-2008-bbjlp
    //     #addition-add-2007-bl
    // 10M + 1S

    // A = Z1 * Z2
    const a = this.z.redMul(p.z);

    // B = A^2
    const b = a.redSqr();

    // C = X1 * X2
    const c = this.x.redMul(p.x);

    // D = Y1 * Y2
    const d = this.y.redMul(p.y);

    // E = d * C * D
    const e = this.curve.d.redMul(c).redMul(d);

    // F = B - E
    const f = b.redSub(e);

    // G = B + E
    const g = b.redIAdd(e);

    // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
    const tmp = this.x.redAdd(this.y)
                      .redMul(p.x.redAdd(p.y))
                      .redISub(c)
                      .redISub(d);

    const nx = a.redMul(f).redMul(tmp);

    let ny;
    let nz;

    if (this.curve.twisted) {
      // Y3 = A * G * (D - a * C)
      ny = a.redMul(g).redMul(d.redISub(this.curve._mulA(c)));
      // Z3 = F * G
      nz = f.redMul(g);
    } else {
      // Y3 = A * G * (D - C)
      ny = a.redMul(g).redMul(d.redISub(c));
      // Z3 = c * F * G
      nz = this.curve._mulC(f).redMul(g);
    }

    return this.curve.point(nx, ny, nz);
  }

  add(p) {
    assert(p instanceof Point);

    if (this.isInfinity())
      return p;

    if (p.isInfinity())
      return this;

    if (this.curve.extended)
      return this._extAdd(p);

    return this._projAdd(p);
  }

  _mul(k, initial, jacobian) {
    assert(k instanceof BN);
    assert(initial == null || (initial instanceof EdwardsPoint));

    if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k, initial, jacobian);

    return this.curve._wnafMul(this, k, initial, jacobian);
  }

  _mulAdd(k1, p, k2, initial, jacobian) {
    assert(k1 instanceof BN);
    assert(p instanceof Point);
    assert(k2 instanceof BN);
    assert(initial == null || (initial instanceof EdwardsPoint));

    return this.curve._wnafMulAdd(1, [this, p], [k1, k2], initial, jacobian);
  }

  normalize() {
    if (this.zOne)
      return this;

    // Normalize coordinates.
    const zi = this.z.redInvm();

    this.x = this.x.redMul(zi);
    this.y = this.y.redMul(zi);

    if (this.t)
      this.t = this.t.redMul(zi);

    this.z = this.curve.one;
    this.zOne = true;

    return this;
  }

  neg() {
    return this.curve.point(this.x.redNeg(),
                            this.y,
                            this.z,
                            this.t && this.t.redNeg());
  }

  getX() {
    this.normalize();
    return this.x.fromRed();
  }

  getY() {
    this.normalize();
    return this.y.fromRed();
  }

  eq(other) {
    assert(other instanceof Point);

    if (this === other)
      return true;

    return this.getX().cmp(other.getX()) === 0
        && this.getY().cmp(other.getY()) === 0;
  }

  hasQuadY() {
    return this.y.redMul(this.z).redJacobi() === 1;
  }

  eqX(x) {
    assert(x instanceof BN);

    const rx = x.toRed(this.curve.red).redIMul(this.z);

    return this.x.cmp(rx) === 0;
  }

  eqXToP(x) {
    assert(x instanceof BN);
    assert(this.curve.redN);

    const rx = x.toRed(this.curve.red).redMul(this.z);

    if (this.x.cmp(rx) === 0)
      return true;

    const xc = x.clone();
    const t = this.curve.redN.redMul(this.z);

    for (;;) {
      xc.iadd(this.curve.n);

      if (xc.cmp(this.curve.p) >= 0)
        return false;

      rx.redIAdd(t);

      if (this.x.cmp(rx) === 0)
        break;
    }

    return true;
  }

  mixedAdd(p) {
    return this.add(p);
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this.curve.point(this.x, this.y, this.z, this.t);
  }

  toJSON() {
    const x = this.getX();
    const y = this.getY();

    if (!this.precomputed)
      return [x, y];

    return [x, y, {
      naf: this.precomputed.naf && {
        wnd: this.precomputed.naf.wnd,
        points: this.precomputed.naf.points.slice(1)
      },
      doubles: this.precomputed.doubles && {
        step: this.precomputed.doubles.step,
        points: this.precomputed.doubles.points.slice(1)
      }
    }];
  }

  [custom]() {
    if (this.isInfinity())
      return '<EdwardsPoint: Infinity>';

    return '<EdwardsPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' y=' + this.y.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }

  static fromJSON(curve, json) {
    assert(curve instanceof Curve);
    assert(Array.isArray(json));

    const [x, y, pre] = json;
    const point = curve.point(x, y);

    if (!pre)
      return point;

    const {naf, doubles} = pre;
    const convert = ([x, y]) => curve.point(x, y);

    point.precomputed = {
      naf: naf && {
        wnd: naf.wnd,
        points: [point, ...naf.points.map(convert)]
      },
      doubles: doubles && {
        step: doubles.step,
        points: [point, ...doubles.points.map(convert)]
      },
      beta: null,
      blinding: null
    };

    return point;
  }
}

/**
 * P192
 */

class P192 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P192',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      seed: '3045ae6f c8422f64 ed579528 d38120ea'
          + 'e12196d5',
      prime: 'p192',
      p: 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff ffffffff',
      a: 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff fffffffc',
      b: '64210519 e59c80e7 0fa7e9ab 72243049'
       + 'feb8deec c146b9b1',
      n: 'ffffffff ffffffff ffffffff 99def836'
       + '146bc9b1 b4d22831',
      h: '1',
      g: [
        ['188da80e b03090f6 7cbf20eb 43a18800',
         'f4ff0afd 82ff1012'].join(''),
        ['07192b95 ffc8da78 631011ed 6b24cdd5',
         '73f977a1 1e794811'].join(''),
        pre
      ]
    });
  }
}

/**
 * P224
 */

class P224 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P224',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      seed: 'bd713447 99d5c7fc dc45b59f a3b9ab8f'
          + '6a948bc5',
      prime: 'p224',
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + '00000000 00000000 00000001',
      a: 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff ffffffff fffffffe',
      b: 'b4050a85 0c04b3ab f5413256 5044b0b7'
       + 'd7bfd8ba 270b3943 2355ffb4',
      n: 'ffffffff ffffffff ffffffff ffff16a2'
       + 'e0b8f03e 13dd2945 5c5c2a3d',
      h: '1',
      g: [
        ['b70e0cbd 6bb4bf7f 321390b9 4a03c1d3',
         '56c21122 343280d6 115c1d21'].join(''),
        ['bd376388 b5f723fb 4c22dfe6 cd4375a0',
         '5a074764 44d58199 85007e34'].join(''),
        pre
      ]
    });
  }
}

/**
 * P256
 */

class P256 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P256',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      seed: 'c49d3608 86e70493 6a6678e1 139d26b7'
          + '819f7e90',
      prime: null,
      p: 'ffffffff 00000001 00000000 00000000'
       + '00000000 ffffffff ffffffff ffffffff',
      a: 'ffffffff 00000001 00000000 00000000'
       + '00000000 ffffffff ffffffff fffffffc',
      b: '5ac635d8 aa3a93e7 b3ebbd55 769886bc'
       + '651d06b0 cc53b0f6 3bce3c3e 27d2604b',
      n: 'ffffffff 00000000 ffffffff ffffffff'
       + 'bce6faad a7179e84 f3b9cac2 fc632551',
      h: '1',
      g: [
        ['6b17d1f2 e12c4247 f8bce6e5 63a440f2',
         '77037d81 2deb33a0 f4a13945 d898c296'].join(''),
        ['4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16',
         '2bce3357 6b315ece cbb64068 37bf51f5'].join(''),
        pre
      ]
    });
  }
}

/**
 * P384
 */

class P384 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P384',
      type: 'short',
      endian: 'be',
      hash: 'SHA384',
      prefix: null,
      context: false,
      seed: 'a335926a a319a27a 1d00896a 6773a482'
          + '7acdac73',
      prime: null,
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff 00000000 00000000 ffffffff',
      a: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff fffffffe'
       + 'ffffffff 00000000 00000000 fffffffc',
      b: 'b3312fa7 e23ee7e4 988e056b e3f82d19'
       + '181d9c6e fe814112 0314088f 5013875a'
       + 'c656398d 8a2ed19d 2a85c8ed d3ec2aef',
      n: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff c7634d81 f4372ddf'
       + '581a0db2 48b0a77a ecec196a ccc52973',
      h: '1',
      g: [
        ['aa87ca22 be8b0537 8eb1c71e f320ad74',
         '6e1d3b62 8ba79b98 59f741e0 82542a38',
         '5502f25d bf55296c 3a545e38 72760ab7'].join(''),
        ['3617de4a 96262c6f 5d9e98bf 9292dc29',
         'f8f41dbd 289a147c e9da3113 b5f0b8c0',
         '0a60b1ce 1d7e819d 7a431d7c 90ea0e5f'].join(''),
        pre
      ]
    });
  }
}

/**
 * P521
 */

class P521 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P521',
      type: 'short',
      endian: 'be',
      hash: 'SHA512',
      prefix: null,
      context: false,
      seed: 'd09e8800 291cb853 96cc6717 393284aa'
          + 'a0da64ba',
      prime: 'p521',
      p: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff',
      a: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'fffffffc',
      b: '00000051 953eb961 8e1c9a1f 929a21a0'
       + 'b68540ee a2da725b 99b315f3 b8b48991'
       + '8ef109e1 56193951 ec7e937b 1652c0bd'
       + '3bb1bf07 3573df88 3d2c34f1 ef451fd4'
       + '6b503f00',
      n: '000001ff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'fffffffa 51868783 bf2f966b 7fcc0148'
       + 'f709a5d0 3bb5c9b8 899c47ae bb6fb71e'
       + '91386409',
      h: '1',
      g: [
        ['000000c6 858e06b7 0404e9cd 9e3ecb66',
         '2395b442 9c648139 053fb521 f828af60',
         '6b4d3dba a14b5e77 efe75928 fe1dc127',
         'a2ffa8de 3348b3c1 856a429b f97e7e31',
         'c2e5bd66'].join(''),
        ['00000118 39296a78 9a3bc004 5c8a5fb4',
         '2c7d1bd9 98f54449 579b4468 17afbd17',
         '273e662c 97ee7299 5ef42640 c550b901',
         '3fad0761 353c7086 a272c240 88be9476',
         '9fd16650'].join(''),
        pre
      ]
    });
  }
}

/**
 * SECP256K1
 */

class SECP256K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP256K1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prefix: null,
      context: false,
      prime: 'k256',
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe fffffc2f',
      a: '0',
      b: '7',
      n: 'ffffffff ffffffff ffffffff fffffffe'
       + 'baaedce6 af48a03b bfd25e8c d0364141',
      h: '1',
      g: [
        ['79be667e f9dcbbac 55a06295 ce870b07',
         '029bfcdb 2dce28d9 59f2815b 16f81798'].join(''),
        ['483ada77 26a3c465 5da4fbfc 0e1108a8',
         'fd17b448 a6855419 9c47d08f fb10d4b8'].join(''),
        pre
      ],
      // Precomputed endomorphism.
      beta: '7ae96a2b 657c0710 6e64479e ac3434e9'
          + '9cf04975 12f58995 c1396c28 719501ee',
      lambda: '5363ad4c c05c30e0 a5261c02 8812645a'
            + '122e22ea 20816678 df02967c 1b23bd72',
      basis: [
        {
          a: '3086d221a7d46bcde86c90e49284eb15',
          b: '-e4437ed6010e88286f547fa90abfe4c3'
        },
        {
          a: '114ca50f7a8e2f3f657c1108d9d44cfd8',
          b: '3086d221a7d46bcde86c90e49284eb15'
        }
      ]
    });
  }
}

/**
 * X25519
 */

class X25519 extends MontCurve {
  constructor() {
    super({
      id: 'X25519',
      type: 'mont',
      endian: 'le',
      hash: 'SHA512',
      prefix: null,
      context: false,
      prime: 'p25519',
      // 2^255 - 19
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffed',
      a: '76d06',
      b: '1',
      n: '10000000 00000000 00000000 00000000'
       + '14def9de a2f79cd6 5812631a 5cf5d3ed',
      h: '8',
      g: [
        '9'
      ]
    });
  }
}

/**
 * ED25519
 */

class ED25519 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED25519',
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigEd25519 no Ed25519 collisions',
      context: false,
      prime: 'p25519',
      // 2^255 - 19
      p: '7fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffed',
      a: '-1',
      c: '1',
      // (-121665 * 121666^-1) mod p
      d: '52036cee 2b6ffe73 8cc74079 7779e898'
       + '00700a4d 4141d8ab 75eb4dca 135978a3',
      n: '10000000 00000000 00000000 00000000'
       + '14def9de a2f79cd6 5812631a 5cf5d3ed',
      h: '8', // c=3
      g: [
        ['216936d3 cd6e53fe c0a4e231 fdd6dc5c',
         '692cc760 9525a7b2 c9562d60 8f25d51a'].join(''),
        // 4/5
        ['66666666 66666666 66666666 66666666',
         '66666666 66666666 66666666 66666658'].join(''),
        pre
      ]
    });
  }
}

/**
 * X448
 */

class X448 extends MontCurve {
  constructor() {
    super({
      id: 'X448',
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: null,
      context: false,
      prime: 'p448',
      // 2^448 - 2^224 - 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff',
      a: '262a6',
      b: '1',
      n: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff 7cca23e9'
       + 'c44edb49 aed63690 216cc272 8dc58f55'
       + '2378c292 ab5844f3',
      h: '4',
      g: [
        '5'
      ]
    });
  }
}

/**
 * ED448
 */

class ED448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED448',
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1
      p: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff',
      a: '1',
      c: '1',
      // -39081 mod p
      d: 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff fffffffe ffffffff'
       + 'ffffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffff6756',
      n: '3fffffff ffffffff ffffffff ffffffff'
       + 'ffffffff ffffffff ffffffff 7cca23e9'
       + 'c44edb49 aed63690 216cc272 8dc58f55'
       + '2378c292 ab5844f3',
      h: '4', // c=2
      g: [
        ['4f1970c6 6bed0ded 221d15a6 22bf36da',
         '9e146570 470f1767 ea6de324 a3d3a464',
         '12ae1af7 2ab66511 433b80e1 8b00938e',
         '2626a82b c70cc05e'].join(''),
        ['693f4671 6eb6bc24 88762037 56c9c762',
         '4bea7373 6ca39840 87789c1e 05a0c2d7',
         '3ad3ff1c e67c39c4 fdbd132c 4ed7c8ad',
         '9808795b f230fa14'].join(''),
        pre
      ]
    });
  }
}

/*
 * Helpers
 */

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}

function getNAF(num, w) {
  assert(num instanceof BN);
  assert((w >>> 0) === w);

  const naf = [];
  const ws = 1 << (w + 1);
  const k = num.clone();

  while (k.cmpn(1) >= 0) {
    let z = 0;

    if (k.isOdd()) {
      const mod = k.andln(ws - 1);

      if (mod > (ws >> 1) - 1)
        z = (ws >> 1) - mod;
      else
        z = mod;

      k.isubn(z);
    }

    naf.push(z);

    // Optimization, shift by word if possible.
    const shift = (k.cmpn(0) !== 0 && k.andln(ws - 1) === 0) ? (w + 1) : 1;

    for (let i = 1; i < shift; i++)
      naf.push(0);

    k.iushrn(shift);
  }

  return naf;
}

function getJSF(k1, k2) {
  assert(k1 instanceof BN);
  assert(k2 instanceof BN);

  const jsf = [[], []];

  k1 = k1.clone();
  k2 = k2.clone();

  let d1 = 0;
  let d2 = 0;

  while (k1.cmpn(-d1) > 0 || k2.cmpn(-d2) > 0) {
    // First phase.
    let m14 = (k1.andln(3) + d1) & 3;
    let m24 = (k2.andln(3) + d2) & 3;

    if (m14 === 3)
      m14 = -1;

    if (m24 === 3)
      m24 = -1;

    let u1;

    if ((m14 & 1) === 0) {
      u1 = 0;
    } else {
      const m8 = (k1.andln(7) + d1) & 7;

      if ((m8 === 3 || m8 === 5) && m24 === 2)
        u1 = -m14;
      else
        u1 = m14;
    }

    jsf[0].push(u1);

    let u2;

    if ((m24 & 1) === 0) {
      u2 = 0;
    } else {
      const m8 = (k2.andln(7) + d2) & 7;

      if ((m8 === 3 || m8 === 5) && m14 === 2)
        u2 = -m24;
      else
        u2 = m24;
    }

    jsf[1].push(u2);

    // Second phase.
    if (2 * d1 === u1 + 1)
      d1 = 1 - d1;

    if (2 * d2 === u2 + 1)
      d2 = 1 - d2;

    k1.iushrn(1);
    k2.iushrn(1);
  }

  return jsf;
}

/*
 * Expose
 */

exports.Curve = Curve;
exports.Point = Point;
exports.ShortCurve = ShortCurve;
exports.ShortPoint = ShortPoint;
exports.JPoint = JPoint;
exports.MontCurve = MontCurve;
exports.MontPoint = MontPoint;
exports.EdwardsCurve = EdwardsCurve;
exports.EdwardsPoint = EdwardsPoint;
exports.P192 = P192;
exports.P224 = P224;
exports.P256 = P256;
exports.P384 = P384;
exports.P521 = P521;
exports.SECP256K1 = SECP256K1;
exports.X25519 = X25519;
exports.ED25519 = ED25519;
exports.X448 = X448;
exports.ED448 = ED448;
