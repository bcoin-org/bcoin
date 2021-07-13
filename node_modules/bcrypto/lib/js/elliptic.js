/*!
 * elliptic.js - elliptic curves for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Formulas from DJB and Tanja Lange [EFD].
 *
 * References:
 *
 *   [GECC] Guide to Elliptic Curve Cryptography
 *     D. Hankerson, A. Menezes, and S. Vanstone
 *     https://tinyurl.com/guide-to-ecc
 *
 *   [GLV] Faster Point Multiplication on Elliptic Curves
 *     R. Gallant, R. Lambert, and S. Vanstone
 *     https://link.springer.com/content/pdf/10.1007/3-540-44647-8_11.pdf
 *
 *   [MONT1] Montgomery curves and the Montgomery ladder
 *     Daniel J. Bernstein, Tanja Lange
 *     https://eprint.iacr.org/2017/293.pdf
 *
 *   [SQUARED] Elligator Squared
 *     Mehdi Tibouchi
 *     https://eprint.iacr.org/2014/043.pdf
 *
 *   [SEC1] SEC 1 - Standards for Efficient Cryptography Group
 *     Certicom Research
 *     https://www.secg.org/sec1-v2.pdf
 *
 *   [SEC2] SEC 2: Recommended Elliptic Curve Domain Parameters
 *     Certicom Research
 *     https://www.secg.org/sec2-v2.pdf
 *
 *   [SIDE1] Elliptic Curves and Side-Channel Attacks
 *     Marc Joye
 *     https://pdfs.semanticscholar.org/8d69/9645033e25d74fcfd4cbf07a770d2e943e14.pdf
 *
 *   [BLIND] Side-Channel Analysis on Blinding Regular Scalar Multiplications
 *     B. Feix, M. Roussellet, A. Venelli
 *     https://eprint.iacr.org/2014/191.pdf
 *
 *   [ALT] Alternative Elliptic Curve Representations
 *     R. Struik
 *     https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html
 *
 *   [ARITH1] Arithmetic of Elliptic Curves
 *     Christophe Doche, Tanja Lange
 *     Handbook of Elliptic and Hyperelliptic Curve Cryptography
 *     Page 267, Section 13 (978-1-58488-518-4)
 *     https://hyperelliptic.org/HEHCC/index.html
 *
 *   [ARITH2] The Arithmetic of Elliptic Curves, 2nd Edition
 *     Joseph H. Silverman
 *     http://www.pdmi.ras.ru/~lowdimma/BSD/Silverman-Arithmetic_of_EC.pdf
 *
 *   [EFD] Explicit-Formulas Database
 *     Daniel J. Bernstein, Tanja Lange
 *     https://hyperelliptic.org/EFD/index.html
 *
 *   [SAFE] SafeCurves: choosing safe curves for elliptic-curve cryptography
 *     Daniel J. Bernstein
 *     https://safecurves.cr.yp.to/
 *
 *   [4GLV] Refinement of the Four-Dimensional GLV Method on Elliptic Curves
 *     Hairong Yi, Yuqing Zhu, and Dongdai Lin
 *     http://www.site.uottawa.ca/~cadams/papers/prepro/paper_19_slides.pdf
 *
 *   [SSWU1] Efficient Indifferentiable Hashing into Ordinary Elliptic Curves
 *     E. Brier, J. Coron, T. Icart, D. Madore, H. Randriam, M. Tibouchi
 *     https://eprint.iacr.org/2009/340.pdf
 *
 *   [SSWU2] Rational points on certain hyperelliptic curves over finite fields
 *     Maciej Ulas
 *     https://arxiv.org/abs/0706.1448
 *
 *   [H2EC] Hashing to Elliptic Curves
 *     A. Faz-Hernandez, S. Scott, N. Sullivan, R. S. Wahby, C. A. Wood
 *     https://git.io/JeWz6
 *     https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
 *
 *   [SVDW1] Construction of Rational Points on Elliptic Curves
 *     A. Shallue, C. E. van de Woestijne
 *     https://works.bepress.com/andrew_shallue/1/download/
 *
 *   [SVDW2] Indifferentiable Hashing to Barreto-Naehrig Curves
 *     Pierre-Alain Fouque, Mehdi Tibouchi
 *     https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf
 *
 *   [SVDW3] Covert ECDH over secp256k1
 *     Pieter Wuille
 *     https://gist.github.com/sipa/29118d3fcfac69f9930d57433316c039
 *
 *   [MONT2] Montgomery Curve (wikipedia)
 *     https://en.wikipedia.org/wiki/Montgomery_curve
 *
 *   [MONT3] Montgomery Curves and their arithmetic
 *     C. Costello, B. Smith
 *     https://eprint.iacr.org/2017/212.pdf
 *
 *   [ELL2] Elliptic-curve points indistinguishable from uniform random strings
 *     D. Bernstein, M. Hamburg, A. Krasnova, T. Lange
 *     https://elligator.cr.yp.to/elligator-20130828.pdf
 *
 *   [RFC7748] Elliptic Curves for Security
 *     A. Langley, M. Hamburg, S. Turner
 *     https://tools.ietf.org/html/rfc7748
 *
 *   [TWISTED] Twisted Edwards Curves
 *     D. Bernstein, P. Birkner, M. Joye, T. Lange, C. Peters
 *     https://eprint.iacr.org/2008/013.pdf
 *
 *   [ELL1] Injective Encodings to Elliptic Curves
 *     P. Fouque, A. Joux, M. Tibouchi
 *     https://eprint.iacr.org/2013/373.pdf
 *
 *   [ISOGENY] Twisting Edwards curves with isogenies
 *     Mike Hamburg
 *     https://www.shiftleft.org/papers/isogeny/isogeny.pdf
 *
 *   [RFC8032] Edwards-Curve Digital Signature Algorithm (EdDSA)
 *     S. Josefsson, SJD AB, I. Liusvaara
 *     https://tools.ietf.org/html/rfc8032
 *
 *   [SCHNORR] Schnorr Signatures for secp256k1
 *     Pieter Wuille
 *     https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki
 *
 *   [BIP340] Schnorr Signatures for secp256k1
 *     Pieter Wuille, Jonas Nick, Tim Ruffing
 *     https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 *
 *   [JCEN12] Efficient Software Implementation of Public-Key Cryptography
 *            on Sensor Networks Using the MSP430X Microcontroller
 *     C. P. L. Gouvea, L. B. Oliveira, J. Lopez
 *     http://conradoplg.cryptoland.net/files/2010/12/jcen12.pdf
 *
 *   [FIPS186] Federal Information Processing Standards Publication
 *     National Institute of Standards and Technology
 *     https://tinyurl.com/fips-186-3
 *
 *   [RFC5639] Elliptic Curve Cryptography (ECC) Brainpool
 *             Standard Curves and Curve Generation
 *     M. Lochter, BSI, J. Merkle
 *     https://tools.ietf.org/html/rfc5639
 *
 *   [TWISTEQ] Twisted Edwards & Short Weierstrass Equivalence
 *     Christopher Jeffrey
 *     https://gist.github.com/chjj/16ba7fa08d64e8dda269a9fe5b2a8bbc
 *
 *   [ECPM] Elliptic Curve Point Multiplication (wikipedia)
 *     https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
 */

'use strict';

const {custom} = require('../internal/custom');
const BN = require('../bn');

/*
 * Constants
 */

const types = {
  AFFINE: 0,
  JACOBIAN: 1,
  PROJECTIVE: 2,
  EXTENDED: 3
};

const jsfIndex = [
  -3, // -1 -1
  -1, // -1 0
  -5, // -1 1
  -7, // 0 -1
  0, // 0 0
  7, // 0 1
  5, // 1 -1
  1, // 1 0
  3  // 1 1
];

const USE_FIXED = false;

let uid = 0;

/**
 * Curve
 */

class Curve {
  constructor(Point, type, conf) {
    this.Point = null;
    this.id = null;
    this.uid = uid++;
    this.ossl = null;
    this.type = 'base';
    this.endian = 'be';
    this.hash = null;
    this.prefix = null;
    this.context = false;
    this.prime = null;
    this.p = null;
    this.red = null;
    this.fieldSize = 0;
    this.fieldBits = 0;
    this.adjustedSize = 0;
    this.signBit = 0;
    this.mask = 0;
    this.n = null;
    this.h = null;
    this.q = null;
    this.z = null;
    this.g = null;
    this.nh = null;
    this.scalarSize = 0;
    this.scalarBits = 0;
    this.zero = null;
    this.one = null;
    this.two = null;
    this.three = null;
    this.four = null;
    this.i2 = null;
    this.i3 = null;
    this.i4 = null;
    this.i6 = null;
    this.torsion = null;
    this.endo = null;
    this.hi = null;
    this._init(Point, type, conf);
  }

  _init(Point, type, conf) {
    assert(typeof Point === 'function');
    assert(typeof type === 'string');
    assert(conf && typeof conf === 'object');
    assert(conf.red == null || (conf.red instanceof BN.Red));
    assert(conf.p != null, 'Must pass a prime.');
    assert(conf.id == null || typeof conf.id === 'string');
    assert(conf.ossl == null || typeof conf.ossl === 'string');
    assert(conf.endian == null || typeof conf.endian === 'string');
    assert(conf.hash == null || typeof conf.hash === 'string');
    assert(conf.prefix == null || typeof conf.prefix === 'string');
    assert(conf.context == null || typeof conf.context === 'boolean');
    assert(conf.prime == null || typeof conf.prime === 'string');
    assert(conf.torsion == null || Array.isArray(conf.torsion));

    // Point class.
    this.Point = Point;

    // Meta.
    this.id = conf.id || null;
    this.ossl = conf.ossl || null;
    this.type = type;
    this.endian = conf.endian || (type === 'short' ? 'be' : 'le');
    this.hash = conf.hash || null;
    this.prefix = conf.prefix ? Buffer.from(conf.prefix, 'binary') : null;
    this.context = conf.context || false;
    this.prime = conf.prime || null;

    // Prime.
    this.p = BN.fromJSON(conf.p);

    // Reduction.
    if (conf.red) {
      this.red = conf.red;
    } else {
      // Use Montgomery when there is no fast reduction for the prime.
      this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);
      this.red.precompute();
    }

    // Precalculate encoding length.
    this.fieldSize = this.p.byteLength();
    this.fieldBits = this.p.bitLength();
    this.adjustedSize = this.fieldSize + ((this.fieldBits & 7) === 0);
    this.signBit = this.adjustedSize * 8 - 1;
    this.mask = 0xff;

    if ((this.fieldBits & 7) !== 0)
      this.mask = (1 << (this.fieldBits & 7)) - 1;

    // Curve configuration, optional.
    this.n = BN.fromJSON(conf.n || '0');
    this.h = BN.fromJSON(conf.h || '1');
    this.q = this.n.mul(this.h);
    this.z = BN.fromJSON(conf.z || '0').toRed(this.red);
    this.g = null;
    this.nh = this.n.ushrn(1);
    this.scalarSize = this.n.byteLength();
    this.scalarBits = this.n.bitLength();

    // Useful for many curves.
    this.zero = new BN(0).toRed(this.red);
    this.one = new BN(1).toRed(this.red);
    this.two = new BN(2).toRed(this.red);
    this.three = new BN(3).toRed(this.red);
    this.four = new BN(4).toRed(this.red);

    // Inverses.
    this.i2 = this.two.redInvert();
    this.i3 = this.three.redInvert();
    this.i4 = this.i2.redSqr();
    this.i6 = this.i2.redMul(this.i3);

    // Torsion.
    this.torsion = new Array(this.h.word(0));

    for (let i = 0; i < this.torsion.length; i++)
      this.torsion[i] = this.point();

    // Endomorphism.
    this.endo = null;

    // Cache.
    this.hi = null;

    // Memoize.
    this._scale = memoize(this._scale, this);
    this.isIsomorphic = memoize(this.isIsomorphic, this);
    this.isIsogenous = memoize(this.isIsogenous, this);

    // Sanity checks.
    assert(this.p.sign() > 0 && this.p.isOdd());
    assert(this.n.sign() >= 0);
    assert(this.h.sign() > 0 && this.h.cmpn(255) <= 0);
    assert(this.endian === 'be' || this.endian === 'le');

    return this;
  }

  _finalize(conf) {
    assert(conf && typeof conf === 'object');

    // Create base point.
    this.g = conf.g ? this.pointFromJSON(conf.g) : this.point();

    // Parse small order points.
    if (conf.torsion) {
      assert(conf.torsion.length === this.torsion.length);

      for (let i = 0; i < this.torsion.length; i++)
        this.torsion[i] = this.pointFromJSON(conf.torsion[i]);
    }

    return this;
  }

  _findTorsion() {
    // Find all torsion points by grinding.
    assert(!this.n.isZero());

    const h = this.h.word(0);
    const x = this.one.redNeg();
    const out = [this.point()];
    const set = new Set();

    let len = h;

    while (out.length < len) {
      let p;

      x.redIAdd(this.one);

      try {
        p = this.pointFromX(x.clone());
      } catch (e) {
        continue;
      }

      try {
        p = p.mul(this.n);
      } catch (e) {
        len = 2;
        continue;
      }

      if (p.isInfinity())
        continue;

      p.normalize();

      for (const point of [p, p.neg()]) {
        const key = point.key();

        if (!set.has(key)) {
          out.push(point);
          set.add(key);
        }
      }
    }

    out.sort((a, b) => a.cmp(b));

    while (out.length < h)
      out.push(this.point());

    return out;
  }

  _fixedMul(p, k) {
    // Fixed-base method for point multiplication.
    //
    // [ECPM] "Windowed method".
    // [GECC] Page 95, Section 3.3.
    //
    // Windows are appropriately shifted to avoid any
    // doublings. This reduces a 256 bit multiplication
    // down to 64 additions with a window size of 4.
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(p.pre && p.pre.windows);

    // Get precomputed windows.
    const {width, points} = p._getWindows(0, 0);

    // Recompute window size.
    const size = 1 << width;

    // Recompute steps.
    const bits = k.bitLength();
    const steps = ((bits + width - 1) / width) >>> 0;

    // Multiply.
    let acc = this.jpoint();

    for (let i = 0; i < steps; i++) {
      const bits = k.bits(i * width, width);

      acc = acc.add(points[i * size + bits]);
    }

    // Adjust sign.
    if (k.isNeg())
      acc = acc.neg();

    return acc;
  }

  _fixedNafMul(p, k) {
    // Fixed-base NAF windowing method for point multiplication.
    //
    // [GECC] Algorithm 3.42, Page 105, Section 3.3.
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(p.pre && p.pre.doubles);

    // Get precomputed doubles.
    const {step, points} = p._getDoubles(0, 0);

    // Get fixed NAF (in a more windowed form).
    const naf = getFixedNAF(k, 2, k.bitLength() + 1, step);

    // Compute steps.
    const I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3;

    // Multiply.
    let a = this.jpoint();
    let b = this.jpoint();

    for (let i = I; i > 0; i--) {
      for (let j = 0; j < naf.length; j++) {
        const nafW = naf[j];

        if (nafW === i)
          b = b.add(points[j]);
        else if (nafW === -i)
          b = b.sub(points[j]);
      }

      a = a.add(b);
    }

    return a;
  }

  _wnafMul(w, p, k) {
    // Window NAF method for point multiplication.
    //
    // [GECC] Algorithm 3.36, Page 100, Section 3.3.
    assert(p instanceof Point);
    assert(k instanceof BN);

    // Precompute window.
    const {width, points} = p._safeNAF(w);

    // Get NAF form.
    const naf = getNAF(k, width, k.bitLength() + 1);

    // Add `this`*(N+1) for every w-NAF index.
    let acc = this.jpoint();

    for (let i = naf.length - 1; i >= 0; i--) {
      const z = naf[i];

      if (i !== naf.length - 1)
        acc = acc.dbl();

      if (z > 0)
        acc = acc.add(points[(z - 1) >> 1]);
      else if (z < 0)
        acc = acc.sub(points[(-z - 1) >> 1]);
    }

    return acc;
  }

  _wnafMulAdd(w, points, coeffs) {
    // Multiple point multiplication, also known
    // as "Shamir's trick" (with interleaved NAFs).
    //
    // [GECC] Algorithm 3.48, Page 109, Section 3.3.3.
    //        Algorithm 3.51, Page 112, Section 3.3.
    //
    // This is particularly useful for signature
    // verifications and mutiplications after an
    // endomorphism split.
    assert((w >>> 0) === w);
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);

    const length = points.length;
    const wnd = new Array(length);
    const naf = new Array(length);

    // Check arrays and calculate size.
    let max = 0;

    for (let i = 0; i < length; i++) {
      const point = points[i];
      const coeff = coeffs[i];

      assert(point instanceof Point);
      assert(coeff instanceof BN);

      if (i > 0 && point.type !== points[i - 1].type)
        throw new Error('Cannot mix points.');

      // Avoid sparse arrays.
      wnd[i] = null;
      naf[i] = null;

      // Compute max scalar size.
      max = Math.max(max, coeff.bitLength() + 1);
    }

    // Compute NAFs.
    let ppoint = null;
    let pcoeff = null;
    let len = 0;

    for (let i = 0; i < length; i++) {
      const point = points[i];
      const coeff = coeffs[i];
      const pre = point._getNAF(0);

      // Use precomputation if available.
      if (pre) {
        wnd[len] = pre.points;
        naf[len] = getNAF(coeff, pre.width, max);
        len += 1;
        continue;
      }

      // Save last non-precomputed point.
      if (!ppoint) {
        ppoint = point;
        pcoeff = coeff;
        continue;
      }

      // Compute JSF in NAF form.
      wnd[len] = ppoint._getJNAF(point);
      naf[len] = getJNAF(pcoeff, coeff, max);

      ppoint = null;
      pcoeff = null;

      len += 1;
    }

    // Regular NAF for odd points.
    if (ppoint) {
      const nafw = ppoint._safeNAF(w);

      wnd[len] = nafw.points;
      naf[len] = getNAF(pcoeff, nafw.width, max);

      len += 1;
    }

    // Multiply and add.
    let acc = this.jpoint();

    for (let i = max - 1; i >= 0; i--) {
      if (i !== max - 1)
        acc = acc.dbl();

      for (let j = 0; j < len; j++) {
        const z = naf[j][i];

        if (z > 0)
          acc = acc.add(wnd[j][(z - 1) >> 1]);
        else if (z < 0)
          acc = acc.sub(wnd[j][(-z - 1) >> 1]);
      }
    }

    return acc;
  }

  _endoWnafMulAdd(points, coeffs) {
    throw new Error('Not implemented.');
  }

  _scale(curve, invert) {
    assert(curve instanceof Curve);
    assert(curve.p.eq(this.p));

    switch (curve.type) {
      case 'short':
        return this._scaleShort(curve, invert);
      case 'mont':
        return this._scaleMont(curve, invert);
      case 'edwards':
        return this._scaleEdwards(curve, invert);
      default:
        throw new Error('Not implemented.');
    }
  }

  _scaleShort(curve, invert) {
    throw new Error('Not implemented.');
  }

  _scaleMont(curve, invert) {
    throw new Error('Not implemented.');
  }

  _scaleEdwards(curve, invert) {
    throw new Error('Not implemented.');
  }

  isElliptic() {
    throw new Error('Not implemented.');
  }

  jinv() {
    throw new Error('Not implemented.');
  }

  isComplete() {
    return false;
  }

  precompute(rng) {
    assert(!this.g.isInfinity(), 'Must have base point.');
    assert(!this.n.isZero(), 'Must have order.');

    this.g.precompute(this.n.bitLength(), rng);

    return this;
  }

  scalar(num, base, endian) {
    const k = new BN(num, base, endian);

    assert(!k.red);

    if (this.n.isZero())
      return k;

    return k.imod(this.n);
  }

  field(num, base, endian) {
    const x = BN.cast(num, base, endian);

    if (x.red)
      return x.forceRed(this.red);

    return x.toRed(this.red);
  }

  point(x, y) {
    throw new Error('Not implemented.');
  }

  jpoint(x, y, z) {
    throw new Error('Not implemented.');
  }

  xpoint(x, z) {
    throw new Error('Not implemented.');
  }

  cpoint(xx, xz, yy, yz) {
    assert(xx instanceof BN);
    assert(xz instanceof BN);
    assert(yy instanceof BN);
    assert(yz instanceof BN);

    if (xz.isZero() || yz.isZero())
      return this.point();

    const z = xz.redMul(yz).redInvert();
    const x = xx.redMul(yz).redMul(z);
    const y = yy.redMul(xz).redMul(z);

    return this.point(x, y);
  }

  solveX2(y) {
    throw new Error('Not implemented.');
  }

  solveX(y) {
    return this.solveX2(y).redSqrt();
  }

  solveY2(x) {
    throw new Error('Not implemented.');
  }

  solveY(x) {
    return this.solveY2(x).redSqrt();
  }

  validate(point) {
    throw new Error('Not implemented.');
  }

  pointFromX(x, sign) {
    throw new Error('Not implemented.');
  }

  pointFromY(y, sign) {
    throw new Error('Not implemented.');
  }

  isIsomorphic(curve) {
    throw new Error('Not implemented.');
  }

  isIsogenous(curve) {
    throw new Error('Not implemented.');
  }

  pointFromShort(point) {
    throw new Error('Not implemented.');
  }

  pointFromMont(point, sign) {
    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    throw new Error('Not implemented.');
  }

  pointFromUniform(u) {
    throw new Error('Not implemented.');
  }

  pointToUniform(p) {
    throw new Error('Not implemented.');
  }

  pointFromHash(bytes, pake = false) {
    // [H2EC] "Roadmap".
    assert(Buffer.isBuffer(bytes));
    assert(typeof pake === 'boolean');

    if (bytes.length !== this.fieldSize * 2)
      throw new Error('Invalid hash size.');

    // Random oracle encoding.
    // Ensure a proper distribution.
    const s1 = bytes.slice(0, this.fieldSize);
    const s2 = bytes.slice(this.fieldSize);
    const u1 = this.decodeUniform(s1);
    const u2 = this.decodeUniform(s2);
    const p1 = this.pointFromUniform(u1);
    const p2 = this.pointFromUniform(u2);
    const p3 = p1.add(p2);

    return pake ? p3.mulH() : p3;
  }

  pointToHash(p, subgroup, rng) {
    // [SQUARED] Algorithm 1, Page 8, Section 3.3.
    assert(p instanceof this.Point);
    assert((subgroup >>> 0) === subgroup);

    // Add a random torsion component.
    const i = subgroup % this.torsion.length;
    const p0 = p.add(this.torsion[i]);

    // Average Cost (R = sqrt):
    //
    //   SSWU (~4 iterations) => 8I + 16R
    //   SVDW (~4 iterations) => 12I + 28R
    //   Elligator 1 (~2 iterations) => 6I + 10R
    //   Elligator 2 (~2 iterations) => 4I + 6R
    //   Ristretto (~1 iteration) => 1I + 2R + h*1R
    for (;;) {
      const u1 = this.randomField(rng);
      const p1 = this.pointFromUniform(u1);

      // Avoid 2-torsion points:
      //   Short Weierstrass: ((A / 3) / B, 0)
      //   Montgomery: (0, 0)
      //   Twisted Edwards: (0, -1)
      if (p1.neg().eq(p1))
        continue;

      const p2 = p0.sub(p1);
      const hint = randomInt(rng);

      let u2;
      try {
        u2 = this.pointToUniform(p2, hint & 15);
      } catch (e) {
        if (e.message === 'Invalid point.')
          continue;
        throw e;
      }

      const s1 = this.encodeUniform(u1, hint >>> 8);
      const s2 = this.encodeUniform(u2, hint >>> 16);

      return Buffer.concat([s1, s2]);
    }
  }

  randomScalar(rng) {
    const max = this.n.isZero() ? this.p : this.n;
    return BN.random(rng, 1, max);
  }

  randomField(rng) {
    return BN.random(rng, 1, this.p).toRed(this.red);
  }

  randomPoint(rng) {
    let p;

    for (;;) {
      const x = this.randomField(rng);
      const sign = (randomInt(rng) & 1) !== 0;

      try {
        p = this.pointFromX(x, sign);
      } catch (e) {
        continue;
      }

      assert(p.validate());

      return p.mulH();
    }
  }

  mulAll(points, coeffs) {
    return this.jmulAll(points, coeffs);
  }

  jmulAll(points, coeffs) {
    assert(Array.isArray(points));
    assert(points.length === 0 || (points[0] instanceof Point));

    // Multiply with endomorphism if we're using affine points.
    if (this.endo && points.length > 0 && points[0].type === types.AFFINE)
      return this._endoWnafMulAdd(points, coeffs);

    // Otherwise, a regular Shamir's trick.
    return this._wnafMulAdd(5, points, coeffs);
  }

  mulH(k) {
    assert(k instanceof BN);
    return this.imulH(k.clone());
  }

  imulH(k) {
    assert(k instanceof BN);
    assert(!k.red);

    const word = this.h.word(0);

    // Optimize for powers of two.
    if ((word & (word - 1)) === 0) {
      const bits = this.h.bitLength();
      return k.iushln(bits - 1).imod(this.n);
    }

    return k.imuln(word).imod(this.n);
  }

  normalizeAll(points) {
    assert(Array.isArray(points));

    const len = points.length;
    const z = new Array(len);

    for (let i = 0; i < len; i++) {
      const p = points[i];

      assert(p instanceof Point);
      assert(p.curve === this);

      if (p.type === types.AFFINE) {
        z[i] = this.one;
        continue;
      }

      z[i] = p.z;
    }

    const zi = this.red.invertAll(z);
    const out = new Array(len);

    for (let i = 0; i < len; i++)
      out[i] = points[i].scale(zi[i]);

    return out;
  }

  affinizeAll(points) {
    return this.normalizeAll(points);
  }

  clamp(scalar) {
    // [RFC7748] Page 8, Section 5.
    // [RFC8032] Section 5.1.5 & 5.2.5.
    assert(Buffer.isBuffer(scalar));
    assert(scalar.length === this.scalarSize);
    assert(this.scalarSize <= this.fieldSize);

    let top = (this.fieldBits & 7) || 8;
    let lsb = 0;
    let msb = this.scalarSize - 1;

    // Swap endianness.
    if (this.endian === 'be')
      [lsb, msb] = [msb, lsb];

    // Adjust for low order.
    if (this.scalarSize < this.fieldSize)
      top = 8;

    // Ensure a multiple of the cofactor.
    scalar[lsb] &= -this.h.word(0) & 0xff;

    // Clamp to the prime.
    scalar[msb] &= (1 << top) - 1;

    // Set the high bit.
    scalar[msb] |= 1 << (top - 1);

    return scalar;
  }

  splitHash(bytes) {
    // [RFC8032] Section 5.1.6 & 5.2.6.
    assert(Buffer.isBuffer(bytes));
    assert(bytes.length === this.adjustedSize * 2);
    assert(this.scalarSize <= this.adjustedSize);

    let off = 0;

    if (this.endian === 'be')
      off = this.adjustedSize - this.scalarSize;

    const scalar = bytes.slice(off, off + this.scalarSize);
    const prefix = bytes.slice(this.adjustedSize);

    this.clamp(scalar);

    return [scalar, prefix];
  }

  encodeField(x) {
    // [SEC1] Page 12, Section 2.3.5.
    assert(x instanceof BN);
    assert(!x.red);

    return x.encode(this.endian, this.fieldSize);
  }

  decodeField(bytes) {
    // [SEC1] Page 13, Section 2.3.6.
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.fieldSize)
      throw new Error('Invalid field element size.');

    return BN.decode(bytes, this.endian);
  }

  encodeAdjusted(x) {
    assert(x instanceof BN);
    assert(!x.red);

    return x.encode(this.endian, this.adjustedSize);
  }

  decodeAdjusted(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.adjustedSize)
      throw new Error('Invalid field element size.');

    return BN.decode(bytes, this.endian);
  }

  encodeScalar(k) {
    // [SEC1] Page 13, Section 2.3.7.
    assert(k instanceof BN);
    assert(!k.red);

    return k.encode(this.endian, this.scalarSize);
  }

  decodeScalar(bytes) {
    // [SEC1] Page 14, Section 2.3.8.
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.scalarSize)
      throw new Error('Invalid scalar size.');

    return BN.decode(bytes, this.endian);
  }

  encodeClamped(k) {
    // [RFC7748] Page 8, Section 5.
    // [RFC8032] Section 5.1.5 & 5.2.5.
    return this.clamp(this.encodeScalar(k));
  }

  decodeClamped(bytes) {
    // [RFC7748] Page 8, Section 5.
    // [RFC8032] Section 5.1.5 & 5.2.5.
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.scalarSize)
      throw new Error('Invalid scalar size.');

    const clamped = this.clamp(Buffer.from(bytes));

    return BN.decode(clamped, this.endian);
  }

  encodeUniform(x, bits) {
    assert(x instanceof BN);
    assert((bits >>> 0) === bits);

    const msb = this.endian === 'le' ? this.fieldSize - 1 : 0;
    const bytes = x.fromRed().encode(this.endian, this.fieldSize);

    bytes[msb] |= (bits & ~this.mask) & 0xff;

    return bytes;
  }

  decodeUniform(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.fieldSize)
      throw new Error('Invalid field size.');

    const x = BN.decode(bytes, this.endian);

    x.iumaskn(this.fieldBits);

    return x.toRed(this.red);
  }

  encodePoint(point, compact) {
    assert(point instanceof Point);
    return point.encode(compact);
  }

  decodePoint(bytes) {
    throw new Error('Not implemented.');
  }

  encodeX(point) {
    throw new Error('Not implemented.');
  }

  decodeX(bytes) {
    throw new Error('Not implemented.');
  }

  decodeEven(bytes) {
    throw new Error('Not implemented.');
  }

  decodeSquare(bytes) {
    throw new Error('Not implemented.');
  }

  toShort() {
    throw new Error('Not implemented.');
  }

  toMont(b0) {
    throw new Error('Not implemented.');
  }

  toEdwards(a0) {
    throw new Error('Not implemented.');
  }

  pointToJSON(point, pre) {
    assert(point instanceof Point);
    return point.toJSON(pre);
  }

  pointFromJSON(json) {
    throw new Error('Not implemented.');
  }

  toJSON(pre) {
    let prefix, context;
    let n, z, endo;

    if (this.type === 'edwards') {
      prefix = this.prefix ? this.prefix.toString() : null;
      context = this.context;
    }

    if (!this.n.isZero())
      n = this.n.toJSON();

    if (!this.z.isZero()) {
      z = this.z.fromRed();

      if (this.z.redIsHigh())
        z.isub(this.p);

      z = z.toString(16);
    }

    if (this.endo)
      endo = this.endo.toJSON();

    return {
      id: this.id,
      ossl: this.ossl,
      type: this.type,
      endian: this.endian,
      hash: this.hash,
      prefix,
      context,
      prime: this.prime,
      p: this.p.toJSON(),
      a: undefined,
      b: undefined,
      d: undefined,
      n,
      h: this.h.toString(16),
      s: undefined,
      z,
      c: undefined,
      g: this.g.toJSON(pre),
      endo
    };
  }

  static fromJSON(json) {
    return new this(json);
  }
}

/**
 * Point
 */

class Point {
  constructor(curve, type) {
    assert(curve instanceof Curve);
    assert((type >>> 0) === type);

    this.curve = curve;
    this.type = type;
    this.pre = null;
  }

  _init() {
    throw new Error('Not implemented.');
  }

  _safeNAF(width) {
    assert((width >>> 0) === width);

    if (this.pre && this.pre.naf)
      return this.pre.naf;

    if (width === 0)
      return null;

    const size = 1 << (width - 2);
    const points = new Array(size);
    const p = this.toJ();
    const dbl = size === 1 ? null : p.dbl();

    points[0] = p;

    for (let i = 1; i < size; i++)
      points[i] = points[i - 1].add(dbl);

    return new NAF(width, points);
  }

  _getNAF(width) {
    assert((width >>> 0) === width);

    if (this.pre && this.pre.naf)
      return this.pre.naf;

    if (width === 0)
      return null;

    const odds = this._safeNAF(width).points;
    const points = this.curve.affinizeAll(odds);

    return new NAF(width, points);
  }

  _getWindows(width, bits) {
    assert((width >>> 0) === width);
    assert((bits >>> 0) === bits);

    if (this.pre && this.pre.windows)
      return this.pre.windows;

    if (width === 0)
      return null;

    const size = 1 << width;
    const steps = ((bits + width - 1) / width) >>> 0;
    const wnds = new Array(steps * size);

    let g = this.toJ();

    for (let i = 0; i < steps; i++) {
      wnds[i * size] = this.curve.jpoint();

      for (let j = 1; j < size; j++)
        wnds[i * size + j] = wnds[i * size + j - 1].add(g);

      g = g.dblp(width);
    }

    const points = this.curve.affinizeAll(wnds);

    return new Windows(width, bits, points);
  }

  _getDoubles(step, power) {
    assert((step >>> 0) === step);
    assert((power >>> 0) === power);

    if (this.pre && this.pre.doubles)
      return this.pre.doubles;

    if (step === 0)
      return null;

    const len = Math.ceil(power / step) + 1;
    const dbls = new Array(len);

    let acc = this.toJ();
    let k = 0;

    dbls[k++] = acc;

    for (let i = 0; i < power; i += step) {
      for (let j = 0; j < step; j++)
        acc = acc.dbl();

      dbls[k++] = acc;
    }

    assert(k === len);

    const points = this.curve.affinizeAll(dbls);

    return new Doubles(step, points);
  }

  _getBeta() {
    return null;
  }

  _getBlinding(rng) {
    if (this.pre && this.pre.blinding)
      return this.pre.blinding;

    if (!rng)
      return null;

    if (this.curve.n.isZero())
      return null;

    // Pregenerate a random blinding value:
    //
    //   blind = random integer in [1,n-1]
    //   unblind = G * blind
    //
    // We intend to subtract the blinding value
    // from scalars before multiplication. We
    // can add the unblinding point once the
    // multiplication is complete.
    const blind = this.curve.randomScalar(rng);
    const unblind = this.mul(blind);

    return new Blinding(blind, unblind);
  }

  _hasWindows(k) {
    assert(k instanceof BN);

    if (!this.pre || !this.pre.windows)
      return false;

    const {width, bits} = this.pre.windows;
    const steps = ((bits + width - 1) / width) >>> 0;

    return k.bitLength() <= steps * width;
  }

  _hasDoubles(k) {
    assert(k instanceof BN);

    if (!this.pre || !this.pre.doubles)
      return false;

    const {step, points} = this.pre.doubles;
    const power = k.bitLength() + 1;

    return points.length >= Math.ceil(power / step) + 1;
  }

  _getJNAF(point) {
    assert(point instanceof Point);
    assert(point.type === this.type);

    // Create comb for JSF.
    return [
      this, // 1
      this.add(point), // 3
      this.sub(point), // 5
      point // 7
    ];
  }

  _blind(k, rng) {
    // [SIDE1] Page 5, Section 4.
    // [BLIND] Page 20, Section 7.
    assert(k instanceof BN);
    assert(!k.red);

    // Scalar splitting (requires precomputation).
    //
    // Blind a multiplication by first subtracting
    // a blinding value from the scalar. Example:
    //
    //   b = random integer in [1,n-1]
    //   B = P * b (precomputed)
    //   Q = P * (k - b) + B
    //
    // Note that Joye describes a different method
    // (multiplier randomization) which computes:
    //
    //   B = random point in E
    //   Q = (P + B) * k - B * k
    //
    // Our method is more similar to the "scalar
    // splitting" technique described in the
    // second source above.
    //
    // The blinding value and its corresponding
    // point are randomly generated and computed
    // on boot. As long as an attacker is not
    // able to observe the boot, this should give
    // a decent bit of protection against various
    // channel attacks.
    if (this.pre && this.pre.blinding) {
      const {blind, unblind} = this.pre.blinding;
      const t = k.sub(blind);

      return [this, t, unblind];
    }

    // Randomization is not possible without
    // an RNG. Do a normal multiplication.
    if (!rng)
      return [this, k, null];

    // If we have no precomputed blinding
    // factor, there are two possibilities
    // for randomization:
    //
    // 1. Randomize the multiplier by adding
    //    a random multiple of `n`.
    //
    // 2. Re-scale the point itself by a
    //    random factor.
    //
    // The first option can be accomplished
    // with some like:
    //
    //   a = random integer in [1,n-1]
    //   r = a * n
    //   Q = P * (k + r)
    //
    // The second is accomplished with:
    //
    //   a = random element in F(p)
    //   R = (x * a^2, y * a^3, z * a)
    //   Q = R * k
    //
    // If we have precomputed doubles / naf
    // points, we opt for the first method
    // to avoid randomizing everything.
    if (this.pre) {
      if (this.curve.n.isZero())
        return [this, k, null];

      const a = this.curve.randomScalar(rng);
      const r = a.mul(this.curve.n);
      const t = r.iadd(k);

      return [this, t, null];
    }

    // If there is no precomputation _at all_,
    // we opt for the second method.
    const p = this.randomize(rng);

    return [p, k, null];
  }

  clone() {
    throw new Error('Not implemented.');
  }

  precompute(bits, rng) {
    assert((bits >>> 0) === bits);

    if (!this.pre)
      this.pre = new Precomp();

    if (!this.pre.naf)
      this.pre.naf = this._getNAF(9);

    if (USE_FIXED && !this.pre.windows)
      this.pre.windows = this._getWindows(4, bits);

    if (!this.pre.doubles)
      this.pre.doubles = this._getDoubles(4, bits + 1);

    if (!this.pre.beta)
      this.pre.beta = this._getBeta();

    if (!this.pre.blinding)
      this.pre.blinding = this._getBlinding(rng);

    return this;
  }

  validate() {
    return this.curve.validate(this);
  }

  normalize() {
    return this;
  }

  scale(a) {
    throw new Error('Not implemented.');
  }

  randomize(rng) {
    const z = this.curve.randomField(rng);
    return this.scale(z);
  }

  neg() {
    throw new Error('Not implemented.');
  }

  add(point) {
    throw new Error('Not implemented.');
  }

  sub(point) {
    assert(point instanceof Point);
    return this.add(point.neg());
  }

  dbl() {
    throw new Error('Not implemented.');
  }

  dblp(pow) {
    // Repeated doubling. This can
    // be optimized by child classes.
    assert((pow >>> 0) === pow);

    let r = this;

    for (let i = 0; i < pow; i++)
      r = r.dbl();

    return r;
  }

  diffAddDbl(p, q) {
    throw new Error('Not implemented.');
  }

  getX() {
    throw new Error('Not implemented.');
  }

  getY() {
    throw new Error('Not implemented.');
  }

  eq(point) {
    throw new Error('Not implemented.');
  }

  cmp(point) {
    throw new Error('Not implemented.');
  }

  isInfinity() {
    throw new Error('Not implemented.');
  }

  isOrder2() {
    throw new Error('Not implemented.');
  }

  isOdd() {
    throw new Error('Not implemented.');
  }

  isEven() {
    throw new Error('Not implemented.');
  }

  isSquare() {
    throw new Error('Not implemented.');
  }

  eqX(x) {
    throw new Error('Not implemented.');
  }

  eqR(x) {
    throw new Error('Not implemented.');
  }

  isSmall() {
    // Test whether the point is of small order.
    if (this.isInfinity())
      return false;

    // P * h = O
    return this.jmulH().isInfinity();
  }

  hasTorsion() {
    // Test whether the point is in another subgroup.
    if (this.isInfinity())
      return false;

    // P * n != O
    return !this.jmul(this.curve.n).isInfinity();
  }

  order() {
    // Calculate point order.
    const {h, n} = this.curve;

    let p = this.toJ();
    let q = new BN(1);

    while (!p.isInfinity()) {
      q.iaddn(1);

      if (q.cmp(h) > 0) {
        q = n.clone();
        break;
      }

      p = p.add(this);
    }

    return q;
  }

  mul(k) {
    return this.jmul(k);
  }

  muln(k) {
    return this.jmuln(k);
  }

  mulBlind(k, rng) {
    return this.jmulBlind(k, rng);
  }

  mulAdd(k1, p2, k2) {
    return this.jmulAdd(k1, p2, k2);
  }

  mulH() {
    return this.jmulH();
  }

  div(k) {
    return this.jdiv(k);
  }

  divn(k) {
    return this.jdivn(k);
  }

  divH() {
    return this.jdivH();
  }

  jmul(k) {
    if (USE_FIXED && this._hasWindows(k))
      return this.curve._fixedMul(this, k);

    if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k);

    if (this.curve.endo && this.type === types.AFFINE)
      return this.curve._endoWnafMulAdd([this], [k]);

    return this.curve._wnafMul(5, this, k);
  }

  jmuln(k) {
    assert((k | 0) === k);
    return this.jmul(new BN(k));
  }

  jmulBlind(k, rng = null) {
    const [p, t, unblind] = this._blind(k, rng);
    const q = p.jmul(t);

    if (unblind)
      return q.add(unblind);

    return q;
  }

  jmulAdd(k1, p2, k2) {
    if (this.curve.endo && this.type === types.AFFINE)
      return this.curve._endoWnafMulAdd([this, p2], [k1, k2]);

    return this.curve._wnafMulAdd(5, [this, p2], [k1, k2]);
  }

  jmulH() {
    const word = this.curve.h.word(0);

    // Optimize for powers of two.
    if ((word & (word - 1)) === 0) {
      const bits = this.curve.h.bitLength();
      return this.toJ().dblp(bits - 1);
    }

    return this.jmul(this.curve.h);
  }

  jdiv(k) {
    assert(k instanceof BN);
    assert(!k.red);

    return this.jmul(k.invert(this.curve.n));
  }

  jdivn(k) {
    assert(!this.curve.n.isZero());

    if (this.curve.h.cmpn(k) === 0)
      return this.jdivH();

    return this.jdiv(new BN(k));
  }

  jdivH() {
    if (this.curve.n.isZero())
      return this.toJ();

    if (this.curve.h.cmpn(1) === 0)
      return this.toJ();

    if (this.curve.hi === null)
      this.curve.hi = this.curve.h.invert(this.curve.n);

    return this.jmul(this.curve.hi);
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this;
  }

  toX() {
    return this;
  }

  key() {
    if (this.isInfinity())
      return `${this.curve.uid}:oo`;

    this.normalize();

    const x = this.getX().toString(16);
    const y = this.getY().toString(16);

    return `${this.curve.uid}:${x},${y}`;
  }

  encode(compact) {
    throw new Error('Not implemented.');
  }

  static decode(curve, bytes) {
    throw new Error('Not implemented.');
  }

  encodeX() {
    throw new Error('Not implemented.');
  }

  static decodeX(curve, bytes) {
    throw new Error('Not implemented.');
  }

  static decodeEven(curve, bytes) {
    throw new Error('Not implemented.');
  }

  static decodeSquare(curve, bytes) {
    throw new Error('Not implemented.');
  }

  toJSON(pre) {
    throw new Error('Not implemented.');
  }

  static fromJSON(curve, json) {
    throw new Error('Not implemented.');
  }

  [custom]() {
    return '<Point>';
  }
}

/**
 * ShortCurve
 */

class ShortCurve extends Curve {
  constructor(conf) {
    super(ShortPoint, 'short', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.b = BN.fromJSON(conf.b).toRed(this.red);
    this.c = BN.fromJSON(conf.c || '0').toRed(this.red);
    this.ai = this.a.isZero() ? this.zero : this.a.redInvert();
    this.zi = this.z.isZero() ? this.zero : this.z.redInvert();

    this.zeroA = this.a.isZero();
    this.threeA = this.a.eq(this.three.redNeg());
    this.redN = this.n.toRed(this.red);
    this.pmodn = this.p.clone();
    this.highOrder = this.n.cmp(this.p) >= 0;
    this.smallGap = false;

    this._finalize(conf);
  }

  _finalize(conf) {
    super._finalize(conf);

    // Precalculate endomorphism.
    if (conf.endo != null)
      this.endo = Endo.fromJSON(this, conf.endo);
    else
      this.endo = this._getEndomorphism();

    if (!this.n.isZero()) {
      this.pmodn = this.p.mod(this.n);

      // Check for Maxwell's trick (see eqR).
      this.smallGap = this.p.div(this.n).cmpn(1) <= 0;
    }

    return this;
  }

  static _isomorphism(curveA, curveB, custom, odd) {
    // Short Weierstrass Isomorphism.
    //
    // [GECC] Page 84, Section 3.1.5.
    // [ARITH1] Page 274, Section 13.1.5.
    // [ALT] Appendix F.3 (Isomorphic Mapping between Weierstrass Curves).
    //
    // Find `u` such that `a * u^4 = a'` and `b * u^6 = b'`.
    //
    // Transformation:
    //
    //   u4 = a' / a
    //   u2 = +-sqrt(u4)
    //   u6 = u4 * u2
    //   a' = a * u4
    //   b' = b * u6
    //
    // Where `u2` is any root that is square.
    //
    // If a = 0, we can do:
    //
    //   a' = 0
    //   b' = b'
    //
    // Where (b' / b)^(1 / 3) is square.
    //
    // If b = 0, we can do:
    //
    //   a' = a'
    //   b' = 0
    //
    // Where sqrt(a' / a) is square.
    assert(curveA instanceof BN);
    assert(curveB instanceof BN);
    assert(custom instanceof BN);
    assert(odd == null || typeof odd === 'boolean');
    assert(!curveA.isZero() || !curveB.isZero());

    if (custom.isZero())
      throw new Error('Invalid coefficient.');

    if (curveA.isZero()) {
      const customB = custom;
      const u6 = customB.redDiv(curveB);
      // Todo: allow index flag.
      const u2 = uncube(u6);

      // Already checked in uncube().
      assert(u2.redJacobi() === 1);

      return [curveA.clone(), customB.clone()];
    }

    if (curveB.isZero()) {
      const customA = custom;
      const u4 = customA.redDiv(curveA);
      const u2 = u4.redSqrt();

      // Todo: allow odd flag.
      if (u2.redJacobi() !== 1)
        u2.redINeg();

      if (u2.redJacobi() !== 1)
        throw new Error('Invalid `a` coefficient.');

      return [customA.clone(), curveB.clone()];
    }

    const customA = custom;
    const u4 = customA.redDiv(curveA);
    const u2 = u4.redSqrt();

    if (odd != null) {
      if (u2.redIsOdd() !== odd)
        u2.redINeg();
    } else {
      if (u2.redJacobi() !== 1)
        u2.redINeg();
    }

    if (u2.redJacobi() !== 1)
      throw new Error('Invalid `a` coefficient.');

    const u6 = u4.redMul(u2);
    const a = curveA.redMul(u4);
    const b = curveB.redMul(u6);

    assert(a.eq(customA));

    return [a, b];
  }

  _short(a0, odd) {
    return ShortCurve._isomorphism(this.a, this.b, a0, odd);
  }

  _mont(b0, odd) {
    // Short Weierstrass->Montgomery Equivalence.
    //
    // [ARITH1] Page 286, Section 13.2.3.c.
    // [SAFE] "Ladders".
    //
    // Transformation:
    //
    //   r = A / (3 * B)
    //   s = +-sqrt(3 * r^2 + a)
    //   A = 3 * r / s
    //   B = 1 / s
    const [r, s] = this._findRS(odd);
    const b = s.redInvert();
    const a = r.redMuln(3).redMul(b);

    if (b0 != null)
      return MontCurve._isomorphism(a, b, b0);

    return [a, b];
  }

  _edwards(a0, odd) {
    // Short Weierstrass->Twisted Edwards Equivalence.
    //
    // [TWISTEQ] Section 1.
    //
    // Transformation:
    //
    //   r = (a' + d') / 6
    //   s = +-sqrt(3 * r^2 + a)
    //   a' = 3 * r + 2 * s
    //   d' = 3 * r - 2 * s
    const [r, s] = this._findRS(odd);
    const r3 = r.redMuln(3);
    const s2 = s.redMuln(2);
    const a = r3.redAdd(s2);
    const d = r3.redSub(s2);

    if (a0 != null)
      return EdwardsCurve._isomorphism(a, d, a0);

    return [a, d];
  }

  _findRS(sign) {
    // Find `r` and `s` for equivalence.
    //
    // [ARITH1] Page 286, Section 13.2.3.c.
    // [SAFE] "Ladders".
    //
    // Computation:
    //
    //   r = solve(r^3 + a * r + b == 0, r)
    //   s = +-sqrt(3 * r^2 + a)
    //
    // Computing `r` is non-trivial. We need
    // to solve `r^3 + a * r + b = 0`, but we
    // don't have a polynomial solver, so we
    // loop over random points until we find
    // one with 2-torsion. Multiplying by the
    // subgroup order should yield a point of
    // ((A / 3) / B, 0) which is a solution.
    assert(sign == null || typeof sign === 'boolean');
    assert(this.h.word(0) >= 4);
    assert(!this.n.isZero());

    const x = this.one.redNeg();

    let p;

    for (;;) {
      x.redIAdd(this.one);

      try {
        p = this.pointFromX(x.clone());
      } catch (e) {
        continue;
      }

      p = p.mul(this.n);

      if (p.isInfinity())
        continue;

      if (!p.y.isZero())
        continue;

      break;
    }

    const r = p.x;
    const r2 = r.redSqr();
    const s = r2.redMuln(3).redIAdd(this.a).redSqrt();

    if (sign != null) {
      if (s.redIsOdd() !== sign)
        s.redINeg();
    }

    return [r, s];
  }

  _scale0(a, b) {
    // We can extract the isomorphism factors with:
    //
    //   u4 = a' / a
    //   u6 = b' / b
    //   u2 = +-sqrt(u4)
    //   u = +-sqrt(u2)
    //   u3 = u2 * u
    //
    // `u2` should be picked such that `u4 * u2 = u6`.
    //
    // If a = 0, we can do:
    //
    //   u6 = b' / b
    //   u2 = u6^(1 / 3)
    //   u = +-sqrt(u2)
    //   u3 = u2 * u
    //
    // Where `u2` is any root that is square.
    //
    // If b = 0, we can do:
    //
    //   u4 = a' / a
    //   u2 = +-sqrt(u4)
    //   u = +-sqrt(u2)
    //   u3 = u2 * u
    //
    // Where `u2` is any root that is square.
    assert(this.a.isZero() === a.isZero());
    assert(this.b.isZero() === b.isZero());

    if (this.a.isZero()) {
      const u6 = this.b.redDiv(this.field(b));
      // Todo: figure out how to check index.
      const u2 = uncube(u6);
      const u = u2.redSqrt();
      const u3 = u2.redMul(u);

      assert(u3.redSqr().eq(u6));
      assert(!u.isZero());

      return [u2, u3];
    }

    if (this.b.isZero()) {
      const u4 = this.a.redDiv(this.field(a));
      const u2 = u4.redSqrt();

      // Todo: figure out how to check oddness.
      if (u2.redJacobi() !== 1)
        u2.redINeg();

      const u = u2.redSqrt();
      const u3 = u2.redMul(u);

      assert(u3.redMul(u).eq(u4));
      assert(!u.isZero());

      return [u2, u3];
    }

    const u4 = this.a.redDiv(this.field(a));
    const u6 = this.b.redDiv(this.field(b));
    const u2 = u4.redSqrt();

    if (!u4.redMul(u2).eq(u6))
      u2.redINeg();

    assert(u4.redMul(u2).eq(u6));

    const u = u2.redSqrt();
    const u3 = u2.redMul(u);

    assert(!u.isZero());

    return [u2, u3];
  }

  _scale1(x, y) {
    // If base points are available, it is much
    // easier, with:
    //
    //   u2 = x' / x
    //   u3 = y' / y
    //   u = +-sqrt(u2)
    //
    // `u` should be picked such that `u2 * u = u3`.
    const u2 = this.g.x.redDiv(this.field(x));
    const u3 = this.g.y.redDiv(this.field(y));
    const u = u2.redSqrt();

    if (!u2.redMul(u).eq(u3))
      u.redINeg();

    assert(u2.redMul(u).eq(u3));
    assert(!u.isZero());

    return [u2, u3];
  }

  _scaleShort(curve) {
    assert(curve instanceof ShortCurve);

    if (this.g.isInfinity() || curve.g.isInfinity())
      return this._scale0(curve.a, curve.b);

    return this._scale1(curve.g.x, curve.g.y);
  }

  _scaleMont(curve) {
    assert(curve instanceof MontCurve);

    if (this.g.isInfinity() || curve.g.isInfinity()) {
      const [a, b] = curve._short();
      return this._scale0(a, b);
    }

    const {x, y} = curve.g;
    const nx = x.redAdd(curve.a3).redMul(curve.bi);
    const ny = y.redMul(curve.bi);

    return this._scale1(nx, ny);
  }

  _scaleEdwards(curve) {
    assert(curve instanceof EdwardsCurve);

    if (this.g.isInfinity() || curve.g.isInfinity()) {
      const [a, b] = curve._short();
      return this._scale0(a, b);
    }

    const {x, y, z} = curve.g;
    const a5 = curve.a.redMuln(5);
    const d5 = curve.d.redMuln(5);
    const dma = curve.d.redSub(curve.a);
    const d5a = d5.redSub(curve.a);
    const da5 = curve.d.redSub(a5);
    const ypz = y.redAdd(z);
    const ymz = y.redSub(z);
    const xx = d5a.redMul(y).redIAdd(da5.redMul(z));
    const xz = ymz.redMuln(12);
    const yy = dma.redMul(ypz).redMul(z);
    const yz = ymz.redMul(x).redIMuln(4);
    const zi = xz.redMul(yz).redInvert();
    const nx = xx.redMul(yz).redMul(zi);
    const ny = yy.redMul(xz).redMul(zi);

    return this._scale1(nx, ny);
  }

  _getEndomorphism(index = 0) {
    // Compute endomorphism.
    //
    // [GECC] Example 3.76, Page 128, Section 3.5.

    // No curve params.
    if (this.n.isZero() || this.g.isInfinity())
      return null;

    // No efficient endomorphism.
    if (!this.zeroA || this.p.modrn(3) !== 1 || this.n.modrn(3) !== 1)
      return null;

    // Solve beta^3 mod p = 1.
    const [b1, b2] = this._getEndoRoots(this.p);

    // Choose the smallest beta by default.
    const beta = [b1, b2][index & 1].toRed(this.red);

    // Solve lambda^3 mod n = 1.
    const [l1, l2] = this._getEndoRoots(this.n);

    // Choose the lambda matching selected beta.
    // Note that P * lambda = (x * beta, y).
    const p = this.point(this.g.x.redMul(beta), this.g.y);

    let lambda;

    if (this.g.mul(l1).eq(p)) {
      lambda = l1;
    } else {
      assert(this.g.mul(l2).eq(p));
      lambda = l2;
    }

    // Get basis vectors.
    const basis = this._getEndoBasis(lambda);

    // Precompute `g1` and `g2`.
    const pre = this._getEndoPrecomp(basis);

    return new Endo(beta, lambda, basis, pre);
  }

  _getEndoRoots(num) {
    // Find roots for x^2 + x + 1 in F.
    //
    // [GECC] Example 3.76, Page 128, Section 3.5.
    // [GLV] Page 192, Section 2 (Endomorphisms).
    //
    // The above document doesn't fully explain how
    // to derive these and only "hints" at it, as
    // mentioned by Hal Finney[1], but we're basically
    // computing two possible cube roots of 1 here.
    //
    // Note that we could also compute[2]:
    //
    //   beta = 2^((p - 1) / 3) mod p
    //   lambda = 3^((n - 1) / 3) mod n
    //
    // As an extension of Fermat's little theorem:
    //
    //   g^(p - 1) mod p == 1
    //
    // It is suspected[3] this is how Hal Finney[4]
    // computed his original endomorphism roots.
    //
    // @indutny's method for computing cube roots
    // of unity[5] appears to be the method described
    // on wikipedia[6][7].
    //
    // Sage produces the same solution:
    //
    //   sage: solve(x^2 + x + 1 == 0, x)
    //   [x == -1/2*I*sqrt(3) - 1/2, x == 1/2*I*sqrt(3) - 1/2]
    //
    // This can be reduced to:
    //
    //   x = (+-sqrt(-3) - 1) / 2
    //
    // [1] https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
    // [2] https://crypto.stackexchange.com/a/22739
    // [3] https://bitcoin.stackexchange.com/a/35872
    // [4] https://github.com/halfinney/bitcoin/commit/dc411b5
    // [5] https://en.wikipedia.org/wiki/Cube_root_of_unity
    // [6] https://en.wikipedia.org/wiki/Splitting_field#Cubic_example
    // [7] http://mathworld.wolfram.com/SplittingField.html
    const red = num === this.p ? this.red : BN.mont(num);
    const two = new BN(2).toRed(red);
    const three = new BN(3).toRed(red);
    const i2 = two.redInvert();

    // S1 = sqrt(-3) / 2
    const s1 = three.redNeg().redSqrt().redMul(i2);

    // S2 = -S1
    const s2 = s1.redNeg();

    // R1 = S1 - 1 / 2
    const r1 = s1.redSub(i2).fromRed();

    // R2 = S2 - 1 / 2
    const r2 = s2.redSub(i2).fromRed();

    return [r1, r2].sort(BN.cmp);
  }

  _getEndoBasis(lambda) {
    // Compute endomorphic basis.
    //
    // This essentially computes Cornacchia's algorithm
    // for solving x^2 + d * y^2 = m (d = lambda, m = order).
    //
    // https://en.wikipedia.org/wiki/Cornacchia%27s_algorithm
    //
    // [GECC] Algorithm 3.74, Page 127, Section 3.5.
    // [GLV] Page 196, Section 4 (Decomposing K).
    //
    // Balanced length-two representation of a multiplier.
    //
    // 1. Run the extended euclidean algorithm with inputs n
    //    and lambda. The algorithm produces a sequence of
    //    equations si*n + ti*lam = ri where s0=1, t0=0,
    //    r0=n, s1=0, t1=1, r1=lam, and the remainders ri
    //    and are non-negative and strictly decreasing. Let
    //    l be the greatest index for which rl >= sqrt(n).
    const [rl, tl, rl1, tl1, rl2, tl2] = this._egcdSqrt(lambda);

    // 2. Set (a1, b1) <- (rl+1, -tl+1).
    const a1 = rl1;
    const b1 = tl1.neg();

    // 3. If (rl^2 + tl^2) <= (rl+2^2 + tl+2^2)
    //    then set (a2, b2) <- (rl, -tl).
    //    else set (a2, b2) <- (rl+2, -tl+2).
    const lhs = rl.sqr().iadd(tl.sqr());
    const rhs = rl2.sqr().iadd(tl2.sqr());

    let a2, b2;

    if (lhs.cmp(rhs) <= 0) {
      a2 = rl;
      b2 = tl.neg();
    } else {
      a2 = rl2;
      b2 = tl2.neg();
    }

    return [
      new Vector(a1, b1),
      new Vector(a2, b2)
    ];
  }

  _egcdSqrt(lambda) {
    // Extended Euclidean algorithm for integers.
    //
    // [GECC] Algorithm 2.19, Page 40, Section 2.2.
    // [GLV] Page 196, Section 4 (Decomposing K).
    assert(lambda instanceof BN);
    assert(!lambda.red);
    assert(lambda.sign() > 0);
    assert(this.n.sign() > 0);

    // Note that we insert the approximate square
    // root checks as described in algorithm 3.74.
    //
    // Algorithm 2.19 is defined as:
    //
    // 1. u <- a
    //    v <- b
    //
    // 2. x1 <- 1
    //    y1 <- 0
    //    x2 <- 0
    //    y2 <- 1
    //
    // 3. while u != 0 do
    //
    // 3.1. q <- floor(v / u)
    //      r <- v - q * u
    //      x <- x2 - q * x1
    //      y <- y2 - q * y1
    //
    // 3.2. v <- u
    //      u <- r
    //      x2 <- x1
    //      x1 <- x
    //      y2 <- y1
    //      y1 <- y
    //
    // 4. d <- v
    //    x <- x2
    //    y <- y2
    //
    // 5. Return (d, x, y).

    // Start with an approximate square root of n.
    const sqrtn = this.n.ushrn(this.n.bitLength() >>> 1);

    let u = lambda; // r1
    let v = this.n.clone(); // r0
    let x1 = new BN(1); // t1
    let y1 = new BN(0); // t0
    let x2 = new BN(0); // s1
    let y2 = new BN(1); // s0

    // All vectors are roots of: a + b * lambda = 0 (mod n).
    let rl, tl;

    // First vector.
    let rl1, tl1;

    // Inner.
    let i = 0;
    let j = 0;
    let p;

    // Compute EGCD.
    while (!u.isZero() && i < 2) {
      const q = v.quo(u);
      const r = v.sub(q.mul(u));
      const x = x2.sub(q.mul(x1));
      const y = y2.sub(q.mul(y1));

      // Check for r < sqrt(n).
      if (j === 0 && r.cmp(sqrtn) < 0) {
        rl = p;
        tl = x1;
        rl1 = r;
        tl1 = x;
        j = 1; // 1 more round.
      }

      p = r;
      v = u;
      u = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;

      i += j;
    }

    // Should never happen.
    assert(j !== 0, 'Could not find r < sqrt(n).');

    // Second vector.
    const rl2 = x2;
    const tl2 = x1;

    return [
      rl,
      tl,
      rl1,
      tl1,
      rl2,
      tl2
    ];
  }

  _getEndoPrecomp(basis) {
    // Precompute `g1` and `g2` to avoid round division.
    //
    // [JCEN12] Page 5, Section 4.3.
    //
    // Computation:
    //
    //   d = a1 * b2 - b1 * a2
    //   t = ceil(log2(d+1)) + p
    //   g1 = round((2^t * b2) / d)
    //   g2 = round((2^t * b1) / d)
    //
    // Where:
    //
    //   `p` is the number of precision bits.
    //   `d` is equal to `n` (the curve order).
    //
    // The paper above uses 2 as the value of `p`,
    // whereas libsecp256k1 uses 128 (total=384).
    //
    // We pick precision for `g1` and `g2` such that:
    //
    //   abs(g1) < n
    //   abs(g2) < n
    //
    // This ensures maximum precision for the constants
    // while also ensuring they fit into a fixed number
    // of scalar limbs in more optimized implementations.
    //
    // Furthermore, we attempt to align to a limb width
    // of 64 bits. This allows us to optimize the shift,
    // a la libsecp256k1[1].
    //
    // [1] https://github.com/bitcoin-core/secp256k1/pull/822
    assert(Array.isArray(basis));
    assert(basis.length === 2);
    assert(basis[0] instanceof Vector);
    assert(basis[1] instanceof Vector);

    const [v1, v2] = basis;
    const d = v1.a.mul(v2.b).isub(v1.b.mul(v2.a));
    const bits = d.bitLength();
    const align = bits >= 160;

    assert(d.eq(this.n));

    // Start with a rough estimate.
    let shift = bits + Math.ceil(bits / 2) + 1;
    let g1, g2;

    if (align)
      shift -= shift & 63;

    while (shift > bits) {
      g1 = v2.b.ushln(shift).divRound(d);
      g2 = v1.b.ushln(shift).divRound(d);

      if (g1.ucmp(d) < 0 && g2.ucmp(d) < 0)
        break;

      if (align)
        shift -= 64;
      else
        shift -= 1;
    }

    if (shift <= bits)
      throw new Error('Could not calculate g1 and g2.');

    return [shift, g1, g2];
  }

  _endoSplit(k) {
    // Balanced length-two representation of a multiplier.
    //
    // [GECC] Algorithm 3.74, Page 127, Section 3.5.
    //
    // Also note that it is possible to precompute[1]
    // values in order to avoid the division[2][3][4].
    //
    // This involves precomputing `g1` and `g2 (see
    // above). `c1` and `c2` can then be computed as
    // follows:
    //
    //   t = ceil(log2(n+1)) + p
    //   c1 = (k * g1) >> t
    //   c2 = -((k * g2) >> t)
    //
    // Where `>>` is an _unsigned_ right shift. Also
    // note that the last bit discarded in the shift
    // must be stored. If it is 1, then add 1 to the
    // scalar (absolute addition).
    //
    // It's worth noting that libsecp256k1 uses a
    // different calculation along the lines of:
    //
    //   t = ceil(log2(n+1)) + p
    //   c1 = ((k * g1) >> t) * -b1
    //   c2 = ((k * -g2) >> t) * -b2
    //   k2 = c1 + c2
    //   k1 = k2 * -lambda + k
    //
    // So, in the future, we can consider changing
    // step 4 to:
    //
    //   4. Compute c1 = (k * g1) >> t
    //          and c2 = -((k * g2) >> t).
    //
    //   const [shift, g1, g2] = this.endo.pre;
    //   const c1 = k.mulShift(g1, shift);
    //   const c2 = k.mulShift(g2, shift).ineg();
    //
    // Once we're brave enough, that is.
    //
    // [1] [JCEN12] Page 5, Section 4.3.
    // [2] https://github.com/bitcoin-core/secp256k1/blob/0b70241/src/scalar_impl.h#L259
    // [3] https://github.com/bitcoin-core/secp256k1/pull/21
    // [4] https://github.com/bitcoin-core/secp256k1/pull/127
    assert(k instanceof BN);
    assert(!k.red);
    assert(!this.n.isZero());

    const [v1, v2] = this.endo.basis;

    // 4. Compute c1 = round(b2 * k / n)
    //        and c2 = round(-b1 * k / n).
    const c1 = v2.b.mul(k).divRound(this.n);
    const c2 = v1.b.neg().mul(k).divRound(this.n);

    // 5. Compute k1 = k - c1 * a1 - c2 * a2
    //        and k2 = -c1 * b1 - c2 * b2.
    const p1 = c1.mul(v1.a);
    const p2 = c2.mul(v2.a);
    const q1 = c1.ineg().mul(v1.b);
    const q2 = c2.mul(v2.b);

    // Calculate answer.
    const k1 = k.sub(p1).isub(p2);
    const k2 = q1.isub(q2);

    // 6. Return (k1, k2).
    return [k1, k2];
  }

  _endoBeta(point) {
    assert(point instanceof ShortPoint);
    return [point, point._getBeta()];
  }

  _endoWnafMulAdd(points, coeffs) {
    // Point multiplication with efficiently computable endomorphisms.
    //
    // [GECC] Algorithm 3.77, Page 129, Section 3.5.
    // [GLV] Page 193, Section 3 (Using Efficient Endomorphisms).
    //
    // Note it may be possible to do this 4-dimensionally [4GLV].
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);
    assert(this.endo != null);

    const len = points.length;
    const npoints = new Array(len * 2);
    const ncoeffs = new Array(len * 2);

    for (let i = 0; i < len; i++) {
      const [p1, p2] = this._endoBeta(points[i]);
      const [k1, k2] = this._endoSplit(coeffs[i]);

      npoints[i * 2 + 0] = p1;
      ncoeffs[i * 2 + 0] = k1;
      npoints[i * 2 + 1] = p2;
      ncoeffs[i * 2 + 1] = k2;
    }

    return this._wnafMulAdd(5, npoints, ncoeffs);
  }

  _sswu(u) {
    // Simplified Shallue-Woestijne-Ulas Method.
    //
    // Distribution: 3/8.
    //
    // [SSWU1] Page 15-16, Section 7. Appendix G.
    // [SSWU2] Page 5, Theorem 2.3.
    // [H2EC] "Simplified Shallue-van de Woestijne-Ulas Method".
    //
    // Assumptions:
    //
    //   - a != 0, b != 0.
    //   - Let z be a non-square in F(p).
    //   - z != -1.
    //   - The polynomial g(x) - z is irreducible over F(p).
    //   - g(b / (z * a)) is square in F(p).
    //   - u != 0, u != +-sqrt(-1 / z).
    //
    // Map:
    //
    //   g(x) = x^3 + a * x + b
    //   t1 = 1 / (z^2 * u^4 + z * u^2)
    //   x1 = (-b / a) * (1 + t1)
    //   x1 = b / (z * a), if t1 = 0
    //   x2 = z * u^2 * x1
    //   x = x1, if g(x1) is square
    //     = x2, otherwise
    //   y = sign(u) * abs(sqrt(g(x)))
    const {b, z, ai, zi, one} = this;
    const z2 = z.redSqr();
    const ba = b.redNeg().redMul(ai);
    const bza = b.redMul(zi).redMul(ai);
    const u2 = u.redSqr();
    const u4 = u2.redSqr();
    const t0 = z2.redMul(u4).redIAdd(z.redMul(u2));
    const t1 = t0.isZero() ? t0 : t0.redInvert();
    const x1 = t1.isZero() ? bza : ba.redMul(one.redAdd(t1));
    const x2 = z.redMul(u2).redMul(x1);
    const y1 = this.solveY2(x1);
    const y2 = this.solveY2(x2);
    const alpha = y1.redIsSquare() | 0;
    const x = [x1, x2][alpha ^ 1];
    const y = [y1, y2][alpha ^ 1].redSqrt();

    if (y.redIsOdd() !== u.redIsOdd())
      y.redINeg();

    return this.point(x, y);
  }

  _sswui(p, hint) {
    // Inverting the Map (Simplified Shallue-Woestijne-Ulas).
    //
    // Assumptions:
    //
    //   - a^2 * x^2 - 2 * a * b * x - 3 * b^2 is square in F(p).
    //   - If r < 3 then x != -b / a.
    //
    // Unlike SVDW, the preimages here are evenly
    // distributed (more or less). SSWU covers ~3/8
    // of the curve points. Each preimage has a 1/2
    // chance of mapping to either x1 or x2.
    //
    // Assuming the point is within that set, each
    // point has a 1/4 chance of inverting to any
    // of the preimages. This means we can simply
    // randomly select a preimage if one exists.
    //
    // However, the [SVDW2] sampling method seems
    // slighly faster in practice for [SQUARED].
    //
    // Map:
    //
    //   c = sqrt(a^2 * x^2 - 2 * a * b * x - 3 * b^2)
    //   u1 = -(a * x + b - c) / (2 * (a * x + b) * z)
    //   u2 = -(a * x + b + c) / (2 * (a * x + b) * z)
    //   u3 = -(a * x + b - c) / (2 * b * z)
    //   u4 = -(a * x + b + c) / (2 * b * z)
    //   r = random integer in [1,4]
    //   u = sign(y) * abs(sqrt(ur))
    const {a, b, z} = this;
    const {x, y} = p;
    const r = hint & 3;
    const a2x2 = a.redSqr().redMul(x.redSqr());
    const abx2 = a.redMul(b).redMul(x).redIMuln(2);
    const b23 = b.redSqr().redMuln(3);
    const axb = a.redMul(x).redIAdd(b);
    const c = a2x2.redISub(abx2).redISub(b23).redSqrt();
    const n0 = axb.redSub(c).redINeg();
    const n1 = axb.redAdd(c).redINeg();
    const d0 = axb.redMul(z).redIMuln(2);
    const d1 = b.redMul(z).redIMuln(2);
    const n = [n0, n1][r & 1]; // r = 1 or 3
    const d = [d0, d1][r >>> 1]; // r = 2 or 3
    const u = n.redDivSqrt(d);

    if (u.redIsOdd() !== y.redIsOdd())
      u.redINeg();

    return u;
  }

  _svdwf(u) {
    // Shallue-van de Woestijne Method.
    //
    // Distribution: 9/16.
    //
    // [SVDW1] Section 5.
    // [SVDW2] Page 8, Section 3.
    //         Page 15, Section 6, Algorithm 1.
    // [H2EC] "Shallue-van de Woestijne Method".
    //
    // Assumptions:
    //
    //   - p = 1 (mod 3).
    //   - a = 0, b != 0.
    //   - Let z be a unique element in F(p).
    //   - g((sqrt(-3 * z^2) - z) / 2) is square in F(p).
    //   - u != 0, u != +-sqrt(-g(z)).
    //
    // Map:
    //
    //   g(x) = x^3 + b
    //   c = sqrt(-3 * z^2)
    //   t1 = u^2 + g(z)
    //   t2 = 1 / (u^2 * t1)
    //   t3 = u^4 * t2 * c
    //   x1 = (c - z) / 2 - t3
    //   x2 = t3 - (c + z) / 2
    //   x3 = z - t1^3 * t2 / (3 * z^2)
    //   x = x1, if g(x1) is square
    //     = x2, if g(x2) is square
    //     = x3, otherwise
    //   y = sign(u) * abs(sqrt(g(x)))
    const {c, z, zi, i2, i3} = this;
    const gz = this.solveY2(z);
    const z3 = i3.redMul(zi.redSqr());
    const u2 = u.redSqr();
    const u4 = u2.redSqr();
    const t1 = u2.redAdd(gz);
    const u2t1 = u2.redMul(t1);
    const t2 = u2t1.isZero() ? u2t1 : u2t1.redInvert();
    const t3 = u4.redMul(t2).redMul(c);
    const t4 = t1.redSqr().redMul(t1);
    const x1 = c.redSub(z).redMul(i2).redISub(t3);
    const x2 = t3.redSub(c.redAdd(z).redMul(i2));
    const x3 = z.redSub(t4.redMul(t2).redMul(z3));
    const y1 = this.solveY2(x1);
    const y2 = this.solveY2(x2);
    const y3 = this.solveY2(x3);
    const alpha = y1.redJacobi() | 1;
    const beta = y2.redJacobi() | 1;
    const i = mod((alpha - 1) * beta, 3);
    const x = [x1, x2, x3][i];
    const y = [y1, y2, y3][i];

    return [x, y];
  }

  _svdw(u) {
    const [x, yy] = this._svdwf(u);
    const y = yy.redSqrt();

    if (y.redIsOdd() !== u.redIsOdd())
      y.redINeg();

    return this.point(x, y);
  }

  _svdwi(p, hint) {
    // Inverting the Map (Shallue-van de Woestijne).
    //
    // [SQUARED] Algorithm 1, Page 8, Section 3.3.
    // [SVDW2] Page 12, Section 5.
    // [SVDW3] "Inverting the map".
    //
    // Assumptions:
    //
    //   - If r = 1 then x != -(c + z) / 2.
    //   - If r = 2 then x != (c - z) / 2.
    //   - If r > 2 then (t0 - t1 + t2) is square in F(p).
    //   - f(f^-1(x)) = x where f is the map function.
    //
    // We use the sampling method from [SVDW2],
    // _not_ [SQUARED]. This seems to have a
    // better distribution in practice.
    //
    // Note that [SVDW3] also appears to be
    // incorrect in terms of distribution.
    //
    // The distribution of f(u), assuming u is
    // random, is (1/2, 1/4, 1/4).
    //
    // To mirror this, f^-1(x) should simply
    // pick (1/2, 1/4, 1/8, 1/8).
    //
    // To anyone running the forward map, our
    // strings will appear to be random.
    //
    // Map:
    //
    //   g(x) = x^3 + b
    //   c = sqrt(-3 * z^2)
    //   t0 = 9 * (x^2 * z^2 + z^4)
    //   t1 = 18 * x * z^3
    //   t2 = 12 * g(z) * (x - z)
    //   t3 = sqrt(t0 - t1 + t2)
    //   t4 = t3 * z
    //   u1 = g(z) * (c - 2 * x - z) / (c + 2 * x + z)
    //   u2 = g(z) * (c + 2 * x + z) / (c - 2 * x - z)
    //   u3 = (3 * (z^3 - x * z^2) - 2 * g(z) + t4) / 2
    //   u4 = (3 * (z^3 - x * z^2) - 2 * g(z) - t4) / 2
    //   r = random integer in [1,4]
    //   u = sign(y) * abs(sqrt(ur))
    const {b, c, z, zero, two} = this;
    const {x, y} = p;
    const r = hint & 3;
    const z2 = z.redSqr();
    const z3 = z2.redMul(z);
    const z4 = z2.redSqr();
    const gz = z3.redAdd(b);
    const gz2 = gz.redMuln(2);
    const xx = x.redSqr();
    const x2z = x.redMuln(2).redIAdd(z);
    const xz2 = x.redMul(z2);
    const c0 = c.redSub(x2z);
    const c1 = c.redAdd(x2z);
    const t0 = xx.redMul(z2).redIAdd(z4).redIMuln(9);
    const t1 = x.redMul(z3).redIMuln(18);
    const t2 = gz.redMul(x.redSub(z)).redIMuln(12);
    const t3 = r >= 2 ? t0.redISub(t1).redIAdd(t2).redSqrt() : zero;
    const t4 = t3.redMul(z);
    const t5 = z3.redISub(xz2).redIMuln(3).redISub(gz2);
    const n0 = gz.redMul(c0);
    const n1 = gz.redMul(c1);
    const n2 = t5.redAdd(t4);
    const n3 = t5.redSub(t4);
    const d2 = two;
    const n = [n0, n1, n2, n3][r];
    const d = [c1, c0, d2, d2][r];
    const u = n.redDivSqrt(d);
    const [x0] = this._svdwf(u);

    if (!x0.eq(x))
      throw new Error('Invalid point.');

    if (u.redIsOdd() !== y.redIsOdd())
      u.redINeg();

    return u;
  }

  isElliptic() {
    const {a, b} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const b2 = b.redSqr();
    const d = b2.redMuln(27).redIAdd(a3.redMuln(4));

    // 4 * a^3 + 27 * b^2 != 0
    return !d.isZero();
  }

  jinv() {
    // [ARITH1] Page 71, Section 4.4.
    // http://mathworld.wolfram.com/j-Invariant.html
    const {a, b} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const b2 = b.redSqr();
    const t0 = a3.redMuln(4);
    const lhs = t0.redMuln(1728);
    const rhs = b2.redMuln(27).redIAdd(t0);

    if (rhs.isZero())
      throw new Error('Curve is not elliptic.');

    // (1728 * 4 * a^3) / (4 * a^3 + 27 * b^2)
    return lhs.redDiv(rhs).fromRed();
  }

  point(x, y) {
    return new ShortPoint(this, x, y);
  }

  jpoint(x, y, z) {
    return new JPoint(this, x, y, z);
  }

  solveX(y) {
    assert(y instanceof BN);

    if (!this.a.isZero())
      throw new Error('Not implemented.');

    // x^3 = y^2 - b
    const y2 = y.redSqr();
    const x3 = y2.redSub(this.b);

    return cubeRoots(x3);
  }

  solveY2(x) {
    // [GECC] Page 89, Section 3.2.2.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
    assert(x instanceof BN);

    // y^2 = x^3 + a * x + b
    const x3 = x.redSqr().redMul(x);
    const y2 = x3.redIAdd(this.b);

    if (!this.zeroA) {
      // Save some cycles for a = -3.
      if (this.threeA)
        y2.redIAdd(x.redMuln(-3));
      else
        y2.redIAdd(this.a.redMul(x));
    }

    return y2;
  }

  validate(point) {
    assert(point instanceof ShortPoint);

    if (point.inf)
      return true;

    const {x, y} = point;
    const y2 = this.solveY2(x);

    return y.redSqr().eq(y2);
  }

  pointFromX(x, sign = null) {
    assert(x instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!x.red)
      x = x.toRed(this.red);

    const y = this.solveY(x);

    if (sign != null) {
      if (this.h.cmpn(1) > 0) {
        if (y.isZero() && sign)
          throw new Error('Invalid point.');
      }

      if (y.redIsOdd() !== sign)
        y.redINeg();
    }

    return this.point(x, y);
  }

  pointFromY(y, index = 0) {
    assert(y instanceof BN);
    assert((index >>> 0) === index);

    if (!y.red)
      y = y.toRed(this.red);

    const coords = this.solveX(y);

    if (index >= coords.length)
      throw new Error('Invalid X coordinate index.');

    const x = coords[index];

    return this.point(x, y);
  }

  isIsomorphic(curve) {
    // [GECC] Page 84, Section 3.1.5.
    // [ARITH1] Page 286, Section 13.2.3.c.
    assert(curve instanceof Curve);

    if (!curve.p.eq(this.p))
      return false;

    let u2, u3;
    try {
      [u2, u3] = this._scale(curve);
    } catch (e) {
      return false;
    }

    // E(a,b) <-> E(au^4,bu^6)
    if (curve.type === 'short') {
      // a' = a * u^4, b' = b * u^6
      const a = this.field(curve.a).redMul(u2.redSqr());
      const b = this.field(curve.b).redMul(u3.redSqr());

      return this.a.eq(a) && this.b.eq(b);
    }

    // E(a,b) <-> M(A,B)
    if (curve.type === 'mont') {
      // (A / (3 * B))^3 + a * (A / (3 * B)) + b = 0
      const {a3, bi} = curve;
      const x = this.field(a3.redMul(bi)).redMul(u2);
      const y2 = this.solveY2(x);

      return y2.isZero();
    }

    // E(a,b) <-> E(a,d)
    if (curve.type === 'edwards') {
      // ((a' + d') / 6)^3 + a * ((a' + d') / 6) + b = 0
      const x = this.field(curve.ad6).redMul(u2);
      const y2 = this.solveY2(x);

      return y2.isZero();
    }

    return false;
  }

  isIsogenous(curve) {
    assert(curve instanceof Curve);
    return false;
  }

  pointFromShort(point) {
    // [GECC] Page 84, Section 3.1.5.
    // [ALT] Appendix F.3 (Isomorphic Mapping between Weierstrass Curves).
    assert(point instanceof ShortPoint);

    if (this.isIsomorphic(point.curve)) {
      // Isomorphic maps for E(a,b)<->E(au^4,bu^6):
      //
      //   x' = x * u^2
      //   y' = y * u^3
      //
      // Where a * u^4 = a' and b * u^6 = b'.
      if (point.isInfinity())
        return this.point();

      const [u2, u3] = this._scale(point.curve);
      const x = this.field(point.x);
      const y = this.field(point.y);
      const nx = x.redMul(u2);
      const ny = y.redMul(u3);

      return this.point(nx, ny);
    }

    throw new Error('Not implemented.');
  }

  pointFromMont(point) {
    // [ALT] Appendix E.2 (Switching between Alternative Representations).
    // [MONT2] "Equivalence with Weierstrass curves"
    assert(point instanceof MontPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for M(A,B)->E(a,b):
      //
      //   x = (u + A / 3) / B
      //   y = v / B
      //
      // Undefined if ((u^3 + A * u^2 + u) / B) is not square.
      if (point.isInfinity())
        return this.point();

      const {a3, bi} = point.curve;
      const [u2, u3] = this._scale(point.curve);
      const nx = point.x.redAdd(a3).redMul(bi);
      const ny = point.y.redMul(bi);

      return this.point(this.field(nx).redMul(u2),
                        this.field(ny).redMul(u3));
    }

    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    // [TWISTEQ] Section 2.
    assert(point instanceof EdwardsPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for E(a,d)->E(a',b'):
      //
      //   x' = ((5 * d - a) * y + d - 5 * a) / (12 * (y - 1))
      //   y' = (d - a) * (y + 1) / (4 * x * (y - 1))
      //
      // Undefined for x = 0 or y = 1.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> ((a + d) / 6, 0)
      //
      // Unexceptional Cases:
      //   - (sqrt(1 / a), 0) -> ((5 * a - d) / 12, (a - d) / 4 * sqrt(a))
      const {a, d, ad6} = point.curve;
      const [u2, u3] = this._scale(point.curve);

      if (point.isInfinity())
        return this.point();

      if (point.x.isZero()) {
        const x = this.field(ad6).redMul(u2);
        return this.point(x, this.zero);
      }

      const {x, y, z} = point;
      const a5 = a.redMuln(5);
      const d5 = d.redMuln(5);
      const dma = d.redSub(a);
      const d5a = d5.redSub(a);
      const da5 = d.redSub(a5);
      const ypz = y.redAdd(z);
      const ymz = y.redSub(z);
      const xx = d5a.redMul(y).redIAdd(da5.redMul(z));
      const xz = ymz.redMuln(12);
      const yy = dma.redMul(ypz).redMul(z);
      const yz = ymz.redMul(x).redIMuln(4);

      return this.cpoint(this.field(xx).redMul(u2),
                         this.field(xz),
                         this.field(yy).redMul(u3),
                         this.field(yz));
    }

    throw new Error('Not implemented.');
  }

  pointFromUniform(u) {
    assert(u instanceof BN);

    // z = 0 or b = 0
    if (this.z.isZero() || this.b.isZero())
      throw new Error('Not implemented.');

    // a != 0, b != 0
    if (!this.a.isZero())
      return this._sswu(u);

    // p = 1 mod 3, a = 0, b != 0
    if (!this.c.isZero())
      return this._svdw(u);

    throw new Error('Not implemented.');
  }

  pointToUniform(p, hint) {
    // Convert a short weierstrass point to a field
    // element by inverting either the SSWU or SVDW
    // map.
    //
    // Hint Layout:
    //
    //   [00000000] [0000] [0000]
    //        |        |      |
    //        |        |      +-- preimage index
    //        |        +--- subgroup
    //        +-- bits to OR with uniform bytes
    assert(p instanceof ShortPoint);
    assert((hint >>> 0) === hint);

    // z = 0 or b = 0
    if (this.z.isZero() || this.b.isZero())
      throw new Error('Not implemented.');

    // P = O
    if (p.isInfinity())
      throw new Error('Invalid point.');

    // Add a random torsion component.
    const i = ((hint >>> 4) & 15) % this.torsion.length;
    const q = p.add(this.torsion[i]);

    return wrapErrors(() => {
      // a != 0, b != 0
      if (!this.a.isZero())
        return this._sswui(q, hint);

      // p = 1 mod 3, a = 0, b != 0
      if (!this.c.isZero())
        return this._svdwi(q, hint);

      throw new Error('Not implemented.');
    });
  }

  mulAll(points, coeffs) {
    return super.mulAll(points, coeffs).toP();
  }

  affinizeAll(points) {
    const out = this.normalizeAll(points);

    for (let i = 0; i < out.length; i++)
      out[i] = out[i].toP();

    return out;
  }

  decodePoint(bytes) {
    return ShortPoint.decode(this, bytes);
  }

  encodeX(point) {
    assert(point instanceof Point);
    return point.encodeX();
  }

  decodeEven(bytes) {
    return ShortPoint.decodeEven(this, bytes);
  }

  decodeSquare(bytes) {
    return ShortPoint.decodeSquare(this, bytes);
  }

  toShort(a0, odd, sign = null) {
    const [a, b] = this._short(a0, odd);

    const curve = new ShortCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = curve._scale(this);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromShort(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromShort(this.torsion[i]);

    return curve;
  }

  toMont(b0, odd, sign = null) {
    const [a, b] = this._mont(b0, odd);

    const curve = new MontCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = this._scale(curve);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromShort(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromShort(this.torsion[i]);

    return curve;
  }

  toEdwards(a0, odd, sign = null) {
    const [a, d] = this._edwards(a0, odd);

    const curve = new EdwardsCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      d: d,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = this._scale(curve);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity()) {
      curve.g = curve.pointFromShort(this.g);
      curve.g.normalize();
    }

    if (curve.isComplete()) {
      for (let i = 0; i < this.h.word(0); i++) {
        curve.torsion[i] = curve.pointFromShort(this.torsion[i]);
        curve.torsion[i].normalize();
      }
    }

    return curve;
  }

  pointFromJSON(json) {
    return ShortPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);

    json.a = this.a.fromRed().toJSON();
    json.b = this.b.fromRed().toJSON();

    if (!this.c.isZero())
      json.c = this.c.fromRed().toJSON();

    return json;
  }
}

/**
 * ShortPoint
 */

class ShortPoint extends Point {
  constructor(curve, x, y) {
    assert(curve instanceof ShortCurve);

    super(curve, types.AFFINE);

    this.x = this.curve.zero;
    this.y = this.curve.zero;
    this.inf = true;

    if (x != null)
      this._init(x, y);
  }

  _init(x, y) {
    assert(x instanceof BN);
    assert(y instanceof BN);

    this.x = x;
    this.y = y;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    this.inf = false;
  }

  _getBeta() {
    if (!this.curve.endo)
      return null;

    if (this.pre && this.pre.beta)
      return this.pre.beta;

    // Augment the point with our beta value.
    // This is the counterpart to `k2` after
    // the endomorphism split of `k`.
    //
    // Note that if we have precomputation,
    // we have to clone and update all of the
    // precomputed points below.
    const xb = this.x.redMul(this.curve.endo.beta);
    const beta = this.curve.point(xb, this.y);

    if (this.pre) {
      beta.pre = this.pre.map((point) => {
        const xb = point.x.redMul(this.curve.endo.beta);
        return this.curve.point(xb, point.y);
      });

      this.pre.beta = beta;
    }

    return beta;
  }

  _getJNAF(point) {
    assert(point instanceof ShortPoint);

    if (this.inf || point.inf)
      return super._getJNAF(point);

    // Create comb for JSF.
    const comb = [
      this, // 1
      null, // 3
      null, // 5
      point // 7
    ];

    // Try to avoid Jacobian points, if possible.
    if (this.y.eq(point.y)) {
      comb[1] = this.add(point);
      comb[2] = this.toJ().sub(point);
    } else if (this.y.eq(point.y.redNeg())) {
      comb[1] = this.toJ().add(point);
      comb[2] = this.sub(point);
    } else {
      comb[1] = this.toJ().add(point);
      comb[2] = this.toJ().sub(point);
    }

    return comb;
  }

  clone() {
    if (this.inf)
      return this.curve.point();

    return this.curve.point(this.x, this.y);
  }

  scale(a) {
    return this.toJ().scale(a);
  }

  neg() {
    // P = O
    if (this.inf)
      return this;

    // -(X1, Y1) = (X1, -Y1)
    return this.curve.point(this.x, this.y.redNeg());
  }

  add(p) {
    // [GECC] Page 80, Section 3.1.2.
    //
    // Addition Law:
    //
    //   l = (y1 - y2) / (x1 - x2)
    //   x3 = l^2 - x1 - x2
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 2M + 1S + 6A
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P, P + -P
    if (this.x.eq(p.x)) {
      // P + -P = O
      if (!this.y.eq(p.y))
        return this.curve.point();

      // P + P = 2P
      return this.dbl();
    }

    // X1 != X2, Y1 = Y2
    if (this.y.eq(p.y)) {
      // X3 = -X1 - X2
      const nx = this.x.redNeg().redISub(p.x);

      // Y3 = -Y1
      const ny = this.y.redNeg();

      // Skip the inverse.
      return this.curve.point(nx, ny);
    }

    // H = X1 - X2
    const h = this.x.redSub(p.x);

    // R = Y1 - Y2
    const r = this.y.redSub(p.y);

    // L = R / H
    const l = r.redDiv(h);

    // X3 = L^2 - X1 - X2
    const nx = l.redSqr().redISub(this.x).redISub(p.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  dbl() {
    // [GECC] Page 80, Section 3.1.2.
    //
    // Addition Law (doubling):
    //
    //   l = (3 * x1^2 + a) / (2 * y1)
    //   x3 = l^2 - 2 * x1
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 2M + 2S + 3A + 2*2 + 1*3

    // P = O
    if (this.inf)
      return this;

    // Y1 = 0
    if (this.y.isZero())
      return this.curve.point();

    // XX = X1^2
    const xx = this.x.redSqr();

    // M = 3 * XX + a
    const m = xx.redIMuln(3).redIAdd(this.curve.a);

    // Z = 2 * Y1
    const z = this.y.redMuln(2);

    // L = M / Z
    const l = m.redDiv(z);

    // X3 = L^2 - 2 * X1
    const nx = l.redSqr().redISub(this.x).redISub(this.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  dblp(pow) {
    return this.toJ().dblp(pow).toP();
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

  eq(p) {
    assert(p instanceof ShortPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.inf)
      return p.inf;

    // Q = O
    if (p.inf)
      return false;

    // X1 = X2, Y1 = Y2
    return this.x.eq(p.x)
        && this.y.eq(p.y);
  }

  cmp(point) {
    assert(point instanceof ShortPoint);

    if (this.inf && !point.inf)
      return -1;

    if (!this.inf && point.inf)
      return 1;

    if (this.inf && point.inf)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX())
        || this.getY().cmp(point.getY());
  }

  isInfinity() {
    // Infinity cannot be represented in
    // the affine space, except by a flag.
    return this.inf;
  }

  isOrder2() {
    if (this.inf)
      return false;

    return this.y.isZero();
  }

  isOdd() {
    if (this.inf)
      return false;

    return this.y.redIsOdd();
  }

  isEven() {
    if (this.inf)
      return false;

    return this.y.redIsEven();
  }

  isSquare() {
    if (this.inf)
      return false;

    return this.y.redJacobi() !== -1;
  }

  eqX(x) {
    assert(x instanceof BN);
    assert(!x.red);

    if (this.inf)
      return false;

    return this.getX().eq(x);
  }

  eqR(x) {
    assert(x instanceof BN);
    assert(!x.red);
    assert(!this.curve.n.isZero());

    if (this.inf)
      return false;

    return this.getX().imod(this.curve.n).eq(x);
  }

  mul(k) {
    return super.mul(k).toP();
  }

  muln(k) {
    return super.muln(k).toP();
  }

  mulBlind(k, rng) {
    return super.mulBlind(k, rng).toP();
  }

  mulAdd(k1, p2, k2) {
    return super.mulAdd(k1, p2, k2).toP();
  }

  mulH() {
    return super.mulH().toP();
  }

  div(k) {
    return super.div(k).toP();
  }

  divn(k) {
    return super.divn(k).toP();
  }

  divH() {
    return super.divH().toP();
  }

  toP() {
    return this;
  }

  toJ() {
    // (X3, Y3, Z3) = (1, 1, 0)
    if (this.inf)
      return this.curve.jpoint();

    // (X3, Y3, Z3) = (X1, Y1, 1)
    return this.curve.jpoint(this.x, this.y, this.curve.one);
  }

  encode(compact) {
    // [SEC1] Page 10, Section 2.3.3.
    if (compact == null)
      compact = true;

    assert(typeof compact === 'boolean');

    const {fieldSize} = this.curve;

    // We do not serialize points at infinity.
    if (this.inf)
      throw new Error('Invalid point.');

    // Compressed form (0x02 = even, 0x03 = odd).
    if (compact) {
      const p = Buffer.alloc(1 + fieldSize);
      const x = this.curve.encodeField(this.getX());

      p[0] = 0x02 | this.y.redIsOdd();
      x.copy(p, 1);

      return p;
    }

    // Uncompressed form (0x04).
    const p = Buffer.alloc(1 + fieldSize * 2);
    const x = this.curve.encodeField(this.getX());
    const y = this.curve.encodeField(this.getY());

    p[0] = 0x04;
    x.copy(p, 1);
    y.copy(p, 1 + fieldSize);

    return p;
  }

  static decode(curve, bytes) {
    // [SEC1] Page 11, Section 2.3.4.
    assert(curve instanceof ShortCurve);
    assert(Buffer.isBuffer(bytes));

    const len = curve.fieldSize;

    if (bytes.length < 1 + len)
      throw new Error('Not a point.');

    // Point forms:
    //
    //   0x00 -> Infinity (openssl, unsupported)
    //   0x02 -> Compressed Even
    //   0x03 -> Compressed Odd
    //   0x04 -> Uncompressed
    //   0x06 -> Hybrid Even (openssl)
    //   0x07 -> Hybrid Odd (openssl)
    //
    // Note that openssl supports serializing points
    // at infinity as {0}. We choose not to support it
    // because it's strange and not terribly useful.
    const form = bytes[0];

    switch (form) {
      case 0x02:
      case 0x03: {
        if (bytes.length !== 1 + len)
          throw new Error('Invalid point size for compressed.');

        const x = curve.decodeField(bytes.slice(1, 1 + len));

        if (x.cmp(curve.p) >= 0)
          throw new Error('Invalid point.');

        const p = curve.pointFromX(x, form === 0x03);

        assert(!p.isInfinity());

        return p;
      }

      case 0x04:
      case 0x06:
      case 0x07: {
        if (bytes.length !== 1 + len * 2)
          throw new Error('Invalid point size for uncompressed.');

        const x = curve.decodeField(bytes.slice(1, 1 + len));
        const y = curve.decodeField(bytes.slice(1 + len, 1 + 2 * len));

        // [GECC] Algorithm 4.3, Page 180, Section 4.
        if (x.cmp(curve.p) >= 0 || y.cmp(curve.p) >= 0)
          throw new Error('Invalid point.');

        // OpenSSL hybrid encoding.
        if (form !== 0x04 && form !== (0x06 | y.isOdd()))
          throw new Error('Invalid hybrid encoding.');

        const p = curve.point(x, y);

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

  encodeX() {
    // [SCHNORR] "Specification".
    // [BIP340] "Specification".
    return this.curve.encodeField(this.getX());
  }

  static decodeEven(curve, bytes) {
    // [BIP340] "Specification".
    assert(curve instanceof ShortCurve);

    const x = curve.decodeField(bytes);

    if (x.cmp(curve.p) >= 0)
      throw new Error('Invalid point.');

    return curve.pointFromX(x, false);
  }

  static decodeSquare(curve, bytes) {
    // [SCHNORR] "Specification".
    assert(curve instanceof ShortCurve);

    const x = curve.decodeField(bytes);

    if (x.cmp(curve.p) >= 0)
      throw new Error('Invalid point.');

    return curve.pointFromX(x);
  }

  toJSON(pre) {
    if (this.inf)
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    if (pre === true && this.pre)
      return [x, y, this.pre.toJSON()];

    return [x, y];
  }

  toPretty() {
    if (this.inf)
      return [];

    const size = this.curve.fieldSize * 2;
    const x = toPretty(this.getX(), size);
    const y = toPretty(this.getY(), size);

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof ShortCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);
    const point = curve.point(x, y);

    if (json.length > 2 && json[2] != null)
      point.pre = Precomp.fromJSON(point, json[2]);

    return point;
  }

  [custom]() {
    if (this.inf)
      return '<ShortPoint: Infinity>';

    return '<ShortPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + '>';
  }
}

/**
 * JPoint
 */

class JPoint extends Point {
  constructor(curve, x, y, z) {
    assert(curve instanceof ShortCurve);

    super(curve, types.JACOBIAN);

    this.x = this.curve.one;
    this.y = this.curve.one;
    this.z = this.curve.zero;
    this.zOne = false;

    if (x != null)
      this._init(x, y, z);
  }

  _init(x, y, z) {
    assert(x instanceof BN);
    assert(y instanceof BN);
    assert(z == null || (z instanceof BN));

    this.x = x;
    this.y = y;
    this.z = z || this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one);
  }

  clone() {
    return this.curve.jpoint(this.x, this.y, this.z);
  }

  validate() {
    // [GECC] Example 3.20, Page 88, Section 3.
    const {a, b} = this.curve;

    // P = O
    if (this.isInfinity())
      return true;

    // Z1 = 1
    if (this.zOne)
      return this.curve.validate(this.toP());

    // y^2 = x^3 + a * x * z^4 + b * z^6
    const lhs = this.y.redSqr();
    const x3 = this.x.redSqr().redMul(this.x);
    const z2 = this.z.redSqr();
    const z4 = z2.redSqr();
    const z6 = z4.redMul(z2);
    const rhs = x3.redIAdd(b.redMul(z6));

    if (!this.curve.zeroA) {
      // Save some cycles for a = -3.
      if (this.curve.threeA)
        rhs.redIAdd(z4.redIMuln(-3).redMul(this.x));
      else
        rhs.redIAdd(a.redMul(z4).redMul(this.x));
    }

    return lhs.eq(rhs);
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
    // 1I + 3M + 1S

    // Z = 1
    if (this.zOne)
      return this;

    // P = O
    if (this.isInfinity())
      return this;

    // A = 1 / Z1
    const a = this.z.redInvert();

    // AA = A^2
    const aa = a.redSqr();

    // X3 = X1 * AA
    this.x = this.x.redMul(aa);

    // Y3 = Y1 * AA * A
    this.y = this.y.redMul(aa).redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = true;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // P = O
    if (this.isInfinity())
      return this.curve.jpoint();

    // AA = A^2
    const aa = a.redSqr();

    // X3 = X1 * AA
    const nx = this.x.redMul(aa);

    // Y3 = Y1 * AA * A
    const ny = this.y.redMul(aa).redMul(a);

    // Z3 = Z1 * A
    const nz = this.z.redMul(a);

    return this.curve.jpoint(nx, ny, nz);
  }

  neg() {
    // -(X1, Y1, Z1) = (X1, -Y1, Z1)
    return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
  }

  add(p) {
    assert(p instanceof Point);

    if (p.type === types.AFFINE)
      return this._mixedAdd(p);

    return this._add(p);
  }

  _add(p) {
    assert(p instanceof JPoint);

    // O + P = P
    if (this.isInfinity())
      return p;

    // P + O = P
    if (p.isInfinity())
      return this;

    // Z1 = 1
    if (this.zOne)
      return p._addJA(this);

    // Z2 = 1
    if (p.zOne)
      return this._addJA(p);

    return this._addJJ(p);
  }

  _mixedAdd(p) {
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.isInfinity())
      return p.toJ();

    // P + O = P
    if (p.isInfinity())
      return this;

    return this._addJA(p);
  }

  _addJJ(p) {
    // No assumptions.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
    // 12M + 4S + 6A + 1*2 (implemented as: 12M + 4S + 7A)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // Z2Z2 = Z2^2
    const z2z2 = p.z.redSqr();

    // U1 = X1 * Z2Z2
    const u1 = this.x.redMul(z2z2);

    // U2 = X2 * Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S1 = Y1 * Z2 * Z2Z2
    const s1 = this.y.redMul(p.z).redMul(z2z2);

    // S2 = Y2 * Z1 * Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2 - U1
    const h = u2.redISub(u1);

    // r = S2 - S1
    const r = s2.redISub(s1);

    // H = 0
    if (h.isZero()) {
      if (!r.isZero())
        return this.curve.jpoint();

      return this.dbl();
    }

    // HH = H^2
    const hh = h.redSqr();

    // HHH = H * HH
    const hhh = h.redMul(hh);

    // V = U1 * HH
    const v = u1.redMul(hh);

    // X3 = r^2 - HHH - 2 * V
    const nx = r.redSqr().redISub(hhh).redISub(v).redISub(v);

    // Y3 = r * (V - X3) - S1 * HHH
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(hhh));

    // Z3 = Z1 * Z2 * H
    const nz = this.z.redMul(p.z).redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  }

  _addJA(p) {
    // Assumes Z2 = 1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd
    // 8M + 3S + 6A + 5*2 (implemented as: 8M + 3S + 7A + 4*2)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // U2 = X2 * Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S2 = Y2 * Z1 * Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2 - X1
    const h = u2.redISub(this.x);

    // r = 2 * (S2 - Y1)
    const r = s2.redISub(this.y).redIMuln(2);

    // H = 0
    if (h.isZero()) {
      if (!r.isZero())
        return this.curve.jpoint();

      return this.dbl();
    }

    // I = (2 * H)^2
    const i = h.redMuln(2).redSqr();

    // J = H * I
    const j = h.redMul(i);

    // V = X1 * I
    const v = this.x.redMul(i);

    // X3 = r^2 - J - 2 * V
    const nx = r.redSqr().redISub(j).redISub(v).redISub(v);

    // Y3 = r * (V - X3) - 2 * Y1 * J
    const ny = r.redMul(v.redISub(nx)).redISub(this.y.redMul(j).redIMuln(2));

    // Z3 = 2 * Z1 * H
    const nz = this.z.redMul(h).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  dbl() {
    // P = O
    if (this.isInfinity())
      return this;

    // Y1 = 0
    if (this.y.isZero())
      return this.curve.jpoint();

    // a = 0
    if (this.curve.zeroA)
      return this._dbl0();

    // a = -3
    if (this.curve.threeA)
      return this._dbl3();

    return this._dblJ();
  }

  _dblJ() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
    // 3M + 6S + 4A + 1*a + 2*2 + 1*3 + 1*4 + 1*8
    // (implemented as: 3M + 6S + 5A + 1*a + 1*2 + 1*3 + 1*4 + 1*8)

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // S = 4 * X1 * YY
    const s = this.x.redMul(yy).redIMuln(4);

    // M = 3 * XX + a * ZZ^2
    const m = xx.redIMuln(3).redIAdd(this.curve.a.redMul(zz.redSqr()));

    // T = M^2 - 2 * S
    const t = m.redSqr().redISub(s).redISub(s);

    // X3 = T
    const nx = t;

    // Y3 = M * (S - T) - 8 * YY^2
    const ny = m.redMul(s.redISub(t)).redISub(yy.redSqr().redIMuln(8));

    // Z3 = 2 * Y1 * Z1
    const nz = this.y.redMul(this.z).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _dbl0() {
    // Assumes a = 0.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    // 2M + 5S + 6A + 3*2 + 1*3 + 1*8
    // (implemented as: 2M + 5S + 7A + 2*2 + 1*3 + 1*8)

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = B^2
    const c = b.redSqr();

    // + XB2 = (X1 + B)^2
    const xb2 = b.redIAdd(this.x).redSqr();

    // D = 2 * ((X1 + B)^2 - A - C)
    const d = xb2.redISub(a).redISub(c).redIMuln(2);

    // E = 3 * A
    const e = a.redIMuln(3);

    // F = E^2
    const f = e.redSqr();

    // X3 = F - 2 * D
    const nx = f.redISub(d).redISub(d);

    // Y3 = E * (D - X3) - 8 * C
    const ny = e.redMul(d.redISub(nx)).redISub(c.redIMuln(8));

    // Z3 = 2 * Y1 * Z1
    const nz = this.y.redMul(this.z).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _dbl3() {
    // Assumes a = -3.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    // 3M + 5S + 8A + 1*3 + 1*4 + 2*8
    // (implemented as: 3M + 5S + 8A + 1*2 + 1*3 + 1*4 + 1*8)

    // delta = Z1^2
    const delta = this.z.redSqr();

    // gamma = Y1^2
    const gamma = this.y.redSqr();

    // beta = X1 * gamma
    const beta = this.x.redMul(gamma);

    // + xmdelta = X1 - delta
    const xmdelta = this.x.redSub(delta);

    // + xpdelta = X1 + delta
    const xpdelta = this.x.redAdd(delta);

    // alpha = 3 * (X1 - delta) * (X1 + delta)
    const alpha = xmdelta.redMul(xpdelta).redIMuln(3);

    // + beta4 = 4 * beta
    const beta4 = beta.redIMuln(4);

    // + beta8 = 2 * beta4
    const beta8 = beta4.redMuln(2);

    // + gamma28 = 8 * gamma^2
    const gamma28 = gamma.redSqr().redIMuln(8);

    // X3 = alpha^2 - 8 * beta
    const nx = alpha.redSqr().redISub(beta8);

    // Z3 = (Y1 + Z1)^2 - gamma - delta
    const nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);

    // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
    const ny = alpha.redMul(beta4.redISub(nx)).redISub(gamma28);

    return this.curve.jpoint(nx, ny, nz);
  }

  getX() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  getY() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.y.fromRed();
  }

  eq(p) {
    assert(p instanceof JPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.isInfinity())
      return p.isInfinity();

    // Q = O
    if (p.isInfinity())
      return false;

    // Z1 = Z2
    if (this.z.eq(p.z)) {
      return this.x.eq(p.x)
          && this.y.eq(p.y);
    }

    // X1 * Z2^2 = X2 * Z1^2
    const zz1 = this.z.redSqr();
    const zz2 = p.z.redSqr();
    const x1 = this.x.redMul(zz2);
    const x2 = p.x.redMul(zz1);

    if (!x1.eq(x2))
      return false;

    // Y1 * Z2^3 = Y2 * Z1^3
    const zzz1 = zz1.redMul(this.z);
    const zzz2 = zz2.redMul(p.z);
    const y1 = this.y.redMul(zzz2);
    const y2 = p.y.redMul(zzz1);

    return y1.eq(y2);
  }

  cmp(point) {
    assert(point instanceof JPoint);

    const inf1 = this.isInfinity();
    const inf2 = point.isInfinity();

    if (inf1 && !inf2)
      return -1;

    if (!inf1 && inf2)
      return 1;

    if (inf1 && inf2)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX())
        || this.getY().cmp(point.getY());
  }

  isInfinity() {
    // Z1 = 0
    return this.z.isZero();
  }

  isOrder2() {
    if (this.isInfinity())
      return false;

    return this.y.isZero();
  }

  isOdd() {
    if (this.isInfinity())
      return false;

    this.normalize();

    return this.y.redIsOdd();
  }

  isEven() {
    if (this.isInfinity())
      return false;

    this.normalize();

    return this.y.redIsEven();
  }

  isSquare() {
    if (this.isInfinity())
      return false;

    return this.y.redMul(this.z).redJacobi() !== -1;
  }

  eqX(x) {
    // Verify that integer `x` is equal to field
    // element `x` by scaling it by our z coordinate.
    // This optimization is mentioned in and used for
    // bip-schnorr[1]. This avoids having to affinize
    // the resulting point during verification.
    //
    // [1] [SCHNORR] "Optimizations".
    assert(x instanceof BN);
    assert(!x.red);

    if (this.isInfinity())
      return false;

    const zz = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zz);

    return this.x.eq(rx);
  }

  eqR(x) {
    // Similar to the optimization above, this
    // optimization, suggested by Maxwell[1],
    // compares an integer to an X coordinate
    // by scaling it.
    //
    // Since a signature's R value is modulo N
    // in ECDSA, we may be dealing with an R
    // value greater than N in actuality.
    //
    // If the equality check fails, we can
    // scale N itself by Z and add it to the
    // X field element.
    //
    // [1] https://github.com/bitcoin-core/secp256k1/commit/ce7eb6f
    assert(x instanceof BN);
    assert(!x.red);

    if (!this.curve.smallGap)
      return this.toP().eqR(x);

    if (this.isInfinity())
      return false;

    if (x.cmp(this.curve.p) >= 0)
      return false;

    const zz = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zz);

    if (this.x.eq(rx))
      return true;

    if (this.curve.highOrder)
      return false;

    if (x.cmp(this.curve.pmodn) >= 0)
      return false;

    const rn = this.curve.redN.redMul(zz);

    rx.redIAdd(rn);

    return this.x.eq(rx);
  }

  toP() {
    // P = O
    if (this.isInfinity())
      return this.curve.point();

    this.normalize();

    // (X3, Y3) = (X1 / Z1^2, Y1 / Z1^3)
    return this.curve.point(this.x, this.y);
  }

  toJ() {
    return this;
  }

  encode(compact) {
    return this.toP().encode(compact);
  }

  static decode(curve, bytes) {
    return ShortPoint.decode(curve, bytes).toJ();
  }

  encodeX() {
    return this.toP().encodeX();
  }

  static decodeEven(curve, bytes) {
    return ShortPoint.decodeEven(curve, bytes).toJ();
  }

  static decodeSquare(curve, bytes) {
    return ShortPoint.decodeSquare(curve, bytes).toJ();
  }

  toJSON(pre) {
    return this.toP().toJSON(pre);
  }

  toPretty() {
    return this.toP().toPretty();
  }

  static fromJSON(curve, json) {
    return ShortPoint.fromJSON(curve, json).toJ();
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
    super(MontPoint, 'mont', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.b = BN.fromJSON(conf.b).toRed(this.red);

    this.bi = this.b.redInvert();
    this.a2 = this.a.redAdd(this.two);
    this.a24 = this.a2.redMul(this.i4);
    this.a3 = this.a.redMul(this.i3);
    this.a0 = this.a.redMul(this.bi);
    this.b0 = this.bi.redSqr();

    this._finalize(conf);
  }

  static _isomorphism(curveA, curveB, customB) {
    // Montgomery Isomorphism.
    //
    // [MONT3] Page 3, Section 2.1.
    //
    // Transformation:
    //
    //   A' = A
    //   B' = B'
    //
    // Where (B / B') is square.
    assert(curveA instanceof BN);
    assert(curveB instanceof BN);
    assert(customB instanceof BN);

    const a = curveA.clone();
    const b = customB.clone();
    const c = curveB.redDiv(customB);

    if (c.redJacobi() !== 1)
      throw new Error('Invalid `b` coefficient.');

    return [a, b];
  }

  _short(a0, odd) {
    // Montgomery->Short Weierstrass Equivalence.
    //
    // [MONT2] "Equivalence with Weierstrass curves".
    //
    // Transformation:
    //
    //   a = (3 - A^2) / (3 * B^2)
    //   b = (2 * A^3 - 9 * A) / (27 * B^3)
    const {a, b, three} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const b2 = b.redSqr();
    const b3 = b2.redMul(b);
    const n0 = three.redSub(a2);
    const d0 = b2.redMuln(3);
    const n1 = a3.redMuln(2).redISub(a.redMuln(9));
    const d1 = b3.redMuln(27);
    const wa = n0.redDiv(d0);
    const wb = n1.redDiv(d1);

    if (a0 != null)
      return ShortCurve._isomorphism(wa, wb, a0, odd);

    return [wa, wb];
  }

  _mont(b0) {
    return MontCurve._isomorphism(this.a, this.b, b0);
  }

  _edwards(a0, invert = false) {
    // Montgomery->Twisted Edwards Transformation.
    //
    // [MONT1] Page 11, Section 4.3.5.
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    //
    // Equivalence:
    //
    //   a = (A + 2) / B
    //   d = (A - 2) / B
    //
    // Isomorphism:
    //
    //   a = a'
    //   d = a' * (A - 2) / (A + 2)
    //
    // Where ((A + 2) / (B * a')) is square.
    //
    // If `d` is square, we can usually find
    // a complete curve by using the `invert`
    // option. This will create an isomorphism
    // chain of: M(A,B)->E(a,d)->E(d,a).
    //
    // The equivalence between E(a,d) and
    // E(d,a) is:
    //
    //   (x, y) = (x, 1 / y)
    //
    // Meaning our map to E(d,a) is:
    //
    //   x = u / v
    //   y = 1 / ((u - 1) / (u + 1))
    //     = (u + 1) / (u - 1)
    assert(typeof invert === 'boolean');

    const {two, bi} = this;
    const a = this.a.redAdd(two).redMul(bi);
    const d = this.a.redSub(two).redMul(bi);

    if (invert)
      a.swap(d);

    if (a0 != null)
      return EdwardsCurve._isomorphism(a, d, a0);

    return [a, d];
  }

  _scaleShort(curve) {
    assert(curve instanceof ShortCurve);

    const [u2, u3] = curve._scale(this);

    return [this.field(u2.redInvert()),
            this.field(u3.redInvert())];
  }

  _scaleMont(curve) {
    // We can extract the isomorphism factor with:
    //
    //   c = +-sqrt(B / B')
    //
    // If base points are available, we can do:
    //
    //   c = v' / v
    assert(curve instanceof MontCurve);

    if (this.g.isInfinity() || curve.g.isInfinity())
      return this.field(curve.b).redDivSqrt(this.b);

    return this.g.y.redDiv(this.field(curve.g.y));
  }

  _scaleEdwards(curve, invert) {
    // We _could_ do something like:
    //
    //   B = 4 / (a - d)
    //   c = +-sqrt(B / B')
    //
    // Which can be reduced to:
    //
    //   c = +-sqrt(4 / ((a - d) * B'))
    //
    // If base points are available:
    //
    //   v = u' / x
    //   c = v' / v
    //
    // Which can be reduced to:
    //
    //   c = v' * x / u'
    //
    // However, the way our maps are
    // written, we can re-use the Edwards
    // isomorphism factor when going the
    // other direction.
    assert(curve instanceof EdwardsCurve);

    const c = curve._scale(this, invert);

    return this.field(c);
  }

  _solveY0(x) {
    assert(x instanceof BN);

    // y^2 = x^3 + A * x^2 + B * x
    const a = this.a0;
    const b = this.b0;
    const x2 = x.redSqr();
    const x3 = x2.redMul(x);
    const y2 = x3.redIAdd(a.redMul(x2)).redIAdd(b.redMul(x));

    return y2;
  }

  _elligator2(u) {
    // Elligator 2.
    //
    // Distribution: 1/2.
    //
    // [ELL2] Page 11, Section 5.2.
    // [H2EC] "Elligator 2 Method".
    //        "Mappings for Montgomery curves".
    // [SAFE] "Indistinguishability from uniform random strings".
    //
    // Assumptions:
    //
    //   - y^2 = x^3 + A * x^2 + B * x.
    //   - A != 0, B != 0.
    //   - A^2 - 4 * B is non-zero and non-square in F(p).
    //   - Let z be a non-square in F(p).
    //   - u != +-sqrt(-1 / z).
    //
    // Note that Elligator 2 is defined over the form:
    //
    //   y'^2 = x'^3 + A' * x'^2 + B' * x'
    //
    // Instead of:
    //
    //   B * y^2 = x^3 + A * x^2 + x
    //
    // Where:
    //
    //   A' = A / B
    //   B' = 1 / B^2
    //   x' = x / B
    //   y' = y / B
    //
    // And:
    //
    //   x = B * x'
    //   y = B * y'
    //
    // This is presumably the result of Elligator 2
    // being designed in long Weierstrass form. If
    // we want to support B != 1, we need to do the
    // conversion.
    //
    // Map:
    //
    //   g(x) = x^3 + A * x^2 + B * x
    //   x1 = -A / (1 + z * u^2)
    //   x1 = -A, if x1 = 0
    //   x2 = -x1 - A
    //   x = x1, if g(x1) is square
    //     = x2, otherwise
    //   y = sign(u) * abs(sqrt(g(x)))
    const lhs = this.a0.redNeg();
    const rhs = this.one.redAdd(this.z.redMul(u.redSqr()));

    if (rhs.isZero())
      rhs.inject(this.one);

    const x1 = lhs.redMul(rhs.redInvert());
    const x2 = x1.redNeg().redISub(this.a0);
    const y1 = this._solveY0(x1);
    const y2 = this._solveY0(x2);
    const alpha = y1.redIsSquare() | 0;
    const x0 = [x1, x2][alpha ^ 1];
    const y0 = [y1, y2][alpha ^ 1].redSqrt();

    if (y0.redIsOdd() !== u.redIsOdd())
      y0.redINeg();

    const x = this.b.redMul(x0);
    const y = this.b.redMul(y0);

    return this.point(x, y);
  }

  _invert2(p, hint) {
    // Inverting the Map (Elligator 2).
    //
    // [ELL2] Page 12, Section 5.3.
    //
    // Assumptions:
    //
    //   - -z * x * (x + A) is square in F(p).
    //   - If r = 1 then x != 0.
    //   - If r = 2 then x != -A.
    //
    // Map:
    //
    //   u1 = -(x + A) / (x * z)
    //   u2 = -x / ((x + A) * z)
    //   r = random integer in [1,2]
    //   u = sign(y) * abs(sqrt(ur))
    //
    // Note that `0 / 0` can only occur if A = 0
    // (this violates the assumptions of Elligator 2).
    const {x, y} = p;
    const r = hint & 1;
    const x0 = x.redMul(this.bi);
    const y0 = y.redMul(this.bi);
    const n = x0.redAdd(this.a0);
    const d = x0;
    const lhs = [n, d][r].redINeg();
    const rhs = [d, n][r].redMul(this.z);
    const u = lhs.redDivSqrt(rhs);

    if (u.redIsOdd() !== y0.redIsOdd())
      u.redINeg();

    return u;
  }

  isElliptic() {
    const a2 = this.a.redSqr();
    const d = this.b.redMul(a2.redSub(this.four));

    // B * (A^2 - 4) != 0
    return !d.isZero();
  }

  jinv() {
    // [MONT3] Page 3, Section 2.
    const {a, three, four} = this;
    const a2 = a.redSqr();
    const t0 = a2.redSub(three);
    const lhs = t0.redPown(3).redIMuln(256);
    const rhs = a2.redSub(four);

    if (rhs.isZero())
      throw new Error('Curve is not elliptic.');

    // (256 * (A^2 - 3)^3) / (A^2 - 4)
    return lhs.redDiv(rhs).fromRed();
  }

  point(x, y) {
    return new MontPoint(this, x, y);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  xpoint(x, z) {
    return new XPoint(this, x, z);
  }

  solveY2(x) {
    // [MONT3] Page 3, Section 2.
    // https://hyperelliptic.org/EFD/g1p/auto-montgom.html
    assert(x instanceof BN);

    // B * y^2 = x^3 + A * x^2 + x
    const x2 = x.redSqr();
    const x3 = x2.redMul(x);
    const by2 = x3.redIAdd(this.a.redMul(x2)).redIAdd(x);
    const y2 = by2.redMul(this.bi);

    return y2;
  }

  validate(point) {
    assert(point instanceof MontPoint);

    if (point.isInfinity())
      return true;

    const {x, y} = point;
    const y2 = this.solveY2(x);

    return y.redSqr().eq(y2);
  }

  pointFromX(x, sign = null) {
    assert(x instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!x.red)
      x = x.toRed(this.red);

    const y = this.solveY(x);

    if (sign != null) {
      if (y.isZero() && sign)
        throw new Error('Invalid point.');

      if (y.redIsOdd() !== sign)
        y.redINeg();
    }

    return this.point(x, y);
  }

  isIsomorphic(curve, invert) {
    // [MONT3] Page 3, Section 2.1.
    assert(curve instanceof Curve);

    if (!curve.p.eq(this.p))
      return false;

    // M(A,B) <-> M(A,B')
    if (curve.type === 'mont') {
      const a = this.field(curve.a);
      const b = this.field(curve.b);

      // A' = A
      if (!this.a.eq(a))
        return false;

      // B' != 0
      if (this.b.isZero())
        return false;

      // jacobi(B / B') = 1
      const c = b.redDiv(this.b);

      return c.redJacobi() === 1;
    }

    return curve.isIsomorphic(this, invert);
  }

  isIsogenous(curve) {
    assert(curve instanceof Curve);

    if (curve.type === 'mont')
      return false;

    return curve.isIsogenous(this);
  }

  pointFromShort(point) {
    // [ALT] Appendix E.2 (Switching between Alternative Representations).
    // [MONT2] "Equivalence with Weierstrass curves"
    assert(point instanceof ShortPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for E(a,b)->M(A,B):
      //
      //   u = B * x - A / 3
      //   v = B * y
      //
      // Undefined if ((u^3 + A * u^2 + u) / B) is not square.
      if (point.isInfinity())
        return this.point();

      const {a3, b} = this;
      const [u2, u3] = this._scale(point.curve);
      const x = this.field(point.x).redMul(u2);
      const y = this.field(point.y).redMul(u3);
      const u = b.redMul(x).redISub(a3);
      const v = b.redMul(y);

      return this.point(u, v);
    }

    throw new Error('Not implemented.');
  }

  pointFromMont(point) {
    // [MONT3] Page 3, Section 2.1.
    assert(point instanceof MontPoint);

    if (this.isIsomorphic(point.curve)) {
      // Isomorphic maps for M(A,B)<->M(A,B'):
      //
      //   u' = u
      //   v' = +-sqrt(B / B') * v
      //
      // Undefined if (B / B') is not square.
      if (point.isInfinity())
        return this.point();

      const c = this._scale(point.curve);
      const u = this.field(point.x);
      const v = this.field(point.y);
      const nu = u;
      const nv = c.redMul(v);

      return this.point(nu, nv);
    }

    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    // [RFC7748] Section 4.1 & 4.2.
    // [MONT3] Page 6, Section 2.5.
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    assert(point instanceof EdwardsPoint);
    assert(point.curve.p.eq(this.p));

    // Edwards `x`, `y`, `z`.
    const x = this.field(point.x);
    const y = this.field(point.y);
    const z = this.field(point.z);

    if (this.isIsogenous(point.curve)) {
      // 4-isogeny maps for E(1,d)->M(2-4d,1):
      //
      //   u = y^2 / x^2
      //   v = (2 - x^2 - y^2) * y / x^3
      //
      // Undefined for x = 0.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> (0, 0)
      //
      // Unexceptional Cases:
      //   - (+-1, 0) -> (0, 0)
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.zero);

      const c = z.redSqr().redIMuln(2);
      const uu = y.redSqr();
      const uz = x.redSqr();
      const vv = c.redISub(uz).redISub(uu).redMul(y);
      const vz = uz.redMul(x);

      return this.cpoint(uu, uz, vv, vz);
    }

    if (this.isIsomorphic(point.curve, true)) {
      // Isomorphic maps for E(d,a)->M(A,B):
      //
      //   u = (y + 1) / (y - 1)
      //   v = +-sqrt((A - 2) / (B * a)) * u / x
      //
      // Undefined for x = 0 or y = 1.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> (0, 0)
      //
      // Unexceptional Cases:
      //   - (+-sqrt(1 / a), 0) -> (-1, +-sqrt((A - 2) / B))
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.zero);

      const c = this._scale(point.curve, true);
      const uu = y.redAdd(z);
      const uz = y.redSub(z);
      const vv = c.redMul(z).redMul(uu);
      const vz = x.redMul(uz);

      return this.cpoint(uu, uz, vv, vz);
    }

    if (this.isIsomorphic(point.curve, false)) {
      // Isomorphic maps for E(a,d)->M(A,B):
      //
      //   u = (1 + y) / (1 - y)
      //   v = +-sqrt((A + 2) / (B * a)) * u / x
      //
      // Undefined for x = 0 or y = 1.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> (0, 0)
      //
      // Unexceptional Cases:
      //   - (+-sqrt(1 / a), 0) -> (1, +-sqrt((A + 2) / B))
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.zero);

      const c = this._scale(point.curve, false);
      const uu = z.redAdd(y);
      const uz = z.redSub(y);
      const vv = c.redMul(z).redMul(uu);
      const vz = x.redMul(uz);

      return this.cpoint(uu, uz, vv, vz);
    }

    throw new Error('Not implemented.');
  }

  pointFromUniform(u) {
    assert(u instanceof BN);

    // z = 0 or A = 0
    if (this.z.isZero() || this.a.isZero())
      throw new Error('Not implemented.');

    return this._elligator2(u);
  }

  pointToUniform(p, hint) {
    // Convert a montgomery point to a field
    // element by inverting the elligator2 map.
    //
    // Hint Layout:
    //
    //   [00000000] [0000] [0000]
    //        |        |      |
    //        |        |      +-- preimage index
    //        |        +--- subgroup
    //        +-- bits to OR with uniform bytes
    assert(p instanceof MontPoint);
    assert((hint >>> 0) === hint);

    // z = 0 or A = 0
    if (this.z.isZero() || this.a.isZero())
      throw new Error('Not implemented.');

    // P = O
    if (p.isInfinity())
      throw new Error('Invalid point.');

    // Add a random torsion component.
    const i = ((hint >>> 4) & 15) % this.torsion.length;
    const q = p.add(this.torsion[i]);

    return wrapErrors(() => {
      return this._invert2(q, hint);
    });
  }

  decodePoint(bytes, sign) {
    return MontPoint.decode(this, bytes, sign);
  }

  encodeX(point) {
    assert(point instanceof XPoint);
    return point.encode();
  }

  decodeX(bytes) {
    return XPoint.decode(this, bytes);
  }

  toShort(a0, odd, sign = null) {
    const [a, b] = this._short(a0, odd);

    const curve = new ShortCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = curve._scale(this);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromMont(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromMont(this.torsion[i]);

    return curve;
  }

  toMont(b0, sign = null) {
    const [a, b] = this._mont(b0);

    const curve = new MontCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = curve._scale(this);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromMont(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromMont(this.torsion[i]);

    return curve;
  }

  toEdwards(a0, invert, sign = null) {
    const [a, d] = this._edwards(a0, invert);

    const curve = new EdwardsCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      d: d,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = curve._scale(this, invert);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity()) {
      curve.g = curve.pointFromMont(this.g);
      curve.g.normalize();
    }

    if (curve.isComplete()) {
      for (let i = 0; i < this.h.word(0); i++) {
        curve.torsion[i] = curve.pointFromMont(this.torsion[i]);
        curve.torsion[i].normalize();
      }
    }

    return curve;
  }

  pointFromJSON(json) {
    return MontPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);
    json.a = this.a.fromRed().toJSON();
    json.b = this.b.fromRed().toJSON();
    return json;
  }
}

/**
 * MontPoint
 */

class MontPoint extends Point {
  constructor(curve, x, y) {
    assert(curve instanceof MontCurve);

    super(curve, types.AFFINE);

    this.x = this.curve.zero;
    this.y = this.curve.zero;
    this.inf = true;

    if (x != null)
      this._init(x, y);
  }

  _init(x, y) {
    assert(x instanceof BN);
    assert(y instanceof BN);

    this.x = x;
    this.y = y;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    this.inf = false;
  }

  clone() {
    if (this.inf)
      return this.curve.point();

    return this.curve.point(this.x, this.y);
  }

  scale(a) {
    return this.clone();
  }

  randomize(rng) {
    return this.clone();
  }

  neg() {
    // P = O
    if (this.inf)
      return this;

    // -(X1, Y1) = (X1, -Y1)
    return this.curve.point(this.x, this.y.redNeg());
  }

  add(p) {
    // [MONT1] Page 8, Section 4.3.2.
    //
    // Addition Law:
    //
    //   l = (y2 - y1) / (x2 - x1)
    //   x3 = b * l^2 - a - x1 - x2
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 2M + 1S + 7A + 1*b
    assert(p instanceof MontPoint);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P, P + -P
    if (this.x.eq(p.x)) {
      // P + -P = O
      if (!this.y.eq(p.y))
        return this.curve.point();

      // P + P = 2P
      return this.dbl();
    }

    // H = X2 - X1
    const h = p.x.redSub(this.x);

    // R = Y2 - Y1
    const r = p.y.redSub(this.y);

    // L = R / H
    const l = r.redDiv(h);

    // K = b * L^2
    const k = this.curve.b.redMul(l.redSqr());

    // X3 = K - a - X1 - X2
    const nx = k.redISub(this.curve.a).redISub(this.x).redISub(p.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  dbl() {
    // [MONT1] Page 8, Section 4.3.2.
    //
    // Addition Law (doubling):
    //
    //   l = (3 * x1^2 + 2 * a * x1 + 1) / (2 * b * y1)
    //   x3 = b * l^2 - a - 2 * x1
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 3M + 2S + 7A + 1*a + 1*b + 1*b + 2*2 + 1*3

    // P = O
    if (this.inf)
      return this;

    // Y1 = 0
    if (this.y.isZero())
      return this.curve.point();

    // M1 = 3 * X1^2
    const m1 = this.x.redSqr().redIMuln(3);

    // M2 = 2 * a * X1
    const m2 = this.curve.a.redMul(this.x).redIMuln(2);

    // M = M1 + M2 + 1
    const m = m1.redIAdd(m2).redIAdd(this.curve.one);

    // Z = 2 * b * Y1
    const z = this.curve.b.redMul(this.y).redIMuln(2);

    // L = M / Z
    const l = m.redDiv(z);

    // K = b * L^2
    const k = this.curve.b.redMul(l.redSqr());

    // X3 = K - a - 2 * X1
    const nx = k.redISub(this.curve.a).redISub(this.x).redISub(this.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

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

  eq(p) {
    assert(p instanceof MontPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.inf)
      return p.inf;

    // Q = O
    if (p.inf)
      return false;

    // X1 = X2, Y1 = Y2
    return this.x.eq(p.x)
        && this.y.eq(p.y);
  }

  cmp(point) {
    assert(point instanceof MontPoint);

    if (this.inf && !point.inf)
      return -1;

    if (!this.inf && point.inf)
      return 1;

    if (this.inf && point.inf)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX())
        || this.getY().cmp(point.getY());
  }

  isInfinity() {
    // Infinity cannot be represented in
    // the affine space, except by a flag.
    return this.inf;
  }

  isOrder2() {
    if (this.inf)
      return false;

    return this.y.isZero();
  }

  isOdd() {
    if (this.inf)
      return false;

    return this.y.redIsOdd();
  }

  isEven() {
    if (this.inf)
      return false;

    return this.y.redIsEven();
  }

  toP() {
    return this;
  }

  toJ() {
    return this;
  }

  toX() {
    // (X3, Z3) = (1, 0)
    if (this.inf)
      return this.curve.xpoint();

    // (X3, Z3) = (X1, 1)
    return this.curve.xpoint(this.x, this.curve.one);
  }

  encode() {
    return this.toX().encode();
  }

  static decode(curve, bytes, sign) {
    assert(curve instanceof MontCurve);
    return curve.decodeX(bytes).toP(sign);
  }

  toJSON(pre) {
    if (this.inf)
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    return [x, y];
  }

  toPretty() {
    if (this.inf)
      return [];

    const size = this.curve.fieldSize * 2;
    const x = toPretty(this.getX(), size);
    const y = toPretty(this.getY(), size);

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof MontCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);

    return curve.point(x, y);
  }

  [custom]() {
    if (this.inf)
      return '<MontPoint: Infinity>';

    return '<MontPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + '>';
  }
}

/**
 * XPoint
 */

class XPoint extends Point {
  constructor(curve, x, z) {
    assert(curve instanceof MontCurve);

    super(curve, types.PROJECTIVE);

    this.x = this.curve.one;
    this.z = this.curve.zero;

    if (x != null)
      this._init(x, z);
  }

  _init(x, z) {
    assert(x instanceof BN);
    assert(z == null || (z instanceof BN));

    this.x = x;
    this.z = z || this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
  }

  clone() {
    return this.curve.xpoint(this.x, this.z);
  }

  precompute(power, rng) {
    // No-op.
    return this;
  }

  validate() {
    if (this.isInfinity())
      return true;

    // B * y^2 * z = x^3 + A * x^2 * z + x * z^2
    const {x, z} = this;
    const x2 = x.redSqr();
    const x3 = x2.redMul(x);
    const z2 = z.redSqr();
    const ax2 = this.curve.a.redMul(x2).redMul(z);
    const by2 = x3.redIAdd(ax2).redIAdd(x.redMul(z2));
    const y2 = by2.redMul(this.curve.bi);

    // sqrt(y^2 * z^4) = y * z^2
    return y2.redMul(z).redJacobi() !== -1;
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#scaling-scale
    // 1I + 1M

    // P = O
    if (this.isInfinity())
      return this;

    // Z1 = 1
    if (this.z.eq(this.curve.one))
      return this;

    // X3 = X1 / Z1
    this.x = this.x.redDiv(this.z);

    // Z3 = 1
    this.z = this.curve.one;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // P = O
    if (this.isInfinity())
      return this.curve.xpoint();

    // X3 = X1 * A
    const nx = this.x.redMul(a);

    // Y3 = Y1 * A
    const nz = this.z.redMul(a);

    return this.curve.xpoint(nx, nz);
  }

  neg() {
    // -(X1, Z1) = (X1, Z1)
    return this;
  }

  dbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
    // 2M + 2S + 4A + 1*a24

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

    // Z3 = C * (BB + a24 * C)
    const nz = c.redMul(bb.redIAdd(this.curve.a24.redMul(c)));

    return this.curve.xpoint(nx, nz);
  }

  diffAddDbl(p2, p3) {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#ladder-ladd-1987-m-3
    // 6M + 4S + 8A + 1*a24
    assert(p2 instanceof XPoint);
    assert(p3 instanceof XPoint);

    // A = X2 + Z2
    const a = p2.x.redAdd(p2.z);

    // AA = A^2
    const aa = a.redSqr();

    // B = X2 - Z2
    const b = p2.x.redSub(p2.z);

    // BB = B^2
    const bb = b.redSqr();

    // E = AA - BB
    const e = aa.redSub(bb);

    // C = X3 + Z3
    const c = p3.x.redAdd(p3.z);

    // D = X3 - Z3
    const d = p3.x.redSub(p3.z);

    // DA = D * A
    const da = d.redMul(a);

    // CB = C * B
    const cb = c.redMul(b);

    // X5 = Z1 * (DA + CB)^2
    const x5 = this.z.redMul(da.redAdd(cb).redSqr());

    // Z5 = X1 * (DA - CB)^2
    const z5 = this.x.redMul(da.redISub(cb).redSqr());

    // X4 = AA * BB
    const x4 = aa.redMul(bb);

    // Z4 = E * (BB + a24 * E)
    const z4 = e.redMul(bb.redIAdd(this.curve.a24.redMul(e)));

    return [
      this.curve.xpoint(x4, z4),
      this.curve.xpoint(x5, z5)
    ];
  }

  getX() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  getY(sign) {
    return this.toP(sign).getY();
  }

  eq(p) {
    assert(p instanceof XPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.isInfinity())
      return p.isInfinity();

    // Q = O
    if (p.isInfinity())
      return false;

    // Z1 = Z2
    if (this.z.eq(p.z))
      return this.x.eq(p.x);

    // X1 * Z2 = X2 * Z1
    const x1 = this.x.redMul(p.z);
    const x2 = p.x.redMul(this.z);

    return x1.eq(x2);
  }

  cmp(point) {
    assert(point instanceof XPoint);

    const inf1 = this.isInfinity();
    const inf2 = point.isInfinity();

    if (inf1 && !inf2)
      return -1;

    if (!inf1 && inf2)
      return 1;

    if (inf1 && inf2)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX());
  }

  isInfinity() {
    // Z1 = 0
    return this.z.isZero();
  }

  isOrder2() {
    if (this.isInfinity())
      return false;

    return this.x.isZero();
  }

  isOdd() {
    return false;
  }

  isEven() {
    return false;
  }

  hasTorsion() {
    if (this.isInfinity())
      return false;

    // X1 = 0, Z1 != 0 (edge case)
    if (this.x.isZero())
      return true;

    return super.hasTorsion();
  }

  order() {
    try {
      return this.toP().order();
    } catch (e) {
      return new BN(1);
    }
  }

  jmul(k) {
    // Multiply with the Montgomery Ladder.
    //
    // [MONT3] Algorithm 4, Page 12, Section 4.2.
    //
    // Note that any clamping is meant to
    // be done _outside_ of this function.
    assert(k instanceof BN);
    assert(!k.red);

    const bits = k.bitLength();

    let a = this.curve.xpoint();
    let b = this;

    for (let i = bits - 1; i >= 0; i--) {
      const bit = k.bit(i);

      if (bit === 0)
        [a, b] = this.diffAddDbl(a, b);
      else
        [b, a] = this.diffAddDbl(b, a);
    }

    return a;
  }

  jmulBlind(k, rng) {
    if (!rng)
      return this.jmul(k);

    // Randomize if available.
    return this.randomize(rng).jmul(k);
  }

  jmulAdd(k1, p2, k2) {
    throw new Error('Not implemented.');
  }

  toP(sign = null) {
    assert(sign == null || typeof sign === 'boolean');

    if (this.isInfinity())
      return this.curve.point();

    this.normalize();

    return this.curve.pointFromX(this.x, sign);
  }

  toJ() {
    return this;
  }

  toX() {
    return this;
  }

  key() {
    if (this.isInfinity())
      return `${this.curve.uid}:oo`;

    this.normalize();

    const x = this.getX().toString(16);

    return `${this.curve.uid}:${x}`;
  }

  encode() {
    // [RFC7748] Section 5.
    return this.curve.encodeField(this.getX());
  }

  static decode(curve, bytes) {
    assert(curve instanceof MontCurve);

    // [RFC7748] Section 5.
    const x = curve.decodeField(bytes);

    // We're supposed to ignore the hi bit
    // on montgomery points... I think. If
    // we don't, the X25519 test vectors
    // break, which is pretty convincing
    // evidence. This is a no-op for X448.
    x.iumaskn(curve.fieldBits);

    // Note: montgomery points are meant to be
    // reduced by the prime and do not have to
    // be explicitly validated in order to do
    // the montgomery ladder.
    const p = curve.xpoint(x, curve.one);

    assert(!p.isInfinity());

    return p;
  }

  toJSON(pre) {
    return this.toP().toJSON(pre);
  }

  toPretty() {
    return this.toP().toPretty();
  }

  static fromJSON(curve, json) {
    return MontPoint.fromJSON(curve, json).toX();
  }

  [custom]() {
    if (this.isInfinity())
      return '<XPoint: Infinity>';

    return '<XPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }
}

/**
 * EdwardsCurve
 */

class EdwardsCurve extends Curve {
  constructor(conf) {
    super(EdwardsPoint, 'edwards', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.d = BN.fromJSON(conf.d).toRed(this.red);
    this.s = BN.fromJSON(conf.s || '0').toRed(this.red);
    this.si = this.s.isZero() ? this.zero : this.s.redInvert();

    this.k = this.d.redMuln(2);
    this.smi = -this.d.redNeg().word(0);
    this.ad6 = this.a.redAdd(this.d).redMul(this.i6);

    this.twisted = !this.a.eq(this.one);
    this.oneA = this.a.eq(this.one);
    this.mOneA = this.a.eq(this.one.redNeg());
    this.smallD = this.prime != null && this.d.redNeg().length === 1;
    this.alt = null;

    this._finalize(conf);
  }

  static _isomorphism(curveA, curveD, customA) {
    // Twisted Edwards Isomorphism.
    //
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    //
    // Transformation:
    //
    //   a' = a'
    //   d' = a' * d / a
    //
    // Where (a / a') is square.
    assert(curveA instanceof BN);
    assert(curveD instanceof BN);
    assert(customA instanceof BN);

    const a = customA.clone();
    const d = customA.redMul(curveD).redDiv(curveA);
    const c = curveA.redDiv(customA);

    if (c.redJacobi() !== 1)
      throw new Error('Invalid `a` coefficient.');

    return [a, d];
  }

  _short(a0, odd) {
    // Twisted Edwards->Short Weierstrass Equivalence.
    //
    // [TWISTEQ] Section 2.
    //
    // Transformation:
    //
    //   a' = -(a^2 + 14 * a * d + d^2) / 48
    //   b' = (33 * (a^2 * d + a * d^2) - a^3 - d^3) / 864
    const {a, d} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const d2 = d.redSqr();
    const d3 = d2.redMul(d);
    const ad14 = a.redMul(d).redIMuln(14);
    const a2d = a2.redMul(d);
    const ad2 = a.redMul(d2);
    const t0 = a2d.redIAdd(ad2).redIMuln(33);
    const wa = a2.redAdd(ad14).redIAdd(d2).redDivn(-48);
    const wb = t0.redISub(a3).redISub(d3).redDivn(864);

    if (a0 != null)
      return ShortCurve._isomorphism(wa, wb, a0, odd);

    return [wa, wb];
  }

  _mont(b0, invert = false) {
    // Twisted Edwards->Montgomery Transformation.
    //
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    //
    // Equivalence:
    //
    //   A = 2 * (a + d) / (a - d)
    //   B = 4 / (a - d)
    //
    // Isomorphism:
    //
    //   A = 2 * (a + d) / (a - d)
    //   B = B'
    //
    // Where ((4 / (a - d)) / B') is square.
    //
    // If `4 / (a - d)` is non-square, we can
    // usually force B=1 by using the `invert`
    // option. This will create an isomorphism
    // chain of: E(a,d)->E(d,a)->M(-A,-B).
    //
    // The equivalence between E(a,d) and E(d,a)
    // is:
    //
    //   (x, y) = (x, 1 / y)
    //
    // Meaning our map to M(-A,-B) is:
    //
    //   u = (1 + 1 / y) / (1 - 1 / y)
    //     = (y + 1) / (y - 1)
    //   v = u / x
    assert(typeof invert === 'boolean');

    let apd, amd;

    if (invert) {
      apd = this.d.redAdd(this.a);
      amd = this.d.redSub(this.a);
    } else {
      apd = this.a.redAdd(this.d);
      amd = this.a.redSub(this.d);
    }

    const z = amd.redInvert();
    const a = apd.redMuln(2).redMul(z);
    const b = z.redMuln(4);

    if (b0 != null)
      return MontCurve._isomorphism(a, b, b0);

    return [a, b];
  }

  _edwards(a0) {
    return EdwardsCurve._isomorphism(this.a, this.d, a0);
  }

  _scaleShort(curve) {
    assert(curve instanceof ShortCurve);

    const [u2, u3] = curve._scale(this);

    return [this.field(u2.redInvert()),
            this.field(u3.redInvert())];
  }

  _scaleMont(curve, invert = false) {
    // Calculate isomorphism factor between
    // Twisted Edwards and Montgomery with:
    //
    //   a = (A + 2) / B
    //   c = +-sqrt(a / a')
    //
    // Which can be reduced to:
    //
    //   c = +-sqrt((A + 2) / (B * a'))
    //
    // If base points are available, we can do:
    //
    //   x = u / v
    //   c = x' / x
    //
    // Which can be reduced to:
    //
    //   c = v * x' / u
    //
    // We can now calculate the Edwards `x` with:
    //
    //   x' = c * u / v
    //
    // And likewise, the Montgomery `v`:
    //
    //   v = c * u / x'
    assert(curve instanceof MontCurve);
    assert(typeof invert === 'boolean');

    if (this.g.isInfinity() || curve.g.isInfinity()) {
      const [a] = curve._edwards(null, invert);

      return this.field(a).redDivSqrt(this.a);
    }

    const x = curve.g.x.redDiv(curve.g.y);

    return this.g.x.redDiv(this.field(x));
  }

  _scaleEdwards(curve) {
    // We can extract the isomorphism factor with:
    //
    //   c = +-sqrt(a / a')
    //
    // If base points are available, we can do:
    //
    //   c = x' / x
    assert(curve instanceof EdwardsCurve);

    if (this.g.isInfinity() || curve.g.isInfinity())
      return this.field(curve.a).redDivSqrt(this.a);

    return this.g.x.redDiv(this.field(curve.g.x));
  }

  _mulA(num) {
    assert(num instanceof BN);

    // n * a = n
    if (this.oneA)
      return num.clone();

    // n * a = -n
    if (this.mOneA)
      return num.redNeg();

    return this.a.redMul(num);
  }

  _mulD(num) {
    assert(num instanceof BN);

    // -d < 0x4000000
    if (this.smallD)
      return num.redMuln(this.smi);

    return this.d.redMul(num);
  }

  _elligator1(t) {
    // Elligator 1.
    //
    // Distribution: 1/2.
    //
    // [ELL1] Page 6, Section 3.
    //        Page 15, Appendix A.
    // [ELL2] Page 7, Section 3.2.
    //
    // Assumptions:
    //
    //   - Let p be a prime power congruent to 3 mod 4.
    //   - Let s be a nonzero element of F(p).
    //   - Let c = 2 / s^2.
    //   - Let r = c + 1 / c.
    //   - Let d = -(c + 1)^2 / (c - 1)^2.
    //   - (s^2 - 2) * (s^2 + 2) != 0.
    //   - c * (c - 1) * (c + 1) != 0.
    //   - r != 0.
    //   - d is not square.
    //   - x^2 + y^2 = 1 + d * x^2 * y^2.
    //   - u * v * X * Y * x * (Y + 1) != 0.
    //   - Y^2 = X^5 + (r^2 - 2) * X^3 + X.
    //
    // Elligator 1, as devised by Fouque et al,
    // takes place on the hyperelliptic curve of:
    //
    //   y^2 = x^5 + (r^2 - 2) * x^3 + x
    //
    // Not only must our Edwards curve be complete,
    // with a prime congruent to 3 mod 4, and a = 1,
    // our curve must be isomorphic to a hyperelliptic
    // curve of the above form. Roughly one half of
    // all Edwards curves are isomorphic to a curve
    // of said form.
    //
    // We can derive the isomorphism with:
    //
    //   c = (d +- 2 * sqrt(-d) - 1) / (d + 1)
    //   s = +-sqrt(2 / c)
    //   r = c + 1 / c
    //
    // Note that even if your curve is an Elligator 1
    // curve, Elligator 2 is probably still preferable,
    // as it has nearly the same properties (i.e. the
    // same distribution), and is much less complex.
    //
    // Map:
    //
    //   f(a) = a^((p - 1) / 2)
    //   u = (1 - t) / (1 + t)
    //   v = u^5 + (r^2 - 2) * u^3 + u
    //   X = f(v) * u
    //   Y = (f(v) * v)^((p + 1) / 4) * f(v) * f(u^2 + 1 / c^2)
    //   Y = 1, if u = 0
    //   x = (c - 1) * s * X * (1 + X) / Y
    //   y = (r * X - (1 + X)^2) / (r * X + (1 + X)^2)
    //
    // When t = +-1, we create the hyperelliptic
    // 2-torsion point of (0, 0). This needs to be
    // mapped to (0, -1) in Edwards form, but the x
    // denominator becomes zero. As far as I can
    // tell, this is the only exceptional case.
    //
    // The only other exceptional case initially
    // appears to be when the y denominator sums to
    // zero (when t = sqrt(4 / r + 1)), however, the
    // hyperelliptic `X` is negated by the sign of
    // `v`, making this impossible.
    const {s, si, i2, one, two} = this;
    const c = si.redSqr().redIMuln(2);
    const ci = s.redSqr().redMul(i2);
    const ci2 = ci.redSqr();
    const r = c.redAdd(ci);
    const r2 = r.redSqr().redISub(two);
    const cm1 = c.redSub(one);
    const uu = one.redSub(t);
    const uz = one.redAdd(t);
    const u = uz.isZero() ? uz : uu.redDiv(uz);
    const u2 = u.redSqr();
    const u3 = u2.redMul(u);
    const u5 = u3.redMul(u2);
    const v = u5.redAdd(r2.redMul(u3)).redIAdd(u);
    const f0 = this.field(v.redJacobi());
    const f1 = this.field(u2.redAdd(ci2).redJacobi());
    const f2 = f0.redMul(f1);
    const X = f0.redMul(u);
    const Y = f0.redMul(v).redSqrt().redMul(f2);
    const X1 = one.redAdd(X);
    const rX = r.redMul(X);
    const X12 = X1.redSqr();
    const xx = cm1.redMul(s).redMul(X).redMul(X1);
    const xz = u.isZero() ? this.one : Y;
    const yy = rX.redSub(X12);
    const yz = rX.redAdd(X12);

    return this.cpoint(xx, xz, yy, yz);
  }

  _invert1(p, hint) {
    // Inverting the Map (Elligator 1).
    //
    // [ELL1] Page 6, Section 3.
    //        Page 15, Appendix A.
    // [ELL2] Page 7, Section 3.3.
    //
    // Assumptions:
    //
    //   - y + 1 != 0.
    //   - (1 + n * r)^2 - 1 is square in F(p).
    //   - If n * r = -2 then x = 2 * s * (c - 1) * f(c) / r.
    //   - Y = (c - 1) * s * X * (1 + X) / x.
    //
    // Map:
    //
    //   f(a) = a^((p - 1) / 2)
    //   n = (y - 1) / (2 * (y + 1))
    //   X = -(1 + n * r) + ((1 + n * r)^2 - 1)^((p + 1) / 4)
    //   z = f((c - 1) * s * X * (1 + X) * x * (X^2 + 1 / c^2))
    //   u = z * X
    //   t = (1 - u) / (1 + u)
    const {s, si, i2, one} = this;
    const {x, y, z} = p;
    const sign = hint & 1;
    const c = si.redSqr().redIMuln(2);
    const ci = s.redSqr().redMul(i2);
    const ci2 = ci.redSqr();
    const r = c.redAdd(ci);
    const cm1 = c.redSub(one);
    const nn = y.redSub(z);
    const nz = y.redAdd(z).redIMuln(2);
    const n = nz.isZero() ? nz : nn.redDiv(nz);
    const nr1 = one.redAdd(n.redMul(r));
    const w2 = nr1.redSqr().redISub(one);
    const w = w2.redSqrt();
    const X = w.redSub(nr1);
    const X1 = one.redAdd(X);
    const YY = cm1.redMul(s).redMul(X).redMul(X1);
    const Y = YY.redMul(x.redMul(z));
    const X2 = X.redSqr().redIAdd(ci2);
    const Z = this.field(Y.redMul(X2).redJacobi());
    const u = Z.redMul(X);
    const tt = one.redSub(u);
    const tz = one.redAdd(u);
    const t = tz.isZero() ? tz : tt.redDiv(tz);

    if (t.redIsOdd() !== Boolean(sign))
      t.redINeg();

    return t;
  }

  _alt() {
    if (!this.alt)
      this.alt = this.toMont();

    return this.alt;
  }

  isElliptic() {
    const ad = this.a.redMul(this.d);
    const amd = this.a.redSub(this.d);

    // a * d * (a - d) != 0
    return !ad.redMul(amd).isZero();
  }

  jinv() {
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    const {a, d} = this;
    const ad = a.redMul(d);
    const amd4 = a.redSub(d).redPown(4);
    const a2 = a.redSqr();
    const d2 = d.redSqr();
    const t0 = a2.redAdd(ad.redMuln(14)).redIAdd(d2);
    const lhs = t0.redPown(3).redIMuln(16);
    const rhs = ad.redMul(amd4);

    if (rhs.isZero())
      throw new Error('Curve is not elliptic.');

    // 16 * (a^2 + 14 * a * d + d^2)^3 / (a * d * (a - d)^4)
    return lhs.redDiv(rhs).fromRed();
  }

  isComplete() {
    return this.a.redJacobi() === 1
        && this.d.redJacobi() === -1;
  }

  point(x, y, z, t) {
    return new EdwardsPoint(this, x, y, z, t);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  cpoint(xx, xz, yy, yz) {
    assert(xx instanceof BN);
    assert(xz instanceof BN);
    assert(yy instanceof BN);
    assert(yz instanceof BN);

    const x = xx.redMul(yz);
    const y = yy.redMul(xz);
    const z = xz.redMul(yz);
    const t = xx.redMul(yy);

    return this.point(x, y, z, t);
  }

  solveX2(y) {
    // [RFC8032] Section 5.1.3 & 5.2.3.
    assert(y instanceof BN);

    // x^2 = (y^2 - 1) / (d * y^2 - a)
    const y2 = y.redSqr();
    const rhs = this._mulD(y2).redISub(this.a);
    const lhs = y2.redISub(this.one);
    const x2 = lhs.redDiv(rhs);

    return x2;
  }

  solveX(y) {
    // Optimize with inverse square root trick.
    //
    // Note that `0 / 0` can only occur if
    // `a == d` (i.e. the curve is singular).
    const y2 = y.redSqr();
    const rhs = this._mulD(y2).redISub(this.a);
    const lhs = y2.redISub(this.one);

    return lhs.redDivSqrt(rhs);
  }

  solveY2(x) {
    assert(x instanceof BN);

    // y^2 = (a * x^2 - 1) / (d * x^2 - 1)
    const x2 = x.redSqr();
    const lhs = this._mulA(x2).redISub(this.one);
    const rhs = this._mulD(x2).redISub(this.one);
    const y2 = lhs.redDiv(rhs);

    return y2;
  }

  solveY(x) {
    // Optimize with inverse square root trick.
    //
    // Note that `0 / 0` can only occur if
    // `a == d` (i.e. the curve is singular).
    const x2 = x.redSqr();
    const lhs = this._mulA(x2).redISub(this.one);
    const rhs = this._mulD(x2).redISub(this.one);

    return lhs.redDivSqrt(rhs);
  }

  validate(point) {
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    //           Page 11, Section 6.
    assert(point instanceof EdwardsPoint);

    // Z1 = 1
    if (point.zOne) {
      // a * x^2 + y^2 = 1 + d * x^2 * y^2
      const x2 = point.x.redSqr();
      const y2 = point.y.redSqr();
      const dxy = this._mulD(x2).redMul(y2);
      const lhs = this._mulA(x2).redIAdd(y2);
      const rhs = this.one.redAdd(dxy);
      const tz = point.t;
      const xy = point.x.redMul(point.y);

      return lhs.eq(rhs) && tz.eq(xy);
    }

    // (a * x^2 + y^2) * z^2 = z^4 + d * x^2 * y^2
    const x2 = point.x.redSqr();
    const y2 = point.y.redSqr();
    const z2 = point.z.redSqr();
    const z4 = z2.redSqr();
    const dxy = this._mulD(x2).redMul(y2);
    const lhs = this._mulA(x2).redIAdd(y2).redMul(z2);
    const rhs = z4.redIAdd(dxy);
    const tz = point.t.redMul(point.z);
    const xy = point.x.redMul(point.y);

    return lhs.eq(rhs) && tz.eq(xy);
  }

  pointFromX(x, sign = null) {
    assert(x instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!x.red)
      x = x.toRed(this.red);

    const y = this.solveY(x);

    if (sign != null) {
      if (y.isZero() && sign)
        throw new Error('Invalid point.');

      if (y.redIsOdd() !== sign)
        y.redINeg();
    }

    return this.point(x, y);
  }

  pointFromY(y, sign = null) {
    assert(y instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!y.red)
      y = y.toRed(this.red);

    const x = this.solveX(y);

    if (sign != null) {
      if (x.isZero() && sign)
        throw new Error('Invalid point.');

      if (x.redIsOdd() !== sign)
        x.redINeg();
    }

    return this.point(x, y);
  }

  isIsomorphic(curve, invert = false) {
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    //           Definition 2.1, Page 3, Section 2.
    assert(curve instanceof Curve);
    assert(typeof invert === 'boolean');

    if (!curve.p.eq(this.p))
      return false;

    // E(a,d) <-> E(a,b)
    if (curve.type === 'short')
      return curve.isIsomorphic(this);

    // E(a,d) <-> M(A,B)
    // E(a,d) <-> M(-A,-B)
    if (curve.type === 'mont') {
      // A * (a - d) = 2 * (a + d)
      const a = this.field(curve.a);

      let apd, amd;

      if (invert) {
        apd = this.d.redAdd(this.a);
        amd = this.d.redSub(this.a);
      } else {
        apd = this.a.redAdd(this.d);
        amd = this.a.redSub(this.d);
      }

      return a.redMul(amd).eq(apd.redIMuln(2));
    }

    // E(a,d) <-> E(a',a'd/a)
    if (curve.type === 'edwards') {
      // a' * d = a * d'
      const a = this.field(curve.a);
      const d = this.field(curve.d);

      return this.a.redMul(d).eq(a.redMul(this.d));
    }

    return false;
  }

  isIsogenous(curve) {
    // Check for the 4-isogenies described by Hamburg:
    // https://moderncrypto.org/mail-archive/curves/2016/000806.html
    assert(curve instanceof Curve);

    if (!curve.p.eq(this.p))
      return false;

    // E(1,d) <-> M(2-4d,1)
    if (curve.type === 'mont') {
      if (!this.a.eq(this.one))
        return false;

      const a = this.field(curve.a);
      const b = this.field(curve.b);
      const d24 = this.two.redSub(this.d.redMuln(4));

      return a.eq(d24) && b.eq(this.one);
    }

    // E(a,d) <-> E(-a,d-a)
    if (curve.type === 'edwards') {
      const a = this.field(curve.a);
      const d = this.field(curve.d);

      return a.eq(this.a.redNeg())
          && d.eq(this.d.redSub(this.a));
    }

    return false;
  }

  pointFromShort(point) {
    // [TWISTEQ] Section 1.
    assert(point instanceof ShortPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for E(a,b)->E(a',d'):
      //
      //   x' = (6 * x - a' - d') / (6 * y)
      //   y' = (12 * x - 5 * a' + d') / (12 * x + a' - 5 * d')
      //
      // Undefined for x = (5 * d' - a') / 12 or y = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - ((a' + d') / 6, 0) -> (0, -1)
      //   - ((5 * d' - a') / 12, (d' - a') / 4 * sqrt(d')) -> (sqrt(1/d'), oo)
      //
      // Unexceptional Cases:
      //   - ((5 * a' - d') / 12, (a' - d') / 4 * sqrt(a')) -> (sqrt(1/a'), 0)
      if (point.isInfinity())
        return this.point();

      if (point.y.isZero())
        return this.point(this.zero, this.one.redNeg());

      const {a, d} = this;
      const [u2, u3] = this._scale(point.curve);
      const a5 = a.redMuln(5);
      const d5 = d.redMuln(5);
      const x = this.field(point.x).redMul(u2);
      const y = this.field(point.y).redMul(u3);
      const x6 = x.redMuln(6);
      const x12 = x.redMuln(12);
      const xx = x6.redSub(a).redISub(d);
      const xz = y.redMuln(6);
      const yy = x12.redSub(a5).redIAdd(d);
      const yz = x12.redAdd(a).redISub(d5);

      return this.cpoint(xx, xz, yy, yz);
    }

    throw new Error('Not implemented.');
  }

  pointFromMont(point) {
    // [RFC7748] Section 4.1 & 4.2.
    // [MONT3] Page 6, Section 2.5.
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    assert(point instanceof MontPoint);
    assert(point.curve.p.eq(this.p));

    // Montgomery `u`, `v`.
    const u = this.field(point.x);
    const v = this.field(point.y);

    if (this.isIsogenous(point.curve)) {
      // 4-isogeny maps for M(2-4d,1)->E(1,d):
      //
      //   x = 4 * v * (u^2 - 1) / (u^4 - 2 * u^2 + 4 * v^2 + 1)
      //   y = -(u^5 - 2 * u^3 - 4 * u * v^2 + u) /
      //        (u^5 - 2 * u^2 * v^2 - 2 * u^3 - 2 * v^2 + u)
      //
      // Undefined for u = 0 and v = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - (0, 0) -> (0, 1)
      //
      // Unexceptional Cases:
      //   - (-1, +-sqrt(A - 2)) -> (0, 1)
      //   - (1, +-sqrt(A + 2)) -> (0, -1)
      //
      // The point (1, v) is invalid on Curve448.
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point();

      const u2 = u.redSqr();
      const u3 = u2.redMul(u);
      const u4 = u3.redMul(u);
      const u5 = u4.redMul(u);
      const v2 = v.redSqr();
      const a = v.redMuln(4);
      const b = u2.redSub(this.one);
      const c = u2.redMuln(2);
      const d = v2.redMuln(4);
      const e = u3.redIMuln(2);
      const f = u.redMul(v2).redIMuln(4);
      const g = u2.redMul(v2).redIMuln(2);
      const h = v2.redIMuln(2);
      const xx = a.redMul(b);
      const xz = u4.redISub(c).redIAdd(d).redIAdd(this.one);
      const yy = u5.redSub(e).redISub(f).redIAdd(u).redINeg();
      const yz = u5.redISub(g).redISub(e).redISub(h).redIAdd(u);

      return this.cpoint(xx, xz, yy, yz).divn(4);
    }

    if (this.isIsomorphic(point.curve, true)) {
      // Isomorphic maps for M(-A,-B)->E(a,d):
      //
      //   x = +-sqrt((A - 2) / (B * a)) * u / v
      //   y = (u + 1) / (u - 1)
      //
      // Undefined for u = 1 or v = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - (0, 0) -> (0, -1)
      //   - (1, +-sqrt((A + 2) / B)) -> (+-sqrt(1 / d), oo)
      //
      // Unexceptional Cases:
      //   - (-1, +-sqrt((A - 2) / B)) -> (+-sqrt(1 / a), 0)
      //
      // The point (1, v) is invalid on Curve448.
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.one.redNeg());

      const c = this._scale(point.curve, true);
      const xx = c.redMul(u);
      const xz = v;
      const yy = u.redAdd(this.one);
      const yz = u.redSub(this.one);

      return this.cpoint(xx, xz, yy, yz);
    }

    if (this.isIsomorphic(point.curve, false)) {
      // Isomorphic maps for M(A,B)->E(a,d):
      //
      //   x = +-sqrt((A + 2) / (B * a)) * u / v
      //   y = (u - 1) / (u + 1)
      //
      // Undefined for u = -1 or v = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - (0, 0) -> (0, -1)
      //   - (-1, +-sqrt((A - 2) / B)) -> (+-sqrt(1 / d), oo)
      //
      // Unexceptional Cases:
      //   - (1, +-sqrt((A + 2) / B)) -> (+-sqrt(1 / a), 0)
      //
      // The point (-1, v) is invalid on Curve25519.
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.one.redNeg());

      const c = this._scale(point.curve, false);
      const xx = c.redMul(u);
      const xz = v;
      const yy = u.redSub(this.one);
      const yz = u.redAdd(this.one);

      return this.cpoint(xx, xz, yy, yz);
    }

    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    // [ISOGENY] Page 2, Section 2.
    assert(point instanceof EdwardsPoint);
    assert(point.curve.p.eq(this.p));

    // Edwards `x`, `y`, `z`, `t`.
    const a = this.field(point.curve.a);
    const x = this.field(point.x);
    const y = this.field(point.y);
    const z = this.field(point.z);
    const t = this.field(point.t);

    if (this.isIsogenous(point.curve)) {
      // 4-isogeny maps for E(a,d)<->E(-a,d-a):
      //
      //   x' = (2 * x * y) / (y^2 - a * x^2)
      //   y' = (y^2 + a * x^2) / (2 - y^2 - a * x^2)
      //
      // Undefined for y^2 - a * x^2 = 0
      //            or y^2 + a * x^2 = 2.
      const xy = x.redMul(y);
      const x2 = x.redSqr();
      const y2 = y.redSqr();
      const z2 = z.redSqr();
      const ax2 = a.redMul(x2);
      const xx = xy.redIMuln(2);
      const xz = y2.redSub(ax2);
      const yy = y2.redAdd(ax2);
      const yz = z2.redIMuln(2).redISub(yy);
      const p = this.cpoint(xx, xz, yy, yz);

      return !this.twisted ? p.divn(4) : p;
    }

    if (this.isIsomorphic(point.curve)) {
      // Isomorphic maps for E(a,d)<->E(a',a'd/a):
      //
      //   x' = +-sqrt(a / a') * x
      //   y' = y
      //
      // Undefined when (a / a') is not square.
      const c = this._scale(point.curve);
      const nx = c.redMul(x);
      const ny = y;
      const nz = z;
      const nt = c.redMul(t);

      return this.point(nx, ny, nz, nt);
    }

    throw new Error('Not implemented.');
  }

  pointFromUniform(u, curve = null) {
    assert(u instanceof BN);
    assert(u.red === this.red);
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    const u0 = curve.field(u);
    const p0 = curve.pointFromUniform(u0);

    return this.pointFromMont(p0);
  }

  pointToUniform(p, hint, curve = null) {
    // Convert an edwards point to a field
    // element by inverting the elligator2 map.
    //
    // Hint Layout:
    //
    //   [00000000] [0000] [0000]
    //        |        |      |
    //        |        |      +-- preimage index
    //        |        +--- subgroup
    //        +-- bits to OR with uniform bytes
    assert(p instanceof EdwardsPoint);
    assert((hint >>> 0) === hint);
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    // Add a random torsion component.
    const i = ((hint >> 4) & 15) % this.torsion.length;
    const q = p.add(this.torsion[i]);

    // Convert and invert.
    const p0 = curve.pointFromEdwards(q);
    const u0 = curve.pointToUniform(p0, hint & 15);

    return this.field(u0);
  }

  pointFromHash(bytes, pake, curve = null) {
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    const p0 = curve.pointFromHash(bytes, pake);

    return this.pointFromMont(p0);
  }

  pointToHash(p, subgroup, rng, curve = null) {
    assert(p instanceof EdwardsPoint);
    assert((subgroup >>> 0) === subgroup);
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    // Add a random torsion component.
    const i = subgroup % this.torsion.length;
    const q = p.add(this.torsion[i]);

    // Convert and invert.
    const p0 = curve.pointFromEdwards(q);

    return curve.pointToHash(p0, 0, rng);
  }

  decodePoint(bytes) {
    return EdwardsPoint.decode(this, bytes);
  }

  toShort(a0, odd, sign = null) {
    const [a, b] = this._short(a0, odd);

    const curve = new ShortCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = curve._scale(this);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromEdwards(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromEdwards(this.torsion[i]);

    return curve;
  }

  toMont(b0, invert, sign = null) {
    const [a, b] = this._mont(b0, invert);

    const curve = new MontCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = this._scale(curve, invert);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromEdwards(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromEdwards(this.torsion[i]);

    return curve;
  }

  toEdwards(a0, sign = null) {
    const [a, d] = this._edwards(a0);

    const curve = new EdwardsCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      d: d,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = curve._scale(this);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity()) {
      curve.g = curve.pointFromEdwards(this.g);
      curve.g.normalize();
    }

    if (curve.isComplete()) {
      for (let i = 0; i < this.h.word(0); i++) {
        curve.torsion[i] = curve.pointFromEdwards(this.torsion[i]);
        curve.torsion[i].normalize();
      }
    }

    return curve;
  }

  pointFromJSON(json) {
    return EdwardsPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);

    json.a = this.a.fromRed().toJSON();
    json.d = this.d.fromRed().toJSON();

    if (!this.s.isZero())
      json.s = this.s.fromRed().toJSON();

    return json;
  }
}

/**
 * EdwardsPoint
 */

class EdwardsPoint extends Point {
  constructor(curve, x, y, z, t) {
    assert(curve instanceof EdwardsCurve);

    super(curve, types.EXTENDED);

    this.x = this.curve.zero;
    this.y = this.curve.one;
    this.z = this.curve.one;
    this.t = this.curve.zero;
    this.zOne = true;

    if (x != null)
      this._init(x, y, z, t);
  }

  _init(x, y, z, t) {
    assert(x instanceof BN);
    assert(y instanceof BN);
    assert(z == null || (z instanceof BN));
    assert(t == null || (t instanceof BN));

    this.x = x;
    this.y = y;
    this.z = z || this.curve.one;
    this.t = t || null;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    if (this.t && !this.t.red)
      this.t = this.t.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one);

    this._check();

    if (!this.t) {
      this.t = this.x.redMul(this.y);
      if (!this.zOne)
        this.t = this.t.redDiv(this.z);
    }
  }

  _check() {
    // In order to achieve complete
    // addition formulas, `a` must
    // be a square (always the case
    // for a=1), and `d` must be a
    // non-square.
    //
    // If this is not the case, the
    // addition formulas may have
    // exceptional cases where Z3=0.
    //
    // In particular, this can occur
    // when: Q*h = -P*h and Q != -P.
    //
    // This is assuming 4-torsion is
    // involved (the 4-torsion point
    // is _not_ representable when
    // `d` is square).
    if (this.z.isZero())
      throw new Error('Invalid point.');
  }

  clone() {
    return this.curve.point(this.x, this.y, this.z, this.t);
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#scaling-z
    // 1I + 2M (+ 1M if extended)

    // Z1 = 1
    if (this.zOne)
      return this;

    // A = 1 / Z1
    const a = this.z.redInvert();

    // X3 = X1 * A
    this.x = this.x.redMul(a);

    // Y3 = Y1 * A
    this.y = this.y.redMul(a);

    // T3 = T1 * A
    this.t = this.t.redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = true;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // X3 = X1 * A
    const nx = this.x.redMul(a);

    // Y3 = Y1 * A
    const ny = this.y.redMul(a);

    // Z3 = Z1 * A
    const nz = this.z.redMul(a);

    // T3 = T1 * A
    const nt = this.t.redMul(a);

    return this.curve.point(nx, ny, nz, nt);
  }

  neg() {
    // -(X1, Y1, Z1, T1) = (-X1, Y1, Z1, -T1)
    const nx = this.x.redNeg();
    const ny = this.y;
    const nz = this.z;
    const nt = this.t.redNeg();

    return this.curve.point(nx, ny, nz, nt);
  }

  add(p) {
    assert(p instanceof EdwardsPoint);

    // P = O
    if (this.isInfinity())
      return p;

    // Q = O
    if (p.isInfinity())
      return this;

    // Z1 = 1
    if (this.zOne)
      return p._add(this);

    return this._add(p);
  }

  _add(p) {
    // a = -1
    if (this.curve.mOneA)
      return this._addM1(p);

    return this._addA(p);
  }

  _addM1(p) {
    // Assumes a = -1.
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
    // 8M + 8A + 1*k + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-madd-2008-hwcd-3
    // 7M + 8A + 1*k + 1*2

    // A = (Y1 - X1) * (Y2 - X2)
    const a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));

    // B = (Y1 + X1) * (Y2 + X2)
    const b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));

    // C = T1 * k * T2
    const c = this.t.redMul(this.curve.k).redMul(p.t);

    // D = Z1 * 2 * Z2
    const d = p.zOne ? this.z.redAdd(this.z) : this.z.redMul(p.z).redIMuln(2);

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

  _addA(p) {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // 9M + 7A + 1*a + 1*d
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-madd-2008-hwcd
    // 8M + 7A + 1*a + 1*d

    // A = X1 * X2
    const a = this.x.redMul(p.x);

    // B = Y1 * Y2
    const b = this.y.redMul(p.y);

    // C = T1 * d * T2
    const c = this.curve._mulD(this.t).redMul(p.t);

    // D = Z1 * Z2
    const d = p.zOne ? this.z.clone() : this.z.redMul(p.z);

    // + XYXY = (X1 + Y1) * (X2 + Y2)
    const xyxy = this.x.redAdd(this.y).redMul(p.x.redAdd(p.y));

    // E = (X1 + Y1) * (X2 + Y2) - A - B
    const e = xyxy.redISub(a).redISub(b);

    // F = D - C
    const f = d.redSub(c);

    // G = D + C
    const g = d.redIAdd(c);

    // H = B - a * A
    const h = b.redISub(this.curve._mulA(a));

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

  dbl() {
    // P = O
    if (this.isInfinity())
      return this;

    return this._dbl();
  }

  _dbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // 4M + 4S + 6A + 1*a + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-mdbl-2008-hwcd
    // 3M + 4S + 7A + 1*a + 1*2

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = 2 * Z1^2
    const c = this.zOne ? this.curve.two : this.z.redSqr().redIMuln(2);

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

  getX() {
    this.normalize();
    return this.x.fromRed();
  }

  getY() {
    this.normalize();
    return this.y.fromRed();
  }

  eq(p) {
    assert(p instanceof EdwardsPoint);
    assert(!this.z.isZero());
    assert(!p.z.isZero());

    // P = Q
    if (this === p)
      return true;

    // Z1 = Z2
    if (this.z.eq(p.z)) {
      return this.x.eq(p.x)
          && this.y.eq(p.y);
    }

    // X1 * Z2 = X2 * Z1
    const x1 = this.x.redMul(p.z);
    const x2 = p.x.redMul(this.z);

    if (!x1.eq(x2))
      return false;

    const y1 = this.y.redMul(p.z);
    const y2 = p.y.redMul(this.z);

    return y1.eq(y2);
  }

  cmp(point) {
    assert(point instanceof EdwardsPoint);

    return this.order().cmp(point.order())
        || this.getY().cmp(point.getY())
        || this.getX().cmp(point.getX());
  }

  isInfinity() {
    assert(!this.z.isZero());

    // X1 = 0
    if (!this.x.isZero())
      return false;

    // Y1 = Z1
    return this.y.eq(this.z);
  }

  isOrder2() {
    if (this.isInfinity())
      return false;

    return this.x.isZero();
  }

  isOdd() {
    this.normalize();
    return this.x.redIsOdd();
  }

  isEven() {
    this.normalize();
    return this.x.redIsEven();
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this;
  }

  encode() {
    // [RFC8032] Section 5.1.2.
    const y = this.getY();

    // Note: `x` normalized from `getY()` call.
    y.setn(this.curve.signBit, this.x.redIsOdd());

    return this.curve.encodeAdjusted(y);
  }

  static decode(curve, bytes) {
    // [RFC8032] Section 5.1.3.
    assert(curve instanceof EdwardsCurve);

    const y = curve.decodeAdjusted(bytes);
    const sign = y.testn(curve.signBit) !== 0;

    y.setn(curve.signBit, 0);

    if (y.cmp(curve.p) >= 0)
      throw new Error('Invalid point.');

    return curve.pointFromY(y, sign);
  }

  toJSON(pre) {
    if (this.isInfinity())
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    if (pre === true && this.pre)
      return [x, y, this.pre.toJSON()];

    return [x, y];
  }

  toPretty() {
    const size = this.curve.fieldSize * 2;
    const x = toPretty(this.getX(), size);
    const y = toPretty(this.getY(), size);

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof EdwardsCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);
    const point = curve.point(x, y);

    if (json.length > 2 && json[2] != null)
      point.pre = Precomp.fromJSON(point, json[2]);

    return point;
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
}

/**
 * Precomp
 */

class Precomp {
  constructor() {
    this.naf = null;
    this.windows = null;
    this.doubles = null;
    this.blinding = null;
    this.beta = null;
  }

  map(func) {
    assert(typeof func === 'function');

    const out = new this.constructor();

    if (this.naf)
      out.naf = this.naf.map(func);

    if (this.doubles)
      out.doubles = this.doubles.map(func);

    return out;
  }

  toJSON() {
    return {
      naf: this.naf ? this.naf.toJSON() : null,
      windows: this.windows ? this.windows.toJSON() : null,
      doubles: this.doubles ? this.doubles.toJSON() : null,
      blinding: this.blinding ? this.blinding.toJSON() : undefined
    };
  }

  fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');

    if (json.naf != null)
      this.naf = NAF.fromJSON(point, json.naf);

    if (json.windows != null)
      this.windows = Windows.fromJSON(point, json.windows);

    if (json.doubles != null)
      this.doubles = Doubles.fromJSON(point, json.doubles);

    if (json.blinding != null)
      this.blinding = Blinding.fromJSON(point, json.blinding);

    return this;
  }

  static fromJSON(point, json) {
    return new this().fromJSON(point, json);
  }
}

/**
 * NAF
 */

class NAF {
  constructor(width, points) {
    this.width = width;
    this.points = points;
  }

  map(func) {
    assert(typeof func === 'function');

    const {width} = this;
    const points = [];

    for (const point of this.points)
      points.push(func(point));

    return new this.constructor(width, points);
  }

  toJSON() {
    return {
      width: this.width,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.width >>> 0) === json.width);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {width} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(width, points);
  }
}

/**
 * Windows
 */

class Windows {
  constructor(width, bits, points) {
    this.width = width;
    this.bits = bits;
    this.points = points;
  }

  toJSON() {
    return {
      width: this.width,
      bits: this.bits,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.width >>> 0) === json.width);
    assert((json.bits >>> 0) === json.bits);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {width, bits} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(width, bits, points);
  }
}

/**
 * Doubles
 */

class Doubles {
  constructor(step, points) {
    this.step = step;
    this.points = points;
  }

  map(func) {
    assert(typeof func === 'function');

    const {step} = this;
    const points = [];

    for (const point of this.points)
      points.push(func(point));

    return new this.constructor(step, points);
  }

  toJSON() {
    return {
      step: this.step,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.step >>> 0) === json.step);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {step} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(step, points);
  }
}

/**
 * Blinding
 */

class Blinding {
  constructor(blind, unblind) {
    this.blind = blind;
    this.unblind = unblind;
  }

  toJSON() {
    return {
      blind: this.blind.toJSON(),
      unblind: this.unblind.toJSON()
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');

    const {curve} = point;
    const blind = BN.fromJSON(json.blind);
    const unblind = curve.pointFromJSON(json.unblind);

    return new this(blind, unblind);
  }
}

/**
 * Endo
 */

class Endo {
  constructor(beta, lambda, basis, pre) {
    this.beta = beta;
    this.lambda = lambda;
    this.basis = basis;
    this.pre = pre;
  }

  toJSON() {
    return {
      beta: this.beta.fromRed().toJSON(),
      lambda: this.lambda.toJSON(),
      basis: [
        this.basis[0].toJSON(),
        this.basis[1].toJSON()
      ],
      pre: [
        this.pre[0],
        this.pre[1].toJSON(),
        this.pre[2].toJSON()
      ]
    };
  }

  static fromJSON(curve, json) {
    assert(curve instanceof Curve);
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.basis));
    assert(Array.isArray(json.pre));
    assert(json.basis.length === 2);
    assert(json.pre.length === 3);
    assert((json.pre[0] >>> 0) === json.pre[0]);

    const beta = BN.fromJSON(json.beta).toRed(curve.red);
    const lambda = BN.fromJSON(json.lambda);

    const basis = [
      Vector.fromJSON(json.basis[0]),
      Vector.fromJSON(json.basis[1])
    ];

    const pre = [
      json.pre[0],
      BN.fromJSON(json.pre[1]),
      BN.fromJSON(json.pre[2])
    ];

    return new this(beta, lambda, basis, pre);
  }
}

/**
 * Vector
 */

class Vector {
  constructor(a, b) {
    this.a = a;
    this.b = b;
  }

  toJSON() {
    return {
      a: this.a.toJSON(),
      b: this.b.toJSON()
    };
  }

  static fromJSON(json) {
    assert(json && typeof json === 'object');

    const a = BN.fromJSON(json.a);
    const b = BN.fromJSON(json.b);

    return new this(a, b);
  }
}

/**
 * P192
 * https://tinyurl.com/fips-186-2 (page 29)
 * https://tinyurl.com/fips-186-3 (page 88)
 */

class P192 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P192',
      ossl: 'prime192v1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'p192',
      // 2^192 - 2^64 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff fffffffe',
          'ffffffff ffffffff'],
      // -3 mod p
      a: ['ffffffff ffffffff ffffffff fffffffe',
          'ffffffff fffffffc'],
      b: ['64210519 e59c80e7 0fa7e9ab 72243049',
          'feb8deec c146b9b1'],
      n: ['ffffffff ffffffff ffffffff 99def836',
          '146bc9b1 b4d22831'],
      h: '1',
      // Icart
      z: '-5',
      g: [
        ['188da80e b03090f6 7cbf20eb 43a18800',
         'f4ff0afd 82ff1012'],
        ['07192b95 ffc8da78 631011ed 6b24cdd5',
         '73f977a1 1e794811'],
        pre
      ]
    });
  }
}

/**
 * P224
 * https://tinyurl.com/fips-186-2 (page 30)
 * https://tinyurl.com/fips-186-3 (page 88)
 */

class P224 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P224',
      ossl: 'secp224r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'p224',
      // 2^224 - 2^96 + 1 (1 mod 16)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          '00000000 00000000 00000001'],
      // -3 mod p
      a: ['ffffffff ffffffff ffffffff fffffffe',
          'ffffffff ffffffff fffffffe'],
      b: ['b4050a85 0c04b3ab f5413256 5044b0b7',
          'd7bfd8ba 270b3943 2355ffb4'],
      n: ['ffffffff ffffffff ffffffff ffff16a2',
          'e0b8f03e 13dd2945 5c5c2a3d'],
      h: '1',
      // SSWU
      z: '1f',
      g: [
        ['b70e0cbd 6bb4bf7f 321390b9 4a03c1d3',
         '56c21122 343280d6 115c1d21'],
        ['bd376388 b5f723fb 4c22dfe6 cd4375a0',
         '5a074764 44d58199 85007e34'],
        pre
      ]
    });
  }
}

/**
 * P256
 * https://tinyurl.com/fips-186-2 (page 31)
 * https://tinyurl.com/fips-186-3 (page 89)
 */

class P256 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P256',
      ossl: 'prime256v1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // 2^256 - 2^224 + 2^192 + 2^96 - 1 (= 3 mod 4)
      p: ['ffffffff 00000001 00000000 00000000',
          '00000000 ffffffff ffffffff ffffffff'],
      // -3 mod p
      a: ['ffffffff 00000001 00000000 00000000',
          '00000000 ffffffff ffffffff fffffffc'],
      b: ['5ac635d8 aa3a93e7 b3ebbd55 769886bc',
          '651d06b0 cc53b0f6 3bce3c3e 27d2604b'],
      n: ['ffffffff 00000000 ffffffff ffffffff',
          'bce6faad a7179e84 f3b9cac2 fc632551'],
      h: '1',
      // SSWU
      z: '-a',
      g: [
        ['6b17d1f2 e12c4247 f8bce6e5 63a440f2',
         '77037d81 2deb33a0 f4a13945 d898c296'],
        ['4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16',
         '2bce3357 6b315ece cbb64068 37bf51f5'],
        pre
      ]
    });
  }
}

/**
 * P384
 * https://tinyurl.com/fips-186-2 (page 32)
 * https://tinyurl.com/fips-186-3 (page 89)
 */

class P384 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P384',
      ossl: 'secp384r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA384',
      prime: null,
      // 2^384 - 2^128 - 2^96 + 2^32 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffffe',
          'ffffffff 00000000 00000000 ffffffff'],
      // -3 mod p
      a: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffffe',
          'ffffffff 00000000 00000000 fffffffc'],
      b: ['b3312fa7 e23ee7e4 988e056b e3f82d19',
          '181d9c6e fe814112 0314088f 5013875a',
          'c656398d 8a2ed19d 2a85c8ed d3ec2aef'],
      n: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff c7634d81 f4372ddf',
          '581a0db2 48b0a77a ecec196a ccc52973'],
      h: '1',
      // Icart
      z: '-c',
      g: [
        ['aa87ca22 be8b0537 8eb1c71e f320ad74',
         '6e1d3b62 8ba79b98 59f741e0 82542a38',
         '5502f25d bf55296c 3a545e38 72760ab7'],
        ['3617de4a 96262c6f 5d9e98bf 9292dc29',
         'f8f41dbd 289a147c e9da3113 b5f0b8c0',
         '0a60b1ce 1d7e819d 7a431d7c 90ea0e5f'],
        pre
      ]
    });
  }
}

/**
 * P521
 * https://tinyurl.com/fips-186-2 (page 33)
 * https://tinyurl.com/fips-186-3 (page 90)
 */

class P521 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P521',
      ossl: 'secp521r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA512',
      prime: 'p521',
      // 2^521 - 1 (= 3 mod 4)
      p: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff'],
      // -3 mod p
      a: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffffffc'],
      b: ['00000051 953eb961 8e1c9a1f 929a21a0',
          'b68540ee a2da725b 99b315f3 b8b48991',
          '8ef109e1 56193951 ec7e937b 1652c0bd',
          '3bb1bf07 3573df88 3d2c34f1 ef451fd4',
          '6b503f00'],
      n: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffffffa 51868783 bf2f966b 7fcc0148',
          'f709a5d0 3bb5c9b8 899c47ae bb6fb71e',
          '91386409'],
      h: '1',
      // SSWU
      z: '-4',
      g: [
        ['000000c6 858e06b7 0404e9cd 9e3ecb66',
         '2395b442 9c648139 053fb521 f828af60',
         '6b4d3dba a14b5e77 efe75928 fe1dc127',
         'a2ffa8de 3348b3c1 856a429b f97e7e31',
         'c2e5bd66'],
        ['00000118 39296a78 9a3bc004 5c8a5fb4',
         '2c7d1bd9 98f54449 579b4468 17afbd17',
         '273e662c 97ee7299 5ef42640 c550b901',
         '3fad0761 353c7086 a272c240 88be9476',
         '9fd16650'],
        pre
      ]
    });
  }
}

/**
 * SECP256K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 15, section 2.7.1)
 * https://www.secg.org/sec2-v2.pdf (page 9, section 2.4.1)
 */

class SECP256K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP256K1',
      ossl: 'secp256k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'k256',
      // 2^256 - 2^32 - 977 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe fffffc2f'],
      a: '0',
      b: '7',
      n: ['ffffffff ffffffff ffffffff fffffffe',
          'baaedce6 af48a03b bfd25e8c d0364141'],
      h: '1',
      // SVDW
      z: '1',
      // sqrt(-3)
      c: ['0a2d2ba9 3507f1df 233770c2 a797962c',
          'c61f6d15 da14ecd4 7d8d27ae 1cd5f852'],
      g: [
        ['79be667e f9dcbbac 55a06295 ce870b07',
         '029bfcdb 2dce28d9 59f2815b 16f81798'],
        ['483ada77 26a3c465 5da4fbfc 0e1108a8',
         'fd17b448 a6855419 9c47d08f fb10d4b8'],
        pre
      ],
      // Precomputed endomorphism.
      endo: {
        beta: ['7ae96a2b 657c0710 6e64479e ac3434e9',
               '9cf04975 12f58995 c1396c28 719501ee'],
        lambda: ['5363ad4c c05c30e0 a5261c02 8812645a',
                 '122e22ea 20816678 df02967c 1b23bd72'],
        basis: [
          {
            a: '3086d221a7d46bcde86c90e49284eb15',
            b: '-e4437ed6010e88286f547fa90abfe4c3'
          },
          {
            a: '114ca50f7a8e2f3f657c1108d9d44cfd8',
            b: '3086d221a7d46bcde86c90e49284eb15'
          }
        ],
        pre: [
          384,
          ['3086d221 a7d46bcd e86c90e4 9284eb15',
           '3daa8a14 71e8ca7f e893209a 45dbb031'],
          ['-',
           'e4437ed6 010e8828 6f547fa9 0abfe4c4',
           '221208ac 9df506c6 1571b4ae 8ac47f71']
        ]
      }
    });
  }
}

/**
 * BRAINPOOLP256
 * https://tools.ietf.org/html/rfc5639#section-3.4
 */

class BRAINPOOLP256 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP256',
      ossl: 'brainpoolP256r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // (= 3 mod 4)
      p: ['a9fb57db a1eea9bc 3e660a90 9d838d72',
          '6e3bf623 d5262028 2013481d 1f6e5377'],
      a: ['7d5a0975 fc2c3057 eef67530 417affe7',
          'fb8055c1 26dc5c6c e94a4b44 f330b5d9'],
      b: ['26dc5c6c e94a4b44 f330b5d9 bbd77cbf',
          '95841629 5cf7e1ce 6bccdc18 ff8c07b6'],
      n: ['a9fb57db a1eea9bc 3e660a90 9d838d71',
          '8c397aa3 b561a6f7 901e0e82 974856a7'],
      h: '1',
      // Icart
      z: '-2',
      g: [
        ['8bd2aeb9 cb7e57cb 2c4b482f fc81b7af',
         'b9de27e1 e3bd23c2 3a4453bd 9ace3262'],
        ['547ef835 c3dac4fd 97f8461a 14611dc9',
         'c2774513 2ded8e54 5c1d54c7 2f046997'],
        pre
      ]
    });
  }
}

/**
 * BRAINPOOLP384
 * https://tools.ietf.org/html/rfc5639#section-3.6
 */

class BRAINPOOLP384 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP384',
      ossl: 'brainpoolP384r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA384',
      prime: null,
      // (= 3 mod 4)
      p: ['8cb91e82 a3386d28 0f5d6f7e 50e641df',
          '152f7109 ed5456b4 12b1da19 7fb71123',
          'acd3a729 901d1a71 87470013 3107ec53'],
      a: ['7bc382c6 3d8c150c 3c72080a ce05afa0',
          'c2bea28e 4fb22787 139165ef ba91f90f',
          '8aa5814a 503ad4eb 04a8c7dd 22ce2826'],
      b: ['04a8c7dd 22ce2826 8b39b554 16f0447c',
          '2fb77de1 07dcd2a6 2e880ea5 3eeb62d5',
          '7cb43902 95dbc994 3ab78696 fa504c11'],
      n: ['8cb91e82 a3386d28 0f5d6f7e 50e641df',
          '152f7109 ed5456b3 1f166e6c ac0425a7',
          'cf3ab6af 6b7fc310 3b883202 e9046565'],
      h: '1',
      // SSWU
      z: '-5',
      g: [
        ['1d1c64f0 68cf45ff a2a63a81 b7c13f6b',
         '8847a3e7 7ef14fe3 db7fcafe 0cbd10e8',
         'e826e034 36d646aa ef87b2e2 47d4af1e'],
        ['8abe1d75 20f9c2a4 5cb1eb8e 95cfd552',
         '62b70b29 feec5864 e19c054f f9912928',
         '0e464621 77918111 42820341 263c5315'],
        pre
      ]
    });
  }
}

/**
 * BRAINPOOLP512
 * https://tools.ietf.org/html/rfc5639#section-3.7
 */

class BRAINPOOLP512 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP512',
      ossl: 'brainpoolP512r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA512',
      prime: null,
      // (= 3 mod 4)
      p: ['aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07',
          'cb308db3 b3c9d20e d6639cca 70330871',
          '7d4d9b00 9bc66842 aecda12a e6a380e6',
          '2881ff2f 2d82c685 28aa6056 583a48f3'],
      a: ['7830a331 8b603b89 e2327145 ac234cc5',
          '94cbdd8d 3df91610 a83441ca ea9863bc',
          '2ded5d5a a8253aa1 0a2ef1c9 8b9ac8b5',
          '7f1117a7 2bf2c7b9 e7c1ac4d 77fc94ca'],
      b: ['3df91610 a83441ca ea9863bc 2ded5d5a',
          'a8253aa1 0a2ef1c9 8b9ac8b5 7f1117a7',
          '2bf2c7b9 e7c1ac4d 77fc94ca dc083e67',
          '984050b7 5ebae5dd 2809bd63 8016f723'],
      n: ['aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07',
          'cb308db3 b3c9d20e d6639cca 70330870',
          '553e5c41 4ca92619 41866119 7fac1047',
          '1db1d381 085ddadd b5879682 9ca90069'],
      h: '1',
      // Icart
      z: '7',
      g: [
        ['81aee4bd d82ed964 5a21322e 9c4c6a93',
         '85ed9f70 b5d916c1 b43b62ee f4d0098e',
         'ff3b1f78 e2d0d48d 50d1687b 93b97d5f',
         '7c6d5047 406a5e68 8b352209 bcb9f822'],
        ['7dde385d 566332ec c0eabfa9 cf7822fd',
         'f209f700 24a57b1a a000c55b 881f8111',
         'b2dcde49 4a5f485e 5bca4bd8 8a2763ae',
         'd1ca2b2f a8f05406 78cd1e0f 3ad80892'],
        pre
      ]
    });
  }
}

/**
 * X25519
 * https://tools.ietf.org/html/rfc7748#section-4.1
 */

class X25519 extends MontCurve {
  constructor() {
    super({
      id: 'X25519',
      ossl: 'X25519',
      type: 'mont',
      endian: 'le',
      hash: 'SHA512',
      prime: 'p25519',
      // 2^255 - 19 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffed'],
      // 486662
      a: '76d06',
      b: '1',
      n: ['10000000 00000000 00000000 00000000',
          '14def9de a2f79cd6 5812631a 5cf5d3ed'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000009'],
        // See: https://www.rfc-editor.org/errata/eid4730
        ['5f51e65e 475f794b 1fe122d3 88b72eb3',
         '6dc2b281 92839e4d d6163a5d 81312c14']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['6be4f497 f9a9c2af c21fa77a d7f4a6ef',
           '635a11c7 284a9363 e9a248ef 9c884415']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['141b0b68 06563d50 3de05885 280b5910',
           '9ca5ee38 d7b56c9c 165db710 6377bbd8']
        ],
        [
          ['57119fd0 dd4e22d8 868e1c58 c45c4404',
           '5bef839c 55b1d0b1 248c50a3 bc959c5f'],
          ['68c59389 3d458e64 31c6ca00 45fb5015',
           '20a44346 8eaa68dd 0f103842 048065b7']
        ],
        [
          ['57119fd0 dd4e22d8 868e1c58 c45c4404',
           '5bef839c 55b1d0b1 248c50a3 bc959c5f'],
          ['173a6c76 c2ba719b ce3935ff ba04afea',
           'df5bbcb9 71559722 f0efc7bd fb7f9a36']
        ],
        [
          ['00b8495f 16056286 fdb1329c eb8d09da',
           '6ac49ff1 fae35616 aeb8413b 7c7aebe0'],
          ['3931c129 569e83a5 29482c14 e628b457',
           '933bfc29 ed801b4d 68871483 92507b1a']
        ],
        [
          ['00b8495f 16056286 fdb1329c eb8d09da',
           '6ac49ff1 fae35616 aeb8413b 7c7aebe0'],
          ['46ce3ed6 a9617c5a d6b7d3eb 19d74ba8',
           '6cc403d6 127fe4b2 9778eb7c 6daf84d3']
        ]
      ]
    });
  }
}

/**
 * X448
 * https://tools.ietf.org/html/rfc7748#section-4.2
 */

class X448 extends MontCurve {
  constructor() {
    super({
      id: 'X448',
      ossl: 'X448',
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      // 156326
      a: '262a6',
      b: '1',
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000005'],
        ['7d235d12 95f5b1f6 6c98ab6e 58326fce',
         'cbae5d34 f55545d0 60f75dc2 8df3f6ed',
         'b8027e23 46430d21 1312c4b1 50677af7',
         '6fd7223d 457b5b1a']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['ba4d3a08 29b6112f 8812e51b a0bb2abe',
           'bc1cb08e b48e5569 36ba50fd d2e7d68a',
           'f8cb3216 0522425b 3f990812 abbe635a',
           'd37a21e1 7551b193']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['45b2c5f7 d649eed0 77ed1ae4 5f44d541',
           '43e34f71 4b71aa96 c945af01 2d182975',
           '0734cde9 faddbda4 c066f7ed 54419ca5',
           '2c85de1e 8aae4e6c']
        ]
      ]
    });
  }
}

/**
 * MONT448
 * Isomorphic to Ed448-Goldilocks.
 */

class MONT448 extends MontCurve {
  constructor() {
    super({
      id: 'MONT448',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      // -78160 / -39082 mod p
      a: ['b2cf97d2 d43459a9 31ed36b1 fc4e3cb5',
          '5d93f8d2 22746997 60ccffc6 49961ed6',
          'c5b05fca c24864ed 6fb59697 931b78da',
          '84ddecd8 ca2b5cfb'],
      b: '1',
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['ac0d24cc c6c75cb0 eb71f81e 7a6edf51',
         '48e88aee 009a2a24 e795687e c28e125a',
         '3e6730a6 0d46367b aa7fe99d 152128dc',
         '41321bc7 7817f059'],
        ['5a4437f6 80c0d0db 9b061276 d5d0ffcc',
         'e786ff33 b6a53d30 98746425 82e66f09',
         '4433dae7 7244a6e2 6b11e905 7228f483',
         '556c41a5 913f55fe']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['bec92fd0 6da2acf2 b4e261e8 7cef0d34',
           '22e75c18 3c589857 b71924e5 73c2f9ce',
           'e18da5f2 466e2f39 3c2eedf0 f105a60a',
           'b40c717d 4f1e1fd7']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['4136d02f 925d530d 4b1d9e17 8310f2cb',
           'dd18a3e7 c3a767a8 48e6db19 8c3d0631',
           '1e725a0d b991d0c6 c3d1120f 0efa59f5',
           '4bf38e82 b0e1e028']
        ]
      ]
    });
  }
}

/**
 * ED25519
 * https://tools.ietf.org/html/rfc8032#section-5.1
 */

class ED25519 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED25519',
      ossl: 'ED25519',
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigEd25519 no Ed25519 collisions',
      context: false,
      prime: 'p25519',
      // 2^255 - 19 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffed'],
      a: '-1',
      // -121665 / 121666 mod p
      d: ['52036cee 2b6ffe73 8cc74079 7779e898',
          '00700a4d 4141d8ab 75eb4dca 135978a3'],
      n: ['10000000 00000000 00000000 00000000',
          '14def9de a2f79cd6 5812631a 5cf5d3ed'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['216936d3 cd6e53fe c0a4e231 fdd6dc5c',
         '692cc760 9525a7b2 c9562d60 8f25d51a'],
        // 4/5
        ['66666666 66666666 66666666 66666666',
         '66666666 66666666 66666666 66666658'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['7fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffec']
        ],
        [
          ['2b832480 4fc1df0b 2b4d0099 3dfbd7a7',
           '2f431806 ad2fe478 c4ee1b27 4a0ea0b0'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['547cdb7f b03e20f4 d4b2ff66 c2042858',
           'd0bce7f9 52d01b87 3b11e4d8 b5f15f3d'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['1fd5b9a0 06394a28 e9339932 38de4abb',
           '5c193c70 13e5e238 dea14646 c545d14a'],
          ['05fc536d 880238b1 3933c6d3 05acdfd5',
           'f098eff2 89f4c345 b027b2c2 8f95e826']
        ],
        [
          ['602a465f f9c6b5d7 16cc66cd c721b544',
           'a3e6c38f ec1a1dc7 215eb9b9 3aba2ea3'],
          ['05fc536d 880238b1 3933c6d3 05acdfd5',
           'f098eff2 89f4c345 b027b2c2 8f95e826']
        ],
        [
          ['1fd5b9a0 06394a28 e9339932 38de4abb',
           '5c193c70 13e5e238 dea14646 c545d14a'],
          ['7a03ac92 77fdc74e c6cc392c fa53202a',
           '0f67100d 760b3cba 4fd84d3d 706a17c7']
        ],
        [
          ['602a465f f9c6b5d7 16cc66cd c721b544',
           'a3e6c38f ec1a1dc7 215eb9b9 3aba2ea3'],
          ['7a03ac92 77fdc74e c6cc392c fa53202a',
           '0f67100d 760b3cba 4fd84d3d 706a17c7']
        ]
      ]
    });
  }
}

/**
 * ISO448
 * https://tools.ietf.org/html/rfc7748#section-4.2
 * https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n658
 */

class ISO448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ISO448',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      a: '1',
      // 39082 / 39081 mod p
      d: ['d78b4bdc 7f0daf19 f24f38c2 9373a2cc',
          'ad461572 42a50f37 809b1da3 412a12e7',
          '9ccc9c81 264cfe9a d0809970 58fb61c4',
          '243cc32d baa156b9'],
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['79a70b2b 70400553 ae7c9df4 16c792c6',
         '1128751a c9296924 0c25a07d 728bdc93',
         'e21f7787 ed697224 9de732f3 8496cd11',
         '69871309 3e9c04fc'],
        // Note: the RFC has this wrong.
        ['7fffffff ffffffff ffffffff ffffffff',
         'ffffffff ffffffff ffffffff 80000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000001'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ]
      ]
    });
  }
}

/**
 * ED448
 * https://tools.ietf.org/html/rfc8032#section-5.2
 */

class ED448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED448',
      ossl: 'ED448',
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      a: '1',
      // -39081 mod p
      d: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffff6756'],
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['4f1970c6 6bed0ded 221d15a6 22bf36da',
         '9e146570 470f1767 ea6de324 a3d3a464',
         '12ae1af7 2ab66511 433b80e1 8b00938e',
         '2626a82b c70cc05e'],
        ['693f4671 6eb6bc24 88762037 56c9c762',
         '4bea7373 6ca39840 87789c1e 05a0c2d7',
         '3ad3ff1c e67c39c4 fdbd132c 4ed7c8ad',
         '9808795b f230fa14'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ]
      ]
    });
  }
}

/*
 * Curve Registry
 */

const curves = {
  __proto__: null,
  P192,
  P224,
  P256,
  P384,
  P521,
  SECP256K1,
  BRAINPOOLP256,
  BRAINPOOLP384,
  BRAINPOOLP512,
  X25519,
  X448,
  MONT448,
  ED25519,
  ISO448,
  ED448
};

const cache = {
  __proto__: null,
  P192: null,
  P224: null,
  P256: null,
  P384: null,
  P521: null,
  SECP256K1: null,
  BRAINPOOLP256: null,
  BRAINPOOLP384: null,
  BRAINPOOLP512: null,
  X25519: null,
  X448: null,
  MONT448: null,
  ED25519: null,
  ISO448: null,
  ED448: null
};

function curve(name, ...args) {
  assert(typeof name === 'string');

  const key = name.toUpperCase();

  let curve = cache[key];

  if (!curve) {
    const Curve = curves[key];

    if (!Curve)
      throw new Error(`Curve not found: "${name}".`);

    curve = new Curve(...args);
    cache[key] = curve;
  }

  return curve;
}

function register(name, Curve) {
  assert(typeof name === 'string');
  assert(typeof Curve === 'function');

  const key = name.toUpperCase();

  if (curves[key])
    throw new Error(`Curve already registered: "${name}".`);

  curves[key] = Curve;
  cache[key] = null;
}

/*
 * Scalar Recoding
 */

function getNAF(k, width, max) {
  // Computing the width-w NAF of a positive integer.
  //
  // [GECC] Algorithm 3.35, Page 100, Section 3.3.
  //
  // The above document describes a rather abstract
  // method of recoding. The more optimal method
  // below was ported from libsecp256k1.
  assert(k instanceof BN);
  assert(!k.red);
  assert((width >>> 0) === width);
  assert((max >>> 0) === max);

  const naf = new Array(max);
  const bits = k.bitLength() + 1;
  const sign = k.sign() | 1;

  assert(bits <= max);

  for (let i = 0; i < max; i++)
    naf[i] = 0;

  let i = 0;
  let carry = 0;
  let word;

  while (i < bits) {
    if (k.bit(i) === carry) {
      i += 1;
      continue;
    }

    word = k.bits(i, width) + carry;
    carry = (word >> (width - 1)) & 1;
    word -= carry << width;

    naf[i] = sign * word;

    i += width;
  }

  assert(carry === 0);

  return naf;
}

function getFixedNAF(k, width, max, step) {
  assert((step >>> 0) === step);

  // Recode to NAF.
  const naf = getNAF(k, width, max);

  // Translate into more windowed form.
  const len = Math.ceil(naf.length / step);
  const repr = new Array(len);

  let i = 0;

  for (let j = 0; j < naf.length; j += step) {
    let nafW = 0;

    for (let k = j + step - 1; k >= j; k--)
      nafW = (nafW << 1) + naf[k];

    repr[i++] = nafW;
  }

  assert(i === len);

  return repr;
}

function getJSF(k1, k2, max) {
  // Joint sparse form.
  //
  // [GECC] Algorithm 3.50, Page 111, Section 3.3.
  assert(k1 instanceof BN);
  assert(k2 instanceof BN);
  assert(!k1.red);
  assert(!k2.red);
  assert((max >>> 0) === max);

  const jsf = [new Array(max), new Array(max)];
  const bits = Math.max(k1.bitLength(), k2.bitLength()) + 1;
  const s1 = k1.sign() | 1;
  const s2 = k2.sign() | 1;

  assert(bits <= max);

  let d1 = 0;
  let d2 = 0;

  for (let i = 0; i < bits; i++) {
    const b1 = k1.bits(i, 3);
    const b2 = k2.bits(i, 3);

    // First phase.
    let m14 = ((b1 & 3) + d1) & 3;
    let m24 = ((b2 & 3) + d2) & 3;
    let u1 = 0;
    let u2 = 0;

    if (m14 === 3)
      m14 = -1;

    if (m24 === 3)
      m24 = -1;

    if (m14 & 1) {
      const m8 = ((b1 & 7) + d1) & 7;

      if ((m8 === 3 || m8 === 5) && m24 === 2)
        u1 = -m14;
      else
        u1 = m14;
    }

    if (m24 & 1) {
      const m8 = ((b2 & 7) + d2) & 7;

      if ((m8 === 3 || m8 === 5) && m14 === 2)
        u2 = -m24;
      else
        u2 = m24;
    }

    jsf[0][i] = u1 * s1;
    jsf[1][i] = u2 * s2;

    // Second phase.
    if (2 * d1 === 1 + u1)
      d1 = 1 - d1;

    if (2 * d2 === 1 + u2)
      d2 = 1 - d2;
  }

  for (let i = bits; i < max; i++) {
    jsf[0][i] = 0;
    jsf[1][i] = 0;
  }

  return jsf;
}

function getJNAF(c1, c2, max) {
  const jsf = getJSF(c1, c2, max);
  const naf = new Array(max);

  // JSF -> NAF conversion.
  for (let i = 0; i < max; i++) {
    const ja = jsf[0][i];
    const jb = jsf[1][i];

    naf[i] = jsfIndex[(ja + 1) * 3 + (jb + 1)];
  }

  return naf;
}

/*
 * Helpers
 */

function assert(val, msg) {
  if (!val) {
    const err = new Error(msg || 'Assertion failed');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assert);

    throw err;
  }
}

function wrapErrors(fn) {
  assert(typeof fn === 'function');

  try {
    return fn();
  } catch (e) {
    if (e.message === 'X is not a square mod P.'
        || e.message === 'Not invertible.') {
      throw new Error('Invalid point.');
    }
    throw e;
  }
}

function mod(x, y) {
  // Euclidean modulo.
  let r = x % y;

  if (r < 0) {
    if (y < 0)
      r -= y;
    else
      r += y;
  }

  return r;
}

function cubeRoot(x) {
  assert(x instanceof BN);
  assert(x.red);

  const p = x.red.m;

  if (p.cmpn(3) <= 0)
    return x.clone();

  // p = 2 mod 3
  if (p.modrn(3) === 2) {
    // e = (2 * p - 1) / 3
    const e = p.ushln(1).isubn(1).idivn(3);
    return x.redPow(e);
  }

  const mod9 = p.modrn(9);

  // p = 4 mod 9
  if (mod9 === 4) {
    // e = (2 * p + 1) / 9
    const e = p.ushln(1).iaddn(1).idivn(9);
    const r = x.redPow(e);
    const c = r.redSqr().redMul(r);

    if (!c.eq(x))
      throw new Error('X is not a cube mod P.');

    return r;
  }

  // p = 7 mod 9
  if (mod9 === 7) {
    // e = (p + 2) / 9
    const e = p.addn(2).idivn(9);
    const r = x.redPow(e);
    const c = r.redSqr().redMul(r);

    if (!c.eq(x))
      throw new Error('X is not a cube mod P.');

    return r;
  }

  throw new Error('Not implemented.');
}

function cubeRoots(x) {
  const r0 = cubeRoot(x);

  // p = 1 mod 3
  if (x.red.m.modrn(3) === 1) {
    // Multiply by roots of unity to find other roots.
    const two = new BN(2).toRed(x.red);
    const three = new BN(3).toRed(x.red);
    const i2 = two.redInvert();
    const s1 = three.redNeg().redSqrt().redMul(i2);
    const s2 = s1.redNeg();
    const u1 = s1.redSub(i2);
    const u2 = s2.redSub(i2);
    const r1 = r0.redMul(u1);
    const r2 = r0.redMul(u2);

    return [r0, r1, r2];
  }

  // p = 2 mod 3 guarantees 1 cube root per element.
  return [r0];
}

function uncube(x) {
  // Find a cube root which is also a quadratic residue.
  for (const root of cubeRoots(x)) {
    if (root.redJacobi() >= 0)
      return root;
  }

  throw new Error('X^(1/3) is not a square mod P.');
}

function randomInt(rng) {
  return BN.randomBits(rng, 32).toNumber();
}

function memoize(method, self) {
  const cache = new WeakMap();

  return function memoized(curve, invert) {
    const i = invert & 1;
    const item = cache.get(curve);

    if (item && item[i] !== null)
      return item[i];

    const result = method.call(self, curve, invert);

    if (!cache.has(curve))
      cache.set(curve, [null, null]);

    cache.get(curve)[i] = result;

    return result;
  };
}

function toPretty(x, size) {
  assert(x instanceof BN);
  assert((size >>> 0) === size);

  if (size & 7)
    size += 8 - (size & 7);

  const str = x.toString(16, size);
  const chunks = [];
  const out = [];

  assert((str.length & 7) === 0);

  for (let i = 0; i < str.length; i += 8)
    chunks.push(str.slice(i, i + 8));

  for (let i = 0; i < chunks.length; i += 4)
    out.push(chunks.slice(i, i + 4).join(' '));

  return out;
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
exports.XPoint = XPoint;
exports.EdwardsCurve = EdwardsCurve;
exports.EdwardsPoint = EdwardsPoint;
exports.curves = curves;
exports.curve = curve;
exports.register = register;
