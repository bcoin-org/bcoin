/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/bn.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/bn.js
 *
 * This software is licensed under the MIT License.
 *
 * Copyright Fedor Indutny, 2015.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 */

/* eslint valid-typeof: "off" */

'use strict';

const {custom} = require('../internal/custom');
const Native = require('./binding').BN;

if (!Native)
  throw new Error('GMP backend not supported.');

/*
 * Constants
 */

const primes = {
  p192: null,
  p224: null,
  p521: null,
  k256: null,
  p25519: null,
  p448: null
};

/**
 * BN
 */

class BN extends Native {
  constructor(num, base, endian) {
    super();

    if (BN.isBN(num))
      return num;

    this.red = null;

    this.from(num, base, endian);
  }

  /*
   * Compat
   */

  get negative() {
    return this.isNeg() ? 1 : 0;
  }

  set negative(val) {
    if ((val & 1) !== this.negative)
      this.ineg();
  }

  get length() {
    return Math.floor((this.bitLength() + 25) / 26);
  }

  /*
   * Addition
   */

  add(num) {
    return this.clone().iadd(num);
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  /*
   * Subtraction
   */

  sub(num) {
    return this.clone().isub(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  /*
   * Multiplication
   */

  mul(num) {
    return this.clone().imul(num);
  }

  muln(num) {
    return this.clone().imuln(num);
  }

  /*
   * Division
   */

  divmod(num, mode, positive) {
    if (typeof mode === 'boolean')
      [mode, positive] = [positive, mode];

    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(mode == null || typeof mode === 'string', 'mode', 'string');
    enforce(positive == null || typeof positive === 'boolean',
            'positive', 'boolean');

    if (mode != null && mode !== 'div' && mode !== 'mod')
      throw new TypeError('"mode" must be "div" or "mod".');

    let div = null;
    let mod = null;

    if (!mode || mode === 'div')
      div = this.div(num);

    if (!mode || mode === 'mod')
      mod = positive ? this.umod(num) : this.mod(num);

    return [div, mod];
  }

  div(num) {
    return this.clone().idiv(num);
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  /*
   * Round Division
   */

  divRound(num) {
    return this.clone().idivRound(num);
  }

  /*
   * Modulo
   */

  mod(num) {
    return this.clone().imod(num);
  }

  modn(num) {
    return this.clone().imodn(num);
  }

  /*
   * Unsigned Modulo
   */

  umod(num) {
    return this.clone().iumod(num);
  }

  umodn(num) {
    return this.clone().iumodn(num);
  }

  /*
   * Exponentiation
   */

  pow(num) {
    return this.clone().ipow(num);
  }

  pown(num) {
    return this.clone().ipown(num);
  }

  sqr() {
    return this.clone().isqr();
  }

  sqrt() {
    return this.clone().isqrt();
  }

  /*
   * AND
   */

  and(num) {
    return this.clone().iand(num);
  }

  andn(num) {
    return this.clone().iandn(num);
  }

  /*
   * Unsigned AND
   */

  uand(num) {
    return this.clone().iuand(num);
  }

  uandn(num) {
    return this.clone().iuandn(num);
  }

  /*
   * OR
   */

  or(num) {
    return this.clone().ior(num);
  }

  orn(num) {
    return this.clone().iorn(num);
  }

  /*
   * Unsigned OR
   */

  uor(num) {
    return this.clone().iuor(num);
  }

  uorn(num) {
    return this.clone().iuorn(num);
  }

  /*
   * XOR
   */

  xor(num) {
    return this.clone().ixor(num);
  }

  xorn(num) {
    return this.clone().ixorn(num);
  }

  /*
   * Unsigned XOR
   */

  uxor(num) {
    return this.clone().ixor(num);
  }

  uxorn(num) {
    return this.clone().iuxorn(num);
  }

  /*
   * NOT
   */

  notn(width) {
    return this.clone().inotn(width);
  }

  /*
   * Left Shift
   */

  ishl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    return this.ishln(num.toNumber());
  }

  shl(num) {
    return this.clone().ishl(num);
  }

  shln(bits) {
    return this.clone().ishln(bits);
  }

  /*
   * Unsigned Left Shift
   */

  iushl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    return this.iushln(num.toNumber());
  }

  ushl(num) {
    return this.clone().iushl(num);
  }

  ushln(bits) {
    return this.clone().iushln(bits);
  }

  /*
   * Right Shift
   */

  ishr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    return this.ishrn(num.toNumber());
  }

  shr(num) {
    return this.clone().ishr(num);
  }

  shrn(bits) {
    return this.clone().ishrn(bits);
  }

  /*
   * Unsigned Right Shift
   */

  iushr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    return this.iushrn(num.toNumber());
  }

  ushr(num) {
    return this.clone().iushr(num);
  }

  ushrn(bits) {
    return this.clone().iushrn(bits);
  }

  /*
   * Bit Manipulation
   */

  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  /*
   * Negation
   */

  neg() {
    return this.clone().ineg();
  }

  abs() {
    return this.clone().iabs();
  }

  /*
   * Comparison
   */

  gt(num) {
    return this.cmp(num) > 0;
  }

  gtn(num) {
    return this.cmpn(num) > 0;
  }

  gte(num) {
    return this.cmp(num) >= 0;
  }

  gten(num) {
    return this.cmpn(num) >= 0;
  }

  lt(num) {
    return this.cmp(num) < 0;
  }

  ltn(num) {
    return this.cmpn(num) < 0;
  }

  lte(num) {
    return this.cmp(num) <= 0;
  }

  lten(num) {
    return this.cmpn(num) <= 0;
  }

  /*
   * Unsigned Comparison
   */

  /*
   * Number Theoretic Functions
   */

  gcd(num) {
    return this.clone().igcd(num);
  }

  egcd(p) {
    const s = new BN();
    const t = new BN();
    const g = new BN();
    super.egcd(s, t, g, p);
    return [s, t, g];
  }

  invm(num) {
    return this.clone().iinvm(num);
  }

  finvm(num) {
    return this.clone().ifinvm(num);
  }

  powm(y, m, mont) {
    return this.clone().ipowm(y, m, mont);
  }

  powmn(y, m, mont) {
    return this.clone().ipowmn(y, m, mont);
  }

  sqrtp(p) {
    return this.clone().isqrtp(p);
  }

  sqrtpq(p, q) {
    return this.clone().isqrtpq(p, q);
  }

  /*
   * Primality Testing
   */

  isPrime(rng, reps, limit) {
    enforce((reps >>> 0) === reps, 'reps', 'integer');

    if (!this.isPrimeMR(rng, reps + 1, true))
      return false;

    if (!this.isPrimeLucas(limit))
      return false;

    return true;
  }

  isPrimeMR(rng, reps, force2) {
    if (force2 == null)
      force2 = false;

    return super.isPrimeMR(rng, reps, force2);
  }

  isPrimeLucas(limit) {
    if (limit == null)
      limit = 0;

    return super.isPrimeLucas(limit);
  }

  /*
   * Twos Complement
   */

  /*
   * Reduction Context
   */

  toRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red)
      throw new Error('Already in reduction context.');

    range(this.negative === 0, 'toRed');

    return ctx.convertTo(this)._forceRed(ctx);
  }

  fromRed() {
    red(this.red, 'fromRed');
    return this.red.convertFrom(this);
  }

  forceRed(ctx) {
    if (this.red)
      throw new Error('Already in reduction context.');

    return this._forceRed(ctx);
  }

  redIAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIAdd');
    return this.red.iadd(this, num);
  }

  redAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redAdd');
    return this.red.add(this, num);
  }

  redISub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redISub');
    return this.red.isub(this, num);
  }

  redSub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redSub');
    return this.red.sub(this, num);
  }

  redIShln(num) {
    enforce(isInteger(num), 'num', 'integer');
    red(this.red, 'redIShln');
    return this.red.ishln(this, num);
  }

  redShln(num) {
    enforce(isInteger(num), 'num', 'integer');
    red(this.red, 'redShln');
    return this.red.shln(this, num);
  }

  redIMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIMul');
    return this.red.imul(this, num);
  }

  redMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redMul');
    return this.red.mul(this, num);
  }

  redISqr() {
    red(this.red, 'redISqr');
    return this.red.isqr(this);
  }

  redSqr() {
    red(this.red, 'redSqr');
    return this.red.sqr(this);
  }

  redISqrt() {
    red(this.red, 'redISqrt');
    return this.red.isqrt(this);
  }

  redSqrt() {
    red(this.red, 'redSqrt');
    return this.red.sqrt(this);
  }

  redIInvm() {
    red(this.red, 'redIInvm');
    return this.red.iinvm(this);
  }

  redInvm() {
    red(this.red, 'redInvm');
    return this.red.invm(this);
  }

  redIFinvm() {
    red(this.red, 'redIFinvm');
    return this.red.ifinvm(this);
  }

  redFinvm() {
    red(this.red, 'redFinvm');
    return this.red.finvm(this);
  }

  redINeg() {
    red(this.red, 'redINeg');
    return this.red.ineg(this);
  }

  redNeg() {
    red(this.red, 'redNeg');
    return this.red.neg(this);
  }

  redJacobi() {
    red(this.red, 'redJacobi');
    return this.red.jacobi(this);
  }

  redIPow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIPow');
    nonred(!num.red, 'redIPow');
    return this.red.ipow(this, num);
  }

  redPow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redPow');
    nonred(!num.red, 'redPow');
    return this.red.pow(this, num);
  }

  /*
   * Internal
   */

  _move(dest) {
    dest.inject(this);
  }

  _expand(size) {
    return this;
  }

  _strip() {
    return this;
  }

  _normSign() {
    return this;
  }

  _forceRed(ctx) {
    this.red = ctx;
    return this;
  }

  /*
   * Helpers
   */

  clone() {
    const n = new BN();
    return n.inject(this);
  }

  copy(dest) {
    enforce(BN.isBN(dest), 'dest', 'bignum');
    dest.inject(this);
  }

  inject(num) {
    super.inject(num);
    this.red = num.red;
    return this;
  }

  set(num, endian) {
    return this.fromNumber(num, endian);
  }

  swap() {
    const neg = this.negative;

    this.fromBuffer(this.toBuffer('le'), 'be');
    this.negative = neg;

    return this;
  }

  [custom]() {
    let prefix = 'BN';

    if (this.red)
      prefix = 'BN-R';

    return `<${prefix}: ${this.toString(10)}>`;
  }

  /*
   * Conversion
   */

  valueOf() {
    return this.toDouble();
  }

  toBigInt() {
    const str = super.toString(16);

    let n = BigInt(`0x${str}`);

    if (this.isNeg())
      n = -n;

    return n;
  }

  toString(base, padding) {
    let str = super.toString(getBase(base));

    if (padding == null)
      padding = 0;

    if (padding === 0)
      padding = 1;

    enforce((padding >>> 0) === padding, 'padding', 'integer');

    while (str.length % padding)
      str = '0' + str;

    if (this.isNeg())
      str = '-' + str;

    return str;
  }

  toJSON() {
    return this.toString(16, 2);
  }

  toArray(endian, length) {
    // 1.75x faster than the common case.
    const buf = this.toBuffer(endian, length);

    if (Array.from)
      return Array.from(buf);

    return Array.prototype.slice.call(buf);
  }

  toBuffer(endian, length) {
    if (endian == null)
      endian = 'be';

    if (length == null)
      length = 0;

    return super.toBuffer(endian, length);
  }

  toArrayLike(ArrayType, endian, length) {
    if (ArrayType === Buffer)
      return this.toBuffer(endian, length);

    if (ArrayType === Array)
      return this.toArray(endian, length);

    if (ArrayType === Int8Array
        || ArrayType === Uint8Array
        || ArrayType === Uint8ClampedArray) {
      const buf = this.toBuffer(endian, length);
      return new ArrayType(buf.buffer, buf.byteOffset, buf.byteLength);
    }

    enforce(typeof ArrayType === 'function', 'ArrayType', 'function');

    const buf = this.toBuffer(endian, length);
    const arr = allocate(ArrayType, buf.length);

    for (let i = 0; i < buf.length; i++)
      arr[i] = buf[i];

    return arr;
  }

  encode(endian, length) {
    return this.toBuffer(endian, length);
  }

  /*
   * Instantiation
   */

  of(num, endian) {
    return this.fromNumber(num, endian);
  }

  fromNumber(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    super.fromNumber(num);

    if (endian === 'le')
      this.swap();

    return this;
  }

  fromDouble(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'number', 'num', 'double');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (!isFinite(num))
      num = 0;

    super.fromDouble(num);

    if (endian === 'le')
      this.swap();

    return this;
  }

  fromBigInt(num, endian) {
    enforce(typeof num === 'bigint', 'num', 'bigint');
    return this.fromString(num.toString(16), 16, endian);
  }

  fromString(str, base, endian) {
    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (endian == null)
      endian = 'be';

    super.fromString(str, getBase(base));

    if (endian === 'le')
      this.swap();

    return this;
  }

  fromJSON(json) {
    return this.fromString(json, 16);
  }

  fromBN(num) {
    return this.inject(num);
  }

  fromArray(data, endian) {
    enforce(Array.isArray(data), 'data', 'array');
    return this.fromBuffer(Buffer.from(data), endian);
  }

  fromBuffer(data, endian) {
    if (endian == null)
      endian = 'be';

    return super.fromBuffer(data, endian);
  }

  fromArrayLike(data, endian) {
    if (Buffer.isBuffer(data))
      return this.fromBuffer(data, endian);

    if (Array.isArray(data))
      return this.fromArray(data, endian);

    if ((data instanceof Int8Array)
        || (data instanceof Uint8Array)
        || (data instanceof Uint8ClampedArray)) {
      const raw = Buffer.from(data.buffer,
                              data.byteOffset,
                              data.byteLength);

      return this.fromBuffer(raw, endian);
    }

    return this.fromBuffer(Buffer.from(data), endian);
  }

  decode(data, endian) {
    return this.fromBuffer(data, endian);
  }

  from(num, base, endian) {
    if (num == null)
      return this;

    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (typeof num === 'number')
      return this.fromNumber(num, endian);

    if (typeof num === 'bigint')
      return this.fromBigInt(num, endian);

    if (typeof num === 'string')
      return this.fromString(num, base, endian);

    if (typeof num === 'object') {
      if (BN.isBN(num))
        return this.fromBN(num, endian);

      if (Buffer.isBuffer(num))
        return this.fromBuffer(num, endian);

      if (typeof num.length === 'number')
        return this.fromArrayLike(num, endian);
    }

    if (typeof num === 'boolean')
      return this.fromBool(num);

    throw new TypeError('Non-numeric object passed to BN.');
  }

  /*
   * Static Methods
   */

  static min(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b) < 0 ? a : b;
  }

  static max(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b) > 0 ? a : b;
  }

  static cmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b);
  }

  static ucmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.ucmp(b);
  }

  static red(num) {
    return new Red(num);
  }

  static mont(num) {
    return new Red(num);
  }

  static _prime(name) {
    if (primes[name])
      return primes[name];

    let prime;

    if (name === 'p192')
      prime = new P192();
    else if (name === 'p224')
      prime = new P224();
    else if (name === 'p521')
      prime = new P521();
    else if (name === 'k256')
      prime = new K256();
    else if (name === 'p25519')
      prime = new P25519();
    else if (name === 'p448')
      prime = new P448();
    else
      throw new Error('Unknown prime ' + name);

    primes[name] = prime;

    return prime;
  }

  static pow(num, exp) {
    return new BN().fromNumber(num).ipown(exp);
  }

  static shift(num, bits) {
    return new BN().fromNumber(num).ishln(bits);
  }

  static randomBits(rng, bits) {
    return super.randomBits(rng, new BN(), bits);
  }

  static random(rng, min, max) {
    const a = new BN();
    const b = new BN(min, 16);
    const c = new BN(max, 16);
    return super.random(rng, a, b, c);
  }

  static of(num, endian) {
    return new BN().of(num, endian);
  }

  static fromNumber(num, endian) {
    return new BN().fromNumber(num, endian);
  }

  static fromDouble(num, endian) {
    return new BN().fromDouble(num, endian);
  }

  static fromBigInt(num, endian) {
    return new BN().fromBigInt(num, endian);
  }

  static fromBool(value) {
    return new BN().fromBool(value);
  }

  static fromString(str, base, endian) {
    return new BN().fromString(str, base, endian);
  }

  static fromJSON(json) {
    return new BN().fromJSON(json);
  }

  static fromBN(num) {
    return new BN().fromBN(num);
  }

  static fromArray(data, endian) {
    return new BN().fromArray(data, endian);
  }

  static fromBuffer(data, endian) {
    return new BN().fromBuffer(data, endian);
  }

  static fromArrayLike(data, endian) {
    return new BN().fromArrayLike(data, endian);
  }

  static decode(data, endian) {
    return new BN().decode(data, endian);
  }

  static from(num, base, endian) {
    return new BN().from(num, base, endian);
  }

  static isBN(obj) {
    return obj instanceof BN;
  }
}

/*
 * Static
 */

BN.BN = BN;
BN.wordSize = 26;
BN.native = 2;

/**
 * Prime
 */

class Prime {
  constructor(name, p) {
    this.name = name;
    this.p = new BN(p, 16);
  }
}

/**
 * P192
 */

class P192 extends Prime {
  constructor() {
    super('p192', 'ffffffff ffffffff ffffffff fffffffe'
                + 'ffffffff ffffffff');
  }
}

/**
 * P224
 */

class P224 extends Prime {
  constructor() {
    super('p224', 'ffffffff ffffffff ffffffff ffffffff'
                + '00000000 00000000 00000001');
  }
}

/**
 * P521
 */

class P521 extends Prime {
  constructor() {
    super('p521', '000001ff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff');
  }
}

/**
 * K256
 */

class K256 extends Prime {
  constructor() {
    super('k256', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe fffffc2f');
  }
}

/**
 * P25519
 */

class P25519 extends Prime {
  constructor() {
    // 2^255 - 19
    super('p25519', '7fffffff ffffffff ffffffff ffffffff'
                  + 'ffffffff ffffffff ffffffff ffffffed');
  }
}

/**
 * P448
 */

class P448 extends Prime {
  constructor() {
    // 2^448 - 2^224 - 1
    super('p448', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff');
  }
}

/**
 * Reduction Engine
 */

class Red {
  constructor(m) {
    if (typeof m === 'string')
      m = BN._prime(m).p;

    enforce(BN.isBN(m), 'm', 'bignum');
    range(m.cmpn(1) > 0, 'reduction');

    this.m = m;
  }

  _verify1(a) {
    range(a.negative === 0, 'red');
    red(a.red, 'red');
  }

  _verify2(a, b) {
    range((a.negative | b.negative) === 0, 'red');
    red(a.red && a.red === b.red, 'red');
  }

  ineg(a) {
    this._verify1(a);

    if (!a.isZero())
      this.m.sub(a)._forceRed(this)._move(a);

    return a;
  }

  neg(a) {
    return this.ineg(a.clone());
  }

  iadd(a, b) {
    this._verify2(a, b);

    a.iadd(b);

    if (a.cmp(this.m) >= 0)
      a.isub(this.m);

    return a;
  }

  add(a, b) {
    return this.iadd(a.clone(), b);
  }

  isub(a, b) {
    this._verify2(a, b);

    a.isub(b);

    if (a.isNeg())
      a.iadd(this.m);

    return a;
  }

  sub(a, b) {
    return this.isub(a.clone(), b);
  }

  ishln(a, num) {
    this._verify1(a);

    a.iushln(num);
    a.iumod(this.m);

    return a;
  }

  shln(a, num) {
    return this.ishln(a.clone(), num);
  }

  imul(a, b) {
    this._verify2(a, b);

    a.imul(b);
    a.iumod(this.m);

    return a;
  }

  mul(a, b) {
    this._verify2(a, b);
    return this.imul(a.clone(), b);
  }

  isqr(a) {
    this._verify1(a);

    a.isqr();
    a.iumod(this.m);

    return a;
  }

  sqr(a) {
    return this.isqr(a.clone());
  }

  isqrt(a) {
    this._verify1(a);

    a.isqrtp(this.m);

    return a;
  }

  sqrt(a) {
    return this.isqrt(a.clone());
  }

  iinvm(a) {
    this._verify1(a);

    a.iinvm(this.m);

    return a;
  }

  invm(a) {
    return this.iinvm(a.clone());
  }

  ifinvm(a) {
    this._verify1(a);

    a.ifinvm(this.m);

    return a;
  }

  finvm(a) {
    return this.ifinvm(a.clone());
  }

  jacobi(a) {
    this._verify1(a);
    return a.jacobi(this.m);
  }

  ipow(a, num) {
    this._verify1(a);

    a.ipowm(num, this.m, false);

    return a;
  }

  pow(a, num) {
    return this.ipow(a.clone(), num);
  }

  convertTo(num) {
    const b = num.umod(this.m);
    b.red = this;
    return b;
  }

  convertFrom(num) {
    const res = num.clone();
    res.red = null;
    return res;
  }

  [custom]() {
    return `<Red: ${this.m.toString(10)}>`;
  }
}

/*
 * Helpers
 */

function makeError(Error, msg, start) {
  const err = new Error(msg);

  if (Error.captureStackTrace)
    Error.captureStackTrace(err, start);

  return err;
}

function enforce(value, name, type) {
  if (!value) {
    const msg = `"${name}" must be a(n) ${type}.`;
    throw makeError(TypeError, msg, enforce);
  }
}

function range(value, name) {
  if (!value) {
    const msg = `"${name}" only works with positive numbers.`;
    throw makeError(RangeError, msg, range);
  }
}

function red(value, name) {
  if (!value) {
    const msg = `"${name}" only works with red numbers.`;
    throw makeError(TypeError, msg, red);
  }
}

function nonred(value, name) {
  if (!value) {
    const msg = `"${name}" only works with normal numbers.`;
    throw makeError(TypeError, msg, red);
  }
}

function isInteger(num) {
  return Number.isSafeInteger(num);
}

function allocate(ArrayType, size) {
  if (ArrayType.allocUnsafe)
    return ArrayType.allocUnsafe(size);

  return new ArrayType(size);
}

function getBase(base) {
  if (base == null)
    return 10;

  if (typeof base === 'number')
    return base;

  switch (base) {
    case 'bin':
      return 2;
    case 'oct':
      return 8;
    case 'dec':
      return 10;
    case 'hex':
      return 16;
  }

  return 0;
}

/*
 * Expose
 */

module.exports = BN;
