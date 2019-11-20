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

/*
 * Constants
 */

const zeros = [
  '',
  '0',
  '00',
  '000',
  '0000',
  '00000',
  '000000',
  '0000000',
  '00000000',
  '000000000',
  '0000000000',
  '00000000000',
  '000000000000',
  '0000000000000',
  '00000000000000',
  '000000000000000',
  '0000000000000000',
  '00000000000000000',
  '000000000000000000',
  '0000000000000000000',
  '00000000000000000000',
  '000000000000000000000',
  '0000000000000000000000',
  '00000000000000000000000',
  '000000000000000000000000',
  '0000000000000000000000000'
];

const groupSizes = [
  0, 0,
  25, 16, 12, 11, 10, 9, 8,
  8, 7, 7, 7, 7, 6, 6,
  6, 6, 6, 6, 6, 5, 5,
  5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5
];

const groupBases = [
  0, 0,
  33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216,
  43046721, 10000000, 19487171, 35831808, 62748517, 7529536, 11390625,
  16777216, 24137569, 34012224, 47045881, 64000000, 4084101, 5153632,
  6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149,
  24300000, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176
];

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

class BN {
  constructor(num, base, endian) {
    if (BN.isBN(num))
      return num;

    this.words = [0];
    this.length = 1;
    this.negative = 0;
    this.red = null;

    this.from(num, base, endian);
  }

  /*
   * Addition
   */

  iadd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    // negative + positive
    if (this.negative !== 0 && num.negative === 0) {
      this.negative = 0;
      this.isub(num);
      this.negative ^= 1;
      return this._normSign();
    }

    // positive + negative
    if (this.negative === 0 && num.negative !== 0) {
      num.negative = 0;
      const r = this.isub(num);
      num.negative = 1;
      return r._normSign();
    }

    // a.length > b.length
    let a = this;
    let b = num;

    if (a.length <= b.length)
      [a, b] = [b, a];

    let carry = 0;
    let i = 0;

    for (; i < b.length; i++) {
      const r = (a.words[i] | 0) + (b.words[i] | 0) + carry;

      this.words[i] = r & 0x3ffffff;

      carry = r >>> 26;
    }

    for (; carry !== 0 && i < a.length; i++) {
      const r = (a.words[i] | 0) + carry;

      this.words[i] = r & 0x3ffffff;

      carry = r >>> 26;
    }

    this.length = a.length;

    if (carry !== 0) {
      this.words[this.length] = carry;
      this.length += 1;
    } else if (a !== this) {
      // Copy the rest of the words.
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    return this;
  }

  iaddn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (num < 0)
      return this.isubn(-num);

    // Possible sign change.
    if (this.negative !== 0) {
      if (this.length === 1 && (this.words[0] | 0) <= num) {
        this.words[0] = num - (this.words[0] | 0);
        this.negative = 0;
        return this;
      }

      this.negative = 0;
      this.isubn(num);
      this.negative = 1;

      return this;
    }

    // Add without checks.
    return this._iaddn(num);
  }

  _iaddn(num) {
    this.words[0] += num;

    // Carry.
    let i = 0;

    for (; i < this.length && this.words[i] >= 0x4000000; i++) {
      this.words[i] -= 0x4000000;

      if (i === this.length - 1)
        this.words[i + 1] = 1;
      else
        this.words[i + 1] += 1;
    }

    this.length = Math.max(this.length, i + 1);

    return this;
  }

  add(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (num.negative !== 0 && this.negative === 0) {
      num.negative = 0;
      const res = this.sub(num);
      num.negative ^= 1;
      return res;
    }

    if (num.negative === 0 && this.negative !== 0) {
      this.negative = 0;
      const res = num.sub(this);
      this.negative = 1;
      return res;
    }

    if (this.length > num.length)
      return this.clone().iadd(num);

    return num.clone().iadd(this);
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  /*
   * Subtraction
   */

  isub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    // this - (-num) = this + num
    if (num.negative !== 0) {
      num.negative = 0;
      const r = this.iadd(num);
      num.negative = 1;
      return r._normSign();
    }

    // -this - num = -(this + num)
    if (this.negative !== 0) {
      this.negative = 0;
      this.iadd(num);
      this.negative = 1;
      return this._normSign();
    }

    // At this point both numbers are positive.
    const cmp = this.cmp(num);

    // Optimization - zeroify.
    if (cmp === 0) {
      this.negative = 0;
      this.length = 1;
      this.words[0] = 0;
      return this;
    }

    // a > b
    let a = this;
    let b = num;

    if (cmp <= 0)
      [a, b] = [b, a];

    let carry = 0;
    let i = 0;

    for (; i < b.length; i++) {
      const r = (a.words[i] | 0) - (b.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }

    for (; carry !== 0 && i < a.length; i++) {
      const r = (a.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }

    // Copy rest of the words.
    if (carry === 0 && i < a.length && a !== this) {
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    this.length = Math.max(this.length, i);

    if (a !== this)
      this.negative = 1;

    return this._strip();
  }

  isubn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (num < 0)
      return this.iaddn(-num);

    if (this.negative !== 0) {
      this.negative = 0;
      this.iaddn(num);
      this.negative = 1;
      return this;
    }

    this.words[0] -= num;

    if (this.length === 1 && this.words[0] < 0) {
      this.words[0] = -this.words[0];
      this.negative = 1;
    } else {
      // Carry.
      for (let i = 0; i < this.length && this.words[i] < 0; i++) {
        this.words[i] += 0x4000000;
        this.words[i + 1] -= 1;
      }
    }

    return this._strip();
  }

  sub(num) {
    return this.clone().isub(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  /*
   * Multiplication
   */

  mulTo(num, out) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(BN.isBN(out), 'out', 'bignum');

    if (this.length === 10 && num.length === 10)
      return comb10MulTo(this, num, out);

    const len = this.length + num.length;

    if (len < 63)
      return smallMulTo(this, num, out);

    return bigMulTo(this, num, out);
  }

  imul(num) {
    return this.clone().mulTo(num, this);
  }

  imuln(num) {
    enforce(isSMI(num), 'num', 'smi');

    const neg = num < 0;

    if (neg)
      num = -num;

    // Carry.
    let carry = 0;
    let i = 0;

    for (; i < this.length; i++) {
      const w = (this.words[i] | 0) * num;
      const lo = (w & 0x3ffffff) + (carry & 0x3ffffff);

      carry >>= 26;
      carry += (w / 0x4000000) | 0;

      // Note: lo is 27bit maximum.
      carry += lo >>> 26;

      this.words[i] = lo & 0x3ffffff;
    }

    if (carry !== 0) {
      this.words[i] = carry;
      this.length += 1;
    }

    return neg ? this.ineg() : this;
  }

  mul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const out = new BN();

    out.words = new Array(this.length + num.length);

    return this.mulTo(num, out);
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

    nonzero(!num.isZero());

    if (mode != null && mode !== 'div' && mode !== 'mod')
      throw new TypeError('"mode" must be "div" or "mod".');

    if (this.isZero())
      return [new BN(0), new BN(0)];

    let div = null;
    let mod = null;

    if (this.negative !== 0 && num.negative === 0) {
      const [q, r] = this.neg().divmod(num, mode);

      if (mode !== 'mod')
        div = q.ineg();

      if (mode !== 'div') {
        mod = r.ineg();

        if (positive && mod.negative !== 0)
          mod.iadd(num);
      }

      return [div, mod];
    }

    if (this.negative === 0 && num.negative !== 0) {
      const [q, r] = this.divmod(num.neg(), mode);

      if (mode !== 'mod')
        div = q.ineg();

      return [div, r];
    }

    if ((this.negative & num.negative) !== 0) {
      const [q, r] = this.neg().divmod(num.neg(), mode);

      if (mode !== 'div') {
        mod = r.ineg();

        if (positive && mod.negative !== 0)
          mod.isub(num);
      }

      return [q, mod];
    }

    // Both numbers are positive at this point.
    // Strip both numbers to approximate shift value.
    if (num.length > this.length || this.cmp(num) < 0)
      return [new BN(0), this.clone()];

    // Very short reduction.
    if (num.length === 1) {
      const w = num.words[0];

      if (mode === 'div')
        return [this.divn(w), null];

      if (mode === 'mod')
        return [null, this.modn(w)];

      return [this.divn(w), this.modn(w)];
    }

    return this._wordDiv(num, mode);
  }

  idiv(num) {
    this.div(num)._move(this);
    return this;
  }

  idivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    const neg = num < 0;

    if (neg)
      num = -num;

    let carry = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      const w = (this.words[i] | 0) + carry * 0x4000000;

      this.words[i] = (w / num) | 0;

      carry = w % num;
    }

    this._strip();

    return neg ? this.ineg() : this;
  }

  div(num) {
    return this.divmod(num, 'div', false)[0];
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  /*
   * Round Division
   */

  divRound(num) {
    const [q, r] = this.divmod(num);

    // Fast case - exact division.
    if (r.isZero())
      return q;

    const mod = q.negative !== 0 ? r.isub(num) : r;

    const half = num.ushrn(1);
    const r2 = num.andln(1);
    const cmp = mod.cmp(half);

    // Round down.
    if (cmp < 0 || r2 === 1 && cmp === 0)
      return q;

    // Round up.
    return q.negative !== 0 ? q.isubn(1) : q.iaddn(1);
  }

  /*
   * Modulo
   */

  imod(num) {
    this.mod(num)._move(this);
    return this;
  }

  imodn(num) {
    let m = this.modrn(num);

    if (m < 0)
      m = -m;

    this.words[0] = m;
    this.length = 1;

    return this._normSign();
  }

  mod(num) {
    return this.divmod(num, 'mod', false)[1];
  }

  modn(num) {
    return this.clone().imodn(num);
  }

  modrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    if (num < 0)
      num = -num;

    const p = (1 << 26) % num;

    let acc = 0;

    for (let i = this.length - 1; i >= 0; i--)
      acc = (p * acc + (this.words[i] | 0)) % num;

    return this.negative ? (-acc | 0) : acc;
  }

  /*
   * Unsigned Modulo
   */

  iumod(num) {
    if (this.ucmp(num) < 0) {
      if (this.negative !== 0) {
        if (num.negative !== 0)
          this.isub(num);
        else
          this.iadd(num);
      }
      return this;
    }

    this.umod(num)._move(this);

    return this;
  }

  iumodn(num) {
    this.words[0] = this.umodrn(num);
    this.length = 1;
    this.negative = 0;
    return this;
  }

  umod(num) {
    return this.divmod(num, 'mod', true)[1];
  }

  umodn(num) {
    return this.clone().iumodn(num);
  }

  umodrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    let m = this.modrn(num);

    if (m < 0)
      m += Math.abs(num);

    return m;
  }

  /*
   * Exponentiation
   */

  ipow(num) {
    this.pow(num)._move(this);
    return this;
  }

  ipown(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (this.isZero())
      return this;

    if (num === 0) {
      this.words[0] = 1;
      this.length = 1;
      this.negative = 0;
      return this;
    }

    let x = this;
    let y = Math.abs(num);
    let r = new BN(1);

    while (y > 0) {
      if (y & 1)
        r = r.imul(x);

      y >>>= 1;
      x = x.isqr();
    }

    r._move(this);

    return this;
  }

  pow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const w = toBitArray(num);

    if (w.length === 0)
      return new BN(1);

    // Skip leading zeroes.
    let res = this;
    let i = 0;

    for (; i < w.length; i++, res = res.sqr()) {
      if (w[i] !== 0)
        break;
    }

    if (++i < w.length) {
      for (let q = res.sqr(); i < w.length; i++, q = q.sqr()) {
        if (w[i] === 0)
          continue;

        res = res.mul(q);
      }
    }

    return res;
  }

  pown(num) {
    return this.clone().ipown(num);
  }

  isqr() {
    return this.imul(this.clone());
  }

  sqr() {
    return this.mul(this);
  }

  isqrt() {
    this.sqrt()._move(this);
    return this;
  }

  sqrt() {
    range(this.negative === 0, 'sqrt');

    if (this.cmpn(1) <= 0)
      return this.clone();

    let r = new BN(1);

    r.iushln((this.bitLength() >>> 1) + 1);

    for (;;) {
      const z = this.div(r);

      z.iadd(r);
      z.iushrn(1);

      if (z.cmp(r) >= 0)
        break;

      r = z;
    }

    return r;
  }

  isSquare() {
    if (this.negative !== 0)
      return false;

    return this.sqrt().isqr().eq(this);
  }

  /*
   * AND
   */

  iand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range((this.negative | num.negative) === 0, 'iand');
    return this.iuand(num);
  }

  iandn(num) {
    enforce(isSMI(num), 'num', 'smi');
    range((this.negative | (num < 0)) === 0, 'iandn');

    this.words[0] &= num;
    this.length = 1;

    return this;
  }

  and(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length > num.length)
      return this.clone().iand(num);

    return num.clone().iand(this);
  }

  andn(num) {
    return this.clone().iandn(num);
  }

  andrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    range((this.negative | (num < 0)) === 0, 'andrn');
    return this.words[0] & num;
  }

  /*
   * Unsigned AND
   */

  iuand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const len = Math.min(this.length, num.length);

    for (let i = 0; i < len; i++)
      this.words[i] = this.words[i] & num.words[i];

    this.length = len;

    return this._strip();
  }

  iuandn(num) {
    enforce(isSMI(num), 'num', 'smi');
    this.words[0] &= Math.abs(num);
    this.length = 1;
    return this._normSign();
  }

  uand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length > num.length)
      return this.clone().iuand(num);

    return num.clone().iuand(this);
  }

  uandn(num) {
    return this.clone().iuandn(num);
  }

  uandrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const n = this.words[0] & Math.abs(num);

    return this.negative !== 0 ? (-n | 0) : n;
  }

  /*
   * OR
   */

  ior(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range((this.negative | num.negative) === 0, 'ior');
    return this.iuor(num);
  }

  iorn(num) {
    enforce(isSMI(num), 'num', 'smi');
    range((this.negative | (num < 0)) === 0, 'iorn');
    this.words[0] |= num;
    return this;
  }

  or(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length > num.length)
      return this.clone().ior(num);

    return num.clone().ior(this);
  }

  orn(num) {
    return this.clone().iorn(num);
  }

  /*
   * Unsigned OR
   */

  iuor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    while (this.length < num.length)
      this.words[this.length++] = 0;

    for (let i = 0; i < num.length; i++)
      this.words[i] = this.words[i] | num.words[i];

    return this._strip();
  }

  iuorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] |= Math.abs(num);

    return this;
  }

  uor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length > num.length)
      return this.clone().iuor(num);

    return num.clone().iuor(this);
  }

  uorn(num) {
    return this.clone().iuorn(num);
  }

  /*
   * XOR
   */

  ixor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range((this.negative | num.negative) === 0, 'ixor');
    return this.iuxor(num);
  }

  ixorn(num) {
    enforce(isSMI(num), 'num', 'smi');
    range((this.negative | (num < 0)) === 0, 'ixorn');
    this.words[0] ^= num;
    return this;
  }

  xor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length > num.length)
      return this.clone().ixor(num);

    return num.clone().ixor(this);
  }

  xorn(num) {
    return this.clone().ixorn(num);
  }

  /*
   * Unsigned XOR
   */

  iuxor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let a = this;
    let b = num;

    if (a.length <= b.length)
      [a, b] = [b, a];

    let i = 0;

    for (; i < b.length; i++)
      this.words[i] = a.words[i] ^ b.words[i];

    if (a !== this) {
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    this.length = a.length;

    return this._strip();
  }

  iuxorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] ^= Math.abs(num);

    return this._normSign();
  }

  uxor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length > num.length)
      return this.clone().iuxor(num);

    return num.clone().iuxor(this);
  }

  uxorn(num) {
    return this.clone().iuxorn(num);
  }

  /*
   * NOT
   */

  inotn(width) {
    enforce(isInteger(width), 'width', 'integer');
    range(width >= 0, 'inotn');

    const bitsLeft = width % 26;

    let bytesNeeded = Math.ceil(width / 26) | 0;
    let i = 0;

    // Extend the buffer with leading zeroes.
    this._expand(bytesNeeded);

    if (bitsLeft > 0)
      bytesNeeded--;

    // Handle complete words.
    for (; i < bytesNeeded; i++)
      this.words[i] = ~this.words[i] & 0x3ffffff;

    // Handle the residue.
    if (bitsLeft > 0)
      this.words[i] = ~this.words[i] & (0x3ffffff >> (26 - bitsLeft));

    // And remove leading zeroes.
    return this._strip();
  }

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

  ishln(bits) {
    range(this.negative === 0, 'ishln');
    return this.iushln(bits);
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

  iushln(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range(bits >= 0, 'iushln');

    const r = bits % 26;
    const s = (bits - r) / 26;
    const carryMask = (0x3ffffff >>> (26 - r)) << (26 - r);

    if (r !== 0) {
      let carry = 0;
      let i = 0;

      for (; i < this.length; i++) {
        const newCarry = this.words[i] & carryMask;
        const c = ((this.words[i] | 0) - newCarry) << r;

        this.words[i] = c | carry;

        carry = newCarry >>> (26 - r);
      }

      if (carry) {
        this.words[i] = carry;
        this.length += 1;
      }
    }

    if (s !== 0) {
      for (let i = this.length - 1; i >= 0; i--)
        this.words[i + s] = this.words[i];

      for (let i = 0; i < s; i++)
        this.words[i] = 0;

      this.length += s;
    }

    return this._strip();
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

  ishrn(bits) {
    range(this.negative === 0, 'ishrn');
    return this.iushrn(bits);
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

  iushrn(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range(bits >= 0, 'iushrn');
    return this._split(bits, 0, null);
  }

  _split(bits, hint, extended) {
    let h = 0;

    if (hint)
      h = (hint - (hint % 26)) / 26;

    const r = bits % 26;
    const s = Math.min((bits - r) / 26, this.length);
    const mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
    const maskedWords = extended;

    h -= s;
    h = Math.max(0, h);

    // Extended mode, copy masked part.
    if (maskedWords) {
      for (let i = 0; i < s; i++)
        maskedWords.words[i] = this.words[i];

      maskedWords.length = s;
    }

    if (s === 0) {
      // No-op, we should not move anything at all.
    } else if (this.length > s) {
      this.length -= s;
      for (let i = 0; i < this.length; i++)
        this.words[i] = this.words[i + s];
    } else {
      this.words[0] = 0;
      this.length = 1;
    }

    let carry = 0;

    for (let i = this.length - 1; i >= 0 && (carry !== 0 || i >= h); i--) {
      const word = this.words[i] | 0;

      this.words[i] = (carry << (26 - r)) | (word >>> r);

      carry = word & mask;
    }

    // Push carried bits as a mask.
    if (maskedWords && carry !== 0)
      maskedWords.words[maskedWords.length++] = carry;

    if (maskedWords && maskedWords.length === 0) {
      maskedWords.words[0] = 0;
      maskedWords.length = 1;
    }

    if (this.length === 0) {
      this.words[0] = 0;
      this.length = 1;
    }

    return this._strip();
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

  setn(bit, val) {
    enforce(isInteger(bit), 'bit', 'integer');
    range(bit >= 0, 'setn');

    const off = (bit / 26) | 0;
    const wbit = bit % 26;

    this._expand(off + 1);

    if (val)
      this.words[off] |= (1 << wbit);
    else
      this.words[off] &= ~(1 << wbit);

    return this._strip();
  }

  testn(bit) {
    enforce(isInteger(bit), 'bit', 'integer');
    range(bit >= 0, 'bit');

    const r = bit % 26;
    const s = (bit - r) / 26;
    const q = 1 << r;

    // Fast case: bit is much higher than all existing words.
    if (this.length <= s)
      return false;

    // Check bit and return.
    const w = this.words[s];

    return (w & q) !== 0;
  }

  imaskn(bits) {
    enforce(isInteger(bits), 'bits', 'integer');
    range((this.negative | (bits < 0)) === 0, 'imaskn');

    const r = bits % 26;

    let s = (bits - r) / 26;

    if (this.length <= s)
      return this;

    if (r !== 0)
      s += 1;

    this.length = Math.min(s, this.length);

    if (r !== 0) {
      const mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);

      this.words[this.length - 1] &= mask;
    }

    if (this.length === 0) {
      this.words[0] = 0;
      this.length = 1;
    }

    return this._strip();
  }

  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  andln(num) {
    enforce(isInteger(num), 'num', 'integer');
    return this.words[0] & num;
  }

  bincn(bit) {
    enforce(isInteger(bit), 'bit', 'integer');

    const r = bit % 26;
    const s = (bit - r) / 26;
    const q = 1 << r;

    // Fast case: bit is much higher than all existing words.
    if (this.length <= s) {
      this._expand(s + 1);
      this.words[s] |= q;
      return this;
    }

    // Add bit and propagate, if needed.
    let carry = q;
    let i = s;

    for (; carry !== 0 && i < this.length; i++) {
      let w = this.words[i] | 0;

      w += carry;
      carry = w >>> 26;
      w &= 0x3ffffff;

      this.words[i] = w;
    }

    if (carry !== 0) {
      this.words[i] = carry;
      this.length += 1;
    }

    return this;
  }

  /*
   * Negation
   */

  ineg() {
    if (!this.isZero())
      this.negative ^= 1;

    return this;
  }

  neg() {
    return this.clone().ineg();
  }

  iabs() {
    this.negative = 0;
    return this;
  }

  abs() {
    return this.clone().iabs();
  }

  /*
   * Comparison
   */

  cmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.negative !== 0 && num.negative === 0)
      return -1;

    if (this.negative === 0 && num.negative !== 0)
      return 1;

    const res = this.ucmp(num);

    if (this.negative !== 0)
      return -res | 0;

    return res;
  }

  cmpn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const negative = num < 0;

    if (this.negative !== 0 && !negative)
      return -1;

    if (this.negative === 0 && negative)
      return 1;

    this._strip();

    let res = 1;

    if (this.length <= 1) {
      if (negative)
        num = -num;

      const w = this.words[0] | 0;

      if (w === num)
        res = 0;
      else
        res = w < num ? -1 : 1;
    }

    if (this.negative !== 0)
      return -res | 0;

    return res;
  }

  eq(num) {
    return this.cmp(num) === 0;
  }

  eqn(num) {
    return this.cmpn(num) === 0;
  }

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

  isZero() {
    return this.length === 1 && this.words[0] === 0;
  }

  isNeg() {
    return this.negative !== 0;
  }

  isOdd() {
    return (this.words[0] & 1) === 1;
  }

  isEven() {
    return (this.words[0] & 1) === 0;
  }

  /*
   * Unsigned Comparison
   */

  ucmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    // At this point both numbers have the same sign.
    if (this.length > num.length)
      return 1;

    if (this.length < num.length)
      return -1;

    let res = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      const a = this.words[i] | 0;
      const b = num.words[i] | 0;

      if (a === b)
        continue;

      if (a < b)
        res = -1;
      else if (a > b)
        res = 1;

      break;
    }

    return res;
  }

  ucmpn(num) {
    enforce(isSMI(num), 'num', 'smi');

    num = (-this.negative * Math.abs(num)) | 0;

    return this.cmpn(num);
  }

  /*
   * Number Theoretic Functions
   */

  jacobi(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (num.isZero() || num.isEven())
      throw new Error('jacobi: `num` must be odd.');

    // See chapter 2, section 2.4:
    // http://yacas.sourceforge.net/Algo.book.pdf
    let a = this._cloneNormal();
    let b = num._cloneNormal();
    let j = 1;

    if (b.isNeg()) {
      if (a.isNeg())
        j = -1;
      b.ineg();
    }

    for (;;) {
      if (b.cmpn(1) === 0)
        return j;

      if (a.isZero())
        return 0;

      a = a.iumod(b);

      if (a.isZero())
        return 0;

      const s = a.zeroBits();

      if (s & 1) {
        const bmod8 = b.andln(7);

        if (bmod8 === 3 || bmod8 === 5)
          j = -j;
      }

      const c = a.iushrn(s);

      if (b.andln(3) === 3 && c.andln(3) === 3)
        j = -j;

      a = b;
      b = c;
    }
  }

  igcd(num) {
    this.gcd(num)._move(this);
    return this;
  }

  gcd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.isZero())
      return num.abs();

    if (num.isZero())
      return this.abs();

    let a = this.clone();
    let b = num.clone();
    let shift = 0;

    a.negative = 0;
    b.negative = 0;

    // Remove common factor of two.
    for (; a.isEven() && b.isEven(); shift++) {
      a.iushrn(1);
      b.iushrn(1);
    }

    for (;;) {
      while (a.isEven())
        a.iushrn(1);

      while (b.isEven())
        b.iushrn(1);

      const r = a.cmp(b);

      if (r < 0) {
        // Swap `a` and `b` to make `a` always bigger than `b`.
        [a, b] = [b, a];
      } else if (r === 0 || b.cmpn(1) === 0) {
        break;
      }

      a.isub(b);
    }

    return b.iushln(shift);
  }

  egcd(p) {
    enforce(BN.isBN(p), 'p', 'bignum');
    range((p.negative | p.isZero()) === 0, 'egcd');

    let x = this;

    const y = p.clone();

    if (x.negative !== 0)
      x = x.umod(p);
    else
      x = x.clone();

    // A * x + B * y = x
    const A = new BN(1);
    const B = new BN(0);

    // C * x + D * y = y
    const C = new BN(0);
    const D = new BN(1);

    let g = 0;

    while (x.isEven() && y.isEven()) {
      x.iushrn(1);
      y.iushrn(1);
      g += 1;
    }

    const yp = y.clone();
    const xp = x.clone();

    while (!x.isZero()) {
      let i = 0;

      for (let im = 1; (x.words[0] & im) === 0 && i < 26; im <<= 1)
        i += 1;

      if (i > 0) {
        x.iushrn(i);

        while (i-- > 0) {
          if (A.isOdd() || B.isOdd()) {
            A.iadd(yp);
            B.isub(xp);
          }

          A.iushrn(1);
          B.iushrn(1);
        }
      }

      let j = 0;

      for (let jm = 1; (y.words[0] & jm) === 0 && j < 26; jm <<= 1)
        j += 1;

      if (j > 0) {
        y.iushrn(j);

        while (j-- > 0) {
          if (C.isOdd() || D.isOdd()) {
            C.iadd(yp);
            D.isub(xp);
          }

          C.iushrn(1);
          D.iushrn(1);
        }
      }

      if (x.cmp(y) >= 0) {
        x.isub(y);
        A.isub(C);
        B.isub(D);
      } else {
        y.isub(x);
        C.isub(A);
        D.isub(B);
      }
    }

    return [C, D, y.iushln(g)];
  }

  iinvm(num) {
    this.invm(num)._move(this);
    return this;
  }

  invm(num) {
    const [s,, g] = this.egcd(num);

    if (g.cmpn(1) > 0)
      throw new Error('Not invertible.');

    return s.iumod(num);
  }

  ifinvm(num) {
    this.finvm(num)._move(this);
    return this;
  }

  finvm(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    // Invert using fermat's little theorem.
    return this.powm(num.subn(2), num, true);
  }

  ipowm(y, m, mont) {
    this.powm(y, m, mont)._move(this);
    return this;
  }

  powm(y, m, mont) {
    enforce(BN.isBN(m), 'm', 'bignum');

    if (m.cmpn(1) === 0)
      return new BN(0);

    const p = mont ? BN.mont(m) : BN.red(m);
    const n = this.toRed(p);

    return n.redPow(y).fromRed();
  }

  ipowmn(y, m, mont) {
    this.powmn(y, m, mont)._move(this);
    return this;
  }

  powmn(y, m, mont) {
    enforce(isSMI(y), 'y', 'smi');
    return this.powm(new BN(y), m, mont);
  }

  isqrtp(p) {
    this.sqrtp(p)._move(this);
    return this;
  }

  sqrtp(p) {
    enforce(BN.isBN(p), 'p', 'bignum');

    if (p.cmpn(1) === 0)
      return new BN(0);

    const n = this.toRed(BN.mont(p));

    return n.redSqrt().fromRed();
  }

  isqrtpq(p, q) {
    this.sqrtpq(p, q)._move(this);
    return this;
  }

  sqrtpq(p, q) {
    const sp = this.sqrtp(p);
    const sq = this.sqrtp(q);
    const [mp, mq] = p.egcd(q);
    const lhs = sq.imul(mp).imul(p);
    const rhs = sp.imul(mq).imul(q);
    const n = p.mul(q);

    return lhs.iadd(rhs).iumod(n);
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

  isPrimeMR(rng, reps, force2 = false) {
    enforce((reps >>> 0) === reps, 'reps', 'integer');
    enforce(reps > 0, 'reps', 'integer');
    enforce(typeof force2 === 'boolean', 'force2', 'boolean');

    const n = this;

    if (n.cmpn(7) < 0) {
      if (n.cmpn(2) === 0 || n.cmpn(3) === 0 || n.cmpn(5) === 0)
        return true;
      return false;
    }

    if (n.isEven())
      return false;

    const nm1 = n.subn(1);
    const nm3 = nm1.subn(2);
    const k = nm1.zeroBits();
    const q = nm1.ushrn(k);

    const red = BN.red(n);
    const rnm1 = nm1.toRed(red);
    const rone = new BN(1).toRed(red);

    // Miller-Rabin primality test.
next:
    for (let i = 0; i < reps; i++) {
      let x;

      if (i === reps - 1 && force2) {
        x = new BN(2);
      } else {
        x = BN.random(rng, 0, nm3);
        x.iaddn(2);
      }

      const y = x.toRed(red).redPow(q);

      if (y.cmp(rone) === 0 || y.cmp(rnm1) === 0)
        continue;

      for (let j = 1; j < k; j++) {
        y.redISqr();

        if (y.cmp(rnm1) === 0)
          continue next;

        if (y.cmp(rone) === 0)
          return false;
      }

      return false;
    }

    return true;
  }

  isPrimeLucas(limit = 0) {
    enforce((limit >>> 0) === limit, 'limit', 'integer');

    const n = this;

    // Ignore 0 and 1.
    if (n.cmpn(1) <= 0)
      return false;

    // Two is the only even prime.
    if (n.isEven())
      return n.cmpn(2) === 0;

    // Baillie-OEIS "method C" for choosing D, P, Q.
    // See: https://oeis.org/A217719/a217719.txt.
    let p = 3;

    for (;;) {
      if (p > 10000) {
        // Thought to be impossible.
        throw new Error(`Cannot find (D/n) = -1 for ${n.toString(10)}.`);
      }

      if (limit > 0 && p > limit) {
        // It's thought to be impossible for `p`
        // to be larger than 10,000, but fail
        // on anything higher than a limit to
        // prevent DoS attacks. `p` never seems
        // to be higher than 30 in practice.
        return false;
      }

      const d = new BN(p * p - 4);
      const j = d.jacobi(n);

      if (j === -1)
        break;

      if (j === 0)
        return n.cmpn(p + 2) === 0;

      if (p === 40) {
        if (n.isSquare())
          return false;
      }

      p += 1;
    }

    // Check for Grantham definition of
    // "extra strong Lucas pseudoprime".
    const s = n.addn(1);
    const r = s.zeroBits();
    const nm2 = n.subn(2);

    let x = new BN(2);
    let y = new BN(p);

    s.iushrn(r);

    for (let i = s.bitLength(); i >= 0; i--) {
      if (s.testn(i)) {
        x = x.imul(y).iadd(n).isubn(p).iumod(n);
        y = y.isqr().iadd(nm2).iumod(n);
      } else {
        y = y.imul(x).iadd(n).isubn(p).iumod(n);
        x = x.isqr().iadd(nm2).iumod(n);
      }
    }

    if (x.cmpn(2) === 0 || x.cmp(nm2) === 0) {
      let a = x.muln(p);
      let b = y.ushln(1);

      if (a.cmp(b) < 0)
        [a, b] = [b, a];

      if (a.isub(b).iumod(n).isZero())
        return true;
    }

    for (let t = 0; t < r - 1; t++) {
      if (x.isZero())
        return true;

      if (x.cmpn(2) === 0)
        return false;

      x = x.isqr().isubn(2).iumod(n);
    }

    return false;
  }

  /*
   * Twos Complement
   */

  toTwos(width) {
    if (this.negative !== 0)
      return this.abs().inotn(width).iaddn(1);

    return this.clone();
  }

  fromTwos(width) {
    if (this.testn(width - 1))
      return this.notn(width).iaddn(1).ineg();

    return this.clone();
  }

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
    red(this.red, 'redISqr');
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
    dest.words = this.words;
    dest.length = this.length;
    dest.negative = this.negative;
    dest.red = this.red;
  }

  _expand(size) {
    while (this.length < size)
      this.words[this.length++] = 0;

    return this;
  }

  _strip() {
    while (this.length > 1 && this.words[this.length - 1] === 0)
      this.length--;

    return this._normSign();
  }

  _normSign() {
    // -0 = 0
    if (this.length === 1 && this.words[0] === 0)
      this.negative = 0;

    return this;
  }

  _invmp(p) {
    enforce(BN.isBN(p), 'p', 'bignum');
    range((p.negative | p.isZero()) === 0, '_invmp');

    let a = this;

    const b = p.clone();

    if (a.negative !== 0)
      a = a.umod(p);
    else
      a = a.clone();

    const x1 = new BN(1);
    const x2 = new BN(0);

    const delta = b.clone();

    while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
      let i = 0;

      for (let im = 1; (a.words[0] & im) === 0 && i < 26; im <<= 1)
        i += 1;

      if (i > 0) {
        a.iushrn(i);
        while (i-- > 0) {
          if (x1.isOdd())
            x1.iadd(delta);

          x1.iushrn(1);
        }
      }

      let j = 0;

      for (let jm = 1; (b.words[0] & jm) === 0 && j < 26; jm <<= 1)
        j += 1;

      if (j > 0) {
        b.iushrn(j);

        while (j-- > 0) {
          if (x2.isOdd())
            x2.iadd(delta);

          x2.iushrn(1);
        }
      }

      if (a.cmp(b) >= 0) {
        a.isub(b);
        x1.isub(x2);
      } else {
        b.isub(a);
        x2.isub(x1);
      }
    }

    let res;

    if (a.cmpn(1) === 0)
      res = x1;
    else
      res = x2;

    if (res.cmpn(0) < 0)
      res.iadd(p);

    return res;
  }

  _ishlnsubmul(num, mul, shift) {
    const len = num.length + shift;

    this._expand(len);

    let carry = 0;
    let i = 0;
    let w;

    for (; i < num.length; i++) {
      w = (this.words[i + shift] | 0) + carry;
      const right = (num.words[i] | 0) * mul;
      w -= right & 0x3ffffff;
      carry = (w >> 26) - ((right / 0x4000000) | 0);
      this.words[i + shift] = w & 0x3ffffff;
    }

    for (; i < this.length - shift; i++) {
      w = (this.words[i + shift] | 0) + carry;
      carry = w >> 26;
      this.words[i + shift] = w & 0x3ffffff;
    }

    if (carry === 0)
      return this._strip();

    // Subtraction overflow.
    assert(carry === -1);
    carry = 0;

    for (i = 0; i < this.length; i++) {
      w = -(this.words[i] | 0) + carry;
      carry = w >> 26;
      this.words[i] = w & 0x3ffffff;
    }

    this.negative = 1;

    return this._strip();
  }

  _wordDiv(num, mode) {
    let shift = this.length - num.length;
    let a = this.clone();
    let b = num;

    // Normalize.
    let bhi = b.words[b.length - 1] | 0;

    const bhiBits = countBits(bhi);

    shift = 26 - bhiBits;

    if (shift !== 0) {
      b = b.ushln(shift);
      a.iushln(shift);
      bhi = b.words[b.length - 1] | 0;
    }

    // Initialize quotient.
    const m = a.length - b.length;
    assert(m >= 0);

    let q;

    if (mode !== 'mod') {
      q = new BN();
      q.length = m + 1;
      q.words = new Array(q.length);

      for (let i = 0; i < q.length; i++)
        q.words[i] = 0;
    }

    const diff = a.clone()._ishlnsubmul(b, 1, m);

    if (diff.negative === 0) {
      a = diff;
      if (q)
        q.words[m] = 1;
    }

    for (let j = m - 1; j >= 0; j--) {
      let qj = (a.words[b.length + j] | 0) * 0x4000000
             + (a.words[b.length + j - 1] | 0);

      qj = Math.min((qj / bhi) | 0, 0x3ffffff);

      a._ishlnsubmul(b, qj, j);

      while (a.negative !== 0) {
        qj--;

        a.negative = 0;
        a._ishlnsubmul(b, 1, j);

        if (!a.isZero())
          a.negative ^= 1;
      }

      if (q)
        q.words[j] = qj;
    }

    if (q)
      q._strip();

    a._strip();

    // Denormalize
    if (mode !== 'div' && shift !== 0)
      a.iushrn(shift);

    return [q || null, a];
  }

  _cloneNormal() {
    return this.red ? this.fromRed() : this.clone();
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
    enforce(BN.isBN(num), 'num', 'bignum');

    this.words = new Array(num.length);

    for (let i = 0; i < num.length; i++)
      this.words[i] = num.words[i];

    this.length = num.length;
    this.negative = num.negative;
    this.red = num.red;

    return this;
  }

  set(num, endian) {
    return this.fromNumber(num, endian);
  }

  swap() {
    const neg = this.negative;

    this.fromBuffer(this.toBuffer('be'), 'le');
    this.negative = neg;

    return this;
  }

  byteLength() {
    return Math.ceil(this.bitLength() / 8);
  }

  bitLength() {
    const w = this.words[this.length - 1];
    const hi = countBits(w);
    return (this.length - 1) * 26 + hi;
  }

  zeroBits() {
    if (this.isZero())
      return 0;

    let r = 0;

    for (let i = 0; i < this.length; i++) {
      const b = zeroBits(this.words[i]);

      r += b;

      if (b !== 26)
        break;
    }

    return r;
  }

  isSafe() {
    if (this.length <= 2)
      return true;

    if (this.length === 3 && this.words[2] === 0x01)
      return true;

    return false;
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

  toNumber() {
    let num = this.words[0];

    if (this.length === 2) {
      num += this.words[1] * 0x4000000;
    } else if (this.length === 3 && this.words[2] === 0x01) {
      // Note: at this stage it is known that the top bit is set.
      num += 0x10000000000000 + (this.words[1] * 0x4000000);
    } else if (this.length > 2) {
      throw new RangeError('Number can only safely store up to 53 bits.');
    }

    return this.negative !== 0 ? -num : num;
  }

  toDouble() {
    let num = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      num *= 0x4000000;
      num += this.words[i] & 0x3ffffff;
    }

    return this.negative !== 0 ? -num : num;
  }

  valueOf() {
    return this.toDouble();
  }

  toBigInt() {
    if (typeof BigInt !== 'function')
      throw new Error('BigInt is not supported!');

    const shift = BigInt(26);

    let num = BigInt(0);

    for (let i = this.length - 1; i >= 0; i--) {
      num <<= shift;
      num |= BigInt(this.words[i] & 0x3ffffff);
    }

    return this.negative !== 0 ? -num : num;
  }

  toBool() {
    return !this.isZero();
  }

  toString(base, padding) {
    base = getBase(base);

    if (padding == null)
      padding = 0;

    if (padding === 0)
      padding = 1;

    enforce((base >>> 0) === base, 'base', 'integer');
    enforce((padding >>> 0) === padding, 'padding', 'integer');

    if (base < 2 || base > 36)
      throw new RangeError('Base ranges between 2 and 36.');

    if (base === 16) {
      let out = '';
      let off = 0;
      let carry = 0;

      for (let i = 0; i < this.length; i++) {
        const w = this.words[i];
        const word = (((w << off) | carry) & 0xffffff).toString(16);

        carry = (w >>> (24 - off)) & 0xffffff;

        if (carry !== 0 || i !== this.length - 1)
          out = zeros[6 - word.length] + word + out;
        else
          out = word + out;

        off += 2;

        if (off >= 26) {
          off -= 26;
          i--;
        }
      }

      if (carry !== 0)
        out = carry.toString(16) + out;

      while (out.length % padding !== 0)
        out = '0' + out;

      if (this.negative !== 0)
        out = '-' + out;

      return out;
    }

    const groupSize = groupSizes[base];
    const groupBase = groupBases[base];

    let c = this.clone();
    let out = '';

    c.negative = 0;

    while (!c.isZero()) {
      const r = c.modrn(groupBase).toString(base);

      c = c.idivn(groupBase);

      if (!c.isZero())
        out = zeros[groupSize - r.length] + r + out;
      else
        out = r + out;
    }

    if (this.isZero())
      out = '0' + out;

    while (out.length % padding !== 0)
      out = '0' + out;

    if (this.negative !== 0)
      out = '-' + out;

    return out;
  }

  toJSON() {
    return this.toString(16, 2);
  }

  toArray(endian, length) {
    return this.toArrayLike(Array, endian, length);
  }

  toBuffer(endian, length) {
    return this.toArrayLike(Buffer, endian, length);
  }

  toArrayLike(ArrayType, endian, length) {
    if (endian == null)
      endian = 'be';

    if (length == null)
      length = 0;

    enforce(typeof ArrayType === 'function', 'ArrayType', 'function');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');
    enforce((length >>> 0) === length, 'length', 'integer');

    const bytes = this.byteLength();
    const size = length || Math.max(1, bytes);

    if (bytes > size)
      throw new RangeError('Byte array longer than desired length.');

    this._strip();

    const res = allocate(ArrayType, size);
    const q = this.clone();

    if (endian === 'be') {
      let i = size - 1;

      while (!q.isZero()) {
        res[i--] = q.words[0] & 0xff;
        q.iushrn(8);
      }

      for (; i >= 0; i--)
        res[i] = 0x00;
    } else {
      let i = 0;

      while (!q.isZero()) {
        res[i++] = q.words[0] & 0xff;
        q.iushrn(8);
      }

      for (; i < size; i++)
        res[i] = 0x00;
    }

    return res;
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

    enforce(isInteger(num), 'num', 'integer');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    if (num < 0x4000000) {
      this.words = [num & 0x3ffffff];
      this.length = 1;
    } else if (num < 0x10000000000000) {
      this.words = [
        num & 0x3ffffff,
        (num / 0x4000000) & 0x3ffffff
      ];
      this.length = 2;
    } else {
      this.words = [
        num & 0x3ffffff,
        (num / 0x4000000) & 0x3ffffff,
        1
      ];
      this.length = 3;
    }

    this.negative = neg;

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

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    num = Math.floor(num);

    this.words = [];
    this.length = 0;

    let len = 0;

    while (num > 0) {
      const lo = num % 0x4000000;
      const hi = (num - lo) / 0x4000000;

      this.words[len++] = lo;

      num = hi;
    }

    if (len === 0)
      this.words[len++] = 0;

    this.length = len;
    this.negative = neg;

    if (endian === 'le')
      this.swap();

    return this;
  }

  fromBigInt(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'bigint', 'num', 'bigint');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (typeof BigInt !== 'function')
      throw new Error('BigInt is not supported!');

    const zero = BigInt(0);
    const mask = BigInt(0x3ffffff);
    const shift = BigInt(26);

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    this.words = [];
    this.length = 0;

    let len = 0;

    while (num > zero) {
      this.words[len++] = Number(num & mask);
      num >>= shift;
    }

    if (len === 0)
      this.words[len++] = 0;

    this.length = len;
    this.negative = neg;

    if (endian === 'le')
      this.swap();

    return this;
  }

  fromBool(value) {
    enforce(typeof value === 'boolean', 'value', 'boolean');
    return this.set(value ? 1 : 0);
  }

  fromString(str, base, endian) {
    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    base = getBase(base);

    if (endian == null)
      endian = 'be';

    enforce(typeof str === 'string', 'string', 'string');
    enforce((base >>> 0) === base, 'base', 'integer');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (base < 2 || base > 36)
      throw new Error('Base ranges between 2 and 36.');

    str = str.replace(/\s+/g, '');

    let start = 0;

    if (str.length > 0 && str[0] === '-')
      start += 1;

    if (base === 16)
      this._fromHex(str, start);
    else
      this._fromBase(str, base, start);

    this.negative = start;

    this._strip();

    if (endian === 'le')
      this.swap();

    return this;
  }

  _fromHex(number, start) {
    // Create possibly bigger array to ensure that it fits the number.
    this.length = Math.ceil((number.length - start) / 6);
    this.words = new Array(this.length);

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    // Scan 24-bit chunks and add them to the number.
    let off = 0;
    let i = number.length - 6;
    let j = 0;

    for (; i >= start; i -= 6) {
      const w = parseHex(number, i, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;

      // `0x3fffff` is intentional here, 26bits max shift + 24bit hex limb.
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;

      off += 24;

      if (off >= 26) {
        off -= 26;
        j += 1;
      }
    }

    if (i + 6 !== start) {
      const w = parseHex(number, start, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;
    }

    if (this.length === 0) {
      this.words[0] = 0;
      this.length = 1;
    }

    return this._strip();
  }

  _fromBase(number, base, start) {
    // Initialize as zero.
    this.words = [0];
    this.length = 1;

    // Find length of limb in base.
    let limbLen = 0;
    let limbPow = 1;

    for (; limbPow <= 0x3ffffff; limbPow *= base)
      limbLen += 1;

    limbLen--;
    limbPow = (limbPow / base) | 0;

    const total = number.length - start;
    const mod = total % limbLen;
    const end = Math.min(total, total - mod) + start;

    let word = 0;
    let i = start;

    for (; i < end; i += limbLen) {
      word = parseBase(number, i, i + limbLen, base);

      this.imuln(limbPow);

      if (this.words[0] + word < 0x4000000)
        this.words[0] += word;
      else
        this._iaddn(word);
    }

    if (mod !== 0) {
      let pow = 1;

      word = parseBase(number, i, number.length, base);

      for (i = 0; i < mod; i++)
        pow *= base;

      this.imuln(pow);

      if (this.words[0] + word < 0x4000000)
        this.words[0] += word;
      else
        this._iaddn(word);
    }

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
    return this.fromArrayLike(data, endian);
  }

  fromBuffer(data, endian) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    return this.fromArrayLike(data, endian);
  }

  fromArrayLike(data, endian) {
    if (endian == null)
      endian = 'be';

    enforce(data && typeof data.length === 'number', 'data', 'array-like');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (data.length <= 0) {
      this.words = [0];
      this.length = 1;
      this.negative = 0;
      return this;
    }

    this.length = Math.ceil(data.length / 3);
    this.words = new Array(this.length);
    this.negative = 0;

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    let off = 0;

    if (endian === 'be') {
      for (let i = data.length - 1, j = 0; i >= 0; i -= 3) {
        const w = data[i] | (data[i - 1] << 8) | (data[i - 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j += 1;
        }
      }
    } else {
      for (let i = 0, j = 0; i < data.length; i += 3) {
        const w = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j += 1;
        }
      }
    }

    return this._strip();
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
    return new Mont(num);
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
    enforce(rng != null, 'rng', 'rng');
    enforce(isInteger(bits), 'bits', 'integer');
    range(bits >= 0, 'randomBits');

    if (typeof rng === 'object') {
      enforce(typeof rng.randomBytes === 'function', 'rng', 'rng');

      const size = (bits + 7) >>> 3;
      const total = size * 8;
      const bytes = rng.randomBytes(size);

      enforce(Buffer.isBuffer(bytes), 'bytes', 'buffer');

      if (bytes.length !== size)
        throw new RangeError('Invalid number of bytes returned from RNG.');

      const num = BN.fromBuffer(bytes);

      if (total > bits)
        num.iushrn(total - bits);

      return num;
    }

    enforce(typeof rng === 'function', 'rng', 'rng');

    const num = rng(bits);

    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.negative === 0, 'RNG');
    nonred(!num.red, 'RNG');

    if (num.bitLength() > bits)
      throw new RangeError('Invalid number of bits returned from RNG.');

    return num;
  }

  static random(rng, min, max) {
    min = new BN(min, 16);
    max = new BN(max, 16);

    if (min.cmp(max) > 0)
      throw new RangeError('Minimum cannot be greater than maximum.');

    const space = max.sub(min).iabs();
    const bits = space.bitLength();

    if (bits === 0)
      return min.clone();

    for (;;) {
      const num = BN.randomBits(rng, bits);

      // Maximum is _exclusive_!
      if (num.cmp(space) >= 0)
        continue;

      // Minimum is _inclusive_!
      num.iadd(min);

      return num;
    }
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
BN.native = 0;

/**
 * Prime
 */

class Prime {
  constructor(name, p) {
    // P = 2 ^ N - K
    this.name = name;
    this.p = new BN(p, 16);
    this.n = this.p.bitLength();
    this.k = new BN(1).iushln(this.n).isub(this.p);

    this.tmp = this._tmp();
  }

  _tmp() {
    const tmp = new BN();
    tmp.words = new Array(Math.ceil(this.n / 13));
    return tmp;
  }

  ireduce(num) {
    // Assumes that `num` is less than `P^2`:
    // num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
    let r = num;
    let rlen;

    do {
      this.split(r, this.tmp);
      r = this.imulK(r);
      r = r.iadd(this.tmp);
      rlen = r.bitLength();
    } while (rlen > this.n);

    const cmp = rlen < this.n ? -1 : r.ucmp(this.p);

    if (cmp === 0) {
      r.words[0] = 0;
      r.length = 1;
    } else if (cmp > 0) {
      r.isub(this.p);
    } else {
      r._strip();
    }

    return r;
  }

  split(input, out) {
    input._split(this.n, 0, out);
  }

  imulK(num) {
    return num.imul(this.k);
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

  imulK(num) {
    // K = 0x10000000000000001
    const n = num.clone();
    return num.iushln(64).iadd(n);
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

  imulK(num) {
    // K = 0xffffffffffffffffffffffff
    const n = num.clone();
    return num.iushln(96).isub(n);
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

  imulK(num) {
    // K = 0x01
    return num;
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

  split(input, output) {
    // 256 = 9 * 26 + 22
    const mask = 0x3fffff;
    const outLen = Math.min(input.length, 9);

    for (let i = 0; i < outLen; i++)
      output.words[i] = input.words[i];

    output.length = outLen;

    if (input.length <= 9) {
      input.words[0] = 0;
      input.length = 1;
      return;
    }

    // Shift by 9 limbs.
    let prev = input.words[9];
    let i = 10;

    output.words[output.length++] = prev & mask;

    for (; i < input.length; i++) {
      const next = input.words[i] | 0;
      input.words[i - 10] = ((next & mask) << 4) | (prev >>> 22);
      prev = next;
    }

    prev >>>= 22;
    input.words[i - 10] = prev;

    if (prev === 0 && input.length > 10)
      input.length -= 10;
    else
      input.length -= 9;
  }

  imulK(num) {
    // K = 0x1000003d1 = [0x40, 0x3d1]
    num.words[num.length] = 0;
    num.words[num.length + 1] = 0;
    num.length += 2;

    // Bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
    let lo = 0;

    for (let i = 0; i < num.length; i++) {
      const w = num.words[i] | 0;
      lo += w * 0x3d1;
      num.words[i] = lo & 0x3ffffff;
      lo = w * 0x40 + ((lo / 0x4000000) | 0);
    }

    // Fast length reduction.
    if (num.words[num.length - 1] === 0) {
      num.length--;
      if (num.words[num.length - 1] === 0)
        num.length--;
    }

    return num;
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

  imulK(num) {
    // K = 0x13
    let carry = 0;

    for (let i = 0; i < num.length; i++) {
      let hi = (num.words[i] | 0) * 0x13 + carry;

      const lo = hi & 0x3ffffff;

      hi >>>= 26;

      num.words[i] = lo;
      carry = hi;
    }

    if (carry !== 0)
      num.words[num.length++] = carry;

    return num;
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

  imulK(num) {
    // K = 0x100000000000000000000000000000000000000000000000000000001
    const n = num.clone();
    return num.iushln(224).iadd(n);
  }
}

/**
 * Reduction Engine
 */

class Red {
  constructor(m) {
    let prime = null;

    if (typeof m === 'string') {
      prime = BN._prime(m);
      m = prime.p;
    }

    enforce(BN.isBN(m), 'm', 'bignum');
    range(m.cmpn(1) > 0, 'reduction');

    this.m = m;
    this.prime = prime;
  }

  _verify1(a) {
    range(a.negative === 0, 'red');
    red(a.red, 'red');
  }

  _verify2(a, b) {
    range((a.negative | b.negative) === 0, 'red');
    red(a.red && a.red === b.red, 'red');
  }

  imod(a) {
    if (this.prime)
      return this.prime.ireduce(a)._forceRed(this);

    a.iumod(this.m)._forceRed(this)._move(a);

    return a;
  }

  ineg(a) {
    this.neg(a)._move(a);
    return a;
  }

  neg(a) {
    this._verify1(a);

    if (a.isZero())
      return a.clone();

    return this.m.sub(a)._forceRed(this);
  }

  iadd(a, b) {
    this._verify2(a, b);

    const res = a.iadd(b);

    if (res.cmp(this.m) >= 0)
      res.isub(this.m);

    return res;
  }

  add(a, b) {
    this._verify2(a, b);

    const res = a.add(b);

    if (res.cmp(this.m) >= 0)
      res.isub(this.m);

    return res._forceRed(this);
  }

  isub(a, b) {
    this._verify2(a, b);

    const res = a.isub(b);

    if (res.cmpn(0) < 0)
      res.iadd(this.m);

    return res;
  }

  sub(a, b) {
    this._verify2(a, b);

    const res = a.sub(b);

    if (res.cmpn(0) < 0)
      res.iadd(this.m);

    return res._forceRed(this);
  }

  ishln(a, num) {
    this.shln(a, num)._move(a);
    return a;
  }

  shln(a, num) {
    this._verify1(a);
    return this.imod(a.ushln(num));
  }

  imul(a, b) {
    this._verify2(a, b);
    return this.imod(a.imul(b));
  }

  mul(a, b) {
    this._verify2(a, b);
    return this.imod(a.mul(b));
  }

  isqr(a) {
    return this.imul(a, a.clone());
  }

  sqr(a) {
    return this.mul(a, a);
  }

  isqrt(a) {
    this.sqrt(a)._move(a);
    return a;
  }

  sqrt(a) {
    this._verify1(a);

    switch (this.jacobi(a)) {
      case -1:
        throw new Error('X is not a square mod P.');
      case 0:
        return new BN(0).toRed(this);
      case 1:
        break;
    }

    if (a.isZero())
      return a.clone();

    // Fast case (mod 4 == 3).
    if (this.m.andln(3) === 3) {
      const pow = this.m.add(new BN(1)).iushrn(2);
      return this.pow(a, pow);
    }

    // Fast case (mod 8 == 5).
    if (this.m.andln(7) === 5) {
      const one = new BN(1).toRed(this);
      const e = this.m.ushrn(3);
      const t = this.shln(a, 1);
      const y = this.pow(t, e);
      const b = y.clone();

      this.imul(b, y);
      this.imul(b, t);
      this.isub(b, one);
      this.imul(b, a);
      this.imul(b, y);

      return b;
    }

    // Tonelli-Shanks algorithm (Totally unoptimized and slow).
    // Find Q and S, that Q * 2 ^ S = (P - 1).
    const q = this.m.subn(1);

    let s = 0;

    while (!q.isZero() && q.andln(1) === 0) {
      s += 1;
      q.iushrn(1);
    }

    assert(!q.isZero());

    const one = new BN(1).toRed(this);
    const nOne = one.redNeg();

    // Find quadratic non-residue.
    // Note: Max is such because of generalized Riemann hypothesis.
    const lpow = this.m.subn(1).iushrn(1);
    const bits = this.m.bitLength();
    const z = new BN(2 * bits * bits).toRed(this);

    while (this.pow(z, lpow).cmp(nOne) !== 0)
      z.redIAdd(nOne);

    let c = this.pow(z, q);
    let r = this.pow(a, q.addn(1).iushrn(1));
    let t = this.pow(a, q);
    let m = s;

    while (t.cmp(one) !== 0) {
      let tmp = t;
      let i = 0;

      for (; tmp.cmp(one) !== 0; i++)
        tmp = tmp.redSqr();

      assert(i < m);

      const b = this.pow(c, new BN(1).iushln(m - i - 1));

      r = r.redMul(b);
      c = b.redSqr();
      t = t.redMul(c);
      m = i;
    }

    return r;
  }

  iinvm(a) {
    this.invm(a)._move(a);
    return a;
  }

  invm(a) {
    this._verify1(a);

    const inv = a._invmp(this.m);

    if (inv.negative !== 0) {
      inv.negative = 0;
      return this.imod(inv).redNeg();
    }

    return this.imod(inv);
  }

  ifinvm(a) {
    this.finvm(a)._move(a);
    return a;
  }

  finvm(a) {
    return this.pow(a, this.m.subn(2));
  }

  jacobi(a) {
    this._verify1(a);
    return a.jacobi(this.m);
  }

  ipow(a, num) {
    this.pow(a, num)._move(a);
    return a;
  }

  pow(a, num) {
    this._verify1(a);

    if (num.isZero())
      return new BN(1).toRed(this);

    // GMP behavior.
    if (num.isNeg()) {
      a = a.redInvm();
      num = num.neg();
    }

    if (num.cmpn(1) === 0)
      return a.clone();

    const windowSize = 4;
    const wnd = new Array(1 << windowSize);

    wnd[0] = new BN(1).toRed(this);
    wnd[1] = a;

    for (let i = 2; i < wnd.length; i++)
      wnd[i] = this.mul(wnd[i - 1], a);

    let res = wnd[0];
    let current = 0;
    let currentLen = 0;
    let start = num.bitLength() % 26;

    if (start === 0)
      start = 26;

    for (let i = num.length - 1; i >= 0; i--) {
      const word = num.words[i];

      for (let j = start - 1; j >= 0; j--) {
        const bit = (word >> j) & 1;

        if (res !== wnd[0])
          res = this.sqr(res);

        if (bit === 0 && current === 0) {
          currentLen = 0;
          continue;
        }

        current <<= 1;
        current |= bit;
        currentLen += 1;

        if (currentLen !== windowSize && (i !== 0 || j !== 0))
          continue;

        res = this.mul(res, wnd[current]);
        currentLen = 0;
        current = 0;
      }

      start = 26;
    }

    return res;
  }

  convertTo(num) {
    return num.umod(this.m);
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

/**
 * Montgomery Method Engine
 */

class Mont extends Red {
  constructor(m) {
    super(m);

    this.shift = this.m.bitLength();

    if (this.shift % 26 !== 0)
      this.shift += 26 - (this.shift % 26);

    this.r = new BN(1).iushln(this.shift);
    this.r2 = this.imod(this.r.sqr());
    this.rinv = this.r._invmp(this.m);

    this.minv = this.rinv.mul(this.r).isubn(1).div(this.m);
    this.minv = this.minv.iumod(this.r);
    this.minv = this.r.sub(this.minv);
  }

  convertTo(num) {
    return this.imod(num.ushln(this.shift));
  }

  convertFrom(num) {
    const r = this.imod(num.mul(this.rinv));
    r.red = null;
    return r;
  }

  imul(a, b) {
    this._verify2(a, b);

    if (a.isZero() || b.isZero()) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    const t = a.imul(b);
    const c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    const u = t.isub(c).iushrn(this.shift);

    let res = u;

    if (u.cmp(this.m) >= 0)
      res = u.isub(this.m);
    else if (u.cmpn(0) < 0)
      res = u.iadd(this.m);

    return res._forceRed(this);
  }

  mul(a, b) {
    this._verify2(a, b);

    if (a.isZero() || b.isZero())
      return new BN(0)._forceRed(this);

    const t = a.mul(b);
    const c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    const u = t.isub(c).iushrn(this.shift);

    let res = u;

    if (u.cmp(this.m) >= 0)
      res = u.isub(this.m);
    else if (u.cmpn(0) < 0)
      res = u.iadd(this.m);

    return res._forceRed(this);
  }

  invm(a) {
    this._verify1(a);

    // (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
    const res = this.imod(a._invmp(this.m).mul(this.r2));

    return res._forceRed(this);
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

function assert(value, message) {
  if (!value) {
    const msg = message || 'Assertion failed.';
    throw makeError(Error, msg, assert);
  }
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

function nonzero(value) {
  if (!value) {
    const msg = 'Cannot divide by zero.';
    throw makeError(RangeError, msg, nonzero);
  }
}

function isInteger(num) {
  return Number.isSafeInteger(num);
}

function isSMI(num) {
  return isInteger(num)
      && num >= -0x3ffffff
      && num <= 0x3ffffff;
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
 * Internal
 */

function toBitArray(num) {
  const w = new Array(num.bitLength());

  for (let bit = 0; bit < w.length; bit++) {
    const off = (bit / 26) | 0;
    const wbit = bit % 26;

    w[bit] = (num.words[off] >>> wbit) & 1;
  }

  return w;
}

function countBits(w) {
  if (Math.clz32)
    return 32 - Math.clz32(w);

  let t = w;
  let r = 0;

  if (t >= 0x1000) {
    r += 13;
    t >>>= 13;
  }

  if (t >= 0x40) {
    r += 7;
    t >>>= 7;
  }

  if (t >= 0x8) {
    r += 4;
    t >>>= 4;
  }

  if (t >= 0x02) {
    r += 2;
    t >>>= 2;
  }

  return r + t;
}

function zeroBits(w) {
  // Shortcut.
  if (w === 0)
    return 26;

  let t = w;
  let r = 0;

  if ((t & 0x1fff) === 0) {
    r += 13;
    t >>>= 13;
  }

  if ((t & 0x7f) === 0) {
    r += 7;
    t >>>= 7;
  }

  if ((t & 0xf) === 0) {
    r += 4;
    t >>>= 4;
  }

  if ((t & 0x3) === 0) {
    r += 2;
    t >>>= 2;
  }

  if ((t & 0x1) === 0)
    r += 1;

  return r;
}

function parseHex(str, start, end) {
  const len = Math.min(str.length, end);

  let r = 0;
  let z = 0;

  for (let i = start; i < len; i++) {
    const c = str.charCodeAt(i) - 48;

    r <<= 4;

    let b;

    if (c >= 49 && c <= 54) {
      // 'a' - 'f'
      b = c - 49 + 0xa;
    } else if (c >= 17 && c <= 22) {
      // 'A' - 'F'
      b = c - 17 + 0xa;
    } else {
      // '0' - '9'
      b = c;
    }

    r |= b;
    z |= b;
  }

  assert(!(z & 0xf0), 'Invalid character in ' + str);

  return r;
}

function parseBase(str, start, end, mul) {
  const len = Math.min(str.length, end);

  let r = 0;
  let b = 0;

  for (let i = start; i < len; i++) {
    const c = str.charCodeAt(i) - 48;

    r *= mul;

    if (c >= 49) {
      // 'a'
      b = c - 49 + 0xa;
    } else if (c >= 17) {
      // 'A'
      b = c - 17 + 0xa;
    } else {
      // '0' - '9'
      b = c;
    }

    assert(c >= 0 && b < mul, 'Invalid character');

    r += b;
  }

  return r;
}

/*
 * Multiplication
 */

function smallMulTo(self, num, out) {
  out.negative = num.negative ^ self.negative;

  let len = (self.length + num.length) | 0;

  out.length = len;

  len = (len - 1) | 0;

  // Peel one iteration (compiler can't
  // do it, because of code complexity).
  let a = self.words[0] | 0;
  let b = num.words[0] | 0;
  let r = a * b;

  const lo = r & 0x3ffffff;

  let carry = (r / 0x4000000) | 0;
  let k = 1;

  out.words[0] = lo;

  for (; k < len; k++) {
    // Sum all words with the same
    // `i + j = k` and accumulate
    // `ncarry`, note that ncarry
    // could be >= 0x3ffffff.
    let ncarry = carry >>> 26;
    let rword = carry & 0x3ffffff;

    const maxJ = Math.min(k, num.length - 1);

    for (let j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
      const i = (k - j) | 0;

      a = self.words[i] | 0;
      b = num.words[j] | 0;
      r = a * b + rword;
      ncarry += (r / 0x4000000) | 0;
      rword = r & 0x3ffffff;
    }

    out.words[k] = rword | 0;
    carry = ncarry | 0;
  }

  if (carry !== 0)
    out.words[k] = carry | 0;
  else
    out.length--;

  return out._strip();
}

function comb10MulTo(self, num, out) {
  const a = self.words;
  const b = num.words;
  const o = out.words;
  const a0 = a[0] | 0;
  const al0 = a0 & 0x1fff;
  const ah0 = a0 >>> 13;
  const a1 = a[1] | 0;
  const al1 = a1 & 0x1fff;
  const ah1 = a1 >>> 13;
  const a2 = a[2] | 0;
  const al2 = a2 & 0x1fff;
  const ah2 = a2 >>> 13;
  const a3 = a[3] | 0;
  const al3 = a3 & 0x1fff;
  const ah3 = a3 >>> 13;
  const a4 = a[4] | 0;
  const al4 = a4 & 0x1fff;
  const ah4 = a4 >>> 13;
  const a5 = a[5] | 0;
  const al5 = a5 & 0x1fff;
  const ah5 = a5 >>> 13;
  const a6 = a[6] | 0;
  const al6 = a6 & 0x1fff;
  const ah6 = a6 >>> 13;
  const a7 = a[7] | 0;
  const al7 = a7 & 0x1fff;
  const ah7 = a7 >>> 13;
  const a8 = a[8] | 0;
  const al8 = a8 & 0x1fff;
  const ah8 = a8 >>> 13;
  const a9 = a[9] | 0;
  const al9 = a9 & 0x1fff;
  const ah9 = a9 >>> 13;
  const b0 = b[0] | 0;
  const bl0 = b0 & 0x1fff;
  const bh0 = b0 >>> 13;
  const b1 = b[1] | 0;
  const bl1 = b1 & 0x1fff;
  const bh1 = b1 >>> 13;
  const b2 = b[2] | 0;
  const bl2 = b2 & 0x1fff;
  const bh2 = b2 >>> 13;
  const b3 = b[3] | 0;
  const bl3 = b3 & 0x1fff;
  const bh3 = b3 >>> 13;
  const b4 = b[4] | 0;
  const bl4 = b4 & 0x1fff;
  const bh4 = b4 >>> 13;
  const b5 = b[5] | 0;
  const bl5 = b5 & 0x1fff;
  const bh5 = b5 >>> 13;
  const b6 = b[6] | 0;
  const bl6 = b6 & 0x1fff;
  const bh6 = b6 >>> 13;
  const b7 = b[7] | 0;
  const bl7 = b7 & 0x1fff;
  const bh7 = b7 >>> 13;
  const b8 = b[8] | 0;
  const bl8 = b8 & 0x1fff;
  const bh8 = b8 >>> 13;
  const b9 = b[9] | 0;
  const bl9 = b9 & 0x1fff;
  const bh9 = b9 >>> 13;

  let c = 0;
  let lo;
  let mid;
  let hi;

  out.negative = self.negative ^ num.negative;
  out.length = 19;

  /* k = 0 */
  lo = Math.imul(al0, bl0);
  mid = Math.imul(al0, bh0);
  mid = (mid + Math.imul(ah0, bl0)) | 0;
  hi = Math.imul(ah0, bh0);
  let w0 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w0 >>> 26)) | 0;
  w0 &= 0x3ffffff;

  /* k = 1 */
  lo = Math.imul(al1, bl0);
  mid = Math.imul(al1, bh0);
  mid = (mid + Math.imul(ah1, bl0)) | 0;
  hi = Math.imul(ah1, bh0);
  lo = (lo + Math.imul(al0, bl1)) | 0;
  mid = (mid + Math.imul(al0, bh1)) | 0;
  mid = (mid + Math.imul(ah0, bl1)) | 0;
  hi = (hi + Math.imul(ah0, bh1)) | 0;
  let w1 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w1 >>> 26)) | 0;
  w1 &= 0x3ffffff;

  /* k = 2 */
  lo = Math.imul(al2, bl0);
  mid = Math.imul(al2, bh0);
  mid = (mid + Math.imul(ah2, bl0)) | 0;
  hi = Math.imul(ah2, bh0);
  lo = (lo + Math.imul(al1, bl1)) | 0;
  mid = (mid + Math.imul(al1, bh1)) | 0;
  mid = (mid + Math.imul(ah1, bl1)) | 0;
  hi = (hi + Math.imul(ah1, bh1)) | 0;
  lo = (lo + Math.imul(al0, bl2)) | 0;
  mid = (mid + Math.imul(al0, bh2)) | 0;
  mid = (mid + Math.imul(ah0, bl2)) | 0;
  hi = (hi + Math.imul(ah0, bh2)) | 0;
  let w2 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w2 >>> 26)) | 0;
  w2 &= 0x3ffffff;

  /* k = 3 */
  lo = Math.imul(al3, bl0);
  mid = Math.imul(al3, bh0);
  mid = (mid + Math.imul(ah3, bl0)) | 0;
  hi = Math.imul(ah3, bh0);
  lo = (lo + Math.imul(al2, bl1)) | 0;
  mid = (mid + Math.imul(al2, bh1)) | 0;
  mid = (mid + Math.imul(ah2, bl1)) | 0;
  hi = (hi + Math.imul(ah2, bh1)) | 0;
  lo = (lo + Math.imul(al1, bl2)) | 0;
  mid = (mid + Math.imul(al1, bh2)) | 0;
  mid = (mid + Math.imul(ah1, bl2)) | 0;
  hi = (hi + Math.imul(ah1, bh2)) | 0;
  lo = (lo + Math.imul(al0, bl3)) | 0;
  mid = (mid + Math.imul(al0, bh3)) | 0;
  mid = (mid + Math.imul(ah0, bl3)) | 0;
  hi = (hi + Math.imul(ah0, bh3)) | 0;
  let w3 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w3 >>> 26)) | 0;
  w3 &= 0x3ffffff;

  /* k = 4 */
  lo = Math.imul(al4, bl0);
  mid = Math.imul(al4, bh0);
  mid = (mid + Math.imul(ah4, bl0)) | 0;
  hi = Math.imul(ah4, bh0);
  lo = (lo + Math.imul(al3, bl1)) | 0;
  mid = (mid + Math.imul(al3, bh1)) | 0;
  mid = (mid + Math.imul(ah3, bl1)) | 0;
  hi = (hi + Math.imul(ah3, bh1)) | 0;
  lo = (lo + Math.imul(al2, bl2)) | 0;
  mid = (mid + Math.imul(al2, bh2)) | 0;
  mid = (mid + Math.imul(ah2, bl2)) | 0;
  hi = (hi + Math.imul(ah2, bh2)) | 0;
  lo = (lo + Math.imul(al1, bl3)) | 0;
  mid = (mid + Math.imul(al1, bh3)) | 0;
  mid = (mid + Math.imul(ah1, bl3)) | 0;
  hi = (hi + Math.imul(ah1, bh3)) | 0;
  lo = (lo + Math.imul(al0, bl4)) | 0;
  mid = (mid + Math.imul(al0, bh4)) | 0;
  mid = (mid + Math.imul(ah0, bl4)) | 0;
  hi = (hi + Math.imul(ah0, bh4)) | 0;
  let w4 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w4 >>> 26)) | 0;
  w4 &= 0x3ffffff;

  /* k = 5 */
  lo = Math.imul(al5, bl0);
  mid = Math.imul(al5, bh0);
  mid = (mid + Math.imul(ah5, bl0)) | 0;
  hi = Math.imul(ah5, bh0);
  lo = (lo + Math.imul(al4, bl1)) | 0;
  mid = (mid + Math.imul(al4, bh1)) | 0;
  mid = (mid + Math.imul(ah4, bl1)) | 0;
  hi = (hi + Math.imul(ah4, bh1)) | 0;
  lo = (lo + Math.imul(al3, bl2)) | 0;
  mid = (mid + Math.imul(al3, bh2)) | 0;
  mid = (mid + Math.imul(ah3, bl2)) | 0;
  hi = (hi + Math.imul(ah3, bh2)) | 0;
  lo = (lo + Math.imul(al2, bl3)) | 0;
  mid = (mid + Math.imul(al2, bh3)) | 0;
  mid = (mid + Math.imul(ah2, bl3)) | 0;
  hi = (hi + Math.imul(ah2, bh3)) | 0;
  lo = (lo + Math.imul(al1, bl4)) | 0;
  mid = (mid + Math.imul(al1, bh4)) | 0;
  mid = (mid + Math.imul(ah1, bl4)) | 0;
  hi = (hi + Math.imul(ah1, bh4)) | 0;
  lo = (lo + Math.imul(al0, bl5)) | 0;
  mid = (mid + Math.imul(al0, bh5)) | 0;
  mid = (mid + Math.imul(ah0, bl5)) | 0;
  hi = (hi + Math.imul(ah0, bh5)) | 0;
  let w5 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w5 >>> 26)) | 0;
  w5 &= 0x3ffffff;

  /* k = 6 */
  lo = Math.imul(al6, bl0);
  mid = Math.imul(al6, bh0);
  mid = (mid + Math.imul(ah6, bl0)) | 0;
  hi = Math.imul(ah6, bh0);
  lo = (lo + Math.imul(al5, bl1)) | 0;
  mid = (mid + Math.imul(al5, bh1)) | 0;
  mid = (mid + Math.imul(ah5, bl1)) | 0;
  hi = (hi + Math.imul(ah5, bh1)) | 0;
  lo = (lo + Math.imul(al4, bl2)) | 0;
  mid = (mid + Math.imul(al4, bh2)) | 0;
  mid = (mid + Math.imul(ah4, bl2)) | 0;
  hi = (hi + Math.imul(ah4, bh2)) | 0;
  lo = (lo + Math.imul(al3, bl3)) | 0;
  mid = (mid + Math.imul(al3, bh3)) | 0;
  mid = (mid + Math.imul(ah3, bl3)) | 0;
  hi = (hi + Math.imul(ah3, bh3)) | 0;
  lo = (lo + Math.imul(al2, bl4)) | 0;
  mid = (mid + Math.imul(al2, bh4)) | 0;
  mid = (mid + Math.imul(ah2, bl4)) | 0;
  hi = (hi + Math.imul(ah2, bh4)) | 0;
  lo = (lo + Math.imul(al1, bl5)) | 0;
  mid = (mid + Math.imul(al1, bh5)) | 0;
  mid = (mid + Math.imul(ah1, bl5)) | 0;
  hi = (hi + Math.imul(ah1, bh5)) | 0;
  lo = (lo + Math.imul(al0, bl6)) | 0;
  mid = (mid + Math.imul(al0, bh6)) | 0;
  mid = (mid + Math.imul(ah0, bl6)) | 0;
  hi = (hi + Math.imul(ah0, bh6)) | 0;
  let w6 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w6 >>> 26)) | 0;
  w6 &= 0x3ffffff;

  /* k = 7 */
  lo = Math.imul(al7, bl0);
  mid = Math.imul(al7, bh0);
  mid = (mid + Math.imul(ah7, bl0)) | 0;
  hi = Math.imul(ah7, bh0);
  lo = (lo + Math.imul(al6, bl1)) | 0;
  mid = (mid + Math.imul(al6, bh1)) | 0;
  mid = (mid + Math.imul(ah6, bl1)) | 0;
  hi = (hi + Math.imul(ah6, bh1)) | 0;
  lo = (lo + Math.imul(al5, bl2)) | 0;
  mid = (mid + Math.imul(al5, bh2)) | 0;
  mid = (mid + Math.imul(ah5, bl2)) | 0;
  hi = (hi + Math.imul(ah5, bh2)) | 0;
  lo = (lo + Math.imul(al4, bl3)) | 0;
  mid = (mid + Math.imul(al4, bh3)) | 0;
  mid = (mid + Math.imul(ah4, bl3)) | 0;
  hi = (hi + Math.imul(ah4, bh3)) | 0;
  lo = (lo + Math.imul(al3, bl4)) | 0;
  mid = (mid + Math.imul(al3, bh4)) | 0;
  mid = (mid + Math.imul(ah3, bl4)) | 0;
  hi = (hi + Math.imul(ah3, bh4)) | 0;
  lo = (lo + Math.imul(al2, bl5)) | 0;
  mid = (mid + Math.imul(al2, bh5)) | 0;
  mid = (mid + Math.imul(ah2, bl5)) | 0;
  hi = (hi + Math.imul(ah2, bh5)) | 0;
  lo = (lo + Math.imul(al1, bl6)) | 0;
  mid = (mid + Math.imul(al1, bh6)) | 0;
  mid = (mid + Math.imul(ah1, bl6)) | 0;
  hi = (hi + Math.imul(ah1, bh6)) | 0;
  lo = (lo + Math.imul(al0, bl7)) | 0;
  mid = (mid + Math.imul(al0, bh7)) | 0;
  mid = (mid + Math.imul(ah0, bl7)) | 0;
  hi = (hi + Math.imul(ah0, bh7)) | 0;
  let w7 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w7 >>> 26)) | 0;
  w7 &= 0x3ffffff;

  /* k = 8 */
  lo = Math.imul(al8, bl0);
  mid = Math.imul(al8, bh0);
  mid = (mid + Math.imul(ah8, bl0)) | 0;
  hi = Math.imul(ah8, bh0);
  lo = (lo + Math.imul(al7, bl1)) | 0;
  mid = (mid + Math.imul(al7, bh1)) | 0;
  mid = (mid + Math.imul(ah7, bl1)) | 0;
  hi = (hi + Math.imul(ah7, bh1)) | 0;
  lo = (lo + Math.imul(al6, bl2)) | 0;
  mid = (mid + Math.imul(al6, bh2)) | 0;
  mid = (mid + Math.imul(ah6, bl2)) | 0;
  hi = (hi + Math.imul(ah6, bh2)) | 0;
  lo = (lo + Math.imul(al5, bl3)) | 0;
  mid = (mid + Math.imul(al5, bh3)) | 0;
  mid = (mid + Math.imul(ah5, bl3)) | 0;
  hi = (hi + Math.imul(ah5, bh3)) | 0;
  lo = (lo + Math.imul(al4, bl4)) | 0;
  mid = (mid + Math.imul(al4, bh4)) | 0;
  mid = (mid + Math.imul(ah4, bl4)) | 0;
  hi = (hi + Math.imul(ah4, bh4)) | 0;
  lo = (lo + Math.imul(al3, bl5)) | 0;
  mid = (mid + Math.imul(al3, bh5)) | 0;
  mid = (mid + Math.imul(ah3, bl5)) | 0;
  hi = (hi + Math.imul(ah3, bh5)) | 0;
  lo = (lo + Math.imul(al2, bl6)) | 0;
  mid = (mid + Math.imul(al2, bh6)) | 0;
  mid = (mid + Math.imul(ah2, bl6)) | 0;
  hi = (hi + Math.imul(ah2, bh6)) | 0;
  lo = (lo + Math.imul(al1, bl7)) | 0;
  mid = (mid + Math.imul(al1, bh7)) | 0;
  mid = (mid + Math.imul(ah1, bl7)) | 0;
  hi = (hi + Math.imul(ah1, bh7)) | 0;
  lo = (lo + Math.imul(al0, bl8)) | 0;
  mid = (mid + Math.imul(al0, bh8)) | 0;
  mid = (mid + Math.imul(ah0, bl8)) | 0;
  hi = (hi + Math.imul(ah0, bh8)) | 0;
  let w8 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w8 >>> 26)) | 0;
  w8 &= 0x3ffffff;

  /* k = 9 */
  lo = Math.imul(al9, bl0);
  mid = Math.imul(al9, bh0);
  mid = (mid + Math.imul(ah9, bl0)) | 0;
  hi = Math.imul(ah9, bh0);
  lo = (lo + Math.imul(al8, bl1)) | 0;
  mid = (mid + Math.imul(al8, bh1)) | 0;
  mid = (mid + Math.imul(ah8, bl1)) | 0;
  hi = (hi + Math.imul(ah8, bh1)) | 0;
  lo = (lo + Math.imul(al7, bl2)) | 0;
  mid = (mid + Math.imul(al7, bh2)) | 0;
  mid = (mid + Math.imul(ah7, bl2)) | 0;
  hi = (hi + Math.imul(ah7, bh2)) | 0;
  lo = (lo + Math.imul(al6, bl3)) | 0;
  mid = (mid + Math.imul(al6, bh3)) | 0;
  mid = (mid + Math.imul(ah6, bl3)) | 0;
  hi = (hi + Math.imul(ah6, bh3)) | 0;
  lo = (lo + Math.imul(al5, bl4)) | 0;
  mid = (mid + Math.imul(al5, bh4)) | 0;
  mid = (mid + Math.imul(ah5, bl4)) | 0;
  hi = (hi + Math.imul(ah5, bh4)) | 0;
  lo = (lo + Math.imul(al4, bl5)) | 0;
  mid = (mid + Math.imul(al4, bh5)) | 0;
  mid = (mid + Math.imul(ah4, bl5)) | 0;
  hi = (hi + Math.imul(ah4, bh5)) | 0;
  lo = (lo + Math.imul(al3, bl6)) | 0;
  mid = (mid + Math.imul(al3, bh6)) | 0;
  mid = (mid + Math.imul(ah3, bl6)) | 0;
  hi = (hi + Math.imul(ah3, bh6)) | 0;
  lo = (lo + Math.imul(al2, bl7)) | 0;
  mid = (mid + Math.imul(al2, bh7)) | 0;
  mid = (mid + Math.imul(ah2, bl7)) | 0;
  hi = (hi + Math.imul(ah2, bh7)) | 0;
  lo = (lo + Math.imul(al1, bl8)) | 0;
  mid = (mid + Math.imul(al1, bh8)) | 0;
  mid = (mid + Math.imul(ah1, bl8)) | 0;
  hi = (hi + Math.imul(ah1, bh8)) | 0;
  lo = (lo + Math.imul(al0, bl9)) | 0;
  mid = (mid + Math.imul(al0, bh9)) | 0;
  mid = (mid + Math.imul(ah0, bl9)) | 0;
  hi = (hi + Math.imul(ah0, bh9)) | 0;
  let w9 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w9 >>> 26)) | 0;
  w9 &= 0x3ffffff;

  /* k = 10 */
  lo = Math.imul(al9, bl1);
  mid = Math.imul(al9, bh1);
  mid = (mid + Math.imul(ah9, bl1)) | 0;
  hi = Math.imul(ah9, bh1);
  lo = (lo + Math.imul(al8, bl2)) | 0;
  mid = (mid + Math.imul(al8, bh2)) | 0;
  mid = (mid + Math.imul(ah8, bl2)) | 0;
  hi = (hi + Math.imul(ah8, bh2)) | 0;
  lo = (lo + Math.imul(al7, bl3)) | 0;
  mid = (mid + Math.imul(al7, bh3)) | 0;
  mid = (mid + Math.imul(ah7, bl3)) | 0;
  hi = (hi + Math.imul(ah7, bh3)) | 0;
  lo = (lo + Math.imul(al6, bl4)) | 0;
  mid = (mid + Math.imul(al6, bh4)) | 0;
  mid = (mid + Math.imul(ah6, bl4)) | 0;
  hi = (hi + Math.imul(ah6, bh4)) | 0;
  lo = (lo + Math.imul(al5, bl5)) | 0;
  mid = (mid + Math.imul(al5, bh5)) | 0;
  mid = (mid + Math.imul(ah5, bl5)) | 0;
  hi = (hi + Math.imul(ah5, bh5)) | 0;
  lo = (lo + Math.imul(al4, bl6)) | 0;
  mid = (mid + Math.imul(al4, bh6)) | 0;
  mid = (mid + Math.imul(ah4, bl6)) | 0;
  hi = (hi + Math.imul(ah4, bh6)) | 0;
  lo = (lo + Math.imul(al3, bl7)) | 0;
  mid = (mid + Math.imul(al3, bh7)) | 0;
  mid = (mid + Math.imul(ah3, bl7)) | 0;
  hi = (hi + Math.imul(ah3, bh7)) | 0;
  lo = (lo + Math.imul(al2, bl8)) | 0;
  mid = (mid + Math.imul(al2, bh8)) | 0;
  mid = (mid + Math.imul(ah2, bl8)) | 0;
  hi = (hi + Math.imul(ah2, bh8)) | 0;
  lo = (lo + Math.imul(al1, bl9)) | 0;
  mid = (mid + Math.imul(al1, bh9)) | 0;
  mid = (mid + Math.imul(ah1, bl9)) | 0;
  hi = (hi + Math.imul(ah1, bh9)) | 0;
  let w10 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w10 >>> 26)) | 0;
  w10 &= 0x3ffffff;

  /* k = 11 */
  lo = Math.imul(al9, bl2);
  mid = Math.imul(al9, bh2);
  mid = (mid + Math.imul(ah9, bl2)) | 0;
  hi = Math.imul(ah9, bh2);
  lo = (lo + Math.imul(al8, bl3)) | 0;
  mid = (mid + Math.imul(al8, bh3)) | 0;
  mid = (mid + Math.imul(ah8, bl3)) | 0;
  hi = (hi + Math.imul(ah8, bh3)) | 0;
  lo = (lo + Math.imul(al7, bl4)) | 0;
  mid = (mid + Math.imul(al7, bh4)) | 0;
  mid = (mid + Math.imul(ah7, bl4)) | 0;
  hi = (hi + Math.imul(ah7, bh4)) | 0;
  lo = (lo + Math.imul(al6, bl5)) | 0;
  mid = (mid + Math.imul(al6, bh5)) | 0;
  mid = (mid + Math.imul(ah6, bl5)) | 0;
  hi = (hi + Math.imul(ah6, bh5)) | 0;
  lo = (lo + Math.imul(al5, bl6)) | 0;
  mid = (mid + Math.imul(al5, bh6)) | 0;
  mid = (mid + Math.imul(ah5, bl6)) | 0;
  hi = (hi + Math.imul(ah5, bh6)) | 0;
  lo = (lo + Math.imul(al4, bl7)) | 0;
  mid = (mid + Math.imul(al4, bh7)) | 0;
  mid = (mid + Math.imul(ah4, bl7)) | 0;
  hi = (hi + Math.imul(ah4, bh7)) | 0;
  lo = (lo + Math.imul(al3, bl8)) | 0;
  mid = (mid + Math.imul(al3, bh8)) | 0;
  mid = (mid + Math.imul(ah3, bl8)) | 0;
  hi = (hi + Math.imul(ah3, bh8)) | 0;
  lo = (lo + Math.imul(al2, bl9)) | 0;
  mid = (mid + Math.imul(al2, bh9)) | 0;
  mid = (mid + Math.imul(ah2, bl9)) | 0;
  hi = (hi + Math.imul(ah2, bh9)) | 0;
  let w11 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w11 >>> 26)) | 0;
  w11 &= 0x3ffffff;

  /* k = 12 */
  lo = Math.imul(al9, bl3);
  mid = Math.imul(al9, bh3);
  mid = (mid + Math.imul(ah9, bl3)) | 0;
  hi = Math.imul(ah9, bh3);
  lo = (lo + Math.imul(al8, bl4)) | 0;
  mid = (mid + Math.imul(al8, bh4)) | 0;
  mid = (mid + Math.imul(ah8, bl4)) | 0;
  hi = (hi + Math.imul(ah8, bh4)) | 0;
  lo = (lo + Math.imul(al7, bl5)) | 0;
  mid = (mid + Math.imul(al7, bh5)) | 0;
  mid = (mid + Math.imul(ah7, bl5)) | 0;
  hi = (hi + Math.imul(ah7, bh5)) | 0;
  lo = (lo + Math.imul(al6, bl6)) | 0;
  mid = (mid + Math.imul(al6, bh6)) | 0;
  mid = (mid + Math.imul(ah6, bl6)) | 0;
  hi = (hi + Math.imul(ah6, bh6)) | 0;
  lo = (lo + Math.imul(al5, bl7)) | 0;
  mid = (mid + Math.imul(al5, bh7)) | 0;
  mid = (mid + Math.imul(ah5, bl7)) | 0;
  hi = (hi + Math.imul(ah5, bh7)) | 0;
  lo = (lo + Math.imul(al4, bl8)) | 0;
  mid = (mid + Math.imul(al4, bh8)) | 0;
  mid = (mid + Math.imul(ah4, bl8)) | 0;
  hi = (hi + Math.imul(ah4, bh8)) | 0;
  lo = (lo + Math.imul(al3, bl9)) | 0;
  mid = (mid + Math.imul(al3, bh9)) | 0;
  mid = (mid + Math.imul(ah3, bl9)) | 0;
  hi = (hi + Math.imul(ah3, bh9)) | 0;
  let w12 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w12 >>> 26)) | 0;
  w12 &= 0x3ffffff;

  /* k = 13 */
  lo = Math.imul(al9, bl4);
  mid = Math.imul(al9, bh4);
  mid = (mid + Math.imul(ah9, bl4)) | 0;
  hi = Math.imul(ah9, bh4);
  lo = (lo + Math.imul(al8, bl5)) | 0;
  mid = (mid + Math.imul(al8, bh5)) | 0;
  mid = (mid + Math.imul(ah8, bl5)) | 0;
  hi = (hi + Math.imul(ah8, bh5)) | 0;
  lo = (lo + Math.imul(al7, bl6)) | 0;
  mid = (mid + Math.imul(al7, bh6)) | 0;
  mid = (mid + Math.imul(ah7, bl6)) | 0;
  hi = (hi + Math.imul(ah7, bh6)) | 0;
  lo = (lo + Math.imul(al6, bl7)) | 0;
  mid = (mid + Math.imul(al6, bh7)) | 0;
  mid = (mid + Math.imul(ah6, bl7)) | 0;
  hi = (hi + Math.imul(ah6, bh7)) | 0;
  lo = (lo + Math.imul(al5, bl8)) | 0;
  mid = (mid + Math.imul(al5, bh8)) | 0;
  mid = (mid + Math.imul(ah5, bl8)) | 0;
  hi = (hi + Math.imul(ah5, bh8)) | 0;
  lo = (lo + Math.imul(al4, bl9)) | 0;
  mid = (mid + Math.imul(al4, bh9)) | 0;
  mid = (mid + Math.imul(ah4, bl9)) | 0;
  hi = (hi + Math.imul(ah4, bh9)) | 0;
  let w13 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w13 >>> 26)) | 0;
  w13 &= 0x3ffffff;

  /* k = 14 */
  lo = Math.imul(al9, bl5);
  mid = Math.imul(al9, bh5);
  mid = (mid + Math.imul(ah9, bl5)) | 0;
  hi = Math.imul(ah9, bh5);
  lo = (lo + Math.imul(al8, bl6)) | 0;
  mid = (mid + Math.imul(al8, bh6)) | 0;
  mid = (mid + Math.imul(ah8, bl6)) | 0;
  hi = (hi + Math.imul(ah8, bh6)) | 0;
  lo = (lo + Math.imul(al7, bl7)) | 0;
  mid = (mid + Math.imul(al7, bh7)) | 0;
  mid = (mid + Math.imul(ah7, bl7)) | 0;
  hi = (hi + Math.imul(ah7, bh7)) | 0;
  lo = (lo + Math.imul(al6, bl8)) | 0;
  mid = (mid + Math.imul(al6, bh8)) | 0;
  mid = (mid + Math.imul(ah6, bl8)) | 0;
  hi = (hi + Math.imul(ah6, bh8)) | 0;
  lo = (lo + Math.imul(al5, bl9)) | 0;
  mid = (mid + Math.imul(al5, bh9)) | 0;
  mid = (mid + Math.imul(ah5, bl9)) | 0;
  hi = (hi + Math.imul(ah5, bh9)) | 0;
  let w14 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w14 >>> 26)) | 0;
  w14 &= 0x3ffffff;

  /* k = 15 */
  lo = Math.imul(al9, bl6);
  mid = Math.imul(al9, bh6);
  mid = (mid + Math.imul(ah9, bl6)) | 0;
  hi = Math.imul(ah9, bh6);
  lo = (lo + Math.imul(al8, bl7)) | 0;
  mid = (mid + Math.imul(al8, bh7)) | 0;
  mid = (mid + Math.imul(ah8, bl7)) | 0;
  hi = (hi + Math.imul(ah8, bh7)) | 0;
  lo = (lo + Math.imul(al7, bl8)) | 0;
  mid = (mid + Math.imul(al7, bh8)) | 0;
  mid = (mid + Math.imul(ah7, bl8)) | 0;
  hi = (hi + Math.imul(ah7, bh8)) | 0;
  lo = (lo + Math.imul(al6, bl9)) | 0;
  mid = (mid + Math.imul(al6, bh9)) | 0;
  mid = (mid + Math.imul(ah6, bl9)) | 0;
  hi = (hi + Math.imul(ah6, bh9)) | 0;
  let w15 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w15 >>> 26)) | 0;
  w15 &= 0x3ffffff;

  /* k = 16 */
  lo = Math.imul(al9, bl7);
  mid = Math.imul(al9, bh7);
  mid = (mid + Math.imul(ah9, bl7)) | 0;
  hi = Math.imul(ah9, bh7);
  lo = (lo + Math.imul(al8, bl8)) | 0;
  mid = (mid + Math.imul(al8, bh8)) | 0;
  mid = (mid + Math.imul(ah8, bl8)) | 0;
  hi = (hi + Math.imul(ah8, bh8)) | 0;
  lo = (lo + Math.imul(al7, bl9)) | 0;
  mid = (mid + Math.imul(al7, bh9)) | 0;
  mid = (mid + Math.imul(ah7, bl9)) | 0;
  hi = (hi + Math.imul(ah7, bh9)) | 0;
  let w16 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w16 >>> 26)) | 0;
  w16 &= 0x3ffffff;

  /* k = 17 */
  lo = Math.imul(al9, bl8);
  mid = Math.imul(al9, bh8);
  mid = (mid + Math.imul(ah9, bl8)) | 0;
  hi = Math.imul(ah9, bh8);
  lo = (lo + Math.imul(al8, bl9)) | 0;
  mid = (mid + Math.imul(al8, bh9)) | 0;
  mid = (mid + Math.imul(ah8, bl9)) | 0;
  hi = (hi + Math.imul(ah8, bh9)) | 0;
  let w17 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w17 >>> 26)) | 0;
  w17 &= 0x3ffffff;

  /* k = 18 */
  lo = Math.imul(al9, bl9);
  mid = Math.imul(al9, bh9);
  mid = (mid + Math.imul(ah9, bl9)) | 0;
  hi = Math.imul(ah9, bh9);
  let w18 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w18 >>> 26)) | 0;
  w18 &= 0x3ffffff;

  o[0] = w0;
  o[1] = w1;
  o[2] = w2;
  o[3] = w3;
  o[4] = w4;
  o[5] = w5;
  o[6] = w6;
  o[7] = w7;
  o[8] = w8;
  o[9] = w9;
  o[10] = w10;
  o[11] = w11;
  o[12] = w12;
  o[13] = w13;
  o[14] = w14;
  o[15] = w15;
  o[16] = w16;
  o[17] = w17;
  o[18] = w18;

  if (c !== 0) {
    o[19] = c;
    out.length += 1;
  }

  return out;
}

// Polyfill comb.
if (!Math.imul)
  comb10MulTo = smallMulTo;

function bigMulTo(self, num, out) {
  out.negative = num.negative ^ self.negative;
  out.length = self.length + num.length;

  let carry = 0;
  let hncarry = 0;
  let k = 0;

  for (; k < out.length - 1; k++) {
    // Sum all words with the same
    // `i + j = k` and accumulate
    // `ncarry`, note that ncarry
    // could be >= 0x3ffffff.
    let ncarry = hncarry;

    hncarry = 0;

    let rword = carry & 0x3ffffff;

    const maxJ = Math.min(k, num.length - 1);

    for (let j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
      const i = k - j;
      const a = self.words[i] | 0;
      const b = num.words[j] | 0;
      const r = a * b;

      let lo = r & 0x3ffffff;
      ncarry = (ncarry + ((r / 0x4000000) | 0)) | 0;
      lo = (lo + rword) | 0;
      rword = lo & 0x3ffffff;
      ncarry = (ncarry + (lo >>> 26)) | 0;

      hncarry += ncarry >>> 26;
      ncarry &= 0x3ffffff;
    }

    out.words[k] = rword;
    carry = ncarry;
    ncarry = hncarry;
  }

  if (carry !== 0)
    out.words[k] = carry;
  else
    out.length--;

  return out._strip();
}

/*
 * Expose
 */

module.exports = BN;
