/*!
 * int64.js - int64 object for javascript.
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/n64
 */

'use strict';

/*
 * N64 (abstract)
 */

function N64(sign) {
  enforce(this instanceof N64, 'this', 'N64');
  enforce(sign === 0 || sign === 1, 'sign', 'bit');

  this.hi = 0;
  this.lo = 0;
  this.sign = sign;
}

/*
 * Addition
 */

N64.prototype._add = function _add(bhi, blo) {
  const ahi = this.hi;
  const alo = this.lo;

  // Credit to @indutny for this method.
  const lo = (alo + blo) | 0;

  const s = lo >> 31;
  const as = alo >> 31;
  const bs = blo >> 31;

  const c = ((as & bs) | (~s & (as ^ bs))) & 1;

  const hi = ((ahi + bhi) | 0) + c;

  this.hi = hi | 0;
  this.lo = lo;

  return this;
};

N64.prototype.iadd = function iadd(b) {
  enforce(N64.isN64(b), 'operand', 'int64');
  return this._add(b.hi, b.lo);
};

N64.prototype.iaddn = function iaddn(num) {
  enforce(isNumber(num), 'operand', 'number');
  return this._add((num >> 31) & -this.sign, num | 0);
};

N64.prototype.add = function add(b) {
  return this.clone().iadd(b);
};

N64.prototype.addn = function addn(num) {
  return this.clone().iaddn(num);
};

/*
 * Subtraction
 */

N64.prototype._sub = function _sub(bhi, blo) {
  bhi = ~bhi;
  blo = ~blo;

  if (blo === -1) {
    blo = 0;
    bhi += 1;
    bhi |= 0;
  } else {
    blo += 1;
  }

  return this._add(bhi, blo);
};

N64.prototype.isub = function isub(b) {
  enforce(N64.isN64(b), 'operand', 'int64');
  return this._sub(b.hi, b.lo);
};

N64.prototype.isubn = function isubn(num) {
  enforce(isNumber(num), 'operand', 'number');
  return this._sub((num >> 31) & -this.sign, num | 0);
};

N64.prototype.sub = function sub(b) {
  return this.clone().isub(b);
};

N64.prototype.subn = function subn(num) {
  return this.clone().isubn(num);
};

/*
 * Multiplication
 */

N64.prototype._mul = function _mul(bhi, blo) {
  const ahi = this.hi;
  const alo = this.lo;

  const a48 = ahi >>> 16;
  const a32 = ahi & 0xffff;
  const a16 = alo >>> 16;
  const a00 = alo & 0xffff;

  const b48 = bhi >>> 16;
  const b32 = bhi & 0xffff;
  const b16 = blo >>> 16;
  const b00 = blo & 0xffff;

  let c48 = 0;
  let c32 = 0;
  let c16 = 0;
  let c00 = 0;

  c00 += a00 * b00;
  c16 += c00 >>> 16;
  c00 &= 0xffff;
  c16 += a16 * b00;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c16 += a00 * b16;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c32 += a32 * b00;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c32 += a16 * b16;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c32 += a00 * b32;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c48 += a48 * b00 + a32 * b16 + a16 * b32 + a00 * b48;
  c48 &= 0xffff;

  const hi = (c48 << 16) | c32;
  const lo = (c16 << 16) | c00;

  this.hi = hi;
  this.lo = lo;

  return this;
};

N64.prototype.imul = function imul(b) {
  enforce(N64.isN64(b), 'multiplicand', 'int64');
  return this._mul(b.hi, b.lo);
};

N64.prototype.imuln = function imuln(num) {
  enforce(isNumber(num), 'multiplicand', 'number');
  return this._mul((num >> 31) & -this.sign, num | 0);
};

N64.prototype.mul = function mul(b) {
  return this.clone().imul(b);
};

N64.prototype.muln = function muln(num) {
  return this.clone().imuln(num);
};

/*
 * Division
 */

N64.prototype.idiv = function idiv(b) {
  let a = this;

  enforce(N64.isN64(b), 'divisor', 'int64');

  if (b.isZero())
    throw new Error('Cannot divide by zero.');

  if (a.isZero())
    return a;

  if (a.eq(b))
    return a.set(1);

  if (a.isSafe() && b.isSafe()) {
    const n = a.toDouble();
    const d = b.toDouble();
    const q = floor(n / d);
    return a.set(q);
  }

  let neg = false;

  if (a.sign) {
    if (a.hi < 0) {
      if (b.hi < 0) {
        a = a.ineg();
        b = b.neg();
      } else {
        a = a.ineg();
        neg = true;
      }
    } else if (b.hi < 0) {
      b = b.neg();
      neg = true;
    }
  }

  const n = a.toU64();
  const d = b.toU64();

  if (n.lt(d))
    return a.set(0);

  if (n.ushrn(1).lt(d))
    return a.set(neg ? -1 : 1);

  const q = new U64();
  const r = new U64();

  let bit = n.bitLength();

  while (bit--) {
    r.ishln(1);
    r.lo |= n.testn(bit);
    if (r.gte(d)) {
      r.isub(d);
      q.setn(bit, 1);
    }
  }

  a.hi = q.hi;
  a.lo = q.lo;

  if (neg)
    a.ineg();

  return a;
};

N64.prototype.idivn = function idivn(num) {
  enforce(isNumber(num), 'divisor', 'number');
  return this.idiv(this._small(num));
};

N64.prototype.div = function div(b) {
  return this.clone().idiv(b);
};

N64.prototype.divn = function divn(num) {
  return this.clone().idivn(num);
};

/*
 * Modulo
 */

N64.prototype.imod = function imod(b) {
  const a = this;

  enforce(N64.isN64(b), 'divisor', 'int64');

  if (b.isZero())
    throw new Error('Cannot divide by zero.');

  if (a.isZero())
    return a;

  if (a.eq(b))
    return a.set(0);

  if (a.isSafe() && b.isSafe()) {
    const n = a.toDouble();
    const d = b.toDouble();
    const r = n % d;
    return a.set(r);
  }

  return a.isub(a.div(b).imul(b));
};

N64.prototype.imodn = function imodn(num) {
  enforce(isNumber(num), 'divisor', 'number');
  return this.imod(this._small(num));
};

N64.prototype.mod = function mod(b) {
  return this.clone().imod(b);
};

N64.prototype.modn = function modn(num) {
  return this.clone().imodn(num);
};

/*
 * Exponentiation
 */

N64.prototype.ipow = function ipow(b) {
  enforce(N64.isN64(b), 'exponent', 'int64');
  return this.ipown(b.lo);
};

N64.prototype.ipown = function ipown(num) {
  enforce(isNumber(num), 'exponent', 'number');

  if (this.isZero())
    return this;

  const x = this.clone();
  const n = this;

  let y = num >>> 0;

  n.set(1);

  while (y > 0) {
    if (y & 1)
      n.imul(x);
    y >>>= 1;
    x.imul(x);
  }

  return n;
};

N64.prototype.pow = function pow(b) {
  return this.clone().ipow(b);
};

N64.prototype.pown = function pown(num) {
  return this.clone().ipown(num);
};

N64.prototype.sqr = function sqr() {
  return this.mul(this);
};

N64.prototype.isqr = function isqr() {
  return this.imul(this);
};

/*
 * AND
 */

N64.prototype.iand = function iand(b) {
  enforce(N64.isN64(b), 'operand', 'int64');
  this.hi &= b.hi;
  this.lo &= b.lo;
  return this;
};

N64.prototype.iandn = function iandn(num) {
  enforce(isNumber(num), 'operand', 'number');
  this.hi &= (num >> 31) & -this.sign;
  this.lo &= num | 0;
  return this;
};

N64.prototype.and = function and(b) {
  return this.clone().iand(b);
};

N64.prototype.andn = function andn(num) {
  return this.clone().iandn(num);
};

/*
 * OR
 */

N64.prototype.ior = function ior(b) {
  enforce(N64.isN64(b), 'operand', 'int64');
  this.hi |= b.hi;
  this.lo |= b.lo;
  return this;
};

N64.prototype.iorn = function iorn(num) {
  enforce(isNumber(num), 'operand', 'number');
  this.hi |= (num >> 31) & -this.sign;
  this.lo |= num | 0;
  return this;
};

N64.prototype.or = function or(b) {
  return this.clone().ior(b);
};

N64.prototype.orn = function orn(num) {
  return this.clone().iorn(num);
};

/*
 * XOR
 */

N64.prototype.ixor = function ixor(b) {
  enforce(N64.isN64(b), 'operand', 'int64');
  this.hi ^= b.hi;
  this.lo ^= b.lo;
  return this;
};

N64.prototype.ixorn = function ixorn(num) {
  enforce(isNumber(num), 'operand', 'number');
  this.hi ^= (num >> 31) & -this.sign;
  this.lo ^= num | 0;
  return this;
};

N64.prototype.xor = function xor(b) {
  return this.clone().ixor(b);
};

N64.prototype.xorn = function xorn(num) {
  return this.clone().ixorn(num);
};

/*
 * NOT
 */

N64.prototype.inot = function inot() {
  this.hi = ~this.hi;
  this.lo = ~this.lo;
  return this;
};

N64.prototype.not = function not() {
  return this.clone().inot();
};

/*
 * Left Shift
 */

N64.prototype.ishl = function ishl(b) {
  enforce(N64.isN64(b), 'bits', 'int64');
  return this.ishln(b.lo);
};

N64.prototype.ishln = function ishln(bits) {
  enforce(isNumber(bits), 'bits', 'number');

  bits &= 63;

  if (bits === 0)
    return this;

  let hi = this.hi;
  let lo = this.lo;

  if (bits < 32) {
    hi <<= bits;
    hi |= lo >>> (32 - bits);
    lo <<= bits;
  } else {
    hi = lo << (bits - 32);
    lo = 0;
  }

  this.hi = hi;
  this.lo = lo;

  return this;
};

N64.prototype.shl = function shl(b) {
  return this.clone().ishl(b);
};

N64.prototype.shln = function shln(bits) {
  return this.clone().ishln(bits);
};

/*
 * Right Shift
 */

N64.prototype.ishr = function ishr(b) {
  enforce(N64.isN64(b), 'bits', 'int64');
  return this.ishrn(b.lo);
};

N64.prototype.ishrn = function ishrn(bits) {
  if (!this.sign)
    return this.iushrn(bits);

  enforce(isNumber(bits), 'bits', 'number');

  bits &= 63;

  if (bits === 0)
    return this;

  let hi = this.hi;
  let lo = this.lo;

  if (bits < 32) {
    lo >>>= bits;
    lo |= hi << (32 - bits);
    hi >>= bits;
  } else {
    lo = hi >> (bits - 32);
    hi = hi >> 31;
  }

  this.hi = hi;
  this.lo = lo;

  return this;
};

N64.prototype.shr = function shr(b) {
  return this.clone().ishr(b);
};

N64.prototype.shrn = function shrn(bits) {
  return this.clone().ishrn(bits);
};

/*
 * Unsigned Right Shift
 */

N64.prototype.iushr = function iushr(b) {
  enforce(N64.isN64(b), 'bits', 'int64');
  return this.iushrn(b.lo);
};

N64.prototype.iushrn = function iushrn(bits) {
  enforce(isNumber(bits), 'bits', 'number');

  bits &= 63;

  if (bits === 0)
    return this;

  let hi = this.hi;
  let lo = this.lo;

  if (bits < 32) {
    lo >>>= bits;
    lo |= hi << (32 - bits);
    hi >>>= bits;
  } else {
    lo = hi >>> (bits - 32);
    hi = 0;
  }

  this.hi = hi | 0;
  this.lo = lo | 0;

  return this;
};

N64.prototype.ushr = function ushr(b) {
  return this.clone().iushr(b);
};

N64.prototype.ushrn = function ushrn(bits) {
  return this.clone().iushrn(bits);
};

/*
 * Bit Manipulation
 */

N64.prototype.setn = function setn(bit, val) {
  enforce(isNumber(bit), 'bit', 'number');

  bit &= 63;

  if (bit < 32) {
    if (val)
      this.lo |= (1 << bit);
    else
      this.lo &= ~(1 << bit);
  } else {
    if (val)
      this.hi |= (1 << (bit - 32));
    else
      this.hi &= ~(1 << (bit - 32));
  }

  return this;
};

N64.prototype.testn = function testn(bit) {
  enforce(isNumber(bit), 'bit', 'number');

  bit &= 63;

  if (bit < 32)
    return (this.lo >>> bit) & 1;

  return (this.hi >>> (bit - 32)) & 1;
};

N64.prototype.setb = function setb(pos, ch) {
  enforce(isNumber(pos), 'pos', 'number');
  enforce(isNumber(ch), 'ch', 'number');

  pos &= 7;
  ch &= 0xff;

  if (pos < 4) {
    this.lo &= ~(0xff << (pos * 8));
    this.lo |= ch << (pos * 8);
  } else {
    this.hi &= ~(0xff << ((pos - 4) * 8));
    this.hi |= ch << ((pos - 4) * 8);
  }

  return this;
};

N64.prototype.orb = function orb(pos, ch) {
  enforce(isNumber(pos), 'pos', 'number');
  enforce(isNumber(ch), 'ch', 'number');

  pos &= 7;
  ch &= 0xff;

  if (pos < 4)
    this.lo |= ch << (pos * 8);
  else
    this.hi |= ch << ((pos - 4) * 8);

  return this;
};

N64.prototype.getb = function getb(pos) {
  enforce(isNumber(pos), 'pos', 'number');

  pos &= 7;

  if (pos < 4)
    return (this.lo >> (pos * 8)) & 0xff;

  return (this.hi >> ((pos - 4) * 8)) & 0xff;
};

N64.prototype.imaskn = function imaskn(bit) {
  enforce(isNumber(bit), 'bit', 'number');

  bit &= 63;

  if (bit < 32) {
    this.hi = 0;
    this.lo &= (1 << bit) - 1;
  } else {
    this.hi &= (1 << (bit - 32)) - 1;
    this.lo &= 0xffffffff;
  }

  return this;
};

N64.prototype.maskn = function maskn(bit) {
  return this.clone().imaskn(bit);
};

N64.prototype.andln = function andln(num) {
  enforce(isNumber(num), 'operand', 'number');
  return this.lo & num;
};

/*
 * Negation
 */

N64.prototype.ineg = function ineg() {
  let hi = ~this.hi;
  let lo = ~this.lo;

  if (lo === -1) {
    lo = 0;
    hi += 1;
    hi |= 0;
  } else {
    lo += 1;
  }

  this.hi = hi;
  this.lo = lo;

  return this;
};

N64.prototype.neg = function neg() {
  return this.clone().ineg();
};

N64.prototype.iabs = function iabs() {
  if (this.isNeg())
    this.ineg();
  return this;
};

N64.prototype.abs = function abs() {
  return this.clone().iabs();
};

/*
 * Comparison
 */

N64.prototype._cmp = function _cmp(bhi, blo) {
  const a = this;

  let ahi = a.hi;
  let alo = a.lo;

  if (ahi === bhi && alo === blo)
    return 0;

  let neg = false;

  if (a.sign) {
    const x = ahi < 0;
    const y = bhi < 0;

    if (x && !y)
      return -1;

    if (!x && y)
      return 1;

    neg = x;
  }

  if (!neg) {
    ahi >>>= 0;
    bhi >>>= 0;
  }

  if (ahi < bhi)
    return -1;

  if (ahi > bhi)
    return 1;

  alo >>>= 0;
  blo >>>= 0;

  if (alo < blo)
    return -1;

  return 1;
};

N64.prototype.cmp = function cmp(b) {
  enforce(N64.isN64(b), 'value', 'int64');
  return this._cmp(b.hi, b.lo);
};

N64.prototype.cmpn = function cmpn(num) {
  enforce(isNumber(num), 'value', 'number');
  return this._cmp((num >> 31) & -this.sign, num | 0);
};

N64.prototype.eq = function eq(b) {
  enforce(N64.isN64(b), 'value', 'int64');
  return this.hi === b.hi && this.lo === b.lo;
};

N64.prototype.eqn = function eqn(num) {
  enforce(isNumber(num), 'value', 'number');
  return this.hi === ((num >> 31) & -this.sign) && this.lo === (num | 0);
};

N64.prototype.gt = function gt(b) {
  return this.cmp(b) > 0;
};

N64.prototype.gtn = function gtn(num) {
  return this.cmpn(num) > 0;
};

N64.prototype.gte = function gte(b) {
  return this.cmp(b) >= 0;
};

N64.prototype.gten = function gten(num) {
  return this.cmpn(num) >= 0;
};

N64.prototype.lt = function lt(b) {
  return this.cmp(b) < 0;
};

N64.prototype.ltn = function ltn(num) {
  return this.cmpn(num) < 0;
};

N64.prototype.lte = function lte(b) {
  return this.cmp(b) <= 0;
};

N64.prototype.lten = function lten(num) {
  return this.cmpn(num) <= 0;
};

N64.prototype.isZero = function isZero() {
  return this.hi === 0 && this.lo === 0;
};

N64.prototype.isNeg = function isNeg() {
  return this.sign === 1 && this.hi < 0;
};

N64.prototype.isOdd = function isOdd() {
  return (this.lo & 1) === 1;
};

N64.prototype.isEven = function isEven() {
  return (this.lo & 1) === 0;
};

/*
 * Helpers
 */

N64.prototype.clone = function clone() {
  const n = new this.constructor();
  n.hi = this.hi;
  n.lo = this.lo;
  return n;
};

N64.prototype.inject = function inject(b) {
  enforce(N64.isN64(b), 'value', 'int64');
  this.hi = b.hi;
  this.lo = b.lo;
  return this;
};

N64.prototype.set = function set(num) {
  enforce(isSafeInteger(num), 'number', 'integer');

  let neg = false;

  if (num < 0) {
    num = -num;
    neg = true;
  }

  this.hi = (num * (1 / 0x100000000)) | 0;
  this.lo = num | 0;

  if (neg)
    this.ineg();

  return this;
};

N64.prototype.join = function join(hi, lo) {
  enforce(isNumber(hi), 'hi', 'number');
  enforce(isNumber(lo), 'lo', 'number');
  this.hi = hi | 0;
  this.lo = lo | 0;
  return this;
};

N64.prototype._small = function _small(num) {
  const n = new this.constructor();
  n.hi = (num >> 31) & -this.sign;
  n.lo = num | 0;
  return n;
};

N64.prototype.bitLength = function bitLength() {
  let a = this;

  if (this.isNeg())
    a = this.neg();

  if (a.hi === 0)
    return countBits(a.lo);

  return countBits(a.hi) + 32;
};

N64.prototype.byteLength = function byteLength() {
  return Math.ceil(this.bitLength() / 8);
};

N64.prototype.isSafe = function isSafe() {
  let hi = this.hi;

  if (this.isNeg()) {
    hi = ~hi;
    if (this.lo === 0)
      hi += 1;
  }

  return (hi & 0xffe00000) === 0;
};

N64.prototype.inspect = function inspect() {
  let prefix = 'I64';

  if (!this.sign)
    prefix = 'U64';

  return `<${prefix}: ${this.toString(10)}>`;
};

/*
 * Encoding
 */

N64.prototype.readLE = function readLE(data, off) {
  enforce(data && typeof data.length === 'number', 'data', 'arraylike');
  enforce((off >> 0) === off, 'offset', 'integer');
  enforce(off + 8 <= data.length, 'offset', 'valid offset');
  this.lo = readI32LE(data, off);
  this.hi = readI32LE(data, off + 4);
  return off + 8;
};

N64.prototype.readBE = function readBE(data, off) {
  enforce(data && typeof data.length === 'number', 'data', 'arraylike');
  enforce((off >> 0) === off, 'offset', 'integer');
  enforce(off + 8 <= data.length, 'offset', 'valid offset');
  this.hi = readI32BE(data, off);
  this.lo = readI32BE(data, off + 4);
  return off + 8;
};

N64.prototype.readRaw = function readRaw(data, off) {
  return this.readLE(data, off);
};

N64.prototype.writeLE = function writeLE(data, off) {
  enforce(data && typeof data.length === 'number', 'data', 'arraylike');
  enforce((off >> 0) === off, 'offset', 'integer');
  enforce(off + 8 <= data.length, 'offset', 'valid offset');
  writeI32LE(data, this.lo, off);
  writeI32LE(data, this.hi, off + 4);
  return off + 8;
};

N64.prototype.writeBE = function writeBE(data, off) {
  enforce(data && typeof data.length === 'number', 'data', 'arraylike');
  enforce((off >> 0) === off, 'offset', 'integer');
  enforce(off + 8 <= data.length, 'offset', 'valid offset');
  writeI32BE(data, this.hi, off);
  writeI32BE(data, this.lo, off + 4);
  return off + 8;
};

N64.prototype.writeRaw = function writeRaw(data, off) {
  return this.writeLE(data, off);
};

/*
 * Conversion
 */

N64.prototype.toU64 = function toU64() {
  const n = new U64();
  n.hi = this.hi;
  n.lo = this.lo;
  return n;
};

N64.prototype.toI64 = function toI64() {
  const n = new I64();
  n.hi = this.hi;
  n.lo = this.lo;
  return n;
};

N64.prototype.toNumber = function toNumber() {
  if (!this.isSafe())
    throw new Error('Number exceeds 53 bits.');

  return this.toDouble();
};

N64.prototype.toDouble = function toDouble() {
  let hi = this.hi;

  if (!this.sign)
    hi >>>= 0;

  return hi * 0x100000000 + (this.lo >>> 0);
};

N64.prototype.toInt = function toInt() {
  return this.sign ? this.lo : this.lo >>> 0;
};

N64.prototype.toBool = function toBool() {
  return !this.isZero();
};

N64.prototype.toBits = function toBits() {
  return [this.hi, this.lo];
};

N64.prototype.toObject = function toObject() {
  return { hi: this.hi, lo: this.lo };
};

N64.prototype.toString = function toString(base, pad) {
  base = getBase(base);

  if (pad == null)
    pad = 0;

  enforce((base >>> 0) === base, 'base', 'integer');
  enforce((pad >>> 0) === pad, 'pad', 'integer');

  if (base < 2 || base > 16)
    throw new Error('Base ranges between 2 and 16.');

  if (pad > 64)
    throw new Error('Maximum padding is 64 characters.');

  let n = this;
  let neg = false;

  if (n.isNeg()) {
    n = n.neg();
    neg = true;
  }

  let hi = n.hi >>> 0;
  let lo = n.lo >>> 0;
  let str = '';

  do {
    const mhi = hi % base;
    hi -= mhi;
    hi /= base;
    lo += mhi * 0x100000000;

    const mlo = lo % base;
    lo -= mlo;
    lo /= base;

    let ch = mlo;

    if (ch < 10)
      ch += 0x30;
    else
      ch += 0x61 - 10;

    str = String.fromCharCode(ch) + str;
  } while (lo > 0 || hi > 0);

  while (str.length < pad)
    str = '0' + str;

  if (neg)
    str = '-' + str;

  return str;
};

N64.prototype.toJSON = function toJSON() {
  return this.toString(16, 16);
};

N64.prototype.toBN = function toBN(BN) {
  const neg = this.isNeg();

  let hi = this.hi;
  let lo = this.lo;

  if (neg) {
    hi = ~hi;
    lo = ~lo;
    if (lo === -1) {
      lo = 0;
      hi += 1;
      hi |= 0;
    } else {
      lo += 1;
    }
  }

  hi >>>= 0;
  lo >>>= 0;

  const num = new BN(hi);
  num.ishln(32);
  num.iadd(new BN(lo));

  if (neg)
    num.ineg();

  return num;
};

N64.prototype.toLE = function toLE(ArrayLike) {
  enforce(typeof ArrayLike === 'function', 'ArrayLike', 'constructor');
  const data = alloc(ArrayLike, 8);
  this.writeLE(data, 0);
  return data;
};

N64.prototype.toBE = function toBE(ArrayLike) {
  enforce(typeof ArrayLike === 'function', 'ArrayLike', 'constructor');
  const data = alloc(ArrayLike, 8);
  this.writeBE(data, 0);
  return data;
};

N64.prototype.toRaw = function toRaw(ArrayLike) {
  return this.toLE(ArrayLike);
};

/*
 * Instantiation
 */

N64.prototype.fromNumber = function fromNumber(num) {
  return this.set(num);
};

N64.prototype.fromInt = function fromInt(num) {
  enforce(isNumber(num), 'integer', 'number');
  return this.join((num >> 31) & -this.sign, num);
};

N64.prototype.fromBool = function fromBool(value) {
  enforce(typeof value === 'boolean', 'value', 'boolean');
  this.hi = 0;
  this.lo = value ? 1 : 0;
  return this;
};

N64.prototype.fromBits = function fromBits(hi, lo) {
  return this.join(hi, lo);
};

N64.prototype.fromObject = function fromObject(num) {
  enforce(num && typeof num === 'object', 'number', 'object');
  return this.fromBits(num.hi, num.lo);
};

N64.prototype.fromString = function fromString(str, base) {
  base = getBase(base);

  enforce(typeof str === 'string', 'string', 'string');
  enforce((base >>> 0) === base, 'base', 'integer');

  if (base < 2 || base > 16)
    throw new Error('Base ranges between 2 and 16.');

  let neg = false;
  let i = 0;

  if (str.length > 0 && str[0] === '-') {
    i += 1;
    neg = true;
  }

  if (str.length === i || str.length > i + 64)
    throw new Error('Invalid string (bad length).');

  let hi = 0;
  let lo = 0;

  for (; i < str.length; i++) {
    let ch = str.charCodeAt(i);

    if (ch >= 0x30 && ch <= 0x39)
      ch -= 0x30;
    else if (ch >= 0x41 && ch <= 0x5a)
      ch -= 0x41 - 10;
    else if (ch >= 0x61 && ch <= 0x7a)
      ch -= 0x61 - 10;
    else
      ch = base;

    if (ch >= base)
      throw new Error('Invalid string (parse error).');

    lo *= base;
    lo += ch;

    hi *= base;

    if (lo > 0xffffffff) {
      ch = lo % 0x100000000;
      hi += (lo - ch) / 0x100000000;
      lo = ch;
    }

    if (hi > 0xffffffff)
      throw new Error('Invalid string (overflow).');
  }

  this.hi = hi | 0;
  this.lo = lo | 0;

  if (neg)
    this.ineg();

  return this;
};

N64.prototype.fromJSON = function fromJSON(json) {
  return this.fromString(json, 16);
};

N64.prototype.fromBN = function fromBN(num) {
  enforce(num && isArray(num.words), 'number', 'big number');

  const a = this;
  const b = num.clone();
  const neg = b.isNeg();

  if (a.sign && b.testn(63))
    throw new Error('Big number overflow.');

  let i = 0;

  while (!b.isZero()) {
    if (i === 8)
      throw new Error('Big number overflow.');

    a.orb(i, b.andln(0xff));
    b.iushrn(8);
    i++;
  }

  if (neg)
    a.ineg();

  return a;
};

N64.prototype.fromLE = function fromLE(data) {
  this.readLE(data, 0);
  return this;
};

N64.prototype.fromBE = function fromBE(data) {
  this.readBE(data, 0);
  return this;
};

N64.prototype.fromRaw = function fromRaw(data) {
  return this.fromLE(data);
};

N64.prototype.from = function from(num, base) {
  if (num == null)
    return this;

  if (typeof num === 'number') {
    if (typeof base === 'number')
      return this.fromBits(num, base);
    return this.fromNumber(num);
  }

  if (typeof num === 'string')
    return this.fromString(num, base);

  if (typeof num === 'object') {
    if (isArray(num.words))
      return this.fromBN(num);

    if (typeof num.length === 'number')
      return this.fromRaw(num);

    return this.fromObject(num);
  }

  if (typeof num === 'boolean')
    return this.fromBool(num);

  throw new TypeError('Non-numeric object passed to N64.');
};

/*
 * Static Methods
 */

N64.min = function min(a, b) {
  return a.cmp(b) < 0 ? a : b;
};

N64.max = function max(a, b) {
  return a.cmp(b) > 0 ? a : b;
};

N64.random = function random() {
  const n = new this();
  n.hi = (Math.random() * 0x100000000) | 0;
  n.lo = (Math.random() * 0x100000000) | 0;
  return n;
};

N64.pow = function pow(num, exp) {
  return new this().fromInt(num).ipown(exp);
};

N64.shift = function shift(num, bits) {
  return new this().fromInt(num).ishln(bits);
};

N64.readLE = function readLE(data, off) {
  const n = new this();
  n.readLE(data, off);
  return n;
};

N64.readBE = function readBE(data, off) {
  const n = new this();
  n.readBE(data, off);
  return n;
};

N64.readRaw = function readRaw(data, off) {
  const n = new this();
  n.readRaw(data, off);
  return n;
};

N64.fromNumber = function fromNumber(num) {
  return new this().fromNumber(num);
};

N64.fromInt = function fromInt(num) {
  return new this().fromInt(num);
};

N64.fromBool = function fromBool(value) {
  return new this().fromBool(value);
};

N64.fromBits = function fromBits(hi, lo) {
  return new this().fromBits(hi, lo);
};

N64.fromObject = function fromObject(obj) {
  return new this().fromObject(obj);
};

N64.fromString = function fromString(str, base) {
  return new this().fromString(str, base);
};

N64.fromJSON = function fromJSON(json) {
  return new this().fromJSON(json);
};

N64.fromBN = function fromBN(num) {
  return new this().fromBN(num);
};

N64.fromLE = function fromLE(data) {
  return new this().fromLE(data);
};

N64.fromBE = function fromBE(data) {
  return new this().fromBE(data);
};

N64.fromRaw = function fromRaw(data) {
  return new this().fromRaw(data);
};

N64.from = function from(num, base) {
  return new this().from(num, base);
};

N64.isN64 = function isN64(obj) {
  return obj instanceof N64;
};

N64.isU64 = function isU64(obj) {
  return obj instanceof U64;
};

N64.isI64 = function isI64(obj) {
  return obj instanceof I64;
};

/*
 * U64
 */

function U64(num, base) {
  if (!(this instanceof U64))
    return new U64(num, base);

  N64.call(this, 0);

  this.from(num, base);
}

U64.__proto__ = N64;
U64.prototype.__proto__ = N64.prototype;

/*
 * Constants
 */

U64.ULONG_MIN = 0x00000000;
U64.ULONG_MAX = 0xffffffff;

U64.UINT32_MIN = U64(0x00000000, 0x00000000);
U64.UINT32_MAX = U64(0x00000000, 0xffffffff);

U64.UINT64_MIN = U64(0x00000000, 0x00000000);
U64.UINT64_MAX = U64(0xffffffff, 0xffffffff);

/*
 * I64
 */

function I64(num, base) {
  if (!(this instanceof I64))
    return new I64(num, base);

  N64.call(this, 1);

  this.from(num, base);
}

I64.__proto__ = N64;
I64.prototype.__proto__ = N64.prototype;

/*
 * Constants
 */

I64.LONG_MIN = -0x80000000;
I64.LONG_MAX = 0x7fffffff;

I64.INT32_MIN = I64(0xffffffff, 0x80000000);
I64.INT32_MAX = I64(0x00000000, 0x7fffffff);

I64.INT64_MIN = I64(0x80000000, 0x00000000);
I64.INT64_MAX = I64(0x7fffffff, 0xffffffff);

/*
 * Helpers
 */

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

function countBits(word) {
  if (Math.clz32)
    return 32 - Math.clz32(word);

  let bit = 31;

  for (; bit >= 0; bit--) {
    if ((word & (1 << bit)) !== 0)
      break;
  }

  return bit + 1;
}

function floor(n) {
  if (n < 0)
    return -Math.floor(-n);
  return Math.floor(n);
}

function enforce(value, name, type) {
  if (!value) {
    const err = new TypeError(`'${name}' must be a(n) ${type}.`);
    if (Error.captureStackTrace)
      Error.captureStackTrace(err, enforce);
    throw err;
  }
}

function isNumber(num) {
  return typeof num === 'number' && isFinite(num);
}

function isArray(num) {
  if (Array.isArray)
    return Array.isArray(num);

  return ({}).toString.call(num).slice(8, -1) === 'Array';
}

function isSafeInteger(num) {
  if (Number.isSafeInteger)
    return Number.isSafeInteger(num);

  return isNumber(num)
    && Math.floor(num) === num
    && num >= -0x001fffffffffffff
    && num <= 0x001fffffffffffff;
}

function alloc(ArrayLike, size) {
  if (ArrayLike.allocUnsafe)
    return ArrayLike.allocUnsafe(size);

  return new ArrayLike(size);
}

function readI32LE(data, off) {
  return data[off]
    | (data[off + 1] << 8)
    | (data[off + 2] << 16)
    | (data[off + 3] << 24);
}

function readI32BE(data, off) {
  return (data[off] << 24)
    | (data[off + 1] << 16)
    | (data[off + 2] << 8)
    | data[off + 3];
}

function writeI32LE(data, num, off) {
  data[off] = num & 0xff;
  data[off + 1] = (num >>> 8) & 0xff;
  data[off + 2] = (num >>> 16) & 0xff;
  data[off + 3] = (num >>> 24) & 0xff;
}

function writeI32BE(data, num, off) {
  data[off] = (num >>> 24) & 0xff;
  data[off + 1] = (num >>> 16) & 0xff;
  data[off + 2] = (num >>> 8) & 0xff;
  data[off + 3] = num & 0xff;
}

/*
 * Expose
 */

exports.N64 = N64;
exports.U64 = U64;
exports.I64 = I64;
