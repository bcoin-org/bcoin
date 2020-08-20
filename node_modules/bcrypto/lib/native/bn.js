/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/bn.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/bn.js
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on openssl/openssl:
 *   Copyright (c) 1998-2018, The OpenSSL Project (Apache License v2.0).
 *   Copyright (c) 1995-1998, Eric A. Young, Tim J. Hudson. All rights reserved.
 *   https://github.com/openssl/openssl
 *
 * Parts of this software are based on libgmp:
 *   Copyright (c) 1991-1997, 1999-2014, Free Software Foundation, Inc.
 *   https://gmplib.org/
 *
 * Parts of this software are based on v8/v8:
 *   Copyright (c) 2017, The V8 Project Authors (BSD-Style License).
 *   https://github.com/v8/v8
 *
 * Resources:
 *   https://github.com/indutny/bn.js/blob/master/lib/bn.js
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/openssl/openssl/tree/master/crypto/bn
 *   https://github.com/openssl/openssl/blob/master/crypto/bn/bn_kron.c
 *   https://github.com/gnutls/nettle/blob/master/mini-gmp.c
 *   https://github.com/v8/v8/blob/master/src/objects/bigint.cc
 */

/* eslint valid-typeof: "off" */

'use strict';

const {custom} = require('../internal/custom');

/*
 * Constants
 */

const U8_MAX = (1n << 8n) - 1n;
const U16_MAX = (1n << 16n) - 1n;
const U32_MAX = (1n << 32n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;
const U256_MAX = (1n << 256n) - 1n;
const MAX_SAFE_INTEGER = 9007199254740991n;
const ENDIAN = new Int8Array(new Int16Array([1]).buffer)[0] === 0 ? 'be' : 'le';

const WND_WIDTH = 4;
const WND_SIZE = 1 << (WND_WIDTH - 1);
const WND_MASK = (1 << WND_WIDTH) - 1;
const WND_WIDTH_BIG = BigInt(WND_WIDTH);
const WND_SIZE_BIG = BigInt(WND_SIZE);
const WND_MASK_BIG = BigInt(WND_MASK);

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
    this.n = 0n;
    this.red = null;
    this.from(num, base, endian);
  }

  /*
   * Compat
   */

  get negative() {
    return this.n < 0n ? 1 : 0;
  }

  set negative(val) {
    if ((val & 1) !== this.negative)
      this.n = -this.n;
  }

  get length() {
    return countWords(this.n, 26);
  }

  /*
   * Addition
   */

  iadd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n += num.n;

    return this;
  }

  iaddn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n += BigInt(num);

    return this;
  }

  add(num) {
    return this.clone().iadd(num);
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  /*
   * Subtraction
   */

  isub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n -= num.n;

    return this;
  }

  isubn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n -= BigInt(num);

    return this;
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

  imul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n *= num.n;

    return this;
  }

  imuln(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n *= BigInt(num);

    return this;
  }

  mul(num) {
    return this.clone().imul(num);
  }

  muln(num) {
    return this.clone().imuln(num);
  }

  /*
   * Multiplication + Shift
   */

  mulShift(num, bits) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(((bits - 1) >>> 0) === bits - 1, 'bits', 'uint32');

    return new BN(mulShift(this.n, num.n, bits));
  }

  /*
   * Truncation Division + Modulo
   */

  quorem(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonzero(num.n !== 0n);

    const [q, r] = quorem(this.n, num.n);

    return [new BN(q), new BN(r)];
  }

  /*
   * Truncation Division
   */

  iquo(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonzero(num.n !== 0n);

    this.n /= num.n;

    return this;
  }

  iquon(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    this.n /= BigInt(num);

    return this;
  }

  quo(num) {
    return this.clone().iquo(num);
  }

  quon(num) {
    return this.clone().iquon(num);
  }

  /*
   * Truncation Modulo
   */

  irem(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonzero(num.n !== 0n);

    this.n %= num.n;

    return this;
  }

  iremn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    this.n %= BigInt(num);

    return this;
  }

  rem(num) {
    return this.clone().irem(num);
  }

  remn(num) {
    return this.clone().iremn(num);
  }

  remrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);
    return remrn(this.n, num);
  }

  /*
   * Euclidean Division + Modulo
   */

  divmod(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonzero(num.n !== 0n);

    const [q, r] = divmod(this.n, num.n);

    return [new BN(q), new BN(r)];
  }

  /*
   * Euclidean Division
   */

  idiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonzero(num.n !== 0n);

    this.n = div(this.n, num.n);

    return this;
  }

  idivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    this.n = div(this.n, BigInt(num));

    return this;
  }

  div(num) {
    return this.clone().idiv(num);
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  /*
   * Euclidean Modulo
   */

  imod(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonzero(num.n !== 0n);

    this.n = mod(this.n, num.n);

    return this;
  }

  imodn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    this.n = mod(this.n, BigInt(num));

    return this;
  }

  mod(num) {
    return this.clone().imod(num);
  }

  modn(num) {
    return this.clone().imodn(num);
  }

  modrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);
    return modrn(this.n, num);
  }

  /*
   * Round Division
   */

  divRound(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonzero(num.n !== 0n);
    return new BN(divRound(this.n, num.n));
  }

  /*
   * Exponentiation
   */

  ipow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n **= abs(num.n);

    return this;
  }

  ipown(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n **= abs(BigInt(num));

    return this;
  }

  pow(num) {
    return this.clone().ipow(num);
  }

  pown(num) {
    return this.clone().ipown(num);
  }

  isqr() {
    this.n *= this.n;
    return this;
  }

  sqr() {
    return this.clone().isqr();
  }

  /*
   * Roots
   */

  rootrem(pow) {
    const [x, r] = rootrem(this.n, pow);
    return [new BN(x), new BN(r)];
  }

  iroot(pow) {
    this.n = root(this.n, pow);
    return this;
  }

  root(pow) {
    return this.clone().iroot(pow);
  }

  isPower(pow) {
    return isPower(this.n, pow);
  }

  sqrtrem() {
    const [x, r] = sqrtrem(this.n);
    return [new BN(x), new BN(r)];
  }

  isqrt() {
    this.n = sqrt(this.n);
    return this;
  }

  sqrt() {
    return this.clone().isqrt();
  }

  isSquare() {
    return isSquare(this.n);
  }

  /*
   * AND
   */

  iand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n &= num.n;

    return this;
  }

  iandn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n &= BigInt(num);

    return this;
  }

  and(num) {
    return this.clone().iand(num);
  }

  andn(num) {
    return this.clone().iandn(num);
  }

  andrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const n = this.n & BigInt(num);

    if (n < -0x3ffffffn || n > 0x3ffffffn)
      throw new RangeError('Number exceeds 26 bits.');

    return Number(n);
  }

  /*
   * Unsigned AND
   */

  iuand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n = uand(this.n, num.n);

    return this;
  }

  iuandn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n = uandn(this.n, num);

    return this;
  }

  uand(num) {
    return this.clone().iuand(num);
  }

  uandn(num) {
    return this.clone().iuandn(num);
  }

  uandrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return Number(uandn(this.n, num));
  }

  /*
   * OR
   */

  ior(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n |= num.n;

    return this;
  }

  iorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n |= BigInt(num);

    return this;
  }

  or(num) {
    return this.clone().ior(num);
  }

  orn(num) {
    return this.clone().iorn(num);
  }

  /*
   * Unsigned OR
   */

  iuor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n = uor(this.n, num.n);

    return this;
  }

  iuorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n = uorn(this.n, num);

    return this;
  }

  uor(num) {
    return this.clone().iuor(num);
  }

  uorn(num) {
    return this.clone().iuorn(num);
  }

  /*
   * XOR
   */

  ixor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n ^= num.n;

    return this;
  }

  ixorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n ^= BigInt(num);

    return this;
  }

  xor(num) {
    return this.clone().ixor(num);
  }

  xorn(num) {
    return this.clone().ixorn(num);
  }

  /*
   * Unsigned XOR
   */

  iuxor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n = uxor(this.n, num.n);

    return this;
  }

  iuxorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.n = uxorn(this.n, num);

    return this;
  }

  uxor(num) {
    return this.clone().ixor(num);
  }

  uxorn(num) {
    return this.clone().iuxorn(num);
  }

  /*
   * NOT
   */

  inot() {
    this.n = ~this.n;
    return this;
  }

  not() {
    return this.clone().inot();
  }

  inotn(width) {
    enforce((width >>> 0) === width, 'width', 'uint32');

    this.n = notn(this.n, width);

    return this;
  }

  notn(width) {
    return this.clone().inotn(width);
  }

  /*
   * Left Shift
   */

  ishl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.n >= 0n && num.n <= U32_MAX, 'bits', 'uint32');

    this.n <<= num.n;

    return this;
  }

  ishln(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    this.n <<= BigInt(bits);

    return this;
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
    enforce(num.n >= 0n && num.n <= U32_MAX, 'bits', 'uint32');

    this.n <<= num.n;

    return this;
  }

  iushln(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    this.n <<= BigInt(bits);

    return this;
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
    enforce(num.n >= 0n && num.n <= U32_MAX, 'bits', 'uint32');

    this.n >>= num.n;

    return this;
  }

  ishrn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    this.n >>= BigInt(bits);

    return this;
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
    enforce(num.n >= 0n && num.n <= U32_MAX, 'bits', 'uint32');

    this.n = ushr(this.n, num.n);

    return this;
  }

  iushrn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    this.n = ushrn(this.n, bits);

    return this;
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
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    this.n = setn(this.n, bit, val);

    return this;
  }

  usetn(bit, val) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    this.n = usetn(this.n, bit, val);

    return this;
  }

  testn(bit) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    return testn(this.n, bit);
  }

  utestn(bit) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    return utestn(this.n, bit);
  }

  imaskn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    this.n = maskn(this.n, bits);

    return this;
  }

  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  iumaskn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    this.n = umaskn(this.n, bits);

    return this;
  }

  umaskn(bits) {
    return this.clone().iumaskn(bits);
  }

  andln(num) {
    return andln(this.n, num);
  }

  bit(pos) {
    return this.utestn(pos);
  }

  bits(pos, width) {
    enforce((pos >>> 0) === pos, 'pos', 'uint32');
    enforce((width >>> 0) === width, 'width', 'uint32');
    enforce(width <= 26, 'width', 'width');

    return bits(this.n, pos, width);
  }

  /*
   * Negation
   */

  ineg() {
    this.n = -this.n;
    return this;
  }

  neg() {
    return this.clone().ineg();
  }

  iabs() {
    this.n = abs(this.n);
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
    return cmp(this.n, num.n);
  }

  cmpn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return cmpn(this.n, num);
  }

  eq(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return this.n === num.n;
  }

  eqn(num) {
    enforce(isSMI(num), 'num', 'smi');
    // v8 allows loose comparisons
    // between bigints and doubles.
    // eslint-disable-next-line
    return this.n == num;
  }

  gt(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return this.n > num.n;
  }

  gtn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return this.n > num;
  }

  gte(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return this.n >= num.n;
  }

  gten(num) {
    enforce(isSMI(num), 'num', 'smi');
    return this.n >= num;
  }

  lt(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return this.n < num.n;
  }

  ltn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return this.n < num;
  }

  lte(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return this.n <= num.n;
  }

  lten(num) {
    enforce(isSMI(num), 'num', 'smi');
    return this.n <= num;
  }

  sign() {
    return (this.n > 0n) - (this.n < 0n);
  }

  isZero() {
    return this.n === 0n;
  }

  isNeg() {
    return this.n < 0n;
  }

  isPos() {
    return this.n >= 0n;
  }

  isOdd() {
    return (this.n & 1n) === 1n;
  }

  isEven() {
    return (this.n & 1n) === 0n;
  }

  /*
   * Unsigned Comparison
   */

  ucmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return ucmp(this.n, num.n);
  }

  ucmpn(num) {
    enforce(isSMI(num), 'num', 'smi');
    return ucmpn(this.n, num);
  }

  /*
   * Number Theoretic Functions
   */

  legendre(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    nonred(!num.red, 'legendre');
    return legendre(this.n, num.n);
  }

  jacobi(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return jacobi(this.n, num.n);
  }

  kronecker(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return kronecker(this.n, num.n);
  }

  igcd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n = gcd(this.n, num.n);

    return this;
  }

  gcd(num) {
    return this.clone().igcd(num);
  }

  ilcm(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n = lcm(this.n, num.n);

    return this;
  }

  lcm(num) {
    return this.clone().ilcm(num);
  }

  egcd(p) {
    enforce(BN.isBN(p), 'p', 'bignum');

    const [a, b, gcd] = egcd(this.n, p.n);

    return [new BN(a), new BN(b), new BN(gcd)];
  }

  iinvert(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.n >= 1n, 'iinvert');

    this.n = invert(this.n, num.n);

    return this;
  }

  invert(num) {
    return this.clone().iinvert(num);
  }

  ifermat(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.n >= 1n, 'ifermat');
    nonred(!num.red, 'ifermat');

    this.n = fermat(this.n, num.n);

    return this;
  }

  fermat(num) {
    return this.clone().ifermat(num);
  }

  ipowm(y, m, mont) {
    enforce(BN.isBN(y), 'y', 'bignum');
    enforce(BN.isBN(m), 'm', 'bignum');
    range(m.n >= 1n, 'ipowm');
    nonred(!this.red && !y.red && !m.red, 'ipowm');

    this.n = powm(this.n, y.n, m.n);

    return this;
  }

  powm(y, m, mont) {
    return this.clone().ipowm(y, m, mont);
  }

  ipowmn(y, m, mont) {
    enforce(isSMI(y), 'y', 'smi');
    enforce(BN.isBN(m), 'm', 'bignum');
    range(m.n >= 1n, 'ipowmn');
    nonred(!this.red && !m.red, 'ipowmn');

    this.n = powm(this.n, BigInt(y), m.n);

    return this;
  }

  powmn(y, m, mont) {
    return this.clone().ipowmn(y, m, mont);
  }

  isqrtm(p) {
    enforce(BN.isBN(p), 'p', 'bignum');
    range(p.n >= 1n, 'isqrtm');
    nonred(!this.red && !p.red, 'isqrtm');

    this.n = sqrtm(this.n, p.n);

    return this;
  }

  sqrtm(p) {
    return this.clone().isqrtm(p);
  }

  isqrtpq(p, q) {
    enforce(BN.isBN(p), 'p', 'bignum');
    enforce(BN.isBN(q), 'q', 'bignum');
    range(p.n >= 1n, 'isqrtpq');
    range(q.n >= 1n, 'isqrtpq');
    nonred(!this.red && !p.red && !q.red, 'isqrtpq');

    this.n = sqrtpq(this.n, p.n, q.n);

    return this;
  }

  sqrtpq(p, q) {
    return this.clone().isqrtpq(p, q);
  }

  /*
   * Primality Testing
   */

  isPrime(rng, reps, limit) {
    enforce((reps >>> 0) === reps, 'reps', 'uint32');

    if (!this.isPrimeMR(rng, reps + 1, true))
      return false;

    if (!this.isPrimeLucas(limit))
      return false;

    return true;
  }

  isPrimeMR(rng, reps, force2) {
    return isPrimeMR(this.n, rng, reps, force2);
  }

  isPrimeLucas(limit) {
    return isPrimeLucas(this.n, limit);
  }

  /*
   * Twos Complement
   */

  toTwos(width) {
    enforce((width >>> 0) === width, 'width', 'uint32');
    return new BN(toTwos(this.n, width));
  }

  fromTwos(width) {
    enforce((width >>> 0) === width, 'width', 'uint32');
    range(width > 0, 'width');
    return new BN(fromTwos(this.n, width));
  }

  /*
   * Reduction Context
   */

  toRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red)
      throw new Error('Already in reduction context.');

    return ctx.convertTo(this);
  }

  fromRed() {
    red(this.red, 'fromRed');
    return this.red.convertFrom(this);
  }

  forceRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red) {
      if (ctx.n !== this.red.n || ctx.mont !== this.red.mont)
        throw new Error('Already in reduction context.');
    } else {
      range(this.n >= 0n, 'red');
      range(this.n < ctx.n, 'red');
    }

    return this.clone()._forceRed(ctx);
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

  redIAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIAddn');
    return this.red.iaddn(this, num);
  }

  redAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redAddn');
    return this.red.addn(this, num);
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

  redISubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redISubn');
    return this.red.isubn(this, num);
  }

  redSubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redSubn');
    return this.red.subn(this, num);
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

  redIMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIMuln');
    return this.red.imuln(this, num);
  }

  redMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redMuln');
    return this.red.muln(this, num);
  }

  redIDiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIDiv');
    return this.red.idiv(this, num);
  }

  redDiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redDiv');
    return this.red.div(this, num);
  }

  redIDivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIDivn');
    return this.red.idivn(this, num);
  }

  redDivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redDivn');
    return this.red.divn(this, num);
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

  redIPown(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIPown');
    return this.red.ipown(this, num);
  }

  redPown(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redPown');
    return this.red.pown(this, num);
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

  redIDivSqrt(v) {
    red(this.red, 'redIDivSqrt');
    return this.red.idivsqrt(this, v);
  }

  redDivSqrt(v) {
    red(this.red, 'redDivSqrt');
    return this.red.divsqrt(this, v);
  }

  redIsSquare() {
    red(this.red, 'redIsSquare');
    return this.red.isSquare(this);
  }

  redIShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIShl');
    nonred(!num.red, 'redIShl');
    return this.red.ishl(this, num);
  }

  redShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(num.n >= 0n && num.n <= U32_MAX, 'num', 'uint32');
    red(this.red, 'redShl');
    nonred(!num.red, 'redShl');
    return this.red.shl(this, num);
  }

  redIShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redIShln');
    return this.red.ishln(this, num);
  }

  redShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redShln');
    return this.red.shln(this, num);
  }

  redINeg() {
    red(this.red, 'redINeg');
    return this.red.ineg(this);
  }

  redNeg() {
    red(this.red, 'redNeg');
    return this.red.neg(this);
  }

  redEq(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redEq');
    return this.red.eq(this, num);
  }

  redEqn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redEqn');
    return this.red.eqn(this, num);
  }

  redIsHigh() {
    red(this.red, 'redIsHigh');
    return this.red.isHigh(this);
  }

  redIsLow() {
    red(this.red, 'redIsLow');
    return this.red.isLow(this);
  }

  redIsOdd() {
    red(this.red, 'redIsOdd');
    return this.red.isOdd(this);
  }

  redIsEven() {
    red(this.red, 'redIsEven');
    return this.red.isEven(this);
  }

  redLegendre() {
    red(this.red, 'redLegendre');
    return this.red.legendre(this);
  }

  redJacobi() {
    red(this.red, 'redJacobi');
    return this.red.jacobi(this);
  }

  redKronecker() {
    red(this.red, 'redKronecker');
    return this.red.kronecker(this);
  }

  redIInvert() {
    red(this.red, 'redIInvert');
    return this.red.iinvert(this);
  }

  redInvert() {
    red(this.red, 'redInvert');
    return this.red.invert(this);
  }

  redIFermat() {
    red(this.red, 'redIFermat');
    return this.red.ifermat(this);
  }

  redFermat() {
    red(this.red, 'redFermat');
    return this.red.fermat(this);
  }

  /*
   * Internal
   */

  _forceRed(ctx) {
    this.red = ctx;
    return this;
  }

  /*
   * Helpers
   */

  clone() {
    return new BN().inject(this);
  }

  inject(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.n = num.n;
    this.red = num.red;

    return this;
  }

  set(num, endian) {
    return this.fromNumber(num, endian);
  }

  swap(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    [this.n, num.n] = [num.n, this.n];
    [this.red, num.red] = [num.red, this.red];

    return this;
  }

  reverse() {
    const neg = this.n < 0n;
    const endian = ENDIAN === 'be' ? 'le' : 'be';

    this.fromBuffer(this.toBuffer(endian), ENDIAN);

    if (neg)
      this.n = -this.n;

    return this;
  }

  byteLength() {
    return byteLength(this.n);
  }

  bitLength() {
    return bitLength(this.n);
  }

  zeroBits() {
    return zeroBits(this.n);
  }

  isSafe() {
    return this.n <= MAX_SAFE_INTEGER
        && this.n >= -MAX_SAFE_INTEGER;
  }

  word(pos) {
    enforce((pos >>> 0) === pos, 'pos', 'uint32');
    return word(this.n, pos);
  }

  [custom]() {
    let prefix = 'BN';

    if (this.red)
      prefix = 'BN-R';

    return `<${prefix}: ${this.toString(10)}>`;
  }

  /*
   * Constant Time (sort of)
   */

  csign() {
    return this.cneg() * -2 + 1 - this.czero();
  }

  czero() {
    return (this.n === 0n) | 0;
  }

  cneg() {
    return (this.n < 0n) | 0;
  }

  cpos() {
    return (this.n >= 0n) | 0;
  }

  ceq(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    return ceq(this.n, num.n);
  }

  ceqn(num) {
    const neg = (num >> 31) | 1;
    const word = (((num | 0) * neg) & 0x3ffffff) * neg;

    return ceqn(this.n, word);
  }

  cswap(num, flag) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const cond = ((flag >> 31) | (-flag >> 31)) & 1;

    [this.n, num.n] = cswap(this.n, num.n, cond);

    return this;
  }

  cinject(num, flag) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const cond = ((flag >> 31) | (-flag >> 31)) & 1;

    this.n = cinject(this.n, num.n, cond);

    return this;
  }

  cset(num, flag) {
    const cond = ((flag >> 31) | (-flag >> 31)) & 1;
    const neg = (num >> 31) | 1;
    const word = (((num | 0) * neg) & 0x3ffffff) * neg;

    this.n = cset(this.n, word, cond);

    return this;
  }

  /*
   * Conversion
   */

  toNumber() {
    if (!this.isSafe())
      throw new RangeError('Number can only safely store up to 53 bits.');

    return Number(this.n);
  }

  toDouble() {
    return Number(this.n);
  }

  valueOf() {
    return this.toDouble();
  }

  toBigInt() {
    return this.n;
  }

  toBool() {
    return this.n !== 0n;
  }

  toString(base, padding) {
    return toString(this.n, base, padding);
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
    return toBuffer(this.n, endian, length);
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

    return toArrayLike(this.n, ArrayType, endian, length);
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

    this.n = BigInt(num);

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromDouble(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'number', 'num', 'double');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (!isFinite(num))
      num = 0;

    this.n = BigInt(Math.trunc(num));

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromBigInt(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'bigint', 'num', 'bigint');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    this.n = num;

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromBool(value) {
    enforce(typeof value === 'boolean', 'value', 'boolean');
    return this.set(value ? 1 : 0);
  }

  fromString(str, base, endian) {
    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (endian == null)
      endian = 'be';

    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    this.n = fromString(str, base);

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromJSON(json) {
    if (BN.isBN(json)) {
      if (json.red)
        return json.fromRed();

      return json.clone();
    }

    if (Array.isArray(json)) {
      for (const chunk of json)
        enforce(typeof chunk === 'string', 'chunk', 'string');

      json = json.join('');
    }

    return this.fromString(json, 16);
  }

  fromBN(num) {
    return this.inject(num);
  }

  fromArray(data, endian) {
    enforce(Array.isArray(data), 'data', 'array');

    this.n = fromArrayLike(data, endian);

    return this;
  }

  fromBuffer(data, endian) {
    this.n = fromBuffer(data, endian);
    return this;
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

    this.n = fromArrayLike(data, endian);

    return this;
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

      if ((num.length >>> 0) === num.length)
        return this.fromArrayLike(num, endian);
    }

    if (typeof num === 'boolean')
      return this.fromBool(num);

    throw new TypeError('Non-numeric object passed to BN.');
  }

  /*
   * Static Methods
   */

  static min(...args) {
    let min = null;

    for (const num of args) {
      enforce(BN.isBN(num), 'num', 'bignum');

      if (!min || num.cmp(min) < 0)
        min = num;
    }

    return min || new BN(0);
  }

  static max(...args) {
    let max = null;

    for (const num of args) {
      enforce(BN.isBN(num), 'num', 'bignum');

      if (!max || num.cmp(max) > 0)
        max = num;
    }

    return max || new BN(0);
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
    return new Red(num, false);
  }

  static barret(num) {
    return new Red(num, false);
  }

  static mont(num) {
    return new Red(num, true);
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
      throw new Error(`Unknown prime: "${name}".`);

    primes[name] = prime;

    return prime;
  }

  static prime(name) {
    return BN._prime(name).p.clone();
  }

  static pow(num, exp) {
    if (num === 2)
      return BN.shift(1, exp);

    return new BN().fromNumber(num).ipown(exp);
  }

  static shift(num, bits) {
    return new BN().fromNumber(num).ishln(bits);
  }

  static mask(bits) {
    return BN.shift(1, bits).isubn(1);
  }

  static randomBits(rng, bits) {
    const n = randomBits(rng, bits);
    return new BN(n);
  }

  static random(rng, min, max) {
    const lo = BN.cast(min, 16);
    const hi = BN.cast(max, 16);
    const n = random(rng, lo.n, hi.n);
    return new BN(n);
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

  static cast(num, base, endian) {
    if (BN.isBN(num))
      return num;

    return new BN(num, base, endian);
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
BN.native = 1;

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
    // 2^192 - 2^64 - 1 (= 3 mod 4)
    super('p192', 'ffffffff ffffffff ffffffff fffffffe'
                + 'ffffffff ffffffff');
  }
}

/**
 * P224
 */

class P224 extends Prime {
  constructor() {
    // 2^224 - 2^96 + 1 (no congruence)
    super('p224', 'ffffffff ffffffff ffffffff ffffffff'
                + '00000000 00000000 00000001');
  }
}

/**
 * P521
 */

class P521 extends Prime {
  constructor() {
    // 2^521 - 1 (= 3 mod 4)
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
    // 2^256 - 2^32 - 977 (= 3 mod 4)
    super('k256', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe fffffc2f');
  }
}

/**
 * P25519
 */

class P25519 extends Prime {
  constructor() {
    // 2^255 - 19 (= 5 mod 8)
    super('p25519', '7fffffff ffffffff ffffffff ffffffff'
                  + 'ffffffff ffffffff ffffffff ffffffed');
  }
}

/**
 * P448
 */

class P448 extends Prime {
  constructor() {
    // 2^448 - 2^224 - 1 (= 3 mod 4)
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
  constructor(m, coprime) {
    let prime = null;

    if (typeof m === 'string') {
      prime = BN._prime(m);
      m = prime.p;
    }

    enforce(BN.isBN(m), 'm', 'bignum');
    nonred(!m.red, 'reduction');
    range(m.n >= 1n, 'reduction');

    this.m = m;
    this.n = m.n;
    this.prime = prime;
    this.coprime = coprime;
    this.sm1 = null;
  }

  _verify1(a) {
    range(a.negative === 0, 'red');
    red(a.red != null, 'red');
  }

  _verify2(a, b) {
    range((a.negative | b.negative) === 0, 'red');
    red(a.red != null && a.red === b.red, 'red');
  }

  get mont() {
    return false;
  }

  precompute() {
    // Precompute `sqrt(-1)` for primes congruent to 5 mod 8.
    if (this.sm1 === null && (this.n & 7n) === 5n) {
      // sqrt(-1) = 2^((p - 1) / 4) mod p
      this.sm1 = powm(2n, (this.n - 1n) >> 2n, this.n);
    }

    return this;
  }

  convertTo(num) {
    const res = new BN();
    res.n = mod(num.n, this.n);
    res.red = this;
    return res;
  }

  convertFrom(num) {
    const res = num.clone();
    res.red = null;
    return res;
  }

  iadd(a, b) {
    this._verify2(a, b);

    a.n += b.n;

    if (a.n >= this.n)
      a.n -= this.n;

    return a;
  }

  add(a, b) {
    return this.iadd(a.clone(), b);
  }

  iaddn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.isubn(a, -num);

    let n = BigInt(num);

    if (this.n < 0x4000000n)
      n %= this.n;

    a.n += n;

    if (a.n >= this.n)
      a.n -= this.n;

    return a;
  }

  addn(a, num) {
    return this.iaddn(a.clone(), num);
  }

  isub(a, b) {
    this._verify2(a, b);

    a.n -= b.n;

    if (a.n < 0n)
      a.n += this.n;

    return a;
  }

  sub(a, b) {
    return this.isub(a.clone(), b);
  }

  isubn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.iaddn(a, -num);

    let n = BigInt(num);

    if (this.n < 0x4000000n)
      n %= this.n;

    a.n -= n;

    if (a.n < 0n)
      a.n += this.n;

    return a;
  }

  subn(a, num) {
    return this.isubn(a.clone(), num);
  }

  imul(a, b) {
    this._verify2(a, b);

    a.n *= b.n;
    a.n %= this.n;

    return a;
  }

  mul(a, b) {
    this._verify2(a, b);
    return this.imul(a.clone(), b);
  }

  imuln(a, num) {
    this._verify1(a);

    a.n *= BigInt(num);
    a.n = mod(a.n, this.n);

    return a;
  }

  muln(a, num) {
    return this.imuln(a.clone(), num);
  }

  idiv(a, b) {
    a.n *= invert(b.n, this.n);
    a.n %= this.n;
    return a;
  }

  div(a, b) {
    return this.idiv(a.clone(), b);
  }

  idivn(a, num) {
    a.n *= invert(BigInt(num), this.n);
    a.n %= this.n;
    return a;
  }

  divn(a, num) {
    return this.idivn(a.clone(), num);
  }

  ipow(a, num) {
    this._verify1(a);

    a.n = powm(a.n, num.n, this.n);

    return a;
  }

  pow(a, num) {
    return this.ipow(a.clone(), num);
  }

  ipown(a, num) {
    this._verify1(a);

    a.n = powm(a.n, BigInt(num), this.n);

    return a;
  }

  pown(a, num) {
    return this.ipown(a.clone(), num);
  }

  isqr(a) {
    this._verify1(a);

    a.n *= a.n;
    a.n %= this.n;

    return a;
  }

  sqr(a) {
    return this.isqr(a.clone());
  }

  isqrt(a) {
    this._verify1(a);

    if (this.sm1 != null)
      a.n = sqrt5mod8sm1(a.n, this.n, this.sm1);
    else
      a.n = sqrtm(a.n, this.n);

    return a;
  }

  sqrt(a) {
    return this.isqrt(a.clone());
  }

  idivsqrt(u, v) {
    this._verify2(u, v);

    u.n = divsqrt(u.n, v.n, this.n, this.sm1);

    return u;
  }

  divsqrt(u, v) {
    return this.idivsqrt(u.clone(), v);
  }

  isSquare(a) {
    this._verify1(a);

    let symbol;

    if (this.prime || this.coprime)
      symbol = legendre(a.n, this.n);
    else if (this.n & 1n)
      symbol = jacobi(a.n, this.n);
    else
      symbol = kronecker(a.n, this.n);

    return Boolean(~symbol >>> 31);
  }

  ishl(a, num) {
    this._verify1(a);

    a.n <<= num.n;
    a.n %= this.n;

    return a;
  }

  shl(a, num) {
    return this.ishl(a.clone(), num);
  }

  ishln(a, num) {
    this._verify1(a);

    a.n <<= BigInt(num);
    a.n %= this.n;

    return a;
  }

  shln(a, num) {
    return this.ishln(a.clone(), num);
  }

  ineg(a) {
    this._verify1(a);

    if (a.n !== 0n)
      a.n = this.n - a.n;

    return a;
  }

  neg(a) {
    return this.ineg(a.clone());
  }

  eq(a, b) {
    this._verify2(a, b);
    return a.n === b.n;
  }

  eqn(a, num) {
    this._verify1(a);

    if (this.n < 0x4000000n) {
      const m = Number(this.n);

      num %= m;

      if (num < 0)
        num += m;

      // eslint-disable-next-line
      return a.n == num;
    }

    if (num < 0)
      return a.n === BigInt(num) + this.n;

    // eslint-disable-next-line
    return a.n == num;
  }

  isHigh(a) {
    return !this.isLow(a);
  }

  isLow(a) {
    this._verify1(a);
    return a.n <= (this.n >> 1n);
  }

  isOdd(a) {
    this._verify1(a);
    return a.isOdd();
  }

  isEven(a) {
    this._verify1(a);
    return a.isEven();
  }

  legendre(a) {
    this._verify1(a);
    return legendre(a.n, this.n);
  }

  jacobi(a) {
    this._verify1(a);
    return jacobi(a.n, this.n);
  }

  kronecker(a) {
    this._verify1(a);
    return kronecker(a.n, this.n);
  }

  iinvert(a) {
    this._verify1(a);

    a.n = invert(a.n, this.n);

    return a;
  }

  invert(a) {
    return this.iinvert(a.clone());
  }

  ifermat(a) {
    this._verify1(a);

    a.n = fermat(a.n, this.n);

    return a;
  }

  fermat(a) {
    return this.ifermat(a.clone());
  }

  [custom]() {
    if (this.prime)
      return `<Red: ${this.prime.name}>`;

    return `<Red: ${this.n.toString(10)}>`;
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
    throw makeError(TypeError, msg, nonred);
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
  if (ArrayType.allocUnsafeSlow)
    return ArrayType.allocUnsafeSlow(size);

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

function isFastBase(base) {
  switch (base) {
    case 2:
    case 8:
    case 10:
    case 16:
      return true;
  }
  return false;
}

function reverse(data) {
  let i = 0;
  let j = data.length - 1;
  let k = data.length >>> 1;

  while (k--) {
    const tmp = data[i];
    data[i++] = data[j];
    data[j--] = tmp;
  }

  return data;
}

/*
 * Multiplication + Shift
 */

function mulShift(x, y, bits) {
  const shift = BigInt(bits);
  const neg = (x < 0n) ^ (y < 0n);

  let r = x * y;

  if (neg)
    r = -r;

  const b = (r >> (shift - 1n)) & 1n;

  r >>= shift;
  r += b;

  if (neg)
    r = -r;

  return r;
}

/*
 * Truncation Division + Modulo
 */

function quorem(x, y) {
  assert(y !== 0n);

  const q = x / y;
  const r = x - (q * y);

  return [q, r];
}

/*
 * Modulo
 */

function remrn(x, y) {
  assert(y !== 0);
  return Number(x % BigInt(y));
}

/*
 * Euclidean Division + Modulo
 */

function divmod(x, y) {
  assert(y !== 0n);

  let q = x / y;
  let r = x - (q * y);

  if (r < 0n) {
    if (y < 0n) {
      q += 1n;
      r -= y;
    } else {
      q -= 1n;
      r += y;
    }
  }

  return [q, r];
}

/*
 * Euclidean Division
 */

function div(x, y) {
  assert(y !== 0n);

  let q = x / y;

  if (x >= 0n)
    return q;

  const r = x - (q * y);

  if (r < 0n) {
    if (y < 0n)
      q += 1n;
    else
      q -= 1n;
  }

  return q;
}

/*
 * Euclidean Modulo
 */

function mod(x, y) {
  assert(y !== 0n);

  let r = x % y;

  if (r < 0n) {
    if (y < 0n)
      r -= y;
    else
      r += y;
  }

  return r;
}

function modrn(x, y) {
  let r = remrn(x, y);

  if (r < 0) {
    if (y < 0)
      r -= y;
    else
      r += y;
  }

  return r;
}

/*
 * Round Division
 */

function divRound(x, y) {
  assert(y !== 0n);

  const half = y < 0n ? -(-y >> 1n) : (y >> 1n);

  if ((x < 0n) ^ (y < 0n))
    return (x - half) / y;

  return (x + half) / y;
}

/*
 * Roots
 */

function _rootrem(y, pow, rem) {
  if (pow === 0)
    throw new RangeError('Zeroth root.');

  if (~pow & (y < 0n))
    throw new RangeError('Negative with even root.');

  if (y === -1n || y === 0n || y === 1n)
    return [y, 0n];

  const exp = BigInt(pow);

  let u = 0n;
  let t = 1n << BigInt(bitLength(y) / pow + 1 | 0);
  let v, r;

  if (y < 0n)
    t = -t;

  if (pow === 2) {
    do {
      u = t;
      t = y / u;
      t += u;
      t >>= 1n;
    } while (ucmp(t, u) < 0);
  } else {
    do {
      u = t;
      t = u ** (exp - 1n);
      t = y / t;
      v = u * (exp - 1n);
      t += v;
      t /= exp;
    } while (ucmp(t, u) < 0);
  }

  if (rem) {
    t = u ** exp;
    r = y - t;
  }

  return [u, r];
}

function rootrem(y, pow) {
  return _rootrem(y, pow, 1);
}

function root(y, pow) {
  return _rootrem(y, pow, 0)[0];
}

function isPower(y, pow) {
  if (pow === 0 || (~pow & (y < 0n)))
    return false;

  const [, r] = rootrem(y, pow);

  return r === 0n;
}

function sqrtrem(y) {
  return rootrem(y, 2);
}

function sqrt(y) {
  return root(y, 2);
}

function isSquare(y) {
  return isPower(y, 2);
}

/*
 * Bit Manipulation
 */

function mask(width) {
  return (1n << BigInt(width)) - 1n;
}

function uand(x, y) {
  const neg = x < 0n;
  const num = abs(x) & abs(y);
  return neg ? -num : num;
}

function uandn(x, y) {
  return uand(x, BigInt(y));
}

function uor(x, y) {
  const neg = x < 0n;
  const num = abs(x) | abs(y);
  return neg ? -num : num;
}

function uorn(x, y) {
  return uor(x, BigInt(y));
}

function uxor(x, y) {
  const neg = x < 0n;
  const num = abs(x) ^ abs(y);
  return neg ? -num : num;
}

function uxorn(x, y) {
  return uxor(x, BigInt(y));
}

function ushr(x, y) {
  if (x < 0n)
    return -(-x >> y);
  return x >> y;
}

function ushrn(x, y) {
  return ushr(x, BigInt(y));
}

function notn(x, width) {
  const neg = x < 0n;

  if (neg)
    x = -x;

  x ^= mask(width);

  if (neg)
    x = -x;

  return x;
}

function setn(x, bit, val) {
  if (val)
    x |= (1n << BigInt(bit));
  else
    x &= ~(1n << BigInt(bit));
  return x;
}

function usetn(x, bit, val) {
  const neg = x < 0n;

  if (neg)
    x = -x;

  x = setn(x, bit, val);

  if (neg)
    x = -x;

  return x;
}

function testn(x, bit) {
  return Number((x >> BigInt(bit)) & 1n);
}

function utestn(x, bit) {
  return testn(abs(x), bit);
}

function maskn(x, width) {
  return x & mask(width);
}

function umaskn(x, width) {
  const neg = x < 0n;

  if (neg)
    x = -x;

  x &= mask(width);

  if (neg)
    x = -x;

  return x;
}

function andln(x, y) {
  if (x < 0n)
    x = -x;

  return Number(x & BigInt(y & 0x3ffffff));
}

function bits(x, pos, width) {
  if (x < 0n)
    x = -x;

  const m = BigInt((1 << width) - 1);
  const r = (x >> BigInt(pos)) & m;

  return Number(r);
}

/*
 * Negation
 */

function abs(x) {
  return x < 0n ? -x : x;
}

/*
 * Comparisons
 */

function cmp(x, y) {
  if (x < y)
    return -1;

  if (x > y)
    return 1;

  return 0;
}

function cmpn(x, y) {
  // No polymorphism.
  if (x < y)
    return -1;

  if (x > y)
    return 1;

  return 0;
}

/*
 * Unsigned Comparison
 */

function ucmp(x, y) {
  return cmp(abs(x), abs(y));
}

function ucmpn(x, y) {
  return cmpn(abs(x), Math.abs(y));
}

/*
 * Number Theoretic Functions
 */

function legendre(x, y) {
  range(y > 0n, 'legendre');

  if ((y & 1n) === 0n)
    throw new Error('legendre: `num` must be odd.');

  // Euler's criterion.
  const s = powm(x, (y - 1n) >> 1n, y); // (p - 1) / 2
  const a = ceq(s, 0n);
  const b = ceq(s, 1n);
  const c = ceq(s, y - 1n);

  // Must be one of these.
  if ((a | b | c) === 0)
    throw new Error('Invalid prime.');

  // Cannot be multiple.
  assert(a + b + c === 1);

  // 0, 1, or -1.
  return b - c;
}

function jacobi(x, y) {
  if (y === 0n || (y & 1n) === 0n)
    throw new Error('jacobi: `num` must be odd.');

  let a = x;
  let b = y;
  let j = 1;

  if (b < 0n) {
    if (a < 0n)
      j = -1;
    b = -b;
  }

  if (a < 0n)
    a = mod(a, b);

  for (;;) {
    if (b === 1n)
      return j;

    if (a === 0n)
      return 0;

    a %= b;

    if (a === 0n)
      return 0;

    const s = zeroBits(a);

    if (s & 1) {
      const bmod8 = b & 7n;

      if (bmod8 === 3n || bmod8 === 5n)
        j = -j;
    }

    const c = a >> BigInt(s);

    if ((b & 3n) === 3n && (c & 3n) === 3n)
      j = -j;

    a = b;
    b = c;
  }
}

function kronecker(x, y) {
  const table = [
    0,  1, 0, -1,
    0, -1, 0,  1
  ];

  let a = x;
  let b = y;
  let s = 1;

  if (b === 0n)
    return abs(a) === 1n ? s : 0;

  if ((a & 1n) === 0n && (b & 1n) === 0n)
    return 0;

  const z = zeroBits(b);

  b >>= BigInt(z);

  if (z & 1)
    s = table[Number(abs(a) & 7n)];

  if (b < 0n) {
    if (a < 0n)
      s = -s;
    b = -b;
  }

  for (;;) {
    if (a === 0n)
      return b === 1n ? s : 0;

    const z = zeroBits(a);

    a >>= BigInt(z);

    if (z & 1)
      s *= table[Number(b & 7n)];

    const w = a < 0n ? ((-a) ^ 3n) : a;

    if ((w & b & 2n) !== 0n)
      s = -s;

    b = mod(b, a);

    [a, b] = [b, a];

    if (b < 0n)
      b = -b;
  }
}

function gcd(x, y) {
  x = abs(x);
  y = abs(y);

  while (y !== 0n)
    [x, y] = [y, x % y];

  return x;
}

function lcm(x, y) {
  if (x === 0n || y === 0n)
    return 0n;

  return abs((x / gcd(x, y)) * y);
}

function egcd(x, y) {
  let s = 0n;
  let os = 1n;
  let t = 1n;
  let ot = 0n;
  let r = abs(y);
  let or = abs(x);

  while (r !== 0n) {
    const q = or / r;

    [or, r] = [r, or - q * r];
    [os, s] = [s, os - q * s];
    [ot, t] = [t, ot - q * t];
  }

  if (or < 0n) {
    or = -or;
    os = -os;
    ot = -ot;
  }

  if (x < 0n)
    os = -os;

  if (y < 0n)
    ot = -ot;

  return [os, ot, or];
}

function invert(x, y) {
  assert(y > 0n);

  if (y === 1n)
    throw new RangeError('Not invertible.');

  if (x < 0n || x >= y)
    x = mod(x, y);

  let t = 0n;
  let nt = 1n;
  let r = y;
  let nr = x;

  while (nr !== 0n) {
    const q = r / nr;

    [t, nt] = [nt, t - q * nt];
    [r, nr] = [nr, r - q * nr];
  }

  if (r < 0n) {
    r = -r;
    t = -t;
  }

  if (r !== 1n)
    throw new RangeError('Not invertible.');

  if (t < 0n)
    t += y;

  return t;
}

function fermat(x, y) {
  assert(y > 0n);

  if (y === 1n)
    throw new RangeError('Not invertible.');

  // Invert using fermat's little theorem.
  const inv = powm(x, y - 2n, y);

  if (inv === 0n)
    throw new RangeError('Not invertible.');

  return inv;
}

function powm(x, e, m) {
  assert(m > 0n);

  if (e < 0n) {
    x = invert(x, m);
    e = -e;
  } else {
    x = mod(x, m);
  }

  if (e <= 0x3ffffffn)
    return rtl(x, e, m);

  return slide(x, e, m);
}

function rtl(x, e, m) {
  let r = 1n;

  while (e > 0n) {
    if ((e & 1n) === 1n)
      r = (r * x) % m;

    x = (x * x) % m;
    e >>= 1n;
  }

  return r;
}

function slide(x, e, m) {
  // Sliding window.
  const wnd = new Array(WND_SIZE);

  wnd[0] = sqrn(x, WND_WIDTH - 1, m);
  wnd[1] = wnd[0] * x;

  for (let i = 2; i < WND_SIZE; i++)
    wnd[i] = (wnd[i - 1] * x) % m;

  let i = BigInt(bitLength(e));
  let r = 1n;

  while (i >= WND_WIDTH_BIG) {
    const pos = i - WND_WIDTH_BIG;
    const bits = (e >> pos) & WND_MASK_BIG;

    if (bits < WND_SIZE_BIG) {
      r = (r * r) % m;
      i -= 1n;
      continue;
    }

    r = sqrn(r, WND_WIDTH, m);
    r = (r * wnd[Number(bits) & ~WND_SIZE]) % m;
    i = pos;
  }

  while (i--) {
    r = (r * r) % m;

    if ((e >> i) & 1n)
      r = (r * x) % m;
  }

  return r;
}

function sqrn(x, n, m) {
  for (let i = 0; i < n; i++)
    x = (x * x) % m;
  return x;
}

function sqrtm(x, p) {
  assert(p > 0n);

  if (x < 0n || x >= p)
    x = mod(x, p);

  if ((p & 3n) === 3n)
    return sqrt3mod4(x, p);

  if ((p & 7n) === 5n)
    return sqrt5mod8(x, p);

  return sqrt0(x, p);
}

function sqrt3mod4(x, p) {
  const e = (p + 1n) >> 2n; // (p + 1) / 4
  const b = powm(x, e, p);

  if (((b * b) % p) !== x)
    throw new Error('X is not a square mod P.');

  return b;
}

function sqrt5mod8(x, p) {
  // Atkin's Algorithm.
  const e = p >> 3n; // (p - 5) / 8
  const x2 = (x << 1n) % p;
  const alpha = powm(x2, e, p);
  const beta = (x2 * alpha * alpha) % p;
  const b = (alpha * x * (beta - 1n)) % p;

  if (((b * b) % p) !== x)
    throw new Error('X is not a square mod P.');

  return b;
}

function sqrt5mod8sm1(x, p, sm1) {
  const e = (p + 3n) >> 3n; // (p + 3) / 8
  const b = powm(x, e, p);

  if (((b * b) % p) === x)
    return b;

  const c = (b * sm1) % p;

  if (((c * c) % p) === x)
    return c;

  throw new Error('X is not a square mod P.');
}

function sqrt0(x, p) {
  if (p === 1n || (p & 1n) === 0n)
    throw new Error('Invalid prime.');

  switch (jacobi(x, p)) {
    case -1:
      throw new Error('X is not a square mod P.');
    case 0:
      return 0n;
    case 1:
      break;
  }

  let s = p - 1n;

  const e = zeroBits(s);

  s >>= BigInt(e);

  let n = 2n;

  while (jacobi(n, p) !== -1)
    n += 1n;

  let y = powm(x, (s + 1n) >> 1n, p);
  let b = powm(x, s, p);
  let g = powm(n, s, p);
  let k = e;

  for (;;) {
    let t = b;
    let m = 0;

    while (t !== 1n && m < k) {
      t = (t * t) % p;
      m += 1;
    }

    if (m === 0)
      break;

    assert(m < k);

    t = sqrn(g, k - m - 1, p);
    g = (t * t) % p;
    y = (y * t) % p;
    b = (b * g) % p;
    k = m;
  }

  return y;
}

function divsqrt(u, v, p, sm1) {
  assert(p > 0n);

  if (u < 0n || u >= p)
    u = mod(u, p);

  if (v < 0n || v >= p)
    v = mod(v, p);

  // v = 0
  if (v === 0n)
    throw new RangeError('Not invertible.');

  // p = 3 mod 4
  if ((p & 3n) === 3n)
    return divsqrt3mod4(u, v, p);

  // p = 5 mod 8
  if (sm1 != null && (p & 7n) === 5n)
    return divsqrt5mod8(u, v, p, sm1);

  return sqrtm(u * invert(v, p), p);
}

function divsqrt3mod4(u, v, p) {
  // x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p
  const e = (p - 3n) >> 2n;
  const u2 = (u * u) % p;
  const u3 = (u2 * u) % p;
  const u5 = (u3 * u2) % p;
  const v3 = (v * v * v) % p;
  const q = powm(u5 * v3, e, p);
  const x = (u3 * v * q) % p;
  const c = (v * x * x) % p;

  if (c === u)
    return x;

  throw new Error('X is not a square mod P.');
}

function divsqrt5mod8(u, v, p, sm1) {
  // x = u * v^3 * (u * v^7)^((p - 5) / 8) mod p
  const e = (p - 5n) >> 3n;
  const v3 = (v * v * v) % p;
  const v7 = (v3 * v3 * v) % p;
  const q = powm(u * v7, e, p);
  const x = (u * v3 * q) % p;
  const c = (v * x * x) % p;

  if (c === u)
    return x;

  if (c === mod(-u, p))
    return (x * sm1) % p;

  throw new Error('X is not a square mod P.');
}

function sqrtpq(x, p, q) {
  assert(p > 0n);
  assert(q > 0n);

  const sp = sqrtm(x, p);
  const sq = sqrtm(x, q);
  const [mp, mq] = egcd(p, q);

  return mod(sq * mp * p + sp * mq * q, p * q);
}

/*
 * Primality Testing
 */

function isPrimeMR(n, rng, reps, force2 = false) {
  enforce((reps >>> 0) === reps, 'reps', 'uint32');
  enforce(reps > 0, 'reps', 'integer');
  enforce(typeof force2 === 'boolean', 'force2', 'boolean');

  if (n < 7n) {
    return n === 2n
        || n === 3n
        || n === 5n;
  }

  if ((n & 1n) === 0n)
    return false;

  const nm1 = n - 1n;
  const nm3 = nm1 - 2n;
  const k = zeroBits(nm1);
  const q = nm1 >> BigInt(k);

next:
  for (let i = 0; i < reps; i++) {
    let x, y;

    if (i === reps - 1 && force2) {
      x = 2n;
    } else {
      x = random(rng, 0n, nm3);
      x += 2n;
    }

    y = powm(x, q, n);

    if (y === 1n || y === nm1)
      continue;

    for (let j = 1; j < k; j++) {
      y = (y * y) % n;

      if (y === nm1)
        continue next;

      if (y === 1n)
        return false;
    }

    return false;
  }

  return true;
}

function isPrimeLucas(n, limit = 0) {
  enforce((limit >>> 0) === limit, 'limit', 'uint32');

  // Ignore 0 and 1.
  if (n <= 1n)
    return false;

  // Two is the only even prime.
  if ((n & 1n) === 0n)
    return n === 2n;

  let p = 3n;

  for (;;) {
    if (p > 10000n) {
      // Thought to be impossible.
      throw new Error(`Cannot find (D/n) = -1 for ${n.toString(10)}.`);
    }

    if (limit !== 0 && p > limit) {
      // Optional DoS limit.
      return false;
    }

    const d = p * p - 4n;
    const j = jacobi(d, n);

    if (j === -1)
      break;

    if (j === 0)
      return n === p + 2n;

    if (p === 40n) {
      if (isSquare(n))
        return false;
    }

    p += 1n;
  }

  let s = n + 1n;

  const r = zeroBits(s);
  const nm2 = n - 2n;

  let x = 2n;
  let y = p;

  s >>= BigInt(r);

  for (let i = BigInt(bitLength(s)); i >= 0n; i--) {
    if (s & (1n << i)) {
      x = mod(x * y + n - p, n);
      y = mod(y * y + nm2, n);
    } else {
      y = mod(y * x + n - p, n);
      x = mod(x * x + nm2, n);
    }
  }

  if (x === 2n || x === nm2) {
    let a = x * p;
    let b = y << 1n;

    if (a < b)
      [a, b] = [b, a];

    if (((a - b) % n) === 0n)
      return true;
  }

  for (let t = 0; t < r - 1; t++) {
    if (x === 0n)
      return true;

    if (x === 2n)
      return false;

    x = mod(x * x - 2n, n);
  }

  return false;
}

/*
 * Twos Complement
 */

function toTwos(x, width) {
  if (x < 0n)
    return notn(-x, width) + 1n;

  return x;
}

function fromTwos(x, width) {
  if (testn(x, width - 1))
    return -(notn(x, width) + 1n);

  return x;
}

/*
 * Helpers
 */

function countWords(x, w) {
  if (x === 0n)
    return 0;

  if (x < 0n)
    x = -x;

  let i = 0;

  while (x >= U256_MAX) {
    i += 256;
    x >>= 256n;
  }

  while (x >= U128_MAX) {
    i += 128;
    x >>= 128n;
  }

  while (x >= U64_MAX) {
    i += 64;
    x >>= 64n;
  }

  while (x >= U32_MAX) {
    i += 32;
    x >>= 32n;
  }

  while (x >= U16_MAX) {
    i += 16;
    x >>= 16n;
  }

  while (x >= U8_MAX) {
    i += 8;
    x >>= 8n;
  }

  while (x > 0n) {
    i += 1;
    x >>= 1n;
  }

  return ((i + (w - 1)) / w) >>> 0;
}

function byteLength(x) {
  return countWords(x, 8);
}

function bitLength(x) {
  return countWords(x, 1);
}

function zeroBits(x) {
  if (x === 0n)
    return 0;

  if (x < 0n)
    x = -x;

  let i = 0;

  while ((x & U32_MAX) === 0n) {
    i += 32;
    x >>= 32n;
  }

  while ((x & U16_MAX) === 0n) {
    i += 16;
    x >>= 16n;
  }

  while ((x & U8_MAX) === 0n) {
    i += 8;
    x >>= 8n;
  }

  while ((x & 1n) === 0n) {
    i += 1;
    x >>= 1n;
  }

  return i;
}

function word(n, pos) {
  return Number((abs(n) >> BigInt(pos * 26)) & 0x3ffffffn);
}

/*
 * Constant Time (sort of)
 */

function ceq(x, y) {
  return ((x ^ y) === 0n) | 0;
}

function ceqn(x, y) {
  return ((x ^ BigInt(y)) === 0n) | 0;
}

function cswap(x, y, flag) {
  const bit = BigInt(flag);
  const a = x * (bit ^ 1n) + y * bit;
  const b = y * (bit ^ 1n) + x * bit;
  return [a, b];
}

function cinject(x, y, flag) {
  const bit = BigInt(flag);
  return x * (bit ^ 1n) + y * bit;
}

function cset(x, y, flag) {
  const bit = BigInt(flag);
  return x * (bit ^ 1n) + BigInt(y) * bit;
}

/*
 * Conversion
 */

function toString(num, base, padding) {
  base = getBase(base);

  if (padding == null)
    padding = 0;

  if (padding === 0)
    padding = 1;

  enforce((base >>> 0) === base, 'base', 'uint32');
  enforce((padding >>> 0) === padding, 'padding', 'uint32');

  if (base < 2 || base > 36)
    throw new RangeError('Base ranges between 2 and 36.');

  let neg = false;

  if (num < 0n) {
    neg = true;
    num = -num;
  }

  let str = num.toString(base);

  while (str.length % padding)
    str = '0' + str;

  if (neg)
    str = '-' + str;

  return str;
}

function fromString(str, base) {
  base = getBase(base);

  enforce(typeof str === 'string', 'str', 'string');
  enforce((base >>> 0) === base, 'base', 'uint32');

  if (base < 2 || base > 36)
    throw new RangeError('Base ranges between 2 and 36.');

  if (isFastBase(base))
    return fromStringFast(str, base);

  let neg = false;
  let i = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x09: // '\t'
      case 0x0a: // '\n'
      case 0x0d: // '\r'
      case 0x20: // ' '
        continue;
    }

    break;
  }

  if (i < str.length && str.charCodeAt(i) === 0x2d) {
    neg = true;
    i += 1;
  }

  const big = BigInt(base);

  let num = 0n;

  for (; i < str.length; i++) {
    let ch = str.charCodeAt(i);

    switch (ch) {
      case 0x09: // '\t'
      case 0x0a: // '\n'
      case 0x0d: // '\r'
      case 0x20: // ' '
        continue;
    }

    if (ch >= 0x30 && ch <= 0x39)
      ch -= 0x30;
    else if (ch >= 0x41 && ch <= 0x5a)
      ch -= 0x41 - 10;
    else if (ch >= 0x61 && ch <= 0x7a)
      ch -= 0x61 - 10;
    else
      ch = base;

    if (ch >= base)
      throw new Error('Invalid string.');

    num *= big;
    num += BigInt(ch);
  }

  if (neg)
    num = -num;

  return num;
}

function fromStringFast(str, base) {
  let neg = false;
  let num;

  str = str.replace(/\s+/g, '');

  if (str.length > 0 && str.charCodeAt(0) === 0x2d) {
    str = str.substring(1);
    neg = true;
  }

  switch (base) {
    case 2:
      str = '0b' + str;
      break;
    case 8:
      str = '0o' + str;
      break;
    case 10:
      if (str.length > 1) {
        const ch = str.charCodeAt(1);
        if (ch < 0x30 || ch > 0x39)
          throw new Error('Invalid string.');
      }
      break;
    case 16:
      str = '0x' + str;
      break;
    default:
      throw new Error('Invalid base.');
  }

  try {
    num = BigInt(str);
  } catch (e) {
    throw new Error('Invalid string.');
  }

  if (neg)
    num = -num;

  return num;
}

function toBuffer(n, endian, length) {
  if (endian == null)
    endian = 'be';

  if (length == null)
    length = 0;

  enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');
  enforce((length >>> 0) === length, 'length', 'uint32');

  // Leverage node's hex parser for faster
  // serialization. To-stringing the number
  // is 14 times faster than counting the
  // bytes and shifting them off.
  let str = abs(n).toString(16);

  if (str.length & 1)
    str = '0' + str;

  const bytes = str.length >>> 1;
  const size = length || Math.max(1, bytes);

  if (bytes > size)
    throw new RangeError('Byte array longer than desired length.');

  const hex = str.padStart(size * 2, '00');
  const out = Buffer.allocUnsafeSlow(size);

  out.write(hex, 'hex');

  // Reverse the buffer in-place.
  if (endian === 'le')
    reverse(out);

  return out;
}

function fromBuffer(data, endian) {
  if (endian == null)
    endian = 'be';

  // 13x speedup if on an arch with the same endianness
  // and the data is properly aligned to 64 bits.
  // 5.5x speedup if on an arch with differing endianness.
  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

  // Convert to machine endianness.
  // Note that the node.js buffer pool
  // always aligns slices to 8 bytes.
  if (endian !== ENDIAN)
    data = reverse(Buffer.from(data));

  // Byte offsets for typed arrays must
  // be aligned to their word size.
  const unaligned = data.byteOffset & 7;

  // Forcefully align. We will read
  // some data that's not our's.
  if (unaligned) {
    data = Buffer.from(data.buffer,
                       data.byteOffset - unaligned,
                       unaligned + data.byteLength);
  }

  // Read buffer as a uint64 array.
  const arr = new BigUint64Array(data.buffer,
                                 data.byteOffset,
                                 data.length >>> 3);

  const left = data.length & 7;
  const start = data.length - left;

  let n = 0n;

  if (ENDIAN === 'be') {
    for (let i = 0; i < arr.length; i++) {
      n <<= 64n;
      n |= arr[i];
    }

    for (let i = start; i < data.length; i++) {
      n <<= 8n;
      n |= BigInt(data[i]);
    }

    // Realign.
    if (unaligned)
      n &= mask((data.length - unaligned) * 8);
  } else {
    for (let i = data.length - 1; i >= start; i--) {
      n <<= 8n;
      n |= BigInt(data[i]);
    }

    for (let i = arr.length - 1; i >= 0; i--) {
      n <<= 64n;
      n |= arr[i];
    }

    // Realign.
    if (unaligned)
      n >>= BigInt(unaligned * 8);
  }

  return n;
}

function toArrayLike(n, ArrayType, endian, length) {
  if (endian == null)
    endian = 'be';

  if (length == null)
    length = 0;

  enforce(typeof ArrayType === 'function', 'ArrayType', 'function');
  enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');
  enforce((length >>> 0) === length, 'length', 'uint32');

  const bytes = byteLength(n);
  const size = length || Math.max(1, bytes);

  if (bytes > size)
    throw new RangeError('Byte array longer than desired length.');

  const res = allocate(ArrayType, size);

  let q = abs(n);

  if (endian === 'be') {
    let i = size - 1;

    while (q > 0n) {
      res[i--] = Number(q & 0xffn);
      q >>= 8n;
    }

    for (; i >= 0; i--)
      res[i] = 0x00;
  } else {
    let i = 0;

    while (q > 0n) {
      res[i++] = Number(q & 0xffn);
      q >>= 8n;
    }

    for (; i < size; i++)
      res[i] = 0x00;
  }

  return res;
}

function fromArrayLike(data, endian) {
  if (endian == null)
    endian = 'be';

  enforce(data && (data.length >>> 0) === data.length, 'data', 'array-like');
  enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

  let n = 0n;

  if (endian === 'be') {
    for (let i = 0; i < data.length; i++) {
      n <<= 8n;
      n |= BigInt(data[i] & 0xff);
    }
  } else {
    for (let i = data.length - 1; i >= 0; i--) {
      n <<= 8n;
      n |= BigInt(data[i] & 0xff);
    }
  }

  return n;
}

/*
 * RNG
 */

function randomBits(rng, bits) {
  enforce(rng != null, 'rng', 'rng');
  enforce((bits >>> 0) === bits, 'bits', 'uint32');

  if (typeof rng === 'object') {
    enforce(typeof rng.randomBytes === 'function', 'rng', 'rng');

    const size = (bits + 7) >>> 3;
    const total = size * 8;
    const bytes = rng.randomBytes(size);

    enforce(Buffer.isBuffer(bytes), 'bytes', 'buffer');

    if (bytes.length !== size)
      throw new RangeError('Invalid number of bytes returned from RNG.');

    let num = fromBuffer(bytes);

    if (total > bits)
      num >>= BigInt(total - bits);

    return num;
  }

  enforce(typeof rng === 'function', 'rng', 'rng');

  const num = rng(bits);

  enforce(BN.isBN(num), 'num', 'bignum');
  range(num.negative === 0, 'RNG');
  nonred(!num.red, 'RNG');

  if (num.bitLength() > bits)
    throw new RangeError('Invalid number of bits returned from RNG.');

  return num.n;
}

function random(rng, min, max) {
  if (min > max)
    throw new RangeError('Minimum cannot be greater than maximum.');

  const space = abs(max - min);
  const bits = bitLength(space);

  if (bits === 0)
    return min;

  for (;;) {
    let num = randomBits(rng, bits);

    // Maximum is _exclusive_!
    if (num >= space)
      continue;

    // Minimum is _inclusive_!
    num += min;

    return num;
  }
}

/*
 * Expose
 */

BN.Red = Red;

module.exports = BN;
