/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const BN = require('../vendor/bn.js');
const n64 = require('../lib/n64');
const native = require('../lib/native');

function run(n64, name) {
  const {N64, U64, I64} = n64;
  const ZERO = I64.fromInt(0);
  const ONE = I64.fromInt(1);
  const UONE = U64.fromInt(1);
  const MIN_I64 = I64.fromBits(0x80000000, 0);
  const MAX_I64 = I64.fromBits(0x7fffffff, 0xffffffff);
  const MAX_U64 = U64.fromBits(0xffffffff, 0xffffffff);
  const MAX_SAFE = U64.fromNumber(Number.MAX_SAFE_INTEGER);
  const MAX_SAFE_MIN = I64.fromNumber(-Number.MAX_SAFE_INTEGER);
  const MAX_SAFE_MAX = I64.fromNumber(Number.MAX_SAFE_INTEGER);

  describe(name, function() {
    it('should instantiate and serialize', () => {
      const num1 = I64.fromBits(0x7fffffff, 0xffffffff);

      assert.strictEqual(num1.toDouble(), 9223372036854775807);
      assert.strictEqual(num1.toString(), '9223372036854775807');

      const num2 = I64.fromString(num1.toString());

      assert.strictEqual(num2.toDouble(), 9223372036854775807);
      assert.strictEqual(num2.toString(), '9223372036854775807');
      assert.strictEqual(num2.sign, num1.sign);
    });

    it('should have instance', () => {
      const num1 = I64.fromBits(0x7fffffff, 0xffffffff);
      assert.strictEqual(N64.isN64(num1), true);
      assert.strictEqual(I64.isI64(num1), true);
      assert.strictEqual(I64.isI64({}), false);
      const num2 = U64.fromBits(0x7fffffff, 0xffffffff);
      assert.strictEqual(N64.isN64(num2), true);
      assert.strictEqual(U64.isU64(num2), true);
      assert.strictEqual(U64.isU64({}), false);
      assert.strictEqual(N64.isN64({}), false);
    });

    it('should serialize unsigned strings', () => {
      const num1 = U64.fromBits(0xffffffff, 0xffffffff);
      assert.strictEqual(num1.toString(16), 'ffffffffffffffff');
      assert.strictEqual(num1.toString(10), '18446744073709551615');
      assert.strictEqual(num1.toString(8), '1777777777777777777777');
      assert.strictEqual(num1.toString(2),
        '1111111111111111111111111111111111111111111111111111111111111111');

      const num2 = U64.fromNumber(123456789012);
      assert.strictEqual(num2.toNumber(), 123456789012);
      assert.strictEqual(num2.toString(16), '1cbe991a14');
      assert.strictEqual(num2.toString('hex'), '1cbe991a14');
      assert.strictEqual(num2.toString(16, 9), '1cbe991a14');
      assert.strictEqual(num2.toString(16, 10), '1cbe991a14');
      assert.strictEqual(num2.toString(16, 11), '01cbe991a14');
      assert.strictEqual(num2.toString(16, 16), '0000001cbe991a14');
      assert.strictEqual(num2.toString(10), '123456789012');
      assert.strictEqual(num2.toString(10, 10), '123456789012');
      assert.strictEqual(num2.toString(10, 12), '123456789012');
      assert.strictEqual(num2.toString(10, 13), '0123456789012');
      assert.strictEqual(num2.toString(10, 20), '00000000123456789012');
      assert.strictEqual(num2.toString(8), '1627646215024');
      assert.strictEqual(num2.toString(8, 10), '1627646215024');
      assert.strictEqual(num2.toString(8, 13), '1627646215024');
      assert.strictEqual(num2.toString(8, 14), '01627646215024');
      assert.strictEqual(num2.toString(8, 22), '0000000001627646215024');
      assert.strictEqual(num2.toString(2),
        '1110010111110100110010001101000010100');
      assert.strictEqual(num2.toString(2, 36),
        '1110010111110100110010001101000010100');
      assert.strictEqual(num2.toString(2, 37),
        '1110010111110100110010001101000010100');
      assert.strictEqual(num2.toString(2, 38),
        '01110010111110100110010001101000010100');
      assert.strictEqual(num2.toString(2, 64),
        '0000000000000000000000000001110010111110100110010001101000010100');
    });

    it('should serialize signed strings', () => {
      const num1 = I64.fromBits(0xffffffff, 0xffffffff);
      assert.strictEqual(num1.toString(16), '-1');
      assert.strictEqual(num1.toString(10), '-1');
      assert.strictEqual(num1.toString(8), '-1');
      assert.strictEqual(num1.toString(2), '-1');

      const num2 = I64.fromNumber(-123456789012);
      assert.strictEqual(num2.toNumber(), -0x1cbe991a14);
      assert.strictEqual(num2.toString(16), '-1cbe991a14');
      assert.strictEqual(num2.toString(16, 9), '-1cbe991a14');
      assert.strictEqual(num2.toString(16, 10), '-1cbe991a14');
      assert.strictEqual(num2.toString(16, 11), '-01cbe991a14');
      assert.strictEqual(num2.toString(16, 16), '-0000001cbe991a14');
      assert.strictEqual(num2.toString(10), '-123456789012');
      assert.strictEqual(num2.toString(8), '-1627646215024');
      assert.strictEqual(num2.toString(2),
        '-1110010111110100110010001101000010100');
      assert.strictEqual(num2.toString(2, 37),
        '-1110010111110100110010001101000010100');
      assert.strictEqual(num2.toString(2, 38),
        '-01110010111110100110010001101000010100');
      assert.strictEqual(num2.toString(2, 64),
        '-0000000000000000000000000001110010111110100110010001101000010100');
    });

    it('should deserialize unsigned strings', () => {
      let num = U64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(num.toString(16), 'ffffffffffffffff');

      num = U64.fromString('18446744073709551615', 10);
      assert.strictEqual(num.toString(10), '18446744073709551615');

      num = U64.fromString('1777777777777777777777', 8);
      assert.strictEqual(num.toString(8), '1777777777777777777777');

      num = U64.fromString(
        '1111111111111111111111111111111111111111111111111111111111111111',
        2);
      assert.strictEqual(num.toString(2),
        '1111111111111111111111111111111111111111111111111111111111111111');

      num = U64.fromString('1cbe991a14', 16);
      assert.strictEqual(num.toString(16), '1cbe991a14');

      num = U64.fromString('123456789012', 10);
      assert.strictEqual(num.toString(10), '123456789012');

      num = U64.fromString('1627646215024', 8);
      assert.strictEqual(num.toString(8), '1627646215024');

      num = U64.fromString('1110010111110100110010001101000010100', 2);
      assert.strictEqual(num.toString(2),
        '1110010111110100110010001101000010100');
    });

    it('should deserialize signed strings', () => {
      let num = I64.fromString('-1', 16);
      assert.strictEqual(num.toNumber(), -1);
      assert.strictEqual(num.toString(16), '-1');

      num = I64.fromString('-1', 10);
      assert.strictEqual(num.toString(10), '-1');

      num = I64.fromString('-1', 8);
      assert.strictEqual(num.toString(8), '-1');

      num = I64.fromString('-1', 2);
      assert.strictEqual(num.toString(2), '-1');

      num = I64.fromString('-1cbe991a14', 16);
      assert.strictEqual(num.toNumber(), -0x1cbe991a14);
      assert.strictEqual(num.toString(16), '-1cbe991a14');

      num = I64.fromString('-123456789012', 10);
      assert.strictEqual(num.toString(10), '-123456789012');

      num = I64.fromString('-1627646215024', 8);
      assert.strictEqual(num.toString(8), '-1627646215024');

      num = I64.fromString('-1110010111110100110010001101000010100', 2);
      assert.strictEqual(num.toString(2),
        '-1110010111110100110010001101000010100');
    });

    it('should serialize strings for min/max', () => {
      assert.strictEqual(MIN_I64.toString(), '-9223372036854775808');
      assert.strictEqual(MAX_I64.toString(), '9223372036854775807');
      assert.strictEqual(MAX_U64.toString(), '18446744073709551615');
    });

    it('should cast a negative', () => {
      let num = U64.fromInt(-1);
      assert.strictEqual(num.lo, -1);
      assert.strictEqual(num.hi, 0);
      assert.strictEqual(num.sign, 0);
      num = I64.fromInt(-1);
      assert.strictEqual(num.lo, -1);
      assert.strictEqual(num.hi, -1);
      assert.strictEqual(num.sign, 1);
      num = num.toU64();
      assert.throws(() => num.toNumber());
      assert.strictEqual(num.toDouble(), 18446744073709551615);
      assert.strictEqual(num.toString(), '18446744073709551615');
    });

    it('should handle uint64 max', () => {
      const num = U64.fromBits(0xffffffff, 0xffffffff);
      assert.strictEqual(num.lo, -1);
      assert.strictEqual(num.hi, -1);
      assert.strictEqual(num.sign, 0);
      assert.throws(() => num.toNumber());
      assert.strictEqual(num.toDouble(), 18446744073709551615);
      assert.strictEqual(num.toString(), '18446744073709551615');
    });

    it('should handle uint64 max as string', () => {
      const num = U64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(num.lo, -1);
      assert.strictEqual(num.hi, -1);
      assert.strictEqual(num.sign, 0);
      assert.strictEqual(num.toDouble(), 18446744073709551615);
      assert.strictEqual(num.toString(), '18446744073709551615');
    });

    it('should count bits', () => {
      let num = U64.fromString('000010000fffffff', 16);
      assert.strictEqual(num.bitLength(), 45);
      assert.strictEqual(num.byteLength(), 6);

      num = I64.fromString('000010000fffffff', 16);
      assert.strictEqual(num.bitLength(), 45);
      assert.strictEqual(num.byteLength(), 6);

      num = U64.fromString('800010000fffffff', 16);
      assert.strictEqual(num.bitLength(), 64);
      assert.strictEqual(num.byteLength(), 8);

      num = I64.fromString('800010000fffffff', 16);
      assert.strictEqual(num.bitLength(), 63);
      assert.strictEqual(num.byteLength(), 8);

      num = U64.fromNumber(0);
      assert.strictEqual(num.bitLength(), 0);
      assert.strictEqual(num.byteLength(), 0);

      num = U64.fromNumber(1);
      assert.strictEqual(num.bitLength(), 1);
      assert.strictEqual(num.byteLength(), 1);
    });

    it('should cast between signed and unsigned', () => {
      let num = I64.fromNumber(-1);
      assert.strictEqual(num.toDouble(), -1);

      num = num.toU64();
      assert.strictEqual(num.toDouble(), 0xffffffffffffffff);
      assert.strictEqual(num.toString(16), 'ffffffffffffffff');

      num = num.toI64();
      assert.strictEqual(num.toDouble(), -1);
    });

    it('should subtract from uint64 max', () => {
      const num = MAX_U64.sub(MAX_I64).sub(ONE);
      assert.strictEqual(num.toDouble(), MAX_I64.toDouble());
      assert.strictEqual(num.toString(), MAX_I64.toString());
    });

    it('should subtract from uint64 max to zero', () => {
      const num = MAX_U64.sub(MAX_U64);
      assert.strictEqual(num.lo, 0);
      assert.strictEqual(num.hi, 0);
      assert.strictEqual(num.sign, 0);
      assert.strictEqual(num.toDouble(), 0);
      assert.strictEqual(num.toString(), '0');
    });

    it('should overflow from subtraction', () => {
      const num = U64.fromInt(0).add(I64.fromInt(-1));
      assert.strictEqual(num.lo, -1);
      assert.strictEqual(num.hi, -1);
      assert.strictEqual(num.sign, 0);
      assert.strictEqual(num.toDouble(), 18446744073709551615);
      assert.strictEqual(num.toString(), '18446744073709551615');
    });

    it('should divide uint64 max by U64 max', () => {
      const num = MAX_U64.div(MAX_I64);
      assert.strictEqual(num.toDouble(), 2);
      assert.strictEqual(num.toString(), '2');
    });

    it('should divide uint64 max by itself', () => {
      const num = MAX_U64;
      assert.strictEqual(num.div(num).toString(), '1');
    });

    it('should cast and divide', () => {
      const a = MAX_U64;
      const b = I64.fromInt(-2);

      assert.strictEqual(b.toU64().toString(), MAX_U64.subn(1).toString());

      const num = a.div(b);
      assert.strictEqual(num.toString(), '1');
      assert.strictEqual(num.toNumber(), 1);
    });

    it('should divide with int64 min edge cases (signed)', () => {
      const MIN_I64 = I64.fromBits(0x80000000, 0);

      let num = MIN_I64.div(ONE);
      assert.strictEqual(num.toString(), MIN_I64.toString());

      num = MIN_I64.div(new I64(1234));
      assert.strictEqual(num.toString(), '-7474369559849899');
      assert.strictEqual(num.toNumber(), -7474369559849899);

      num = MIN_I64.div(new I64(-1234));
      assert.strictEqual(num.toString(), '7474369559849899');
      assert.strictEqual(num.toNumber(), 7474369559849899);

      num = MIN_I64.div(new I64(1));
      assert.strictEqual(num.toString(), MIN_I64.toString());

      num = MIN_I64.div(MIN_I64.clone());
      assert.strictEqual(num.toString(), '1');

      num = I64(2).div(MIN_I64.clone());
      assert.strictEqual(num.toString(), '0');

      // Normally an FPE
      num = MIN_I64.div(new I64(-1));
      assert.strictEqual(num.toString(), MIN_I64.toString());

      // Normally an FPE
      num = MIN_I64.mod(new I64(-1));
      assert.strictEqual(num.toString(), '0');

      assert.strictEqual(MIN_I64.neg().toString(), MIN_I64.toString());

      num = MIN_I64.div(new I64(-2));
      assert.strictEqual(num.toString(), '4611686018427387904');

      num = MIN_I64.div(MIN_I64.subn(1000));
      assert.strictEqual(num.toString(), '-1');

      num = MIN_I64.div(MIN_I64.subn(-1000));
      assert.strictEqual(num.toString(), '1');

      num = MIN_I64.div(MIN_I64.ushrn(5));
      assert.strictEqual(num.toString(), '-32');
      assert.strictEqual(num.toNumber(), -32);

      num = new I64('400000000000000', 16);
      num = MIN_I64.div(num);
      assert.strictEqual(num.toString(), '-32');
    });

    it('should divide with int64 min edge cases (unsigned)', () => {
      const MIN_I64 = U64.fromBits(0x80000000, 0);

      let num = MIN_I64.div(ONE);
      assert.strictEqual(num.toString(), MIN_I64.toString());

      num = MIN_I64.div(new U64(1234));
      assert.strictEqual(num.toString(), '7474369559849899');
      assert.strictEqual(num.toNumber(), 7474369559849899);

      num = MIN_I64.div(new U64(-1234));
      assert.strictEqual(num.toString(), '0');

      num = MIN_I64.div(new U64(1));
      assert.strictEqual(num.toString(), MIN_I64.toString());

      num = MIN_I64.div(MIN_I64.clone());
      assert.strictEqual(num.toString(), '1');
      assert.strictEqual(num.toNumber(), 1);

      num = U64(2).div(MIN_I64.clone());
      assert.strictEqual(num.toString(), '0');

      num = MIN_I64.div(new U64(-1));
      assert.strictEqual(num.toString(), '0');

      num = MIN_I64.mod(new U64(-1));
      assert.strictEqual(num.toString(), MIN_I64.toString());

      assert.strictEqual(MIN_I64.neg().toString(), MIN_I64.toString());

      num = MIN_I64.div(MIN_I64.subn(1000));
      assert.strictEqual(num.toString(), '1');
    });

    it('should implicitly cast for comparison', () => {
      const num = UONE.shln(63);
      assert.strictEqual(num.eq(MIN_I64), true);
      assert.strictEqual(num.cmp(MIN_I64), 0);
      assert.strictEqual(MIN_I64.cmp(num), 0);
      assert.strictEqual(num.toString(), '9223372036854775808');
      assert.strictEqual(
        U64.fromString('9223372036854775808').toString(),
        '9223372036854775808');
    });

    it('should maintain sign after division', () => {
      const a = U64.fromBits(8, 0);
      const b = U64.fromNumber(2656901066);

      assert.strictEqual(a.sign, 0);
      assert.strictEqual(b.sign, 0);

      const x = a.div(b);

      assert.strictEqual(x.toString(), '12');
      assert.strictEqual(x.sign, 0);
    });

    it('should do comparisons', () => {
      assert.strictEqual(ONE.eq(UONE), true);
      assert.strictEqual(ONE.cmp(UONE), 0);
      assert.strictEqual(ONE.cmp(MAX_I64), -1);
      assert.strictEqual(MAX_I64.cmp(ONE), 1);
      assert.strictEqual(ONE.lt(MAX_I64), true);
      assert.strictEqual(ONE.lte(MAX_I64), true);
      assert.strictEqual(MAX_I64.gt(ONE), true);
      assert.strictEqual(MAX_I64.gte(ONE), true);
      assert.strictEqual(MAX_I64.eq(ONE), false);
      assert.strictEqual(ONE.eq(MAX_I64), false);
      assert.strictEqual(MAX_U64.eq(ONE), false);
      assert.strictEqual(ONE.eq(MAX_U64), false);
      assert.strictEqual(ONE.isOdd(), true);
      assert.strictEqual(ONE.isEven(), false);
      assert.strictEqual(MAX_U64.isOdd(), true);
      assert.strictEqual(MAX_U64.isEven(), false);
      assert.strictEqual(MAX_U64.subn(1).isOdd(), false);
      assert.strictEqual(MAX_U64.subn(1).isEven(), true);
      assert.strictEqual(U64.fromNumber(0, false).isZero(), true);
      assert.strictEqual(I64.fromNumber(0).isZero(), true);
      assert.strictEqual(ONE.isZero(), false);
      assert.strictEqual(MAX_U64.isZero(), false);
      assert.strictEqual(MAX_U64.isNeg(), false);
      assert.strictEqual(MAX_I64.isNeg(), false);
      assert.strictEqual(MIN_I64.isNeg(), true);
      assert.strictEqual(MIN_I64.cmpn(0), -1);
      assert.strictEqual(MAX_I64.cmpn(0), 1);
      assert.strictEqual(MIN_I64.eqn(0), false);
      assert.strictEqual(MAX_I64.eqn(0), false);
      assert.strictEqual(ONE.eqn(1), true);
      assert.strictEqual(ONE.ltn(1), false);
      assert.strictEqual(ONE.lten(1), true);
      assert.strictEqual(ONE.subn(1).lten(1), true);
      assert.strictEqual(ONE.subn(1).ltn(1), true);
      assert.strictEqual(ONE.addn(1).lten(1), false);
      assert.strictEqual(ONE.addn(1).ltn(1), false);
      assert.strictEqual(ONE.addn(1).gten(1), true);
      assert.strictEqual(ONE.addn(1).gtn(1), true);
      assert.strictEqual(ONE.addn(1).lten(1), false);
      assert.strictEqual(ONE.addn(1).ltn(1), false);
      assert.strictEqual(N64.min(ZERO, ONE), ZERO);
      assert.strictEqual(N64.max(ZERO, ONE), ONE);
      assert.strictEqual(N64.min(U64(1), ONE), ONE);
      assert.strictEqual(N64.max(U64(1), ONE), ONE);
    });

    it('should do comparisons (signed)', () => {
      assert.strictEqual(I64(-20).eq(I64(-20)), true);
      assert.strictEqual(!I64(-20).eq(I64(20)), true);
      assert.strictEqual(I64(-20).cmp(I64(-20)), 0);
      assert.strictEqual(I64(-20).cmp(I64(20)), -1);
      assert.strictEqual(I64(20).cmp(I64(-20)), 1);
      assert.strictEqual(I64(-1).eq(I64(-1)), true);
      assert.strictEqual(!I64(-1).eq(I64(1)), true);
      assert.strictEqual(I64(-1).cmp(I64(-1)), 0);
      assert.strictEqual(I64(-1).cmp(I64(1)), -1);
      assert.strictEqual(I64(1).cmp(I64(-1)), 1);
      assert.strictEqual(I64(-2147483647).lt(I64(100)), true);
      assert.strictEqual(I64(2147483647).gt(I64(100)), true);
      assert.strictEqual(I64(-2147483647).lt(I64(-100)), true);
      assert.strictEqual(I64(2147483647).gt(I64(-100)), true);
      assert.strictEqual(I64(-0x212345679).lt(I64(-0x212345678)), true);
      assert.strictEqual(I64(0x212345679).gt(I64(-0x212345678)), true);
      assert.strictEqual(I64(0x212345679).gt(I64(0x212345678)), true);
    });

    it('should do small addition (unsigned)', () => {
      let a = U64.fromNumber(100);
      let b = U64.fromNumber(200);
      a.iadd(b);
      assert.strictEqual(a.toString(), '300');

      a = U64.fromNumber(100);
      a.iaddn(200);
      assert.strictEqual(a.toString(), '300');

      a = U64.fromNumber(100);
      b = U64.fromNumber(200);
      assert.strictEqual(a.add(b).toString(), '300');
      assert.strictEqual(a.toString(), '100');

      a = U64.fromNumber(100);
      assert.strictEqual(a.addn(200).toString(), '300');
      assert.strictEqual(a.toString(), '100');
    });

    it('should do small addition (signed)', () => {
      let a = I64.fromNumber(100);
      let b = I64.fromNumber(-50);
      a.iadd(b);
      assert.strictEqual(a.toString(), '50');

      a = I64.fromNumber(100);
      a.iaddn(-50);
      assert.strictEqual(a.toString(), '50');

      a = I64.fromNumber(100);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.add(b).toString(), '50');
      assert.strictEqual(a.toString(), '100');

      a = I64.fromNumber(100);
      assert.strictEqual(a.addn(-50).toString(), '50');
      assert.strictEqual(a.toString(), '100');
    });

    it('should do big addition (unsigned)', () => {
      let a = U64.fromNumber(100 * 0x100000000);
      let b = U64.fromNumber(200 * 0x100000000);
      a.iadd(b);
      assert.strictEqual(a.toString(), '1288490188800');

      a = U64.fromNumber(100 * 0x100000000);
      a.iaddn(0x3ffffff);
      assert.strictEqual(a.toString(), '429563838463');

      a = U64.fromNumber(100 * 0x100000000);
      b = U64.fromNumber(200 * 0x100000000);
      assert.strictEqual(a.add(b).toString(), '1288490188800');
      assert.strictEqual(a.toString(), '429496729600');

      a = U64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.addn(0x3ffffff).toString(), '429563838463');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do big addition (signed)', () => {
      let a = I64.fromNumber(100 * 0x100000000);
      let b = I64.fromNumber(-50 * 0x100000000);
      a.iadd(b);
      assert.strictEqual(a.toString(), '214748364800');

      a = I64.fromNumber(100 * 0x100000000);
      a.iaddn(-50 * 0x100000);
      assert.strictEqual(a.toString(), '429444300800');

      a = I64.fromNumber(100 * 0x100000000);
      b = I64.fromNumber(-50 * 0x100000000);
      assert.strictEqual(a.add(b).toString(), '214748364800');
      assert.strictEqual(a.toString(), '429496729600');

      a = I64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.addn(-50 * 0x100000).toString(), '429444300800');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do small subtraction (unsigned)', () => {
      let a = U64.fromNumber(200);
      let b = U64.fromNumber(100);
      a.isub(b);
      assert.strictEqual(a.toString(), '100');

      a = U64.fromNumber(200);
      a.isubn(100);
      assert.strictEqual(a.toString(), '100');

      a = U64.fromNumber(200);
      b = U64.fromNumber(100);
      assert.strictEqual(a.sub(b).toString(), '100');
      assert.strictEqual(a.toString(), '200');

      a = U64.fromNumber(200);
      assert.strictEqual(a.subn(100).toString(), '100');
      assert.strictEqual(a.toString(), '200');
    });

    it('should do small subtraction (signed)', () => {
      let a = I64.fromNumber(100);
      let b = I64.fromNumber(-50);
      a.isub(b);
      assert.strictEqual(a.toString(), '150');

      a = I64.fromNumber(100);
      a.isubn(-50);
      assert.strictEqual(a.toString(), '150');

      a = I64.fromNumber(100);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.sub(b).toString(), '150');
      assert.strictEqual(a.toString(), '100');

      a = I64.fromNumber(100);
      assert.strictEqual(a.subn(-50).toString(), '150');
      assert.strictEqual(a.toString(), '100');
    });

    it('should do big subtraction (unsigned)', () => {
      let a = U64.fromNumber(100 * 0x100000000);
      let b = U64.fromNumber(200 * 0x100000000);
      a.isub(b);
      assert.strictEqual(a.toString(), '18446743644212822016');

      a = U64.fromNumber(100 * 0x100000000);
      a.isubn(200 * 0x100000);
      assert.strictEqual(a.toString(), '429287014400');

      a = U64.fromNumber(100 * 0x100000000);
      b = U64.fromNumber(200 * 0x100000000);
      assert.strictEqual(a.sub(b).toString(), '18446743644212822016');
      assert.strictEqual(a.toString(), '429496729600');

      a = U64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.subn(200 * 0x100000).toString(), '429287014400');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do big subtraction (signed)', () => {
      let a = I64.fromNumber(100 * 0x100000000);
      let b = I64.fromNumber(200 * 0x100000000);
      a.isub(b);
      assert.strictEqual(a.toString(), '-429496729600');

      a = I64.fromNumber(100 * 0x100000000);
      a.isubn(200 * 0x100000);
      assert.strictEqual(a.toString(), '429287014400');

      a = I64.fromNumber(100 * 0x100000000);
      b = I64.fromNumber(200 * 0x100000000);
      assert.strictEqual(a.sub(b).toString(), '-429496729600');
      assert.strictEqual(a.toString(), '429496729600');

      a = U64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.subn(200 * 0x100000).toString(), '429287014400');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do small multiplication (unsigned)', () => {
      let a = U64.fromNumber(100);
      let b = U64.fromNumber(200);
      a.imul(b);
      assert.strictEqual(a.toString(), '20000');

      a = U64.fromNumber(100);
      a.imuln(200);
      assert.strictEqual(a.toString(), '20000');

      a = U64.fromNumber(100);
      b = U64.fromNumber(200);
      assert.strictEqual(a.mul(b).toString(), '20000');
      assert.strictEqual(a.toString(), '100');

      a = U64.fromNumber(100);
      assert.strictEqual(a.muln(200).toString(), '20000');
      assert.strictEqual(a.toString(), '100');
    });

    it('should do small multiplication (signed)', () => {
      let a = I64.fromNumber(100);
      let b = I64.fromNumber(-50);
      a.imul(b);
      assert.strictEqual(a.toString(), '-5000');

      a = I64.fromNumber(100);
      a.imuln(-50);
      assert.strictEqual(a.toString(), '-5000');

      a = I64.fromNumber(100);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.mul(b).toString(), '-5000');
      assert.strictEqual(a.toString(), '100');

      a = I64.fromNumber(100);
      assert.strictEqual(a.muln(-50).toString(), '-5000');
      assert.strictEqual(a.toString(), '100');
    });

    it('should do big multiplication (unsigned)', () => {
      let a = U64.fromNumber(100 * 0x100000000);
      let b = U64.fromNumber(10 * 0x10000000);
      a.imul(b);
      assert.strictEqual(a.toString(), '9223372036854775808');

      a = U64.fromNumber(100 * 0x100000000);
      a.imuln(200 * 0x1000000);
      assert.strictEqual(a.toString(), '2305843009213693952');

      a = U64.fromNumber(100 * 0x100000000);
      b = U64.fromNumber(10 * 0x10000000);
      assert.strictEqual(a.mul(b).toString(), '9223372036854775808');
      assert.strictEqual(a.toString(), '429496729600');

      a = U64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.muln(200 * 0x1000000).toString(),
        '2305843009213693952');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do big multiplication (signed)', () => {
      let a = I64.fromNumber(100 * 0x100000000);
      let b = I64.fromNumber(-10 * 0x10000000);
      a.imul(b);
      assert.strictEqual(a.toString(), '-9223372036854775808');

      a = I64.fromNumber(100 * 0x100000000);
      a.imuln(-50 * 0x100000);
      assert.strictEqual(a.toString(), '-4071254063142928384');

      a = I64.fromNumber(100 * 0x100000000);
      b = I64.fromNumber(-10 * 0x10000000);
      assert.strictEqual(a.mul(b).toString(), '-9223372036854775808');
      assert.strictEqual(a.toString(), '429496729600');

      a = I64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.muln(-50 * 0x100000).toString(),
        '-4071254063142928384');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do small division (unsigned)', () => {
      let a = U64.fromNumber(200);
      let b = U64.fromNumber(100);
      a.idiv(b);
      assert.strictEqual(a.toString(), '2');

      a = U64.fromNumber(200);
      a.idivn(100);
      assert.strictEqual(a.toString(), '2');

      a = U64.fromNumber(200);
      b = U64.fromNumber(100);
      assert.strictEqual(a.div(b).toString(), '2');
      assert.strictEqual(a.toString(), '200');

      a = U64.fromNumber(200);
      assert.strictEqual(a.divn(100).toString(), '2');
      assert.strictEqual(a.toString(), '200');
    });

    it('should do small division (signed)', () => {
      let a = I64.fromNumber(100);
      let b = I64.fromNumber(-50);
      a.idiv(b);
      assert.strictEqual(a.toString(), '-2');

      a = I64.fromNumber(100);
      a.idivn(-50);
      assert.strictEqual(a.toString(), '-2');

      a = I64.fromNumber(100);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.div(b).toString(), '-2');
      assert.strictEqual(a.toString(), '100');

      a = I64.fromNumber(100);
      assert.strictEqual(a.divn(-50).toString(), '-2');
      assert.strictEqual(a.toString(), '100');
    });

    it('should do big division (unsigned)', () => {
      let a = U64.fromNumber(100 * 0x100000000);
      let b = U64.fromNumber(10 * 0x10000000);
      a.idiv(b);
      assert.strictEqual(a.toString(), '160');

      a = U64.fromNumber(100 * 0x100000000);
      a.idivn(0x3ffffff);
      assert.strictEqual(a.toString(), '6400');

      a = U64.fromNumber(100 * 0x100000000);
      b = U64.fromNumber(10 * 0x10000000);
      assert.strictEqual(a.div(b).toString(), '160');
      assert.strictEqual(a.toString(), '429496729600');

      a = U64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.divn(0x3ffffff).toString(), '6400');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do big division (signed)', () => {
      let a = I64.fromNumber(100 * 0x100000000);
      let b = I64.fromNumber(-10 * 0x10000000);
      a.idiv(b);
      assert.strictEqual(a.toString(), '-160');

      a = I64.fromNumber(100 * 0x100000000);
      a.idivn(-0xfffff);
      assert.strictEqual(a.toString(), '-409600');

      a = I64.fromNumber(100 * 0x100000000);
      b = I64.fromNumber(-10 * 0x10000000);
      assert.strictEqual(a.div(b).toString(), '-160');
      assert.strictEqual(a.toString(), '429496729600');

      a = I64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.divn(-0xfffff).toString(), '-409600');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do small modulo (unsigned)', () => {
      let a = U64.fromNumber(23525432);
      let b = U64.fromNumber(100);
      a.imod(b);
      assert.strictEqual(a.toString(), '32');

      a = U64.fromNumber(435325234);
      a.imodn(100);
      assert.strictEqual(a.toString(), '34');

      a = U64.fromNumber(131235);
      b = U64.fromNumber(100);
      assert.strictEqual(a.mod(b).toString(), '35');
      assert.strictEqual(a.toString(), '131235');

      a = U64.fromNumber(1130021);
      assert.strictEqual(a.modn(100).toString(), '21');
      assert.strictEqual(a.toString(), '1130021');
    });

    it('should do small modulo (signed)', () => {
      let a = I64.fromNumber(354241);
      let b = I64.fromNumber(-50);
      a.imod(b);
      assert.strictEqual(a.toString(), '41');

      a = I64.fromNumber(2124523);
      a.imodn(-50);
      assert.strictEqual(a.toString(), '23');

      a = I64.fromNumber(13210);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.mod(b).toString(), '10');
      assert.strictEqual(a.toString(), '13210');

      a = I64.fromNumber(141001);
      assert.strictEqual(a.modn(-50).toString(), '1');
      assert.strictEqual(a.toString(), '141001');
    });

    it('should do big modulo (unsigned)', () => {
      let a = U64.fromNumber(100 * 0x100000000);
      let b = U64.fromNumber(9 * 0x10000000);
      a.imod(b);
      assert.strictEqual(a.toString(), '1879048192');

      a = U64.fromNumber(100 * 0x100000000);
      a.imodn(0x3ffffff);
      assert.strictEqual(a.toString(), '6400');

      a = U64.fromNumber(100 * 0x100000000);
      b = U64.fromNumber(9 * 0x10000000);
      assert.strictEqual(a.mod(b).toString(), '1879048192');
      assert.strictEqual(a.toString(), '429496729600');

      a = U64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.modn(0x3ffffff).toString(), '6400');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do big modulo (signed)', () => {
      let a = I64.fromNumber(100 * 0x100000000);
      let b = I64.fromNumber(-9 * 0x10000000);
      a.imod(b);
      assert.strictEqual(a.toString(), '1879048192');

      a = I64.fromNumber(100 * 0x100000000);
      a.imodn(-0xfffff);
      assert.strictEqual(a.toString(), '409600');

      a = I64.fromNumber(100 * 0x100000000);
      b = I64.fromNumber(-9 * 0x10000000);
      assert.strictEqual(a.mod(b).toString(), '1879048192');
      assert.strictEqual(a.toString(), '429496729600');

      a = I64.fromNumber(100 * 0x100000000);
      assert.strictEqual(a.modn(-0xfffff).toString(), '409600');
      assert.strictEqual(a.toString(), '429496729600');
    });

    it('should do small pow (unsigned)', () => {
      let a = U64.fromNumber(123);
      let b = U64.fromNumber(6);
      a.ipow(b);
      assert.strictEqual(a.toString(), '3462825991689');

      a = U64.fromNumber(123);
      a.ipown(6);
      assert.strictEqual(a.toString(), '3462825991689');

      a = U64.fromNumber(123);
      b = U64.fromNumber(6);
      assert.strictEqual(a.pow(b).toString(), '3462825991689');
      assert.strictEqual(a.toString(), '123');

      a = U64.fromNumber(123);
      assert.strictEqual(a.pown(6).toString(), '3462825991689');
      assert.strictEqual(a.toString(), '123');
    });

    it('should do small pow (signed)', () => {
      let a = I64.fromNumber(-123);
      let b = I64.fromNumber(6);
      a.ipow(b);
      assert.strictEqual(a.toString(), '3462825991689');

      a = I64.fromNumber(-123);
      a.ipown(6);
      assert.strictEqual(a.toString(), '3462825991689');

      a = I64.fromNumber(-123);
      b = I64.fromNumber(6);
      assert.strictEqual(a.pow(b).toString(), '3462825991689');
      assert.strictEqual(a.toString(), '-123');

      a = I64.fromNumber(-123);
      assert.strictEqual(a.pown(6).toString(), '3462825991689');
      assert.strictEqual(a.toString(), '-123');

      a = I64.fromNumber(-2);
      a.ipown(4);
      assert.strictEqual(a.toString(), '16');
      a = I64.fromNumber(-2);
      a.ipown(3);
      assert.strictEqual(a.toString(), '-8');
    });

    it('should do big pow (unsigned)', () => {
      let a = U64.fromNumber(2);
      let b = U64.fromNumber(63);
      a.ipow(b);
      assert.strictEqual(a.toString(), '9223372036854775808');

      a = U64.fromNumber(2);
      a.ipown(63);
      assert.strictEqual(a.toString(), '9223372036854775808');

      a = U64.fromNumber(2);
      b = U64.fromNumber(63);
      assert.strictEqual(a.pow(b).toString(), '9223372036854775808');
      assert.strictEqual(a.toString(), '2');

      a = U64.fromNumber(2);
      assert.strictEqual(a.pown(63).toString(), '9223372036854775808');
      assert.strictEqual(a.toString(), '2');

      a = U64.fromNumber(2);
      assert.strictEqual(a.pown(64).subn(1).toString(), '18446744073709551615');

      a = U64.fromNumber(2);
      assert.strictEqual(a.pown(64).toString(), '0');
    });

    it('should do big pow (signed)', () => {
      let a = I64.fromNumber(-2);
      let b = I64.fromNumber(63);
      a.ipow(b);
      assert.strictEqual(a.toString(), '-9223372036854775808');

      a = I64.fromNumber(-2);
      a.ipown(63);
      assert.strictEqual(a.toString(), '-9223372036854775808');

      a = I64.fromNumber(-2);
      b = I64.fromNumber(63);
      assert.strictEqual(a.pow(b).toString(), '-9223372036854775808');
      assert.strictEqual(a.toString(), '-2');

      a = I64.fromNumber(-2);
      assert.strictEqual(a.pown(63).toString(), '-9223372036854775808');
      assert.strictEqual(a.toString(), '-2');

      a = I64.fromNumber(-2);
      assert.strictEqual(a.pown(64).subn(1).toString(), '-1');

      a = I64.fromNumber(-2);
      assert.strictEqual(a.pown(64).toString(), '0');
    });

    it('should square', () => {
      let a = U64.fromNumber(6);
      a.isqr();
      assert.strictEqual(a.toString(), '36');

      a = U64.fromNumber(6);
      assert.strictEqual(a.sqr().toString(), '36');
      assert.strictEqual(a.toString(), '6');
    });

    it('should do small AND (unsigned)', () => {
      let a = U64.fromNumber(12412);
      let b = U64.fromNumber(200);
      a.iand(b);
      assert.strictEqual(a.toString(), '72');

      a = U64.fromNumber(12412);
      a.iandn(200);
      assert.strictEqual(a.toString(), '72');

      a = U64.fromNumber(12412);
      b = U64.fromNumber(200);
      assert.strictEqual(a.and(b).toString(), '72');
      assert.strictEqual(a.toString(), '12412');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.andn(200).toString(), '72');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small AND (signed)', () => {
      let a = I64.fromNumber(12412);
      let b = I64.fromNumber(-50);
      a.iand(b);
      assert.strictEqual(a.toString(), '12364');

      a = I64.fromNumber(12412);
      a.iandn(-50);
      assert.strictEqual(a.toString(), '12364');

      a = I64.fromNumber(12412);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.and(b).toString(), '12364');
      assert.strictEqual(a.toString(), '12412');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.andn(-50).toString(), '12364');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big AND (unsigned)', () => {
      let a = U64.fromNumber(1214532435245234);
      let b = U64.fromNumber(1242541452);
      a.iand(b);
      assert.strictEqual(a.toString(), '1242474624');

      a = U64.fromNumber(13545214126);
      a.iandn(7 * 0x1000000);
      assert.strictEqual(a.toString(), '117440512');

      a = U64.fromNumber(13545214126);
      b = U64.fromNumber(7 * 0x10000000);
      assert.strictEqual(a.and(b).toString(), '536870912');
      assert.strictEqual(a.toString(), '13545214126');

      a = U64.fromNumber(13545214126);
      assert.strictEqual(a.andn(7 * 0x1000000).toString(), '117440512');
      assert.strictEqual(a.toString(), '13545214126');
    });

    it('should do big AND (signed)', () => {
      let a = I64.fromNumber(1214532435245234);
      let b = I64.fromNumber(1242541452);
      a.iand(b);
      assert.strictEqual(a.toString(), '1242474624');

      a = I64.fromNumber(13545214126);
      a.iandn(7 * 0x1000000);
      assert.strictEqual(a.toString(), '117440512');

      a = I64.fromNumber(13545214126);
      b = I64.fromNumber(7 * 0x10000000);
      assert.strictEqual(a.and(b).toString(), '536870912');
      assert.strictEqual(a.toString(), '13545214126');

      a = I64.fromNumber(13545214126);
      assert.strictEqual(a.andn(7 * 0x1000000).toString(), '117440512');
      assert.strictEqual(a.toString(), '13545214126');
    });

    it('should do small OR (unsigned)', () => {
      let a = U64.fromNumber(12412);
      let b = U64.fromNumber(200);
      a.ior(b);
      assert.strictEqual(a.toString(), '12540');

      a = U64.fromNumber(12412);
      a.iorn(200);
      assert.strictEqual(a.toString(), '12540');

      a = U64.fromNumber(12412);
      b = U64.fromNumber(200);
      assert.strictEqual(a.or(b).toString(), '12540');
      assert.strictEqual(a.toString(), '12412');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.orn(200).toString(), '12540');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small OR (signed)', () => {
      let a = I64.fromNumber(12412);
      let b = I64.fromNumber(-50);
      a.ior(b);
      assert.strictEqual(a.toString(), '-2');

      a = I64.fromNumber(12412);
      a.iorn(-50);
      assert.strictEqual(a.toString(), '-2');

      a = I64.fromNumber(12412);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.or(b).toString(), '-2');
      assert.strictEqual(a.toString(), '12412');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.orn(-50).toString(), '-2');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big OR (unsigned)', () => {
      let a = U64.fromNumber(1214532435245234);
      let b = U64.fromNumber(1242541452);
      a.ior(b);
      assert.strictEqual(a.toString(), '1214532435312062');

      a = U64.fromNumber(13545214126);
      a.iorn(7 * 0x1000000);
      assert.strictEqual(a.toString(), '13545214126');

      a = U64.fromNumber(13545214126);
      b = U64.fromNumber(7 * 0x10000000);
      assert.strictEqual(a.or(b).toString(), '14887391406');
      assert.strictEqual(a.toString(), '13545214126');

      a = U64.fromNumber(13545214126);
      assert.strictEqual(a.orn(7 * 0x1000000).toString(), '13545214126');
      assert.strictEqual(a.toString(), '13545214126');
    });

    it('should do big OR (signed)', () => {
      let a = I64.fromNumber(1214532435245234);
      let b = I64.fromNumber(1242541452);
      a.ior(b);
      assert.strictEqual(a.toString(), '1214532435312062');

      a = I64.fromNumber(13545214126);
      a.iorn(7 * 0x1000000);
      assert.strictEqual(a.toString(), '13545214126');

      a = I64.fromNumber(13545214126);
      b = I64.fromNumber(7 * 0x10000000);
      assert.strictEqual(a.or(b).toString(), '14887391406');
      assert.strictEqual(a.toString(), '13545214126');

      a = I64.fromNumber(13545214126);
      assert.strictEqual(a.orn(7 * 0x1000000).toString(), '13545214126');
      assert.strictEqual(a.toString(), '13545214126');
    });

    it('should do small XOR (unsigned)', () => {
      let a = U64.fromNumber(12412);
      let b = U64.fromNumber(200);
      a.ixor(b);
      assert.strictEqual(a.toString(), '12468');

      a = U64.fromNumber(12412);
      a.ixorn(200);
      assert.strictEqual(a.toString(), '12468');

      a = U64.fromNumber(12412);
      b = U64.fromNumber(200);
      assert.strictEqual(a.xor(b).toString(), '12468');
      assert.strictEqual(a.toString(), '12412');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.xorn(200).toString(), '12468');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small XOR (signed)', () => {
      let a = I64.fromNumber(12412);
      let b = I64.fromNumber(-50);
      a.ixor(b);
      assert.strictEqual(a.toString(), '-12366');

      a = I64.fromNumber(12412);
      a.ixorn(-50);
      assert.strictEqual(a.toString(), '-12366');

      a = I64.fromNumber(12412);
      b = I64.fromNumber(-50);
      assert.strictEqual(a.xor(b).toString(), '-12366');
      assert.strictEqual(a.toString(), '12412');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.xorn(-50).toString(), '-12366');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big XOR (unsigned)', () => {
      let a = U64.fromNumber(1214532435245234);
      let b = U64.fromNumber(1242541452);
      a.ixor(b);
      assert.strictEqual(a.toString(), '1214531192837438');

      a = U64.fromNumber(13545214126);
      a.ixorn(7 * 0x1000000);
      assert.strictEqual(a.toString(), '13427773614');

      a = U64.fromNumber(13545214126);
      b = U64.fromNumber(7 * 0x10000000);
      assert.strictEqual(a.xor(b).toString(), '14350520494');
      assert.strictEqual(a.toString(), '13545214126');

      a = U64.fromNumber(13545214126);
      assert.strictEqual(a.xorn(7 * 0x1000000).toString(), '13427773614');
      assert.strictEqual(a.toString(), '13545214126');
    });

    it('should do big XOR (signed)', () => {
      let a = I64.fromNumber(1214532435245234);
      let b = I64.fromNumber(1242541452);
      a.ixor(b);
      assert.strictEqual(a.toString(), '1214531192837438');

      a = I64.fromNumber(13545214126);
      a.ixorn(7 * 0x1000000);
      assert.strictEqual(a.toString(), '13427773614');

      a = I64.fromNumber(13545214126);
      b = I64.fromNumber(7 * 0x10000000);
      assert.strictEqual(a.xor(b).toString(), '14350520494');
      assert.strictEqual(a.toString(), '13545214126');

      a = I64.fromNumber(13545214126);
      assert.strictEqual(a.xorn(7 * 0x1000000).toString(), '13427773614');
      assert.strictEqual(a.toString(), '13545214126');
    });

    it('should do small left shift (unsigned)', () => {
      let a = U64.fromNumber(12412);
      let b = U64.fromNumber(2);
      a.ishl(b);
      assert.strictEqual(a.toString(), '49648');

      a = U64.fromNumber(12412);
      a.ishln(2);
      assert.strictEqual(a.toString(), '49648');

      a = U64.fromNumber(12412);
      b = U64.fromNumber(2);
      assert.strictEqual(a.shl(b).toString(), '49648');
      assert.strictEqual(a.toString(), '12412');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.shln(2).toString(), '49648');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small left shift (signed)', () => {
      let a = I64.fromNumber(12412);
      let b = I64.fromNumber(2);
      a.ishl(b);
      assert.strictEqual(a.toString(), '49648');

      a = I64.fromNumber(12412);
      a.ishln(2);
      assert.strictEqual(a.toString(), '49648');

      a = I64.fromNumber(12412);
      b = I64.fromNumber(2);
      assert.strictEqual(a.shl(b).toString(), '49648');
      assert.strictEqual(a.toString(), '12412');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.shln(2).toString(), '49648');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big left shift (unsigned)', () => {
      let a = U64.fromNumber(123);
      let b = U64.fromNumber(60);
      a.ishl(b);
      assert.strictEqual(a.toString(), '12682136550675316736');

      a = U64.fromNumber(123);
      a.ishln(60);
      assert.strictEqual(a.toString(), '12682136550675316736');

      a = U64.fromNumber(123);
      b = U64.fromNumber(60);
      assert.strictEqual(a.shl(b).toString(), '12682136550675316736');
      assert.strictEqual(a.toString(), '123');

      a = U64.fromNumber(123);
      assert.strictEqual(a.shln(60).toString(), '12682136550675316736');
      assert.strictEqual(a.toString(), '123');
    });

    it('should do big left shift (signed)', () => {
      let a = I64.fromNumber(123);
      let b = I64.fromNumber(60);
      a.ishl(b);
      assert.strictEqual(a.toString(), '-5764607523034234880');

      a = I64.fromNumber(123);
      a.ishln(60);
      assert.strictEqual(a.toString(), '-5764607523034234880');

      a = I64.fromNumber(123);
      b = I64.fromNumber(60);
      assert.strictEqual(a.shl(b).toString(), '-5764607523034234880');
      assert.strictEqual(a.toString(), '123');

      a = I64.fromNumber(123);
      assert.strictEqual(a.shln(60).toString(), '-5764607523034234880');
      assert.strictEqual(a.toString(), '123');
    });

    it('should do small right shift (unsigned)', () => {
      let a = U64.fromNumber(12412);
      let b = U64.fromNumber(2);
      a.ishr(b);
      assert.strictEqual(a.toString(), '3103');

      a = U64.fromNumber(12412);
      a.ishrn(2);
      assert.strictEqual(a.toString(), '3103');

      a = U64.fromNumber(12412);
      b = U64.fromNumber(2);
      assert.strictEqual(a.shr(b).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.shrn(2).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small right shift (signed)', () => {
      let a = I64.fromNumber(12412);
      let b = I64.fromNumber(2);
      a.ishr(b);
      assert.strictEqual(a.toString(), '3103');

      a = I64.fromNumber(12412);
      a.ishrn(2);
      assert.strictEqual(a.toString(), '3103');

      a = I64.fromNumber(12412);
      b = I64.fromNumber(2);
      assert.strictEqual(a.shr(b).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.shrn(2).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big right shift (unsigned)', () => {
      let a = U64.fromString('f00fffffffffffff', 16);
      let b = U64.fromNumber(45);
      a.ishr(b);
      assert.strictEqual(a.toString(), '491647');

      a = U64.fromString('f00fffffffffffff', 16);
      a.ishrn(45);
      assert.strictEqual(a.toString(), '491647');

      a = U64.fromString('f00fffffffffffff', 16);
      b = U64.fromNumber(45);
      assert.strictEqual(a.shr(b).toString(), '491647');
      assert.strictEqual(a.toString(), '17298326168730075135');

      a = U64.fromString('f00fffffffffffff', 16);
      assert.strictEqual(a.shrn(45).toString(), '491647');
      assert.strictEqual(a.toString(), '17298326168730075135');
    });

    it('should do big right shift (signed)', () => {
      let a = I64.fromString('f00fffffffffffff', 16);
      let b = I64.fromNumber(45);
      a.ishr(b);
      assert.strictEqual(a.toString(), '-32641');

      a = I64.fromString('f00fffffffffffff', 16);
      a.ishrn(45);
      assert.strictEqual(a.toString(), '-32641');

      a = I64.fromString('f00fffffffffffff', 16);
      b = I64.fromNumber(45);
      assert.strictEqual(a.shr(b).toString(), '-32641');
      assert.strictEqual(a.toString(), '-1148417904979476481');

      a = I64.fromString('f00fffffffffffff', 16);
      assert.strictEqual(a.shrn(45).toString(), '-32641');
      assert.strictEqual(a.toString(), '-1148417904979476481');
    });

    it('should do small unsigned right shift (unsigned)', () => {
      let a = U64.fromNumber(12412);
      let b = U64.fromNumber(2);
      a.iushr(b);
      assert.strictEqual(a.toString(), '3103');

      a = U64.fromNumber(12412);
      a.iushrn(2);
      assert.strictEqual(a.toString(), '3103');

      a = U64.fromNumber(12412);
      b = U64.fromNumber(2);
      assert.strictEqual(a.ushr(b).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.ushrn(2).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small unsigned right shift (signed)', () => {
      let a = I64.fromNumber(12412);
      let b = I64.fromNumber(2);
      a.iushr(b);
      assert.strictEqual(a.toString(), '3103');

      a = I64.fromNumber(12412);
      a.iushrn(2);
      assert.strictEqual(a.toString(), '3103');

      a = I64.fromNumber(12412);
      b = I64.fromNumber(2);
      assert.strictEqual(a.ushr(b).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.ushrn(2).toString(), '3103');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big unsigned right shift (unsigned)', () => {
      let a = U64.fromString('ffffffffffffffff', 16);
      let b = U64.fromNumber(45);
      a.iushr(b);
      assert.strictEqual(a.toString(), '524287');

      a = U64.fromString('ffffffffffffffff', 16);
      a.iushrn(45);
      assert.strictEqual(a.toString(), '524287');

      a = U64.fromString('ffffffffffffffff', 16);
      b = U64.fromNumber(45);
      assert.strictEqual(a.ushr(b).toString(), '524287');
      assert.strictEqual(a.toString(), '18446744073709551615');

      a = U64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(a.ushrn(45).toString(), '524287');
      assert.strictEqual(a.toString(), '18446744073709551615');
    });

    it('should do big unsigned right shift (signed)', () => {
      let a = I64.fromString('ffffffffffffffff', 16);
      let b = I64.fromNumber(45);
      a.iushr(b);
      assert.strictEqual(a.toString(), '524287');

      a = I64.fromString('ffffffffffffffff', 16);
      a.iushrn(45);
      assert.strictEqual(a.toString(), '524287');

      a = I64.fromString('ffffffffffffffff', 16);
      b = I64.fromNumber(45);
      assert.strictEqual(a.ushr(b).toString(), '524287');
      assert.strictEqual(a.toString(), '-1');

      a = I64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(a.ushrn(45).toString(), '524287');
      assert.strictEqual(a.toString(), '-1');
    });

    it('should set and test bits', () => {
      const a = U64(0);
      assert.strictEqual(a.testn(35), 0);
      a.setn(35, 1);
      assert.strictEqual(a.toString(), '34359738368');
      assert.strictEqual(a.testn(35), 1);
      assert.strictEqual(a.testn(34), 0);
      a.setn(35, 0);
      assert.strictEqual(a.testn(35), 0);
      assert.strictEqual(a.toString(), '0');
    });

    it('should set and test bytes', () => {
      const a = U64(0);
      assert.strictEqual(a.testn(35), 0);
      a.setb(6, 1);
      assert.strictEqual(a.toString(), '281474976710656');
      assert.strictEqual(a.getb(6), 1);
      assert.strictEqual(a.getb(5), 0);
      a.orb(3, 2);
      assert.strictEqual(a.getb(3), 2);
      assert.strictEqual(a.toString(), '281475010265088');
    });

    it('should mask bits', () => {
      let a = U64.fromString('ffffffffffffffff', 16);
      a.imaskn(35);
      assert.strictEqual(a.toString(), '34359738367');

      a = U64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(a.maskn(35).toString(), '34359738367');
      assert.strictEqual(a.toString(), '18446744073709551615');
    });

    it('should and lo bits', () => {
      assert.strictEqual(U64(1).andln(0xffff), 1);
    });

    it('should do small NOT (unsigned)', () => {
      let a = U64.fromNumber(12412);
      a.inot();
      assert.strictEqual(a.toString(), '18446744073709539203');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.not().toString(), '18446744073709539203');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small NOT (signed)', () => {
      let a = I64.fromNumber(12412);
      a.inot();
      assert.strictEqual(a.toString(), '-12413');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.not().toString(), '-12413');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big NOT (unsigned)', () => {
      let a = U64.fromString('ffffffffffffffff', 16);
      a.inot();
      assert.strictEqual(a.toString(), '0');

      a = U64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(a.not().toString(), '0');
      assert.strictEqual(a.toString(), '18446744073709551615');
    });

    it('should do big NOT (signed)', () => {
      let a = I64.fromString('ffffffffffffffff', 16);
      a.inot();
      assert.strictEqual(a.toString(), '0');

      a = I64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(a.not().toString(), '0');
      assert.strictEqual(a.toString(), '-1');
    });

    it('should do small NEGATE (unsigned)', () => {
      let a = U64.fromNumber(12412);
      a.ineg();
      assert.strictEqual(a.toString(), '18446744073709539204');

      a = U64.fromNumber(12412);
      assert.strictEqual(a.neg().toString(), '18446744073709539204');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do small NEGATE (signed)', () => {
      let a = I64.fromNumber(12412);
      a.ineg();
      assert.strictEqual(a.toString(), '-12412');

      a = I64.fromNumber(12412);
      assert.strictEqual(a.neg().toString(), '-12412');
      assert.strictEqual(a.toString(), '12412');
    });

    it('should do big NEGATE (unsigned)', () => {
      let a = U64.fromString('ffffffffffffffff', 16);
      a.ineg();
      assert.strictEqual(a.toString(), '1');

      a = U64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(a.neg().toString(), '1');
      assert.strictEqual(a.toString(), '18446744073709551615');
    });

    it('should do big NEGATE (signed)', () => {
      let a = I64.fromString('ffffffffffffffff', 16);
      a.ineg();
      assert.strictEqual(a.toString(), '1');

      a = I64.fromString('ffffffffffffffff', 16);
      assert.strictEqual(a.neg().toString(), '1');
      assert.strictEqual(a.toString(), '-1');
    });

    it('should get absolute value', () => {
      assert.strictEqual(I64(-1).toString(), '-1');
      assert.strictEqual(I64(-1).abs().toString(), '1');
      assert.strictEqual(I64(-1).iabs().toString(), '1');
      assert.strictEqual(I64(1).abs().toString(), '1');
      assert.strictEqual(I64(1).iabs().toString(), '1');
    });

    it('should test safety', () => {
      assert.strictEqual(MAX_SAFE.toString(), '9007199254740991');
      assert.strictEqual(MAX_SAFE_MIN.toString(), '-9007199254740991');
      assert.strictEqual(MAX_SAFE_MAX.toString(), '9007199254740991');
      assert.strictEqual(MAX_SAFE.toNumber(), 9007199254740991);
      assert.strictEqual(MAX_SAFE_MIN.toNumber(), -9007199254740991);
      assert.strictEqual(MAX_SAFE_MAX.toNumber(), 9007199254740991);

      assert.strictEqual(ONE.isSafe(), true);
      assert.strictEqual(UONE.isSafe(), true);
      assert.strictEqual(I64.INT32_MIN.isSafe(), true);
      assert.strictEqual(I64.INT32_MAX.isSafe(), true);
      assert.strictEqual(U64.UINT32_MIN.isSafe(), true);
      assert.strictEqual(U64.UINT32_MAX.isSafe(), true);
      assert.strictEqual(MAX_SAFE.isSafe(), true);
      assert.strictEqual(MAX_SAFE_MIN.isSafe(), true);
      assert.strictEqual(MAX_SAFE_MAX.isSafe(), true);
      assert.strictEqual(MAX_SAFE.clone().addn(1).isSafe(), false);
      assert.strictEqual(MAX_SAFE_MIN.clone().subn(1).isSafe(), false);
      assert.strictEqual(MAX_SAFE_MAX.clone().addn(1).isSafe(), false);
    });

    it('should test static methods', () => {
      assert(U64.isU64(new U64()));
      assert(!U64.isU64(new I64()));
      assert(!U64.isU64({}));

      assert(I64.isI64(new I64()));
      assert(!I64.isI64(new U64()));
      assert(!I64.isI64({}));

      assert(N64.isN64(new U64()));
      assert(N64.isN64(new I64()));
      assert(!N64.isN64({}));

      assert(U64.random() instanceof U64);
      assert(I64.random() instanceof I64);

      assert.strictEqual(
        U64.pow(2, 64).subn(1).toString(),
        '18446744073709551615');

      assert.strictEqual(I64.pow(2, 64).subn(1).toString(), '-1');

      assert.strictEqual(U64.shift(1, 63).toString(), '9223372036854775808');
      assert.strictEqual(I64.shift(1, 63).toString(), '-9223372036854775808');
    });

    it('should test encoding (unsigned)', () => {
      const num = U64.fromString('8864030017785018305');

      let r = num.toRaw(Buffer);
      let n = U64.fromRaw(r);

      assert.strictEqual(r.toString('hex'), 'c1b77968565c037b');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = num.toLE(Buffer);
      n = U64.fromLE(r);

      assert.strictEqual(r.toString('hex'), 'c1b77968565c037b');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = num.toBE(Buffer);
      n = U64.fromBE(r);

      assert.strictEqual(r.toString('hex'), '7b035c566879b7c1');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = Buffer.alloc(8);
      num.writeRaw(r, 0);
      n = U64.readRaw(r, 0);

      assert.strictEqual(r.toString('hex'), 'c1b77968565c037b');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = Buffer.alloc(8);
      num.writeLE(r, 0);
      n = U64.readLE(r, 0);

      assert.strictEqual(r.toString('hex'), 'c1b77968565c037b');
      assert.strictEqual(n.toString(16), num.toString(16));

      n = U64(r);

      assert.strictEqual(r.toString('hex'), 'c1b77968565c037b');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = Buffer.alloc(8);
      num.writeBE(r, 0);
      n = U64.readBE(r, 0);

      assert.strictEqual(r.toString('hex'), '7b035c566879b7c1');
      assert.strictEqual(n.toString(16), num.toString(16));
    });

    it('should test encoding (signed)', () => {
      const num = I64.fromString('-8864030017785018305');

      let r = num.toRaw(Buffer);
      let n = I64.fromRaw(r);

      assert.strictEqual(r.toString('hex'), '3f488697a9a3fc84');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = num.toLE(Buffer);
      n = I64.fromLE(r);

      assert.strictEqual(r.toString('hex'), '3f488697a9a3fc84');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = num.toBE(Buffer);
      n = I64.fromBE(r);

      assert.strictEqual(r.toString('hex'), '84fca3a99786483f');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = Buffer.alloc(8);
      num.writeRaw(r, 0);
      n = I64.readRaw(r, 0);

      assert.strictEqual(r.toString('hex'), '3f488697a9a3fc84');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = Buffer.alloc(8);
      num.writeLE(r, 0);
      n = I64.readLE(r, 0);

      assert.strictEqual(r.toString('hex'), '3f488697a9a3fc84');
      assert.strictEqual(n.toString(16), num.toString(16));

      n = I64(r);

      assert.strictEqual(r.toString('hex'), '3f488697a9a3fc84');
      assert.strictEqual(n.toString(16), num.toString(16));

      r = Buffer.alloc(8);
      num.writeBE(r, 0);
      n = I64.readBE(r, 0);

      assert.strictEqual(r.toString('hex'), '84fca3a99786483f');
      assert.strictEqual(n.toString(16), num.toString(16));
    });

    it('should have bool casting', () => {
      assert.strictEqual(U64(true).toString(10), '1');
      assert.strictEqual(U64(false).toString(10), '0');
      assert.strictEqual(I64(true).toString(10), '1');
      assert.strictEqual(I64(false).toString(10), '0');
      assert.strictEqual(U64.fromBool(true).toString(10), '1');
      assert.strictEqual(U64.fromBool(false).toString(10), '0');
      assert.strictEqual(I64.fromBool(true).toString(10), '1');
      assert.strictEqual(I64.fromBool(false).toString(10), '0');
      assert.strictEqual(U64(1).toBool(), true);
      assert.strictEqual(U64(0).toBool(), false);
      assert.strictEqual(U64(-1).toBool(), true);
      assert.strictEqual(I64(1).toBool(), true);
      assert.strictEqual(I64(0).toBool(), false);
      assert.strictEqual(I64(-1).toBool(), true);
      assert.throws(() => U64.fromBool(1));
      assert.throws(() => I64.fromBool(1));
    });

    it('should test bignum compat', () => {
      let n = new BN('9007199254740991', 10);
      let num = U64.fromBN(n);
      assert.strictEqual(num.toString(), '9007199254740991');
      assert(num.toBN(BN).eq(n));

      n = new BN('-9007199254740991', 10);
      num = I64.fromBN(n);
      assert.strictEqual(num.toString(), '-9007199254740991');
      assert(num.toBN(BN).eq(n));

      n = new BN('ffffffffffffffff', 16);
      num = U64.fromBN(n);
      assert.strictEqual(num.toString(16), 'ffffffffffffffff');
      assert(num.toBN(BN).eq(n));

      n = new BN('ffffffffffffffff', 16);
      assert.throws(() => I64.fromBN(n));

      n = new BN('fffffffffffffffff', 16);
      assert.throws(() => U64.fromBN(n));

      n = new BN('-fffffffffffffff', 16);
      num = I64.fromBN(n);
      assert.strictEqual(num.toString(16), '-fffffffffffffff');
      assert(num.toBN(BN).eq(n));

      n = new BN('-fffffffffffffff', 16);
      num = I64(n);
      assert.strictEqual(num.toString(16), '-fffffffffffffff');
      assert(num.toBN(BN).eq(n));
    });

    it('should test multiplication overflow (1)', () => {
      const number = U64.fromString('8864030017785018305');
      const operand = U64.fromString('17290260146955268389');
      const result = number.mul(operand);
      assert.strictEqual(result.toString(10), '11297288259488448485');
    });

    it('should test multiplication overflow (2)', () => {
      const number = U64.fromString('8439509051110122647');
      const operand = U64.fromString('12580720524404292133');
      const result = number.mul(operand);
      assert.strictEqual(result.toString(10), '379484468253032403');
    });

    it('should test multiplication overflow (3)', () => {
      const number = U64.fromString('8be04bf30ed7308d', 16);
      const operand = U64.fromString('87c4c6fd02280001', 16);
      const result = number.mul(operand);
      assert.strictEqual(result.toString(16), 'f124554cbedf308d');
    });

    it('should test exponent overflow (1)', () => {
      const number = U64.fromString('539709153113928093');
      const operand = 1309648989;
      const result = number.pown(operand);
      assert.strictEqual(result.toString(10), '9390288313338769549');
    });

    it('should test exponent overflow (2)', () => {
      const number = I64.fromString('4240110663');
      const operand = 1444429182;
      const result = number.pown(operand);
      assert.strictEqual(result.toString(10), '3719928238591852881');
    });
  });
}

run(n64, 'n64 (JS)');
run(native, 'n64 (Native)');
