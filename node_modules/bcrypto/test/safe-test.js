'use strict';

const assert = require('bsert');
const safe = require('../lib/safe');
const bytes = Buffer.alloc(32);
const rbytes = Buffer.alloc(32);

for (let i = 0; i < 32; i++)
  bytes[i] = i;

for (let i = 0; i < 32; i++)
  rbytes[i] = 32 - i;

describe('Safe', function() {
  for (const safeEqual of [safe.safeEqual, safe.safeCompare]) {
    it('should compare bytes', () => {
      const bytes2 = Buffer.alloc(32);

      for (let i = 0; i < 32; i++)
        bytes2[i] = i;

      assert.strictEqual(safeEqual(bytes, bytes), 1);
      assert.strictEqual(safeEqual(bytes, bytes2), 1);
      assert.strictEqual(safeEqual(Buffer.alloc(0), Buffer.alloc(0)), 1);
    });

    it('should fail comparing bytes', () => {
      assert.strictEqual(safeEqual(bytes, rbytes), 0);
      assert.strictEqual(safeEqual(rbytes, bytes), 0);
      assert.strictEqual(safeEqual(bytes, bytes.slice(31)), 0);
      assert.strictEqual(safeEqual(bytes.slice(31), bytes), 0);

      const buf = Buffer.concat([bytes, Buffer.from([0x00])]);

      assert.strictEqual(safeEqual(bytes, buf), 0);
      assert.strictEqual(safeEqual(buf, bytes), 0);
      assert.strictEqual(safeEqual(bytes, Buffer.alloc(0)), 0);
      assert.strictEqual(safeEqual(Buffer.alloc(0), bytes), 0);
    });
  }

  it('should compare uint8', () => {
    assert.strictEqual(safe.safeEqualByte(0, 0), 1);
    assert.strictEqual(safe.safeEqualByte(1, 1), 1);
    assert.strictEqual(safe.safeEqualByte(0xff, 0xff), 1);
    assert.strictEqual(safe.safeEqualByte(0xffff, 0xff), 1);
    assert.strictEqual(safe.safeEqualByte(-1, 0xff), 1);
    assert.strictEqual(safe.safeEqualByte(-1, -1), 1);
    assert.strictEqual(safe.safeEqualByte(-1, 0xff - 1), 0);
    assert.strictEqual(safe.safeEqualByte(0, 1), 0);
  });

  it('should compare ints', () => {
    assert.strictEqual(safe.safeEqualInt(0, 0), 1);
    assert.strictEqual(safe.safeEqualInt(1, 1), 1);
    assert.strictEqual(safe.safeEqualInt(0xffffffff, 0xffffffff), 1);
    assert.strictEqual(safe.safeEqualInt(-1, 0xffffffff), 1);
    assert.strictEqual(safe.safeEqualInt(-1, -1), 1);
    assert.strictEqual(safe.safeEqualInt(-1, 0xffffffff - 1), 0);
    assert.strictEqual(safe.safeEqualInt(0, 1), 0);
  });

  it('should select int', () => {
    assert.strictEqual(safe.safeSelect(-1, -2, 0), -1);
    assert.strictEqual(safe.safeSelect(-1, -2, 1), -2);
    assert.strictEqual(safe.safeSelect(0, 0, 0), 0);
    assert.strictEqual(safe.safeSelect(0, 0, 1), 0);
    assert.strictEqual(safe.safeSelect(1, 2, 0), 1);
    assert.strictEqual(safe.safeSelect(1, 2, 1), 2);
    assert.strictEqual(safe.safeSelect(-100, 100, 0), -100);
    assert.strictEqual(safe.safeSelect(-100, 100, 1), 100);
  });

  it('should compare int (LT)', () => {
    assert.strictEqual(safe.safeLT(-1, -2), 0);
    assert.strictEqual(safe.safeLT(-2, -2), 0);
    assert.strictEqual(safe.safeLT(-3, -2), 1);
    assert.strictEqual(safe.safeLT(0, 0), 0);
    assert.strictEqual(safe.safeLT(1, 2), 1);
    assert.strictEqual(safe.safeLT(2, 2), 0);
    assert.strictEqual(safe.safeLT(3, 2), 0);
    assert.strictEqual(safe.safeLT(-100, 100), 1);
    assert.strictEqual(safe.safeLT(100, -100), 0);
  });

  it('should compare int (LTE)', () => {
    assert.strictEqual(safe.safeLTE(-1, -2), 0);
    assert.strictEqual(safe.safeLTE(-2, -2), 1);
    assert.strictEqual(safe.safeLTE(-3, -2), 1);
    assert.strictEqual(safe.safeLTE(0, 0), 1);
    assert.strictEqual(safe.safeLTE(1, 2), 1);
    assert.strictEqual(safe.safeLTE(2, 2), 1);
    assert.strictEqual(safe.safeLTE(3, 2), 0);
    assert.strictEqual(safe.safeLTE(-100, 100), 1);
    assert.strictEqual(safe.safeLTE(100, -100), 0);
  });

  it('should compare int (GT)', () => {
    assert.strictEqual(safe.safeGT(-1, -2), 1);
    assert.strictEqual(safe.safeGT(-2, -2), 0);
    assert.strictEqual(safe.safeGT(-3, -2), 0);
    assert.strictEqual(safe.safeGT(0, 0), 0);
    assert.strictEqual(safe.safeGT(1, 2), 0);
    assert.strictEqual(safe.safeGT(2, 2), 0);
    assert.strictEqual(safe.safeGT(3, 2), 1);
    assert.strictEqual(safe.safeGT(-100, 100), 0);
    assert.strictEqual(safe.safeGT(100, -100), 1);
  });

  it('should compare int (GTE)', () => {
    assert.strictEqual(safe.safeGTE(-1, -2), 1);
    assert.strictEqual(safe.safeGTE(-2, -2), 1);
    assert.strictEqual(safe.safeGTE(-3, -2), 0);
    assert.strictEqual(safe.safeGTE(0, 0), 1);
    assert.strictEqual(safe.safeGTE(1, 2), 0);
    assert.strictEqual(safe.safeGTE(2, 2), 1);
    assert.strictEqual(safe.safeGTE(3, 2), 1);
    assert.strictEqual(safe.safeGTE(-100, 100), 0);
    assert.strictEqual(safe.safeGTE(100, -100), 1);
  });

  it('should take min', () => {
    assert.strictEqual(safe.safeMin(-1, -2), -2);
    assert.strictEqual(safe.safeMin(-2, -1), -2);
    assert.strictEqual(safe.safeMin(-2, -2), -2);
    assert.strictEqual(safe.safeMin(0, 0), 0);
    assert.strictEqual(safe.safeMin(1, 2), 1);
    assert.strictEqual(safe.safeMin(2, 1), 1);
    assert.strictEqual(safe.safeMin(2, 2), 2);
    assert.strictEqual(safe.safeMin(-100, 100), -100);
    assert.strictEqual(safe.safeMin(100, -100), -100);
  });

  it('should take max', () => {
    assert.strictEqual(safe.safeMax(-1, -2), -1);
    assert.strictEqual(safe.safeMax(-2, -1), -1);
    assert.strictEqual(safe.safeMax(-2, -2), -2);
    assert.strictEqual(safe.safeMax(0, 0), 0);
    assert.strictEqual(safe.safeMax(1, 2), 2);
    assert.strictEqual(safe.safeMax(2, 1), 2);
    assert.strictEqual(safe.safeMax(2, 2), 2);
    assert.strictEqual(safe.safeMax(-100, 100), 100);
    assert.strictEqual(safe.safeMax(100, -100), 100);
  });

  it('should take abs', () => {
    assert.strictEqual(safe.safeAbs(-100), 100);
    assert.strictEqual(safe.safeAbs(-1), 1);
    assert.strictEqual(safe.safeAbs(0), 0);
    assert.strictEqual(safe.safeAbs(1), 1);
    assert.strictEqual(safe.safeAbs(100), 100);
  });

  it('should take bool', () => {
    assert.strictEqual(safe.safeBool(-100), 1);
    assert.strictEqual(safe.safeBool(-1), 1);
    assert.strictEqual(safe.safeBool(0), 0);
    assert.strictEqual(safe.safeBool(1), 1);
    assert.strictEqual(safe.safeBool(100), 1);
    assert.strictEqual(safe.safeBool(null), 0);
    assert.strictEqual(safe.safeBool(false), 0);
    assert.strictEqual(safe.safeBool(true), 1);
    assert.strictEqual(safe.safeBool({}), 0);
  });

  it('should copy', () => {
    const zero = Buffer.alloc(6, 0x00);
    const out = Buffer.alloc(6, 0x00);
    const foo = Buffer.from('foobar');

    safe.safeCopy(out, foo, 0);
    assert(out.equals(zero));

    safe.safeCopy(out, foo, 1);
    assert(out.equals(foo));
  });
});
