/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const consensus = require('../lib/protocol/consensus');
const BN = require('bcrypto/lib/bn.js');

describe('Consensus', function() {
  it('should calculate reward properly', () => {
    let height = 0;
    let total = 0;

    for (;;) {
      const reward = consensus.getReward(height, 210000);
      assert(reward <= consensus.COIN * 50);
      total += reward;
      if (reward === 0)
        break;
      height++;
    }

    assert.strictEqual(height, 6930000);
    assert.strictEqual(total, 2099999997690000);
  });

  it('should verify proof-of-work', () => {
    const bits = 0x1900896c;

    const hash = Buffer.from(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );

    assert(consensus.verifyPOW(hash, bits));
  });

  it('should not verify proof-of-work if bits is negative', () => {
    const bits = 0x1d00ffff * -1;

    const hash = Buffer.from(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );

    assert(!consensus.verifyPOW(hash, bits));
  });

  it('should not verify proof-of-work if bits is zero', () => {
    const bits = 0;

    const hash = Buffer.from(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );

    assert(!consensus.verifyPOW(hash, bits));
  });

  it('should not verify proof-of-work if bits is too high', () => {
    const bits = 0x1d00ffff * 2;

    const hash = Buffer.from(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );

    assert(!consensus.verifyPOW(hash, bits));
  });

  it('should convert bits to target', () => {
    const bits = 0x1900896c;
    const target = consensus.fromCompact(bits);
    const expected = new BN(
      '0000000000000000896c00000000000000000000000000000000000000000000',
      'hex');

    assert.strictEqual(target.toString('hex'), expected.toString('hex'));
  });

  it('should convert target to bits', () => {
    const target = new BN(
      '0000000000000000896c00000000000000000000000000000000000000000000',
      'hex');

    const bits = consensus.toCompact(target);
    const expected = 0x1900896c;

    assert.strictEqual(bits, expected);
  });

  it('should check version bit', () => {
    assert(consensus.hasBit(0x20000001, 0));
    assert(!consensus.hasBit(0x20000000, 0));
    assert(!consensus.hasBit(0x10000001, 0));
    assert(consensus.hasBit(0x20000003, 1));
    assert(consensus.hasBit(0x20000003, 0));
  });

  it('should return BN(0) from fromCompact when called with a zero', () => {
    const target = consensus.fromCompact(0);
    const bnZero = new BN(0);

    // assert that the return object is correct by type and value
    assert.strictEqual(target.constructor.name, bnZero.constructor.name);
    assert.strictEqual(target.toString(), bnZero.toString());
  });

  it('should return BN(0) from fromCompact when the passed in value right shifted 24 is less than three', () => {
    const target = consensus.fromCompact(0x01000000);
    const expected = new BN(0x00000000);

    assert.strictEqual(target.toString(), expected.toString());
  });

  it('should return the correct value from fromCompact when called with 0x0fffffff', () => {
    const target = consensus.fromCompact(0x0fffffff);
    const expected = new BN(-664613918664295422187565936596221952n);

    assert.strictEqual(target.toString(), expected.toString());
  });

  it('should return 0 from toCompact when called with BN(0)', () => {
    const target = new BN(0);
    const bits = consensus.toCompact(target);
    const expected = 0;

    assert.strictEqual(bits, expected);
  });

  it('should return 16842752 when the byteLength of the passed in value is less than three', () => {
    const target = new BN(0x00000001);
    const bits = consensus.toCompact(target);
    const expected = 16842752;

    assert.strictEqual(bits, expected);
  });

  it('should return correct value from toCompact when the param is negative and its byteLength is less than three', () => {
    const target = new BN(-10000n);
    const bits = consensus.toCompact(target);
    const expected = 4294957296;

    assert.strictEqual(bits, expected);
  });
});
