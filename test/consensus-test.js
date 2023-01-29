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

  it('should calculate block reward properly', () => {
    let height = 0;
    const reward = consensus.getReward(height, 210000);
    assert.strictEqual(reward, 50 * consensus.COIN);
    height = 210000;
    const reward2 = consensus.getReward(height, 210000);
    assert.strictEqual(reward2, 25 * consensus.COIN);
  });

  it('should throw an error for invalid height', () => {
    assert.throws(() => {
    consensus.getReward(-100, 210000);
    }, /Bad height for reward./);
  });

  it('should return false for invalid proof-of-work', () => {
    const bits = 0x1900896c;
    const hash = Buffer.from(
    '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000001',
    'hex');
    assert.strictEqual(consensus.verifyPOW(hash, bits), false);
  });

  it('should return correct reward amount at given height and reward interval', () => {
    const height = 210000;
    const rewardInterval = 210000;
    const expectedReward = 25 * consensus.COIN;

    const reward = consensus.getReward(height, rewardInterval);

    assert.strictEqual(reward, expectedReward);
  });

  it('should correctly determine whether a given version number contains a specific bit', () => {
    const version = 0x20000001;
    const bit = 0;
    const expectedResult = true;

    const result = consensus.hasBit(version, bit);

    assert.strictEqual(result, expectedResult);
  });

  it('should correctly convert target to compact representation of target', () => {
    const target = new BN(
      '0000000000000000896c00000000000000000000000000000000000000000000',
      'hex');
    const expectedCompact = 0x1900896c;

    const compact = consensus.toCompact(target);

    assert.strictEqual(compact, expectedCompact);
  });

  it('should correctly verify proof of work', () => {
    const hash = Buffer.from(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );
    const bits = 0x1900896c;
    const expectedResult = true;

    const result = consensus.verifyPOW(hash, bits);

    assert.strictEqual(result, expectedResult);
  });

  it('should correctly return total reward for all blocks until the reward becomes zero', () => {
    let height = 0;
    let total = 0;

    for (;;) {
      const reward = consensus.getReward(height, 210000);
      total += reward;
      if (reward === 0)
        break;
      height++;
    }

    const expectedHeight = 6930000;
    const expectedTotal = 2099999997690000;

    assert.strictEqual(height, expectedHeight);
    assert.strictEqual(total, expectedTotal);
  });
});