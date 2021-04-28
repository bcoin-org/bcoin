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
});
