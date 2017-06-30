'use strict';

const assert = require('assert');
const siphash = require('../lib/crypto/siphash');
const siphash256 = siphash.siphash256;

describe('SipHash', function() {
  it('should perform siphash with no data', () => {
    let data = Buffer.alloc(0);
    let key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepEqual(siphash256(data, key), [1919933255, -586281423]);
  });

  it('should perform siphash with data', () => {
    let data = Buffer.from('0001020304050607', 'hex');
    let key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepEqual(siphash256(data, key), [-1812597383, -1701632926]);
  });

  it('should perform siphash with uint256', () => {
    let data = Buffer.from(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      'hex');
    let key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepEqual(siphash256(data, key), [1898402095, 1928494286]);
  });
});
