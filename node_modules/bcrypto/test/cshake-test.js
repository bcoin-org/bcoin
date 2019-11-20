/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const CSHAKE = require('../lib/cshake');
const CSHAKE128 = require('../lib/cshake128');
const CSHAKE256 = require('../lib/cshake256');

// https://github.com/XKCP/XKCP/blob/8f447eb/tests/UnitTests/testSP800-185.c
const vectors = [
  {
    bits: 128,
    len: 32,
    N: '',
    X: '00010203',
    S: '456d61696c205369676e6174757265',
    O: 'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5'
  },
  {
    bits: 128,
    len: 32,
    N: '',
    X: ''
      + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
      + '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7',
    S: '456d61696c205369676e6174757265',
    O: 'c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b'
  },
  {
    bits: 256,
    len: 64,
    N: '',
    X: '00010203',
    S: '456d61696c205369676e6174757265',
    O: ''
      + 'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1'
      + '64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c'
  },
  {
    bits: 256,
    len: 64,
    N: '',
    X: ''
      + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
      + '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7',
    S: '456d61696c205369676e6174757265',
    O: ''
      + '07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917'
      + '27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb'
  }
];

describe('CSHAKE', function() {
  for (const vector of vectors) {
    const bits = vector.bits;
    const len = vector.len;
    const N = Buffer.from(vector.N, 'hex');
    const S = Buffer.from(vector.S, 'hex');
    const X = Buffer.from(vector.X, 'hex');
    const O = Buffer.from(vector.O, 'hex');

    it(`should compute cSHAKE of ${vector.O}`, () => {
      const ctx = new CSHAKE();

      ctx.init(bits, N, S);
      ctx.update(X);

      const h = ctx.final(len);

      assert.bufferEqual(h, O);
      assert.bufferEqual(CSHAKE.digest(X, bits, N, S, len), O);
    });

    it(`should compute cSHAKE of ${vector.O}`, () => {
      const CSHAKE = bits === 128 ? CSHAKE128 : CSHAKE256;
      const ctx = new CSHAKE();

      ctx.init(N, S);
      ctx.update(X);

      const h = ctx.final(len);

      assert.bufferEqual(h, O);
      assert.bufferEqual(CSHAKE.digest(X, N, S, len), O);
    });
  }
});
