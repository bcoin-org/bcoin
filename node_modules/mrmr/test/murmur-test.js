/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const murmur3 = require('../lib/murmur3');

function testMurmur(str, seed, expect, enc) {
  if (!enc)
    enc = 'ascii';

  const data = Buffer.from(str, enc);
  const hash = murmur3.sum(data, seed);

  assert.strictEqual(hash, expect);
}

describe('mrmr', function() {
  this.timeout(20000);

  it('should do proper murmur3', () => {
    testMurmur('', 0, 0);
    testMurmur('', 0xfba4c795, 0x6a396f08);
    testMurmur('00', 0xfba4c795, 0x2a101837);
    testMurmur('hello world', 0, 0x5e928f0f);

    testMurmur('', 0x00000000, 0x00000000, 'hex');
    testMurmur('', 0xfba4c795, 0x6a396f08, 'hex');
    testMurmur('', 0xffffffff, 0x81f16f39, 'hex');

    testMurmur('00', 0x00000000, 0x514e28b7, 'hex');
    testMurmur('00', 0xfba4c795, 0xea3f0b17, 'hex');
    testMurmur('ff', 0x00000000, 0xfd6cf10d, 'hex');

    testMurmur('0011', 0x00000000, 0x16c6b7ab, 'hex');
    testMurmur('001122', 0x00000000, 0x8eb51c3d, 'hex');
    testMurmur('00112233', 0x00000000, 0xb4471bf8, 'hex');
    testMurmur('0011223344', 0x00000000, 0xe2301fa8, 'hex');
    testMurmur('001122334455', 0x00000000, 0xfc2e4a15, 'hex');
    testMurmur('00112233445566', 0x00000000, 0xb074502c, 'hex');
    testMurmur('0011223344556677', 0x00000000, 0x8034d2a0, 'hex');
    testMurmur('001122334455667788', 0x00000000, 0xb4698def, 'hex');
  });
});
