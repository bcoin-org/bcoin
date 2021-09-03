'use strict';

const assert = require('bsert');
const Salsa20 = require('../lib/salsa20');

// Salsa20 Vectors
// See: https://github.com/golang/crypto/blob/master/salsa20/salsa20_test.go
// See: http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?logsort=rev&rev=210&view=markup
const vectors = [
  [
    Buffer.from('0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba0d', 'hex'),
    Buffer.from('0d74db42a91077de', 'hex'),
    131072,
    Buffer.from('c349b6a51a3ec9b712eaed3f90d8bcee69b7628645f251a996f55260c62ef31f'
              + 'd6c6b0aea94e136c9d984ad2df3578f78e457527b03a0450580dd874f63b1ab9', 'hex')
  ],
  [
    Buffer.from('0558abfe51a4f74a9df04396e93c8fe23588db2e81d4277acd2073c6196cbf12', 'hex'),
    Buffer.from('167de44bb21980e7', 'hex'),
    131072,
    Buffer.from('c3eaaf32836bace32d04e1124231ef47e101367d6305413a0eeb07c60698a287'
              + '6e4d031870a739d6ffddd208597aff0a47ac17edb0167dd67eba84f1883d4dfd', 'hex')
  ],
  [
    Buffer.from('0a5db00356a9fc4fa2f5489bee4194e73a8de03386d92c7fd22578cb1e71c417', 'hex'),
    Buffer.from('1f86ed54bb2289f0', 'hex'),
    131072,
    Buffer.from('3cd23c3dc90201acc0cf49b440b6c417f0dc8d8410a716d5314c059e14b1a8d9'
              + 'a9fb8ea3d9c8dae12b21402f674aa95c67b1fc514e994c9d3f3a6e41dff5bba6', 'hex')
  ],
  [
    Buffer.from('0f62b5085bae0154a7fa4da0f34699ec3f92e5388bde3184d72a7dd02376c91c', 'hex'),
    Buffer.from('288ff65dc42b92f9', 'hex'),
    131072,
    Buffer.from('e00ebccd70d69152725f9987982178a2e2e139c7bcbe04ca8a0e99e318d9ab76'
              + 'f988c8549f75add790ba4f81c176da653c1a043f11a958e169b6d2319f4eec1a', 'hex')
  ]
];

// XSalsa20 Vectors
// See: https://github.com/golang/crypto/blob/master/salsa20/salsa20_test.go
const xvectors = [
  [
    Buffer.from('Hello world!'),
    Buffer.from('24-byte nonce for xsalsa'),
    Buffer.from('this is 32-byte key for xsalsa20'),
    Buffer.from([0x00, 0x2d, 0x45, 0x13, 0x84, 0x3f, 0xc2, 0x40, 0xc4, 0x01, 0xe5, 0x41])
  ],
  [
    Buffer.alloc(64, 0x00),
    Buffer.from('24-byte nonce for xsalsa'),
    Buffer.from('this is 32-byte key for xsalsa20'),
    Buffer.from([0x48, 0x48, 0x29, 0x7f, 0xeb, 0x1f, 0xb5, 0x2f, 0xb6,
                 0x6d, 0x81, 0x60, 0x9b, 0xd5, 0x47, 0xfa, 0xbc, 0xbe, 0x70,
                 0x26, 0xed, 0xc8, 0xb5, 0xe5, 0xe4, 0x49, 0xd0, 0x88, 0xbf,
                 0xa6, 0x9c, 0x08, 0x8f, 0x5d, 0x8d, 0xa1, 0xd7, 0x91, 0x26,
                 0x7c, 0x2c, 0x19, 0x5a, 0x7f, 0x8c, 0xae, 0x9c, 0x4b, 0x40,
                 0x50, 0xd0, 0x8c, 0xe6, 0xd3, 0xa1, 0x51, 0xec, 0x26, 0x5f,
                 0x3a, 0x58, 0xe4, 0x76, 0x48])
  ]
];

describe('Salsa20', function() {
  for (const [key, iv, size, expect] of vectors) {
    it(`should encrypt with ${key.toString('hex')} (salsa20)`, () => {
      const out = Buffer.alloc(size, 0x00);
      const xor = Buffer.alloc(64, 0x00);
      const salsa = new Salsa20();

      salsa.init(key, iv);
      salsa.encrypt(out);

      for (let i = 0; i < out.length; i += 64) {
        for (let j = 0; j < 64; j++)
          xor[j] ^= out[i + j];
      }

      assert.bufferEqual(xor, expect);

      salsa.destroy();
    });
  }

  for (const [input, iv, key, out] of xvectors) {
    it(`should encrypt with ${key.toString('hex')} (xsalsa20)`, () => {
      const data = Buffer.from(input);
      const salsa = new Salsa20();

      salsa.init(key, iv);
      salsa.encrypt(data);

      assert.bufferEqual(data, out);
    });
  }
});
