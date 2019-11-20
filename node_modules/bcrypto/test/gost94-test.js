/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const GOST94 = require('../lib/gost94');

// https://en.wikipedia.org/wiki/GOST_(hash_function)#GOST_hash_test_vectors
const vectors_cryptopro = [
  [
    '',
    '981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0',
    'binary'
  ],
  [
    'a',
    'e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011',
    'binary'
  ],
  [
    'abc',
    'b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c',
    'binary'
  ],
  [
    'message digest',
    'bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0',
    'binary'
  ],
  [
    'The quick brown fox jumps over the lazy dog',
    '9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76',
    'binary'
  ],
  [
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    '73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61',
    'binary'
  ],
  [
    ''
      + '1234567890123456789012345678901234567890123456789012345678901234'
      + '5678901234567890',
    '6bc7b38989b28cf93ae8842bf9d752905910a7528a61e5bce0782de43e610c90',
    'binary'
  ],
  [
    'This is message, length=32 bytes',
    '2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb',
    'binary'
  ],
  [
    'Suppose the original message has length = 50 bytes',
    'c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011',
    'binary'
  ],
  [
    Array(128 + 1).join('U'),
    '1c4ac7614691bbf427fa2316216be8f10d92edfd37cd1027514c1008f649c4e8',
    'binary'
  ],
  [
    Array(1000000 + 1).join('a'),
    '8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f',
    'binary'
  ],
  [
    // https://tools.ietf.org/html/rfc5933#section-4.1
    ''
      + '076578616d706c65036e6574000101030c2cc817447cd26c82469fa8b5e'
      + '8afac0e36837ff935a3d0dbc5270e80462a612feb961d8c7fe051018dd0'
      + '1cf6f0a0f8767e40ca06ba05491191ed961cc7e60843',
    '22261a8b0e0d799183e35e24e2ad6bb58533cba7e3b14d659e9ca09b2071398f',
    'hex'
  ]
];

// https://en.wikipedia.org/wiki/GOST_(hash_function)#GOST_hash_test_vectors
const vectors_test = [
  [
    '',
    'ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d',
    'binary'
  ],
  [
    'a',
    'd42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd',
    'binary'
  ],
  [
    'message digest',
    'ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d',
    'binary'
  ],
  [
    Array(128 + 1).join('U'),
    '53a3a3ed25180cef0c1d85a074273e551c25660a87062a52d926a9e8fe5733a4',
    'binary'
  ],
  [
    Array(1000000 + 1).join('a'),
    '5c00ccc2734cdd3332d3d4749576e3c1a7dbaf0e7ea74e9fa602413c90a129fa',
    'binary'
  ]
];

function testHash(msg, expect, enc, box) {
  const m = Buffer.from(msg, enc);
  const e = Buffer.from(expect, 'hex');

  const hash = GOST94.digest(m, box);

  assert.bufferEqual(hash, e);

  const ctx = new GOST94();
  ctx.init(box);

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < m.length; i++) {
    ch[0] = m[i];
    ctx.update(ch);
  }

  assert.bufferEqual(ctx.final(), e);
}

describe('GOST94', function() {
  this.timeout(10000);

  for (const [msg, expect, enc] of vectors_cryptopro) {
    it(`should get GOST94 hash of ${expect}`, () => {
      testHash(msg, expect, enc, GOST94.CRYPTOPRO);
    });
  }

  for (const [msg, expect, enc] of vectors_test) {
    it(`should get GOST94 hash of ${expect}`, () => {
      testHash(msg, expect, enc, GOST94.TEST);
    });
  }
});
