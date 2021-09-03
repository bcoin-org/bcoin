'use strict';

const assert = require('bsert');
const base58 = require('../lib/encoding/base58');
const json = require('./data/base58.json');

const vectors = [
  ['', ''],
  ['61', '2g'],
  ['626262', 'a3gV'],
  ['636363', 'aPEr'],
  [
    '73696d706c792061206c6f6e6720737472696e67',
    '2cFupjhnEsSn59qHXstmK2ffpLv2'
  ],
  [
    '00eb15231dfceb60925886b67d065299925915aeb172c06647',
    '1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L'
  ],
  ['516b6fcd0f', 'ABnLTmg'],
  ['bf4f89001e670274dd', '3SEo3LWLoPntC'],
  ['572e4794', '3EFU7m'],
  ['ecac89cad93923c02321', 'EJDM8drfXA6uyA'],
  ['10c8511e', 'Rt5zm'],
  ['00000000000000000000', '1111111111'],
  ['000000deadbeef', '1116h8cQN'],
  ...json
];

describe('Base58', function() {
  for (const [hex, b58] of vectors) {
    const text = b58.slice(0, 32) + '...';
    const data = Buffer.from(hex, 'hex');

    it(`should encode/decode base58: ${text}`, () => {
      assert.strictEqual(base58.test(b58), true);
      assert.strictEqual(base58.encode(data), b58);
      assert.bufferEqual(base58.decode(b58), data);
    });
  }
});
