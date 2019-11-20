/* eslint-env mocha */
/* eslint prefer-arrow-callback: 'off' */

'use strict';

const assert = require('bsert');
const bs32 = require('../');

// https://tools.ietf.org/html/rfc4648#section-10
const vectors = [
  ['', ''],
  ['f', 'my======'],
  ['fo', 'mzxq===='],
  ['foo', 'mzxw6==='],
  ['foob', 'mzxw6yq='],
  ['fooba', 'mzxw6ytb'],
  ['foobar', 'mzxw6ytboi======']
];

const vectorsHex = [
  ['', ''],
  ['f', 'co======'],
  ['fo', 'cpng===='],
  ['foo', 'cpnmu==='],
  ['foob', 'cpnmuog='],
  ['fooba', 'cpnmuoj1'],
  ['foobar', 'cpnmuoj1e8======']
];

describe('Base32', function() {
  for (const [str, b32] of vectors) {
    const data = Buffer.from(str, 'binary');

    it(`should encode and decode base32: ${str}: ${b32}`, () => {
      assert.strictEqual(bs32.encode(data, true), b32);
      assert.strictEqual(bs32.encode(data, false), b32.replace(/=+$/, ''));
      assert.bufferEqual(bs32.decode(b32, true), data);
      assert.bufferEqual(bs32.decode(b32.replace(/=+$/, ''), false), data);
      assert.strictEqual(bs32.test(b32, true), true);
      assert.strictEqual(bs32.test(b32.replace(/=+$/, ''), false), true);
    });
  }

  for (const [str, b32] of vectorsHex) {
    const data = Buffer.from(str, 'binary');

    it(`should encode and decode base32: ${str}: ${b32}`, () => {
      assert.strictEqual(bs32.encodeHex(data, true), b32);
      assert.strictEqual(bs32.encodeHex(data, false), b32.replace(/=+$/, ''));
      assert.bufferEqual(bs32.decodeHex(b32, true), data);
      assert.bufferEqual(bs32.decodeHex(b32.replace(/=+$/, ''), false), data);
      assert.strictEqual(bs32.testHex(b32, true), true);
      assert.strictEqual(bs32.testHex(b32.replace(/=+$/, ''), false), true);
    });
  }
});
