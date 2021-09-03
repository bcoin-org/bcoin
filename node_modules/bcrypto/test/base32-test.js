'use strict';

const assert = require('bsert');
const base32 = require('../lib/encoding/base32');
const rng = require('../lib/random');

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
      assert.strictEqual(base32.encode(data, true), b32);
      assert.strictEqual(base32.encode(data, false), b32.replace(/=+$/, ''));
      assert.bufferEqual(base32.decode(b32, true), data);
      assert.bufferEqual(base32.decode(b32.replace(/=+$/, ''), false), data);
      assert.strictEqual(base32.test(b32, true), true);
      assert.strictEqual(base32.test(b32.replace(/=+$/, ''), false), true);
    });
  }

  for (const [str, b32] of vectorsHex) {
    const data = Buffer.from(str, 'binary');

    it(`should encode and decode base32: ${str}: ${b32}`, () => {
      assert.strictEqual(base32.encodeHex(data, true), b32);
      assert.strictEqual(base32.encodeHex(data, false), b32.replace(/=+$/, ''));
      assert.bufferEqual(base32.decodeHex(b32, true), data);
      assert.bufferEqual(base32.decodeHex(b32.replace(/=+$/, ''), false), data);
      assert.strictEqual(base32.testHex(b32, true), true);
      assert.strictEqual(base32.testHex(b32.replace(/=+$/, ''), false), true);
    });
  }

  it('should encode/decode random data', () => {
    for (let i = 0; i < 128; i++) {
      const data = rng.randomBytes(i);
      const str1 = base32.encode(data, false);
      const dec1 = base32.decode(str1, false);
      const str2 = base32.encode(data, true);
      const dec2 = base32.decode(str2, true);

      assert(base32.test(str1, false));
      assert(base32.test(str2, true));

      assert.bufferEqual(dec1, data);
      assert.bufferEqual(dec2, data);
    }
  });
});
