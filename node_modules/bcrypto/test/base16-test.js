'use strict';

const assert = require('bsert');
const base16 = require('../lib/encoding/base16');
const rng = require('../lib/random');

// https://tools.ietf.org/html/rfc4648#section-10
const vectors = [
  ['', ''],
  ['f', '66'],
  ['fo', '666f'],
  ['foo', '666f6f'],
  ['foob', '666f6f62'],
  ['fooba', '666f6f6261'],
  ['foobar', '666f6f626172']
];

const vectorsLE = [
  ['', ''],
  ['f', '66'],
  ['fo', '6f66'],
  ['foo', '6f6f66'],
  ['foob', '626f6f66'],
  ['fooba', '61626f6f66'],
  ['foobar', '7261626f6f66']
];

const invalid = [
  '6',
  '6x',
  'x6',
  '66 ',
  ' 66',
  '666fxa'
];

describe('Base16', function() {
  for (const [str, hex] of vectors) {
    const data = Buffer.from(str, 'binary');

    it(`should encode and decode base16: ${hex}`, () => {
      assert.strictEqual(base16.test(hex), true);
      assert.strictEqual(base16.test(hex.toUpperCase()), true);
      assert.strictEqual(base16.encode(data), hex);
      assert.bufferEqual(base16.decode(hex), data);
      assert.bufferEqual(base16.decode(hex.toUpperCase()), data);
    });
  }

  for (const [str, hex] of vectorsLE) {
    const data = Buffer.from(str, 'binary');

    it(`should encode and decode base16 (LE): ${hex}`, () => {
      assert.strictEqual(base16.encodeLE(data), hex);
      assert.bufferEqual(base16.decodeLE(hex), data);
      assert.bufferEqual(base16.decodeLE(hex.toUpperCase()), data);
    });
  }

  for (const hex of invalid) {
    it(`should recognize invalid base16: ${hex}`, () => {
      assert.strictEqual(base16.test(hex), false);
      assert.strictEqual(base16.test(hex.toUpperCase()), false);
      assert.throws(() => base16.decode(hex));
      assert.throws(() => base16.decode(hex.toUpperCase()));
      assert.throws(() => base16.decodeLE(hex));
      assert.throws(() => base16.decodeLE(hex.toUpperCase()));
    });
  }

  it('should encode/decode random data', () => {
    for (let i = 0; i < 128; i++) {
      const data = rng.randomBytes(i);
      const str = base16.encode(data);
      const dec = base16.decode(str);

      assert(base16.test(str));

      assert.strictEqual(str, data.toString('hex'));
      assert.bufferEqual(dec, data);
    }
  });
});
