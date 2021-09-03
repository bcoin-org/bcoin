// Parts of this software are based on "bech32".
// https://github.com/sipa/bech32
//
// Copyright (c) 2017 Pieter Wuille
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

'use strict';

const assert = require('bsert');
const bech32 = require('../lib/encoding/bech32');
const vectors = require('./data/bech32.json');
const random = require('../lib/random');

const validAddresses = [
  [
    'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
    '0014751e76e8199196d454941c45d1b3a323f1433bd6'
  ],
  [
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
    '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'
  ],
  [
    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
    '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'
  ],
  [
    'BC1SW50QA3JX3S',
    '6002751e'
  ],
  [
    'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
    '5210751e76e8199196d454941c45d1b3a323'
  ],
  [
    'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
    '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'
  ]
];

const invalidAddresses = [
  'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty',
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
  'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2',
  'bc1rw5uspcuh',
  'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
  'bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035',
  'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
  'tb1pw508d6qejxtdg4y5r3zarqfsj6c3',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv',
  'wtfbbqhelpnoshitwe2z5nuhllhu6z8pptu8m36clzge37dnfsdquht73wsx4cmwcwql322x3gmmwq2gjuxp6eaaus',
  'bcfbbqhelpnoshitwe2z7anje5j3wvz8hw3rxadzcppgghm0aec23ttfstphjegfx08hwk5uhmusa7j28yrk8cx4qj'
];

const invalidIs = [
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
  'bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
  'wtfbbqhelpnoshitwe2z5nuhllhu6z8pptu8m36clzge37dnfsdquht73wsx4cmwcwql322x3gmmwq2gjuxp6eaaus',
  'bcfbbqhelpnoshitwe2z7anje5j3wvz8hw3rxadzcppgghm0aec23ttfstphjegfx08hwk5uhmusa7j28yrk8cx4qj'
];

let invalidTest = [
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
  'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
  'bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
  'wtfbbqhelpnoshitwe2z5nuhllhu6z8pptu8m36clzge37dnfsdquht73wsx4cmwcwql322x3gmmwq2gjuxp6eaaus',
  'bcfbbqhelpnoshitwe2z7anje5j3wvz8hw3rxadzcppgghm0aec23ttfstphjegfx08hwk5uhmusa7j28yrk8cx4qj'
];

// valid bech32m strings
// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#test-vectors
invalidTest = invalidTest.concat([
  'A1LQFN3A',
  'a1lqfn3a',
  'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
  'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
  '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
  'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
  '?1v759aa'
]);

const validStrings = [
  [
    'A12UEL5L',
    'a',
    ''
  ],
  [
    'a12uel5l',
    'a',
    ''
  ],
  [
    'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
    'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio',
    ''
  ],
  [
    'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
    'abcdef',
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
  ],
  [
    '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
    '1',
    ['000000000000000000000000000000000000000000000000000000000000000000',
     '000000000000000000000000000000000000000000000000000000000000000000',
     '00000000000000000000000000000000'].join('')
  ],
  [
    'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
    'split',
    '18171918161c01100b1d0819171d130d10171d16191c01100b03191d1b1903031d130b190303190d181d01190303190d'
  ],
  [
    '?1ezyfcl',
    '?',
    ''
  ]
];

const invalidStrings = [
  'a12uel5l\x00foobar',
  '\x201nwldj5',
  '\x7f1axkwrx',
  '\x801eym55h',
  'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx',
  'pzry9x0s0muk',
  '1pzry9x0s0muk',
  'x1b4n0q5v',
  'li1dgmt3',
  'de1lg7wt\xff',
  'A1G7SGD8',
  '10a06t8',
  '1qzzfhee'
];

function encode(hrp, version, hash) {
  const addr = bech32.encode(hrp, version, hash);

  decode(hrp, addr);

  return addr;
}

function decode(expect, addr) {
  const [hrp, version, hash] = bech32.decode(addr);

  if (hrp !== expect)
    throw new Error('Invalid bech32 prefix or data length.');

  if (version === 0 && hash.length !== 20 && hash.length !== 32)
    throw new Error('Malformed witness program.');

  if (version > 16)
    throw new Error('Malformed witness program.');

  return [hrp, version, hash];
}

function encodeManual(hrp, version, hash, lax) {
  const data = bech32.convertBits(hash, 8, 5, true);
  const addr = bech32.serialize(hrp, concat(version, data));

  decodeManual(hrp, addr, lax);

  return addr;
}

function decodeManual(expect, addr, lax = false) {
  const [hrp, data] = bech32.deserialize(addr);

  if (!lax) {
    if (hrp !== expect || data.length < 1 || data[0] > 16)
      throw new Error('Invalid bech32 prefix or data length.');
  }

  const hash = bech32.convertBits(data.slice(1), 5, 8, false);

  if (!lax) {
    if (hash.length < 2 || hash.length > 40)
      throw new Error('Invalid witness program size.');

    if (data[0] === 0 && hash.length !== 20 && hash.length !== 32)
      throw new Error('Malformed witness program.');
  }

  return [hrp, data[0], hash];
}

function program(version, hash) {
  const data = Buffer.alloc(2 + hash.length);
  // Bitcoin PUSH opcodes > 0 start at 0x50
  data[0] = version ? version + 0x50 : 0;
  data[1] = hash.length;
  hash.copy(data, 2);
  return data;
}

function concat(version, hash) {
  const buf = Buffer.alloc(1 + hash.length);
  buf[0] = version;
  hash.copy(buf, 1);
  return buf;
}

describe('Bech32', function() {
  for (const [addr, script_] of validAddresses) {
    const script = Buffer.from(script_, 'hex');
    const text = addr.slice(0, 32) + '...';

    it(`should have valid address for ${text}`, () => {
      let expect = 'bc';
      let hrp, version, hash;

      try {
        [hrp, version, hash] = decode(expect, addr);
      } catch (e) {
        hrp = null;
      }

      if (hrp === null) {
        expect = 'tb';
        try {
          [hrp, version, hash] = decode(expect, addr);
        } catch (e) {
          hrp = null;
        }
      }

      assert(hrp !== null);
      assert.bufferEqual(program(version, hash), script);
      assert.strictEqual(encode(hrp, version, hash), addr.toLowerCase());
      assert.strictEqual(bech32.test(addr), true);
    });
  }

  for (const addr of invalidAddresses) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => decode('bc', addr));
      assert.throws(() => decode('tb', addr));
    });
  }

  for (const [addr, script_] of validAddresses) {
    const script = Buffer.from(script_, 'hex');
    const text = addr.slice(0, 32) + '...';

    it(`should have valid address for ${text}`, () => {
      let expect = 'bc';
      let hrp, version, hash;

      try {
        [hrp, version, hash] = decodeManual(expect, addr);
      } catch (e) {
        hrp = null;
      }

      if (hrp === null) {
        expect = 'tb';
        try {
          [hrp, version, hash] = decodeManual(expect, addr);
        } catch (e) {
          hrp = null;
        }
      }

      assert(hrp !== null);
      assert.bufferEqual(program(version, hash), script);
      assert.strictEqual(encodeManual(hrp, version, hash), addr.toLowerCase());
      assert.strictEqual(bech32.test(addr), true);
      assert.strictEqual(bech32.is(addr), true);
    });
  }

  for (const addr of invalidAddresses) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => decodeManual('bc', addr));
      assert.throws(() => decodeManual('tb', addr));
    });
  }

  for (const addr of invalidIs) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => bech32.deserialize(addr));
      assert.strictEqual(bech32.is(addr), false);
    });
  }

  for (const addr of invalidTest) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => bech32.decode(addr));
      assert.strictEqual(bech32.test(addr), false);
    });
  }

  for (const [hrp, version, hex, addr1] of vectors) {
    const text = addr1.slice(0, 32) + '...';
    const hash = Buffer.from(hex, 'hex');

    it(`should decode and reserialize ${text}`, () => {
      const [hrp_, version_, hash_] = bech32.decode(addr1);

      assert.strictEqual(hrp_, hrp);
      assert.strictEqual(version_, version);
      assert.bufferEqual(hash_, hash);

      const addr2 = bech32.encode(hrp, version, hash);

      assert.strictEqual(addr2, addr1.toLowerCase());
    });

    it(`should decode and reserialize ${text}`, () => {
      const [hrp_, version_, hash_] = decodeManual(hrp, addr1, true);

      assert.strictEqual(hrp_, hrp);
      assert.strictEqual(version_, version);
      assert.bufferEqual(hash_, hash);

      const addr2 = encodeManual(hrp, version, hash, true);

      assert.strictEqual(addr2, addr1.toLowerCase());
    });
  }

  for (const [str, hrp_, data_] of validStrings) {
    const text = str.slice(0, 32) + '...';

    it(`should have valid string for ${text}`, () => {
      const [hrp, data] = bech32.deserialize(str);

      assert(bech32.is(str));

      assert.strictEqual(hrp, hrp_);
      assert.bufferEqual(data, data_, 'hex');
    });
  }

  for (const str of invalidStrings) {
    const text = str.slice(0, 32).replace(/[^\w]/g, '') + '...';

    it(`should have invalid string for ${text}`, () => {
      assert(!bech32.is(str));
      assert.throws(() => bech32.deserialize(str));
    });
  }

  it('should encode/decode random data', () => {
    for (let i = 20; i <= 50; i++) {
      const data = random.randomBytes(i);
      const data_ = bech32.convertBits(data, 8, 5, true);
      const str = bech32.serialize('bc', data_);
      const [, dec_] = bech32.deserialize(str);
      const dec = bech32.convertBits(dec_, 5, 8, false);

      assert(bech32.is(str));

      assert.bufferEqual(dec, data);
    }
  });
});
