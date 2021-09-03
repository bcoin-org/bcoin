// Copyright (c) 2018 the bcoin developers
//
// Parts of this software are based on "CashAddr".
// https://github.com/Bitcoin-ABC/bitcoin-abc
//
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
const base58 = require('../lib/encoding/base58');
const cash32 = require('../lib/encoding/cash32');
const rng = require('../lib/random');

const vectors = {
  translation: require('./data/cash32/translation.json'),
  size: require('./data/cash32/size.json'),
  encode: require('./data/cash32/encode.json'),
  decode: require('./data/cash32/decode.json'),
  edge: require('./data/cash32/edge.json')
};

function encodeManual(prefix, type, hash) {
  assert(typeof prefix === 'string');
  assert((type >>> 0) === type);
  assert(Buffer.isBuffer(hash));

  if (type > 15)
    throw new Error('Invalid cash32 type.');

  let size;

  switch (hash.length) {
    case 20:
      size = 0;
      break;
    case 24:
      size = 1;
      break;
    case 28:
      size = 2;
      break;
    case 32:
      size = 3;
      break;
    case 40:
      size = 4;
      break;
    case 48:
      size = 5;
      break;
    case 56:
      size = 6;
      break;
    case 64:
      size = 7;
      break;
    default:
      throw new Error('Non standard length.');
  }

  const data = Buffer.alloc(hash.length + 1);

  data[0] = (type << 3) | size;

  hash.copy(data, 1);

  const conv = cash32.convertBits(data, 8, 5, true);

  return cash32.serialize(prefix, conv);
}

function decodeManual(addr, expect = 'bitcoincash') {
  const [prefix, conv] = cash32.deserialize(addr, expect);

  if (prefix !== expect)
    throw new Error('Invalid cash32 prefix.');

  if (conv.length === 0 || conv.length > 104)
    throw new Error('Invalid cash32 data.');

  const data = cash32.convertBits(conv, 5, 8, false);

  if (data.length === 0 || data.length > 1 + 64)
    throw new Error('Invalid cash32 data.');

  const type = (data[0] >>> 3) & 0x1f;
  const hash = data.slice(1);

  let size = 20 + 4 * (data[0] & 0x03);

  if (data[0] & 0x04)
    size *= 2;

  if (type > 15)
    throw new Error('Invalid cash32 type.');

  if (size !== hash.length)
    throw new Error('Invalid cash32 data length.');

  return [type, hash];
}

describe('Cash32', function() {
  describe('Encoding', () => {
    for (const vector of vectors.size) {
      const text = vector.addr.slice(0, 32) + '...';

      it(`should encode address ${text} (${vector.bytes} bytes)`, () => {
        const addr = cash32.encode(vector.prefix, vector.type,
                                   Buffer.from(vector.hash, 'hex'));

        assert.strictEqual(addr, vector.addr);
      });

      it(`should decode address ${text} (${vector.bytes} bytes)`, () => {
        const [type, hash] = cash32.decode(vector.addr, vector.prefix);

        assert.strictEqual(cash32.test(vector.addr, vector.prefix), true);
        assert.strictEqual(cash32.is(vector.addr, vector.prefix), true);
        assert.strictEqual(type, vector.type);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });
    }
  });

  describe('Encoding (Manual)', () => {
    for (const vector of vectors.size) {
      const text = vector.addr.slice(0, 32) + '...';

      it(`should encode address ${text} (${vector.bytes} bytes)`, () => {
        const addr = encodeManual(vector.prefix, vector.type,
                                  Buffer.from(vector.hash, 'hex'));

        assert.strictEqual(addr, vector.addr);
      });

      it(`should decode address ${text} (${vector.bytes} bytes)`, () => {
        const [type, hash] = decodeManual(vector.addr, vector.prefix);

        assert.strictEqual(cash32.test(vector.addr, vector.prefix), true);
        assert.strictEqual(cash32.is(vector.addr, vector.prefix), true);
        assert.strictEqual(type, vector.type);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });
    }
  });

  describe('Translation', () => {
    for (const translation of vectors.translation.p2pkh) {
      const text = translation.legacy.slice(0, 32) + '...';

      it(`should translate base58 P2PKH for ${text}`, () => {
        const hash = base58.decode(translation.legacy).slice(1, -4);
        const addr = cash32.encode('bitcoincash', 0, hash);

        assert.strictEqual(addr, translation.address);
      });
    }

    for (const translation of vectors.translation.p2sh) {
      const text = translation.legacy.slice(0, 32) + '...';

      it(`should translate base58 P2SH for ${text}`, () => {
        const hash = base58.decode(translation.legacy).slice(1, -4);
        const addr = cash32.encode('bitcoincash', 1, hash);

        assert.strictEqual(addr, translation.address);
      });
    }

    for (const vector of vectors.translation.p2pkh) {
      const text = vector.address.slice(0, 32) + '...';

      it(`should decode P2PKH for ${text}`, () => {
        const [type, hash] = cash32.decode(vector.address);

        assert.strictEqual(type, 0);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });

      it(`should encode P2PKH for ${text}`, () => {
        const addr = cash32.encode('bitcoincash', 0,
                                   Buffer.from(vector.hash, 'hex'));

        assert.strictEqual(addr, vector.address);
      });
    }

    for (const vector of vectors.translation.p2sh) {
      const text = vector.address.slice(0, 32) + '...';

      it(`should decode P2SH for ${text}`, () => {
        const [type, hash] = cash32.decode(vector.address);

        assert.strictEqual(type, 1);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });

      it(`should encode P2SH for ${text}`, () => {
        const addr = cash32.encode('bitcoincash', 1,
                                   Buffer.from(vector.hash, 'hex'));

        assert.strictEqual(addr, vector.address);
      });
    }

    for (const vector of vectors.translation.p2pkh) {
      const text = vector.address.slice(0, 32) + '...';

      it(`should decode P2PKH with prefix ${text}`, () => {
        const addr = vector.address.split(':')[1];
        const [type, hash] = cash32.decode(addr, 'bitcoincash');

        assert.strictEqual(type, 0);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });

      it(`should decode P2PKH with default prefix ${text}`, () => {
        const addr = vector.address.split(':')[1];
        const [type, hash] = cash32.decode(addr);

        assert.strictEqual(type, 0);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });
    }

    for (const vector of vectors.translation.p2sh) {
      const text = vector.address.slice(0, 32) + '...';

      it(`should decode P2SH with prefix ${text}`, () => {
        const addr = vector.address.split(':')[1];
        const [type, hash] = cash32.decode(addr, 'bitcoincash');

        assert.strictEqual(type, 1);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });

      it(`should decode P2SH with default prefix ${text}`, () => {
        const addr = vector.address.split(':')[1];
        const [type, hash] = cash32.decode(addr);

        assert.strictEqual(type, 1);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });
    }
  });

  describe('Invalid Encoding', () => {
    for (const vector of vectors.encode) {
      it(`"${vector.reason}" (${vector.note})`, () => {
        assert.throws(() => {
          cash32.encode(vector.prefix, vector.type,
                        Buffer.from(vector.hash, 'hex'));
        });
      });
    }
  });

  describe('Invalid Decoding', () => {
    for (const vector of vectors.decode) {
      const text = vector.addr.slice(0, 32) + '...';

      it(`"${vector.reason}" w/ invalid address ${text}`, () => {
        assert.throws(() => cash32.decode(vector.addr, vector.prefix));
      });
    }
  });

  describe('Edge Cases', () => {
    for (const vector of vectors.edge) {
      const text = vector.addr.slice(0, 32) + '...';

      it(`encode ${vector.note} with address: ${text}`, () => {
        const addr = cash32.encode(vector.prefix.toLowerCase(), vector.type,
                                   Buffer.from(vector.hash, 'hex'));
        assert.strictEqual(addr, vector.addr.toLowerCase());
      });

      it(`decode ${vector.note} with address: ${text}`, () => {
        const [type, hash] = cash32.decode(
          vector.addr, vector.prefix.toLowerCase());

        assert.strictEqual(type, vector.type);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });

      it(`round trip ${vector.note} with address: ${text}`, () => {
        const addr = cash32.encode(vector.prefix.toLowerCase(), vector.type,
                                   Buffer.from(vector.hash, 'hex'));

        assert.strictEqual(addr, vector.addr.toLowerCase());

        const [type, hash] = cash32.decode(
          vector.addr, vector.prefix.toLowerCase());

        assert.strictEqual(type, vector.type);
        assert.bufferEqual(hash, Buffer.from(vector.hash, 'hex'));
      });
    }
  });

  describe('Random', () => {
    it('should encode/decode random data', () => {
      for (let i = 20; i <= 64; i++) {
        const data = rng.randomBytes(i);
        const data_ = cash32.convertBits(data, 8, 5, true);
        const str = cash32.serialize('prefix', data_);
        const [prefix, dec_] = cash32.deserialize(str, 'prefix');
        const dec = cash32.convertBits(dec_, 5, 8, false);

        assert(cash32.is(str, 'prefix'));

        assert.strictEqual(prefix, 'prefix');
        assert.bufferEqual(dec, data);
      }
    });

    it('should encode/decode random addresses', () => {
      for (const size of [20, 28, 32, 48, 64]) {
        const hash = rng.randomBytes(size);
        const type = rng.randomRange(0, 16);
        const addr = cash32.encode('bitcoincash', type, hash);
        const [type_, hash_] = cash32.decode(addr);

        assert.strictEqual(type_, type);
        assert.bufferEqual(hash_, hash);
      }
    });
  });
});
