'use strict';

const assert = require('bsert');
const KMAC = require('../lib/kmac');
const KMAC128 = require('../lib/kmac128');
const KMAC256 = require('../lib/kmac256');

// https://github.com/XKCP/XKCP/blob/8f447eb/tests/UnitTests/testSP800-185.c
const vectors = [
  {
    bits: 128,
    len: 32,
    K: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    S: '',
    X: '00010203',
    O: 'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e'
  },
  {
    bits: 128,
    len: 32,
    K: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    S: '4d7920546167676564204170706c69636174696f6e',
    X: '00010203',
    O: '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5'
  },
  {
    bits: 128,
    len: 32,
    K: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    S: '4d7920546167676564204170706c69636174696f6e',
    X: ''
      + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
      + '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7',
    O: '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230'
  },
  {
    bits: 256,
    len: 64,
    K: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    S: '',
    X: ''
      + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
      + '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7',
    O: ''
      + '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691'
      + '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69'
  },
  {
    bits: 256,
    len: 64,
    K: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
    S: '4d7920546167676564204170706c69636174696f6e',
    X: '00010203',
    O: ''
      + '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7'
      + 'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd'
  }
];

describe('KMAC', function() {
  for (const vector of vectors) {
    const bits = vector.bits;
    const len = vector.len;
    const K = Buffer.from(vector.K, 'hex');
    const S = Buffer.from(vector.S, 'hex');
    const X = Buffer.from(vector.X, 'hex');
    const O = Buffer.from(vector.O, 'hex');
    const text = vector.O.slice(0, 32) + '...';

    it(`should compute KMAC of ${text}`, () => {
      const ctx = new KMAC();

      ctx.init(bits, K, S);
      ctx.update(X);

      const mac = ctx.final(len);

      assert.bufferEqual(mac, O);
      assert.bufferEqual(KMAC.digest(X, bits, K, S, len), O);
    });

    it(`should compute KMAC of ${text}`, () => {
      const KMAC = bits === 128 ? KMAC128 : KMAC256;
      const ctx = new KMAC();

      ctx.init(K, S);
      ctx.update(X);

      const mac = ctx.final(len);

      assert.bufferEqual(mac, O);
      assert.bufferEqual(KMAC.digest(X, K, S, len), O);
    });
  }
});
