/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const hkdf = require('../lib/crypto/hkdf');

describe('HKDF', function() {
  it('should do proper hkdf (1)', () => {
    // https://tools.ietf.org/html/rfc5869
    const alg = 'sha256';
    const ikm = Buffer.from(
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex');
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
    const len = 42;

    const prkE = Buffer.from(
      '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
      'hex');

    const okmE = Buffer.from(''
      + '3cb25f25faacd57a90434f64d0362f2a2d2d0a90'
      + 'cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
      'hex');

    const prk = hkdf.extract(ikm, salt, alg);
    const okm = hkdf.expand(prk, info, len, alg);

    assert.bufferEqual(prk, prkE);
    assert.bufferEqual(okm, okmE);
  });

  it('should do proper hkdf (2)', () => {
    const alg = 'sha256';

    const ikm = Buffer.from(''
      + '000102030405060708090a0b0c0d0e0f'
      + '101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f'
      + '303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f',
      'hex');

    const salt = Buffer.from(''
      + '606162636465666768696a6b6c6d6e6f'
      + '707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f'
      + '909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      'hex');

    const info = Buffer.from(''
      + 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
      + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
      + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
      + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      'hex');

    const len = 82;

    const prkE = Buffer.from(''
      + '06a6b88c5853361a06104c9ceb35b45c'
      + 'ef760014904671014a193f40c15fc244',
      'hex');

    const okmE = Buffer.from(''
      + 'b11e398dc80327a1c8e7f78c596a4934'
      + '4f012eda2d4efad8a050cc4c19afa97c'
      + '59045a99cac7827271cb41c65e590e09'
      + 'da3275600c2f09b8367793a9aca3db71'
      + 'cc30c58179ec3e87c14c01d5c1f3434f'
      + '1d87',
      'hex');

    const prk = hkdf.extract(ikm, salt, alg);
    const okm = hkdf.expand(prk, info, len, alg);

    assert.bufferEqual(prk, prkE);
    assert.bufferEqual(okm, okmE);
  });
});
