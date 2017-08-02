/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const hkdf = require('../lib/crypto/hkdf');

describe('HKDF', function() {
  it('should do proper hkdf', () => {
    // https://tools.ietf.org/html/rfc5869
    let alg = 'sha256';
    let ikm = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
    let salt = '000102030405060708090a0b0c';
    let info = 'f0f1f2f3f4f5f6f7f8f9';
    let len = 42;

    let prkE = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec8'
      + '44ad7c2b3e5';
    let okmE = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1'
      + 'a5a4c5db02d56ecc4c5bf34007208d5b887185865';

    ikm = Buffer.from(ikm, 'hex');
    salt = Buffer.from(salt, 'hex');
    info = Buffer.from(info, 'hex');

    let prk = hkdf.extract(ikm, salt, alg);
    let okm = hkdf.expand(prk, info, len, alg);

    assert.equal(prk.toString('hex'), prkE);
    assert.equal(okm.toString('hex'), okmE);

    alg = 'sha256';

    ikm = '000102030405060708090a0b0c0d0e0f'
      + '101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f'
      + '303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f';

    salt = '606162636465666768696a6b6c6d6e6f'
      + '707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f'
      + '909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';

    info = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
      + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
      + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
      + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';

    len = 82;

    prkE = '06a6b88c5853361a06104c9ceb35b45c'
      + 'ef760014904671014a193f40c15fc244';

    okmE = 'b11e398dc80327a1c8e7f78c596a4934'
      + '4f012eda2d4efad8a050cc4c19afa97c'
      + '59045a99cac7827271cb41c65e590e09'
      + 'da3275600c2f09b8367793a9aca3db71'
      + 'cc30c58179ec3e87c14c01d5c1f3434f'
      + '1d87';

    ikm = Buffer.from(ikm, 'hex');
    salt = Buffer.from(salt, 'hex');
    info = Buffer.from(info, 'hex');

    prk = hkdf.extract(ikm, salt, alg);
    okm = hkdf.expand(prk, info, len, alg);

    assert.equal(prk.toString('hex'), prkE);
    assert.equal(okm.toString('hex'), okmE);
  });
});
