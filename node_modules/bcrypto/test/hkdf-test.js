'use strict';

const assert = require('bsert');
const hkdf = require('../lib/hkdf');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');

const vectors = [
  // https://tools.ietf.org/html/rfc5869
  {
    hash: SHA256,
    ikm: Buffer.from(
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
    salt: Buffer.from('000102030405060708090a0b0c', 'hex'),
    info: Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'),
    len: 42,
    prk: Buffer.from(
      '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
      'hex'),
    okm: Buffer.from(''
      + '3cb25f25faacd57a90434f64d0362f2a2d2d0a90'
      + 'cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
      'hex')
  },
  {
    hash: SHA256,
    ikm: Buffer.from(''
      + '000102030405060708090a0b0c0d0e0f'
      + '101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f'
      + '303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f',
      'hex'),
    salt: Buffer.from(''
      + '606162636465666768696a6b6c6d6e6f'
      + '707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f'
      + '909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      'hex'),
    info: Buffer.from(''
      + 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
      + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
      + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
      + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      'hex'),
    len: 82,
    prk: Buffer.from(''
      + '06a6b88c5853361a06104c9ceb35b45c'
      + 'ef760014904671014a193f40c15fc244',
      'hex'),
    okm: Buffer.from(''
      + 'b11e398dc80327a1c8e7f78c596a4934'
      + '4f012eda2d4efad8a050cc4c19afa97c'
      + '59045a99cac7827271cb41c65e590e09'
      + 'da3275600c2f09b8367793a9aca3db71'
      + 'cc30c58179ec3e87c14c01d5c1f3434f'
      + '1d87',
      'hex')
  },
  {
    hash: SHA256,
    ikm: Buffer.from(
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
    salt: Buffer.alloc(0),
    info: null,
    len: 42,
    prk: Buffer.from(
      '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
      'hex'),
    okm: Buffer.from(''
      + '8da4e775a563c18f715f802a063c5a31'
      + 'b8a11f5c5ee1879ec3454e5f3c738d2d'
      + '9d201395faa4b61a96c8',
      'hex')
  },
  {
    hash: SHA1,
    ikm: Buffer.from(
      '0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
    salt: Buffer.from('000102030405060708090a0b0c', 'hex'),
    info: Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'),
    len: 42,
    prk: Buffer.from(
      '9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243',
      'hex'),
    okm: Buffer.from(''
      + '085a01ea1b10f36933068b56efa5ad81'
      + 'a4f14b822f5b091568a9cdd4f155fda2'
      + 'c22e422478d305f3f896',
      'hex')
  },
  {
    hash: SHA1,
    ikm: Buffer.from(''
      + '000102030405060708090a0b0c0d0e0f'
      + '101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f'
      + '303132333435363738393a3b3c3d3e3f'
      + '404142434445464748494a4b4c4d4e4f',
      'hex'),
    salt: Buffer.from(''
      + '606162636465666768696a6b6c6d6e6f'
      + '707172737475767778797a7b7c7d7e7f'
      + '808182838485868788898a8b8c8d8e8f'
      + '909192939495969798999a9b9c9d9e9f'
      + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      'hex'),
    info: Buffer.from(''
      + 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
      + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
      + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
      + 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
      + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      'hex'),
    len: 82,
    prk: Buffer.from(
      '8adae09a2a307059478d309b26c4115a224cfaf6',
      'hex'),
    okm: Buffer.from(''
      + '0bd770a74d1160f7c9f12cd5912a06eb'
      + 'ff6adcae899d92191fe4305673ba2ffe'
      + '8fa3f1a4e5ad79f3f334b3b202b2173c'
      + '486ea37ce3d397ed034c7f9dfeb15c5e'
      + '927336d0441f4c4300e2cff0d0900b52'
      + 'd3b4',
      'hex')
  },
  {
    hash: SHA1,
    ikm: Buffer.from(
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
    salt: Buffer.alloc(0),
    info: null,
    len: 42,
    prk: Buffer.from(
      'da8c8a73c7fa77288ec6f5e7c297786aa0d32d01',
      'hex'),
    okm: Buffer.from(''
      + '0ac1af7002b3d761d1e55298da9d0506'
      + 'b9ae52057220a306e07b6b87e8df21d0'
      + 'ea00033de03984d34918',
      'hex')
  },
  {
    hash: SHA1,
    ikm: Buffer.from(
      '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 'hex'),
    salt: null, // Defaults to HashLen zero bytes.
    info: null,
    len: 42,
    prk: Buffer.from(
      '2adccada18779e7c2077ad2eb19d3f3e731385dd',
      'hex'),
    okm: Buffer.from(''
      + '2c91117204d745f3500d636a62f64f0a'
      + 'b3bae548aa53d423b0d1f27ebba6f5e5'
      + '673a081d70cce7acfc48',
      'hex')
  }
];

describe('HKDF', function() {
  for (const [i, vector] of vectors.entries()) {
    const {hash, ikm, salt, info, len, prk, okm} = vector;

    it(`should do hkdf (${i + 1})`, () => {
      const prk1 = hkdf.extract(hash, ikm, salt);
      const okm1 = hkdf.expand(hash, prk1, info, len);

      assert.bufferEqual(prk1, prk);
      assert.bufferEqual(okm1, okm);
    });

    it(`should do one-shot hkdf (${i + 1})`, () => {
      const okm1 = hkdf.derive(hash, ikm, salt, info, len);

      assert.bufferEqual(okm1, okm);
    });
  }
});
