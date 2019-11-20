/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const {Cipher, Decipher} = require('../lib/cipher');
const random = require('../lib/random');

const parts = process.version.split(/[^\d]/);
const major = parts[1] >>> 0;
const minor = parts[2] >>> 0;
const NODE_ELEVEN = major >= 11 && minor >= 12;

const algs = [
  {
    name: 'AES-128',
    keyLen: 16,
    ivLen: 16,
    ids: [
      'AES-128-ECB',
      'AES-128-CBC',
      'AES-128-CTR',
      'AES-128-CFB',
      'AES-128-OFB',
      NODE_ELEVEN && 'AES-128-GCM'
    ]
  },
  {
    name: 'AES-192',
    keyLen: 24,
    ivLen: 16,
    ids: [
      'AES-192-ECB',
      'AES-192-CBC',
      'AES-192-CTR',
      'AES-192-CFB',
      'AES-192-OFB',
      NODE_ELEVEN && 'AES-192-GCM'
    ]
  },
  {
    name: 'AES-256',
    keyLen: 32,
    ivLen: 16,
    ids: [
      'AES-256-ECB',
      'AES-256-CBC',
      'AES-256-CTR',
      'AES-256-CFB',
      'AES-256-OFB',
      NODE_ELEVEN && 'AES-256-GCM'
    ]
  },
  {
    name: 'Blowfish',
    keyLen: 32,
    ivLen: 8,
    ids: [
      'BF-ECB',
      'BF-CBC',
      'BF-CFB',
      'BF-OFB'
    ]
  },
  {
    name: 'CAMELLIA-128',
    keyLen: 16,
    ivLen: 16,
    ids: [
      'CAMELLIA-128-ECB',
      'CAMELLIA-128-CBC',
      NODE_ELEVEN && 'CAMELLIA-128-CTR',
      NODE_ELEVEN && 'CAMELLIA-128-CFB',
      NODE_ELEVEN && 'CAMELLIA-128-OFB'
    ]
  },
  {
    name: 'CAMELLIA-192',
    keyLen: 24,
    ivLen: 16,
    ids: [
      'CAMELLIA-192-ECB',
      'CAMELLIA-192-CBC',
      NODE_ELEVEN && 'CAMELLIA-192-CTR',
      NODE_ELEVEN && 'CAMELLIA-192-CFB',
      NODE_ELEVEN && 'CAMELLIA-192-OFB'
    ]
  },
  {
    name: 'CAMELLIA-256',
    keyLen: 32,
    ivLen: 16,
    ids: [
      'CAMELLIA-256-ECB',
      'CAMELLIA-256-CBC',
      NODE_ELEVEN && 'CAMELLIA-256-CTR',
      NODE_ELEVEN && 'CAMELLIA-256-CFB',
      NODE_ELEVEN && 'CAMELLIA-256-OFB'
    ]
  },
  {
    name: 'CAST5',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'CAST5-ECB',
      'CAST5-CBC',
      'CAST5-CFB',
      'CAST5-OFB'
    ]
  },
  {
    name: 'DES',
    keyLen: 8,
    ivLen: 8,
    ids: [
      'DES-ECB',
      'DES-CBC',
      'DES-CFB',
      'DES-OFB'
    ]
  },
  {
    name: 'IDEA',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'IDEA-ECB',
      'IDEA-CBC',
      'IDEA-CFB',
      'IDEA-OFB'
    ]
  },
  {
    name: 'RC2',
    keyLen: 8,
    ivLen: 8,
    ids: [
      'RC2-64-CBC'
    ]
  },
  {
    name: 'Triple-DES (EDE)',
    keyLen: 16,
    ivLen: 8,
    ids: [
      NODE_ELEVEN && 'DES-EDE-ECB',
      'DES-EDE-CBC',
      'DES-EDE-CFB',
      'DES-EDE-OFB'
    ]
  },
  {
    name: 'Triple-DES (EDE3)',
    keyLen: 24,
    ivLen: 8,
    ids: [
      NODE_ELEVEN && 'DES-EDE3-ECB',
      'DES-EDE3-CBC',
      'DES-EDE3-CFB',
      'DES-EDE3-OFB'
    ]
  }
];

if (process.browser)
  algs.length = 3;

const key = Buffer.from(
  '3a0c0bf669694ac7685e6806eeadee8e56c9b9bd22c3caa81c718ed4bbf809a1',
  'hex');

const iv = Buffer.from('6dd26d9045b73c377a9ed2ffeca72ffd', 'hex');

function testVector(name, keyLen, ivLen) {
  const key = random.randomBytes(keyLen);
  const gcm = name.endsWith('-GCM');

  let iv = Buffer.alloc(0);

  if (!name.endsWith('-ECB'))
    iv = random.randomBytes(ivLen);

  const data = random.randomBytes((Math.random() * 256) >>> 0);
  const cipher = crypto.createCipheriv(name, key, iv);
  const expect = Buffer.concat([
    cipher.update(data),
    cipher.final(),
    gcm ? cipher.getAuthTag() : Buffer.alloc(0)
  ]);

  return {
    key,
    iv,
    data,
    expect
  };
}

function encipher(name, data, key, iv) {
  const gcm = name.endsWith('-GCM');
  const c = new Cipher(name);
  c.init(key, iv);
  return Buffer.concat([
    c.update(data),
    c.final(),
    gcm ? c.getAuthTag() : Buffer.alloc(0)
  ]);
}

function decipher(name, data, key, iv) {
  const gcm = name.endsWith('-GCM');
  const c = new Decipher(name);
  c.init(key, iv);

  if (gcm) {
    const tag = data.slice(-16);
    data = data.slice(0, -16);
    c.setAuthTag(tag);
  }

  return Buffer.concat([
    c.update(data),
    c.final()
  ]);
}

describe('Cipher', function() {
  it('should encrypt and decrypt with 2 blocks', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e'
      + '9921ddb126b25262c41f1dcff4d67ccfb40e4116e5a4569c1',
      'hex');

    const ciphertext = encipher('AES-256-CBC', data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = decipher('AES-256-CBC', ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  it('should encrypt and decrypt with uneven blocks', () => {
    const data = Buffer.from(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855010203',
      'hex');

    const expected = Buffer.from(''
      + '83de502a9c83112ca6383f2214a892a0cdad5ab2b3e192e9'
      + '921ddb126b25262c5211801019a30c0c6f795296923e0af8',
      'hex');

    const ciphertext = encipher('AES-256-CBC', data, key, iv);
    assert.bufferEqual(ciphertext, expected);

    const plaintext = decipher('AES-256-CBC', ciphertext, key, iv);
    assert.bufferEqual(plaintext, data);
  });

  for (const alg of algs) {
    describe(alg.name, function() {
      for (const id of alg.ids) {
        if (!id)
          continue;

        for (let i = 0; i < 50; i++) {
          const {key, iv, data, expect} = testVector(id, alg.keyLen, alg.ivLen);
          const hex = data.toString('hex', 0, 32);

          it(`should encrypt and decrypt ${hex} with ${id}`, () => {
            const ciphertext = encipher(id, data, key, iv);
            assert.bufferEqual(ciphertext, expect);

            const plaintext = decipher(id, ciphertext, key, iv);
            assert.bufferEqual(plaintext, data);
          });
        }
      }
    });
  }
});
