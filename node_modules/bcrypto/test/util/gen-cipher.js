'use strict';

const fs = require('fs');
const crypto = require('crypto');

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
      'AES-128-GCM'
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
      'AES-192-GCM'
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
      'AES-256-GCM'
    ]
  },
  {
    name: 'ARC2',
    keyLen: 8,
    ivLen: 8,
    ids: [
      'ARC2-64-CBC'
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
      'CAMELLIA-128-CTR',
      'CAMELLIA-128-CFB',
      'CAMELLIA-128-OFB'
    ]
  },
  {
    name: 'CAMELLIA-192',
    keyLen: 24,
    ivLen: 16,
    ids: [
      'CAMELLIA-192-ECB',
      'CAMELLIA-192-CBC',
      'CAMELLIA-192-CTR',
      'CAMELLIA-192-CFB',
      'CAMELLIA-192-OFB'
    ]
  },
  {
    name: 'CAMELLIA-256',
    keyLen: 32,
    ivLen: 16,
    ids: [
      'CAMELLIA-256-ECB',
      'CAMELLIA-256-CBC',
      'CAMELLIA-256-CTR',
      'CAMELLIA-256-CFB',
      'CAMELLIA-256-OFB'
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
    name: 'Triple-DES (EDE)',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'DES-EDE-ECB',
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
      'DES-EDE3-ECB',
      'DES-EDE3-CBC',
      'DES-EDE3-CFB',
      'DES-EDE3-OFB'
    ]
  }
];

function testVector(name, keyLen, ivLen) {
  if (name.startsWith('ARC2'))
    name = name.substring(1);

  const key = crypto.randomBytes(keyLen);
  const gcm = name.endsWith('-GCM');

  let iv = Buffer.alloc(0);

  if (!name.endsWith('-ECB'))
    iv = crypto.randomBytes(ivLen);

  const data = crypto.randomBytes((Math.random() * 256) >>> 0);
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

for (const alg of algs) {
  for (const id of alg.ids) {
    const vectors = [];

    for (let i = 0; i < 50; i++) {
      const {key, iv, data, expect} = testVector(id, alg.keyLen, alg.ivLen);

      vectors.push([
        key.toString('hex'),
        iv.toString('hex'),
        data.toString('hex'),
        expect.toString('hex')
      ]);
    }

    const file = `${__dirname}/../data/ciphers/${id.toLowerCase()}.json`;

    fs.writeFileSync(file, JSON.stringify(vectors, null, 2) + '\n', 'utf8');
  }
}
