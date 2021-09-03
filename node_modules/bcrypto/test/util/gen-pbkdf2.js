'use strict';

const fs = require('fs');
const crypto = require('crypto');

const hashes = [
  ['SHA1', 'sha1'],
  ['SHA256', 'sha256'],
  ['SHA512', 'sha512'],
  ['SHA3_256', 'sha3-256'],
  ['BLAKE2s256', 'blake2s256'],
  ['BLAKE2b512', 'blake2b512']
];

function testVector(name) {
  const passwd = crypto.randomBytes(Math.random() * 256 | 0);
  const salt = crypto.randomBytes(Math.random() * 32 | 0);
  const iter = 1 + (Math.random() * 5000 | 0);
  const len = 1 + (Math.random() * 64 | 0);
  const expect = crypto.pbkdf2Sync(passwd, salt, iter, len, name);

  return {
    passwd,
    salt,
    iter,
    len,
    expect
  };
}

const vectors = [];

for (const [hash, name] of hashes) {
  for (let i = 0; i < 10; i++) {
    const {passwd, salt, iter, len, expect} = testVector(name);

    vectors.push([
      hash,
      passwd.toString('hex'),
      salt.toString('hex'),
      iter,
      len,
      expect.toString('hex')
    ]);
  }
}

fs.writeFileSync(`${__dirname}/../data/pbkdf2.json`,
  JSON.stringify(vectors, null, 2) + '\n');
