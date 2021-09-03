'use strict';

const fs = require('fs');
const crypto = require('crypto');
const {createHash, createHmac} = require('./create-hash');

const algs = [
  ['blake2b160', true], // python
  ['blake2b256', true], // python
  ['blake2b384', true], // python
  ['blake2b512', true],
  ['blake2s128', true], // python
  ['blake2s160', true], // python
  ['blake2s224', true], // python
  ['blake2s256', true],
  ['gost94', false], // js (bad)
  ['hash160', false],
  ['hash256', false],
  ['keccak224', false], // native
  ['keccak256', false], // native
  ['keccak384', false], // native
  ['keccak512', false], // native
  ['md2', false], // js (bad)
  ['md4', false],
  ['md5', false],
  ['md5-sha1', false],
  ['ripemd160', false],
  ['sha1', false],
  ['sha224', false],
  ['sha256', false],
  ['sha384', false],
  ['sha512', false],
  ['sha3-224', false],
  ['sha3-256', false],
  ['sha3-384', false],
  ['sha3-512', false],
  ['shake128', false],
  ['shake256', false],
  ['whirlpool', false]
];

const defaults = [
  ['', ''],
  ['Foobar', 'Baz'],
  ['The quick brown fox jumps over the lazy dog', 'Secret key goes here!'],
  ['The quick brown fox jumps over the lazy dog.', 'Secret key goes here.'],
  ['Message goes here!', 'The quick brown fox jumps over the lazy dog'],
  ['Message goes here.', 'The quick brown fox jumps over the lazy dog.'],
  [Buffer.alloc(777, 0), Buffer.alloc(777, 0)],
  [Buffer.alloc(777, 0xaa), Buffer.alloc(777, 0xff)]
];

function hash(alg, msg, key) {
  const ctx = createHash(alg, key);
  ctx.update(msg);
  return ctx.digest();
}

function hmac(alg, msg, key) {
  const ctx = createHmac(alg, key);
  ctx.update(msg);
  return ctx.digest();
}

for (const [alg, hasKey] of algs) {
  const vectors = [];

  for (const [m] of defaults) {
    const msg = Buffer.from(m);
    const digest = hash(alg, msg).toString('hex');

    vectors.push([msg.toString('hex'), null, null, digest]);
  }

  for (let i = 0; i < 100; i++) {
    const msg = crypto.randomBytes(Math.random() * 300 | 0);
    const digest = hash(alg, msg).toString('hex');

    vectors.push([msg.toString('hex'), null, null, digest]);
  }

  if (hasKey) {
    for (const [m, k] of defaults) {
      const msg = Buffer.from(m);
      const key = Buffer.from(k).slice(0, 32);
      const digest = hash(alg, msg, key).toString('hex');

      vectors.push([msg.toString('hex'), key.toString('hex'), null, digest]);
    }

    for (let i = 0; i < 100; i++) {
      const msg = crypto.randomBytes(Math.random() * 300 | 0);
      const key = crypto.randomBytes(Math.random() * 33 | 0);
      const digest = hash(alg, msg, key).toString('hex');

      vectors.push([msg.toString('hex'), key.toString('hex'), null, digest]);
    }
  }

  if (alg !== 'shake128' && alg !== 'shake256') {
    for (const [m, k] of defaults) {
      const msg = Buffer.from(m);
      const key = Buffer.from(k);
      const mac = hmac(alg, msg, key).toString('hex');

      vectors.push([msg.toString('hex'), null, key.toString('hex'), mac]);
    }

    for (let i = 0; i < 100; i++) {
      const msg = crypto.randomBytes(Math.random() * 300 | 0);
      const key = crypto.randomBytes(Math.random() * 300 | 0);
      const mac = hmac(alg, msg, key).toString('hex');

      vectors.push([msg.toString('hex'), null, key.toString('hex'), mac]);
    }
  }

  fs.writeFileSync(`${__dirname}/../data/hashes/${alg}.json`,
    JSON.stringify(vectors, null, 2) + '\n');
}
