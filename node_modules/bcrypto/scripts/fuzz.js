/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');

const bhash = {
  ripemd160: require('../lib/js/ripemd160'),
  sha1: require('../lib/js/sha1'),
  sha256: require('../lib/js/sha256'),
  sha512: require('../lib/js/sha512')
};

const algs = [
  'ripemd160',
  'sha1',
  'sha256',
  'sha512'
];

function nhash(alg, msg) {
  const nctx = crypto.createHash(alg);
  nctx.update(msg);
  return nctx.digest();
}

function nhmac(alg, msg, key) {
  const nctx = crypto.createHmac(alg, key);
  nctx.update(msg);
  return nctx.digest();
}

function nencipher(data, key, iv) {
  const ctx = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([ctx.update(data), ctx.final()]);
};

function ndecipher(data, key, iv) {
  const ctx = crypto.createDecipheriv('aes-256-cbc', key, iv);
  try {
    return Buffer.concat([ctx.update(data), ctx.final()]);
  } catch (e) {
    throw new Error('Bad key for decryption.');
  }
}

for (const alg of algs) {
  console.log(alg);

  for (let i = 0; i < 100000; i++) {
    const data = crypto.randomBytes((Math.random() * 1000) | 0);
    const key = crypto.randomBytes((Math.random() * 1000) | 0);

    const h1 = bhash[alg].digest(data);
    const h2 = nhash(alg, data);
    assert.bufferEqual(h1, h2);

    const m1 = bhash[alg].mac(data, key);
    const m2 = nhmac(alg, data, key);
    assert.bufferEqual(m1, m2);
  }
}

const native = {
  keccak: require('../lib/native/keccak'),
  sha3: require('../lib/native/sha3'),
  blake2b: require('../lib/native/blake2b')
};

const js = {
  keccak: require('../lib/js/keccak'),
  sha3: require('../lib/js/sha3'),
  blake2b: require('../lib/js/blake2b')
};

for (const alg of Object.keys(native)) {
  console.log(alg);

  for (let i = 0; i < 100000; i++) {
    const data = crypto.randomBytes((Math.random() * 1000) | 0);

    const h1 = js[alg].digest(data);
    const h2 = native[alg].digest(data);
    assert.bufferEqual(h1, h2);

    if (alg === 'blake2b') {
      const key = crypto.randomBytes((Math.random() * 65) | 0);
      const m1 = js[alg].mac(data, key);
      const m2 = native[alg].mac(data, key);
      assert.bufferEqual(m1, m2);
    }
  }
}

const aes = require('../lib/js/aes');
const nativeAES = require('../lib/native/aes');

console.log('aes');

for (let i = 0; i < 100000; i++) {
  const data = crypto.randomBytes((Math.random() * 1000) | 0);
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const h1 = aes.encipher(data, key, iv);
  const h2 = nencipher(data, key, iv);
  const h3 = nativeAES.encipher(data, key, iv);
  assert.bufferEqual(h2, h1);
  assert.bufferEqual(h3, h1);

  const m1 = aes.decipher(h1, key, iv);
  const m2 = ndecipher(h2, key, iv);
  const m3 = nativeAES.decipher(h3, key, iv);
  assert.bufferEqual(m2, m1);
  assert.bufferEqual(m3, m1);
}
