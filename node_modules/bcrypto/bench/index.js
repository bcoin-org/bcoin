'use strict';

const bench = require('./bench');
const sha256 = require('../lib/sha256');
const blake2b = require('../lib/blake2b');
const sha3 = require('../lib/sha3');
const random = require('../lib/random');
const ChaCha20 = require('../lib/chacha20');
const Poly1305 = require('../lib/poly1305');
const AEAD = require('../lib/aead');

for (const size of [32, 64, 65, 512, 1024]) {
  const rounds = 2000000;
  const msg = random.randomBytes(size);

  bench(`sha256 (${size})`, rounds, () => {
    sha256.digest(msg);
  });

  bench(`blake2b (${size})`, rounds, () => {
    blake2b.digest(msg);
  });

  bench(`sha3 (${size})`, rounds, () => {
    sha3.digest(msg);
  });

  const chacha = new ChaCha20();
  const key = random.randomBytes(32);
  const iv = random.randomBytes(12);

  bench(`chacha20 (${size})`, rounds, () => {
    chacha.init(key, iv, 0);
    chacha.encrypt(msg);
  });

  const poly1305 = new Poly1305();

  bench(`poly1305 (${size})`, rounds, () => {
    poly1305.init(key);
    poly1305.update(msg);
    poly1305.final();
  });

  bench(`aead (${size})`, rounds, () => {
    AEAD.encrypt(key, iv, msg);
  });

  if (size !== 1024)
    console.log('---');
}
