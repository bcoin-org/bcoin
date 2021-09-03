'use strict';

const bench = require('./bench');
const random = require('../lib/random');
const AEAD = require('../lib/aead');

for (const size of [32, 64, 65, 512, 1024]) {
  const rounds = 200000;
  const key = random.randomBytes(32);
  const iv = random.randomBytes(12);
  const msg = random.randomBytes(size);

  bench(`aead (${size})`, rounds, () => {
    AEAD.encrypt(key, iv, msg);
  });
}
