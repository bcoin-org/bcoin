'use strict';

const bench = require('./bench');
const random = require('../lib/random');
const ChaCha20 = require('../lib/chacha20');

for (const size of [32, 64, 65, 512, 1024]) {
  const rounds = 200000;
  const msg = random.randomBytes(size);

  const chacha = new ChaCha20();
  const key = random.randomBytes(32);
  const iv = random.randomBytes(12);

  bench(`chacha20 (${size})`, rounds, () => {
    chacha.init(key, iv, 0);
    chacha.encrypt(msg);
  });
}
