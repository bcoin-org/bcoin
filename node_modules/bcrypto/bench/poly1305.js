'use strict';

const bench = require('./bench');
const random = require('../lib/random');
const Poly1305 = require('../lib/poly1305');

for (const size of [32, 64, 65, 512, 1024]) {
  const rounds = 200000;
  const msg = random.randomBytes(size);
  const key = random.randomBytes(32);
  const poly1305 = new Poly1305();

  bench(`poly1305 (${size})`, rounds, () => {
    poly1305.init(key);
    poly1305.update(msg);
    poly1305.final();
  });
}
