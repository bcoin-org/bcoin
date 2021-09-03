'use strict';

const assert = require('bsert');
const rng = require('../lib/random');
const Poly1305 = require('../lib/poly1305');
const vectors = require('./data/poly1305.json');

function updateRand(ctx, msg) {
  const max = Math.max(2, msg.length >>> 2);

  let i = 0;

  while (i < msg.length) {
    const j = rng.randomRange(0, max);

    ctx.update(msg.slice(i, i + j));

    i += j;
  }
}

describe('Poly1305', function() {
  it('should perform poly1305 (1)', () => {
    const key = Buffer.alloc(32);
    const msg = Buffer.alloc(73);
    const tag = Buffer.from('ddb9da7ddd5e52792730ed5cda5f90a4', 'hex');
    const poly = new Poly1305();

    for (let i = 0; i < key.length; i++)
      key[i] = i + 221;

    for (let i = 0; i < msg.length; i++)
      msg[i] = i + 121;

    poly.init(key);
    poly.update(msg);

    assert.bufferEqual(poly.final(), tag);
  });

  it('should perform poly1305 (2)', () => {
    const key = Buffer.from('85d6be7857556d337f4452fe42d506a'
                          + '80103808afb0db2fd4abff6af4149f51b', 'hex');
    const msg = Buffer.from('Cryptographic Forum Research Group', 'ascii');
    const tag = Buffer.from('a8061dc1305136c6c22b8baf0c0127a9', 'hex');
    const poly = new Poly1305();

    poly.init(key);
    poly.update(msg);

    assert.bufferEqual(poly.final(), tag);
  });

  for (const [key_, msg_, tag_] of vectors) {
    const msg = Buffer.from(msg_, 'hex');
    const key = Buffer.from(key_, 'hex');
    const tag = Buffer.from(tag_, 'hex');
    const text = key_.slice(0, 32) + '...';

    it(`should perform incremental poly1305 (${text})`, () => {
      const poly = new Poly1305();

      poly.init(key);

      updateRand(poly, msg);

      assert.bufferEqual(poly.final(), tag);

      poly.destroy();
    });

    it(`should perform incremental poly1305 + verify (${text})`, () => {
      const poly = new Poly1305();

      poly.init(key);

      updateRand(poly, msg);

      assert.strictEqual(poly.verify(tag), true);

      poly.init(key);

      updateRand(poly, msg);

      const tag0 = Buffer.from(tag);

      tag0[0] ^= 1;

      assert.strictEqual(poly.verify(tag0), false);
    });
  }
});
