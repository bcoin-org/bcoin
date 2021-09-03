'use strict';

const assert = require('bsert');
const cipher = require('../lib/cipher');
const rng = require('../lib/random');

describe('CTS', function() {
  const alg = 'AES-128-CTS';

  it(`should encrypt with ${alg} (random)`, () => {
    const key = rng.randomBytes(16);
    const iv = rng.randomBytes(16);
    const pt1 = rng.randomBytes(rng.randomRange(16, 128));
    const c = new cipher.Cipher(alg);
    const d = new cipher.Decipher(alg);

    c.init(key, iv);
    d.init(key, iv);

    const ct2 = Buffer.concat([c.update(pt1), c.final()]);
    const pt2 = Buffer.concat([d.update(ct2), d.final()]);

    assert.bufferEqual(pt2, pt1);
  });

  it(`should encrypt with ${alg} (uneven)`, () => {
    const key = Buffer.from('1234567890123456');
    const iv = Buffer.from('alwodbcfhilkwtvb');
    const pt1 = Buffer.from('1234567890123456789');
    const ct1 = Buffer.from('1dd4198c1c5942ae2021c36ae2774272b0cae4', 'hex');
    const c = new cipher.Cipher(alg);
    const d = new cipher.Decipher(alg);

    c.init(key, iv);
    d.init(key, iv);

    const ct2 = Buffer.concat([c.update(pt1), c.final()]);
    const pt2 = Buffer.concat([d.update(ct1), d.final()]);

    assert.bufferEqual(ct2, ct1);
    assert.bufferEqual(pt2, pt1);
  });

  it(`should encrypt with ${alg} (even)`, () => {
    const key = Buffer.from('1234567890123456');
    const iv = Buffer.from('alwodbcfhilkwtvb');
    const pt1 = Buffer.alloc(16, 0xaa);
    const ct1 = Buffer.from('7e46ed6975f8b58f6eed3b16cb6a3b35', 'hex');
    const c = new cipher.Cipher(alg);
    const d = new cipher.Decipher(alg);

    c.init(key, iv);
    d.init(key, iv);

    const ct2 = Buffer.concat([c.update(pt1), c.final()]);
    const pt2 = Buffer.concat([d.update(ct2), d.final()]);

    assert.bufferEqual(ct2, ct1);
    assert.bufferEqual(pt2, pt1);
  });

  it(`should encrypt with ${alg} (even)`, () => {
    const key = Buffer.from('1234567890123456');
    const iv = Buffer.from('alwodbcfhilkwtvb');
    const pt1 = Buffer.alloc(32, 0xaa);
    const ct1 = Buffer.from(
      'ab5083bd82147bf79047f8b1e6fe4aad10936d5e23ecb806940f273887c7db52',
      'hex');
    const c = new cipher.Cipher(alg);
    const d = new cipher.Decipher(alg);

    c.init(key, iv);
    d.init(key, iv);

    const ct2 = Buffer.concat([c.update(pt1), c.final()]);
    const pt2 = Buffer.concat([d.update(ct2), d.final()]);

    assert.bufferEqual(ct2, ct1);
    assert.bufferEqual(pt2, pt1);
  });
});
