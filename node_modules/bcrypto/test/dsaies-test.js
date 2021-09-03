'use strict';

const assert = require('bsert');
const RNG = require('./util/rng');
const SHA256 = require('../lib/sha256');
const dsa = require('../lib/dsa');
const dsaies = require('../lib/dsaies');
const keys = require('./data/dsaies-keys.json');
const vectors = require('./data/ies/dsa.json');

describe('DSAIES', function() {
  if (process.env.BMOCHA_VALGRIND)
    this.skip();

  const rng = new RNG();

  for (const key of keys) {
    const priv = Buffer.from(key, 'hex');
    const params = dsa.paramsCreate(priv);
    const bits = dsa.paramsBits(params);

    it(`should encrypt and decrypt (${bits})`, () => {
      const bobPriv = priv;
      const bobPub = dsa.publicKeyCreate(bobPriv);
      const alicePriv = dsa.privateKeyCreate(params);

      const msg = rng.randomBytes(rng.randomRange(0, 100));
      const ct = dsaies.encrypt(SHA256, msg, bobPub, alicePriv);

      assert.notBufferEqual(ct, msg);
      assert(ct.length > msg.length);

      const pt = dsaies.decrypt(SHA256, ct, bobPriv);
      assert.bufferEqual(pt, msg);

      assert.throws(() => {
        dsaies.decrypt(SHA256, ct, alicePriv);
      });

      ct[1] ^= 1;
      assert.throws(() => {
        dsaies.decrypt(SHA256, ct, bobPriv);
      });
      ct[1] ^= 1;
    });
  }

  for (const [i, json] of vectors.entries()) {
    const vector = json.map(item => Buffer.from(item, 'hex'));
    const [, bob,, msg, ct] = vector;

    it(`should decrypt ciphertext #${i + 1}`, () => {
      const pt = dsaies.decrypt(SHA256, ct, bob);
      assert.bufferEqual(pt, msg);
    });
  }
});
