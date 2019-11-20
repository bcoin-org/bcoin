/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const SHA256 = require('../lib/sha256');
const dsa = require('../lib/dsa');
const dsaies = require('../lib/dsaies');
const keys = require('./data/dsaies-keys.json');
const vectors = require('./data/dsaies.json');

describe('DSAIES', function() {
  this.timeout(30000);

  for (const key of keys) {
    const priv = dsa.privateKeyImport(Buffer.from(key, 'hex'));

    it(`should encrypt and decrypt (${priv.bits()})`, () => {
      const bobPriv = priv;
      const bobPub = dsa.publicKeyCreate(bobPriv);
      const alicePriv = dsa.privateKeyCreate(bobPub);

      const msg = random.randomBytes(100);
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

  for (const vector of vectors) {
    const hash = SHA256;
    const ct = Buffer.from(vector.msg, 'hex');
    const priv = dsa.privateKeyImport(Buffer.from(vector.priv, 'hex'));
    const expect = Buffer.from(vector.expect, 'hex');

    it(`should decrypt (${priv.bits()})`, () => {
      const pt = dsaies.decrypt(hash, ct, priv);
      assert.bufferEqual(pt, expect);
    });
  }
});
