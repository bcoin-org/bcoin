/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const SHA256 = require('../lib/sha256');
const rsa = require('../lib/rsa');
const rsaies = require('../lib/rsaies');
// const keys = require('./data/rsaies-keys.json');
// const vectors = require('./data/rsaies.json');

describe('RSAIES', function() {
  this.timeout(120000);

  const badPriv = rsa.privateKeyGenerate(1024);

  for (const size of [1024, 2048, 4096]) {
    if (size > 1024 && rsa.native < 2)
      continue;

    it(`should encrypt and decrypt (${size})`, () => {
      const priv = rsa.privateKeyGenerate(size);
      const pub = rsa.publicKeyCreate(priv);

      // Larger messages than normal:
      const msg = random.randomBytes(2048);
      const ct = rsaies.encrypt(SHA256, msg, pub, 4096); // veil to 4096

      assert.notBufferEqual(ct, msg);
      assert(ct.length > msg.length);

      const pt = rsaies.decrypt(SHA256, ct, priv, 4096);
      assert.bufferEqual(pt, msg);

      if (size === 4096) {
        assert(rsaies.decrypt(SHA256, ct, priv));
      } else {
        assert.throws(() => {
          rsaies.decrypt(SHA256, ct, priv);
        });
      }

      assert.throws(() => {
        rsaies.decrypt(SHA256, ct, badPriv, 4096);
      });

      ct[1] ^= 1;
      assert.throws(() => {
        rsaies.decrypt(SHA256, ct, priv, 4096);
      });
      ct[1] ^= 1;
    });
  }
});
