'use strict';

const assert = require('bsert');
const ed25519 = require('../lib/ed25519');
const vectors = require('./data/wycheproof/eddsa_test.json');

describe('EDDSA-Wycheproof', function() {
  this.timeout(30000);

  for (const group of vectors.testGroups) {
    const priv = Buffer.from(group.key.sk, 'hex');
    const pub = Buffer.from(group.key.pk, 'hex');

    for (const test of group.tests) {
      const text = test.sig.slice(0, 32) + '...';

      it(`should verify signature ${text}`, () => {
        const msg = Buffer.from(test.msg, 'hex');
        const sig = Buffer.from(test.sig, 'hex');
        const res = test.result !== 'invalid';

        if (res)
          assert.bufferEqual(ed25519.sign(msg, priv), sig);

        assert.strictEqual(ed25519.verify(msg, sig, pub), res);
        assert.strictEqual(ed25519.verifySingle(msg, sig, pub), res);
        assert.strictEqual(ed25519.verifyBatch([[msg, sig, pub]]), res);
      });
    }
  }
});
