'use strict';

const assert = require('bsert');
const x25519 = require('../lib/x25519');
const wycheproof = require('./data/wycheproof/x25519_test.json');

describe('X25519-Wycheproof', function() {
  for (const group of wycheproof.testGroups) {
    for (const test of group.tests) {
      const text = test.shared.slice(0, 32) + '...';

      it(`should derive ${text}`, () => {
        const pub = Buffer.from(test.public, 'hex');
        const priv = Buffer.from(test.private, 'hex');
        const shared = Buffer.from(test.shared, 'hex');
        const zero = Buffer.alloc(32, 0x00);

        let result = test.result !== 'invalid';

        if (test.comment.includes('low order'))
          result = false;

        if (shared.equals(zero))
          result = false;

        if (!result)
          assert.throws(() => x25519.derive(pub, priv));
        else
          assert.bufferEqual(x25519.derive(pub, priv), shared);
      });
    }
  }
});
