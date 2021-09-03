'use strict';

const assert = require('bsert');
const AEAD = require('../lib/aead');
const wycheproof = require('./data/wycheproof/chacha20_poly1305_test.json');

describe('AEAD-Wycheproof', function() {
  for (const group of wycheproof.testGroups) {
    const {ivSize, keySize, tagSize} = group;
    const suff = `${ivSize}:${keySize}:${tagSize}`;

    for (const test of group.tests) {
      const text = test.msg.slice(0, 32) + '...';

      it(`should encrypt/decrypt ${text} (${suff})`, () => {
        const key = Buffer.from(test.key, 'hex');
        const iv = Buffer.from(test.iv, 'hex');
        const aad = Buffer.from(test.aad, 'hex');
        const msg = Buffer.from(test.msg, 'hex');
        const ct = Buffer.from(test.ct, 'hex');
        const tag = Buffer.from(test.tag, 'hex');
        const result = test.result !== 'invalid';

        const data = Buffer.from(msg);
        const ctx = new AEAD();

        if (test.comment.includes('invalid nonce size')) {
          if (ivSize === 64 || ivSize === 128)
            return;

          assert.throws(() => ctx.init(key, iv));

          return;
        }

        ctx.init(key, iv);
        ctx.aad(aad);
        ctx.encrypt(data);

        assert.bufferEqual(data, ct);

        if (result)
          assert.bufferEqual(ctx.final(), tag);
        else
          assert.notBufferEqual(ctx.final(), tag);
      });
    }
  }
});
