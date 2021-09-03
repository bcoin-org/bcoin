'use strict';

const assert = require('bsert');
const SHA3 = require('../lib/sha3');
const json = require('./data/sha3.json');

const vectors = [
  ...json,
  [
    Buffer.alloc(1000000, 'a').toString('hex'),
    256,
    '5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1'
  ]
];

describe('SHA3', function() {
  for (const [msg, bits, expect] of vectors) {
    const text = expect.slice(0, 32) + '...';

    it(`should get SHA3 hash of ${text}`, () => {
      const m = Buffer.from(msg, 'hex');
      const e = Buffer.from(expect, 'hex');

      const hash = SHA3.digest(m, bits);

      assert.bufferEqual(hash, e);

      const ctx = new SHA3();
      ctx.init(bits);

      const ch = Buffer.alloc(1);

      for (let i = 0; i < m.length; i++) {
        ch[0] = m[i];
        ctx.update(ch);
      }

      assert.bufferEqual(ctx.final(), e);
    });
  }
});
