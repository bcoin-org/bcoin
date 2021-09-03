'use strict';

const assert = require('bsert');
const BLAKE2b = require('../lib/blake2b');
const vectors = require('./data/blake2b.json');

describe('BLAKE2b', function() {
  for (const [msg, size, key, expect] of vectors) {
    const text = expect.slice(0, 32) + '...';

    it(`should get BLAKE2b hash of ${text}`, () => {
      const m = Buffer.from(msg, 'hex');
      const k = Buffer.from(key, 'hex');
      const e = Buffer.from(expect, 'hex');

      const hash = BLAKE2b.digest(m, size, k);

      assert.bufferEqual(hash, e);

      const ctx = new BLAKE2b();
      ctx.init(size, k);

      const ch = Buffer.alloc(1);

      for (let i = 0; i < m.length; i++) {
        ch[0] = m[i];
        ctx.update(ch);
      }

      assert.bufferEqual(ctx.final(), e);
    });
  }
});
