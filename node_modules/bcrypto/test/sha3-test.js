/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {SHA3} = require('../');
const vectors = require('./data/sha3.json');

vectors.push([
  Buffer.alloc(1000000, 'a').toString('hex'),
  256,
  '5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1'
]);

function testHash(msg, bits = 256, expect) {
  const m = Buffer.from(msg, 'hex');
  const e = Buffer.from(expect, 'hex');

  const hash = SHA3.digest(m, bits);

  assert.bufferEqual(hash, e);

  const ctx = new SHA3();
  ctx.init(bits);

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < m.length; i++) {
    ch[0] = m[i];
    ctx.update(ch);
  }

  assert.bufferEqual(ctx.final(), e);
}

describe('SHA3', function() {
  for (const [msg, bits, expect] of vectors) {
    it(`should get SHA3 hash of ${expect}`, () => {
      testHash(msg, bits, expect);
    });
  }
});
