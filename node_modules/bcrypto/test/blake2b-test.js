/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {BLAKE2b} = require('../');
const vectors = require('./data/blake2b.json');

function testHash(msg, size = 64, key = '', expect) {
  const m = Buffer.from(msg, 'hex');
  const k = Buffer.from(key, 'hex');
  const e = Buffer.from(expect, 'hex');

  const hash = BLAKE2b.digest(m, size, k);

  assert.bufferEqual(hash, e);

  const ctx = new BLAKE2b();
  ctx.init(size, k);

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < m.length; i++) {
    ch[0] = m[i];
    ctx.update(ch);
  }

  assert.bufferEqual(ctx.final(), e);
}

describe('BLAKE2b', function() {
  for (const [msg, size, key, expect] of vectors) {
    it(`should get BLAKE2b hash of ${expect}`, () => {
      testHash(msg, size, key, expect);
    });
  }
});
