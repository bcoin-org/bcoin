/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint camelcase: "off" */

'use strict';

const assert = require('bsert');
const MD2 = require('../lib/md2');

const vectors = [
  [
    '',
    '8350e5a3e24c153df2275c9f80692773'
  ],
  [
    'The quick brown fox jumps over the lazy dog',
    '03d85a0d629d2c442e987525319fc471'
  ],
  [
    'The quick brown fox jumps over the lazy cog',
    '6b890c9292668cdbbfda00a4ebf31f05'
  ]
];

function testHash(msg, expect) {
  const m = Buffer.from(msg, 'binary');
  const e = Buffer.from(expect, 'hex');

  const hash = MD2.digest(m);

  assert.bufferEqual(hash, e);

  const ctx = new MD2();
  ctx.init();

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < m.length; i++) {
    ch[0] = m[i];
    ctx.update(ch);
  }

  assert.bufferEqual(ctx.final(), e);
}

describe('MD2', function() {
  for (const [msg, expect] of vectors) {
    it(`should get MD2 hash of ${expect}`, () => {
      testHash(msg, expect);
    });
  }
});
