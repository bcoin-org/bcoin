'use strict';

const assert = require('bsert');
const ChaCha20 = require('../lib/chacha20');
const vectors = require('./data/chacha20.json');

describe('ChaCha20', function() {
  for (const [key_, nonce_, counter, input_, output_] of vectors) {
    const key = Buffer.from(key_, 'hex');
    const nonce = Buffer.from(nonce_, 'hex');
    const input = Buffer.from(input_, 'hex');
    const output = Buffer.from(output_, 'hex');
    const text = key_.slice(0, 32) + '...';

    it(`should perform chacha20 (${text})`, () => {
      const data = Buffer.from(input);
      const ctx = new ChaCha20();

      ctx.init(key, nonce, counter);
      ctx.encrypt(data);

      assert.bufferEqual(data, output);

      ctx.init(key, nonce, counter);
      ctx.encrypt(data);

      assert.bufferEqual(data, input);

      ctx.destroy();
    });
  }
});
