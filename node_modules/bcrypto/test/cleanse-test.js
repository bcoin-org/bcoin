'use strict';

const assert = require('bsert');
const cleanse = require('../lib/cleanse');

describe('Cleanse', function() {
  for (const size of [0, 32, 65535, 65536, 65537]) {
    it(`should cleanse ${size} bytes`, () => {
      const bytes = Buffer.alloc(size);

      for (let i = 0; i < size; i++)
        bytes[i] = i & 0xff;

      const clean = Buffer.from(bytes);

      assert.bufferEqual(clean, bytes);

      cleanse(clean);

      if (size > 0)
        assert.notBufferEqual(clean, bytes);
    });
  }
});
