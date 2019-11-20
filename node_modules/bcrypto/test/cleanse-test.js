/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const cleanse = require('../lib/cleanse');
const bytes = Buffer.allocUnsafe(32);

for (let i = 0; i < 32; i++)
  bytes[i] = i;

describe('Cleanse', function() {
  it('should cleanse bytes', () => {
    const c = Buffer.from(bytes);
    cleanse(c);
    assert.notBufferEqual(c, bytes);
  });
});
