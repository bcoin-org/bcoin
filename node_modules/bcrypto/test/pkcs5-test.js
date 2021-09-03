'use strict';

const assert = require('bsert');
const pkcs5 = require('../lib/encoding/pkcs5');

describe('PKCS5', function() {
  it('should add and remove padding', () => {
    const buf = Buffer.from('01020304', 'hex');
    const expect = Buffer.from('0102030404040404', 'hex');
    const padded = pkcs5.pad(buf, 8);

    assert.bufferEqual(padded, expect);
    assert.bufferEqual(pkcs5.unpad(padded, 8), buf);
  });
});
