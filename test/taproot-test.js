/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {TaggedHash} = require('../lib/utils/taggedhash');

describe('Taproot', function() {
  it('should create a generic tagged hash', () => {
    // Without 'bytes' argument
    const testHash1 = new TaggedHash('test');
    const digest1 = testHash1.digest(Buffer.alloc(32, 12));

    // With 'bytes' argument
    const testHash2 = new TaggedHash('test', Buffer.alloc(32, 12));
    assert.bufferEqual(digest1, testHash2);

    // Test vector created with
    // https://github.com/bitcoin/bitcoin/blob/0.21/
    //   test/functional/test_framework/key.py#L17-L21
    // TaggedHash('test', bytearray([12]*32)).hex()
    assert.bufferEqual(
      digest1,
      Buffer.from(
        'f88d26c35028f6e63b5cfc3fc67b4a3ae6da9c48d9f0be94df97a94ab64d5a68',
        'hex'
      )
    );
  });
});
