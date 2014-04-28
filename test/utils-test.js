var assert = require('assert');
var bcoin = require('../');

describe('Utils', function() {
  it('should encode/decode base58', function() {
    var arr = [ 0, 0, 0, 0xde, 0xad, 0xbe, 0xef ];
    var b = bcoin.utils.toBase58(arr);
    assert.equal(b, '1116h8cQN');
    assert.deepEqual(bcoin.utils.fromBase58(b), arr);
  });
});
