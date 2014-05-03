var assert = require('assert');
var bcoin = require('../');

describe('Utils', function() {
  it('should encode/decode base58', function() {
    var arr = [ 0, 0, 0, 0xde, 0xad, 0xbe, 0xef ];
    var b = bcoin.utils.toBase58(arr);
    assert.equal(b, '1116h8cQN');
    assert.deepEqual(bcoin.utils.fromBase58(b), arr);
  });

  it('should translate bits to target', function() {
    var bits = 0x1900896c;
    var hash = bcoin.utils.toArray(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );
    var target = bcoin.utils.bitsToTarget(bits);
    assert(bcoin.utils.testTarget(target, hash));
  });
});
