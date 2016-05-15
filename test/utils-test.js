var bn = require('bn.js');
var bcoin = require('../').set('main');
var assert = require('assert');
var utils = bcoin.utils;

describe('Utils', function() {
  it('should encode/decode base58', function() {
    var arr = new Buffer([ 0, 0, 0, 0xde, 0xad, 0xbe, 0xef ]);
    var b = utils.toBase58(arr);
    assert.equal(b, '1116h8cQN');
    assert.deepEqual(utils.fromBase58(b), arr);
  });

  it('should translate bits to target', function() {
    var bits = 0x1900896c;
    var hash = new Buffer(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );
    var target = utils.fromCompact(bits);
    assert(utils.testTarget(target, hash));
  });

  it('should convert satoshi to btc', function() {
    var btc = utils.btc(5460);
    assert.equal(btc, '0.0000546');
    btc = utils.btc(54678 * 1000000);
    assert.equal(btc, '546.78');
    btc = utils.btc(5460 * 10000000);
    assert.equal(btc, '546.0');
  });

  it('should convert btc to satoshi', function() {
    var btc = utils.satoshi('0.0000546');
    assert(btc === 5460);
    btc = utils.satoshi('546.78');
    assert(btc === 54678 * 1000000);
    btc = utils.satoshi('546.0');
    assert(btc === 5460 * 10000000);
  });
});
