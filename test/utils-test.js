var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../');
var utils = bcoin.utils;

describe('Utils', function() {
  it('should encode/decode base58', function() {
    var arr = [ 0, 0, 0, 0xde, 0xad, 0xbe, 0xef ];
    var b = utils.toBase58(arr);
    assert.equal(b, '1116h8cQN');
    assert.deepEqual(utils.fromBase58(b), arr);
  });

  it('should translate bits to target', function() {
    var bits = 0x1900896c;
    var hash = utils.toArray(
      '672b3f1bb11a994267ea4171069ba0aa4448a840f38e8f340000000000000000',
      'hex'
    );
    var target = utils.fromCompact(bits);
    assert(utils.testTarget(target, hash));
  });

  it('should convert satoshi to btc', function() {
    var btc = utils.toBTC(new bn(5460));
    assert.equal(btc, '0.0000546');
    btc = utils.toBTC(new bn(54678).mul(new bn(1000000)));
    assert.equal(btc, '546.78');
    btc = utils.toBTC(new bn(5460).mul(new bn(10000000)));
    assert.equal(btc, '546.0');
    btc = utils.toBTC(new bn(5460).mul(new bn(10000000)).toArray());
    assert.equal(btc, '546.0');
    btc = utils.toBTC(new bn(5460).mul(new bn(10000000)).toString('hex'));
    assert.equal(btc, '546.0');
  });

  it('should convert btc to satoshi', function() {
    var btc = utils.fromBTC('0.0000546');
    assert(btc.cmp(new bn(5460)) === 0);
    btc = utils.fromBTC('546.78');
    assert(btc.cmp(new bn(54678).mul(new bn(1000000))) === 0);
    btc = utils.fromBTC('546.0');
    assert(btc.cmp(new bn(5460).mul(new bn(10000000))) === 0);
  });

  it('should convert objects to hashes', function() {
    var b1 = '00';
    var b2 = [0];
    var b3 = { hash: function(enc) { return enc === 'hex' ? '00' : [0]; } };
    var b4 = { hash: '00' };
    var b5 = { _hash: '00' };
    var b6 = { hash: [0] };
    var b7 = { _hash: [0] };
    [b1, b2, b3, b4, b5, b6, b7].forEach(function(b, i) {
      utils.assert.equal(utils.hash(b, 'hex'), '00');
      utils.assert(utils.isEqual(utils.hash(b), [0]));
    });
    var thrown = true;
    try {
      utils.hash(1, 'hex');
    } catch (e) {
      thrown = true;
    }
    assert.equal(thrown, true);
  });
});
