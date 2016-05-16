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
    btc = utils.satoshi('546');
    assert(btc === 5460 * 10000000);
    btc = utils.satoshi('546.0');
    assert(btc === 5460 * 10000000);
    btc = utils.satoshi('546.0000');
    assert(btc === 5460 * 10000000);
    assert.doesNotThrow(function() {
      utils.satoshi('546.00000000000000000');
    });
    assert.throws(function() {
      utils.satoshi('546.00000000000000001');
    });
    assert.doesNotThrow(function() {
      utils.satoshi('90071992.54740991');
    });
    assert.doesNotThrow(function() {
      utils.satoshi('090071992.547409910');
    });
    assert.throws(function() {
      utils.satoshi('90071992.54740992');
    });
    assert.throws(function() {
      utils.satoshi('190071992.54740991');
    });
  });

  var unsigned = [
    new bn('ffeeffee'),
    new bn('001fffeeffeeffee'),
    new bn('eeffeeff'),
    new bn('001feeffeeffeeff'),
    new bn(0),
    new bn(1)
  ];

  var signed = [
    new bn('ffeeffee'),
    new bn('001fffeeffeeffee'),
    new bn('eeffeeff'),
    new bn('001feeffeeffeeff'),
    new bn(0),
    new bn(1),
    new bn('ffeeffee').ineg(),
    new bn('001fffeeffeeffee').ineg(),
    new bn('eeffeeff').ineg(),
    new bn('001feeffeeffeeff').ineg(),
    new bn(0).ineg(),
    new bn(1).ineg()
  ];

  unsigned.forEach(function(num) {
    var buf1 = new Buffer(8);
    var buf2 = new Buffer(8);
    var msg = 'should write+read a ' + num.bitLength() + ' bit unsigned int';
    it(msg, function() {
      utils.writeU64(buf1, num, 0);
      utils.writeU64N(buf2, num.toNumber(), 0);
      assert.deepEqual(buf1, buf2);
      var n1 = utils.readU64(buf1, 0);
      var n2 = utils.readU64N(buf2, 0);
      assert.equal(n1.toNumber(), n2);
    });
  });

  signed.forEach(function(num) {
    var buf1 = new Buffer(8);
    var buf2 = new Buffer(8);
    var msg = 'should write+read a ' + num.bitLength()
      + ' bit ' + (num.isNeg() ? 'negative' : 'positive') + ' int';
    it(msg, function() {
      utils.write64(buf1, num, 0);
      utils.write64N(buf2, num.toNumber(), 0);
      assert.deepEqual(buf1, buf2);
      var n1 = utils.read64(buf1, 0);
      var n2 = utils.read64N(buf2, 0);
      assert.equal(n1.toNumber(), n2);
    });
    var msg = 'should write+read a ' + num.bitLength()
      + ' bit ' + (num.isNeg() ? 'negative' : 'positive') + ' int as unsigned';
    it(msg, function() {
      utils.writeU64(buf1, num, 0);
      utils.writeU64N(buf2, num.toNumber(), 0);
      assert.deepEqual(buf1, buf2);
      var n1 = utils.readU64(buf1, 0);
      if (num.isNeg()) {
        assert.throws(function() {
          utils.readU64N(buf2, 0);
        });
      } else {
        var n2 = utils.readU64N(buf2, 0);
        assert.equal(n1.toNumber(), n2);
      }
    });
  });
});
