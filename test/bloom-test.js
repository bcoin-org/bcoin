'use strict';

var bcoin = require('../').set('main');
var util = bcoin.util;
var crypto = require('../lib/crypto/crypto');
var Bloom = require('../lib/utils/bloom');
var murmur3 = require('../lib/utils/murmur3');
var constants = bcoin.constants;
var assert = require('assert');

describe('Bloom', function() {
  this.timeout(20000);

  var filterHex = ''
    + '000000000000000000000000000000000000000000000000088004000000000000000'
    + '000000000200000000000000000000000000000000800000000000000000002000000'
    + '000000000000002000000000000000000000000000000000000000000040000200000'
    + '0000000001000000800000080000000';

  it('should do proper murmur3', function() {
    function mm(str, seed, expect, enc) {
      assert.equal(murmur3(new Buffer(str, enc || 'ascii'), seed), expect);
    }

    mm('', 0, 0);
    mm('', 0xfba4c795, 0x6a396f08);
    mm('00', 0xfba4c795, 0x2a101837);
    mm('hello world', 0, 0x5e928f0f);

    mm('', 0x00000000, 0x00000000, 'hex');
    mm('', 0xfba4c795, 0x6a396f08, 'hex');
    mm('', 0xffffffff, 0x81f16f39, 'hex');

    mm('00', 0x00000000, 0x514e28b7, 'hex');
    mm('00', 0xfba4c795, 0xea3f0b17, 'hex');
    mm('ff', 0x00000000, 0xfd6cf10d, 'hex');

    mm('0011', 0x00000000, 0x16c6b7ab, 'hex');
    mm('001122', 0x00000000, 0x8eb51c3d, 'hex');
    mm('00112233', 0x00000000, 0xb4471bf8, 'hex');
    mm('0011223344', 0x00000000, 0xe2301fa8, 'hex');
    mm('001122334455', 0x00000000, 0xfc2e4a15, 'hex');
    mm('00112233445566', 0x00000000, 0xb074502c, 'hex');
    mm('0011223344556677', 0x00000000, 0x8034d2a0, 'hex');
    mm('001122334455667788', 0x00000000, 0xb4698def, 'hex');
  });

  it('should test and add stuff', function() {
    var b = new Bloom(512, 10, 156);

    b.add('hello', 'ascii');
    assert(b.test('hello', 'ascii'));
    assert(!b.test('hello!', 'ascii'));
    assert(!b.test('ping', 'ascii'));

    b.add('hello!', 'ascii');
    assert(b.test('hello!', 'ascii'));
    assert(!b.test('ping', 'ascii'));

    b.add('ping', 'ascii');
    assert(b.test('ping', 'ascii'));
  });

  it('should serialize to the correct format', function() {
    var filter = new Bloom(952, 6, 3624314491, constants.filterFlags.NONE);
    var item1 = '8e7445bbb8abd4b3174d80fa4c409fea6b94d96b';
    var item2 = '047b00000078da0dca3b0ec2300c00d0ab4466ed10'
      + 'e763272c6c9ca052972c69e3884a9022084215e2eef'
      + '0e6f781656b5d5a87231cd4349e534b6dea55ad4ff55e';
    filter.add(item1, 'hex');
    filter.add(item2, 'hex');
    assert.equal(filter.filter.toString('hex'), filterHex);
  });

  it('should handle 1m ops with regular filter', function() {
    var filter = Bloom.fromRate(210000, 0.00001, -1);
    filter.tweak = 0xdeadbeef;
    // ~1m operations
    for (var i = 0; i < 1000; i++) {
      var str = 'foobar' + i;
      filter.add(str, 'ascii');
      var j = i;
      do {
        var str = 'foobar' + j;
        assert(filter.test(str, 'ascii') === true);
        assert(filter.test(str + '-', 'ascii') === false);
      } while (j--);
    }
  });

  it('should handle 1m ops with rolling filter', function() {
    var filter = new Bloom.Rolling(210000, 0.00001);
    filter.tweak = 0xdeadbeef;
    // ~1m operations
    for (var i = 0; i < 1000; i++) {
      var str = 'foobar' + i;
      filter.add(str, 'ascii');
      var j = i;
      do {
        var str = 'foobar' + j;
        assert(filter.test(str, 'ascii') === true);
        assert(filter.test(str + '-', 'ascii') === false);
      } while (j--);
    }
  });

  it('should handle rolling generations', function() {
    var filter = new Bloom.Rolling(50, 0.00001);
    filter.tweak = 0xdeadbeee;
    for (var i = 0; i < 25; i++) {
      var str = 'foobar' + i;
      filter.add(str, 'ascii');
      var j = i;
      do {
        var str = 'foobar' + j;
        assert(filter.test(str, 'ascii') === true);
        assert(filter.test(str + '-', 'ascii') === false);
      } while (j--);
    }
    for (var i = 25; i < 50; i++) {
      var str = 'foobar' + i;
      filter.add(str, 'ascii');
      var j = i;
      do {
        var str = 'foobar' + j;
        assert(filter.test(str, 'ascii') === true, str);
        assert(filter.test(str + '-', 'ascii') === false, str);
      } while (j--);
    }
    for (var i = 50; i < 75; i++) {
      var str = 'foobar' + i;
      filter.add(str, 'ascii');
      var j = i;
      do {
        var str = 'foobar' + j;
        assert(filter.test(str, 'ascii') === true, str);
        assert(filter.test(str + '-', 'ascii') === false, str);
      } while (j--);
    }
    for (var i = 75; i < 100; i++) {
      var str = 'foobar' + i;
      filter.add(str, 'ascii');
      var j = i;
      do {
        var str = 'foobar' + j;
        assert(filter.test(str, 'ascii') === true, str);
        assert(filter.test(str + '-', 'ascii') === false, str);
      } while (j-- > 25);
      assert(filter.test('foobar 24', 'ascii') === false);
    }
    for (var i = 100; i < 125; i++) {
      var str = 'foobar' + i;
      filter.add(str, 'ascii');
      var j = i;
      do {
        var str = 'foobar' + j;
        assert(filter.test(str, 'ascii') === true, str);
        assert(filter.test(str + '-', 'ascii') === false, str);
      } while (j-- > 50);
    }
    assert(filter.test('foobar 49', 'ascii') === false);
  });
});
