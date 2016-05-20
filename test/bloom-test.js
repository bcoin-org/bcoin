var bcoin = require('../').set('main');
var assert = require('assert');

describe('Bloom', function() {
  this.timeout(20000);

  it('should do proper murmur3', function() {
    var murmur3 = bcoin.bloom.murmur3;
    assert.equal(murmur3(new Buffer('', 'ascii'), 0), 0);
    assert.equal(murmur3(new Buffer('', 'ascii'), 0xfba4c795), 0x6a396f08);
    assert.equal(murmur3(new Buffer('00', 'ascii'), 0xfba4c795), 0x2a101837);
    assert.equal(murmur3(new Buffer('hello world', 'ascii'), 0), 0x5e928f0f);
  });

  it('should test and add stuff', function() {
    var b = new bcoin.bloom(512, 10, 156);

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

  it('should test regular filter', function() {
    var filter = bcoin.bloom.fromRate(210000, 0.00001, -1);
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

  it('should test rolling filter', function() {
    var filter = new bcoin.bloom.rolling(210000, 0.00001);
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
    var filter = new bcoin.bloom.rolling(50, 0.00001);
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
