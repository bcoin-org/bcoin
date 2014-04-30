var assert = require('assert');
var bcoin = require('../');

describe('Bloom', function() {
  it('should do proper murmur3', function() {
    var h = bcoin.bloom.hash;

    assert.equal(h('', 0), 0);
    assert.equal(h('', 0xfba4c795), 0x6a396f08);
    assert.equal(h('00', 0xfba4c795), 0x2a101837);
    assert.equal(h('hello world', 0), 0x5e928f0f);
  });

  it('should test and add stuff', function() {
    var b = bcoin.bloom(512, 10, 156);

    b.add('hello');
    assert(b.test('hello'));
    assert(!b.test('hello!'));
    assert(!b.test('ping'));

    b.add('hello!');
    assert(b.test('hello!'));
    assert(!b.test('ping'));

    b.add('ping');
    assert(b.test('ping'));
  });
});
