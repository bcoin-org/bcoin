var assert = require('assert');
var bcoin = require('../')();

describe('Bloom', function() {
  it('should do proper murmur3', function() {
    var h = bcoin.bloom.hash;

    assert.equal(h(new Buffer('', 'ascii'), 0), 0);
    assert.equal(h(new Buffer('', 'ascii'), 0xfba4c795), 0x6a396f08);
    assert.equal(h(new Buffer('00', 'ascii'), 0xfba4c795), 0x2a101837);
    assert.equal(h(new Buffer('hello world', 'ascii'), 0), 0x5e928f0f);
  });

  it('should test and add stuff', function() {
    var b = bcoin.bloom(512, 10, 156);

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
});
