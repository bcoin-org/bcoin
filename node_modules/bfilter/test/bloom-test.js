/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const BloomFilter = require('../lib/bloom');
const RollingFilter = require('../lib/rolling');

describe('bfilter', function() {
  this.timeout(20000);

  it('should test and add stuff', () => {
    const filter = new BloomFilter(512, 10, 156);

    filter.add('hello', 'ascii');
    assert(filter.test('hello', 'ascii'));
    assert(!filter.test('hello!', 'ascii'));
    assert(!filter.test('ping', 'ascii'));

    filter.add('hello!', 'ascii');
    assert(filter.test('hello!', 'ascii'));
    assert(!filter.test('ping', 'ascii'));

    filter.add('ping', 'ascii');
    assert(filter.test('ping', 'ascii'));
  });

  it('should serialize to the correct format', () => {
    const filter = new BloomFilter(952, 6, 3624314491, BloomFilter.flags.NONE);
    const item1 = '8e7445bbb8abd4b3174d80fa4c409fea6b94d96b';
    const item2 = '047b00000078da0dca3b0ec2300c00d0ab4466ed10'
      + 'e763272c6c9ca052972c69e3884a9022084215e2eef'
      + '0e6f781656b5d5a87231cd4349e534b6dea55ad4ff55e';

    const expected = Buffer.from(''
      + '000000000000000000000000000000000000000000000000088004000000000000000'
      + '000000000200000000000000000000000000000000800000000000000000002000000'
      + '000000000000002000000000000000000000000000000000000000000040000200000'
      + '0000000001000000800000080000000',
      'hex');

    filter.add(item1, 'hex');
    filter.add(item2, 'hex');

    assert.strictEqual(filter.filter.toString('hex'), expected.toString('hex'));
  });

  it('should handle 1m ops with regular filter', () => {
    const filter = BloomFilter.fromRate(210000, 0.00001, -1);

    filter.tweak = 0xdeadbeef;

    // ~1m operations
    for (let i = 0; i < 1000; i++) {
      const str = 'foobar' + i;
      let j = i;
      filter.add(str, 'ascii');
      do {
        const str = 'foobar' + j;
        assert(filter.test(str, 'ascii'));
        assert(!filter.test(str + '-', 'ascii'));
      } while (j--);
    }
  });

  it('should handle 1m ops with rolling filter', () => {
    const filter = new RollingFilter(210000, 0.00001);

    filter.tweak = 0xdeadbeef;

    // ~1m operations
    for (let i = 0; i < 1000; i++) {
      const str = 'foobar' + i;
      let j = i;
      filter.add(str, 'ascii');
      do {
        const str = 'foobar' + j;
        assert(filter.test(str, 'ascii'));
        assert(!filter.test(str + '-', 'ascii'));
      } while (j--);
    }
  });

  it('should handle rolling generations', () => {
    const filter = new RollingFilter(50, 0.00001);

    filter.tweak = 0xdeadbeee;

    for (let i = 0; i < 25; i++) {
      const str = 'foobar' + i;
      let j = i;
      filter.add(str, 'ascii');
      do {
        const str = 'foobar' + j;
        assert(filter.test(str, 'ascii'));
        assert(!filter.test(str + '-', 'ascii'));
      } while (j--);
    }

    for (let i = 25; i < 50; i++) {
      const str = 'foobar' + i;
      let j = i;
      filter.add(str, 'ascii');
      do {
        const str = 'foobar' + j;
        assert(filter.test(str, 'ascii'));
        assert(!filter.test(str + '-', 'ascii'));
      } while (j--);
    }

    for (let i = 50; i < 75; i++) {
      const str = 'foobar' + i;
      let j = i;
      filter.add(str, 'ascii');
      do {
        const str = 'foobar' + j;
        assert(filter.test(str, 'ascii'));
        assert(!filter.test(str + '-', 'ascii'));
      } while (j--);
    }

    for (let i = 75; i < 100; i++) {
      const str = 'foobar' + i;
      let j = i;
      filter.add(str, 'ascii');
      do {
        const str = 'foobar' + j;
        assert(filter.test(str, 'ascii'));
        assert(!filter.test(str + '-', 'ascii'));
      } while (j-- > 25);
      assert(!filter.test('foobar 24', 'ascii'));
    }

    for (let i = 100; i < 125; i++) {
      const str = 'foobar' + i;
      let j = i;
      filter.add(str, 'ascii');
      do {
        const str = 'foobar' + j;
        assert(filter.test(str, 'ascii'));
        assert(!filter.test(str + '-', 'ascii'));
      } while (j-- > 50);
    }

    assert(!filter.test('foobar 49', 'ascii'));
  });
});
