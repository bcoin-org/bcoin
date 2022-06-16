/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const random = require('bcrypto/lib/random');
const assert = require('bsert');
const BasicFilter = require('../lib/golomb/basicFilter');
const {U64} = require('n64');
const Golomb = require('../lib/golomb/golomb');

const key = random.randomBytes(16);

const contents1 = [
  Buffer.from('Alex', 'ascii'),
  Buffer.from('Bob', 'ascii'),
  Buffer.from('Charlie', 'ascii'),
  Buffer.from('Dick', 'ascii'),
  Buffer.from('Ed', 'ascii'),
  Buffer.from('Frank', 'ascii'),
  Buffer.from('George', 'ascii'),
  Buffer.from('Harry', 'ascii'),
  Buffer.from('Ilya', 'ascii'),
  Buffer.from('John', 'ascii'),
  Buffer.from('Kevin', 'ascii'),
  Buffer.from('Larry', 'ascii'),
  Buffer.from('Michael', 'ascii'),
  Buffer.from('Nate', 'ascii'),
  Buffer.from('Owen', 'ascii'),
  Buffer.from('Paul', 'ascii'),
  Buffer.from('Quentin', 'ascii')
];

const contents2 = [
  Buffer.from('Alice', 'ascii'),
  Buffer.from('Betty', 'ascii'),
  Buffer.from('Charmaine', 'ascii'),
  Buffer.from('Donna', 'ascii'),
  Buffer.from('Edith', 'ascii'),
  Buffer.from('Faina', 'ascii'),
  Buffer.from('Georgia', 'ascii'),
  Buffer.from('Hannah', 'ascii'),
  Buffer.from('Ilsbeth', 'ascii'),
  Buffer.from('Jennifer', 'ascii'),
  Buffer.from('Kayla', 'ascii'),
  Buffer.from('Lena', 'ascii'),
  Buffer.from('Michelle', 'ascii'),
  Buffer.from('Natalie', 'ascii'),
  Buffer.from('Ophelia', 'ascii'),
  Buffer.from('Peggy', 'ascii'),
  Buffer.from('Queenie', 'ascii')
];

describe('GCS', function() {
  let filter1 = null;
  let filter2 = null;
  let filter3 = null;
  const basicFilter = new BasicFilter();
  const testFilter = new Golomb(25, new U64(786515));
  let testFilter1 = null;
  let testFilter2 = null;
  let testFilter3 = null;

  it('should test GCS filter build', () => {
    filter1 = basicFilter.fromItems(key, contents1);
    assert(filter1);
    testFilter1 = testFilter.fromItems(key, contents1);
    assert(testFilter1);
  });

  it('should test GCS filter copy', () => {
    filter2 = basicFilter.fromBytes(filter1.n, filter1.toBytes());
    assert(filter2);
    testFilter2 = testFilter.fromBytes(testFilter1.n, testFilter1.toBytes());
    assert(testFilter2);
    filter3 = basicFilter.fromNBytes(filter1.toNBytes());
    assert(filter3);
    testFilter3 = testFilter.fromNBytes(testFilter1.toNBytes());
    assert(testFilter3);
  });

  it('should test GCS filter metadata', () => {
    assert.strictEqual(filter1.n, contents1.length);
    assert.strictEqual(filter1.p, filter2.p);
    assert.strictEqual(filter1.n, filter2.n);
    assert.bufferEqual(filter1.data, filter2.data);
    assert.strictEqual(filter1.p, filter3.p);
    assert.strictEqual(filter1.n, filter3.n);
    assert.bufferEqual(filter1.data, filter3.data);

    assert.strictEqual(testFilter1.n, filter1.n);
    assert.strictEqual(testFilter1.n, contents1.length);
    assert.strictEqual(testFilter1.p, testFilter2.p);
    assert.strictEqual(testFilter1.n, testFilter2.n);
    assert.bufferEqual(testFilter1.data, testFilter2.data);
    assert.strictEqual(testFilter1.p, testFilter3.p);
    assert.strictEqual(testFilter1.n, testFilter3.n);
    assert.bufferEqual(testFilter1.data, testFilter3.data);
  });

  it('should test GCS filter match', () => {
    let match = filter1.match(key, Buffer.from('Nate'));
    assert(match);
    match = filter2.match(key, Buffer.from('Nate'));
    assert(match);
    match = filter1.match(key, Buffer.from('Quentin'));
    assert(match);
    match = filter2.match(key, Buffer.from('Quentin'));
    assert(match);

    match = filter1.match(key, Buffer.from('Nates'));
    assert(!match);
    match = filter2.match(key, Buffer.from('Nates'));
    assert(!match);
    match = filter1.match(key, Buffer.from('Quentins'));
    assert(!match);
    match = filter2.match(key, Buffer.from('Quentins'));
    assert(!match);

    match = testFilter1.match(key, Buffer.from('Nate'));
    assert(match);
    match = testFilter2.match(key, Buffer.from('Nate'));
    assert(match);
    match = testFilter1.match(key, Buffer.from('Quentin'));
    assert(match);
    match = testFilter2.match(key, Buffer.from('Quentin'));
    assert(match);

    match = testFilter1.match(key, Buffer.from('Nates'));
    assert(!match);
    match = testFilter2.match(key, Buffer.from('Nates'));
    assert(!match);
    match = testFilter1.match(key, Buffer.from('Quentins'));
    assert(!match);
    match = testFilter2.match(key, Buffer.from('Quentins'));
    assert(!match);
  });

  it('should test GCS filter matchAny', () => {
    let match = filter1.matchAny(key, contents2);
    assert(!match);
    match = filter2.matchAny(key, contents2);
    assert(!match);

    const contents = contents2.slice();
    contents.push(Buffer.from('Nate'));

    match = filter1.matchAny(key, contents);
    assert(match);
    match = filter2.matchAny(key, contents);
    assert(match);
  });
});
