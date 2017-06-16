'use strict';

var assert = require('assert');
var fs = require('fs');
var GCSFilter = require('../lib/utils/gcs');
var util = require('../lib/utils/util');
var crypto = require('../lib/crypto/crypto');
var Block = require('../lib/primitives/block');
var Outpoint = require('../lib/primitives/outpoint');
var Address = require('../lib/primitives/address');

var raw = fs.readFileSync(__dirname + '/data/block928927.raw');
var block = Block.fromRaw(raw);

describe('GCS', function() {
  var key = crypto.randomBytes(16);
  var P = 20;
  var filter1, filter2, filter3, filter4, filter5;
  var contents1, contents2;
  var op1, op2, op3, op4;
  var addr1, addr2;

  contents1 = [
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

  contents2 = [
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

  op1 = new Outpoint(
    '4cba1d1753ed19dbeafffb1a6c805d20e4af00b194a8f85353163cef83319c2c',
    4);

  op2 = new Outpoint(
    'b7c3c4bce1a23baef2da05f9b7e4bff813449ec7e80f980ec7e4cacfadcd3314',
    3);

  op3 = new Outpoint(
    '4cba1d1753ed19dbeafffb1a6c805d20e4af00b194a8f85353163cef83319c2c',
    400);

  op4 = new Outpoint(
    'b7c3c4bce1a23baef2da05f9b7e4bff813449ec7e80f980ec7e4cacfadcd3314',
    300);

  addr1 = new Address('bc1qmyrddmxglk49ye2wd29wefaavw7es8k5d555lx');
  addr2 = new Address('bc1q4645ycu0l9pnvxaxnhemushv0w4cd9flkqh95j');

  it('should test GCS filter build', function() {
    filter1 = GCSFilter.fromData(P, key, contents1);
    assert(filter1);
  });

  it('should test GCS filter copy', function() {
    filter2 = GCSFilter.fromBytes(filter1.n, P, filter1.toBytes());
    assert(filter2);
    filter3 = GCSFilter.fromNBytes(P, filter1.toNBytes());
    assert(filter3);
    filter4 = GCSFilter.fromPBytes(filter1.n, filter1.toPBytes());
    assert(filter4);
    filter5 = GCSFilter.fromNPBytes(filter1.toNPBytes());
    assert(filter5);
  });

  it('should test GCS filter metadata', function() {
    assert.equal(filter1.p, P);
    assert.equal(filter1.n, contents1.length);
    assert.equal(filter1.p, filter2.p);
    assert.equal(filter1.n, filter2.n);
    assert.deepEqual(filter1.data, filter2.data);
    assert.equal(filter1.p, filter3.p);
    assert.equal(filter1.n, filter3.n);
    assert.deepEqual(filter1.data, filter3.data);
    assert.equal(filter1.p, filter4.p);
    assert.equal(filter1.n, filter4.n);
    assert.deepEqual(filter1.data, filter4.data);
    assert.equal(filter1.p, filter5.p);
    assert.equal(filter1.n, filter5.n);
    assert.deepEqual(filter1.data, filter5.data);
  });

  it('should test GCS filter match', function() {
    var match = filter1.match(key, Buffer.from('Nate'));
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
  });

  it('should test GCS filter matchAny', function() {
    var c, match;

    match = filter1.matchAny(key, contents2);
    assert(!match);
    match = filter2.matchAny(key, contents2);
    assert(!match);

    c = contents2.slice();
    c.push(Buffer.from('Nate'));

    match = filter1.matchAny(key, c);
    assert(match);
    match = filter2.matchAny(key, c);
    assert(match);
  });

  it('should test GCS filter fromBlock', function() {
    var key = block.hash().slice(0, 16);
    var filter = GCSFilter.fromBlock(block);
    assert(filter.match(key, op1.toRaw()));
    assert(filter.match(key, op2.toRaw()));
    assert(!filter.match(key, op3.toRaw()));
    assert(!filter.match(key, op4.toRaw()));
    assert(filter.match(key, addr1.hash));
    assert(filter.match(key, addr2.hash));
    assert(filter.matchAny(key, [op1.toRaw(), addr1.hash]));
    assert(filter.matchAny(key, [op1.toRaw(), op3.toRaw()]));
    assert(!filter.matchAny(key, [op3.toRaw(), op4.toRaw()]));
  });

  it('should test GCS filter fromExtended', function() {
    var key = block.hash().slice(0, 16);
    var filter = GCSFilter.fromExtended(block);
    assert(!filter.match(key, op1.toRaw()));
    assert(filter.match(key, block.txs[0].hash()));
    assert(filter.match(key, block.txs[1].hash()));
    assert(filter.matchAny(key, [block.txs[0].hash(), block.txs[1].hash()]));
    assert(filter.matchAny(key, [op1.toRaw(), block.txs[1].hash()]));
    assert(!filter.matchAny(key, [op1.toRaw(), op2.toRaw()]));
  });
});
