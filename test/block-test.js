'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var util = bcoin.util;
var btcutils = require('../lib/btc/utils');
var crypto = require('../lib/crypto/crypto');
var Bloom = require('../lib/utils/bloom');
var constants = bcoin.constants;
var network = bcoin.networks;
var assert = require('assert');
var block300025 = require('./data/block300025.json');
var fs = require('fs');
var cmpct = fs.readFileSync(__dirname + '/data/compactblock.hex', 'utf8').trim().split('\n');
var bip152 = require('../lib/net/bip152');
var cmpct2 = fs.readFileSync(__dirname + '/data/cmpct2', 'utf8').trim();
var cmpct2block = fs.readFileSync(__dirname + '/data/cmpct2.bin');

bcoin.cache();

describe('Block', function() {
  var mblock = bcoin.merkleblock({
    version: 2,
    prevBlock: 'd1831d4411bdfda89d9d8c842b541beafd1437fc560dbe5c0000000000000000',
    merkleRoot: '28bec1d35af480ba3884553d72694f6ba6c163a5c081d7e6edaec15f373f19af',
    ts: 1399713634,
    bits: 419465580,
    nonce: 1186968784,
    totalTX: 461,
    hashes: [
      '7d22e53bce1bbb3294d1a396c5acc45bdcc8f192cb492f0d9f55421fd4c62de1',
      '9d6d585fdaf3737b9a54aaee1dd003f498328d699b7dfb42dd2b44b6ebde2333',
      '8b61da3053d6f382f2145bdd856bc5dcf052c3a11c1784d3d51b2cbe0f6d0923',
      'd7bbaae4716cb0d329d755b707cee588cddc68601f99bc05fef1fabeb8dfe4a0',
      '7393f84cd04ca8931975c66282ebf1847c78d8de6c2578d4f9bae23bc6f30857',
      'ec8c51de3170301430ec56f6703533d9ea5b05c6fa7068954bcb90eed8c2ee5c',
      'c7c152869db09a5ae2291fa03142912d9d7aba75be7d491a8ac4230ee9a920cb',
      '5adbf04583354515a225f2c418de7c5cdac4cef211820c79717cd2c50412153f',
      '1f5e46b9da3a8b1241f4a1501741d3453bafddf6135b600b926e3f4056c6d564',
      '33825657ba32afe269819f01993bd77baba86379043168c94845d32370e53562'
    ],
    flags: new Buffer([245, 122, 0])
  });
  var raw = mblock.toRaw().toString('hex');
  var block;

  var raw2 = '02000000d1831d4411bdfda89d9d8c842b541beafd1437fc560dbe5c0'
    + '00000000000000028bec1d35af480ba3884553d72694f6ba6c163a5c081d7e6edaec'
    + '15f373f19af62ef6d536c890019d0b4bf46cd0100000a7d22e53bce1bbb3294d1a39'
    + '6c5acc45bdcc8f192cb492f0d9f55421fd4c62de19d6d585fdaf3737b9a54aaee1dd'
    + '003f498328d699b7dfb42dd2b44b6ebde23338b61da3053d6f382f2145bdd856bc5d'
    + 'cf052c3a11c1784d3d51b2cbe0f6d0923d7bbaae4716cb0d329d755b707cee588cdd'
    + 'c68601f99bc05fef1fabeb8dfe4a07393f84cd04ca8931975c66282ebf1847c78d8d'
    + 'e6c2578d4f9bae23bc6f30857ec8c51de3170301430ec56f6703533d9ea5b05c6fa7'
    + '068954bcb90eed8c2ee5cc7c152869db09a5ae2291fa03142912d9d7aba75be7d491'
    + 'a8ac4230ee9a920cb5adbf04583354515a225f2c418de7c5cdac4cef211820c79717'
    + 'cd2c50412153f1f5e46b9da3a8b1241f4a1501741d3453bafddf6135b600b926e3f4'
    + '056c6d56433825657ba32afe269819f01993bd77baba86379043168c94845d32370e'
    + '5356203f57a00';

  var mblock = bcoin.merkleblock.fromRaw(raw2, 'hex');

  this.timeout(10000);

  it('should parse partial merkle tree', function() {
    assert(mblock.verify());
    assert.equal(mblock.matches.length, 2);
    assert.equal(mblock.hash('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.equal(mblock.rhash,
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.equal(
      mblock.matches[0].toString('hex'),
      '7393f84cd04ca8931975c66282ebf1847c78d8de6c2578d4f9bae23bc6f30857');
    assert.equal(
      mblock.matches[1].toString('hex'),
      'ec8c51de3170301430ec56f6703533d9ea5b05c6fa7068954bcb90eed8c2ee5c');
  });

  it('should decode/encode with parser/framer', function() {
    var b = bcoin.merkleblock.fromRaw(raw, 'hex');
    assert.equal(b.toRaw().toString('hex'), raw);
    assert.equal(raw, raw2);
  });

  it('should be verifiable', function() {
    var b = bcoin.merkleblock.fromRaw(raw, 'hex');
    assert(b.verify());
  });

  it('should be serialized and deserialized and still verify', function() {
    var raw = mblock.toRaw();
    var b = bcoin.merkleblock.fromRaw(raw);
    assert.deepEqual(b.toRaw(), raw);
    assert(b.verify());
  });

  it('should be jsonified and unjsonified and still verify', function() {
    var raw = mblock.toJSON();
    var b = bcoin.merkleblock.fromJSON(raw);
    assert.deepEqual(b.toJSON(), raw);
    assert(b.verify());
  });

  it('should calculate reward properly', function() {
    var height = 0;
    var total = 0;
    var reward;

    for (;;) {
      reward = btcutils.getReward(height, 210000);
      assert(reward <= constants.COIN * 50);
      total += reward;
      if (reward === 0)
        break;
      height++;
    }

    assert.equal(height, 6930000);
    assert.equal(total, 2099999997690000);
  });

  it('should parse JSON', function() {
    block = bcoin.block.fromJSON(block300025);
    assert.equal(block.hash('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.equal(block.rhash,
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.equal(block.merkleRoot, block.createMerkleRoot('hex'));
  });

  it('should create a merkle block', function() {
    var filter = Bloom.fromRate(1000, 0.01, constants.filterFlags.NONE);
    var item1 = '8e7445bbb8abd4b3174d80fa4c409fea6b94d96b';
    var item2 = '047b00000078da0dca3b0ec2300c00d0ab4466ed10'
      + 'e763272c6c9ca052972c69e3884a9022084215e2eef'
      + '0e6f781656b5d5a87231cd4349e534b6dea55ad4ff55e';
    filter.add(item1, 'hex');
    filter.add(item2, 'hex');
    var mblock2 = bcoin.merkleblock.fromBlock(block, filter);
    assert(mblock2.verifyPartial());
    assert.deepEqual(mblock2.toRaw(), mblock.toRaw());
  });

  it('should verify a historical block', function() {
    assert(block.verify());
    assert(block.txs[0].isCoinbase());
    assert(block.txs[0].isSane());
    assert(!block.hasWitness());
    assert.equal(block.getWeight(), 1136924);
    var flags = constants.flags.VERIFY_P2SH | constants.flags.VERIFY_DERSIG;
    for (var i = 1; i < block.txs.length; i++) {
      var tx = block.txs[i];
      assert(tx.isSane());
      assert(tx.checkInputs(block.height));
      assert(tx.verify(flags));
      assert(!tx.hasWitness());
    }
    assert.equal(block.getReward(), 2507773345);
    assert.equal(block.getReward(), block.txs[0].outputs[0].value);
  });

  it('should fail with a bad merkle root', function() {
    var block2 = new bcoin.block(block);
    block2.hash();
    block2.merkleRoot = constants.NULL_HASH;
    delete block2._valid;
    var ret = {};
    assert(!block2.verify(0, ret));
    assert.equal(ret.reason, 'bad-txnmrklroot');
    delete block2._valid;
    delete block2._hash;
    block2.merkleRoot = block.merkleRoot;
    assert(block2.verify());
  });

  it('should fail on merkle block with a bad merkle root', function() {
    var mblock2 = new bcoin.merkleblock(mblock);
    mblock2.hash();
    mblock2.merkleRoot = constants.NULL_HASH;
    var ret = {};
    assert(!mblock2.verify(0, ret));
    assert.equal(ret.reason, 'bad-txnmrklroot');
    delete mblock2._validPartial;
    delete mblock2._valid;
    delete mblock2._hash;
    mblock2.merkleRoot = mblock.merkleRoot;
    assert(mblock2.verify());
  });

  it('should fail with a low target', function() {
    var block2 = new bcoin.block(block);
    block2.hash();
    block2.bits = 403014710;
    var ret = {};
    assert(!block2.verify(0, ret));
    assert.equal(ret.reason, 'high-hash');
    delete block2._valid;
    delete block2._hash;
    block2.bits = block.bits;
    assert(block2.verify());
  });

  it('should fail on duplicate txs', function() {
    var block2 = new bcoin.block(block);
    block2.txs.push(block2.txs[block2.txs.length - 1]);
    var ret = {};
    assert(!block2.verify(0, ret));
    assert.equal(ret.reason, 'bad-txns-duplicate');
  });

  it('should verify with headers', function() {
    var headers = new bcoin.headers(block);
    assert(headers.verify());
  });

  it('should handle compact block', function(cb) {
    var cblock = bip152.CompactBlock.fromRaw(cmpct[0], 'hex');
    var block = bcoin.block.fromRaw(cmpct[1], 'hex');
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock.keyNonce);
    var map = {};

    assert.equal(cblock.toRaw().toString('hex'), cmpct[0]);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct[0]);

    for (var i = 0; i < block.txs.length; i++) {
      var tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    var fakeMempool = {
      getSnapshot: function(callback) {
        return Object.keys(map);
      },
      getTX: function(hash, callback) {
        return map[hash];
      }
    };

    assert.equal(cblock.sid(block.txs[1].hash()), 125673511480291);

    var result = cblock.fillMempool(false, fakeMempool);
    assert(result);
    for (var i = 0; i < cblock.available.length; i++)
      assert(cblock.available[i]);
    assert.equal(cblock.toBlock().toRaw().toString('hex'), block.toRaw().toString('hex'));
    cb();
  });

  it('should handle half-full compact block', function(cb) {
    var cblock = bip152.CompactBlock.fromRaw(cmpct[0], 'hex');
    var block = bcoin.block.fromRaw(cmpct[1], 'hex');
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock.keyNonce);
    var map = {};

    assert.equal(cblock.toRaw().toString('hex'), cmpct[0]);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct[0]);

    for (var i = 0; i < block.txs.length; i++) {
      var tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    var mid = block.txs.length >>> 1;
    var keys = Object.keys(map).slice(0, mid);

    var fakeMempool = {
      getSnapshot: function(callback) {
        return keys;
      },
      getTX: function(hash, callback) {
        return map[hash];
      }
    };

    assert.equal(cblock.sid(block.txs[1].hash()), 125673511480291);

    var result = cblock.fillMempool(false, fakeMempool);
    assert(!result);

    var req = cblock.toRequest();
    assert.equal(req.hash, cblock.hash('hex'));
    assert.deepEqual(req.indexes, [5, 6, 7, 8, 9]);

    req = bip152.TXRequest.fromRaw(req.toRaw());
    assert.equal(req.hash, cblock.hash('hex'));
    assert.deepEqual(req.indexes, [5, 6, 7, 8, 9]);

    var res = bip152.TXResponse.fromBlock(block, req);
    res = bip152.TXResponse.fromRaw(res.toRaw());

    var result = cblock.fillMissing(res);
    assert(result);

    for (var i = 0; i < cblock.available.length; i++)
      assert(cblock.available[i]);

    assert.equal(cblock.toBlock().toRaw().toString('hex'), block.toRaw().toString('hex'));

    cb();
  });

  it('should handle compact block', function(cb) {
    var cblock = bip152.CompactBlock.fromRaw(cmpct2, 'hex');
    var block = bcoin.block.fromRaw(cmpct2block);
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock.keyNonce);
    var map = {};

    assert.equal(cblock.toRaw().toString('hex'), cmpct2);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct2);

    for (var i = 0; i < block.txs.length; i++) {
      var tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    var fakeMempool = {
      getSnapshot: function(callback) {
        return Object.keys(map);
      },
      getTX: function(hash, callback) {
        return map[hash];
      }
    };

    //assert.equal(cblock.sid(block.txs[1].hash()), 125673511480291);

    var result = cblock.fillMempool(false, fakeMempool);
    assert(result);
    for (var i = 0; i < cblock.available.length; i++)
      assert(cblock.available[i]);
    assert.equal(cblock.toBlock().toRaw().toString('hex'), block.toRaw().toString('hex'));
    cb();
  });

  it('should handle half-full compact block', function(cb) {
    var cblock = bip152.CompactBlock.fromRaw(cmpct2, 'hex');
    var block = bcoin.block.fromRaw(cmpct2block);
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock.keyNonce);
    var map = {};

    assert.equal(cblock.toRaw().toString('hex'), cmpct2);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct2);

    for (var i = 0; i < block.txs.length; i++) {
      var tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    var mid = block.txs.length >>> 1;
    var keys = Object.keys(map).slice(0, mid);

    var fakeMempool = {
      getSnapshot: function(callback) {
        return keys;
      },
      getTX: function(hash, callback) {
        return map[hash];
      }
    };

    //assert.equal(cblock.sid(block.txs[1].hash()), 125673511480291);

    var result = cblock.fillMempool(false, fakeMempool);
    assert(!result);

    var req = cblock.toRequest();
    assert.equal(req.hash, cblock.hash('hex'));
    //assert.deepEqual(req.indexes, [5, 6, 7, 8, 9]);

    req = bip152.TXRequest.fromRaw(req.toRaw());
    assert.equal(req.hash, cblock.hash('hex'));
    //assert.deepEqual(req.indexes, [5, 6, 7, 8, 9]);

    var res = bip152.TXResponse.fromBlock(block, req);
    res = bip152.TXResponse.fromRaw(res.toRaw());

    var result = cblock.fillMissing(res);
    assert(result);

    for (var i = 0; i < cblock.available.length; i++)
      assert(cblock.available[i]);

    assert.equal(cblock.toBlock().toRaw().toString('hex'), block.toRaw().toString('hex'));

    cb();
  });
});
