'use strict';

var fs = require('fs');
var assert = require('assert');
var Bloom = require('../lib/utils/bloom');
var Block = require('../lib/primitives/block');
var Headers = require('../lib/primitives/headers');
var MerkleBlock = require('../lib/primitives/merkleblock');
var CoinView = require('../lib/coins/coinview');
var Coin = require('../lib/primitives/coin');
var Coins = require('../lib/coins/coins');
var UndoCoins = require('../lib/coins/undocoins');
var consensus = require('../lib/protocol/consensus');
var Script = require('../lib/script/script');
var encoding = require('../lib/utils/encoding');
var bip152 = require('../lib/net/bip152');

var block300025 = require('./data/block300025.json');
var cmpct1 = fs.readFileSync(__dirname + '/data/compactblock.hex', 'utf8');
var cmpct2 = fs.readFileSync(__dirname + '/data/cmpct2', 'utf8');
var cmpct2block = fs.readFileSync(__dirname + '/data/cmpct2.bin');

cmpct1 = cmpct1.trim().split('\n');
cmpct2 = cmpct2.trim();

function applyUndo(block, undo) {
  var view = new CoinView();
  var i, j, tx, input, prev, coins;

  for (i = block.txs.length - 1; i > 0; i--) {
    tx = block.txs[i];

    for (j = tx.inputs.length - 1; j >= 0; j--) {
      input = tx.inputs[j];
      prev = input.prevout.hash;

      if (!view.has(prev)) {
        assert(!undo.isEmpty());

        if (undo.top().height === -1) {
          coins = new Coins();
          coins.hash = prev;
          coins.coinbase = false;
          view.add(coins);
        }
      }

      undo.apply(view, input.prevout);
    }
  }

  assert(undo.isEmpty(), 'Undo coins data inconsistency.');

  return view;
}

describe('Block', function() {
  var mblock, raw, block, raw2;

  mblock = new MerkleBlock({
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
  raw = mblock.toRaw().toString('hex');

  raw2 = '02000000d1831d4411bdfda89d9d8c842b541beafd1437fc560dbe5c0'
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

  mblock = MerkleBlock.fromRaw(raw2, 'hex');

  this.timeout(10000);

  it('should parse partial merkle tree', function() {
    var tree;

    assert(mblock.verifyPOW());
    assert(mblock.verifyBody());
    assert(mblock.verify());

    tree = mblock.getTree();

    assert.equal(tree.matches.length, 2);
    assert.equal(mblock.hash('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.equal(mblock.rhash(),
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.equal(
      tree.matches[0].toString('hex'),
      '7393f84cd04ca8931975c66282ebf1847c78d8de6c2578d4f9bae23bc6f30857');
    assert.equal(
      tree.matches[1].toString('hex'),
      'ec8c51de3170301430ec56f6703533d9ea5b05c6fa7068954bcb90eed8c2ee5c');
  });

  it('should decode/encode with parser/framer', function() {
    var b = MerkleBlock.fromRaw(raw, 'hex');
    assert.equal(b.toRaw().toString('hex'), raw);
    assert.equal(raw, raw2);
  });

  it('should be verifiable', function() {
    var b = MerkleBlock.fromRaw(raw, 'hex');
    assert(b.verify());
  });

  it('should be serialized and deserialized and still verify', function() {
    var raw = mblock.toRaw();
    var b = MerkleBlock.fromRaw(raw);
    assert.deepEqual(b.toRaw(), raw);
    assert(b.verify());
  });

  it('should be jsonified and unjsonified and still verify', function() {
    var raw = mblock.toJSON();
    var b = MerkleBlock.fromJSON(raw);
    assert.deepEqual(b.toJSON(), raw);
    assert(b.verify());
  });

  it('should calculate reward properly', function() {
    var height = 0;
    var total = 0;
    var reward;

    for (;;) {
      reward = consensus.getReward(height, 210000);
      assert(reward <= consensus.COIN * 50);
      total += reward;
      if (reward === 0)
        break;
      height++;
    }

    assert.equal(height, 6930000);
    assert.equal(total, 2099999997690000);
  });

  it('should parse JSON', function() {
    block = Block.fromJSON(block300025);
    assert.equal(block.hash('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.equal(block.rhash(),
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.equal(block.merkleRoot, block.createMerkleRoot('hex'));
  });

  it('should create a merkle block', function() {
    var filter, item1, item2, mblock2;

    filter = Bloom.fromRate(1000, 0.01, Bloom.flags.NONE);

    item1 = '8e7445bbb8abd4b3174d80fa4c409fea6b94d96b';
    item2 = '047b00000078da0dca3b0ec2300c00d0ab4466ed10'
      + 'e763272c6c9ca052972c69e3884a9022084215e2eef'
      + '0e6f781656b5d5a87231cd4349e534b6dea55ad4ff55e';

    filter.add(item1, 'hex');
    filter.add(item2, 'hex');

    mblock2 = MerkleBlock.fromBlock(block, filter);

    assert(mblock2.verifyBody());
    assert.deepEqual(mblock2.toRaw(), mblock.toRaw());
  });

  it('should verify a historical block', function() {
    var view = new CoinView();
    var height = block300025.height;
    var sigops = 0;
    var reward = 0;
    var i, j, tx, input, coin, flags;

    for (i = 1; i < block300025.txs.length; i++) {
      tx = block300025.txs[i];
      for (j = 0; j < tx.inputs.length; j++) {
        input = tx.inputs[j];
        coin = Coin.fromJSON(input.coin);
        view.addCoin(coin);
      }
    }

    assert(block.verify());
    assert(block.txs[0].isCoinbase());
    assert(block.txs[0].isSane());
    assert(!block.hasWitness());
    assert.equal(block.getWeight(), 1136924);

    flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;

    for (i = 1; i < block.txs.length; i++) {
      tx = block.txs[i];
      assert(tx.isSane());
      assert(tx.checkInputs(view, height));
      assert(tx.verify(view, flags));
      assert(!tx.hasWitness());
      sigops += tx.getSigopsCost(view, flags);
      view.addTX(tx, height);
      reward += tx.getFee(view);
    }

    reward += consensus.getReward(height, 210000);

    assert.equal(sigops, 5280);
    assert.equal(reward, 2507773345);
    assert.equal(reward, block.txs[0].outputs[0].value);
  });

  it('should fail with a bad merkle root', function() {
    var block2 = new Block(block);
    var ret = {};
    block2.merkleRoot = encoding.NULL_HASH;
    block2.refresh();
    assert(!block2.verifyPOW());
    assert(!block2.verifyBody(ret));
    assert(!block2.verify());
    assert.equal(ret.reason, 'bad-txnmrklroot');
    block2.merkleRoot = block.merkleRoot;
    block2.refresh();
    assert(block2.verify());
  });

  it('should fail on merkle block with a bad merkle root', function() {
    var mblock2 = new MerkleBlock(mblock);
    var ret = {};
    mblock2.merkleRoot = encoding.NULL_HASH;
    mblock2.refresh();
    assert(!mblock2.verifyPOW());
    assert(!mblock2.verifyBody(ret));
    assert(!mblock2.verify());
    assert.equal(ret.reason, 'bad-txnmrklroot');
    mblock2.merkleRoot = mblock.merkleRoot;
    mblock2.refresh();
    assert(mblock2.verify());
  });

  it('should fail with a low target', function() {
    var block2 = new Block(block);
    block2.bits = 403014710;
    block2.refresh();
    assert(!block2.verifyPOW());
    assert(block2.verifyBody());
    assert(!block2.verify());
    block2.bits = block.bits;
    block2.refresh();
    assert(block2.verify());
  });

  it('should fail on duplicate txs', function() {
    var block2 = new Block(block);
    var ret = {};
    block2.txs.push(block2.txs[block2.txs.length - 1]);
    block2.refresh();
    assert(!block2.verifyBody(ret));
    assert.equal(ret.reason, 'bad-txns-duplicate');
  });

  it('should verify with headers', function() {
    var headers = new Headers(block);
    assert(headers.verifyPOW());
    assert(headers.verifyBody());
    assert(headers.verify());
  });

  it('should handle compact block', function() {
    var block = Block.fromRaw(cmpct1[1], 'hex');
    var cblock1 = bip152.CompactBlock.fromRaw(cmpct1[0], 'hex');
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    var map = {};
    var i, tx, mempool, result;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct1[0]);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct1[0]);

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    mempool = {
      getSnapshot: function() {
        return Object.keys(map);
      },
      getTX: function(hash) {
        return map[hash];
      }
    };

    assert.equal(cblock1.sid(block.txs[1].hash()), 125673511480291);

    result = cblock1.fillMempool(false, mempool);
    assert(result);

    for (i = 0; i < cblock1.available.length; i++)
      assert(cblock1.available[i]);

    assert.equal(
      cblock1.toBlock().toRaw().toString('hex'),
      block.toRaw().toString('hex'));
  });

  it('should handle half-full compact block', function() {
    var block = Block.fromRaw(cmpct1[1], 'hex');
    var cblock1 = bip152.CompactBlock.fromRaw(cmpct1[0], 'hex');
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    var map = {};
    var i, tx, mid, keys, mempool, result, req, res;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct1[0]);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct1[0]);

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    mid = block.txs.length >>> 1;
    keys = Object.keys(map).slice(0, mid);

    mempool = {
      getSnapshot: function() {
        return keys;
      },
      getTX: function(hash) {
        return map[hash];
      }
    };

    assert.equal(cblock1.sid(block.txs[1].hash()), 125673511480291);

    result = cblock1.fillMempool(false, mempool);
    assert(!result);

    req = cblock1.toRequest();
    assert.equal(req.hash, cblock1.hash('hex'));
    assert.deepEqual(req.indexes, [5, 6, 7, 8, 9]);

    req = bip152.TXRequest.fromRaw(req.toRaw());
    assert.equal(req.hash, cblock1.hash('hex'));
    assert.deepEqual(req.indexes, [5, 6, 7, 8, 9]);

    res = bip152.TXResponse.fromBlock(block, req);
    res = bip152.TXResponse.fromRaw(res.toRaw());

    result = cblock1.fillMissing(res);
    assert(result);

    for (i = 0; i < cblock1.available.length; i++)
      assert(cblock1.available[i]);

    assert.equal(
      cblock1.toBlock().toRaw().toString('hex'),
      block.toRaw().toString('hex'));
  });

  it('should handle compact block', function() {
    var block = Block.fromRaw(cmpct2block);
    var cblock1 = bip152.CompactBlock.fromRaw(cmpct2, 'hex');
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    var map = {};
    var i, tx, result, mempool;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct2);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct2);

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    mempool = {
      getSnapshot: function() {
        return Object.keys(map);
      },
      getTX: function(hash) {
        return map[hash];
      }
    };

    result = cblock1.fillMempool(false, mempool);
    assert(result);

    for (i = 0; i < cblock1.available.length; i++)
      assert(cblock1.available[i]);

    assert.equal(
      cblock1.toBlock().toRaw().toString('hex'),
      block.toRaw().toString('hex'));
  });

  it('should handle half-full compact block', function() {
    var block = Block.fromRaw(cmpct2block);
    var cblock1 = bip152.CompactBlock.fromRaw(cmpct2, 'hex');
    var cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    var map = {};
    var i, tx, mid, keys, mempool, result, req, res;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct2);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct2);

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      map[tx.hash('hex')] = tx;
    }

    mid = block.txs.length >>> 1;
    keys = Object.keys(map).slice(0, mid);

    mempool = {
      getSnapshot: function() {
        return keys;
      },
      getTX: function(hash) {
        return map[hash];
      }
    };

    result = cblock1.fillMempool(false, mempool);
    assert(!result);

    req = cblock1.toRequest();
    assert.equal(req.hash, cblock1.hash('hex'));

    req = bip152.TXRequest.fromRaw(req.toRaw());
    assert.equal(req.hash, cblock1.hash('hex'));

    res = bip152.TXResponse.fromBlock(block, req);
    res = bip152.TXResponse.fromRaw(res.toRaw());

    result = cblock1.fillMissing(res);
    assert(result);

    for (i = 0; i < cblock1.available.length; i++)
      assert(cblock1.available[i]);

    assert.equal(
      cblock1.toBlock().toRaw().toString('hex'),
      block.toRaw().toString('hex'));
  });

  it('should count sigops for block 928828 (testnet)', function() {
    var blockRaw = fs.readFileSync(__dirname + '/data/block928828.raw');
    var undoRaw = fs.readFileSync(__dirname + '/data/undo928828.raw');
    var block = Block.fromRaw(blockRaw);
    var undo = UndoCoins.fromRaw(undoRaw);
    var view = applyUndo(block, undo);
    var sigops = 0;
    var flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;
    var i, tx;

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      sigops += tx.getSigopsCost(view, flags);
    }

    assert.equal(sigops, 23236);
    assert.equal(block.getWeight(), 2481560);
  });

  it('should count sigops for block 928927 (testnet)', function() {
    var blockRaw = fs.readFileSync(__dirname + '/data/block928927.raw');
    var undoRaw = fs.readFileSync(__dirname + '/data/undo928927.raw');
    var block = Block.fromRaw(blockRaw);
    var undo = UndoCoins.fromRaw(undoRaw);
    var view = applyUndo(block, undo);
    var sigops = 0;
    var flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;
    var i, tx;

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      sigops += tx.getSigopsCost(view, flags);
    }

    assert.equal(sigops, 10015);
    assert.equal(block.getWeight(), 3992391);
  });

  it('should count sigops for block 1087400 (testnet)', function() {
    var blockRaw = fs.readFileSync(__dirname + '/data/block1087400.raw');
    var undoRaw = fs.readFileSync(__dirname + '/data/undo1087400.raw');
    var block = Block.fromRaw(blockRaw);
    var undo = UndoCoins.fromRaw(undoRaw);
    var view = applyUndo(block, undo);
    var sigops = 0;
    var flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;
    var i, tx;

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      sigops += tx.getSigopsCost(view, flags);
    }

    assert.equal(sigops, 1298);
    assert.equal(block.getWeight(), 193331);
  });
});
