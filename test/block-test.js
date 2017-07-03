'use strict';

const fs = require('fs');
const assert = require('assert');
const Bloom = require('../lib/utils/bloom');
const Block = require('../lib/primitives/block');
const Headers = require('../lib/primitives/headers');
const MerkleBlock = require('../lib/primitives/merkleblock');
const CoinView = require('../lib/coins/coinview');
const Coin = require('../lib/primitives/coin');
const UndoCoins = require('../lib/coins/undocoins');
const consensus = require('../lib/protocol/consensus');
const Script = require('../lib/script/script');
const encoding = require('../lib/utils/encoding');
const bip152 = require('../lib/net/bip152');

const block300025 = require('./data/block300025.json');
const cmpct2block = fs.readFileSync(`${__dirname}/data/cmpct2.bin`);

let cmpct1 = fs.readFileSync(`${__dirname}/data/compactblock.hex`, 'utf8');
let cmpct2 = fs.readFileSync(`${__dirname}/data/cmpct2`, 'utf8');

cmpct1 = cmpct1.trim().split('\n');
cmpct2 = cmpct2.trim();

function applyUndo(block, undo) {
  let view = new CoinView();

  for (let i = block.txs.length - 1; i > 0; i--) {
    let tx = block.txs[i];

    for (let j = tx.inputs.length - 1; j >= 0; j--) {
      let input = tx.inputs[j];
      undo.apply(view, input.prevout);
    }
  }

  assert(undo.isEmpty(), 'Undo coins data inconsistency.');

  return view;
}

describe('Block', function() {
  let mblock, raw, block, raw2;

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
    flags: Buffer.from([245, 122, 0])
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

  it('should parse partial merkle tree', () => {
    let tree;

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

  it('should decode/encode with parser/framer', () => {
    let b = MerkleBlock.fromRaw(raw, 'hex');
    assert.equal(b.toRaw().toString('hex'), raw);
    assert.equal(raw, raw2);
  });

  it('should be verifiable', () => {
    let b = MerkleBlock.fromRaw(raw, 'hex');
    assert(b.verify());
  });

  it('should be serialized and deserialized and still verify', () => {
    let raw = mblock.toRaw();
    let b = MerkleBlock.fromRaw(raw);
    assert.deepEqual(b.toRaw(), raw);
    assert(b.verify());
  });

  it('should be jsonified and unjsonified and still verify', () => {
    let raw = mblock.toJSON();
    let b = MerkleBlock.fromJSON(raw);
    assert.deepEqual(b.toJSON(), raw);
    assert(b.verify());
  });

  it('should calculate reward properly', () => {
    let height = 0;
    let total = 0;

    for (;;) {
      let reward = consensus.getReward(height, 210000);
      assert(reward <= consensus.COIN * 50);
      total += reward;
      if (reward === 0)
        break;
      height++;
    }

    assert.equal(height, 6930000);
    assert.equal(total, 2099999997690000);
  });

  it('should parse JSON', () => {
    block = Block.fromJSON(block300025);
    assert.equal(block.hash('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.equal(block.rhash(),
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.equal(block.merkleRoot, block.createMerkleRoot('hex'));
  });

  it('should create a merkle block', () => {
    let filter, item1, item2, mblock2;

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

  it('should verify a historical block', () => {
    let view = new CoinView();
    let height = block300025.height;
    let sigops = 0;
    let reward = 0;
    let flags;

    for (let i = 1; i < block300025.txs.length; i++) {
      let tx = block300025.txs[i];
      for (let j = 0; j < tx.inputs.length; j++) {
        let input = tx.inputs[j];
        let coin = Coin.fromJSON(input.coin);
        view.addCoin(coin);
      }
    }

    assert(block.verify());
    assert(block.txs[0].isCoinbase());
    assert(block.txs[0].isSane());
    assert(!block.hasWitness());
    assert.equal(block.getWeight(), 1136924);

    flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;

    for (let i = 1; i < block.txs.length; i++) {
      let tx = block.txs[i];
      assert(tx.isSane());
      assert(tx.verifyInputs(view, height));
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

  it('should fail with a bad merkle root', () => {
    let block2 = new Block(block);
    let reason;
    block2.merkleRoot = encoding.NULL_HASH;
    block2.refresh();
    assert(!block2.verifyPOW());
    [, reason] = block2.checkBody();
    assert.equal(reason, 'bad-txnmrklroot');
    assert(!block2.verify());
    block2.merkleRoot = block.merkleRoot;
    block2.refresh();
    assert(block2.verify());
  });

  it('should fail on merkle block with a bad merkle root', () => {
    let mblock2 = new MerkleBlock(mblock);
    let reason;
    mblock2.merkleRoot = encoding.NULL_HASH;
    mblock2.refresh();
    assert(!mblock2.verifyPOW());
    [, reason] = mblock2.checkBody();
    assert.equal(reason, 'bad-txnmrklroot');
    assert(!mblock2.verify());
    mblock2.merkleRoot = mblock.merkleRoot;
    mblock2.refresh();
    assert(mblock2.verify());
  });

  it('should fail with a low target', () => {
    let block2 = new Block(block);
    block2.bits = 403014710;
    block2.refresh();
    assert(!block2.verifyPOW());
    assert(block2.verifyBody());
    assert(!block2.verify());
    block2.bits = block.bits;
    block2.refresh();
    assert(block2.verify());
  });

  it('should fail on duplicate txs', () => {
    let block2 = new Block(block);
    let reason;
    block2.txs.push(block2.txs[block2.txs.length - 1]);
    block2.refresh();
    [, reason] = block2.checkBody();
    assert.equal(reason, 'bad-txns-duplicate');
  });

  it('should verify with headers', () => {
    let headers = new Headers(block);
    assert(headers.verifyPOW());
    assert(headers.verifyBody());
    assert(headers.verify());
  });

  it('should handle compact block', () => {
    let block = Block.fromRaw(cmpct1[1], 'hex');
    let cblock1 = bip152.CompactBlock.fromRaw(cmpct1[0], 'hex');
    let cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    let map = new Map();
    let i, tx, mempool, result;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct1[0]);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct1[0]);

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      map.set(tx.hash('hex'), { tx: tx });
    }

    mempool = {
      map: map
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

  it('should handle half-full compact block', () => {
    let block = Block.fromRaw(cmpct1[1], 'hex');
    let cblock1 = bip152.CompactBlock.fromRaw(cmpct1[0], 'hex');
    let cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    let map = new Map();
    let i, tx, mempool, result, req, res;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct1[0]);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct1[0]);

    for (i = 0; i < block.txs.length >>> 1; i++) {
      tx = block.txs[i];
      map.set(tx.hash('hex'), { tx: tx });
    }

    mempool = {
      map: map
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

  it('should handle compact block', () => {
    let block = Block.fromRaw(cmpct2block);
    let cblock1 = bip152.CompactBlock.fromRaw(cmpct2, 'hex');
    let cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    let map = new Map();
    let i, tx, result, mempool;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct2);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct2);

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      map.set(tx.hash('hex'), { tx: tx });
    }

    mempool = {
      map: map
    };

    result = cblock1.fillMempool(false, mempool);
    assert(result);

    for (i = 0; i < cblock1.available.length; i++)
      assert(cblock1.available[i]);

    assert.equal(
      cblock1.toBlock().toRaw().toString('hex'),
      block.toRaw().toString('hex'));
  });

  it('should handle half-full compact block', () => {
    let block = Block.fromRaw(cmpct2block);
    let cblock1 = bip152.CompactBlock.fromRaw(cmpct2, 'hex');
    let cblock2 = bip152.CompactBlock.fromBlock(block, false, cblock1.keyNonce);
    let map = new Map();
    let i, tx, mempool, result, req, res;

    assert(cblock1.init());

    assert.equal(cblock1.toRaw().toString('hex'), cmpct2);
    assert.equal(cblock2.toRaw().toString('hex'), cmpct2);

    for (i = 0; i < block.txs.length >>> 1; i++) {
      tx = block.txs[i];
      map.set(tx.hash('hex'), { tx: tx });
    }

    mempool = {
      map: map
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

  it('should count sigops for block 928828 (testnet)', () => {
    let blockRaw = fs.readFileSync(`${__dirname}/data/block928828.raw`);
    let undoRaw = fs.readFileSync(`${__dirname}/data/undo928828.raw`);
    let block = Block.fromRaw(blockRaw);
    let undo = UndoCoins.fromRaw(undoRaw);
    let view = applyUndo(block, undo);
    let sigops = 0;
    let flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;
    let i, tx;

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      sigops += tx.getSigopsCost(view, flags);
    }

    assert.equal(sigops, 23236);
    assert.equal(block.getWeight(), 2481560);
  });

  it('should count sigops for block 928927 (testnet)', () => {
    let blockRaw = fs.readFileSync(`${__dirname}/data/block928927.raw`);
    let undoRaw = fs.readFileSync(`${__dirname}/data/undo928927.raw`);
    let block = Block.fromRaw(blockRaw);
    let undo = UndoCoins.fromRaw(undoRaw);
    let view = applyUndo(block, undo);
    let sigops = 0;
    let flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;
    let i, tx;

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      sigops += tx.getSigopsCost(view, flags);
    }

    assert.equal(sigops, 10015);
    assert.equal(block.getWeight(), 3992391);
  });

  it('should count sigops for block 1087400 (testnet)', () => {
    let blockRaw = fs.readFileSync(`${__dirname}/data/block1087400.raw`);
    let undoRaw = fs.readFileSync(`${__dirname}/data/undo1087400.raw`);
    let block = Block.fromRaw(blockRaw);
    let undo = UndoCoins.fromRaw(undoRaw);
    let view = applyUndo(block, undo);
    let sigops = 0;
    let flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;
    let i, tx;

    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i];
      sigops += tx.getSigopsCost(view, flags);
    }

    assert.equal(sigops, 1298);
    assert.equal(block.getWeight(), 193331);
  });
});
