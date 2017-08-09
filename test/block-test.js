/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const fs = require('../lib/utils/fs');
const common = require('./util/common');
const Bloom = require('../lib/utils/bloom');
const Block = require('../lib/primitives/block');
const Headers = require('../lib/primitives/headers');
const MerkleBlock = require('../lib/primitives/merkleblock');
const consensus = require('../lib/protocol/consensus');
const Script = require('../lib/script/script');
const encoding = require('../lib/utils/encoding');
const bip152 = require('../lib/net/bip152');
const CompactBlock = bip152.CompactBlock;
const TXRequest = bip152.TXRequest;
const TXResponse = bip152.TXResponse;

// Block test vectors
const block300025 = fs.readFileSync(`${__dirname}/data/block300025.raw`);
const undo300025 = fs.readFileSync(`${__dirname}/data/undo300025.raw`);

// Merkle block test vectors
const merkle300025 = fs.readFileSync(`${__dirname}/data/merkle300025.raw`);

// Compact block test vectors
const block426884 = fs.readFileSync(`${__dirname}/data/block426884.raw`);
const compact426884 = fs.readFileSync(`${__dirname}/data/compact426884.raw`);
const block898352 = fs.readFileSync(`${__dirname}/data/block898352.raw`);
const compact898352 = fs.readFileSync(`${__dirname}/data/compact898352.raw`);

// Sigops counting test vectors
const block928927 = fs.readFileSync(`${__dirname}/data/block928927.raw`);
const undo928927 = fs.readFileSync(`${__dirname}/data/undo928927.raw`);
const block928828 = fs.readFileSync(`${__dirname}/data/block928828.raw`);
const undo928828 = fs.readFileSync(`${__dirname}/data/undo928828.raw`);
const block1087400 = fs.readFileSync(`${__dirname}/data/block1087400.raw`);
const undo1087400 = fs.readFileSync(`${__dirname}/data/undo1087400.raw`);

describe('Block', function() {
  const mblock = MerkleBlock.fromRaw(merkle300025);
  const block = Block.fromRaw(block300025);

  this.timeout(10000);

  it('should parse partial merkle tree', () => {
    assert(mblock.verifyPOW());
    assert(mblock.verifyBody());
    assert(mblock.verify());

    const tree = mblock.getTree();

    assert.strictEqual(tree.matches.length, 2);
    assert.strictEqual(mblock.hash('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.strictEqual(mblock.rhash(),
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.strictEqual(
      tree.matches[0].toString('hex'),
      '7393f84cd04ca8931975c66282ebf1847c78d8de6c2578d4f9bae23bc6f30857');
    assert.strictEqual(
      tree.matches[1].toString('hex'),
      'ec8c51de3170301430ec56f6703533d9ea5b05c6fa7068954bcb90eed8c2ee5c');
  });

  it('should decode/encode merkle block', () => {
    const merkle = MerkleBlock.fromRaw(merkle300025);
    merkle.refresh();
    assert.deepStrictEqual(merkle.toRaw(), merkle300025);
    assert.deepStrictEqual(merkle300025, mblock.toRaw());
  });

  it('should be verify merkle block', () => {
    const merkle = MerkleBlock.fromRaw(merkle300025);
    assert(merkle.verify());
  });

  it('should be encoded/decoded and still verify', () => {
    const raw = mblock.toRaw();
    const merkle = MerkleBlock.fromRaw(raw);
    assert.deepStrictEqual(merkle.toRaw(), raw);
    assert(merkle.verify());
  });

  it('should be jsonified/unjsonified and still verify', () => {
    const json = mblock.toJSON();
    const merkle = MerkleBlock.fromJSON(json);
    assert.deepStrictEqual(merkle.toJSON(), json);
    assert(merkle.verify());
  });

  it('should calculate reward properly', () => {
    let height = 0;
    let total = 0;

    for (;;) {
      const reward = consensus.getReward(height, 210000);
      assert(reward <= consensus.COIN * 50);
      total += reward;
      if (reward === 0)
        break;
      height++;
    }

    assert.strictEqual(height, 6930000);
    assert.strictEqual(total, 2099999997690000);
  });

  it('should parse JSON', () => {
    const block = Block.fromJSON(Block.fromRaw(block300025).toJSON());
    assert.strictEqual(block.hash('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.strictEqual(block.rhash(),
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.strictEqual(block.merkleRoot, block.createMerkleRoot('hex'));
  });

  it('should create a merkle block', () => {
    const filter = Bloom.fromRate(1000, 0.01, Bloom.flags.NONE);

    const item1 = '8e7445bbb8abd4b3174d80fa4c409fea6b94d96b';
    const item2 = '047b00000078da0dca3b0ec2300c00d0ab4466ed10'
      + 'e763272c6c9ca052972c69e3884a9022084215e2eef'
      + '0e6f781656b5d5a87231cd4349e534b6dea55ad4ff55e';

    filter.add(item1, 'hex');
    filter.add(item2, 'hex');

    const merkle = MerkleBlock.fromBlock(block, filter);

    assert(merkle.verifyBody());
    assert.deepStrictEqual(merkle.toRaw(), mblock.toRaw());
  });

  it('should verify a historical block', () => {
    const block = Block.fromRaw(block300025);
    const undo = common.parseUndo(undo300025);
    const view = common.applyUndo(block, undo);
    const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
    const height = 300025;

    assert(block.verify());
    assert(block.txs[0].isCoinbase());
    assert(block.txs[0].isSane());
    assert(!block.hasWitness());
    assert.strictEqual(block.getWeight(), 1136924);

    let sigops = 0;
    let reward = 0;

    for (let i = 1; i < block.txs.length; i++) {
      const tx = block.txs[i];
      assert(tx.isSane());
      assert(tx.verifyInputs(view, height));
      assert(tx.verify(view, flags));
      assert(!tx.hasWitness());
      sigops += tx.getSigopsCost(view, flags);
      view.addTX(tx, height);
      reward += tx.getFee(view);
    }

    reward += consensus.getReward(height, 210000);

    assert.strictEqual(sigops, 5280);
    assert.strictEqual(reward, 2507773345);
    assert.strictEqual(reward, block.txs[0].outputs[0].value);
  });

  it('should fail with a bad merkle root', () => {
    const block2 = new Block(block);
    block2.merkleRoot = encoding.NULL_HASH;
    block2.refresh();
    assert(!block2.verifyPOW());
    const [, reason] = block2.checkBody();
    assert.strictEqual(reason, 'bad-txnmrklroot');
    assert(!block2.verify());
    block2.merkleRoot = block.merkleRoot;
    block2.refresh();
    assert(block2.verify());
  });

  it('should fail on merkle block with a bad merkle root', () => {
    const mblock2 = new MerkleBlock(mblock);
    mblock2.merkleRoot = encoding.NULL_HASH;
    mblock2.refresh();
    assert(!mblock2.verifyPOW());
    const [, reason] = mblock2.checkBody();
    assert.strictEqual(reason, 'bad-txnmrklroot');
    assert(!mblock2.verify());
    mblock2.merkleRoot = mblock.merkleRoot;
    mblock2.refresh();
    assert(mblock2.verify());
  });

  it('should fail with a low target', () => {
    const block2 = new Block(block);
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
    const block2 = new Block(block);
    block2.txs.push(block2.txs[block2.txs.length - 1]);
    block2.refresh();
    const [, reason] = block2.checkBody();
    assert.strictEqual(reason, 'bad-txns-duplicate');
  });

  it('should verify with headers', () => {
    const headers = new Headers(block);
    assert(headers.verifyPOW());
    assert(headers.verifyBody());
    assert(headers.verify());
  });

  it('should handle compact block', () => {
    const block = Block.fromRaw(block426884);
    const cblock1 = CompactBlock.fromRaw(compact426884);
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.deepStrictEqual(cblock1.toRaw(), compact426884);
    assert.deepStrictEqual(cblock2.toRaw(), compact426884);

    const map = new Map();

    for (let i = 1; i < block.txs.length; i++) {
      const tx = block.txs[i];
      map.set(tx.hash('hex'), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(full);

    for (const tx of cblock1.available)
      assert(tx);

    assert.deepStrictEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  it('should handle half-full compact block', () => {
    const block = Block.fromRaw(block426884);
    const cblock1 = CompactBlock.fromRaw(compact426884);
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.deepStrictEqual(cblock1.toRaw(), compact426884);
    assert.deepStrictEqual(cblock2.toRaw(), compact426884);

    const map = new Map();

    for (let i = 1; i < ((block.txs.length + 1) >>> 1); i++) {
      const tx = block.txs[i];
      map.set(tx.hash('hex'), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(!full);

    let req = cblock1.toRequest();
    assert.strictEqual(req.hash, cblock1.hash('hex'));

    req = TXRequest.fromRaw(req.toRaw());
    assert.strictEqual(req.hash, cblock1.hash('hex'));

    let res = TXResponse.fromBlock(block, req);
    res = TXResponse.fromRaw(res.toRaw());

    const filled = cblock1.fillMissing(res);
    assert(filled);

    for (const tx of cblock1.available)
      assert(tx);

    assert.deepStrictEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  it('should handle compact block', () => {
    const block = Block.fromRaw(block898352);
    const cblock1 = CompactBlock.fromRaw(compact898352);
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.deepStrictEqual(cblock1.toRaw(), compact898352);
    assert.deepStrictEqual(cblock2.toRaw(), compact898352);

    assert.strictEqual(cblock1.sid(block.txs[1].hash()), 125673511480291);

    const map = new Map();

    for (let i = 1; i < block.txs.length; i++) {
      const tx = block.txs[i];
      map.set(tx.hash('hex'), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(full);

    for (const tx of cblock1.available)
      assert(tx);

    assert.deepStrictEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  it('should handle half-full compact block', () => {
    const block = Block.fromRaw(block898352);
    const cblock1 = CompactBlock.fromRaw(compact898352);
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.deepStrictEqual(cblock1.toRaw(), compact898352);
    assert.deepStrictEqual(cblock2.toRaw(), compact898352);

    assert.strictEqual(cblock1.sid(block.txs[1].hash()), 125673511480291);

    const map = new Map();

    for (let i = 1; i < ((block.txs.length + 1) >>> 1); i++) {
      const tx = block.txs[i];
      map.set(tx.hash('hex'), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(!full);

    let req = cblock1.toRequest();
    assert.strictEqual(req.hash, cblock1.hash('hex'));
    assert.deepStrictEqual(req.indexes, [5, 6, 7, 8, 9]);

    req = TXRequest.fromRaw(req.toRaw());
    assert.strictEqual(req.hash, cblock1.hash('hex'));
    assert.deepStrictEqual(req.indexes, [5, 6, 7, 8, 9]);

    let res = TXResponse.fromBlock(block, req);
    res = TXResponse.fromRaw(res.toRaw());

    const filled = cblock1.fillMissing(res);
    assert(filled);

    for (const tx of cblock1.available)
      assert(tx);

    assert.deepStrictEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  it('should count sigops for block 928927 (testnet)', () => {
    const block = Block.fromRaw(block928927);
    const undo = common.parseUndo(undo928927);
    const view = common.applyUndo(block, undo);
    const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;

    let sigops = 0;
    for (const tx of block.txs)
      sigops += tx.getSigopsCost(view, flags);

    assert.strictEqual(sigops, 10015);
    assert.strictEqual(block.getWeight(), 3992391);
  });

  it('should count sigops for block 928828 (testnet)', () => {
    const block = Block.fromRaw(block928828);
    const undo = common.parseUndo(undo928828);
    const view = common.applyUndo(block, undo);
    const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;

    let sigops = 0;
    for (const tx of block.txs)
      sigops += tx.getSigopsCost(view, flags);

    assert.strictEqual(sigops, 23236);
    assert.strictEqual(block.getWeight(), 2481560);
  });

  it('should count sigops for block 1087400 (testnet)', () => {
    const block = Block.fromRaw(block1087400);
    const undo = common.parseUndo(undo1087400);
    const view = common.applyUndo(block, undo);
    const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;

    let sigops = 0;
    for (const tx of block.txs)
      sigops += tx.getSigopsCost(view, flags);

    assert.strictEqual(sigops, 1298);
    assert.strictEqual(block.getWeight(), 193331);
  });
});
