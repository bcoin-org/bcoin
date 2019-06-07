/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const common = require('./util/common');
const {BloomFilter} = require('bfilter');
const {BufferMap} = require('buffer-map');
const Block = require('../lib/primitives/block');
const MerkleBlock = require('../lib/primitives/merkleblock');
const consensus = require('../lib/protocol/consensus');
const Script = require('../lib/script/script');
const nodejsUtil = require('util');
const bip152 = require('../lib/net/bip152');
const CompactBlock = bip152.CompactBlock;
const TXRequest = bip152.TXRequest;
const TXResponse = bip152.TXResponse;

// Block test vectors
const block300025 = common.readBlock('block300025');

// Merkle block test vectors
const merkle300025 = common.readMerkle('merkle300025');

// Compact block test vectors
const block426884 = common.readBlock('block426884');
const compact426884 = common.readCompact('compact426884');
const block898352 = common.readBlock('block898352');
const compact898352 = common.readCompact('compact898352');

// Small SegWit block test vector
const block482683 = common.readBlock('block482683');

// Sigops counting test vectors
// Format: [name, sigops, weight]
const sigopsVectors = [
  ['block928816', 9109, 3568200],
  ['block928828', 23236, 2481560],
  ['block928831', 10035, 3992382],
  ['block928848', 11319, 3992537],
  ['block928849', 9137, 3682105],
  ['block928927', 10015, 3992391],
  ['block1087400', 1298, 193331]
];

describe('Block', function() {
  this.timeout(10000);

  it('should parse partial merkle tree', () => {
    const [block] = merkle300025.getBlock();

    assert(block.verifyPOW());
    assert(block.verifyBody());
    assert(block.verify());

    const tree = block.getTree();

    assert.strictEqual(tree.matches.length, 2);
    assert.strictEqual(block.hash().toString('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.strictEqual(block.rhash(),
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.strictEqual(
      tree.matches[0].toString('hex'),
      '7393f84cd04ca8931975c66282ebf1847c78d8de6c2578d4f9bae23bc6f30857');
    assert.strictEqual(
      tree.matches[1].toString('hex'),
      'ec8c51de3170301430ec56f6703533d9ea5b05c6fa7068954bcb90eed8c2ee5c');
  });

  it('should decode/encode merkle block', () => {
    const [block] = merkle300025.getBlock();
    block.refresh();
    assert.bufferEqual(block.toRaw(), merkle300025.getRaw());
  });

  it('should verify merkle block', () => {
    const [block] = merkle300025.getBlock();
    assert(block.verify());
  });

  it('should be encoded/decoded and still verify', () => {
    const [block1] = merkle300025.getBlock();
    const raw = block1.toRaw();
    const block2 = MerkleBlock.fromRaw(raw);
    assert.bufferEqual(block2.toRaw(), raw);
    assert(block2.verify());
  });

  it('should be jsonified/unjsonified and still verify', () => {
    const [block1] = merkle300025.getBlock();
    const json = block1.toJSON();
    const block2 = MerkleBlock.fromJSON(json);
    assert.deepStrictEqual(block2.toJSON(), json);
    assert(block2.verify());
  });

  it('should parse JSON', () => {
    const [block1] = block300025.getBlock();
    const block2 = Block.fromJSON(block1.toJSON());
    assert.strictEqual(block2.hash().toString('hex'),
      '8cc72c02a958de5a8b35a23bb7e3bced8bf840cc0a4e1c820000000000000000');
    assert.strictEqual(block2.rhash(),
      '0000000000000000821c4e0acc40f88bedbce3b73ba2358b5ade58a9022cc78c');
    assert.bufferEqual(block2.merkleRoot, block2.createMerkleRoot());
  });

  it('should inspect a block with a witness commitment', () => {
    const [block] = block482683.getBlock();
    const fmt = nodejsUtil.format(block);
    assert(typeof fmt === 'string');
    assert(fmt.includes('Block'));
    assert(fmt.includes('commitmentHash'));
  });

  it('should create a merkle block', () => {
    const filter = BloomFilter.fromRate(1000, 0.01, BloomFilter.flags.NONE);

    const item1 = Buffer.from(
      '8e7445bbb8abd4b3174d80fa4c409fea6b94d96b',
      'hex');

    const item2 = Buffer.from('047b00000078da0dca3b0ec2300c00d0ab4466ed10'
      + 'e763272c6c9ca052972c69e3884a9022084215e2eef'
      + '0e6f781656b5d5a87231cd4349e534b6dea55ad4ff55e', 'hex');

    filter.add(item1);
    filter.add(item2);

    const [block1] = block300025.getBlock();
    const block2 = MerkleBlock.fromBlock(block1, filter);

    assert(block2.verifyBody());
    assert.bufferEqual(block2.toRaw(), merkle300025.getRaw());
  });

  it('should verify a historical block', () => {
    const [block, view] = block300025.getBlock();
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
      reward += tx.getFee(view);

      view.addTX(tx, height);
    }

    reward += consensus.getReward(height, 210000);

    assert.strictEqual(sigops, 5280);
    assert.strictEqual(reward, 2507773345);
    assert.strictEqual(reward, block.txs[0].outputs[0].value);
  });

  it('should fail with a bad merkle root', () => {
    const [block] = block300025.getBlock();
    const merkleRoot = block.merkleRoot;
    block.merkleRoot = consensus.ZERO_HASH;
    block.refresh();
    assert(!block.verifyPOW());
    const [, reason] = block.checkBody();
    assert.strictEqual(reason, 'bad-txnmrklroot');
    assert(!block.verify());
    block.merkleRoot = merkleRoot;
    block.refresh();
    assert(block.verify());
  });

  it('should fail on merkle block with a bad merkle root', () => {
    const [block] = merkle300025.getBlock();
    const merkleRoot = block.merkleRoot;
    block.merkleRoot = consensus.ZERO_HASH;
    block.refresh();
    assert(!block.verifyPOW());
    const [, reason] = block.checkBody();
    assert.strictEqual(reason, 'bad-txnmrklroot');
    assert(!block.verify());
    block.merkleRoot = merkleRoot;
    block.refresh();
    assert(block.verify());
  });

  it('should fail with a low target', () => {
    const [block] = block300025.getBlock();
    const bits = block.bits;
    block.bits = 403014710;
    block.refresh();
    assert(!block.verifyPOW());
    assert(block.verifyBody());
    assert(!block.verify());
    block.bits = bits;
    block.refresh();
    assert(block.verify());
  });

  it('should fail on duplicate txs', () => {
    const [block] = block300025.getBlock();
    block.txs.push(block.txs[block.txs.length - 1]);
    block.refresh();
    const [, reason] = block.checkBody();
    assert.strictEqual(reason, 'bad-txns-duplicate');
  });

  it('should verify with headers', () => {
    const headers = block300025.getHeaders();
    assert(headers.verifyPOW());
    assert(headers.verifyBody());
    assert(headers.verify());
  });

  it('should handle compact block', () => {
    const [block] = block426884.getBlock();
    const [cblock1] = compact426884.getBlock();
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.bufferEqual(cblock1.toRaw(), compact426884.getRaw());
    assert.bufferEqual(cblock2.toRaw(), compact426884.getRaw());

    const map = new BufferMap();

    for (let i = 1; i < block.txs.length; i++) {
      const tx = block.txs[i];
      map.set(tx.hash(), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(full);

    for (const tx of cblock1.available)
      assert(tx);

    assert.bufferEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  it('should handle half-full compact block', () => {
    const [block] = block426884.getBlock();
    const [cblock1] = compact426884.getBlock();
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.bufferEqual(cblock1.toRaw(), compact426884.getRaw());
    assert.bufferEqual(cblock2.toRaw(), compact426884.getRaw());

    const map = new BufferMap();

    for (let i = 1; i < ((block.txs.length + 1) >>> 1); i++) {
      const tx = block.txs[i];
      map.set(tx.hash(), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(!full);

    const rawReq = cblock1.toRequest().toRaw();
    const req = TXRequest.fromRaw(rawReq);
    assert.bufferEqual(req.hash, cblock1.hash());

    const rawRes = TXResponse.fromBlock(block, req).toRaw();
    const res = TXResponse.fromRaw(rawRes);

    const filled = cblock1.fillMissing(res);
    assert(filled);

    for (const tx of cblock1.available)
      assert(tx);

    assert.bufferEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  it('should handle compact block', () => {
    const [block] = block898352.getBlock();
    const [cblock1] = compact898352.getBlock();
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.bufferEqual(cblock1.toRaw(), compact898352.getRaw());
    assert.bufferEqual(cblock2.toRaw(), compact898352.getRaw());

    assert.strictEqual(cblock1.sid(block.txs[1].hash()), 125673511480291);

    const map = new BufferMap();

    for (let i = 1; i < block.txs.length; i++) {
      const tx = block.txs[i];
      map.set(tx.hash(), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(full);

    for (const tx of cblock1.available)
      assert(tx);

    assert.bufferEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  it('should handle half-full compact block', () => {
    const [block] = block898352.getBlock();
    const [cblock1] = compact898352.getBlock();
    const cblock2 = CompactBlock.fromBlock(block, false, cblock1.keyNonce);

    assert(cblock1.init());

    assert.bufferEqual(cblock1.toRaw(), compact898352.getRaw());
    assert.bufferEqual(cblock2.toRaw(), compact898352.getRaw());

    assert.strictEqual(cblock1.sid(block.txs[1].hash()), 125673511480291);

    const map = new BufferMap();

    for (let i = 1; i < ((block.txs.length + 1) >>> 1); i++) {
      const tx = block.txs[i];
      map.set(tx.hash(), { tx });
    }

    const full = cblock1.fillMempool(false, { map });
    assert(!full);

    const rawReq = cblock1.toRequest().toRaw();
    const req = TXRequest.fromRaw(rawReq);
    assert.bufferEqual(req.hash, cblock1.hash());
    assert.deepStrictEqual(req.indexes, [5, 6, 7, 8, 9]);

    const rawRes = TXResponse.fromBlock(block, req).toRaw();
    const res = TXResponse.fromRaw(rawRes);

    const filled = cblock1.fillMissing(res);
    assert(filled);

    for (const tx of cblock1.available)
      assert(tx);

    assert.bufferEqual(cblock1.toBlock().toRaw(), block.toRaw());
  });

  for (const cache of [false, true]) {
    const word = cache ? 'with' : 'without';
    for (const [name, sigops, weight] of sigopsVectors) {
      const ctx = common.readBlock(name);
      it(`should count sigops for ${name} (${word} cache)`, () => {
        const [block, view] = ctx.getBlock();
        const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_WITNESS;

        if (!cache)
          block.refresh(true);

        let count = 0;
        for (const tx of block.txs)
          count += tx.getSigopsCost(view, flags);

        assert.strictEqual(count, sigops);
        assert.strictEqual(block.getWeight(), weight);
      });
    }
  }

  it('should deserialize with offset positions for txs (witness)', () => {
    const [block] = block482683.getBlock();

    const expected = [
      {offset: 81, size: 217},
      {offset: 298, size: 815},
      {offset: 1113, size: 192},
      {offset: 1305, size: 259},
      {offset: 1564, size: 223},
      {offset: 1787, size: 1223},
      {offset: 3010, size: 486},
      {offset: 3496, size: 665},
      {offset: 4161, size: 3176},
      {offset: 7337, size: 225},
      {offset: 7562, size: 1223},
      {offset: 8785, size: 503}
    ];

    assert.equal(expected.length, block.txs.length);
    assert.equal(block.getSize(), expected.reduce((a, b) => a + b.size, 81));

    for (let i = 0; i < block.txs.length; i++) {
      const {offset, size} = block.txs[i].getPosition();

      assert.strictEqual(offset, expected[i].offset);
      assert.strictEqual(size, expected[i].size);
    }
  });

  it('should serialize with offset positions for txs (witness)', () => {
    const [block] = block482683.getBlock();

    const expected = [
      {offset: 81, size: 217},
      {offset: 298, size: 815},
      {offset: 1113, size: 192},
      {offset: 1305, size: 259},
      {offset: 1564, size: 223},
      {offset: 1787, size: 1223},
      {offset: 3010, size: 486},
      {offset: 3496, size: 665},
      {offset: 4161, size: 3176},
      {offset: 7337, size: 225},
      {offset: 7562, size: 1223},
      {offset: 8785, size: 503}
    ];

    assert.equal(expected.length, block.txs.length);
    assert.equal(block.getSize(), expected.reduce((a, b) => a + b.size, 81));

    // Reset the offset for all transactions, and clear
    // any cached values for the block.
    block.refresh(true);
    for (let i = 0; i < block.txs.length; i++)
      assert.equal(block.txs[i]._offset, -1);

    // Serialize the block, as done before saving to disk.
    const raw = block.toRaw();
    assert(raw);

    for (let i = 0; i < block.txs.length; i++) {
      const {offset, size} = block.txs[i].getPosition();

      assert.strictEqual(offset, expected[i].offset);
      assert.strictEqual(size, expected[i].size);
    }
  });

  it('should deserialize with offset positions for txs', () => {
    const [block] = block300025.getBlock();

    assert.equal(block.txs.length, 461);

    let expect = 83;
    let total = 83;

    for (let i = 0; i < block.txs.length; i++) {
      const {offset, size} = block.txs[i].getPosition();

      assert.strictEqual(offset, expect);
      expect += size;
      total += size;
    }

    assert.equal(total, 284231);
  });
});
