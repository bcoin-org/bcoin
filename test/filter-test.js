/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const hash256 = require('bcrypto/lib/hash256');
const FullNode = require('../lib/node/fullnode');
const {filters} = require('../lib/blockstore/common');
const {BufferSet} = require('buffer-map');
const {opcodes} = require('../lib/script/common');
const FilterIndexer = require('../lib/indexer/filterindexer');
const Block = require('../lib/primitives/block');
const Golomb = require('../lib/golomb/golomb');
const {U64} = require('n64');
const BasicFilter = require('../lib/golomb/basicFilter');
const {NodeClient} = require('../lib/client');

class TestFilter extends Golomb {
  constructor() {
    super(21, new U64(744931));
  }
}

class TestBlock extends Block {
  constructor() {
    super();
  }

  toTestFilter(view) {
    const hash = this.hash();
    const key = hash.slice(0, 16);
    const items = new BufferSet();

    for (let i = 0; i < this.txs.length; i++) {
      const tx = this.txs[i];

      for (const output of tx.outputs) {
        if (output.script.length === 0)
          continue;

        // In order to allow the filters to later be committed
        // to within an OP_RETURN output, we ignore all
        // OP_RETURNs to avoid a circular dependency.
        if (output.script.raw[0] === opcodes.OP_RETURN)
          continue;

        items.add(output.script.raw);
      }
    }

    for (const [, coins] of view.map) {
      for (const [, coin] of coins.outputs) {
        if (coin.output.script.length === 0)
          continue;

        items.add(coin.output.script.raw);
      }
    }

    return new TestFilter().fromItems(key, items);
  }

  toFilter(view, filterType) {
    switch (filterType) {
      case filters.BASIC:
        return this.toBasicFilter(view);
      case filters.TEST:
        return this.toTestFilter(view);
      default:
        return null;
    }
  }
}

Block.fromRaw = (data, enc) => {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new TestBlock().fromRaw(data);
};

const node = new FullNode({
  network: 'regtest',
  memory: true,
  indexFilter: true,
  plugins: [require('../lib/wallet/plugin')]
});

filters['TEST'] = 0xffffffff;

describe('Filter', function() {
  this.timeout(15000);

  before(async () => {
    const testFilterIndex = new FilterIndexer({
      network: node.network,
      logger: node.logger,
      blocks: node.blocks,
      chain: node.chain,
      memory: node.config.bool('memory'),
      prefix: node.config.str('index-prefix', node.config.prefix),
      filterType: 'TEST'
    });
    node.filterIndexers.set('TEST', testFilterIndex);

    await node.open();
  });

  after(async () => {
    await node.close();
  });

  it('should test blocks get generated', async () => {
    const generateblocks = async (height, entry) => {
      for (let i = 0; i <= height; i++) {
        const block = await node.miner.mineBlock(entry);
        const testBlock = new TestBlock().fromRaw(block.toRaw());
        entry = await node.chain.add(testBlock);
      }
      return entry;
    };
    await generateblocks(5, await node.chain.getEntry(0));
  });

  it('should basic filter get generated', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const indexer = node.filterIndexers.get('BASIC');
      const filter = (await indexer.getFilter(hash)).toJSON();

      assert.notStrictEqual(filter.filter.length, 0);
      assert.notStrictEqual(filter.header.length, 0);
    }
  });

  it('should test filter get generated', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const indexer = node.filterIndexers.get('TEST');
      const filter = (await indexer.getFilter(hash)).toJSON();

      assert.notStrictEqual(filter.filter.length, 0);
      assert.notStrictEqual(filter.header.length, 0);
    }
  });

  it('should not test filter equal basic filter', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const basicIndexer = node.filterIndexers.get('BASIC');
      const testIndexer = node.filterIndexers.get('TEST');
      const basicFilter = (await basicIndexer.getFilter(hash)).toJSON();
      const testFilter =  (await testIndexer.getFilter(hash)).toJSON();

      assert.notStrictEqual(basicFilter.filter, testFilter.filter);
      assert.notStrictEqual(basicFilter.header, testFilter.header);
    }
  });

  it('should basic filter be reconstructed', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const indexer = node.filterIndexers.get('BASIC');
      const rawBasicFilter = (await indexer.getFilter(hash));
      const basicFilter = new BasicFilter().fromRaw(rawBasicFilter.filter);

      assert.ok(basicFilter);
    }
  });

  it('should reconstructed basic filter be matched', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const block = await node.chain.getBlock(hash);
      const indexer = node.filterIndexers.get('BASIC');
      const rawBasicFilter = (await indexer.getFilter(hash));
      const basicFilter = new BasicFilter().fromRaw(rawBasicFilter.filter);

      const key = hash.slice(0, 16);
      const items = new BufferSet();
      for (let i = 0; i < block.txs.length; i++) {
        const tx = block.txs[i];

        for (const output of tx.outputs) {
          if (output.script.length === 0)
            continue;

          // In order to allow the filters to later be committed
          // to within an OP_RETURN output, we ignore all
          // OP_RETURNs to avoid a circular dependency.
          if (output.script.raw[0] === opcodes.OP_RETURN)
            continue;
          items.add(output.script.raw);
        }
      }
      const view = await node.chain.getBlockView(block);
      for (const [, coins] of view.map) {
        for (const [, coin] of coins.outputs) {
          if (coin.output.script.length === 0)
            continue;

          items.add(coin.output.script.raw);
        }
      }

      assert.ok(basicFilter);
      for (const item of items) {
        assert.ok(basicFilter.match(key, item));
      }
    }
  });

  it('should test filter be reconstructed', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const indexer = node.filterIndexers.get('TEST');
      const rawTestFilter = (await indexer.getFilter(hash));
      const testFilter = new TestFilter().fromRaw(rawTestFilter.filter);

      assert.ok(testFilter);
    }
  });

  it('should reconstructed test filter be matched', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const block = await node.chain.getBlock(hash);
      const indexer = node.filterIndexers.get('TEST');
      const rawTestFilter = (await indexer.getFilter(hash));
      const testFilter = new TestFilter().fromRaw(rawTestFilter.filter);

      const key = hash.slice(0, 16);
      const items = new BufferSet();
      for (let i = 0; i < block.txs.length; i++) {
        const tx = block.txs[i];

        for (const output of tx.outputs) {
          if (output.script.length === 0)
            continue;

          // In order to allow the filters to later be committed
          // to within an OP_RETURN output, we ignore all
          // OP_RETURNs to avoid a circular dependency.
          if (output.script.raw[0] === opcodes.OP_RETURN)
            continue;
          items.add(output.script.raw);
        }
      }
      const view = await node.chain.getBlockView(block);
      for (const [, coins] of view.map) {
        for (const [, coin] of coins.outputs) {
          if (coin.output.script.length === 0)
            continue;

          items.add(coin.output.script.raw);
        }
      }

      assert.ok(testFilter);
      for (const item of items) {
        assert.ok(testFilter.match(key, item));
      }
    }
  });

  it('should basic filter hash be generated', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const indexer = node.filterIndexers.get('BASIC');
      const basicFilterHash  = await indexer.getFilterHash(hash);

      const rawBasicFilter = await indexer.getFilter(hash);
      const expected = hash256.digest(rawBasicFilter.filter);
      assert.bufferEqual(expected, basicFilterHash);
    }
  });

  it('should test filter hash be generated', async () => {
    for (let i = 0; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const indexer = node.filterIndexers.get('TEST');
      const testFilterHash  = await indexer.getFilterHash(hash);

      const rawTestFilter = await indexer.getFilter(hash);
      const expected = hash256.digest(rawTestFilter.filter);
      assert.bufferEqual(expected, testFilterHash);
    }
  });

  it('should basic filter header be generated by a chain of filter hashes', async () => {
    const indexer = node.filterIndexers.get('BASIC');
    const initialHash = await node.chain.getHash(0);
    const initialFilter = await indexer.getFilter(initialHash);
    let prev = initialFilter.header;

    for (let i = 1; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const basicFilterHash  = await indexer.getFilterHash(hash);
      prev = hash256.root(basicFilterHash, prev);
    }

    const finalHash = await node.chain.getHash(node.chain.height);
    const finalFilter = await indexer.getFilter(finalHash);
    const expected = finalFilter.header;
    assert.bufferEqual(prev, expected);
  });

  it('should test filter header be generated by a chain of filter hashes', async () => {
    const indexer = node.filterIndexers.get('TEST');
    const initialHash = await node.chain.getHash(0);
    const initialFilter = await indexer.getFilter(initialHash);
    let prev = initialFilter.header;

    for (let i = 1; i <= node.chain.height; i++) {
      const hash = await node.chain.getHash(i);
      const testFilterHash = await indexer.getFilterHash(hash);
      prev = hash256.root(testFilterHash, prev);
    }

    const finalHash = await node.chain.getHash(node.chain.height);
    const finalFilter = await indexer.getFilter(finalHash);
    const expected = finalFilter.header;
    assert.bufferEqual(prev, expected);
  });

  it('should compute correct filter hash', () => {
    // Test vectors derived from Bitcoin Core
    const filter = new BasicFilter().fromNBytes(
      Buffer.from('0189a630', 'hex')
    );
    const actual = filter.hash();
    const expected = Buffer.from(
      'c1bf78c13365fd48548224efdb81c5eda29982438f8f5217cc44ff752b6ab867',
      'hex'
    );
    assert.bufferEqual(actual, expected);
  });

  describe('HTTP', function() {
    const nclient = new NodeClient({
      port: node.network.rpcPort
    });

    it('should get info', async () => {
      const {indexes: {filter}} = await nclient.getInfo();

      assert.strictEqual(Object.keys(filter).length, 2);

      assert(filter.BASIC);
      assert(filter.BASIC.enabled);
      assert.strictEqual(filter.BASIC.height, node.chain.height);

      assert(filter.TEST);
      assert(filter.TEST.enabled);
      assert.strictEqual(filter.TEST.height, node.chain.height);
    });
  });
});
