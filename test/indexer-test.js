/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const reorg = require('./util/reorg');
const Script = require('../lib/script/script');
const Opcode = require('../lib/script/opcode');
const Address = require('../lib/primitives/address');
const Block = require('../lib/primitives/block');
const TX = require('../lib/primitives/tx');
const Output = require('../lib/primitives/output');
const Input = require('../lib/primitives/input');
const Chain = require('../lib/blockchain/chain');
const WorkerPool = require('../lib/workers/workerpool');
const Miner = require('../lib/mining/miner');
const MemWallet = require('./util/memwallet');
const TXIndexer = require('../lib/indexer/txindexer');
const AddrIndexer = require('../lib/indexer/addrindexer');
const BlockStore = require('../lib/blockstore/level');
const FullNode = require('../lib/node/fullnode');
const SPVNode = require('../lib/node/spvnode');
const Network = require('../lib/protocol/network');
const network = Network.get('regtest');
const {NodeClient, WalletClient} = require('../lib/client');
const {forValue, testdir, rimraf} = require('./util/common');
const {services} = require('../lib/net/common');

const ports = {
  p2p: 49331,
  node: 49332,
  wallet: 49333
};

const vectors = [
  // Secret for the public key vectors:
  // cVDJUtDjdaM25yNVVDLLX3hcHUfth4c7tY3rSc4hy9e8ibtCuj6G
  {
    addr: 'bcrt1qngw83fg8dz0k749cg7k3emc7v98wy0c7azaa6h',
    amount: 19.99,
    label: 'p2wpkh'
  },
  {
    addr: 'muZpTpBYhxmRFuCjLc7C6BBDF32C8XVJUi',
    amount: 1.99,
    label: 'p2pkh'
  },
  // Secrets for 1 of 2 multisig vectors:
  // cVDJUtDjdaM25yNVVDLLX3hcHUfth4c7tY3rSc4hy9e8ibtCuj6G
  // 93KCDD4LdP4BDTNBXrvKUCVES2jo9dAKKvhyWpNEMstuxDauHty
  {
    addr: 'bcrt1q2nj8e2nhmsa4hl9qw3xas7l5n2547h5uhlj47nc3pqfxaeq5rtjs9g328g',
    amount: 0.99,
    label: 'p2wsh'
  },
  {
    addr: '2Muy8nSQaMsMFAZwPyiXSEMTVFJv9iYuhwT',
    amount: 0.11,
    label: 'p2sh'
  },
  // Same data part as version 0 p2wsh address but different witness version (1)
  {
    addr: 'bcrt1p2nj8e2nhmsa4hl9qw3xas7l5n2547h5uhlj47nc3pqfxaeq5rtjs0l3rl5',
    amount: 0.22,
    label: 'p2tr'
  }
];

const workers = new WorkerPool({
  enabled: true,
  size: 2
});

const blocks = new BlockStore({
  memory: true,
  network
});

const chain = new Chain({
  memory: true,
  network,
  workers,
  blocks
});

const miner = new Miner({
  chain,
  version: 4,
  workers
});

const cpu = miner.cpu;

const wallet = new MemWallet({
  network
});

const txindexer = new TXIndexer({
  memory: true,
  network,
  chain,
  blocks
});

const addrindexer = new AddrIndexer({
  memory: true,
  network,
  chain,
  blocks
});

describe('Indexer', function() {
  this.timeout(120000);

  before(async () => {
    await blocks.open();
    await chain.open();
    await miner.open();
    await txindexer.open();
    await addrindexer.open();
    await workers.open();
  });

  after(async () => {
    await workers.close();
    await blocks.close();
    await chain.close();
    await miner.close();
    await txindexer.close();
    await addrindexer.close();
  });

  describe('Unit', function() {
    it('should connect block', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      indexer.height = 9;

      indexer.getBlockMeta = (height) => {
        return {
          hash: Buffer.alloc(32, 0x00),
          height: height
        };
      };

      let called = false;
      indexer._addBlock = async () => {
        called = true;
      };

      const meta = {height: 10};
      const block = {prevBlock: Buffer.alloc(32, 0x00)};
      const view = {};

      const connected = await indexer._syncBlock(meta, block, view);
      assert.equal(connected, true);
      assert.equal(called, true);
    });

    it('should not connect block', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      indexer.height = 9;

      indexer.getBlockMeta = (height) => {
        return {
          hash: Buffer.alloc(32, 0x02),
          height: height
        };
      };

      let called = false;
      indexer._addBlock = async () => {
        called = true;
      };

      const meta = {height: 10};
      const block = {prevBlock: Buffer.alloc(32, 0x01)};
      const view = {};

      const connected = await indexer._syncBlock(meta, block, view);
      assert.equal(connected, false);
      assert.equal(called, false);
    });

    it('should disconnect block', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      indexer.height = 9;

      indexer.getBlockMeta = (height) => {
        return {
          hash: Buffer.alloc(32, 0x00),
          height: height
        };
      };

      let called = false;
      indexer._removeBlock = async () => {
        called = true;
      };

      const meta = {height: 9};
      const block = {hash: () => Buffer.alloc(32, 0x00)};
      const view = {};

      const connected = await indexer._syncBlock(meta, block, view);
      assert.equal(connected, true);
      assert.equal(called, true);
    });

    it('should not disconnect block', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      indexer.height = 9;

      indexer.getBlockMeta = (height) => {
        return {
          hash: Buffer.alloc(32, 0x01),
          height: height
        };
      };

      let called = false;
      indexer._removeBlock = async () => {
        called = true;
      };

      const meta = {height: 9};
      const block = {hash: () => Buffer.alloc(32, 0x02)};
      const view = {};

      const connected = await indexer._syncBlock(meta, block, view);
      assert.equal(connected, false);
      assert.equal(called, false);
    });

    it('should not index tx w/ invalid address (witness v0)', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      const ops = [];

      indexer.put = (key, value) => ops.push([key, value]);
      indexer.del = (key, value) => ops.push([key, value]);

      // Create a witness program version 0 with
      // 10 byte data push (BIP141 limits v0 to either 20 or 32).
      const script = new Script();
      script.push(Opcode.fromSmall(0));
      script.push(Opcode.fromData(Buffer.alloc(10)));
      script.compile();

      const tx = new TX({
        inputs: [
          new Input()
        ],
        outputs: [
          new Output({script})
        ]
      });;

      const entry = {height: 323549};
      const block = {txs: [tx]};
      const view = {};

      indexer.indexBlock(entry, block, view);
      indexer.unindexBlock(entry, block, view);

      assert.equal(ops.length, 0);
    });

    it('should not index tx w/ invalid address (witness v1)', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      const ops = [];

      indexer.put = (key, value) => ops.push([key, value]);
      indexer.del = (key, value) => ops.push([key, value]);

      // Create a witness program version 1 with
      // 50 byte data push (40 is the BIP141 maximum).
      const script = new Script();
      script.push(Opcode.fromSmall(1));
      script.push(Opcode.fromData(Buffer.alloc(50)));
      script.compile();

      const tx = new TX({
        inputs: [
          new Input()
        ],
        outputs: [
          new Output({script})
        ]
      });;

      const entry = {height: 323549};
      const block = {txs: [tx]};
      const view = {};

      indexer.indexBlock(entry, block, view);
      indexer.unindexBlock(entry, block, view);

      assert.equal(ops.length, 0);
    });

    it('should index tx w/ valid address (witness v0)', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      const ops = [];

      indexer.put = (key, value) => ops.push([key, value]);
      indexer.del = (key, value) => ops.push([key, value]);

      // Create a witness program version 0 with
      // 20 byte data push.
      const script = new Script();
      script.push(Opcode.fromSmall(0));
      script.push(Opcode.fromData(Buffer.alloc(20)));
      script.compile();
      const addr = Address.fromScript(script);

      const tx = {
        getAddresses: () => [addr],
        hash: () => Buffer.alloc(32)
      };

      const entry = {height: 323549};
      const block = {txs: [tx]};
      const view = {};

      indexer.indexBlock(entry, block, view);
      indexer.unindexBlock(entry, block, view);

      assert.equal(ops.length, 6);
    });

    it('should index tx w/ valid address (witness v1)', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      const ops = [];

      indexer.put = (key, value) => ops.push([key, value]);
      indexer.del = (key, value) => ops.push([key, value]);

      // Create a witness program version 1 with
      // 20 byte data push.
      const script = new Script();
      script.push(Opcode.fromSmall(1));
      script.push(Opcode.fromData(Buffer.alloc(20)));
      script.compile();
      const addr = Address.fromScript(script);

      const tx = {
        getAddresses: () => [addr],
        hash: () => Buffer.alloc(32)
      };

      const entry = {height: 323549};
      const block = {txs: [tx]};
      const view = {};

      indexer.indexBlock(entry, block, view);
      indexer.unindexBlock(entry, block, view);

      assert.equal(ops.length, 6);
    });

    it('should index tx w/ valid address (witness v1, taproot)', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {}
      });

      const ops = [];

      indexer.put = (key, value) => ops.push([key, value]);
      indexer.del = (key, value) => ops.push([key, value]);

      // Create a witness program version 1 with
      // 32 byte data push.
      const script = new Script();
      script.push(Opcode.fromSmall(1));
      script.push(Opcode.fromData(Buffer.alloc(32)));
      script.compile();
      const addr = Address.fromScript(script);

      const tx = {
        getAddresses: () => [addr],
        hash: () => Buffer.alloc(32)
      };

      const entry = {height: 323549};
      const block = {txs: [tx]};
      const view = {};

      indexer.indexBlock(entry, block, view);
      indexer.unindexBlock(entry, block, view);

      assert.equal(ops.length, 6);
    });

    it('should error with limits', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: {},
        maxTxs: 10
      });

      await assert.rejects(async () => {
        await indexer.getHashesByAddress(vectors[0].addr, {limit: 11});
      }, {
        name: 'Error',
        message: 'Limit above max of 10.'
      });
    });

    it('should track bound chain events and remove on close', async () => {
      const indexer = new AddrIndexer({
        blocks: {},
        chain: new EventEmitter()
      });

      const events = ['connect', 'disconnect', 'reset'];

      await indexer.open();

      for (const event of events)
        assert.equal(indexer.chain.listeners(event).length, 1);

      await indexer.close();

      for (const event of events)
        assert.equal(indexer.chain.listeners(event).length, 0);
    });
  });

  describe('Index 10 blocks', function() {
    let addr = null;

    before(async () => {
      miner.addresses.length = 0;
      miner.addAddress(wallet.getReceive());

      addr = miner.getAddress();

      for (let i = 0; i < 10; i++) {
        const block = await cpu.mineBlock();
        assert(block);
        assert(await chain.add(block));
      }

      assert.strictEqual(chain.height, 10);
      assert.strictEqual(txindexer.height, 10);
      assert.strictEqual(addrindexer.height, 10);
    });

    it('should get txs by address', async () => {
      const hashes = await addrindexer.getHashesByAddress(miner.getAddress());
      assert.strictEqual(hashes.length, 10);
    });

    it('should get txs by address (limit)', async () => {
      const hashes = await addrindexer.getHashesByAddress(addr, {limit: 1});
      assert.strictEqual(hashes.length, 1);
    });

    it('should get txs by address (reverse)', async () => {
      const hashes = await addrindexer.getHashesByAddress(
        addr, {reverse: false});

      assert.strictEqual(hashes.length, 10);

      const reversed = await addrindexer.getHashesByAddress(
        addr, {reverse: true});

      assert.strictEqual(reversed.length, 10);

      for (let i = 0; i < 10; i++)
        assert.deepEqual(hashes[i], reversed[9 - i]);
    });

    it('should get txs by address after txid', async () => {
      const hashes = await addrindexer.getHashesByAddress(addr, {limit: 5});

      assert.strictEqual(hashes.length, 5);

      const txid = hashes[4];

      const next = await addrindexer.getHashesByAddress(
        addr, {after: txid, limit: 5});

      assert.strictEqual(next.length, 5);

      const all = await addrindexer.getHashesByAddress(addr);
      assert.strictEqual(all.length, 10);

      assert.deepEqual(hashes.concat(next), all);
    });

    it('should get txs by address after txid (reverse)', async () => {
      const hashes = await addrindexer.getHashesByAddress(
        addr, {limit: 5, reverse: true});

      assert.strictEqual(hashes.length, 5);

      const txid = hashes[4];

      const next = await addrindexer.getHashesByAddress(
        addr, {after: txid, limit: 5, reverse: true});

      assert.strictEqual(next.length, 5);

      const all = await addrindexer.getHashesByAddress(
        addr, {reverse: true});

      assert.strictEqual(all.length, 10);

      assert.deepEqual(hashes.concat(next), all);
    });

    it('should get tx and meta', async () => {
      const hashes = await addrindexer.getHashesByAddress(addr, {limit: 1});
      assert.equal(hashes.length, 1);
      const hash = hashes[0];

      const tx = await txindexer.getTX(hash);
      const meta = await txindexer.getMeta(hash);

      assert(meta.height);
      assert(meta.block);
      assert(meta.time);

      assert.deepEqual(meta.tx, tx);
    });

    it('should get null if not found for tx and meta', async () => {
      const hash = Buffer.alloc(32);

      const tx = await txindexer.getTX(hash);
      const meta = await txindexer.getMeta(hash);

      assert.strictEqual(tx, null);
      assert.strictEqual(meta, null);
    });

    it('should get unspendable genesis tx', async () => {
      const block = Block.fromRaw(Buffer.from(network.genesisBlock, 'hex'));
      const hash = block.txs[0].hash();

      const tx = await txindexer.getTX(hash);
      const meta = await txindexer.getMeta(hash);

      assert(meta);
      assert.equal(meta.height, 0);
      assert(meta.block);
      assert(meta.time);

      assert.deepEqual(meta.tx, tx);
    });
  });

  describe('Reorg and rescan', function() {
    it('should rescan and reindex 10 missed blocks', async () => {
      for (let i = 0; i < 10; i++) {
        const block = await cpu.mineBlock();
        assert(block);
        assert(await chain.add(block));
      }

      assert.strictEqual(chain.height, 20);
      assert.strictEqual(txindexer.height, 20);
      assert.strictEqual(addrindexer.height, 20);

      const hashes = await addrindexer.getHashesByAddress(miner.getAddress());
      assert.strictEqual(hashes.length, 20);

      for (const hash of hashes) {
        const meta = await txindexer.getMeta(hash);
        assert.bufferEqual(meta.tx.hash(), hash);
      }
    });

    it('should handle indexing a reorg', async () => {
      await reorg(chain, cpu, 10);

      assert.strictEqual(txindexer.height, 31);
      assert.strictEqual(addrindexer.height, 31);

      const hashes = await addrindexer.getHashesByAddress(miner.getAddress());
      assert.strictEqual(hashes.length, 31);

      for (const hash of hashes) {
        const meta = await txindexer.getMeta(hash);
        assert.bufferEqual(meta.tx.hash(), hash);
      }
    });

    describe('Integration', function() {
      const prefix = testdir('indexer');

      beforeEach(async () => {
        await rimraf(prefix);
      });

      after(async () => {
        await rimraf(prefix);
      });

      it('will enable indexes retroactively', async () => {
        let node, nclient = null;

        try {
          node = new FullNode({
            prefix: prefix,
            network: 'regtest',
            apiKey: 'foo',
            memory: false,
            indexTX: false,
            indexAddress: false,
            port: ports.p2p,
            httpPort: ports.node
          });

          await node.ensure();
          await node.open();

          nclient = new NodeClient({
            port: ports.node,
            apiKey: 'foo',
            timeout: 120000
          });

          await nclient.open();

          const blocks = await nclient.execute(
            'generatetoaddress', [150, vectors[0].addr]);

          assert.equal(blocks.length, 150);

          await forValue(node.chain, 'height', 150);

          const info = await nclient.request('GET', '/');

          assert.equal(info.chain.height, 150);
          assert.equal(info.indexes.addr.enabled, false);
          assert.equal(info.indexes.addr.height, 0);
          assert.equal(info.indexes.tx.enabled, false);
          assert.equal(info.indexes.tx.height, 0);
        } finally {
          if (nclient)
            await nclient.close();

          if (node)
            await node.close();
        }

        try {
          node = new FullNode({
            prefix: prefix,
            network: 'regtest',
            memory: false,
            indexTX: true,
            indexAddress: false,
            port: ports.p2p,
            httpPort: ports.node
          });

          await node.ensure();
          await node.open();

          assert(node.txindex);
          assert.equal(node.txindex.height, 0);

          node.startSync();

          await forValue(node.txindex, 'height', 150);
        } finally {
          if (node)
            await node.close();
        }
      });

      it('will sync if disabled during reorganization', async () => {
        let node, nclient, wclient = null;

        try {
          // Generate initial set of blocks that are are spending
          // coins and therefore data in undo blocks.
          node = new FullNode({
            prefix: prefix,
            network: 'regtest',
            apiKey: 'foo',
            memory: false,
            indexTX: true,
            indexAddress: false,
            port: ports.p2p,
            httpPort: ports.node,
            plugins: [require('../lib/wallet/plugin')],
            env: {
              'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
            },
            logLevel: 'none'
          });

          await node.ensure();
          await node.open();

          nclient = new NodeClient({
            port: ports.node,
            apiKey: 'foo',
            timeout: 120000
          });

          await nclient.open();

          wclient = new WalletClient({
            port: ports.wallet,
            apiKey: 'foo',
            timeout: 120000
          });

          await wclient.open();

          const coinbase = await wclient.execute(
            'getnewaddress', ['default']);

          const blocks = await nclient.execute(
            'generatetoaddress', [150, coinbase]);

          assert.equal(blocks.length, 150);

          for (let i = 0; i < 10; i++) {
            for (const v of vectors) {
              await wclient.execute('sendtoaddress', [v.addr, v.amount, '', '', false, true]);
            }

            const blocks = await nclient.execute(
              'generatetoaddress', [1, coinbase]);

            assert.equal(blocks.length, 1);
          }

          await forValue(node.chain, 'height', 160);
          await forValue(node.txindex, 'height', 160);
        } finally {
          if (wclient)
            await wclient.close();

          if (nclient)
            await nclient.close();

          if (node)
            await node.close();
        }

        try {
          // Now create a reorganization in the chain while
          // the indexer is disabled.
          node = new FullNode({
            prefix: prefix,
            network: 'regtest',
            apiKey: 'foo',
            memory: false,
            indexTX: false,
            indexAddress: false,
            port: ports.p2p,
            httpPort: ports.node,
            logLevel: 'none'
          });

          await node.ensure();
          await node.open();

          nclient = new NodeClient({
            port: ports.node,
            apiKey: 'foo',
            timeout: 120000
          });

          await nclient.open();

          for (let i = 0; i < 10; i++) {
            const hash = await nclient.execute('getbestblockhash');
            await nclient.execute('invalidateblock', [hash]);
          }

          await forValue(node.chain, 'height', 150);

          const blocks = await nclient.execute(
            'generatetoaddress', [20, vectors[0].addr]);

          assert.equal(blocks.length, 20);

          await forValue(node.chain, 'height', 170);
        } finally {
          if (nclient)
            await nclient.close();

          if (node)
            await node.close();
        }

        try {
          // Now turn the indexer back on and check that it
          // is able to disconnect blocks and add the new blocks.
          node = new FullNode({
            prefix: prefix,
            network: 'regtest',
            apiKey: 'foo',
            memory: false,
            indexTX: true,
            indexAddress: false,
            port: ports.p2p,
            httpPort: ports.node,
            logLevel: 'none'
          });

          await node.ensure();
          await node.open();

          assert(node.txindex);
          assert.equal(node.txindex.height, 160);

          node.txindex.sync();

          await forValue(node.txindex, 'height', 170, 5000);
        } finally {
          if (node)
            await node.close();
        }
      });

      it('will reset indexes', async () => {
        let node, nclient = null;

        try {
          node = new FullNode({
            prefix: prefix,
            network: 'regtest',
            apiKey: 'foo',
            memory: false,
            indexTX: true,
            indexAddress: false,
            port: ports.p2p,
            httpPort: ports.node,
            logLevel: 'none'
          });

          await node.ensure();
          await node.open();

          nclient = new NodeClient({
            port: ports.node,
            apiKey: 'foo',
            timeout: 120000
          });

          await nclient.open();

          const blocks = await nclient.execute(
            'generatetoaddress', [150, vectors[0].addr]);

          assert.equal(blocks.length, 150);

          await forValue(node.txindex, 'height', 150);

          await node.chain.reset(0);

          await forValue(node.txindex, 'height', 1);
        } finally {
          if (nclient)
            await nclient.close();

          if (node)
            await node.close();
        }
      });

      it('will not index if pruned', async () => {
        let err = null;

        try {
          new FullNode({
            prefix: prefix,
            network: 'regtest',
            apiKey: 'foo',
            memory: false,
            prune: true,
            indexTX: true,
            indexAddress: true,
            port: ports.p2p,
            httpPort: ports.node
          });
        } catch (e) {
          err = e;
        }

        assert(err);
        assert.equal(err.message, 'Can not index while pruned.');
      });

      it('will not index if spv', async () => {
        const node = new SPVNode({
          prefix: prefix,
          network: 'regtest',
          apiKey: 'foo',
          memory: false,
          indexTX: true,
          indexAddress: true,
          port: ports.p2p,
          httpPort: ports.node
        });

        assert.equal(node.txindex, null);
        assert.equal(node.addrindex, null);
      });

      it('will require filter index for BIP157 (negative)', async () => {
        let err = null;

        try {
          new FullNode({
            prefix: prefix,
            network: 'regtest',
            port: ports.p2p,
            httpPort: ports.node,
            bip157: true
          });
        } catch (e) {
          err = e;
        }
        assert(err);
        assert.equal(err.message, 'Filter indexer is required for BIP 157');
      });

      it('will require filter index for BIP157 (positive)', async () => {
        const node = new FullNode({
          prefix: prefix,
          network: 'regtest',
          port: ports.p2p,
          httpPort: ports.node,
          indexFilter: true,
          bip157: true
        });

        await node.open();
        assert(node.pool.options.services & services.NODE_COMPACT_FILTERS);
        await node.close();
      });
    });
  });

  describe('HTTP', function() {
    this.timeout(120000);

    let node, nclient, wclient = null;

    const confirmed = [];
    const unconfirmed = [];

    function sanitize(txs) {
      return txs.map((tx) => {
        // Remove mtime from the results for deep
        // comparisons as it can be variable.
        delete tx.mtime;
        return tx;
      });
    }

    before(async () => {
      this.timeout(120000);

      // Setup a testing node with txindex, addrindex and filterindex enabled.
      node = new FullNode({
        network: 'regtest',
        apiKey: 'foo',
        walletAuth: true,
        memory: true,
        workers: true,
        workersSize: 2,
        indexTX: true,
        indexAddress: true,
        indexFilter: true,
        port: ports.p2p,
        httpPort: ports.node,
        plugins: [require('../lib/wallet/plugin')],
        env: {
          'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
        }
      });

      await node.open();

      // Setup the node client to make calls to the node
      // to generate blocks and other tasks.
      nclient = new NodeClient({
        port: ports.node,
        apiKey: 'foo',
        timeout: 120000
      });

      await nclient.open();

      // Setup a test wallet to generate transactions for
      // testing various scenarios.
      wclient = new WalletClient({
        port: ports.wallet,
        apiKey: 'foo',
        timeout: 120000
      });

      await wclient.open();

      // Generate initial set of transactions and
      // send the coinbase to alice.
      const coinbase = await wclient.execute(
        'getnewaddress', ['default']);

      const blocks = await nclient.execute(
        'generatetoaddress', [150, coinbase]);

      assert.equal(blocks.length, 150);

      // Send to the vector addresses for several blocks.
      for (let i = 0; i < 10; i++) {
        for (const v of vectors) {
          const txid = await wclient.execute(
            'sendtoaddress', [v.addr, v.amount, '', '', false, true]);

          confirmed.push(txid);
        }

        const blocks = await nclient.execute(
          'generatetoaddress', [1, coinbase]);

        assert.equal(blocks.length, 1);
      }

      await forValue(node.chain, 'height', 160);

      // Send unconfirmed to the vector addresses.
      for (let i = 0; i < 5; i++) {
        for (const v of vectors) {
          const txid = await wclient.execute(
            'sendtoaddress', [v.addr, v.amount, '', '', false, true]);

          unconfirmed.push(txid);
        }
      }

      await forValue(node.mempool.map, 'size', 25);
    });

    after(async () => {
      await nclient.close();
      await wclient.close();
      await node.close();
    });

    for (const v of vectors) {
      it(`txs by ${v.label} addr`, async () => {
        const res = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {});

        assert.equal(res.length, 15);

        for (let i = 0; i < 10; i++)
          assert(confirmed.includes(res[i].hash));

        for (let i = 10; i < 15; i++)
          assert(unconfirmed.includes(res[i].hash));
      });

      it(`txs by ${v.label} addr (limit)`, async () => {
        const res = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 3});

        assert.equal(res.length, 3);

        for (const tx of res)
          assert(confirmed.includes(tx.hash));
      });

      it(`txs by ${v.label} addr (limit w/ unconf)`, async () => {
        const res = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 11});

        assert.equal(res.length, 11);

        for (let i = 0; i < 10; i++)
          assert(confirmed.includes(res[i].hash));

        for (let i = 10; i < 11; i++)
          assert(unconfirmed.includes(res[i].hash));
      });

      it(`txs by ${v.label} addr (reverse)`, async () => {
        const asc = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {reverse: false});

        assert.equal(asc.length, 15);

        const dsc = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {reverse: true});

        assert.equal(dsc.length, 15);

        for (let i = 0; i < 10; i++)
          assert(confirmed.includes(asc[i].hash));

        for (let i = 10; i < 15; i++)
          assert(unconfirmed.includes(asc[i].hash));

        // Check the the results are reverse
        // of each other.
        for (let i = 0; i < dsc.length; i++) {
          const atx = asc[i];
          const dtx = dsc[dsc.length - i - 1];
          assert.equal(atx.hash, dtx.hash);
        }
      });

      it(`txs by ${v.label} addr (after)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 3});
        assert.strictEqual(one.length, 3);

        for (let i = 0; i < 3; i++)
          assert(confirmed.includes(one[i].hash));

        // The after hash is within the
        // confirmed transactions.
        const hash = one[2].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {after: hash, limit: 3});
        assert.strictEqual(one.length, 3);

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 6});
        assert.strictEqual(one.length, 3);

        assert.deepEqual(sanitize(one.concat(two)), sanitize(all));
      });

      it(`txs by ${v.label} addr (after w/ unconf)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 11});
        assert.strictEqual(one.length, 11);

        for (let i = 0; i < 10; i++)
          assert(confirmed.includes(one[i].hash));

        for (let i = 10; i < 11; i++)
          assert(unconfirmed.includes(one[i].hash));

        // The after hash is within the
        // unconfirmed transactions.
        const hash = one[10].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {after: hash, limit: 1});
        assert.strictEqual(two.length, 1);
        assert(unconfirmed.includes(two[0].hash));

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 12});
        assert.strictEqual(all.length, 12);

        assert.deepEqual(sanitize(one.concat(two)), sanitize(all));
      });

      it(`txs by ${v.label} addr (after w/ unconf 2)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 12});
        assert.strictEqual(one.length, 12);

        for (let i = 0; i < 10; i++)
          assert(confirmed.includes(one[i].hash));

        for (let i = 10; i < 12; i++)
          assert(unconfirmed.includes(one[i].hash));

        const hash = one[11].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {after: hash, limit: 10});
        assert.strictEqual(two.length, 3);

        for (let i = 0; i < 3; i++)
          assert(unconfirmed.includes(two[i].hash));

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 100});
        assert.strictEqual(all.length, 15);

        assert.deepEqual(sanitize(one.concat(two)), sanitize(all));
      });

      it(`txs by ${v.label} addr (after w/ unconf 3)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 13});
        assert.strictEqual(one.length, 13);

        for (let i = 0; i < 10; i++)
          assert(confirmed.includes(one[i].hash));

        for (let i = 10; i < 13; i++)
          assert(unconfirmed.includes(one[i].hash));

        const hash = one[12].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {after: hash, limit: 1});
        assert.strictEqual(two.length, 1);
        assert(unconfirmed.includes(two[0].hash));

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 14});
        assert.strictEqual(all.length, 14);

        assert.deepEqual(sanitize(one.concat(two)), sanitize(all));
      });

      it(`txs by ${v.label} addr (after, reverse)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 8, reverse: true});

        assert.strictEqual(one.length, 8);

        for (let i = 0; i < 5; i++)
          assert(unconfirmed.includes(one[i].hash));

        for (let i = 5; i < 8; i++)
          assert(confirmed.includes(one[i].hash));

        // The after hash is within the
        // confirmed transactions.
        const hash = one[7].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {after: hash, limit: 3, reverse: true});

        assert.strictEqual(two.length, 3);

        for (let i = 0; i < 3; i++)
          assert(confirmed.includes(two[i].hash));

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 11, reverse: true});

        assert.strictEqual(all.length, 11);

        for (let i = 0; i < 5; i++)
          assert(unconfirmed.includes(all[i].hash));

        for (let i = 5; i < 11; i++)
          assert(confirmed.includes(all[i].hash));

        assert.deepEqual(sanitize(one.concat(two)), sanitize(all));
      });

      it(`txs by ${v.label} addr (after, reverse w/ unconf)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 5, reverse: true});

        assert.strictEqual(one.length, 5);
        for (let i = 0; i < 5; i++)
          assert(unconfirmed.includes(one[i].hash));

        // The after hash is within the
        // unconfirmed transactions.
        const hash = one[4].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {after: hash, limit: 3, reverse: true});

        assert.strictEqual(two.length, 3);

        for (let i = 0; i < 3; i++)
          assert(confirmed.includes(two[i].hash));

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 8, reverse: true});

        assert.strictEqual(all.length, 8);

        for (let i = 0; i < 5; i++)
          assert(unconfirmed.includes(all[i].hash));

        for (let i = 5; i < 8; i++)
          assert(confirmed.includes(all[i].hash));

        assert.deepEqual(sanitize(one.concat(two)), sanitize(all));
      });

      it(`txs by ${v.label} addr (after, reverse w/ unconf 2)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 3, reverse: true});

        assert.strictEqual(one.length, 3);
        for (let i = 0; i < 3; i++)
          assert(unconfirmed.includes(one[i].hash));

        const hash = one[2].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {after: hash, limit: 1, reverse: true});

        assert.strictEqual(two.length, 1);
        assert(unconfirmed.includes(two[0].hash));

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 4, reverse: true});

        assert.strictEqual(all.length, 4);

        for (let i = 0; i < 4; i++)
          assert(unconfirmed.includes(all[i].hash));

        assert.deepEqual(sanitize(one.concat(two)), sanitize(all));
      });

      it('should get info', async () => {
        const {indexes: {filter}} = await nclient.getInfo();

        assert.strictEqual(Object.keys(filter).length, 1);

        assert(filter.BASIC);
        assert(filter.BASIC.enabled);
        assert.strictEqual(filter.BASIC.height, node.chain.height);
      });
    }

    describe('Errors', function() {
      it('will give error if limit is exceeded', async () => {
        await assert.rejects(async () => {
          await nclient.request(
            'GET', `/tx/address/${vectors[0].addr}`, {limit: 101});
        }, {
          name: 'Error',
          message: 'Limit above max of 100.'
        });
      });

      it('will give error with invalid after hash', async () => {
        await assert.rejects(async () => {
          await nclient.request(
            'GET', `/tx/address/${vectors[0].addr}`, {after: 'deadbeef'});
        }, {
          name: 'Error',
          message: 'after must be a hex string.'
        });
      });

      it('will give error with invalid reverse', async () => {
        await assert.rejects(async () => {
          await nclient.request(
            'GET', `/tx/address/${vectors[0].addr}`, {reverse: 'sure'});
        }, {
          name: 'Error',
          message: 'reverse must be a boolean.'
        });
      });
    });
  });
});
