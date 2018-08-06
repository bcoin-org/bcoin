/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const reorg = require('./util/reorg');
const Chain = require('../lib/blockchain/chain');
const WorkerPool = require('../lib/workers/workerpool');
const Miner = require('../lib/mining/miner');
const MemWallet = require('./util/memwallet');
const TXIndexer = require('../lib/indexer/txindexer');
const AddrIndexer = require('../lib/indexer/addrindexer');
const Network = require('../lib/protocol/network');
const network = Network.get('regtest');

const workers = new WorkerPool({
  enabled: true
});

const chain = new Chain({
  memory: true,
  network,
  workers
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
  'memory': true,
  'network': network,
  'chain': chain
});

const addrindexer = new AddrIndexer({
  'memory': true,
  'network': network,
  'chain': chain
});

describe('Indexer', function() {
  this.timeout(45000);

  it('should open indexer', async () => {
    await chain.open();
    await miner.open();
    await txindexer.open();
    await addrindexer.open();
  });

  it('should index 10 blocks', async () => {
    miner.addresses.length = 0;
    miner.addAddress(wallet.getReceive());
    for (let i = 0; i < 10; i++) {
      const block = await cpu.mineBlock();
      assert(block);
      assert(await chain.add(block));
    }

    assert.strictEqual(chain.height, 10);
    assert.strictEqual(txindexer.state.startHeight, 10);
    assert.strictEqual(addrindexer.state.startHeight, 10);

    const coins =
      await addrindexer.getCoinsByAddress(miner.getAddress());
    assert.strictEqual(coins.length, 10);

    for (const coin of coins) {
      const meta = await txindexer.getMeta(coin.hash);
      assert.bufferEqual(meta.tx.hash(), coin.hash);
    }
  });

  it('should rescan and reindex 10 missed blocks', async () => {
    await txindexer.disconnect();
    await addrindexer.disconnect();

    for (let i = 0; i < 10; i++) {
      const block = await cpu.mineBlock();
      assert(block);
      assert(await chain.add(block));
    }

    assert.strictEqual(chain.height, 20);

    await txindexer.connect();
    await addrindexer.connect();

    await new Promise(r => addrindexer.once('chain tip', r));

    assert.strictEqual(txindexer.state.startHeight, 20);
    assert.strictEqual(addrindexer.state.startHeight, 20);

    const coins =
      await addrindexer.getCoinsByAddress(miner.getAddress());
    assert.strictEqual(coins.length, 20);

    for (const coin of coins) {
      const meta = await txindexer.getMeta(coin.hash);
      assert.bufferEqual(meta.tx.hash(), coin.hash);
    }
  });

  it('should handle indexing a reorg', async () => {
    await reorg(chain, cpu, 10);

    assert.strictEqual(txindexer.state.startHeight, 31);
    assert.strictEqual(addrindexer.state.startHeight, 31);

    const coins =
      await addrindexer.getCoinsByAddress(miner.getAddress());
    assert.strictEqual(coins.length, 31);

    for (const coin of coins) {
      const meta = await txindexer.getMeta(coin.hash);
      assert.bufferEqual(meta.tx.hash(), coin.hash);
    }
  });
});
