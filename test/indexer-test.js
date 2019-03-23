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
const BlockStore = require('../lib/blockstore/level');
const Network = require('../lib/protocol/network');
const network = Network.get('regtest');

const workers = new WorkerPool({
  enabled: true
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
  this.timeout(45000);

  before(async () => {
    await blocks.open();
    await chain.open();
    await miner.open();
    await txindexer.open();
    await addrindexer.open();
  });

  after(async () => {
    await blocks.close();
    await chain.close();
    await miner.close();
    await txindexer.close();
    await addrindexer.close();
  });

  describe('index 10 blocks', function() {
    before(async () => {
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
    });

    it('should get coins by address', async () => {
      const coins = await addrindexer.getCoinsByAddress(miner.getAddress());
      assert.strictEqual(coins.length, 10);
    });

    it('should get txs by address', async () => {
      const hashes = await addrindexer.getHashesByAddress(miner.getAddress());
      assert.strictEqual(hashes.length, 10);
    });

    it('should get txs for coins by address', async () => {
      const coins = await addrindexer.getCoinsByAddress(miner.getAddress());
      assert.strictEqual(coins.length, 10);

      for (const coin of coins) {
        const meta = await txindexer.getMeta(coin.hash);
        assert.bufferEqual(meta.tx.hash(), coin.hash);
      }
    });

    it('should coins by address (limit)', async () => {
      const addr = miner.getAddress();
      const coins = await addrindexer.getCoinsByAddress(addr, {limit: 1});
      assert.strictEqual(coins.length, 1);
    });

    it('should coins by address (reverse)', async () => {
      const addr = miner.getAddress();
      const coins = await addrindexer.getCoinsByAddress(
        addr, {reverse: false});

      assert.strictEqual(coins.length, 10);

      const reversed = await addrindexer.getCoinsByAddress(
        addr, {reverse: true});

      assert.strictEqual(reversed.length, 10);

      for (let i = 0; i < 10; i++)
        assert.deepEqual(coins[i], reversed[9 - i]);
    });

    it('should get txs by address (limit)', async () => {
      const addr = miner.getAddress();
      const hashes = await addrindexer.getHashesByAddress(addr, {limit: 1});
      assert.strictEqual(hashes.length, 1);
    });

    it('should get txs by address (reverse)', async () => {
      const addr = miner.getAddress();
      const hashes = await addrindexer.getHashesByAddress(
        addr, {reverse: false});

      assert.strictEqual(hashes.length, 10);

      const reversed = await addrindexer.getHashesByAddress(
        addr, {reverse: true});

      assert.strictEqual(reversed.length, 10);

      for (let i = 0; i < 10; i++)
        assert.deepEqual(hashes[i], reversed[9 - i]);
    });

    it('should coins by address after txid and index', async () => {
      const addr = miner.getAddress();
      const coins = await addrindexer.getCoinsByAddress(addr, {limit: 5});

      assert.strictEqual(coins.length, 5);

      const txid = coins[4].hash;
      const index = coins[4].index;

      const next = await addrindexer.getCoinsByAddressAfter(
        addr, {txid: txid, index: index, limit: 5});

      assert.strictEqual(next.length, 5);

      const all = await addrindexer.getCoinsByAddress(addr);
      assert.strictEqual(all.length, 10);

      assert.deepEqual(coins.concat(next), all);
    });

    it('should coins by address after txid and index (reverse)', async () => {
      const addr = miner.getAddress();
      const coins = await addrindexer.getCoinsByAddress(
        addr, {limit: 5, reverse: true});

      assert.strictEqual(coins.length, 5);

      const txid = coins[4].hash;
      const index = coins[4].index;

      const next = await addrindexer.getCoinsByAddressAfter(
        addr, {txid: txid, index: index, limit: 5, reverse: true});

      assert.strictEqual(next.length, 5);

      const all = await addrindexer.getCoinsByAddress(addr, {reverse: true});
      assert.strictEqual(all.length, 10);

      assert.deepEqual(coins.concat(next), all);
    });

    it('should txs by address after txid', async () => {
      const addr = miner.getAddress();
      const hashes = await addrindexer.getHashesByAddress(addr, {limit: 5});

      assert.strictEqual(hashes.length, 5);

      const txid = hashes[4];

      const next = await addrindexer.getHashesByAddressAfter(
        addr, {txid: txid, limit: 5});

      assert.strictEqual(next.length, 5);

      const all = await addrindexer.getHashesByAddress(addr);
      assert.strictEqual(all.length, 10);

      assert.deepEqual(hashes.concat(next), all);
    });

    it('should txs by address after txid (reverse)', async () => {
      const addr = miner.getAddress();
      const hashes = await addrindexer.getHashesByAddress(
        addr, {limit: 5, reverse: true});

      assert.strictEqual(hashes.length, 5);

      const txid = hashes[4];

      const next = await addrindexer.getHashesByAddressAfter(
        addr, {txid: txid, limit: 5, reverse: true});

      assert.strictEqual(next.length, 5);

      const all = await addrindexer.getHashesByAddress(
        addr, {reverse: true});

      assert.strictEqual(all.length, 10);

      assert.deepEqual(hashes.concat(next), all);
    });
  });

  describe('rescan and reorg', function() {
    it('should rescan and reindex 10 missed blocks', async () => {
      for (let i = 0; i < 10; i++) {
        const block = await cpu.mineBlock();
        assert(block);
        assert(await chain.add(block));
      }

      assert.strictEqual(chain.height, 20);
      assert.strictEqual(txindexer.state.startHeight, 20);
      assert.strictEqual(addrindexer.state.startHeight, 20);

      const coins = await addrindexer.getCoinsByAddress(miner.getAddress());
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

      const coins = await addrindexer.getCoinsByAddress(miner.getAddress());
      assert.strictEqual(coins.length, 31);

      for (const coin of coins) {
        const meta = await txindexer.getMeta(coin.hash);
        assert.bufferEqual(meta.tx.hash(), coin.hash);
      }
    });
  });
});
