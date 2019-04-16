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
const FullNode = require('../lib/node/fullnode');
const Network = require('../lib/protocol/network');
const network = Network.get('regtest');
const {NodeClient, WalletClient} = require('bclient');

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
  this.timeout(120000);

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
      assert.strictEqual(txindexer.height, 10);
      assert.strictEqual(addrindexer.height, 10);
    });

    it('should get txs by address', async () => {
      const hashes = await addrindexer.getHashesByAddress(miner.getAddress());
      assert.strictEqual(hashes.length, 10);
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

    it('should txs by address after txid', async () => {
      const addr = miner.getAddress();
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

    it('should txs by address after txid (reverse)', async () => {
      const addr = miner.getAddress();
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
  });

  describe('rescan and reorg', function() {
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
  });

  describe('http', function() {
    this.timeout(120000);

    let node, nclient, wclient = null;

    const vectors = [
      // Secret for the vectors:
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
      }
    ];

    const txids = [];

    const ports = {
      p2p: 49331,
      node: 49332,
      wallet: 49333
    };

    before(async () => {
      this.timeout(120000);

      // Setup a testing node with txindex and addrindex
      // both enabled.
      node = new FullNode({
        network: 'regtest',
        apiKey: 'foo',
        walletAuth: true,
        memory: true,
        workers: true,
        indexTX: true,
        indexAddress: true,
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
            'sendtoaddress', [v.addr, v.amount]);

          txids.push(txid);
        }

        const blocks = await nclient.execute(
          'generatetoaddress', [1, coinbase]);

        assert.equal(blocks.length, 1);
      }
    });

    after(async () => {
      await nclient.close();
      await wclient.close();
      await node.close();
    });

    for (const v of vectors) {
      it(`will get txs by ${v.label} address`, async () => {
        const res = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {});

        assert.equal(res.length, 10);

        for (const tx of res)
          assert(txids.includes(tx.hash));
      });

      it(`will get txs by ${v.label} address (limit)`, async () => {
        const res = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 3});

        for (const tx of res)
          assert(txids.includes(tx.hash));
      });

      it(`txs by ${v.label} address (reverse)`, async () => {
        const asc = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {reverse: false});

        const dsc = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {reverse: true});

        for (let i = 0; i < dsc.length; i++)
          assert.equal(asc[i].hash, dsc[dsc.length - i - 1].hash);
      });

      it(`txs by ${v.label} address after txid`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 3});
        assert.strictEqual(one.length, 3);

        const hash = one[2].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {after: hash, limit: 3});
        assert.strictEqual(one.length, 3);

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`, {limit: 6});
        assert.strictEqual(one.length, 3);

        assert.deepEqual(one.concat(two), all);
      });

      it(`txs by ${v.label} address after txid (reverse)`, async () => {
        const one = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 3, reverse: true});

        assert.strictEqual(one.length, 3);

        const hash = one[2].hash;

        const two = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {after: hash, limit: 3, reverse: true});

        assert.strictEqual(one.length, 3);

        const all = await nclient.request(
          'GET', `/tx/address/${v.addr}`,
          {limit: 6, reverse: true});

        assert.strictEqual(one.length, 3);

        assert.deepEqual(one.concat(two), all);
      });
    }
  });
});
