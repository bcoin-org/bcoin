/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Network = require('../lib/protocol/network');
const consensus = require('../lib/protocol/consensus');
const Chain = require('../lib/blockchain/chain');
const BlockStore = require('../lib/blockstore/level');
const Miner = require('../lib/mining/miner');
const util = require('../lib/utils/util');
const MemWallet = require('./util/memwallet');

const network = Network.get('regtest');
const savedBip16Time = consensus.BIP16_TIME;
const savedUtilNow = util.now;

const blocks = new BlockStore({
  memory: true,
  network
});

const chain = new Chain({
  memory: true,
  blocks,
  network
});

const miner = new Miner({
  chain
});

const wallet = new MemWallet({
  network,
  witness: true
});

const address = wallet.getReceive();

async function mineBlocks(n) {
  const entries = [];
  for (let i = 0; i < n; i++) {
    const job = await miner.cpu.createJob();
    // Mine blocks all ten minutes apart from regtest genesis
    job.attempt.time = chain.tip.time + (60 * 10);
    const block = await job.mineAsync();
    const entry = await chain.add(block);
    wallet.addBlock(entry, block.txs);
    entries.push(entry);
  }
  return entries;
}

async function mineBlockWithMTXs(mtxs) {
  const job = await miner.cpu.createJob();
  for (const mtx of mtxs)
    job.addTX(mtx.toTX(), mtx.view);
  job.refresh();
  job.attempt.time = chain.tip.time + (60 * 10);
  const block = await job.mineAsync();
  const entry = await chain.add(block);
  wallet.addBlock(entry, block.txs);
  return entry;
}

describe('Chain Sync Progress', function () {
  before(async () => {
    await blocks.open();
    await chain.open();
    await miner.open();

    miner.addresses.length = 0;
    miner.addAddress(address);

    // regtest genesis timestamp ordinarily pre-dates P2SH
    consensus.BIP16_TIME = 0;
  });

  after(async () => {
    await miner.close();
    await chain.close();
    await blocks.close();

    // restore
    consensus.BIP16_TIME = savedBip16Time;
    util.now = savedUtilNow;
    network.txnData = {
      rate: 0,
      time: 0,
      count: 0
    };
  });

  it('should generate 100 blocks with 1 tx each (coinbase only)', async () => {
    await mineBlocks(100);

    // Imagine releasing software at this point using these data
    network.txnData = {
      count: 101,
      time: chain.tip.time,
      rate: 1 / 600 // tx per second (one per ten minute block)
    };
  });

  it('should generate 100 blocks with 2 tx each', async () => {
    for (let i = 0; i < 100; i++) {
      const mtx = await wallet.create({
        outputs: [{
          address: wallet.getAddress(),
          value: 1e8
        }]
      });
      await mineBlockWithMTXs([mtx]);
    }
  });

  it('should generate 100 blocks with 3 tx each', async () => {
    for (let i = 0; i < 100; i++) {
      const mtx1 = await wallet.create({
        outputs: [{
          address: wallet.getAddress(),
          value: 1e8
        }]
      });
      // prevent double spend
      wallet.addTX(mtx1.toTX());
      const mtx2 = await wallet.create({
        outputs: [{
          address: wallet.getAddress(),
          value: 1e8
        }]
      });
      await mineBlockWithMTXs([mtx1, mtx2]);
    }
  });

  it('should have expected chain state', async () => {
    assert.strictEqual(chain.height, 300);
    assert.strictEqual(chain.db.state.tx, (1 + 100 + 200 + 300));
  });

  for (const spv of [false, true]) {
    describe(`New chain: ${spv ? 'SPV' : 'Full'}`, function () {
      // time never changes
      util.now = () => {
        return chain.tip.time;
      };

      const newBlocks = new BlockStore({
        memory: true,
        network
      });

      const newChain = new Chain({
        memory: true,
        blocks,
        network,
        spv
      });

      before(async () => {
        await newBlocks.open();
        await newChain.open();
      });

      after(async () => {
        await newChain.close();
        await newBlocks.close();
      });

      it('should sync the first 100 blocks and get progress', async () => {
        for (let i = 1; i <= 100; i++) {
          const entry = await chain.getEntry(i);
          const block = await chain.getBlock(entry.hash);
          await newChain.add(block);
        }

        const percent = parseInt(newChain.getProgress() * 100);
        // Only 100 out of 600 total txs have been processed
        // but at this point all we know about the chain is the
        // hard-coded values. We assume the tx rate of one per ten minutes
        // continues until the current time, which turns out to be wrong.
        // The current guess is 100 down out of (we think) 300 total.
        // Should be the same result for SPV node (1/3 of blocks synced).
        assert.strictEqual(percent, 33);
      });

      it('should sync the next 100 blocks and get progress', async () => {
        for (let i = 101; i <= 200; i++) {
          const entry = await chain.getEntry(i);
          const block = await chain.getBlock(entry.hash);
          await newChain.add(block);
        }

        const percent = parseInt(newChain.getProgress() * 100);

        if (spv) {
          // SPV node has synced 2/3 of the blocks, this would be 67% progress
          // considering it uses the old algorithm.
          assert.strictEqual(percent, 67);
        } else {
          // Even though we have observed the tx rate on chain double
          // over the last 100 blocks, we continue to use the 1 tx per ten minutes
          // rate to predict the future from this point forward.
          // The new guess is 300 down out of (we think) 400 total.
          assert.strictEqual(percent, 75);
        }
      });

      it('should sync the next 99 blocks and approach 100%', async () => {
        for (let i = 201; i < 300; i++) {
          const entry = await chain.getEntry(i);
          const block = await chain.getBlock(entry.hash);
          await newChain.add(block);
        }

        const percent = parseInt(newChain.getProgress() * 100);

        if (spv) {
          // At this point, the SPV node should consider itself fully synced.
          assert.strictEqual(percent, 100);
        } else {
          // As we approach the current time the actual tx count gets closer and
          // closer to accurate and the amount of future txs we need to predict
          // drops to almost zero.
          // The new guess is essentially 599 down out of (we think) 600 total.
          assert.strictEqual(percent, 99);
        }
      });

      it('should sync the last block and reach 100%', async () => {
        const entry = await chain.getEntry(300);
        const block = await chain.getBlock(entry.hash);
        await newChain.add(block);

        const percent = parseInt(newChain.getProgress() * 100);
        assert.strictEqual(percent, 100);
      });
    });
  }
});
