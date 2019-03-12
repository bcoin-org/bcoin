/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Chain = require('../lib/blockchain/chain');
const Miner = require('../lib/mining/miner');
const Network = require('../lib/protocol/network');
const common = require('../lib/blockchain/common');
const BlockStore = require('../lib/blockstore/level');
const thresholdStates = common.thresholdStates;

const network = Network.get('regtest');
const deployments = network.deployments;

const blocks = new BlockStore({
  memory: true,
  network
});

const chain = new Chain({
  memory: true,
  network,
  blocks
});
const miner = new Miner({
  chain: chain
});

async function addBIP9Blocks(number, setCSVbit) {
  for (let i = 0; i < number; i++) {
    const entry = await chain.getEntry(chain.tip.hash);
    const job = await miner.cpu.createJob(entry);
    if (setCSVbit)
      job.attempt.version |= (1 << deployments.csv.bit);
    else
      job.attempt.version = 0x20000000;
    job.refresh();
    const block = await job.mineAsync();
    await chain.add(block);
  }
};

async function getCSVState() {
  const prev = chain.tip;
  const state = await chain.getState(prev, deployments.csv);
  return state;
};

describe('BIP9 Signalling Statistics', function() {
  before(async () => {
    await blocks.open();
    await chain.open();
    await miner.cpu.open();
  });

  after(async () => {
    await chain.close();
    await miner.cpu.close();
    await blocks.close();
  });

  it('should advance from DEFINED to STARTED', async () => {
    await addBIP9Blocks(142, true);
    const state1 = await getCSVState(chain.tip);
    assert.strictEqual(state1, thresholdStates.DEFINED);
    await addBIP9Blocks(1, true);
    const state2 = await getCSVState(chain.tip);
    assert.strictEqual(state2, thresholdStates.STARTED);
  });

  it('should add blocks: LOCKED_IN still possible', async () => {
    // 10 yes, 36 no
    await addBIP9Blocks(10, true);
    await addBIP9Blocks(36, false);
    const stats1 = await chain.getBIP9Stats(chain.tip, deployments.csv);
    assert.deepStrictEqual(stats1, {
      period: network.minerWindow,
      threshold: network.activationThreshold,
      elapsed: 46,
      count: 10,
      possible: true
    });
  });

  it('should add non-signalling block: LOCKED_IN impossible', async () => {
    // 1 no
    await addBIP9Blocks(1, false);
    const stats2 = await chain.getBIP9Stats(chain.tip, deployments.csv);
    assert.deepStrictEqual(stats2, {
      period: network.minerWindow,
      threshold: network.activationThreshold,
      elapsed: 47,
      count: 10,
      possible: false
    });
  });

  it('should finish signalling period without LOCKED_IN', async () => {
    // 97 yes
    await addBIP9Blocks(97, true);
    const stats3 = await chain.getBIP9Stats(chain.tip, deployments.csv);
    assert.deepStrictEqual(stats3, {
      period: network.minerWindow,
      threshold: network.activationThreshold,
      elapsed: 0,
      count: 0,
      possible: true
    });
    const state3 = await getCSVState(chain.tip);
    assert.strictEqual(state3, thresholdStates.STARTED);
  });

  it('should add blocks: LOCKED_IN still possible', async () => {
    // new activation window
    // 107 yes, 36 no -- one block left this period
    await addBIP9Blocks(107, true);
    await addBIP9Blocks(36, false);
    const stats4 = await chain.getBIP9Stats(chain.tip, deployments.csv);
    assert.deepStrictEqual(stats4, {
      period: network.minerWindow,
      threshold: network.activationThreshold,
      elapsed: 143,
      count: 107,
      possible: true
    });
    const state4 = await getCSVState(chain.tip);
    assert.strictEqual(state4, thresholdStates.STARTED);
  });

  it('should add 1 signalling block to reach LOCKED_IN', async () => {
    // 1 yes - should LOCKED_IN
    await addBIP9Blocks(1, true);
    const stats5 = await chain.getBIP9Stats(chain.tip, deployments.csv);
    assert.deepStrictEqual(stats5, {
      period: network.minerWindow,
      threshold: network.activationThreshold,
      elapsed: 0,
      count: 0,
      possible: true
    });
    const state5 = await getCSVState(chain.tip);
    assert.strictEqual(state5, thresholdStates.LOCKED_IN);
  });
});
