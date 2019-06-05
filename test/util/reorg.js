'use strict';

const assert = require('bsert');
const Chain = require('../../lib/blockchain/chain');
const CPUMiner = require('../../lib/mining/cpuminer');

/**
 * Reorgs the chain to given height using miners.
 * @param {Chain} chain chain
 * @param {CPUMiner} cpu cpuminer
 * @param {Number} height height
 * @returns {Promise} null
 */
async function reorg(chain, cpu, height) {
  assert(chain instanceof Chain);
  assert(cpu instanceof CPUMiner);
  assert(typeof height === 'number');

  let tip1, tip2 = null;
  for (let i = 0; i < height; i++) {
    const job1 = await cpu.createJob(tip1);
    const job2 = await cpu.createJob(tip2);

    const blk1 = await job1.mineAsync();
    const blk2 = await job2.mineAsync();

    const hash1 = blk1.hash();
    const hash2 = blk2.hash();

    assert(await chain.add(blk1));
    assert(await chain.add(blk2));

    assert.bufferEqual(chain.tip.hash, hash1);

    tip1 = await chain.getEntry(hash1);
    tip2 = await chain.getEntry(hash2);

    assert(tip1);
    assert(tip2);

    assert(!await chain.isMainChain(tip2));
  }

  const entry = await chain.getEntry(tip2.hash);
  assert(entry);
  assert.strictEqual(chain.height, entry.height);

  const block = await cpu.mineBlock(entry);
  assert(block);

  let forked = false;
  chain.once('reorganize', () => {
    forked = true;
  });

  assert(await chain.add(block));

  assert(forked);
  assert.bufferEqual(chain.tip.hash, block.hash());
  assert(chain.tip.chainwork.gt(tip1.chainwork));
}

module.exports = reorg;
