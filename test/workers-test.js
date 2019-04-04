/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const WorkerPool = require('../lib/workers/workerpool');
const Miner = require('../lib/mining/miner');
const Chain = require('../lib/blockchain/chain');

const workers = new WorkerPool({
  enabled: true,
  size: 1
});

const chain = new Chain({
  network: 'regtest'
});

const miner = new Miner({
  chain: chain,
  workers: workers
});

describe('Workers', function() {
  it('should spawn workers', async () => {
    await miner.open();
    await chain.open();

    assert(workers.children.size === 0);

    const job = await miner.createJob();
    const block = await job.mineAsync();
    assert(block);

    assert(workers.children.size === 1);

    const cp = workers.children.get(0).child.child;
    assert(!cp.killed);
  });

  it('should cleanup', async () => {
    // Close worker threads.
    // Testing framework will hang if this fails
    // https://boneskull.com/mocha-v4-nears-release/#mochawontforceexit
    await workers.close();

    const cp = workers.children.get(0).child.child;
    assert(cp.killed);
  });
});
