'use strict';
const bcoin = require('../..');
const Chain = bcoin.chain;
const Mempool = bcoin.mempool;
const Miner = bcoin.miner;

// Default network (so we can avoid passing
// the `network` option into every object below.)
bcoin.set('regtest');

// Start up a blockchain, mempool, and miner using in-memory
// databases (stored in a red-black tree instead of on-disk).
const chain = new Chain({ db: 'memory' });
const mempool = new Mempool({ chain: chain });
const miner = new Miner({
  chain: chain,
  mempool: mempool,

  // Make sure miner won't block the main thread.
  useWorkers: true
});

(async () => {
  // Open the miner (initialize the databases, etc).
  // Miner will implicitly call `open` on chain and mempool.
  await miner.open();

  // Create a Cpu miner job
  const job = await miner.createJob();

  // run miner
  const block = await job.mineAsync();

  // Add the block to the chain
  console.log('Adding %s to the blockchain.', block.rhash);
  console.log(block);
  await chain.add(block);
  console.log('Added block!');
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
