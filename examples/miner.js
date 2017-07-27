'use strict';

const KeyRing = require('bcoin/lib/primitives/keyring');
const WorkerPool = require('bcoin/lib/workers/workerpool');
const Chain = require('bcoin/lib/blockchain/chain');
const Miner = require('bcoin/lib/mining/miner');

const key = KeyRing.generate('regtest');

const workers = new WorkerPool({
  enabled: true
});

const chain = new Chain({
  network: 'regtest',
  workers: workers
});

const miner = new Miner({
  chain: chain,
  addresses: [key.getAddress()],
  coinbaseFlags: 'my-miner',
  workers: workers
});

(async () => {
  await miner.open();

  const tmpl = await miner.createBlock();

  console.log('Block template:');
  console.log(tmpl);

  const job = await miner.cpu.createJob();
  const block = await job.mineAsync();

  console.log('Mined block:');
  console.log(block);
  console.log(block.txs[0]);

  await chain.add(block);

  console.log('New tip:');
  console.log(chain.tip);
})();
