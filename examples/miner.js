'use strict';

var Chain = require('bcoin/lib/blockchain/chain');
var Miner = require('bcoin/lib/mining/miner');

var chain = new Chain({
  network: 'regtest'
});

var miner = new Miner({
  chain: chain,
  addresses: ['mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8'],
  coinbaseFlags: 'my-miner'
});

async function main() {
  var tmpl, job, block;

  await miner.open();

  tmpl = await miner.createBlock();

  console.log('Block template:');
  console.log(tmpl);

  job = await miner.cpu.createJob();
  block = await job.mineAsync();

  console.log('Mined block:');
  console.log(block);

  await chain.add(block);

  console.log('New tip:');
  console.log(chain.tip);
}

main();
