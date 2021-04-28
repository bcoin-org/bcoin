'use strict';

const bcoin = require('../..');

const node = new bcoin.FullNode({
  memory: true,
  network: 'testnet',
  workers: true
});

(async () => {
  await node.open();
  await node.connect();

  node.on('connect', (entry, block) => {
    console.log('%s (%d) added to chain.', entry.rhash(), entry.height);
  });

  node.on('tx', (tx) => {
    console.log('%s added to mempool.', tx.txid());
  });

  node.startSync();
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
