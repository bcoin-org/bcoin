'use strict';

const FullNode = require('bcoin/lib/node/fullnode');

const node = new FullNode({
  network: 'testnet',
  db: 'memory'
});

async function main() {
  await node.open();

  await node.connect();

  node.on('connect', (entry, block) => {
    console.log('%s (%d) added to chain.', entry.rhash(), entry.height);
  });

  node.on('tx', (tx) => {
    console.log('%s added to mempool.', tx.txid());
  });

  node.startSync();
}

main();
