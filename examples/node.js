'use strict';

var FullNode = require('bcoin/lib/node/fullnode');

var node = new FullNode({
  network: 'testnet',
  db: 'memory'
});

async function main() {
  await node.open();

  await node.connect();

  node.on('connect', function(entry, block) {
    console.log('%s (%d) added to chain.', entry.rhash(), entry.height);
  });

  node.on('tx', function(tx) {
    console.log('%s added to mempool.', tx.txid());
  });

  node.startSync();
}

main();
