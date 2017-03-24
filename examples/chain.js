'use strict';

var Chain = require('bcoin/lib/blockchain/chain');

var chain = new Chain({
  network: 'testnet'
});

async function main() {
  var entry;

  await chain.open();

  entry = await chain.getEntry(0);

  console.log(entry);
}

main();
