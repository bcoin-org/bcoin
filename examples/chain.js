'use strict';

const Chain = require('bcoin/lib/blockchain/chain');

const chain = new Chain({
  network: 'testnet'
});

(async () => {
  let entry;

  await chain.open();

  entry = await chain.getEntry(0);

  console.log(entry);
})();
