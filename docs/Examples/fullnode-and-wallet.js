'use strict';
const bcoin = require('../..').set('main');
const walletPlugin = bcoin.wallet.plugin;

const node = bcoin.fullnode({
  checkpoints: true,
  // Primary wallet passphrase
  passsphrase: 'node',
  logLevel: 'info'
});

node.use(walletPlugin);

// We get a lot of errors sometimes,
// usually from peers hanging up on us.
// Just ignore them for now.
node.on('error', (err) => {
  ;
});

// New Address we'll be sending to.
const newReceiving = 'AddressHere';

// Start the node
(async () => {
  await node.open();

  const options = {
    id: 'mywallet',
    passphrase: 'foo',
    witness: false,
    type: 'pubkeyhash'
  };

  const walletdb = node.require('walletdb');

  await walletdb.open();
  const wallet = await walletdb.create(options);

  console.log('Created wallet with address: %s', wallet.getAddress('base58'));

  await node.connect();

  // Start syncing the blockchain
  node.startSync();

  // Wait for balance and send it to a new address.
  wallet.once('balance', async (balance) => {
    // Create a transaction, fill
    // it with coins, and sign it.
    const options = {
      subtractFee: true,
      outputs: [{
        address: newReceiving,
        value: balance.total
      }]
    };

    const tx = await wallet.createTX(options);
    const stx = await wallet.sign(tx, 'foo');

    console.log('sending tx:');
    console.log(stx);

    await node.sendTX(stx);
    console.log('tx sent!');
  });

  node.chain.on('block', (block) => {
    ;
  });

  node.mempool.on('tx', (tx) => {
    ;
  });

  node.chain.on('full', () => {
    node.mempool.getHistory().then(console.log);
  });
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
