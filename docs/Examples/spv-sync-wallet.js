'use strict';

const bcoin = require('../..');
const Chain = bcoin.chain;
const Pool = bcoin.pool;
const WalletDB = bcoin.walletdb;

bcoin.set('testnet');

// SPV chains only store the chain headers.
const chain = Chain({
  db: 'leveldb',
  location: process.env.HOME + '/spvchain',
  spv: true
});

const pool = new Pool({
  chain: chain,
  spv: true,
  maxPeers: 8
});

const walletdb = new WalletDB({ db: 'memory' });

(async () => {
  await pool.open();
  await walletdb.open();

  const wallet = await walletdb.create();

  console.log('Created wallet with address %s', wallet.getAddress('base58'));

  // Add our address to the spv filter.
  pool.watchAddress(wallet.getAddress());

  // Connect, start retrieving and relaying txs
  await pool.connect();

  // Start the blockchain sync.
  pool.startSync();

  pool.on('tx', async (tx) => {
    console.log('received TX');

    await walletdb.addTX(tx);
    console.log('Transaction added to walletDB');
  });

  wallet.on('balance', (balance) => {
    console.log('Balance updated.');
    console.log(bcoin.amount.btc(balance.unconfirmed));
  });
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
