'use strict';

const bcoin = require('../..');

bcoin.set('regtest');

// SPV chains only store the chain headers.
const chain = new bcoin.Chain({
  spv: true
});

const pool = new bcoin.Pool({
  chain: chain,
  maxOutbound: 1
});

const walletdb = new bcoin.wallet.WalletDB({ memory: true });

// Full node will provide tx data to SPV node
const full = {};
full.chain = new bcoin.Chain();
full.pool = new bcoin.Pool({
  chain: full.chain,
  port: 44444,
  bip37: true,
  listen: true
});

(async () => {
  await pool.open();
  await walletdb.open();
  await chain.open();
  await pool.connect();

  await full.pool.open();
  await full.chain.open();
  await full.pool.connect();

  const wallet = await walletdb.create();
  const walletAddress = await wallet.receiveAddress();
  console.log('Created wallet with address %s', walletAddress);

  // Add our address to the SPV filter.
  pool.watchAddress(walletAddress);

  // Start the blockchain sync.
  pool.startSync();

  // Get ready to receive transactions!
  pool.on('tx', (tx) => {
    console.log('Received TX:\n', tx);

    walletdb.addTX(tx);
    console.log('TX added to wallet DB!');
  });

  wallet.on('balance', (balance) => {
    console.log('Balance updated:\n', balance.toJSON());
  });

  // Connect the SPV node to the full node server
  const netAddr = await pool.hosts.addNode('127.0.0.1:44444');
  const peer = pool.createOutbound(netAddr);
  pool.peers.add(peer);

  full.pool.on('peer open', async () => {
    console.log('SPV node peers:\n', pool.peers);
    console.log('Full node peers:\n', full.pool.peers);

    // Create a dummy transaction and send it from full to SPV node
    const mtx = new bcoin.MTX();
    mtx.addOutpoint(new bcoin.Outpoint(bcoin.consensus.ZERO_HASH, 0));
    mtx.addOutput(walletAddress, 12000);
    const tx = mtx.toTX();

    // Give the node a few seconds to process connection before sending
    console.log('Waiting for transaction...');
    await new Promise(r => setTimeout(r, 3000));
    await full.pool.broadcast(tx);
  });
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
