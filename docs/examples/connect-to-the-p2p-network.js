'use strict';

const bcoin = require('../..').set('main');

const Logger = require('blgr');

// Setup logger to see what's Bcoin doing.
const logger = new Logger({
  level: 'info'
});

// Create a blockchain and store it in memory.
const chain = new bcoin.Chain({
  memory: true,
  network: 'main',
  logger: logger
});

const mempool = new bcoin.Mempool({
  chain: chain,
  logger: logger
});

// Create a network pool of peers with a limit of 8 peers.
const pool = new bcoin.Pool({
  chain: chain,
  mempool: mempool,
  maxPeers: 8,
  logger: logger
});

(async function() {
  await logger.open();
  await chain.open();

  await pool.open();

  // Connect, start retrieving and relaying txs
  await pool.connect();

  // Start the blockchain sync.
  pool.startSync();

  // Watch the action
  const color = '\x1b[31m';
  chain.on('block', (block) => {
    console.log(color, 'Added mainnet block:');
    console.log(block.rhash());
  });

  mempool.on('tx', (tx) => {
    console.log(color, 'Added mainnet tx to mempool:');
    console.log(tx.rhash);
  });

  pool.on('tx', (tx) => {
    console.log(color, 'Saw mainnet transaction:');
    console.log(tx.rhash);
  });
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});;

// Start up a testnet sync in-memory
// while we're at it (because we can).

const tchain = new bcoin.Chain({
  memory: true,
  network: 'testnet',
  logger: logger
});

const tmempool = new bcoin.Mempool({
  network: 'testnet',
  chain: tchain,
  logger: logger
});

const tpool = new bcoin.Pool({
  network: 'testnet',
  chain: tchain,
  mempool: tmempool,
  size: 8,
  logger: logger
});

(async function() {
  await tchain.open();

  await tpool.open();

  // Connect, start retrieving and relaying txs
  await tpool.connect();

  // Start the blockchain sync.
  tpool.startSync();

  const color = '\x1b[32m';
  tchain.on('block', (block) => {
    console.log(color, 'Added testnet block:');
    console.log(block.rhash());
  });

  tmempool.on('tx', (tx) => {
    console.log(color, 'Added testnet tx to mempool:');
    console.log(tx.rhash);
  });

  tpool.on('tx', (tx) => {
    console.log(color, 'Saw testnet transaction:');
    console.log(tx.rhash);
  });
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
