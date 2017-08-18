'use strict';
const bcoin = require('../..').set('main');
const Chain = bcoin.chain;
const Mempool = bcoin.mempool;
const Pool = bcoin.pool;

// Create a blockchain and store it in leveldb.
// `db` also accepts `rocksdb` and `lmdb`.
const prefix = process.env.HOME + '/my-bcoin-environment';
const chain = new Chain({
  db: 'leveldb',
  location: prefix + '/chain',
  network: 'main'
});

const mempool = new Mempool({ chain: chain });

// Create a network pool of peers with a limit of 8 peers.
const pool = new Pool({
  chain: chain,
  mempool: mempool,
  maxPeers: 8
});

// Open the pool (implicitly opens mempool and chain).
(async function() {
  await pool.open();

  // Connect, start retrieving and relaying txs
  await pool.connect();

  // Start the blockchain sync.
  pool.startSync();

  // Watch the action
  chain.on('block', (block) => {
    console.log('Connected block to blockchain:');
    console.log(block);
  });

  mempool.on('tx', (tx) => {
    console.log('Added tx to mempool:');
    console.log(tx);
  });

  pool.on('tx', (tx) => {
    console.log('Saw transaction:');
    console.log(tx.rhash);
  });
})();

// Start up a testnet sync in-memory
// while we're at it (because we can).

const tchain = new Chain({
  network: 'testnet',
  db: 'memory'
});

const tmempool = new Mempool({
  network: 'testnet',
  chain: tchain
});

const tpool = new Pool({
  network: 'testnet',
  chain: tchain,
  mempool: tmempool,
  size: 8
});

(async function() {
  await tpool.open();

  // Connect, start retrieving and relaying txs
  await tpool.connect();

  // Start the blockchain sync.
  tpool.startSync();

  tchain.on('block', (block) => {
    console.log('Added testnet block:');
    console.log(block);
  });

  tmempool.on('tx', (tx) => {
    console.log('Added testnet tx to mempool:');
    console.log(tx);
  });

  tpool.on('tx', (tx) => {
    console.log('Saw testnet transaction:');
    console.log(tx);
  });
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
