'use strict';

const bcoin = require('../..');
const Logger = require('blgr');

// Setup logger to see what's Bcoin doing.
const logger = new Logger({
  level: 'debug'
});

// Create chain for testnet, specify chain directory
const chain = new bcoin.Chain({
  logger: logger,
  memory: true,
  network: 'testnet'
});

const mempool = new bcoin.Mempool({ chain: chain });

// Create a network pool of peers with a limit of 8 peers.
const pool = new bcoin.Pool({
  chain: chain,
  mempool: mempool,
  maxPeers: 8
});

// Create a chain indexer which indexes tx by hash
const indexer = new bcoin.TXIndexer({
  logger: logger,
  memory: true,
  network: 'testnet',
  chain: chain
});

// Open the chain, pool and indexer
(async function() {
  await logger.open();

  await pool.open();

  // Connect, start retrieving and relaying txs
  await pool.connect();

  // Start the blockchain sync.
  pool.startSync();

  await chain.open();

  await indexer.open();

  console.log('Current height:', chain.height);

  // Watch the action
  chain.on('block', (block) => {
    console.log('block: %s', block.rhash());
  });

  mempool.on('tx', (tx) => {
    console.log('tx: %s', tx.rhash);
  });

  pool.on('tx', (tx) => {
    console.log('tx: %s', tx.rhash);
  });

  await new Promise(r => setTimeout(r, 300));

  await pool.stopSync();

  const tip = await indexer.getTip();
  const block = await chain.getBlock(tip.hash);
  const meta = await indexer.getMeta(block.txs[0].hash());
  const tx = meta.tx;
  const view = await indexer.getSpentView(tx);

  console.log(`Tx with hash ${tx.rhash()}:`, meta);
  console.log(`Tx input: ${tx.getInputValue(view)},` +
    ` output: ${tx.getOutputValue()}, fee: ${tx.getFee(view)}`);

  await indexer.close();
  await chain.close();
  await pool.close();
})();
