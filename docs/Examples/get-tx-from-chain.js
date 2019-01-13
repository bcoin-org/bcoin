'use strict';

const bcoin = require('../..');
const fs = require('bfile');

// Create chain for testnet, stored in memory by default.
// To store the chain on disk at the `prefix` location,
// set `memory: false`.
const chain = new bcoin.Chain({
  network: 'testnet',
  indexTX: true,
  indexAddress: true,
  db: 'leveldb',
  prefix: '/tmp/bcoin-testnet-example',
  memory: true
});

// Create a network pool of peers with a limit of 8 peers.
const pool = new bcoin.Pool({
  chain: chain,
  maxPeers: 8
});

(async () => {
  // Ensure the directory exists if we are writing to disk
  if (!chain.options.memory)
    await fs.mkdirp(chain.options.prefix);

  await chain.open();

  // Connect the blockchain to the network
  await pool.open();
  await pool.connect();
  pool.startSync();

  // Monitor blockchain height and react when we hit the target
  chain.on('connect', async (entry, block) => {
    const height = entry.height;
    console.log(
      `Height: ${chain.height} ` +
      `Block: ${entry.rhash()} ` +
      `TXs: ${block.txs.length}`
    );

    if (height === 1000) {
      const entry = await chain.getEntry(1000);
      console.log('Block at height 1000:\n', entry);

      // testnet tx at height 500
      const txhash =
        'fc407d7a3b819daa5cf1ecc2c2a4b103c3782104d1425d170993bd534779a0da';
      const txhashBuffer = Buffer.from(txhash, 'hex').reverse();

      const txmeta = await chain.db.getMeta(txhashBuffer);
      const tx = txmeta.tx;
      const coinview = await chain.db.getSpentView(tx);

      console.log(`Tx with hash ${txhash}:\n`, txmeta);
      console.log(
        `\n  Input value: ${tx.getInputValue(coinview)}` +
        `\n  Output value: ${tx.getOutputValue()}` +
        `\n  Fee: ${tx.getFee(coinview)}`
      );

      // testnet block at height 800
      const hash =
        Buffer.from(
          '000000004df86f64cca38c6587df348e0c6849ebee628b3f840f552c707cc862',
          'hex'
        );
      // chainDB indexes blocks by the REVERSE (little endian) hash
      const block = await chain.getBlock(hash.reverse());
      console.log(`Block with hash ${hash.toString('hex')}:`, block);

      process.exit(1);
    }
  });
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
