'use strict';

const path = require('path');
const bcoin = require('../..');
const Chain = bcoin.chain;
const Logger = bcoin.logger;
const util = bcoin.util;

const HOME = process.env.HOME;

// Setup logger to see what's Bcoin doing.
const logger = new Logger({
  level: 'debug'
});

// Create chain for testnet, specify chain directory
const chain = new Chain({
  logger: logger,
  network: 'testnet',
  db: 'leveldb',
  prefix: path.join(HOME, '.bcoin/testnet'),
  indexTX: true,
  indexAddress: true
});

(async () => {
  await logger.open();
  await chain.open();

  console.log('Current height:', chain.height);

  const entry = await chain.getEntry(50000);
  console.log('Block at 50k:', entry);

  // eslint-disable-next-line max-len
  const txhash = '4dd628123dcde4f2fb3a8b8a18b806721b56007e32497ebe76cde598ce1652af';
  const txmeta = await chain.db.getMeta(util.revHex(txhash));
  const tx = txmeta.tx;
  const coinview = await chain.db.getSpentView(tx);

  console.log(`Tx with hash ${txhash}:`, txmeta);
  console.log(`Tx input: ${tx.getInputValue(coinview)},` +
    ` output: ${tx.getOutputValue()}, fee: ${tx.getFee(coinview)}`);

  // eslint-disable-next-line max-len
  const bhash = '00000000077eacdd2c803a742195ba430a6d9545e43128ba55ec3c80beea6c0c';
  const block = await chain.db.getBlock(util.revHex(bhash));
  console.log(`Block with hash ${bhash}:`, block);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
