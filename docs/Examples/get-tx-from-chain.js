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
  const txhash = '7f5990b008a2d0fc006d13b15e25d05ff30fadab656d49a5c6afea0e0d0b458c';
  const txmeta = await chain.db.getMeta(util.revHex(txhash));
  console.log(`Tx with hash ${txhash}:`, txmeta);

  // eslint-disable-next-line max-len
  const bhash = '00000000077eacdd2c803a742195ba430a6d9545e43128ba55ec3c80beea6c0c';
  const block = await chain.db.getBlock(util.revHex(bhash));

  console.log(`Block with hash ${bhash}:`, block);
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
