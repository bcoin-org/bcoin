'use strict';

const fs = require('fs');
const assert = require('assert');
const networks = require('../lib/protocol/networks');
const Block = require('../lib/primitives/block');
const BlockIO = require('../lib/utils/blockio');
const BlockStream = require('../lib/utils/blockstream');
const Chain = require('../lib/blockchain/chain');

let location = process.argv[2];
const from = process.argv[3];
assert(typeof location === 'string', 'Please pass in a database path.');
assert(typeof from === 'string', 'Please pass in a blocks path.');

location = location.replace(/\.fdb\/?$/, '');

const options = {};
options.spv = process.argv.indexOf('--spv') !== -1;
options.prune = process.argv.indexOf('--prune') !== -1;
options.indexTX = process.argv.indexOf('--index-tx') !== -1;
options.indexAddress = process.argv.indexOf('--index-address') !== -1;
options.network = networks.main;

const index = process.argv.indexOf('--network');

if (index !== -1) {
  options.network = networks[process.argv[index + 1]];
  assert(options.network, 'Invalid network.');
}

const chain = new Chain({
  db: 'ffldb',
  location: location,
  network: options.network.type
});

const blockio = BlockIO({
  location: from,
  network: options.network.type
});

const blockstream = new BlockStream({network: options.network.type});

const end = new Promise((resolve, reject) => {
  blockstream.on('data', async (chunk) => {
      const block = Block.fromRaw(chunk);
      try {
        await chain.add(block);
        console.log('imported block: %s', block.rhash());
      } catch (e) {
        console.warn('%s: ', e);
      }
  })
  .on('close', () => {
    console.log('import finished');
    resolve();
  })
  .on('error', reject);
});

async function importFlatFiles() {
  const [file] = await blockio.scanFiles();
  for (let i=0; i <= file; i++) {
    const path = blockio.filepath(i);
    const blockfile = fs.createReadStream(path);
    blockfile.pipe(blockstream);
    await end;
  }
};

(async () => {
  await chain.open();
  console.log('Opened %s.', location);
  await importFlatFiles();
  await chain.close();
})().then(() => {
  console.log('Migration complete.');
  process.exit(0);
});
