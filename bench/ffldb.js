'use strict';

const assert = require('../test/util/assert');
const fs = require('../lib/utils/fs');
const path = require('path');
const bench = require('./bench');
const networks = require('../lib/protocol/networks');
const FlatFileDB = require('../lib/db/ffldb');

const TESTDB = './ffldb-test';

const ffldb = new FlatFileDB(TESTDB, {'network': 'simnet'});

const rm = async (dir) => {
  const files = await fs.readdir(dir);
  for (const file of files) {
    const fp = path.join(dir, file);
    const stat = await fs.lstat(fp);
    if (stat.isDirectory()) {
      await rm(fp);
    } else {
      await fs.unlink(fp);
    }
  }
  fs.rmdir(dir);
};

(async () => {
  await ffldb.open();

  // Read Block
  {
    const key = networks.main.genesis.hash;

    const block = Buffer.from(networks.main.genesisBlock, 'hex');
    await ffldb.putBlock(key, block);

    const expected = await ffldb.getBlock(key);
    assert.bufferEqual(expected, block);

    const end = bench('read block');

    for (let i = 0; i < 100000; i++) {
      await ffldb.getBlock(key);
    }

    end(100000);
  }

  await ffldb.close();

  await rm(TESTDB);
})();
