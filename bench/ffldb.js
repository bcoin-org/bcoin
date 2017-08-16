'use strict';

const assert = require('../test/util/assert');
const fs = require('../lib/utils/fs');
const path = require('path');
const bench = require('./bench');
const co = require('../lib/utils/co');
const networks = require('../lib/protocol/networks');
const FlatFileDB = require('../lib/db/ffldb');

const TESTDB = './ffldb-test';

const ffldb = new FlatFileDB(TESTDB);

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
  const open = co.promisify(ffldb.open);
  await open.call(ffldb);

  // Block
  {
    const key = networks.main.genesis.hash;

    const block = Buffer.from(networks.main.genesisBlock, 'hex');
    await ffldb.putBlock(key, block);

    const end = bench('block');
    const expected = await ffldb.getBlock(key);
    assert.bufferEqual(expected, block);
    end(1);
  }

  const close = co.promisify(ffldb.close);
  await close.call(ffldb);

  await rm(TESTDB);
})();
