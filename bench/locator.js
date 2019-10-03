/*!
 * bench/locator.js - benchmark locator for bcoin
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {isAbsolute} = require('path');
const {mkdirp, exists} = require('bfile');
const Chain = require('../lib/blockchain/chain');
const common = require('../lib/blockchain/common');
const BlockStore = require('../lib/blockstore/file');
const WorkerPool = require('../lib/workers/workerpool');
const Network = require('../lib/protocol/network');
const Headers = require('../lib/primitives/headers');
const {processArgs, hrToSeconds} = require('./utils');

const config = {
  'location': {
    value: true,
    valid: a => isAbsolute(a),
    fallback: '/tmp/bcoin-bench-locator'
  }
};

(async () => {
  const network = Network.get('regtest');

  let settings = null;
  try {
    settings = processArgs(process.argv, config);
  } catch (err) {
    console.log(err.message);
    process.exit(1);
  }

  const generated = await exists(settings.location);
  if (!generated)
    await mkdirp(settings.location);

  const workers = new WorkerPool({enabled: true});

  const blocks = new BlockStore({
    network,
    location: settings.location
  });

  const chain = new Chain({
    memory: false,
    prefix: settings.location,
    blocks,
    network,
    workers,
    logLevel: 'debug'
  });

  await workers.open();
  await blocks.open();
  await chain.open();

  async function addHeaders(count) {
    const flags = common.flags.DEFAULT_FLAGS & ~common.flags.VERIFY_POW;
    const interval = 1;
    let last = network.genesis.hash;
    let time = network.genesis.time + interval;
    let height = 1;

    for (let i = 0; i < count; i++) {
      const header = new Headers();
      header.time = time;
      header.version = 1;
      header.height = height;

      if (height >= network.block.bip34height)
        header.version = 2;

      if (height >= network.block.bip66height)
        header.version = 3;

      if (height >= network.block.bip65height)
        header.version = 4;

      const prev = await chain.getEntry(last);
      const bits = await chain.getTarget(header.time, prev);
      header.bits = bits;

      if (last)
        header.prevBlock = last;

      await chain.addHeader(header, flags);

      last = header.hash();
      time += interval;
      height += 1;
    }
  }

  if (!generated) {
    console.log('Building chain...');
    await addHeaders(600000);
    console.log('Done.');
  }

  const tips = await chain.db.getTipEntries({reverse: true});
  const best = tips[0];

  console.log('Starting benchmark...');
  const start = process.hrtime();
  const locator = await chain.getLocator(best.hash);
  console.log('locator:', locator);
  const diff = process.hrtime(start);
  console.log('Done.');

  console.log('time: %ds', hrToSeconds(diff).toFixed(2));

  await workers.close();
  await blocks.close();
  await chain.close();
})();
