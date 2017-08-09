'use strict';

const heapdump = require('heapdump');
const fs = require('../lib/utils/fs');
const MempoolEntry = require('../lib/mempool/mempoolentry');
const Coins = require('../lib/coins/coins');
const TX = require('../lib/primitives/tx');
const common = require('../test/util/common');

const SNAPSHOT = `${__dirname}/../dump.heapsnapshot`;

const {tx, view} = common.parseTX('data/tx4.hex');
const coins = Coins.fromTX(tx, 0);
const entry = MempoolEntry.fromTX(tx, view, 1000000);

setInterval(() => {
  console.log(tx.hash('hex'));
  console.log(coins.outputs.length);
  console.log(entry.tx);
}, 60 * 1000);

setImmediate(() => {
  heapdump.writeSnapshot(SNAPSHOT, (err) => {
    if (err)
      throw err;
  });
});
