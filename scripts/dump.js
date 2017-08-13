'use strict';

const heapdump = require('heapdump');
const MempoolEntry = require('../lib/mempool/mempoolentry');
const Coins = require('../lib/coins/coins');
const common = require('../test/util/common');

const [tx, view] = common.readTX('tx4').getTX();
const coins = Coins.fromTX(tx, 0);
const entry = MempoolEntry.fromTX(tx, view, 1000000);

setInterval(() => {
  console.log(tx.hash('hex'));
  console.log(coins.outputs.length);
  console.log(entry.tx);
}, 60 * 1000);

setImmediate(() => {
  heapdump.writeSnapshot(`${__dirname}/../dump.heapsnapshot`, (err) => {
    if (err)
      throw err;
  });
});
