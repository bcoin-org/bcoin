'use strict';

const fs = require('fs');
const heapdump = require('heapdump');
const MempoolEntry = require('../lib/mempool/mempoolentry');
const Coins = require('../lib/coins/coins');
const TX = require('../lib/primitives/tx');
const CoinView = require('../lib/coins/coinview');

let SNAPSHOT = `${__dirname}/../dump.heapsnapshot`;
let tx = parseTX('../test/data/tx4.hex');
let raw, coins, entry;

function parseTX(file) {
  let data = fs.readFileSync(`${__dirname}/${file}`, 'utf8');
  let parts = data.trim().split(/\n+/);
  let raw = parts[0];
  let tx = TX.fromRaw(raw.trim(), 'hex');
  let view = new CoinView();
  let i, prev;

  for (i = 1; i < parts.length; i++) {
    raw = parts[i];
    prev = TX.fromRaw(raw.trim(), 'hex');
    view.addTX(prev, -1);
  }

  return { tx: tx, view: view };
}

raw = Coins.fromTX(tx.tx, 0).toRaw();
coins = Coins.fromRaw(raw, tx.tx.hash('hex'));
entry = MempoolEntry.fromTX(tx.tx, tx.view, 1000000);

setInterval(() => {
  console.log(tx.hash('hex'));
  console.log(coins.hash);
  console.log(entry.tx);
}, 60 * 1000);

setImmediate(() => {
  heapdump.writeSnapshot(SNAPSHOT, (err) => {
    if (err)
      throw err;
  });
});
