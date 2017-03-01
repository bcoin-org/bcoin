'use strict';

var fs = require('fs');
var heapdump = require('heapdump');
var MempoolEntry = require('../lib/mempool/mempoolentry');
var Coins = require('../lib/coins/coins');
var TX = require('../lib/primitives/tx');
var CoinView = require('../lib/coins/coinview');

var SNAPSHOT = __dirname + '/../dump.heapsnapshot';
var tx = parseTX('../test/data/tx4.hex');
var raw, coins, entry;

function parseTX(file) {
  var data = fs.readFileSync(__dirname + '/' + file, 'utf8');
  var parts = data.trim().split(/\n+/);
  var raw = parts[0];
  var tx = TX.fromRaw(raw.trim(), 'hex');
  var view = new CoinView();
  var i, prev;

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

setInterval(function() {
  console.log(tx.hash('hex'));
  console.log(coins.hash);
  console.log(entry.tx);
}, 60 * 1000);

setImmediate(function() {
  heapdump.writeSnapshot(SNAPSHOT, function(err) {
    if (err)
      throw err;
  });
});
