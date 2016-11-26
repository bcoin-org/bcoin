var fs = require('fs');
var heapdump = require('heapdump');

var MempoolEntry = require('../lib/mempool/mempoolentry');
var Coins = require('../lib/blockchain/coins');
var TX = require('../lib/primitives/tx');

var SNAPSHOT = __dirname + '/../dump.heapsnapshot';
var tx = parseTX('../test/data/tx4.hex');

function parseTX(file) {
  var filename = __dirname + '/' + file;
  var data = fs.readFileSync(filename, 'utf8');
  var parts = data.trim().split(/\n+/);
  var hex = parts[0].trim();
  var tx = TX.fromRaw(hex, 'hex');
  var i, tx, coin;

  for (i = 1; i < parts.length; i++) {
    hex = parts[i].trim();
    coin = TX.fromRaw(hex, 'hex');
    tx.fillCoins(coin);
  }

  return tx;
}

var coins = Coins.fromRaw(Coins.fromTX(tx).toRaw(), tx.hash('hex'));
var entry = MempoolEntry.fromTX(tx, 1000000);

setInterval(function() {
  console.log(tx.hash('hex'));
  console.log(coins.hash);
  console.log(entry.tx);
}, 60 * 1000)

setImmediate(function() {
  heapdump.writeSnapshot(SNAPSHOT, function(err) {
    if (err)
      throw err;
  });
});
