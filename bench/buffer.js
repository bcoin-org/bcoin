'use strict';

var fs = require('fs');
var TX = require('../lib/primitives/tx');
var CoinView = require('../lib/coins/coinview');
var BufferWriter = require('../lib/utils/writer');
var StaticWriter = require('../lib/utils/staticwriter');
var bench = require('./bench');

var tx3 = parseTX('../test/data/tx3.hex');
var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
var i, tx, end, raw;

wtx = new Buffer(wtx.trim(), 'hex');
tx = TX.fromRaw(wtx);

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

end = bench('serialize (static-writer)');
for (i = 0; i < 10000; i++) {
  tx._raw = null;
  tx._size = -1;
  tx._witness = -1;
  raw = tx.writeWitness(new StaticWriter(tx.getWitnessSizes().total)).render();
}
end(i);

end = bench('serialize (buffer-writer)');
for (i = 0; i < 10000; i++) {
  tx._raw = null;
  tx._size = -1;
  tx._witness = -1;
  raw = tx.writeWitness(new BufferWriter()).render();
}
end(i);
