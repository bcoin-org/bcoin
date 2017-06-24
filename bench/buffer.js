'use strict';

var fs = require('fs');
var TX = require('../lib/primitives/tx');
var BufferWriter = require('../lib/utils/writer');
var StaticWriter = require('../lib/utils/staticwriter');
var bench = require('./bench');

var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
var i, tx, end;

wtx = Buffer.from(wtx.trim(), 'hex');
tx = TX.fromRaw(wtx);

end = bench('serialize (static-writer)');
for (i = 0; i < 10000; i++) {
  tx._raw = null;
  tx._size = -1;
  tx._witness = -1;
  tx.writeWitness(new StaticWriter(tx.getWitnessSizes().total)).render();
}
end(i);

end = bench('serialize (buffer-writer)');
for (i = 0; i < 10000; i++) {
  tx._raw = null;
  tx._size = -1;
  tx._witness = -1;
  tx.writeWitness(new BufferWriter()).render();
}
end(i);
