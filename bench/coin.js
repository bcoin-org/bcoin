'use strict';

var fs = require('fs');
var Coins = require('../lib/blockchain/coins');
var TX = require('../lib/primitives/tx');
var bench = require('./bench');

var raw = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
var wtx = TX.fromRaw(raw.trim(), 'hex');
var coins = Coins.fromTX(wtx);
var i, j, end, hash;

end = bench('serialize');
for (i = 0; i < 10000; i++)
  raw = coins.toRaw();
end(i);

end = bench('parse');
for (i = 0; i < 10000; i++)
  Coins.fromRaw(raw);
end(i);

end = bench('parse-single');
hash = wtx.hash('hex');
for (i = 0; i < 10000; i++)
  Coins.parseCoin(raw, hash, 5);
end(i);

coins = Coins.fromRaw(raw);
end = bench('get');
for (i = 0; i < 10000; i++) {
  for (j = 0; j < coins.outputs.length; j++)
    coins.get(j);
}
end(i * coins.outputs.length);
