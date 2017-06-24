'use strict';

var fs = require('fs');
var bench = require('./bench');
var Coins = require('../migrate/coins-old');
var TX = require('../lib/primitives/tx');

var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
wtx = TX.fromRaw(wtx.trim(), 'hex');

var coins = Coins.fromTX(wtx);
var i, j, end, raw, hash;

//raw = coins.toRaw();
//console.log(Coins.fromRaw(raw));

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

for (i = 0; i < 10000; i++)
  for (j = 0; j < coins.outputs.length; j++)
    coins.get(j);
end(i * coins.outputs.length);
