'use strict';

var fs = require('fs');
var assert = require('assert');
var util = require('../lib/utils/util');
var Coins = require('../lib/blockchain/coins');
var TX = require('../lib/primitives/tx');
var bench = require('./bench');

var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
var i, j, coins, raw, end;

wtx = TX.fromRaw(wtx.trim(), 'hex');
coins = Coins.fromTX(wtx);

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
