'use strict';

var BN = require('bn.js');
var constants = require('../lib/protocol/constants');
var util = require('../lib/utils/util');
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var bench = require('./bench');
var fs = require('fs');
var Coins = require('../lib/blockchain/coins');
var TX = require('../lib/primitives/tx');

var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
wtx = TX.fromRaw(wtx.trim(), 'hex');

var coins = Coins.fromTX(wtx);
var raw;
//raw = coins.toRaw2();
//console.log(Coins.fromRaw2(raw));

var end = bench('serialize');
for (var i = 0; i < 10000; i++)
  raw = coins.toRaw2();
end(i);

var end = bench('parse');
for (var i = 0; i < 10000; i++)
  Coins.fromRaw2(raw);
end(i);

var end = bench('parse-single');
var hash = wtx.hash('hex');
for (var i = 0; i < 10000; i++)
  Coins.parseCoin2(raw, hash, 5);
end(i);

var coins = Coins.fromRaw2(raw);
var end = bench('get');
var j;

for (var i = 0; i < 10000; i++)
  for (var j = 0; j < coins.outputs.length; j++)
    coins.get2(j);
end(i * coins.outputs.length);
