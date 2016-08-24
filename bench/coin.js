'use strict';

var bn = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var utils = bcoin.utils;
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var bench = require('./bench');
var fs = require('fs');

var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
wtx = bcoin.tx.fromRaw(wtx.trim(), 'hex');

var coins = bcoin.coins.fromTX(wtx);
var raw;

var end = bench('serialize');
for (var i = 0; i < 10000; i++)
  raw = coins.toRaw();
end(i);

var end = bench('parse');
for (var i = 0; i < 10000; i++)
  bcoin.coins.fromRaw(raw);
end(i);

var end = bench('parse-single');
var hash = wtx.hash('hex');
for (var i = 0; i < 10000; i++)
  bcoin.coins.parseCoin(raw, hash, 5);
end(i);

var coins = bcoin.coins.fromRaw(raw);
var end = bench('get');
var j;

for (var i = 0; i < 10000; i++)
  for (var j = 0; j < coins.outputs.length; j++)
    coins.get(j);
end(i * coins.outputs.length);
