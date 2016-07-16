'use strict';

var bn = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var bench = require('./bench');
var fs = require('fs');

var tx1 = parseTX('../test/data/tx3.hex');
var tx4 = parseExtended('../test/data/tx4.hex');
var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
wtx = new Buffer(wtx.trim(), 'hex');
var tx;

function parseTX(file) {
  file = fs.readFileSync(__dirname + '/' + file, 'utf8').trim().split(/\n+/);
  var tx = bcoin.tx.fromRaw(file.shift().trim(), 'hex');
  for (var i = 0; i < file.length; i++) {
    var coin = bcoin.tx.fromRaw(file[i].trim(), 'hex');
    tx.fillCoins(coin);
  }
  return tx;
}

function parseExtended(file) {
  file = fs.readFileSync(__dirname + '/' + file, 'utf8').trim();
  return bcoin.tx.fromExtended(file, true, 'hex');
}

var end = bench('parse');
for (var i = 0; i < 1000; i++)
  tx = bcoin.tx.fromRaw(wtx);
end(i);

var end = bench('serialize');
var raw;

for (var i = 0; i < 1000; i++) {
  tx._raw = null;
  raw = tx.toRaw();
}
end(i);

var end = bench('fee');
for (var i = 0; i < 1000; i++)
  tx.getFee();
end(i);

var end = bench('sanity');
for (var i = 0; i < 1000; i++)
  tx.isSane();
end(i);

var end = bench('input hashes');
for (var i = 0; i < 1000; i++)
  tx.getInputHashes('hex');
end(i);

var end = bench('output hashes');
for (var i = 0; i < 1000; i++)
  tx.getOutputHashes('hex');
end(i);

var end = bench('all hashes');
for (var i = 0; i < 1000; i++)
  tx.getHashes('hex');
end(i);

var end = bench('verify');
for (var i = 0; i < 3000; i++)
  tx1.verify(constants.flags.VERIFY_P2SH);
end(i * tx1.inputs.length);

var tx = bcoin.mtx();

for (var i = 0; i < 100; i++) {
  tx.addInput({
    prevout: {
      hash: constants.NULL_HASH,
      index: 0
    },
    script: [
      new Buffer(9),
      bcoin.ec.random(33)
    ]
  });
  tx.addOutput({
    address: bcoin.address.fromHash(bcoin.ec.random(20)),
    value: 0
  });
}

tx = tx.toTX();

var end = bench('input hashes');
for (var i = 0; i < 1000; i++)
  tx.getInputHashes('hex');
end(i);

var end = bench('output hashes');
for (var i = 0; i < 1000; i++)
  tx.getOutputHashes('hex');
end(i);

var end = bench('all hashes');
for (var i = 0; i < 1000; i++)
  tx.getHashes('hex');
end(i);
