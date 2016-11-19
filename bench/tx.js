'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var util = bcoin.util;
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var bench = require('./bench');
var fs = require('fs');

bcoin.cache();

var block = bcoin.block.fromJSON(require('../test/data/block300025.json'));
var btx = block.txs[397];

var tx1 = parseTX('../test/data/tx3.hex');
var tx4 = parseTX('../test/data/tx4.hex');
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

var end = bench('hash');
for (var i = 0; i < 3000; i++) {
  tx1.hash();
  tx1._hash = null;
}
end(i);

var end = bench('witness hash');
for (var i = 0; i < 3000; i++) {
  tx.witnessHash();
  tx._whash = null;
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

var flags = constants.flags.VERIFY_P2SH | constants.flags.VERIFY_DERSIG;
var end = bench('verify multisig');
for (var i = 0; i < 3000; i++)
  btx.verify(flags);
end(i * btx.inputs.length);

var tx = bcoin.mtx();

for (var i = 0; i < 100; i++) {
  tx.addInput({
    prevout: {
      hash: constants.NULL_HASH,
      index: 0
    },
    script: [
      new Buffer(9),
      bcoin.crypto.randomBytes(33)
    ]
  });
  tx.addOutput({
    address: bcoin.address.fromHash(bcoin.crypto.randomBytes(20)),
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
