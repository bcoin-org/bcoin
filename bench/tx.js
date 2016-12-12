'use strict';

var fs = require('fs');
var Block = require('../lib/primitives/block');
var Address = require('../lib/primitives/address');
var TX = require('../lib/primitives/tx');
var MTX = require('../lib/primitives/mtx');
var Coin = require('../lib/primitives/coin');
var CoinView = require('../lib/coins/coinview');
var constants = require('../lib/protocol/constants');
var crypto = require('../lib/crypto/crypto');
var bench = require('./bench');

var json = require('../test/data/block300025.json');
var block = Block.fromJSON(json);
var btx = { tx: block.txs[397], view: new CoinView() };

var tx3 = parseTX('../test/data/tx3.hex');
var wtx = fs.readFileSync(__dirname + '/../test/data/wtx.hex', 'utf8');
var i, tx, raw, end, flags, input;

wtx = new Buffer(wtx.trim(), 'hex');

tx = json.txs[397];
for (i = 0; i < tx.inputs.length; i++) {
  input = tx.inputs[i];
  btx.view.addCoin(Coin.fromJSON(input.coin));
}

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

end = bench('parse');
for (i = 0; i < 1000; i++)
  tx = TX.fromRaw(wtx);
end(i);

end = bench('serialize');
for (i = 0; i < 1000; i++) {
  tx._raw = null;
  raw = tx.toRaw();
}
end(i);

end = bench('hash');
for (i = 0; i < 3000; i++) {
  tx3.tx.hash();
  tx3.tx._hash = null;
}
end(i);

end = bench('witness hash');
for (i = 0; i < 3000; i++) {
  tx.witnessHash();
  tx._whash = null;
}
end(i);

end = bench('sanity');
for (i = 0; i < 1000; i++)
  tx.isSane();
end(i);

end = bench('input hashes');
for (i = 0; i < 1000; i++)
  tx.getInputHashes(null, 'hex');
end(i);

end = bench('output hashes');
for (i = 0; i < 1000; i++)
  tx.getOutputHashes('hex');
end(i);

end = bench('all hashes');
for (i = 0; i < 1000; i++)
  tx.getHashes(null, 'hex');
end(i);

end = bench('verify');
for (i = 0; i < 3000; i++)
  tx3.tx.verify(tx3.view, constants.flags.VERIFY_P2SH);
end(i * tx3.tx.inputs.length);

end = bench('fee');
for (i = 0; i < 1000; i++)
  tx3.tx.getFee(tx3.view);
end(i);

flags = constants.flags.VERIFY_P2SH | constants.flags.VERIFY_DERSIG;
end = bench('verify multisig');
for (i = 0; i < 3000; i++)
  btx.tx.verify(btx.view, flags);
end(i * btx.tx.inputs.length);

tx = new MTX();

for (i = 0; i < 100; i++) {
  tx.addInput({
    prevout: {
      hash: constants.NULL_HASH,
      index: 0
    },
    script: [
      new Buffer(9),
      crypto.randomBytes(33)
    ]
  });
  tx.addOutput({
    address: Address.fromHash(crypto.randomBytes(20)),
    value: 0
  });
}

tx = tx.toTX();

end = bench('input hashes');
for (i = 0; i < 1000; i++)
  tx.getInputHashes(null, 'hex');
end(i);

end = bench('output hashes');
for (i = 0; i < 1000; i++)
  tx.getOutputHashes('hex');
end(i);

end = bench('all hashes');
for (i = 0; i < 1000; i++)
  tx.getHashes(null, 'hex');
end(i);
