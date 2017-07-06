'use strict';

const fs = require('fs');
const Block = require('../lib/primitives/block');
const Address = require('../lib/primitives/address');
const TX = require('../lib/primitives/tx');
const Script = require('../lib/script/script');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const CoinView = require('../lib/coins/coinview');
const encoding = require('../lib/utils/encoding');
const random = require('../lib/crypto/random');
const bench = require('./bench');

let json = require('../test/data/block300025.json');
let block = Block.fromJSON(json);
let btx = { tx: block.txs[397], view: new CoinView() };

let tx3 = parseTX('../test/data/tx3.hex');
let wtx = fs.readFileSync(`${__dirname}/../test/data/wtx.hex`, 'utf8');
let i, tx, end, flags, input;

wtx = Buffer.from(wtx.trim(), 'hex');

tx = json.txs[397];
for (i = 0; i < tx.inputs.length; i++) {
  input = tx.inputs[i];
  btx.view.addCoin(Coin.fromJSON(input.coin));
}

function parseTX(file) {
  let data = fs.readFileSync(`${__dirname}/${file}`, 'utf8');
  let parts = data.trim().split(/\n+/);
  let raw = parts[0];
  let tx = TX.fromRaw(raw.trim(), 'hex');
  let view = new CoinView();
  let i, prev;

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
  tx.toRaw();
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
  tx3.tx.verify(tx3.view, Script.flags.VERIFY_P2SH);
end(i * tx3.tx.inputs.length);

end = bench('verify2');
let script = tx3.view.getOutputFor(tx3.tx.inputs[0]).script;
for (i = 0; i < 100000; i++)
  tx3.tx.signatureHashV0(0, script, Script.hashType.ALL);
end(i);

end = bench('fee');
for (i = 0; i < 1000; i++)
  tx3.tx.getFee(tx3.view);
end(i);

flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
end = bench('verify multisig');
for (i = 0; i < 3000; i++)
  btx.tx.verify(btx.view, flags);
end(i * btx.tx.inputs.length);

tx = new MTX();

for (i = 0; i < 100; i++) {
  tx.addInput({
    prevout: {
      hash: encoding.NULL_HASH,
      index: 0
    },
    script: [
      Buffer.allocUnsafe(9),
      random.randomBytes(33)
    ]
  });
  tx.addOutput({
    address: Address.fromHash(random.randomBytes(20)),
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
