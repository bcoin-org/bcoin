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

const json = require('../test/data/block300025.json');
const block = Block.fromJSON(json);
const btx = { tx: block.txs[397], view: new CoinView() };

const tx3 = parseTX('../test/data/tx3.hex');
const hex = fs.readFileSync(`${__dirname}/../test/data/wtx.hex`, 'utf8');
const raw = Buffer.from(hex.trim(), 'hex');

{
  const tx = json.txs[397];
  for (const input of tx.inputs)
    btx.view.addCoin(Coin.fromJSON(input.coin));
}

function parseTX(file) {
  const data = fs.readFileSync(`${__dirname}/${file}`, 'utf8');
  const parts = data.trim().split(/\n+/);
  const raw = parts[0];
  const tx = TX.fromRaw(raw.trim(), 'hex');
  const view = new CoinView();

  for (let i = 1; i < parts.length; i++) {
    const raw = parts[i];
    const prev = TX.fromRaw(raw.trim(), 'hex');
    view.addTX(prev, -1);
  }

  return { tx: tx, view: view };
}

{
  const end = bench('parse');
  for (let i = 0; i < 1000; i++)
    TX.fromRaw(raw);
  end(1000);
}

{
  const end = bench('serialize');
  for (let i = 0; i < 1000; i++) {
    tx._raw = null;
    tx.toRaw();
  }
  end(1000);
}

{
  const end = bench('hash');
  for (let i = 0; i < 3000; i++) {
    tx3.tx.hash();
    tx3.tx._hash = null;
  }
  end(3000);
}

{
  const end = bench('witness hash');
  for (let i = 0; i < 3000; i++) {
    tx.witnessHash();
    tx._whash = null;
  }
  end(3000);
}

{
  const end = bench('sanity');
  for (let i = 0; i < 1000; i++)
    tx.isSane();
  end(1000);
}

{
  const end = bench('input hashes');
  for (let i = 0; i < 1000; i++)
    tx.getInputHashes(null, 'hex');
  end(1000);
}

{
  const end = bench('output hashes');
  for (let i = 0; i < 1000; i++)
    tx.getOutputHashes('hex');
  end(1000);
}

{
  const end = bench('all hashes');
  for (let i = 0; i < 1000; i++)
    tx.getHashes(null, 'hex');
  end(1000);
}

{
  const end = bench('verify');
  for (let i = 0; i < 3000; i++)
    tx3.tx.verify(tx3.view, Script.flags.VERIFY_P2SH);
  end(3000 * tx3.tx.inputs.length);
}

{
  const end = bench('verify2');
  const script = tx3.view.getOutputFor(tx3.tx.inputs[0]).script;
  for (let i = 0; i < 100000; i++)
    tx3.tx.signatureHashV0(0, script, Script.hashType.ALL);
  end(100000);
}

{
  const end = bench('fee');
  for (let i = 0; i < 1000; i++)
    tx3.tx.getFee(tx3.view);
  end(1000);
}

{
  const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
  const end = bench('verify multisig');
  for (let i = 0; i < 3000; i++)
    btx.tx.verify(btx.view, flags);
  end(3000 * btx.tx.inputs.length);
}

const mtx = new MTX();

for (let i = 0; i < 100; i++) {
  mtx.addInput({
    prevout: {
      hash: encoding.NULL_HASH,
      index: 0
    },
    script: [
      Buffer.allocUnsafe(9),
      random.randomBytes(33)
    ]
  });
  mtx.addOutput({
    address: Address.fromHash(random.randomBytes(20)),
    value: 0
  });
}

const tx = mtx.toTX();

{
  const end = bench('input hashes');
  for (let i = 0; i < 1000; i++)
    tx.getInputHashes(null, 'hex');
  end(1000);
}

{
  const end = bench('output hashes');
  for (let i = 0; i < 1000; i++)
    tx.getOutputHashes('hex');
  end(1000);
}

{
  const end = bench('all hashes');
  for (let i = 0; i < 1000; i++)
    tx.getHashes(null, 'hex');
  end(1000);
}
