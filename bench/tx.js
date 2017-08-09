'use strict';

const fs = require('../lib/utils/fs');
const Block = require('../lib/primitives/block');
const Address = require('../lib/primitives/address');
const TX = require('../lib/primitives/tx');
const Script = require('../lib/script/script');
const MTX = require('../lib/primitives/mtx');
const encoding = require('../lib/utils/encoding');
const random = require('../lib/crypto/random');
const common = require('../test/util/common');
const bench = require('./bench');

const blockRaw = fs.readFileSync(`${__dirname}/../test/data/block300025.raw`);
const undoRaw = fs.readFileSync(`${__dirname}/../test/data/undo300025.raw`);

const block = Block.fromRaw(blockRaw);
const undo = common.parseUndo(undoRaw);

const btx = {
  tx: block.txs[397],
  view: common.applyUndo(block, undo)
};

const tx3 = common.parseTX('data/tx3.hex');
const tx5 = common.parseTX('data/tx5.hex');
const raw = tx5.tx.toRaw();

{
  const end = bench('parse');

  for (let i = 0; i < 1000; i++)
    TX.fromRaw(raw);

  end(1000);
}

{
  const end = bench('serialize');

  for (let i = 0; i < 1000; i++) {
    tx5.tx._raw = null;
    tx5.tx.toRaw();
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
    tx5.tx.witnessHash();
    tx5.tx._whash = null;
  }

  end(3000);
}

{
  const end = bench('sanity');

  for (let i = 0; i < 1000; i++)
    tx5.tx.isSane();

  end(1000);
}

{
  const end = bench('input hashes');

  for (let i = 0; i < 1000; i++)
    tx5.tx.getInputHashes(null, 'hex');

  end(1000);
}

{
  const end = bench('output hashes');

  for (let i = 0; i < 1000; i++)
    tx5.tx.getOutputHashes('hex');

  end(1000);
}

{
  const end = bench('all hashes');

  for (let i = 0; i < 1000; i++)
    tx5.tx.getHashes(null, 'hex');

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
  const {script} = tx3.view.getOutputFor(tx3.tx.inputs[0]);

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

const tx2 = mtx.toTX();

{
  const end = bench('input hashes');

  for (let i = 0; i < 1000; i++)
    tx2.getInputHashes(null, 'hex');

  end(1000);
}

{
  const end = bench('output hashes');

  for (let i = 0; i < 1000; i++)
    tx2.getOutputHashes('hex');

  end(1000);
}

{
  const end = bench('all hashes');

  for (let i = 0; i < 1000; i++)
    tx2.getHashes(null, 'hex');

  end(1000);
}
