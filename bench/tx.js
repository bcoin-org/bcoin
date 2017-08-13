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

const tx3 = common.readTX('tx3');
const tx5 = common.readTX('tx5');
const tx10 = common.readTX('tx10');

{
  const raw = tx5.getRaw();
  const end = bench('parse');

  for (let i = 0; i < 1000; i++)
    TX.fromRaw(raw);

  end(1000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('serialize');

  for (let i = 0; i < 1000; i++) {
    tx._raw = null;
    tx.toRaw();
  }

  end(1000);
}

{
  const [tx] = tx3.getTX();
  const end = bench('hash');

  for (let i = 0; i < 3000; i++) {
    tx.hash();
    tx._hash = null;
  }

  end(3000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('witness hash');

  for (let i = 0; i < 3000; i++) {
    tx.witnessHash();
    tx._whash = null;
  }

  end(3000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('sanity');

  for (let i = 0; i < 1000; i++)
    tx.isSane();

  end(1000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('input hashes');

  for (let i = 0; i < 1000; i++)
    tx.getInputHashes(null, 'hex');

  end(1000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('output hashes');

  for (let i = 0; i < 1000; i++)
    tx.getOutputHashes('hex');

  end(1000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('all hashes');

  for (let i = 0; i < 1000; i++)
    tx.getHashes(null, 'hex');

  end(1000);
}

{
  const [tx, view] = tx3.getTX();
  const end = bench('verify');

  for (let i = 0; i < 3000; i++)
    tx.verify(view, Script.flags.VERIFY_P2SH);

  end(3000 * tx.inputs.length);
}

{
  const [tx, view] = tx3.getTX();
  const {script} = view.getOutputFor(tx.inputs[0]);
  const end = bench('sighash');

  for (let i = 0; i < 100000; i++)
    tx.signatureHashV0(0, script, Script.hashType.ALL);

  end(100000);
}

{
  const [tx, view] = tx3.getTX();
  const end = bench('fee');

  for (let i = 0; i < 1000; i++)
    tx.getFee(view);

  end(1000);
}

{
  const [tx, view] = tx10.getTX();
  const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
  const end = bench('verify multisig');

  for (let i = 0; i < 3000; i++)
    tx.verify(view, flags);

  end(3000 * tx.inputs.length);
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
