'use strict';

const random = require('bcrypto/lib/random');
const Address = require('../lib/primitives/address');
const TX = require('../lib/primitives/tx');
const Script = require('../lib/script/script');
const MTX = require('../lib/primitives/mtx');
const consensus = require('../lib/protocol/consensus');
const common = require('../test/util/common');
const bench = require('./bench');

const tx3 = common.readTX('tx3');
const tx5 = common.readTX('tx5');
const tx10 = common.readTX('tx10');

{
  const raw = tx5.getRaw();
  const end = bench('parse');

  for (let i = 0; i < 10000; i++)
    TX.fromRaw(raw);

  end(10000);
}

{
  const [tx, view] = tx5.getTX();
  const end = bench('sigops');

  for (let i = 0; i < 100000; i++)
    tx.getSigopsCost(view);

  end(100000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('serialize');

  for (let i = 0; i < 10000; i++) {
    tx._raw = null;
    tx.toRaw();
  }

  end(10000);
}

{
  const [tx] = tx3.getTX();
  const end = bench('hash');

  for (let i = 0; i < 30000; i++) {
    tx.hash();
    tx._hash = null;
  }

  end(30000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('witness hash');

  for (let i = 0; i < 30000; i++) {
    tx.witnessHash();
    tx._whash = null;
  }

  end(30000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('sanity');

  for (let i = 0; i < 10000; i++)
    tx.isSane();

  end(10000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('input hashes');

  for (let i = 0; i < 10000; i++)
    tx.getInputHashes();

  end(10000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('output hashes');

  for (let i = 0; i < 10000; i++)
    tx.getOutputHashes();

  end(10000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('all hashes');

  for (let i = 0; i < 10000; i++)
    tx.getHashes();

  end(10000);
}

{
  const [tx, view] = tx3.getTX();
  const end = bench('verify');

  for (let i = 0; i < 30000; i++)
    tx.verify(view, Script.flags.VERIFY_P2SH);

  end(30000 * tx.inputs.length);
}

{
  const [tx, view] = tx3.getTX();
  const {script} = view.getOutputFor(tx.inputs[0]);
  const end = bench('sighash');

  for (let i = 0; i < 1000000; i++)
    tx.signatureHashV0(0, script, Script.hashType.ALL);

  end(1000000);
}

{
  const [tx, view] = tx3.getTX();
  const end = bench('fee');

  for (let i = 0; i < 10000; i++)
    tx.getFee(view);

  end(10000);
}

{
  const [tx, view] = tx10.getTX();
  const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
  const end = bench('verify multisig');

  for (let i = 0; i < 30000; i++)
    tx.verify(view, flags);

  end(30000 * tx.inputs.length);
}

const mtx = new MTX();

for (let i = 0; i < 100; i++) {
  mtx.addInput({
    prevout: {
      hash: consensus.ZERO_HASH,
      index: 0
    },
    script: new Script()
      .pushData(Buffer.allocUnsafe(9))
      .pushData(random.randomBytes(33))
      .compile()
  });
  mtx.addOutput({
    address: Address.fromHash(random.randomBytes(20)),
    value: 0
  });
}

const tx2 = mtx.toTX();

{
  const end = bench('input hashes');

  for (let i = 0; i < 10000; i++)
    tx2.getInputHashes();

  end(10000);
}

{
  const end = bench('output hashes');

  for (let i = 0; i < 10000; i++)
    tx2.getOutputHashes();

  end(10000);
}

{
  const end = bench('all hashes');

  for (let i = 0; i < 10000; i++)
    tx2.getHashes();

  end(10000);
}
