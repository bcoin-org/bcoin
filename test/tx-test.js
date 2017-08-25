/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const util = require('../lib/utils/util');
const encoding = require('../lib/utils/encoding');
const random = require('../lib/crypto/random');
const consensus = require('../lib/protocol/consensus');
const TX = require('../lib/primitives/tx');
const Output = require('../lib/primitives/output');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const Witness = require('../lib/script/witness');
const Opcode = require('../lib/script/opcode');
const Input = require('../lib/primitives/input');
const CoinView = require('../lib/coins/coinview');
const KeyRing = require('../lib/primitives/keyring');
const common = require('./util/common');

const validTests = require('./data/tx-valid.json');
const invalidTests = require('./data/tx-invalid.json');
const sighashTests = require('./data/sighash-tests.json');

const tx1 = common.readTX('tx1');
const tx2 = common.readTX('tx2');
const tx3 = common.readTX('tx3');
const tx4 = common.readTX('tx4');
const tx5 = common.readTX('tx5');
const tx6 = common.readTX('tx6');
const tx7 = common.readTX('tx7');

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_SAFE_ADDITION = 0xfffffffffffff;

function clearCache(tx, noCache) {
  if (noCache) {
    tx.refresh();
    return;
  }

  const copy = tx.clone();

  assert.bufferEqual(tx.hash(), copy.hash());
  assert.bufferEqual(tx.witnessHash(), copy.witnessHash());
}

function parseTXTest(data) {
  const coins = data[0];
  const hex = data[1];
  const names = data[2] || 'NONE';

  let flags = 0;

  for (const name of names.split(',')) {
    const flag = Script.flags[`VERIFY_${name}`];

    if (flag == null)
      throw new Error(`Unknown flag: ${name}.`);

    flags |= flag;
  }

  const view = new CoinView();

  for (const [txid, index, str, amount] of coins) {
    const hash = util.revHex(txid);
    const script = Script.fromString(str);
    const value = parseInt(amount || '0', 10);

    // Ignore the coinbase tests.
    // They should all fail.
    if ((index >>> 0) === 0xffffffff)
      continue;

    const prevout = new Outpoint(hash, index);
    const output = new Output({script, value});

    view.addOutput(prevout, output);
  }

  const raw = Buffer.from(hex, 'hex');
  const tx = TX.fromRaw(raw);

  const coin = view.getOutputFor(tx.inputs[0]);

  return {
    tx: tx,
    flags: flags,
    view: view,
    comments: coin
      ? util.inspectify(coin.script, false)
      : 'coinbase',
    data: data
  };
}

function parseSighashTest(data) {
  const [txHex, scriptHex, index, type, hash] = data;

  const tx = TX.fromRaw(txHex, 'hex');
  const script = Script.fromRaw(scriptHex, 'hex');

  const expected = util.revHex(hash);

  let hex = type & 3;

  if (type & 0x80)
    hex |= 0x80;

  hex = hex.toString(16);

  if (hex.length % 2 !== 0)
    hex = '0' + hex;

  return {
    tx: tx,
    script: script,
    index: index,
    type: type,
    hash: hash,
    expected: expected,
    hex: hex
  };
}

function createInput(value, view) {
  const hash = random.randomBytes(32).toString('hex');

  const input = {
    prevout: {
      hash: hash,
      index: 0
    }
  };

  const output = new Output();
  output.value = value;

  if (!view)
    view = new CoinView();

  view.addOutput(new Outpoint(hash, 0), output);

  return [input, view];
};

function sigopContext(scriptSig, witness, scriptPubkey) {
  const fund = new TX();

  {
    fund.version = 1;

    const input = new Input();
    fund.inputs.push(input);

    const output = new Output();
    output.value = 1;
    output.script = scriptPubkey;
    fund.outputs.push(output);

    fund.refresh();
  }

  const spend = new TX();

  {
    spend.version = 1;

    const input = new Input();
    input.prevout.hash = fund.hash('hex');
    input.prevout.index = 0;
    input.script = scriptSig;
    input.witness = witness;
    spend.inputs.push(input);

    const output = new Output();
    output.value = 1;
    spend.outputs.push(output);

    spend.refresh();
  }

  const view = new CoinView();

  view.addTX(fund, 0);

  return {
    fund: fund,
    spend: spend,
    view: view
  };
}

describe('TX', function() {
  for (const noCache of [false, true]) {
    const suffix = noCache ? 'without cache' : 'with cache';

    it(`should verify non-minimal output ${suffix}`, () => {
      const [tx, view] = tx1.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify tx.version == 0 ${suffix}`, () => {
      const [tx, view] = tx2.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify sighash_single bug w/ findanddelete ${suffix}`, () => {
      const [tx, view] = tx3.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify high S value with only DERSIG enabled ${suffix}`, () => {
      const [tx, view] = tx4.getTX();
      const coin = view.getOutputFor(tx.inputs[0]);
      const flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
      clearCache(tx, noCache);
      assert(tx.verifyInput(0, coin, flags));
    });

    it(`should parse witness tx properly ${suffix}`, () => {
      const [tx] = tx5.getTX();
      clearCache(tx, noCache);

      assert.strictEqual(tx.inputs.length, 5);
      assert.strictEqual(tx.outputs.length, 1980);
      assert(tx.hasWitness());
      assert.notStrictEqual(tx.txid(), tx.wtxid());
      assert.strictEqual(tx.witnessHash('hex'),
        '088c919cd8408005f255c411f786928385688a9e8fdb2db4c9bc3578ce8c94cf');
      assert.strictEqual(tx.getSize(), 62138);
      assert.strictEqual(tx.getVirtualSize(), 61813);
      assert.strictEqual(tx.getWeight(), 247250);

      const raw1 = tx.toRaw();
      tx.refresh();

      const raw2 = tx.toRaw();
      assert.bufferEqual(raw1, raw2);

      const tx2 = TX.fromRaw(raw2);
      clearCache(tx2, noCache);

      assert.strictEqual(tx.txid(), tx2.txid());
      assert.strictEqual(tx.wtxid(), tx2.wtxid());
      assert.notStrictEqual(tx.txid(), tx2.wtxid());
    });

    it(`should verify the coolest tx ever sent ${suffix}`, () => {
      const [tx, view] = tx6.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view, Script.flags.VERIFY_NONE));
    });

    it(`should verify a historical transaction ${suffix}`, () => {
      const [tx, view] = tx7.getTX();
      clearCache(tx, noCache);
      assert(tx.verify(view));
    });

    for (const tests of [validTests, invalidTests]) {
      let comment = '';

      for (const json of tests) {
        if (json.length === 1) {
          comment += ' ' + json[0];
          continue;
        }

        const data = parseTXTest(json);
        const {tx, view, flags} = data;
        const comments = comment.trim() || data.comments;

        comment = '';

        if (tests === validTests) {
          if (comments.indexOf('Coinbase') === 0) {
            it(`should handle valid tx test ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(tx.isSane());
            });
            continue;
          }
          it(`should handle valid tx test ${suffix}: ${comments}`, () => {
            clearCache(tx, noCache);
            assert.ok(tx.verify(view, flags));
          });
        } else {
          if (comments === 'Duplicate inputs') {
            it(`should handle invalid tx test ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(tx.verify(view, flags));
              assert.ok(!tx.isSane());
            });
            continue;
          }
          if (comments === 'Negative output') {
            it(`should handle invalid tx test ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(tx.verify(view, flags));
              assert.ok(!tx.isSane());
            });
            continue;
          }
          if (comments.indexOf('Coinbase') === 0) {
            it(`should handle invalid tx test ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(!tx.isSane());
            });
            continue;
          }
          it(`should handle invalid tx test ${suffix}: ${comments}`, () => {
            clearCache(tx, noCache);
            assert.ok(!tx.verify(view, flags));
          });
        }
      }
    }

    for (const json of sighashTests) {
      if (json.length === 1)
        continue;

      const test = parseSighashTest(json);
      const {tx, script, index, type} = test;
      const {hash, hex, expected} = test;

      clearCache(tx, noCache);

      it(`should get sighash of ${hash} (${hex}) ${suffix}`, () => {
        const subscript = script.getSubscript(0).removeSeparators();
        const hash = tx.signatureHash(index, subscript, 0, type, 0);
        assert.strictEqual(hash.toString('hex'), expected);
      });
    }
  }

  it('should fail on >51 bit coin values', () => {
    const [input, view] = createInput(consensus.MAX_MONEY + 1);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: consensus.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should handle 51 bit coin values', () => {
    const [input, view] = createInput(consensus.MAX_MONEY);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: consensus.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(tx.verifyInputs(view, 0));
  });

  it('should fail on >51 bit output values', () => {
    const [input, view] = createInput(consensus.MAX_MONEY);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: consensus.MAX_MONEY + 1
      }],
      locktime: 0
    });
    assert.ok(!tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should handle 51 bit output values', () => {
    const [input, view] = createInput(consensus.MAX_MONEY);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: consensus.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(tx.verifyInputs(view, 0));
  });

  it('should fail on >51 bit fees', () => {
    const [input, view] = createInput(consensus.MAX_MONEY + 1);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: 0
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should fail on >51 bit values from multiple', () => {
    const view = new CoinView();
    const tx = new TX({
      version: 1,
      inputs: [
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)[0],
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)[0],
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)[0]
      ],
      outputs: [{
        script: [],
        value: consensus.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should fail on >51 bit output values from multiple', () => {
    const [input, view] = createInput(consensus.MAX_MONEY);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [
        {
          script: [],
          value: Math.floor(consensus.MAX_MONEY / 2)
        },
        {
          script: [],
          value: Math.floor(consensus.MAX_MONEY / 2)
        },
        {
          script: [],
          value: Math.floor(consensus.MAX_MONEY / 2)
        }
      ],
      locktime: 0
    });
    assert.ok(!tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should fail on >51 bit fees from multiple', () => {
    const view = new CoinView();
    const tx = new TX({
      version: 1,
      inputs: [
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)[0],
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)[0],
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)[0]
      ],
      outputs: [{
        script: [],
        value: 0
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should fail to parse >53 bit values', () => {
    const [input] = createInput(Math.floor(consensus.MAX_MONEY / 2));

    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: 0xdeadbeef
      }],
      locktime: 0
    });

    let raw = tx.toRaw();
    assert.strictEqual(encoding.readU64(raw, 47), 0xdeadbeef);
    raw[54] = 0x7f;

    assert.throws(() => TX.fromRaw(raw));

    tx.outputs[0].value = 0;
    tx.refresh();

    raw = tx.toRaw();
    assert.strictEqual(encoding.readU64(raw, 47), 0x00);
    raw[54] = 0x80;
    assert.throws(() => TX.fromRaw(raw));
  });

  it('should fail on 53 bit coin values', () => {
    const [input, view] = createInput(MAX_SAFE_INTEGER);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: consensus.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should fail on 53 bit output values', () => {
    const [input, view] = createInput(consensus.MAX_MONEY);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: MAX_SAFE_INTEGER
      }],
      locktime: 0
    });
    assert.ok(!tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  it('should fail on 53 bit fees', () => {
    const [input, view] = createInput(MAX_SAFE_INTEGER);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: 0
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  for (const value of [MAX_SAFE_ADDITION, MAX_SAFE_INTEGER]) {
    it('should fail on >53 bit values from multiple', () => {
      const view = new CoinView();
      const tx = new TX({
        version: 1,
        inputs: [
          createInput(value, view)[0],
          createInput(value, view)[0],
          createInput(value, view)[0]
        ],
        outputs: [{
          script: [],
          value: consensus.MAX_MONEY
        }],
        locktime: 0
      });
      assert.ok(tx.isSane());
      assert.ok(!tx.verifyInputs(view, 0));
    });

    it('should fail on >53 bit output values from multiple', () => {
      const [input, view] = createInput(consensus.MAX_MONEY);
      const tx = new TX({
        version: 1,
        inputs: [input],
        outputs: [
          {
            script: [],
            value: value
          },
          {
            script: [],
            value: value
          },
          {
            script: [],
            value: value
          }
        ],
        locktime: 0
      });
      assert.ok(!tx.isSane());
      assert.ok(!tx.verifyInputs(view, 0));
    });

    it('should fail on >53 bit fees from multiple', () => {
      const view = new CoinView();
      const tx = new TX({
        version: 1,
        inputs: [
          createInput(value, view)[0],
          createInput(value, view)[0],
          createInput(value, view)[0]
        ],
        outputs: [{
          script: [],
          value: 0
        }],
        locktime: 0
      });
      assert.ok(tx.isSane());
      assert.ok(!tx.verifyInputs(view, 0));
    });
  }

  it('should count sigops for multisig', () => {
    const flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    const key = KeyRing.generate();
    const pub = key.publicKey;

    const output = Script.fromMultisig(1, 2, [pub, pub]);

    const input = new Script([
      Opcode.fromInt(0),
      Opcode.fromInt(0)
    ]);

    const witness = new Witness();

    const ctx = sigopContext(input, witness, output);

    assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags), 0);
    assert.strictEqual(ctx.fund.getSigopsCost(ctx.view, flags),
      consensus.MAX_MULTISIG_PUBKEYS * consensus.WITNESS_SCALE_FACTOR);
  });

  it('should count sigops for p2sh multisig', () => {
    const flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    const key = KeyRing.generate();
    const pub = key.publicKey;

    const redeem = Script.fromMultisig(1, 2, [pub, pub]);
    const output = Script.fromScripthash(redeem.hash160());

    const input = new Script([
      Opcode.fromInt(0),
      Opcode.fromInt(0),
      Opcode.fromData(redeem.toRaw())
    ]);

    const witness = new Witness();

    const ctx = sigopContext(input, witness, output);

    assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags),
      2 * consensus.WITNESS_SCALE_FACTOR);
  });

  it('should count sigops for p2wpkh', () => {
    const flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    const key = KeyRing.generate();

    const witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0])
    ]);

    const input = new Script();

    {
      const output = Script.fromProgram(0, key.getKeyHash());
      const ctx = sigopContext(input, witness, output);

      assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags), 1);
      assert.strictEqual(
        ctx.spend.getSigopsCost(ctx.view, flags & ~Script.flags.VERIFY_WITNESS),
        0);
    }

    {
      const output = Script.fromProgram(1, key.getKeyHash());
      const ctx = sigopContext(input, witness, output);

      assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags), 0);
    }

    {
      const output = Script.fromProgram(0, key.getKeyHash());
      const ctx = sigopContext(input, witness, output);

      ctx.spend.inputs[0].prevout.hash = encoding.NULL_HASH;
      ctx.spend.inputs[0].prevout.index = 0xffffffff;
      ctx.spend.refresh();

      assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags), 0);
    }
  });

  it('should count sigops for nested p2wpkh', () => {
    const flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    const key = KeyRing.generate();

    const redeem = Script.fromProgram(0, key.getKeyHash());
    const output = Script.fromScripthash(redeem.hash160());

    const input = new Script([
      Opcode.fromData(redeem.toRaw())
    ]);

    const witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0])
    ]);

    const ctx = sigopContext(input, witness, output);

    assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags), 1);
  });

  it('should count sigops for p2wsh', () => {
    const flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    const key = KeyRing.generate();
    const pub = key.publicKey;

    const redeem = Script.fromMultisig(1, 2, [pub, pub]);
    const output = Script.fromProgram(0, redeem.sha256());

    const input = new Script();

    const witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0]),
      redeem.toRaw()
    ]);

    const ctx = sigopContext(input, witness, output);

    assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags), 2);
    assert.strictEqual(
      ctx.spend.getSigopsCost(ctx.view, flags & ~Script.flags.VERIFY_WITNESS),
      0);
  });

  it('should count sigops for nested p2wsh', () => {
    const flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    const key = KeyRing.generate();
    const pub = key.publicKey;

    const wscript = Script.fromMultisig(1, 2, [pub, pub]);
    const redeem = Script.fromProgram(0, wscript.sha256());
    const output = Script.fromScripthash(redeem.hash160());

    const input = new Script([
      Opcode.fromData(redeem.toRaw())
    ]);

    const witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0]),
      wscript.toRaw()
    ]);

    const ctx = sigopContext(input, witness, output);

    assert.strictEqual(ctx.spend.getSigopsCost(ctx.view, flags), 2);
  });
});
