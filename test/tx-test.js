/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const {inspect} = require('util');
const {encoding} = require('bufio');
const assert = require('bsert');
const random = require('bcrypto/lib/random');
const util = require('../lib/utils/util');
const consensus = require('../lib/protocol/consensus');
const TX = require('../lib/primitives/tx');
const MTX = require('../lib/primitives/mtx');
const Output = require('../lib/primitives/output');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const Witness = require('../lib/script/witness');
const Opcode = require('../lib/script/opcode');
const Input = require('../lib/primitives/input');
const CoinView = require('../lib/coins/coinview');
const KeyRing = require('../lib/primitives/keyring');
const Address = require('../lib/primitives/address');
const BufferWriter = require('bufio').BufferWriter;
const common = require('./util/common');
const nodejsUtil = require('util');

// test files: https://github.com/bitcoin/bitcoin/tree/master/src/test/data
const validTests = require('./data/core-data/tx-valid.json');
const invalidTests = require('./data/core-data/tx-invalid.json');
const sighashTests = require('./data/core-data/sighash-tests.json');

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
    const hash = util.fromRev(txid);
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
      ? inspect(coin.script)
      : 'coinbase',
    data: data
  };
}

function parseSighashTest(data) {
  const [txHex, scriptHex, index, type, hash] = data;

  const tx = TX.fromRaw(txHex, 'hex');
  const script = Script.fromRaw(scriptHex, 'hex');

  const expected = util.fromRev(hash);

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
  const hash = random.randomBytes(32);

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
    input.prevout.hash = fund.hash();
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
      assert.strictEqual(tx.witnessHash().toString('hex'),
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
        assert.bufferEqual(hash, expected);
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

      ctx.spend.inputs[0].prevout.hash = consensus.ZERO_HASH;
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

  it('should return addresses for standard inputs', () => {
    // txid: 7ef7cde4e4a7829ea6feaf377c924b36d0958e2231a31ff268bd33a59ac9e178
    const [tx, view] = tx2.getTX();

    const inputAddresses = [
      Address.fromBase58('1Wjrrc2DrtB2CXRiPa3c8528fDdNHnQ2K')
    ];

    const inputAddressesView = tx.getInputAddresses(view);
    const inputAddressesNoView = tx.getInputAddresses();

    assert.strictEqual(inputAddresses.length, inputAddressesView.length);
    assert.strictEqual(inputAddresses.length, inputAddressesNoView.length);

    inputAddresses.forEach((inputAddr, i) => {
      assert(inputAddr.equals(inputAddressesView[i]));
      assert(inputAddr.equals(inputAddressesNoView[i]));
    });
  });

  it('should return addresses for standard outputs', () => {
    // txid: 7f2dc9bcc0b1b0d19a4cb62d0f6474990c12a5b996d2fa2c4be54ca1beb5d339
    const [tx] = tx7.getTX();

    // If you fetch only outputs they should be sorted
    // by vouts, not merged.
    const outputAddresses = [
      Address.fromBase58('1fLeMazoEy8FfgeFcppRxNYZs54jyLccw'),
      Address.fromBase58('1EeREnzQujX7CLgmzDSaebS48jxjeyBHQM')
    ];

    const getOutputAddresses = tx.getOutputAddresses();

    assert.strictEqual(outputAddresses.length, getOutputAddresses.length);

    outputAddresses.forEach((outputAddr, i) => {
      assert(outputAddr.equals(getOutputAddresses[i]));
    });
  });

  it('should return addresses for standard inputs and outputs', () => {
    // txid: 7ef7cde4e4a7829ea6feaf377c924b36d0958e2231a31ff268bd33a59ac9e178
    const [tx, view] = tx2.getTX();

    const addresses = [
      // inputs
      Address.fromBase58('1Wjrrc2DrtB2CXRiPa3c8528fDdNHnQ2K'),
      // outputs
      Address.fromBase58('1GcKLBv6iFSCkbhht2m44qnZTYK8xV8nNA'),
      Address.fromBase58('1EpKnnMo1rSkktYw8vPLtXGBRNLraXWd73')
    ];

    const addressesView = tx.getAddresses(view);
    const addressesNoView = tx.getAddresses();

    assert.strictEqual(addresses.length, addressesView.length);
    assert.strictEqual(addresses.length, addressesNoView.length);

    addresses.forEach((addr, i) => {
      assert(addr.equals(addressesView[i]));
      assert(addr.equals(addressesNoView[i]));
    });
  });

  it('should return merged addresses for same input/output address', () => {
    // txid: 7f2dc9bcc0b1b0d19a4cb62d0f6474990c12a5b996d2fa2c4be54ca1beb5d339
    const [tx, view] = tx7.getTX();

    const addresses = [
      // this is input and output
      Address.fromBase58('1EeREnzQujX7CLgmzDSaebS48jxjeyBHQM'),
      Address.fromBase58('1fLeMazoEy8FfgeFcppRxNYZs54jyLccw')
    ];

    const addressesView = tx.getAddresses(view);
    const addressesNoView = tx.getAddresses();

    assert.strictEqual(addresses.length, addressesView.length);
    assert.strictEqual(addresses.length, addressesNoView.length);

    addresses.forEach((addr, i) => {
      assert(addr.equals(addressesView[i]));
      assert(addr.equals(addressesNoView[i]));
    });
  });

  it('should return addresses with witness data', () => {
    const [tx, view] = tx5.getTX();

    const addresses = [
      // inputs
      Address.fromBech32('bc1qnjhhj5g8u46fvhnm34me52ahnx5vhhhuk6m7ng'),
      Address.fromBech32('bc1q3ehzk5qa02sf05zyll0thth5t92kg6twah8hj3'),
      Address.fromBase58('1C4irrkJiHhjKq62uPBw9huZnQsFSRHtjn'),
      Address.fromBech32('bc1q4gzv2jkfnym3s8f69kj55l4yfh7aallphtzutp'),
      Address.fromBech32('bc1q8838eem5cqqlxn34neay8sd7ru4nnm7yfv66xv'),

      // outputs
      Address.fromBech32('bc1q4uxyx3qaanm5elq4w2kxytvkpufa33s08vldx7'),
      Address.fromBech32('bc1q8m66kw3789mvpfpcxxh880zg6jjwpyntspcnmy')
    ];

    const addressesView = tx.getAddresses(view);
    const addressesNoView = tx.getAddresses();

    assert.strictEqual(addresses.length, addressesView.length);
    assert.strictEqual(addresses.length, addressesNoView.length);

    addresses.forEach((addr, i) => {
      assert(addr.equals(addressesView[i]));
      assert(addr.equals(addressesNoView[i]));
    });
  });

  it('should return address hashes for standard inputs and outputs', () => {
    // txid: 7ef7cde4e4a7829ea6feaf377c924b36d0958e2231a31ff268bd33a59ac9e178
    const [tx, view] = tx2.getTX();

    const hashes = [
      // inputs
      Address.fromBase58('1Wjrrc2DrtB2CXRiPa3c8528fDdNHnQ2K').getHash(),
      // outputs
      Address.fromBase58('1GcKLBv6iFSCkbhht2m44qnZTYK8xV8nNA').getHash(),
      Address.fromBase58('1EpKnnMo1rSkktYw8vPLtXGBRNLraXWd73').getHash()
    ];

    const hashesBuf = tx.getHashes(view);

    assert.strictEqual(hashes.length, hashesBuf.length);

    hashes.forEach((hash, i) => {
      assert.bufferEqual(hash, hashesBuf[i]);
    });
  });

  it('should return address hashes for standard inputs', () => {
    // txid: 7ef7cde4e4a7829ea6feaf377c924b36d0958e2231a31ff268bd33a59ac9e178
    const [tx, view] = tx2.getTX();

    const inputHashes = [
      Address.fromBase58('1Wjrrc2DrtB2CXRiPa3c8528fDdNHnQ2K').getHash()
    ];

    const hashesBuf = tx.getInputHashes(view);

    assert.strictEqual(inputHashes.length, hashesBuf.length);

    inputHashes.forEach((hash, i) => {
      assert.bufferEqual(hash, hashesBuf[i]);
    });
  });

  it('should return address hashes for standard outputs', () => {
    // txid: 7ef7cde4e4a7829ea6feaf377c924b36d0958e2231a31ff268bd33a59ac9e178
    const [tx] = tx2.getTX();

    const outputHashes = [
      Address.fromBase58('1GcKLBv6iFSCkbhht2m44qnZTYK8xV8nNA').getHash(),
      Address.fromBase58('1EpKnnMo1rSkktYw8vPLtXGBRNLraXWd73').getHash()
    ];

    const hashesBuf = tx.getOutputHashes();

    assert.strictEqual(outputHashes.length, hashesBuf.length);

    outputHashes.forEach((hash, i) => {
      assert.bufferEqual(hash, hashesBuf[i]);
    });
  });

  it('should return all prevouts', () => {
    const [tx] = tx3.getTX();

    const expectedPrevouts = [
      '2f196cf1e5bd426a04f07b882c893b5b5edebad67da6eb50f066c372ed736d5f',
      'ff8755f073f1170c0d519457ffc4acaa7cb2988148163b5dc457fae0fe42aa19'
    ];

    const prevouts = tx.getPrevout();

    assert(expectedPrevouts.length, prevouts.length);
    expectedPrevouts.forEach((prevout, i) => {
      assert.strictEqual(prevout, prevouts[i].toString('hex'));
    });
  });

  it('should serialize without witness data', () => {
    const [tx] = tx2.getTX();
    const [txWit] = tx5.getTX();

    const bw1 = new BufferWriter();
    const bw2 = new BufferWriter();

    tx.toNormalWriter(bw1);
    txWit.toNormalWriter(bw2);

    const tx1normal = TX.fromRaw(bw1.render());
    const tx2normal = TX.fromRaw(bw2.render());

    assert.strictEqual(tx1normal.hasWitness(), false);
    assert.strictEqual(tx2normal.hasWitness(), false);
  });

  it('should check if tx is free', () => {
    const value = 100000000; // 1 btc
    const height = 100;
    const [input, view] = createInput(value);

    // hack height into coinEntry
    const entry = view.getEntry(input.prevout);
    entry.height = height;

    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: value
      }],
      locktime: 0
    });

    // Priority should be more than FREE_THRESHOLD
    // txsize: 60, value: 1 btc
    // freeAfter: 144/250*txsize = 34.56
    const size = tx.getSize();
    const freeHeight = height + 35;
    const freeAt34 = tx.isFree(view, freeHeight - 1);
    const freeAt34size = tx.isFree(view, freeHeight - 1, tx, size);
    const freeAt35 = tx.isFree(view, freeHeight);
    const freeAt35size = tx.isFree(view, freeHeight, size);

    assert.strictEqual(freeAt34, false);
    assert.strictEqual(freeAt34size, false);
    assert.strictEqual(freeAt35, true);
    assert.strictEqual(freeAt35size, true);
  });

  it('should return correct minFee and roundedFee', () => {
    const value = 100000000; // 1 btc

    const [input] = createInput(value);
    const tx = new TX({
      version: 1,
      inputs: [input],
      outputs: [{
        script: [],
        value: value
      }],
      locktime: 0
    });

    // 1000 satoshis per kb
    const rate = 1000;
    const size = tx.getSize(); // 60 bytes

    // doesn't round to KB
    assert.strictEqual(tx.getMinFee(size, rate), 60);
    assert.strictEqual(tx.getMinFee(size, rate * 10), 600);
    assert.strictEqual(tx.getMinFee(size * 10, rate), 600);

    // rounds to KB
    assert.strictEqual(tx.getRoundFee(size, rate), 1000);
    // still under kb
    assert.strictEqual(tx.getRoundFee(size * 10, rate), 1000);
    assert.strictEqual(tx.getRoundFee(size, rate * 10), 10000);

    assert.strictEqual(tx.getRoundFee(1000, rate), 1000);
    assert.strictEqual(tx.getRoundFee(1001, rate), 2000);
  });

  it('should return JSON for tx', () => {
    const [tx, view] = tx2.getTX();
    const hash = '7ef7cde4e4a7829ea6feaf377c924b36d0958e22'
      + '31a31ff268bd33a59ac9e178';
    const version = 0;
    const locktime = 0;
    const hex = tx2.getRaw().toString('hex');

    // hack for ChainEntry
    const entry = {
      height: 1000,
      hash: Buffer.from(
        'c82d447db6150d2308d9571c19bc3dc6efde97a8227d9e57bc77ec0900000000',
        'hex'),
      time: 1365870306
    };
    const network = 'testnet';
    const index = 0;

    const jsonDefault = tx.getJSON(network);
    const jsonView = tx.getJSON(network, view);
    const jsonEntry = tx.getJSON(network, null, entry);
    const jsonIndex = tx.getJSON(network, null, null, index);
    const jsonAll = tx.getJSON(network, view, entry, index);

    for (const json of [jsonDefault, jsonView, jsonEntry, jsonIndex, jsonAll]) {
      assert.strictEqual(json.hash, hash);
      assert.strictEqual(json.witnessHash, hash);
      assert.strictEqual(json.version, version);
      assert.strictEqual(json.locktime, locktime);
      assert.strictEqual(json.hex, hex);
    }

    const fee = 10000;
    const rate = 44247;

    for (const json of [jsonView, jsonAll]) {
      assert.strictEqual(json.fee, fee);
      assert.strictEqual(json.rate, rate);
    }

    const date = '2013-04-13T16:25:06Z';
    for (const json of [jsonEntry, jsonAll]) {
      assert.strictEqual(json.height, entry.height);
      assert.strictEqual(json.block, util.revHex(entry.hash));
      assert.strictEqual(json.time, entry.time);
      assert.strictEqual(json.date, date);
    }

    for (const json of [jsonIndex, jsonAll]) {
      assert.strictEqual(json.index, index);
    }
  });

  it('should recover coins from JSON', () => {
    const [tx, view] = tx2.getTX();

    const mtx = MTX.fromTX(tx);
    mtx.view = view;

    // get input value as example
    const value1 = mtx.getInputValue();

    const mtx2 = MTX.fromJSON(mtx.toJSON());
    const value2 = mtx2.getInputValue();

    assert.strictEqual(value1, value2);
  });

  it('should inspect TX', () => {
    const tx = new TX();
    const fmt = nodejsUtil.format(tx);
    assert(typeof fmt === 'string');
    assert(fmt.includes('hash'));
    assert(fmt.includes('version'));
    assert(fmt.includes('locktime'));
  });
});
