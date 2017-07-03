'use strict';

const assert = require('assert');
const util = require('../lib/utils/util');
const encoding = require('../lib/utils/encoding');
const random = require('../lib/crypto/random');
const consensus = require('../lib/protocol/consensus');
const TX = require('../lib/primitives/tx');
const Coin = require('../lib/primitives/coin');
const Output = require('../lib/primitives/output');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const Witness = require('../lib/script/witness');
const Input = require('../lib/primitives/input');
const CoinView = require('../lib/coins/coinview');
const KeyRing = require('../lib/primitives/keyring');
const parseTX = require('./util/common').parseTX;
const opcodes = Script.opcodes;

const valid = require('./data/tx_valid.json');
const invalid = require('./data/tx_invalid.json');
const sighash = require('./data/sighash.json');
const tx1 = parseTX('data/tx1.hex');
const tx2 = parseTX('data/tx2.hex');
const tx3 = parseTX('data/tx3.hex');
const tx4 = parseTX('data/tx4.hex');
const wtx = parseTX('data/wtx.hex');
const coolest = parseTX('data/coolest-tx-ever-sent.hex');

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const MAX_SAFE_ADDITION = 0xfffffffffffff;

function clearCache(tx, noCache) {
  if (!noCache) {
    assert.equal(tx.hash('hex'), tx.clone().hash('hex'));
    return;
  }
  tx.refresh();
}

function parseTest(data) {
  let [coins, tx, names] = data;
  let view = new CoinView();
  let flags = 0;
  let coin;

  if (!names)
    names = '';

  tx = TX.fromRaw(tx, 'hex');
  names = names.trim().split(/,\s*/);

  for (let name of names) {
    name = `VERIFY_${name}`;
    assert(Script.flags[name] != null, 'Unknown flag.');
    flags |= Script.flags[name];
  }

  for (let [hash, index, script, value] of coins) {
    hash = util.revHex(hash);
    script = Script.fromString(script);
    value = parseInt(value || '0', 10);

    if (index === -1)
      continue;

    coin = new Coin({
      version: 1,
      height: -1,
      coinbase: false,
      hash: hash,
      index: index,
      script: script,
      value: value
    });

    view.addCoin(coin);
  }

  coin = view.getOutput(tx.inputs[0]);

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

function sigopContext(scriptSig, witness, scriptPubkey) {
  let view = new CoinView();
  let input, output, fund, spend;

  input = new Input();
  output = new Output();
  output.value = 1;
  output.script = scriptPubkey;

  fund = new TX();
  fund.version = 1;
  fund.inputs.push(input);
  fund.outputs.push(output);
  fund.refresh();

  input = new Input();
  input.prevout.hash = fund.hash('hex');
  input.prevout.index = 0;
  input.script = scriptSig;
  input.witness = witness;

  output = new Output();
  output.value = 1;

  spend = new TX();
  spend.version = 1;
  spend.inputs.push(input);
  spend.outputs.push(output);
  spend.refresh();

  view.addTX(fund, 0);

  return {
    fund: fund,
    spend: spend,
    view: view
  };
}

describe('TX', function() {
  let raw = '010000000125393c67cd4f581456dd0805fa8e9db3abdf90dbe1d4b53e28' +
            '6490f35d22b6f2010000006b483045022100f4fa5ced20d2dbd2f905809d' +
            '79ebe34e03496ef2a48a04d0a9a1db436a211dd202203243d086398feb4a' +
            'c21b3b79884079036cd5f3707ba153b383eabefa656512dd0121022ebabe' +
            'fede28804b331608d8ef11e1d65b5a920720db8a644f046d156b3a73c0ff' +
            'ffffff0254150000000000001976a9140740345f114e1a1f37ac1cc442b4' +
            '32b91628237e88ace7d27b00000000001976a91495ad422bb5911c2c9fe6' +
            'ce4f82a13c85f03d9b2e88ac00000000';
  let inp = '01000000052fa236559f51f343f0905ea627a955f421a198541d928798b8' +
            '186980273942ec010000006b483045022100ae27626778eba264d56883f5' +
            'edc1a49897bf209e98f21c870a55d13bec916e1802204b66f4e3235143d1' +
            '1aef327d9454754cd1f28807c3bf9996c107900df9d19ea60121022ebabe' +
            'fede28804b331608d8ef11e1d65b5a920720db8a644f046d156b3a73c0ff' +
            'ffffffe2136f72e4a25e300137b98b402cda91db5c6db6373ba81c722ae1' +
            'a85315b591000000006b483045022100f84293ea9bfb6d150f3a72d8b5ce' +
            'b294a77b31442bf9d4ab2058f046a9b65a9f022075935dc0a6a628df26eb' +
            'b7215634fd33b65f4da105665595028837680b87ea360121039708df1967' +
            '09c5041dc9a26457a0cfa303076329f389687bdc9709d5862fd664ffffff' +
            'fff6e67655a42a2f955ec8610940c983042516c32298e57684b3c29fcade' +
            '7e637a000000006a47304402203bbfb53c3011d742f3f942db18a44d8c3d' +
            'd111990ee7cc42959383dd7a3e8e8d02207f0f5ed3e165d9db81ac69d36c' +
            '60a1a4a482f22cb0048dafefa5e704e84dd18e0121039708df196709c504' +
            '1dc9a26457a0cfa303076329f389687bdc9709d5862fd664ffffffff9a02' +
            'e72123a149570c11696d3c798593785e95b8a3c3fc49ae1d07d809d94d5a' +
            '000000006b483045022100ad0e6f5f73221aa4eda9ad82c7074882298bcf' +
            '668f34ae81126df0213b2961850220020ba23622d75fb8f95199063b804f' +
            '62ba103545af4e16b5be0b6dc0cb51aac60121039708df196709c5041dc9' +
            'a26457a0cfa303076329f389687bdc9709d5862fd664ffffffffd7db5a38' +
            '72589ca8aa3cd5ebb0f22dbb3956f8d691e15dc010fe1093c045c3de0000' +
            '00006b48304502210082b91a67da1f02dcb0d00e63b67f10af8ba9639b16' +
            '5f9ff974862a9d4900e27c022069e4a58f591eb3fc7d7d0b176d64d59e90' +
            'aef0c601b3c84382abad92f6973e630121039708df196709c5041dc9a264' +
            '57a0cfa303076329f389687bdc9709d5862fd664ffffffff025415000000' +
            '0000001976a9140740345f114e1a1f37ac1cc442b432b91628237e88ac4b' +
            '0f7c00000000001976a91495ad422bb5911c2c9fe6ce4f82a13c85f03d9b' +
            '2e88ac00000000';

  [false, true].forEach((noCache) => {
    let suffix = noCache ? 'without cache' : 'with cache';

    it(`should decode/encode with parser/framer ${suffix}`, () => {
      let tx = TX.fromRaw(raw, 'hex');
      clearCache(tx, noCache);
      assert.equal(tx.toRaw().toString('hex'), raw);
    });

    it(`should be verifiable ${suffix}`, () => {
      let tx = TX.fromRaw(raw, 'hex');
      let p = TX.fromRaw(inp, 'hex');
      let view = new CoinView();
      view.addTX(p, -1);

      clearCache(tx, noCache);
      clearCache(p, noCache);

      assert(tx.verify(view));
    });

    it(`should verify non-minimal output ${suffix}`, () => {
      clearCache(tx1.tx, noCache);
      assert(tx1.tx.verify(tx1.view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify tx.version == 0 ${suffix}`, () => {
      clearCache(tx2.tx, noCache);
      assert(tx2.tx.verify(tx2.view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify sighash_single bug w/ findanddelete ${suffix}`, () => {
      clearCache(tx3.tx, noCache);
      assert(tx3.tx.verify(tx3.view, Script.flags.VERIFY_P2SH));
    });

    it(`should verify high S value with only DERSIG enabled ${suffix}`, () => {
      let coin = tx4.view.getOutput(tx4.tx.inputs[0]);
      let flags = Script.flags.VERIFY_P2SH | Script.flags.VERIFY_DERSIG;
      clearCache(tx4.tx, noCache);
      assert(tx4.tx.verifyInput(0, coin, flags));
    });

    it(`should verify the coolest tx ever sent ${suffix}`, () => {
      clearCache(coolest.tx, noCache);
      assert(coolest.tx.verify(coolest.view, Script.flags.VERIFY_NONE));
    });

    it(`should parse witness tx properly ${suffix}`, () => {
      let raw1, raw2, wtx2;

      clearCache(wtx.tx, noCache);

      assert.equal(wtx.tx.inputs.length, 5);
      assert.equal(wtx.tx.outputs.length, 1980);
      assert(wtx.tx.hasWitness());
      assert.notEqual(wtx.tx.hash('hex'), wtx.tx.witnessHash('hex'));
      assert.equal(wtx.tx.witnessHash('hex'),
        '088c919cd8408005f255c411f786928385688a9e8fdb2db4c9bc3578ce8c94cf');
      assert.equal(wtx.tx.getSize(), 62138);
      assert.equal(wtx.tx.getVirtualSize(), 61813);
      assert.equal(wtx.tx.getWeight(), 247250);

      raw1 = wtx.tx.toRaw();
      clearCache(wtx.tx, true);

      raw2 = wtx.tx.toRaw();
      assert.deepEqual(raw1, raw2);

      wtx2 = TX.fromRaw(raw2);
      clearCache(wtx2, noCache);

      assert.equal(wtx.tx.hash('hex'), wtx2.hash('hex'));
      assert.equal(wtx.tx.witnessHash('hex'), wtx2.witnessHash('hex'));
    });

    [[valid, true], [invalid, false]].forEach((test) => {
      let [arr, valid] = test;
      let comment = '';

      arr.forEach((json, i) => {
        let data, tx, view, flags, comments;

        if (json.length === 1) {
          comment += ' ' + json[0];
          return;
        }

        data = parseTest(json);

        if (!data) {
          comment = '';
          return;
        }

        tx = data.tx;
        view = data.view;
        flags = data.flags;
        comments = comment.trim();

        if (!comments)
          comments = data.comments;

        comment = '';

        if (valid) {
          if (comments.indexOf('Coinbase') === 0) {
            it(`should handle valid coinbase ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(tx.isSane());
            });
            return;
          }
          it(`should handle valid tx test ${suffix}: ${comments}`, () => {
            clearCache(tx, noCache);
            assert.ok(tx.verify(view, flags));
          });
        } else {
          if (comments === 'Duplicate inputs') {
            it(`should handle duplicate input test ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(tx.verify(view, flags));
              assert.ok(!tx.isSane());
            });
            return;
          }
          if (comments === 'Negative output') {
            it(`should handle invalid tx (negative) ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(tx.verify(view, flags));
              assert.ok(!tx.isSane());
            });
            return;
          }
          if (comments.indexOf('Coinbase') === 0) {
            it(`should handle invalid coinbase ${suffix}: ${comments}`, () => {
              clearCache(tx, noCache);
              assert.ok(!tx.isSane());
            });
            return;
          }
          it(`should handle invalid tx test ${suffix}: ${comments}`, () => {
            clearCache(tx, noCache);
            assert.ok(!tx.verify(view, flags));
          });
        }
      });
    });

    sighash.forEach((data) => {
      let [tx, script, index, type, hash] = data;
      let expected, hex;

      if (data.length === 1)
        return;

      tx = TX.fromRaw(tx, 'hex');
      script = Script.fromRaw(script, 'hex');
      expected = util.revHex(hash);
      hex = type & 3;

      if (type & 0x80)
        hex |= 0x80;

      hex = hex.toString(16);

      if (hex.length % 2 !== 0)
        hex = '0' + hex;

      clearCache(tx, noCache);

      it(`should get sighash of ${hash} (${hex}) ${suffix}`, () => {
        let subscript = script.getSubscript(0).removeSeparators();
        let hash = tx.signatureHash(index, subscript, 0, type, 0);
        assert.equal(hash.toString('hex'), expected);
      });
    });
  });

  function createInput(value, view) {
    let hash = random.randomBytes(32).toString('hex');
    let output = new Output();
    output.value = value;
    view.addOutput(new Outpoint(hash, 0), output);
    return {
      prevout: {
        hash: hash,
        index: 0
      }
    };
  }

  it('should fail on >51 bit coin values', () => {
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(consensus.MAX_MONEY + 1, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(consensus.MAX_MONEY, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(consensus.MAX_MONEY, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(consensus.MAX_MONEY, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(consensus.MAX_MONEY + 1, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [
        createInput(Math.floor(consensus.MAX_MONEY / 2), view),
        createInput(Math.floor(consensus.MAX_MONEY / 2), view),
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(consensus.MAX_MONEY, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [
        createInput(Math.floor(consensus.MAX_MONEY / 2), view),
        createInput(Math.floor(consensus.MAX_MONEY / 2), view),
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)
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
    let view = new CoinView();
    let tx, raw;

    tx = new TX({
      version: 1,
      flag: 1,
      inputs: [
        createInput(Math.floor(consensus.MAX_MONEY / 2), view)
      ],
      outputs: [{
        script: [],
        value: 0xdeadbeef
      }],
      locktime: 0
    });

    raw = tx.toRaw();
    assert(encoding.readU64(raw, 47) === 0xdeadbeef);
    raw[54] = 0x7f;

    assert.throws(() => {
      TX.fromRaw(raw);
    });

    tx.outputs[0].value = 0;
    tx.refresh();

    raw = tx.toRaw();
    assert(encoding.readU64(raw, 47) === 0x00);
    raw[54] = 0x80;
    assert.throws(() => {
      TX.fromRaw(raw);
    });
  });

  it('should fail on 53 bit coin values', () => {
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(MAX_SAFE_INTEGER, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(consensus.MAX_MONEY, view)],
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
    let view = new CoinView();
    let tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(MAX_SAFE_INTEGER, view)],
      outputs: [{
        script: [],
        value: 0
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.verifyInputs(view, 0));
  });

  [MAX_SAFE_ADDITION, MAX_SAFE_INTEGER].forEach((MAX) => {
    it('should fail on >53 bit values from multiple', () => {
      let view = new CoinView();
      let tx = new TX({
        version: 1,
        flag: 1,
        inputs: [
          createInput(MAX, view),
          createInput(MAX, view),
          createInput(MAX, view)
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
      let view = new CoinView();
      let tx = new TX({
        version: 1,
        flag: 1,
        inputs: [createInput(consensus.MAX_MONEY, view)],
        outputs: [
          {
            script: [],
            value: MAX
          },
          {
            script: [],
            value: MAX
          },
          {
            script: [],
            value: MAX
          }
        ],
        locktime: 0
      });
      assert.ok(!tx.isSane());
      assert.ok(!tx.verifyInputs(view, 0));
    });

    it('should fail on >53 bit fees from multiple', () => {
      let view = new CoinView();
      let tx = new TX({
        version: 1,
        flag: 1,
        inputs: [
          createInput(MAX, view),
          createInput(MAX, view),
          createInput(MAX, view)
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
  });

  it('should count sigops for multisig', () => {
    let flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    let key = KeyRing.generate();
    let pub = key.publicKey;
    let ctx, output, input, witness;

    output = Script.fromMultisig(1, 2, [pub, pub]);

    input = new Script([
      opcodes.OP_0,
      opcodes.OP_0
    ]);

    witness = new Witness();

    ctx = sigopContext(input, witness, output);

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags), 0);
    assert.equal(ctx.fund.getSigopsCost(ctx.view, flags),
      consensus.MAX_MULTISIG_PUBKEYS * consensus.WITNESS_SCALE_FACTOR);
  });

  it('should count sigops for p2sh multisig', () => {
    let flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    let key = KeyRing.generate();
    let pub = key.publicKey;
    let ctx, redeem, output, input, witness;

    redeem = Script.fromMultisig(1, 2, [pub, pub]);
    output = Script.fromScripthash(redeem.hash160());

    input = new Script([
      opcodes.OP_0,
      opcodes.OP_0,
      redeem.toRaw()
    ]);

    witness = new Witness();

    ctx = sigopContext(input, witness, output);

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags),
      2 * consensus.WITNESS_SCALE_FACTOR);
  });

  it('should count sigops for p2wpkh', () => {
    let flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    let key = KeyRing.generate();
    let ctx, output, input, witness;

    output = Script.fromProgram(0, key.getKeyHash());

    input = new Script();

    witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0])
    ]);

    ctx = sigopContext(input, witness, output);

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags), 1);
    assert.equal(
      ctx.spend.getSigopsCost(ctx.view, flags & ~Script.flags.VERIFY_WITNESS),
      0);

    output = Script.fromProgram(1, key.getKeyHash());
    ctx = sigopContext(input, witness, output);

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags), 0);

    output = Script.fromProgram(0, key.getKeyHash());
    ctx = sigopContext(input, witness, output);

    ctx.spend.inputs[0].prevout.hash = encoding.NULL_HASH;
    ctx.spend.inputs[0].prevout.index = 0xffffffff;
    ctx.spend.refresh();

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags), 0);
  });

  it('should count sigops for nested p2wpkh', () => {
    let flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    let key = KeyRing.generate();
    let ctx, redeem, output, input, witness;

    redeem = Script.fromProgram(0, key.getKeyHash());
    output = Script.fromScripthash(redeem.hash160());

    input = new Script([
      redeem.toRaw()
    ]);

    witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0])
    ]);

    ctx = sigopContext(input, witness, output);

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags), 1);
  });

  it('should count sigops for p2wsh', () => {
    let flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    let key = KeyRing.generate();
    let pub = key.publicKey;
    let ctx, redeem, output, input, witness;

    redeem = Script.fromMultisig(1, 2, [pub, pub]);
    output = Script.fromProgram(0, redeem.sha256());

    input = new Script();

    witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0]),
      redeem.toRaw()
    ]);

    ctx = sigopContext(input, witness, output);

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags), 2);
    assert.equal(
      ctx.spend.getSigopsCost(ctx.view, flags & ~Script.flags.VERIFY_WITNESS),
      0);
  });

  it('should count sigops for nested p2wsh', () => {
    let flags = Script.flags.VERIFY_WITNESS | Script.flags.VERIFY_P2SH;
    let key = KeyRing.generate();
    let pub = key.publicKey;
    let ctx, wscript, redeem, output, input, witness;

    wscript = Script.fromMultisig(1, 2, [pub, pub]);
    redeem = Script.fromProgram(0, wscript.sha256());
    output = Script.fromScripthash(redeem.hash160());

    input = new Script([
      redeem.toRaw()
    ]);

    witness = new Witness([
      Buffer.from([0]),
      Buffer.from([0]),
      wscript.toRaw()
    ]);

    ctx = sigopContext(input, witness, output);

    assert.equal(ctx.spend.getSigopsCost(ctx.view, flags), 2);
  });
});
