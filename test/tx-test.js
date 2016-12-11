'use strict';

var fs = require('fs');
var assert = require('assert');
var util = require('../lib/utils/util');
var encoding = require('../lib/utils/encoding');
var crypto = require('../lib/crypto/crypto');
var constants = require('../lib/protocol/constants');
var Network = require('../lib/protocol/network');
var TX = require('../lib/primitives/tx');
var Block = require('../lib/primitives/block');
var Coin = require('../lib/primitives/coin');
var Output = require('../lib/primitives/output');
var Script = require('../lib/script/script');
var CoinView = require('../lib/coins/coinview');

var valid = require('./data/tx_valid.json');
var invalid = require('./data/tx_invalid.json');
var sighash = require('./data/sighash.json');
var tx1 = parseTX('data/tx1.hex');
var tx2 = parseTX('data/tx2.hex');
var tx3 = parseTX('data/tx3.hex');
var tx4 = parseTX('data/tx4.hex');
var wtx = parseTX('data/wtx.hex');
var coolest = parseTX('data/coolest-tx-ever-sent.hex');

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

function clearCache(tx, noCache) {
  if (!noCache) {
    assert.equal(tx.hash('hex'), tx.clone().hash('hex'));
    return;
  }

  tx._raw = null;
  tx._size = -1;
  tx._witnessSize = -1;
  tx._hash = null;
  tx._hhash = null;
  tx._whash = null;
  tx._inputValue = -1;
  tx._outputValue = -1;
  tx._hashPrevouts = null;
  tx._hashSequence = null;
  tx._hashOutputs = null;
}

function parseTest(data) {
  var coins = data[0];
  var tx = TX.fromRaw(data[1], 'hex');
  var flags = data[2] ? data[2].trim().split(/,\s*/) : [];
  var view = new CoinView();
  var flag = 0;
  var i, name, coin;

  for (i = 0; i < flags.length; i++) {
    name = 'VERIFY_' + flags[i];
    assert(constants.flags[name] != null, 'Unknown flag.');
    flag |= constants.flags[name];
  }

  flags = flag;

  coins.forEach(function(data) {
    var hash = util.revHex(data[0]);
    var index = data[1];
    var script = Script.fromString(data[2]);
    var amount = data[3] != null ? data[3] : '0';
    var value = parseInt(amount, 10);
    var coin;

    if (index === -1)
      return;

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
  });

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

describe('TX', function() {
  var raw = '010000000125393c67cd4f581456dd0805fa8e9db3abdf90dbe1d4b53e28' +
            '6490f35d22b6f2010000006b483045022100f4fa5ced20d2dbd2f905809d' +
            '79ebe34e03496ef2a48a04d0a9a1db436a211dd202203243d086398feb4a' +
            'c21b3b79884079036cd5f3707ba153b383eabefa656512dd0121022ebabe' +
            'fede28804b331608d8ef11e1d65b5a920720db8a644f046d156b3a73c0ff' +
            'ffffff0254150000000000001976a9140740345f114e1a1f37ac1cc442b4' +
            '32b91628237e88ace7d27b00000000001976a91495ad422bb5911c2c9fe6' +
            'ce4f82a13c85f03d9b2e88ac00000000';
  var inp = '01000000052fa236559f51f343f0905ea627a955f421a198541d928798b8' +
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

  [false, true].forEach(function(noCache) {
    var suffix = noCache ? ' without cache' : ' with cache';

    it('should decode/encode with parser/framer' + suffix, function() {
      var tx = TX.fromRaw(raw, 'hex');
      clearCache(tx, noCache);
      assert.equal(tx.toRaw().toString('hex'), raw);
    });

    it('should be verifiable' + suffix, function() {
      var tx = TX.fromRaw(raw, 'hex');
      var p = TX.fromRaw(inp, 'hex');
      var view = new CoinView();
      view.addTX(p, -1);

      clearCache(tx, noCache);
      clearCache(p, noCache);

      assert(tx.verify(view));
    });

    it('should verify non-minimal output' + suffix, function() {
      clearCache(tx1.tx, noCache);
      assert(tx1.tx.verify(tx1.view, constants.flags.VERIFY_P2SH));
    });

    it('should verify tx.version == 0' + suffix, function() {
      clearCache(tx2.tx, noCache);
      assert(tx2.tx.verify(tx2.view, constants.flags.VERIFY_P2SH));
    });

    it('should verify sighash_single bug w/ findanddelete' + suffix, function() {
      clearCache(tx3.tx, noCache);
      assert(tx3.tx.verify(tx3.view, constants.flags.VERIFY_P2SH));
    });

    it('should verify high S value with only DERSIG enabled' + suffix, function() {
      var coin = tx4.view.getOutput(tx4.tx.inputs[0]);
      var flags = constants.flags.VERIFY_P2SH | constants.flags.VERIFY_DERSIG;
      clearCache(tx4.tx, noCache);
      assert(tx4.tx.verifyInput(0, coin, flags));
    });

    it('should verify the coolest tx ever sent' + suffix, function() {
      clearCache(coolest.tx, noCache);
      assert(coolest.tx.verify(coolest.view, constants.flags.VERIFY_NONE));
    });

    it('should parse witness tx properly' + suffix, function() {
      var raw1, raw2, wtx2;

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

    [[valid, true], [invalid, false]].forEach(function(test) {
      var arr = test[0];
      var valid = test[1];
      var comment = '';

      arr.forEach(function(json, i) {
        var data, tx, view, flags, comments;

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
            it('should handle valid coinbase' + suffix + ': ' + comments, function() {
              clearCache(tx, noCache);
              assert.ok(tx.isSane());
            });
            return;
          }
          it('should handle valid tx test' + suffix + ': ' + comments, function() {
            clearCache(tx, noCache);
            assert.ok(tx.verify(view, flags));
          });
        } else {
          if (comments === 'Duplicate inputs') {
            it('should handle duplicate input test' + suffix + ': ' + comments, function() {
              clearCache(tx, noCache);
              assert.ok(tx.verify(view, flags));
              assert.ok(!tx.isSane());
            });
            return;
          }
          if (comments === 'Negative output') {
            it('should handle invalid tx (negative)' + suffix + ': ' + comments, function() {
              clearCache(tx, noCache);
              assert.ok(tx.verify(view, flags));
              assert.ok(!tx.isSane());
            });
            return;
          }
          if (comments.indexOf('Coinbase') === 0) {
            it('should handle invalid coinbase' + suffix + ': ' + comments, function() {
              clearCache(tx, noCache);
              assert.ok(!tx.isSane());
            });
            return;
          }
          it('should handle invalid tx test' + suffix + ': ' + comments, function() {
            clearCache(tx, noCache);
            assert.ok(!tx.verify(view, flags));
          });
        }
      });
    });

    sighash.forEach(function(data) {
      var name, tx, script, index;
      var type, expected, hexType;

      if (data.length === 1)
        return;

      tx = TX.fromRaw(data[0], 'hex');
      clearCache(tx, noCache);

      script = Script.fromRaw(data[1], 'hex');

      index = data[2];
      type = data[3];
      expected = util.revHex(data[4]);
      hexType = type & 3;

      if (type & 0x80)
        hexType |= 0x80;

      hexType = hexType.toString(16);

      if (hexType.length % 2 !== 0)
        hexType = '0' + hexType;

      name = 'should get signature hash of '
        + data[4] + ' (' + hexType + ')' + suffix;

      it(name, function() {
        var subscript = script.getSubscript(0).removeSeparators();
        var hash = tx.signatureHash(index, subscript, 0, type, 0);
        assert.equal(hash.toString('hex'), expected);
      });
    });
  });

  function createInput(value, view) {
    var hash = crypto.randomBytes(32).toString('hex');
    var output = new Output();
    output.value = value;
    view.addOutput(hash, 0, output);
    return {
      prevout: {
        hash: hash,
        index: 0
      }
    };
  }

  it('should fail on >51 bit coin values', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(constants.MAX_MONEY + 1, view)],
      outputs: [{
        script: [],
        value: constants.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should handle 51 bit coin values', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(constants.MAX_MONEY, view)],
      outputs: [{
        script: [],
        value: constants.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(tx.checkInputs(view, 0));
  });

  it('should fail on >51 bit output values', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(constants.MAX_MONEY, view)],
      outputs: [{
        script: [],
        value: constants.MAX_MONEY + 1
      }],
      locktime: 0
    });
    assert.ok(!tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should handle 51 bit output values', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(constants.MAX_MONEY, view)],
      outputs: [{
        script: [],
        value: constants.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(tx.checkInputs(view, 0));
  });

  it('should fail on >51 bit fees', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(constants.MAX_MONEY + 1, view)],
      outputs: [{
        script: [],
        value: 0
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should fail on >51 bit values from multiple', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [
        createInput(Math.floor(constants.MAX_MONEY / 2), view),
        createInput(Math.floor(constants.MAX_MONEY / 2), view),
        createInput(Math.floor(constants.MAX_MONEY / 2), view)
      ],
      outputs: [{
        script: [],
        value: constants.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should fail on >51 bit output values from multiple', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(constants.MAX_MONEY, view)],
      outputs: [
        {
          script: [],
          value: Math.floor(constants.MAX_MONEY / 2)
        },
        {
          script: [],
          value: Math.floor(constants.MAX_MONEY / 2)
        },
        {
          script: [],
          value: Math.floor(constants.MAX_MONEY / 2)
        }
      ],
      locktime: 0
    });
    assert.ok(!tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should fail on >51 bit fees from multiple', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [
        createInput(Math.floor(constants.MAX_MONEY / 2), view),
        createInput(Math.floor(constants.MAX_MONEY / 2), view),
        createInput(Math.floor(constants.MAX_MONEY / 2), view)
      ],
      outputs: [{
        script: [],
        value: 0
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should fail on >51 bit fees from multiple txs', function() {
    var view = new CoinView();
    var genesis = Network.get().genesis;
    var block = new Block(genesis);
    var i, tx;

    for (i = 0; i < 3; i++) {
      tx = new TX({
        version: 1,
        flag: 1,
        inputs: [
          createInput(Math.floor(constants.MAX_MONEY / 2), view)
        ],
        outputs: [{
          script: [],
          value: 0
        }],
        locktime: 0
      });

      block.txs.push(tx);
    }

    assert.equal(block.getReward(view, 0), -1);
  });

  it('should fail to parse >53 bit values', function() {
    var view = new CoinView();
    var tx, raw;

    tx = new TX({
      version: 1,
      flag: 1,
      inputs: [
        createInput(Math.floor(constants.MAX_MONEY / 2), view)
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
    assert.throws(function() {
      TX.fromRaw(raw);
    });
    tx._raw = null;
    tx.outputs[0].value = 0;

    raw = tx.toRaw();
    assert(encoding.readU64(raw, 47) === 0x00);
    raw[54] = 0x80;
    assert.throws(function() {
      TX.fromRaw(raw);
    });
  });

  it('should fail on 53 bit coin values', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(util.MAX_SAFE_INTEGER, view)],
      outputs: [{
        script: [],
        value: constants.MAX_MONEY
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should fail on 53 bit output values', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(constants.MAX_MONEY, view)],
      outputs: [{
        script: [],
        value: util.MAX_SAFE_INTEGER
      }],
      locktime: 0
    });
    assert.ok(!tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  it('should fail on 53 bit fees', function() {
    var view = new CoinView();
    var tx = new TX({
      version: 1,
      flag: 1,
      inputs: [createInput(util.MAX_SAFE_INTEGER, view)],
      outputs: [{
        script: [],
        value: 0
      }],
      locktime: 0
    });
    assert.ok(tx.isSane());
    assert.ok(!tx.checkInputs(view, 0));
  });

  [util.MAX_SAFE_ADDITION, util.MAX_SAFE_INTEGER].forEach(function(MAX) {
    it('should fail on >53 bit values from multiple', function() {
      var view = new CoinView();
      var tx = new TX({
        version: 1,
        flag: 1,
        inputs: [
          createInput(MAX, view),
          createInput(MAX, view),
          createInput(MAX, view)
        ],
        outputs: [{
          script: [],
          value: constants.MAX_MONEY
        }],
        locktime: 0
      });
      assert.ok(tx.isSane());
      assert.ok(!tx.checkInputs(view, 0));
    });

    it('should fail on >53 bit output values from multiple', function() {
      var view = new CoinView();
      var tx = new TX({
        version: 1,
        flag: 1,
        inputs: [createInput(constants.MAX_MONEY, view)],
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
      assert.ok(!tx.checkInputs(view, 0));
    });

    it('should fail on >53 bit fees from multiple', function() {
      var view = new CoinView();
      var tx = new TX({
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
      assert.ok(!tx.checkInputs(view, 0));
    });

    it('should fail on >53 bit fees from multiple txs', function() {
      var view = new CoinView();
      var genesis = Network.get().genesis;
      var block = new Block(genesis);
      var i, tx;

      for (i = 0; i < 3; i++) {
        tx = new TX({
          version: 1,
          flag: 1,
          inputs: [
            createInput(MAX, view)
          ],
          outputs: [{
            script: [],
            value: 0
          }],
          locktime: 0
        });
        block.txs.push(tx);
      }

      assert.equal(block.getReward(view, 0), -1);
    });
  });
});
