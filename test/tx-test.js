var assert = require('assert');
var bn = require('bn.js');
var bcoin = require('../')();
var utils = bcoin.utils;
var constants = bcoin.protocol.constants;
var opcodes = bcoin.protocol.constants.opcodes;
var valid = require('./data/tx_valid.json');
var invalid = require('./data/tx_invalid.json');
var sighash = require('./data/sighash.json');
var fs = require('fs');
var tx1 = parseTX('data/tx1.hex');
var tx2 = parseTX('data/tx2.hex');
var tx3 = parseTX('data/tx3.hex');
var tx4 = parseExtended('data/tx4.hex');

function parseTX(file) {
  file = fs.readFileSync(__dirname + '/' + file, 'utf8').trim().split(/\n+/);
  var tx = bcoin.tx.fromRaw(file.shift().trim(), 'hex');
  for (var i = 0; i < file.length; i++) {
    var coin = bcoin.tx.fromRaw(file[i].trim(), 'hex');
    tx.fillCoins(coin);
  }
  return tx;
}

function parseExtended(file) {
  file = fs.readFileSync(__dirname + '/' + file, 'utf8').trim();
  return bcoin.tx.fromExtended(file, 'hex', true);
}

function clearCache(tx, nocache) {
  var i, input, output;

  if (tx instanceof bcoin.script) {
    if (!nocache)
      return;
    delete tx.raw;
    return;
  }

  if (!nocache) {
    assert.equal(tx.hash('hex'), tx.clone().hash('hex'));
    return;
  }

  delete tx._raw;
  delete tx._hash;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    delete input.script.raw;
    if (input.coin)
      delete input.coin.script.raw;
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    delete output.script.raw;
  }
}

describe('TX', function() {
  var parser = bcoin.protocol.parser;
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

  [false, true].forEach(function(nocache) {
    var suffix = nocache ? ' without cache' : ' with cache';

    it('should decode/encode with parser/framer' + suffix, function() {
      var tx = bcoin.tx.fromRaw(raw, 'hex');
      clearCache(tx, nocache);
      assert.equal(tx.render().toString('hex'), raw);
    });

    it('should be verifiable' + suffix, function() {
      var tx = bcoin.tx.fromRaw(raw, 'hex');
      var p = bcoin.tx.fromRaw(inp, 'hex');
      tx.fillCoins(p);

      clearCache(tx, nocache);
      clearCache(p, nocache);

      assert(tx.verify());
    });

    it('should verify non-minimal output' + suffix, function() {
      clearCache(tx1, nocache);
      assert(tx1.verify(null, true, constants.flags.VERIFY_P2SH));
    });

    it('should verify tx.version == 0' + suffix, function() {
      clearCache(tx2, nocache);
      assert(tx2.verify(null, true, constants.flags.VERIFY_P2SH));
    });

    it('should verify sighash_single bug w/ findanddelete' + suffix, function() {
      clearCache(tx3, nocache);
      assert(tx3.verify(null, true, constants.flags.VERIFY_P2SH));
    });

    it('should verify high S value with only DERSIG enabled' + suffix, function() {
      clearCache(tx4, nocache);
      assert(tx4.verify(0, true, constants.flags.VERIFY_P2SH | constants.flags.VERIFY_DERSIG));
    });

    function parseTest(data) {
      var coins = data[0];
      var tx = bcoin.tx.fromRaw(data[1], 'hex');
      var flags = data[2] ? data[2].trim().split(/,\s*/) : [];
      var flag = 0;

      for (var i = 0; i < flags.length; i++)
        flag |= constants.flags['VERIFY_' + flags[i]];

      flags = flag;

      coins.forEach(function(data) {
        var hash = data[0];
        var index = data[1];
        var script = bcoin.script.fromTestString(data[2]);
        var value = data[3];
        var coin = new bcoin.coin({
          version: 1,
          height: -1,
          coinbase: false,
          hash: utils.revHex(hash),
          index: index,
          script: script,
          value: value != null ? new bn(value) : new bn(0)
        });
        tx.fillCoins(coin);
      });

      return {
        tx: tx,
        flags: flags,
        comments: tx.hasCoins()
          ? utils._inspect(tx.inputs[0].coin.script, false).slice(0, -1)
          : 'coinbase',
        data: data
      };
    }

    [[valid, true], [invalid, false]].forEach(function(test) {
      // ["[[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"],
      var arr = test[0];
      var valid = test[1];
      var comment = '';
      arr.forEach(function(json, i) {
        if (json.length === 1) {
          comment += ' ' + json[0];
          return;
        }

        var data = parseTest(json);

        if (!data) {
          comment = '';
          return;
        }

        var tx = data.tx;
        var flags = data.flags;
        var comments = comment.trim();
        if (!comments)
          comments = data.comments;
        comment = '';

        if (valid) {
          if (comments.indexOf('Coinbase') === 0) {
            it('should handle valid coinbase' + suffix + ': ' + comments, function () {
              clearCache(tx, nocache);
              assert.ok(tx.isSane());
            });
            return;
          }
          it('should handle valid tx test' + suffix + ': ' + comments, function () {
            clearCache(tx, nocache);
            assert.ok(tx.verify(null, true, flags));
          });
        } else {
          if (comments === 'Duplicate inputs') {
            it('should handle duplicate input test' + suffix + ': ' + comments, function () {
              clearCache(tx, nocache);
              assert.ok(tx.verify(null, true, flags));
              assert.ok(!tx.isSane());
            });
            return;
          }
          if (comments === 'Negative output') {
            it('should handle invalid tx (negative)' + suffix + ': ' + comments, function () {
              clearCache(tx, nocache);
              assert.ok(tx.verify(null, true, flags));
              assert.ok(!tx.isSane());
            });
            return;
          }
          if (comments.indexOf('Coinbase') === 0) {
            it('should handle invalid coinbase' + suffix + ': ' + comments, function () {
              clearCache(tx, nocache);
              assert.ok(!tx.isSane());
            });
            return;
          }
          it('should handle invalid tx test' + suffix + ': ' + comments, function () {
            clearCache(tx, nocache);
            assert.ok(!tx.verify(null, true, flags));
          });
        }
      });
    });

    sighash.forEach(function(data) {
      // ["raw_transaction, script, input_index, hashType, signature_hash (result)"],
      if (data.length === 1)
        return;
      var tx = bcoin.tx.fromRaw(data[0], 'hex');
      clearCache(tx, nocache);
      var script = bcoin.script.fromRaw(data[1], 'hex');
      clearCache(script, nocache);
      var index = data[2];
      var type = data[3];
      var expected = utils.revHex(data[4]);
      var hexType = type & 3;
      if (type & 0x80)
        hexType |= 0x80;
      hexType = hexType.toString(16);
      if (hexType.length % 2 !== 0)
        hexType = '0' + hexType;
      it('should get signature hash of ' + data[4] + ' (' + hexType + ')' + suffix, function () {
        var subscript = script.getSubscript();
        var hash = tx.signatureHash(index, subscript, type, 0).toString('hex');
        assert.equal(hash, expected);
      });
    });
  });
});
