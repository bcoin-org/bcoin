var assert = require('assert');
var bcoin = require('../')();
var Script = bcoin.script;
var Stack = bcoin.script.stack;
var utils = bcoin.utils;
var constants = bcoin.protocol.constants;
var opcodes = bcoin.protocol.constants.opcodes;
var scripts = require('./data/script_tests');
var bn = require('bn.js');

describe('Script', function() {
  it('should encode/decode script', function() {
    var src = '20' +
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
        '20' +
        '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f' +
        'ac';

    var decoded = bcoin.script.decode(new Buffer(src, 'hex'));
    assert.equal(decoded.length, 3);
    assert.equal(
      decoded[0].toString('hex'),
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    assert.equal(
      decoded[1].toString('hex'),
      '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
    assert.equal(decoded[2], opcodes.OP_CHECKSIG);

    var dst = bcoin.script.encode(decoded);
    assert.equal(dst.toString('hex'), src);
  });

  it('should encode/decode numbers', function() {
    var script = [ 0, 0x51, 0x52, 0x60 ];
    var encoded = bcoin.script.encode(script);
    var decoded = bcoin.script.decode(encoded);
    assert.deepEqual(decoded, script);
  });

  it('should recognize a P2SH output', function () {
    var hex = 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87'
    var decoded = bcoin.script.fromRaw(hex, 'hex');
    assert(decoded.isScripthash())
  });

  it('should recognize a Null Data output', function () {
    var hex = '6a28590c080112220a1b353930632e6f7267282a5f5e294f7665726c6179404f7261636c65103b1a010c'
    var decoded = bcoin.script.fromRaw(hex, 'hex');
    assert(decoded.isNulldata())
  });

  it('should handle if statements correctly', function () {
    var inputScript = new Script([opcodes.OP_1, opcodes.OP_2]);
    var prevOutScript = new Script([
      opcodes.OP_2,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ELSE,
      opcodes.OP_4,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);
    var stack = new Stack();
    inputScript.execute(stack);
    var res = prevOutScript.execute(stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [3], [5]]);

    var inputScript = new Script([opcodes.OP_1, opcodes.OP_2]);
    var prevOutScript = new Script([
      opcodes.OP_9,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ELSE,
      opcodes.OP_4,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);
    var stack = new Stack();
    inputScript.execute(stack);
    var res = prevOutScript.execute(stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [4], [5]]);

    var inputScript = new Script([opcodes.OP_1, opcodes.OP_2]);
    var prevOutScript = new Script([
      opcodes.OP_2,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);
    var stack = new Stack();
    inputScript.execute(stack);
    var res = prevOutScript.execute(stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [3], [5]]);

    var inputScript = new Script([opcodes.OP_1, opcodes.OP_2]);
    var prevOutScript = new Script([
      opcodes.OP_9,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);
    var stack = new Stack();
    inputScript.execute(stack);
    var res = prevOutScript.execute(stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [5]]);

    var inputScript = new Script([opcodes.OP_1, opcodes.OP_2]);
    var prevOutScript = new Script([
      opcodes.OP_9,
      opcodes.OP_EQUAL,
      opcodes.OP_NOTIF,
      opcodes.OP_3,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);
    var stack = new Stack();
    inputScript.execute(stack);
    var res = prevOutScript.execute(stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [3], [5]]);
  });

  function success(res, stack) {
    if (!res)
      return false;
    if (stack.length === 0)
      return false;
    if (!bcoin.script.bool(stack.pop()))
      return false;
    return true;
  }

  it('should handle CScriptNums correctly', function () {
    var s = bcoin.script.fromSymbolic([
      new Buffer([0xff, 0xff, 0xff, 0x7f]), 'OP_NEGATE', 'OP_DUP', 'OP_ADD'
    ]);
    var s2 = bcoin.script.fromSymbolic([
      new Buffer([0xfe, 0xff, 0xff, 0xff, 0x80]),
      'OP_EQUAL'
    ]);
    var stack = new bcoin.script.stack();
    assert(s.execute(stack));
    assert(success(s2.execute(stack), stack));
  });

  it('should handle CScriptNums correctly', function () {
    var s = bcoin.script.fromSymbolic([
      'OP_11', 'OP_10', 'OP_1', 'OP_ADD'
    ]);
    var s2 = bcoin.script.fromSymbolic([
      'OP_NUMNOTEQUAL',
      'OP_NOT'
    ]);
    var stack = new bcoin.script.stack();
    assert(s.execute(stack));
    assert(success(s2.execute(stack), stack));
  });

  it('should handle OP_ROLL correctly', function () {
    var s = bcoin.script.fromSymbolic([
      new Buffer([0x16]), new Buffer([0x15]), new Buffer([0x14])
    ]);
    var s2 = bcoin.script.fromSymbolic([
      'OP_0',
      'OP_ROLL',
      new Buffer([0x14]),
      'OP_EQUALVERIFY',
      'OP_DEPTH',
      'OP_2',
      'OP_EQUAL'
    ]);
    var stack = new bcoin.script.stack();
    assert(s.execute(stack));
    assert(success(s2.execute(stack), stack));
  });

  scripts.forEach(function(data) {
    // ["Format is: [[wit...]?, scriptSig, scriptPubKey, flags, expected_scripterror, ... comments]"],
    var witness = Array.isArray(data[0]) ? data.shift() : null;
    var input = data[0] ? data[0].trim() : data[0] || '';
    var output = data[1] ? data[1].trim() : data[1] || '';
    var flags = data[2] ? data[2].trim().split(/,\s*/) : [];
    var expected = data[3] || '';
    var comments = Array.isArray(data[4]) ? data[4].join('. ') : data[4] || '';

    if (data.length === 1)
      return;

    if (!comments)
      comments = output.slice(0, 60);

    comments += ' (' + expected + ')';

    witness = bcoin.witness.fromTestString(witness);
    input = bcoin.script.fromTestString(input);
    output = bcoin.script.fromTestString(output);

    var flag = 0;
    for (var i = 0; i < flags.length; i++) {
      flag |= constants.flags['VERIFY_' + flags[i]];
    }
    flags = flag;

    [false, true].forEach(function(nocache) {
      var suffix = nocache ? ' without cache' : ' with cache';
      it('should handle script test' + suffix + ': ' + comments, function () {
        var coin = bcoin.tx({
          version: 1,
          inputs: [{
            prevout: {
              hash: constants.NULL_HASH,
              index: 0xffffffff
            },
            coin: null,
            script: [bcoin.script.array(0), bcoin.script.array(0)],
            witness: new bcoin.script.witness(),
            sequence: 0xffffffff
          }],
          outputs: [{
            script: output,
            value: new bn(0)
          }],
          locktime: 0
        });
        var tx = bcoin.tx({
          version: 1,
          inputs: [{
            prevout: {
              hash: coin.hash('hex'),
              index: 0
            },
            coin: bcoin.coin(coin, 0),
            script: input,
            witness: witness,
            sequence: 0xffffffff
          }],
          outputs: [{
            script: new bcoin.script(),
            value: new bn(0)
          }],
          locktime: 0
        });
        if (nocache) {
          delete input.raw;
          delete output.raw;
        }
        var res = Script.verify(input, witness, output, tx, 0, flags);
        if (expected === 'OK')
          assert.ok(res);
        else
          assert.ok(!res);
      });
    });
  });
});
