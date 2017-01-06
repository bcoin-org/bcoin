'use strict';

var assert = require('assert');
var Script = require('../lib/script/script');
var Witness = require('../lib/script/witness');
var Stack = require('../lib/script/stack');
var TX = require('../lib/primitives/tx');
var encoding = require('../lib/utils/encoding');
var opcodes = Script.opcodes;

var scripts = require('./data/script_tests');

function success(res, stack) {
  if (!res)
    return false;

  if (stack.length === 0)
    return false;

  if (!Script.bool(stack.top(-1)))
    return false;

  return true;
}

describe('Script', function() {
  it('should encode/decode script', function() {
    var src, decoded, dst;

    src = '20'
      + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '20'
      + '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'
      + 'ac';

    decoded = Script.fromRaw(src, 'hex');
    assert.equal(decoded.code.length, 3);
    assert.equal(decoded.code[0].data.toString('hex'),
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    assert.equal(decoded.code[1].data.toString('hex'),
      '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
    assert.equal(decoded.code[2].value, opcodes.OP_CHECKSIG);

    dst = decoded.toRaw();
    assert.equal(dst.toString('hex'), src);
  });

  it('should encode/decode numbers', function() {
    var script = [0, 0x51, 0x52, 0x60];
    var encoded = Script.fromArray(script).raw;
    var decoded = Script(encoded).toArray();
    assert.deepEqual(decoded, script);
  });

  it('should recognize a P2SH output', function() {
    var hex = 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87';
    var decoded = Script.fromRaw(hex, 'hex');
    assert(decoded.isScripthash());
  });

  it('should recognize a Null Data output', function() {
    var hex = '6a28590c080112220a1b353930632e6f7267282a5f'
      + '5e294f7665726c6179404f7261636c65103b1a010c';
    var decoded = Script.fromRaw(hex, 'hex');
    assert(decoded.isNulldata());
  });

  it('should handle if statements correctly', function() {
    var input, output, stack, res;

    input = new Script([opcodes.OP_1, opcodes.OP_2]);

    output = new Script([
      opcodes.OP_2,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ELSE,
      opcodes.OP_4,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);

    stack = new Stack();

    input.execute(stack);

    res = output.execute(stack);
    assert(res);

    assert.deepEqual(stack.items, [[1], [3], [5]]);

    input = new Script([opcodes.OP_1, opcodes.OP_2]);
    output = new Script([
      opcodes.OP_9,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ELSE,
      opcodes.OP_4,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);

    stack = new Stack();
    input.execute(stack);

    res = output.execute(stack);
    assert(res);
    assert.deepEqual(stack.items, [[1], [4], [5]]);

    input = new Script([opcodes.OP_1, opcodes.OP_2]);
    output = new Script([
      opcodes.OP_2,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);

    stack = new Stack();

    input.execute(stack);

    res = output.execute(stack);
    assert(res);
    assert.deepEqual(stack.items, [[1], [3], [5]]);

    input = new Script([opcodes.OP_1, opcodes.OP_2]);
    output = new Script([
      opcodes.OP_9,
      opcodes.OP_EQUAL,
      opcodes.OP_IF,
      opcodes.OP_3,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);

    stack = new Stack();
    input.execute(stack);

    res = output.execute(stack);
    assert(res);
    assert.deepEqual(stack.items, [[1], [5]]);

    input = new Script([opcodes.OP_1, opcodes.OP_2]);
    output = new Script([
      opcodes.OP_9,
      opcodes.OP_EQUAL,
      opcodes.OP_NOTIF,
      opcodes.OP_3,
      opcodes.OP_ENDIF,
      opcodes.OP_5
    ]);
    stack = new Stack();
    input.execute(stack);

    res = output.execute(stack);
    assert(res);
    assert.deepEqual(stack.items, [[1], [3], [5]]);
  });

  it('should handle CScriptNums correctly', function() {
    var input, output, stack;

    input = new Script([
      new Buffer('ffffff7f', 'hex'),
      opcodes.OP_NEGATE,
      opcodes.OP_DUP,
      opcodes.OP_ADD
    ]);

    output = new Script([
      new Buffer('feffffff80', 'hex'),
      opcodes.OP_EQUAL
    ]);

    stack = new Stack();

    assert(input.execute(stack));
    assert(success(output.execute(stack), stack));
  });

  it('should handle CScriptNums correctly', function() {
    var input, output, stack;

    input = new Script([
      opcodes.OP_11,
      opcodes.OP_10,
      opcodes.OP_1,
      opcodes.OP_ADD
    ]);

    output = new Script([
      opcodes.OP_NUMNOTEQUAL,
      opcodes.OP_NOT
    ]);

    stack = new Stack();

    assert(input.execute(stack));
    assert(success(output.execute(stack), stack));
  });

  it('should handle OP_ROLL correctly', function() {
    var input, output, stack;

    input = new Script([
      new Buffer([0x16]),
      new Buffer([0x15]),
      new Buffer([0x14])
    ]);

    output = new Script([
      opcodes.OP_0,
      opcodes.OP_ROLL,
      new Buffer([0x14]),
      opcodes.OP_EQUALVERIFY,
      opcodes.OP_DEPTH,
      opcodes.OP_2,
      opcodes.OP_EQUAL
    ]);

    stack = new Stack();

    assert(input.execute(stack));
    assert(success(output.execute(stack), stack));
  });

  scripts.forEach(function(data) {
    var witness = Array.isArray(data[0]) ? data.shift() : [];
    var input = data[0] ? data[0].trim() : data[0] || '';
    var output = data[1] ? data[1].trim() : data[1] || '';
    var flags = data[2] ? data[2].trim().split(/,\s*/) : [];
    var expected = data[3] || '';
    var comments = Array.isArray(data[4]) ? data[4].join('. ') : data[4] || '';
    var amount = 0;
    var flag = 0;
    var i, name;

    if (data.length === 1)
      return;

    if (!comments)
      comments = output.slice(0, 60);

    comments += ' (' + expected + ')';

    if (witness.length !== 0)
      amount = witness.pop() * 100000000;

    witness = Witness.fromString(witness);
    input = Script.fromString(input);
    output = Script.fromString(output);

    for (i = 0; i < flags.length; i++) {
      name = 'VERIFY_' + flags[i];
      assert(Script.flags[name] != null, 'Unknown flag.');
      flag |= Script.flags[name];
    }

    flags = flag;

    [false, true].forEach(function(noCache) {
      var suffix = noCache ? ' without cache' : ' with cache';
      it('should handle script test' + suffix + ': ' + comments, function() {
        var prev, tx, err, res;

        // Funding transaction.
        prev = new TX({
          version: 1,
          flag: 1,
          inputs: [{
            prevout: {
              hash: encoding.NULL_HASH,
              index: 0xffffffff
            },
            script: new Script([opcodes.OP_0, opcodes.OP_0]),
            witness: new Witness(),
            sequence: 0xffffffff
          }],
          outputs: [{
            script: output,
            value: amount
          }],
          locktime: 0
        });

        // Spending transaction.
        tx = new TX({
          version: 1,
          flag: 1,
          inputs: [{
            prevout: {
              hash: prev.hash('hex'),
              index: 0
            },
            script: input,
            witness: witness,
            sequence: 0xffffffff
          }],
          outputs: [{
            script: new Script(),
            value: amount
          }],
          locktime: 0
        });

        if (noCache) {
          prev.refresh();
          tx.refresh();
        }

        try {
          res = Script.verify(input, witness, output, tx, 0, amount, flags);
        } catch (e) {
          err = e;
        }

        if (expected !== 'OK') {
          assert(!res);
          assert(err);
          assert.equal(err.code, expected);
          return;
        }

        assert.ifError(err);
        assert(res);
      });
    });
  });
});
