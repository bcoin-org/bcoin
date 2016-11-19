'use strict';

var bcoin = require('../').set('main');
var assert = require('assert');
var Script = bcoin.script;
var Stack = bcoin.stack;
var util = bcoin.util;
var crypto = require('../lib/crypto/crypto');
var constants = bcoin.constants;
var opcodes = bcoin.constants.opcodes;
var scripts = require('./data/script_tests');
var BN = require('bn.js');

describe('Script', function() {
  it('should encode/decode script', function() {
    var src = '20'
      + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '20'
      + '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'
      + 'ac';

    var decoded = bcoin.script.decode(new Buffer(src, 'hex'));
    assert.equal(decoded.length, 3);
    assert.equal(decoded[0].data.toString('hex'),
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    assert.equal(decoded[1].data.toString('hex'),
      '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
    assert.equal(decoded[2].value, opcodes.OP_CHECKSIG);

    var dst = bcoin.script.encode(decoded);
    assert.equal(dst.toString('hex'), src);
  });

  it('should encode/decode numbers', function() {
    var script = [0, 0x51, 0x52, 0x60];
    var encoded = bcoin.script.fromArray(script).raw;
    var decoded = bcoin.script.decode(encoded).map(function(op) { return op.value; });
    assert.deepEqual(decoded, script);
  });

  it('should recognize a P2SH output', function() {
    var hex = 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87';
    var decoded = bcoin.script.fromRaw(hex, 'hex');
    assert(decoded.isScripthash());
  });

  it('should recognize a Null Data output', function() {
    var hex = '6a28590c080112220a1b353930632e6f7267282a5f'
      + '5e294f7665726c6179404f7261636c65103b1a010c';
    var decoded = bcoin.script.fromRaw(hex, 'hex');
    assert(decoded.isNulldata());
  });

  it('should handle if statements correctly', function() {
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
    assert.deepEqual(stack.items, [[1], [3], [5]]);

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
    assert.deepEqual(stack.items, [[1], [4], [5]]);

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
    assert.deepEqual(stack.items, [[1], [3], [5]]);

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
    assert.deepEqual(stack.items, [[1], [5]]);

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
    assert.deepEqual(stack.items, [[1], [3], [5]]);
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

  /*
  it('should handle bad size pushes correctly.', function() {
    var err;
    var stack = new bcoin.stack();
    var s = bcoin.script.fromString(
      'OP_1 OP_DUP OP_PUSHDATA1'
    );
    assert(util.equal(s.raw, new Buffer('51764c', 'hex')));
    delete s.raw;
    assert(util.equal(s.encode(), new Buffer('51764c', 'hex')));
    try {
      s.execute(stack);
    } catch (e) {
      err = e;
    }
    assert(err);
    assert(err.code === 'BAD_OPCODE');
    var s = bcoin.script.fromString(
      'OP_1 OP_DUP OP_PUSHDATA2 0x01'
    );
    assert(util.equal(s.raw, new Buffer('51764d01', 'hex')));
    delete s.raw;
    assert(util.equal(s.encode(), new Buffer('51764d01', 'hex')));
    err = null;
    try {
      s.execute(stack);
    } catch (e) {
      err = e;
    }
    assert(err);
    assert(err.code === 'BAD_OPCODE');
    var s = bcoin.script.fromString(
      'OP_1 OP_DUP OP_PUSHDATA4 0x0001'
    );
    assert(util.equal(s.raw, new Buffer('51764e0001', 'hex')));
    delete s.raw;
    assert(util.equal(s.encode(), new Buffer('51764e0001', 'hex')));
    err = null;
    try {
      s.execute(stack);
    } catch (e) {
      err = e;
    }
    assert(err);
    assert(err.code === 'BAD_OPCODE');
    var s = bcoin.script.fromString(
      'OP_1 OP_DUP OP_PUSHDATA1 0x02 0x01'
    );
    assert(util.equal(s.raw, new Buffer('51764c0201', 'hex')));
    delete s.raw;
    assert(util.equal(s.encode(), new Buffer('51764c0201', 'hex')));
    err = null;
    try {
      s.execute(stack);
    } catch (e) {
      err = e;
    }
    assert(err);
    assert(err.code === 'BAD_OPCODE');
    var s = bcoin.script.fromString(
      'OP_1 OP_DUP OP_PUSHDATA2 0x0200 0x01'
    );
    assert(util.equal(s.raw, new Buffer('51764d020001', 'hex')));
    delete s.raw;
    assert(util.equal(s.encode(), new Buffer('51764d020001', 'hex')));
    err = null;
    try {
      s.execute(stack);
    } catch (e) {
      err = e;
    }
    assert(err);
    assert(err.code === 'BAD_OPCODE');
  });
  */

  it('should handle CScriptNums correctly', function() {
    var s = new bcoin.script([
      new Buffer([0xff, 0xff, 0xff, 0x7f]),
      opcodes.OP_NEGATE,
      opcodes.OP_DUP,
      opcodes.OP_ADD
    ]);
    var s2 = new bcoin.script([
      new Buffer([0xfe, 0xff, 0xff, 0xff, 0x80]),
      opcodes.OP_EQUAL
    ]);
    var stack = new bcoin.stack();
    assert(s.execute(stack));
    assert(success(s2.execute(stack), stack));
  });

  it('should handle CScriptNums correctly', function() {
    var s = new bcoin.script([
      opcodes.OP_11,
      opcodes.OP_10,
      opcodes.OP_1,
      opcodes.OP_ADD
    ]);
    var s2 = new bcoin.script([
      opcodes.OP_NUMNOTEQUAL,
      opcodes.OP_NOT
    ]);
    var stack = new bcoin.stack();
    assert(s.execute(stack));
    assert(success(s2.execute(stack), stack));
  });

  it('should handle OP_ROLL correctly', function() {
    var s = new bcoin.script([
      new Buffer([0x16]),
      new Buffer([0x15]),
      new Buffer([0x14])
    ]);
    var s2 = new bcoin.script([
      opcodes.OP_0,
      opcodes.OP_ROLL,
      new Buffer([0x14]),
      opcodes.OP_EQUALVERIFY,
      opcodes.OP_DEPTH,
      opcodes.OP_2,
      opcodes.OP_EQUAL
    ]);
    var stack = new bcoin.stack();
    assert(s.execute(stack));
    assert(success(s2.execute(stack), stack));
  });

  scripts.forEach(function(data) {
    // ["Format is: [[wit...]?, scriptSig, scriptPubKey, flags, expected_scripterror, ... comments]"],
    var witness = Array.isArray(data[0]) ? data.shift() : [];
    var input = data[0] ? data[0].trim() : data[0] || '';
    var output = data[1] ? data[1].trim() : data[1] || '';
    var flags = data[2] ? data[2].trim().split(/,\s*/) : [];
    var expected = data[3] || '';
    var comments = Array.isArray(data[4]) ? data[4].join('. ') : data[4] || '';
    var amount = 0;

    if (data.length === 1)
      return;

    if (!comments)
      comments = output.slice(0, 60);

    comments += ' (' + expected + ')';

    if (witness.length !== 0)
      amount = witness.pop() * 100000000;

    witness = bcoin.witness.fromString(witness);
    input = bcoin.script.fromString(input);
    output = bcoin.script.fromString(output);

    var flag = 0;
    for (var i = 0; i < flags.length; i++) {
      flag |= constants.flags['VERIFY_' + flags[i]];
    }
    flags = flag;

    [false, true].forEach(function(nocache) {
      var suffix = nocache ? ' without cache' : ' with cache';
      it('should handle script test' + suffix + ': ' + comments, function() {
        var coin = bcoin.tx({
          version: 1,
          flag: 1,
          inputs: [{
            prevout: {
              hash: constants.NULL_HASH,
              index: 0xffffffff
            },
            coin: null,
            script: [bcoin.script.array(0), bcoin.script.array(0)],
            witness: new bcoin.witness(),
            sequence: 0xffffffff
          }],
          outputs: [{
            script: output,
            value: amount
          }],
          locktime: 0
        });
        var tx = bcoin.tx({
          version: 1,
          flag: 1,
          inputs: [{
            prevout: {
              hash: coin.hash('hex'),
              index: 0
            },
            coin: bcoin.coin.fromTX(coin, 0),
            script: input,
            witness: witness,
            sequence: 0xffffffff
          }],
          outputs: [{
            script: new bcoin.script(),
            value: amount
          }],
          locktime: 0
        });
        if (nocache) {
          tx._raw = null;
          tx._size = -1;
          tx._witnessSize = -1;
          tx._lastWitnessSize = 0;
          tx._hash = null;
          tx._hhash = null;
          tx._whash = null;
          tx._inputValue = -1;
          tx._outputValue = -1;
          tx._hashPrevouts = null;
          tx._hashSequence = null;
          tx._hashOutputs = null;

          coin._raw = null;
          coin._size = -1;
          coin._witnessSize = -1;
          coin._lastWitnessSize = 0;
          coin._hash = null;
          coin._inputValue = -1;
          coin._outputValue = -1;
          coin._hashPrevouts = null;
          coin._hashSequence = null;
          coin._hashOutputs = null;

          delete input._address;
          delete output._address;
        }
        var err, res;
        try {
          res = Script.verify(input, witness, output, tx, 0, flags);
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

  /*
  it('should execute FindAndDelete correctly', function() {
    var s, d, expect;

    function del(s) {
      s.mutable = true;
      return s;
    }

    s = bcoin.script.fromString('OP_1 OP_2');
    del(s);
    d = new bcoin.script();
    expect = s.clone();
    assert.equal(s.findAndDelete(d.encode()), 0);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromString('OP_1 OP_2 OP_3');
    del(s);
    d = bcoin.script.fromString('OP_2');
    del(d);
    expect = bcoin.script.fromString('OP_1 OP_3');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 1);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromString('OP_3 OP_1 OP_3 OP_3 OP_4 OP_3');
    del(s);
    d = bcoin.script.fromString('OP_3');
    del(d);
    expect = bcoin.script.fromString('OP_1 OP_4');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 4);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('0302ff03', 'hex');
    del(s);
    d = bcoin.script.fromRaw('0302ff03', 'hex');
    del(d);
    expect = new bcoin.script();
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 1);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('0302ff030302ff03', 'hex');
    del(s);
    d = bcoin.script.fromRaw('0302ff03', 'hex');
    del(d);
    expect = new bcoin.script();
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 2);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('0302ff030302ff03', 'hex');
    del(s);
    d = bcoin.script.fromRaw('02', 'hex');
    del(d);
    expect = s.clone();
    del(expect);
    //assert.equal(s.findAndDelete(d.encode()), 0);
    s.findAndDelete(d.encode());
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('0302ff030302ff03', 'hex');
    del(s);
    d = bcoin.script.fromRaw('ff', 'hex');
    del(d);
    expect = s.clone();
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 0);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('0302ff030302ff03', 'hex');
    del(s);
    d = bcoin.script.fromRaw('03', 'hex');
    del(d);
    expect = new bcoin.script([new Buffer([0xff, 0x03]), new Buffer([0xff, 0x03])]);
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 2);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('02feed5169', 'hex');
    del(s);
    d = bcoin.script.fromRaw('feed51', 'hex');
    del(d);
    expect = s.clone();
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 0);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('02feed5169', 'hex');
    del(s);
    d = bcoin.script.fromRaw('02feed51', 'hex');
    del(d);
    expect = bcoin.script.fromRaw('69', 'hex');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 1);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('516902feed5169', 'hex');
    del(s);
    d = bcoin.script.fromRaw('feed51', 'hex');
    del(d);
    expect = s.clone();
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 0);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('516902feed5169', 'hex');
    del(s);
    d = bcoin.script.fromRaw('02feed51', 'hex');
    del(d);
    expect = bcoin.script.fromRaw('516969', 'hex');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 1);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromString('OP_0 OP_0 OP_1 OP_1');
    del(s);
    d = bcoin.script.fromString('OP_0 OP_1');
    del(d);
    expect = bcoin.script.fromString('OP_0 OP_1');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 1);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromString('OP_0 OP_0 OP_1 OP_0 OP_1 OP_1');
    del(s);
    d = bcoin.script.fromString('OP_0 OP_1');
    del(d);
    expect = bcoin.script.fromString('OP_0 OP_1');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 2);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('0003feed', 'hex');
    del(s);
    d = bcoin.script.fromRaw('03feed', 'hex');
    del(d);
    expect = bcoin.script.fromRaw('00', 'hex');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 1);
    assert.deepEqual(s.encode(), expect.encode());

    s = bcoin.script.fromRaw('0003feed', 'hex');
    del(s);
    d = bcoin.script.fromRaw('00', 'hex');
    del(d);
    expect = bcoin.script.fromRaw('03feed', 'hex');
    del(expect);
    assert.equal(s.findAndDelete(d.encode()), 1);
    assert.deepEqual(s.encode(), expect.encode());
  });
  */
});
