var assert = require('assert');
var bcoin = require('../');
var Script = bcoin.script;
var Stack = bcoin.script.stack;
var opcodes = bcoin.protocol.constants.opcodes;

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
      bcoin.utils.toHex(decoded[0]),
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    assert.equal(
      bcoin.utils.toHex(decoded[1]),
      '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
    assert.equal(decoded[2], opcodes.OP_CHECKSIG);

    var dst = bcoin.script.encode(decoded);
    assert.equal(bcoin.utils.toHex(dst), src);
  });

  if (0)
  it('should encode/decode numbers', function() {
    var script = [ 0, 1, 2, 16 ];
    var encoded = bcoin.script.encode(script);
    assert.deepEqual(encoded, [ 0, 0x51, 0x52, 0x60 ]);
    var decoded = bcoin.script.decode(encoded);
    assert.deepEqual(decoded, script);
  });

  it('should recognize a P2SH output', function () {
    var hex = 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87'
    var encoded = new Buffer(hex, 'hex')
    var decoded = new bcoin.script(encoded);
    assert(decoded.isScripthash())
  });

  it('should recognize a Null Data output', function () {
    var hex = '6a28590c080112220a1b353930632e6f7267282a5f5e294f7665726c6179404f7261636c65103b1a010c'
    var encoded = new Buffer(hex, 'hex')
    var decoded = new Script(encoded);
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
});
