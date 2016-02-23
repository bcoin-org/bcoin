var assert = require('assert');
var bcoin = require('../');

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
    assert.equal(decoded[2], 'checksig');

    var dst = bcoin.script.encode(decoded);
    assert.equal(bcoin.utils.toHex(dst), src);
  });

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
    var decoded = bcoin.script.decode(encoded);
    assert(bcoin.script.isScripthash(decoded))
  })

  it('should recognize a Null Data output', function () {
    var hex = '6a28590c080112220a1b353930632e6f7267282a5f5e294f7665726c6179404f7261636c65103b1a010c'
    var encoded = new Buffer(hex, 'hex')
    var decoded = bcoin.script.decode(encoded);
    assert(bcoin.script.isNulldata(decoded))
  })

  it('should handle if statements correctly', function () {
    var inputScript = [1, 2];
    var prevOutScript = [2, 'equal', 'if', 3, 'else', 4, 'endif', 5];
    var stack = [];
    bcoin.script.execute(inputScript, stack);
    var res = bcoin.script.execute(prevOutScript, stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [3], [5]]);

    var inputScript = [1, 2];
    var prevOutScript = [9, 'equal', 'if', 3, 'else', 4, 'endif', 5];
    var stack = [];
    bcoin.script.execute(inputScript, stack);
    var res = bcoin.script.execute(prevOutScript, stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [4], [5]]);

    var inputScript = [1, 2];
    var prevOutScript = [2, 'equal', 'if', 3, 'endif', 5];
    var stack = [];
    bcoin.script.execute(inputScript, stack);
    var res = bcoin.script.execute(prevOutScript, stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [3], [5]]);

    var inputScript = [1, 2];
    var prevOutScript = [9, 'equal', 'if', 3, 'endif', 5];
    var stack = [];
    bcoin.script.execute(inputScript, stack);
    var res = bcoin.script.execute(prevOutScript, stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [5]]);

    var inputScript = [1, 2];
    var prevOutScript = [9, 'equal', 'notif', 3, 'endif', 5];
    var stack = [];
    bcoin.script.execute(inputScript, stack);
    var res = bcoin.script.execute(prevOutScript, stack);
    assert(res);
    assert.deepEqual(stack.slice(), [[1], [3], [5]]);
  })
});
