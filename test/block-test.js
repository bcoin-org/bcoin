var bn = require('bn.js');
var bcoin = require('../')();
var assert = require('assert');

describe('Block', function() {
  var parser = bcoin.protocol.parser;
  var block = bcoin.merkleblock({
    type: 'block',
    version: 2,
    prevBlock: 'd1831d4411bdfda89d9d8c842b541beafd1437fc560dbe5c0000000000000000',
    merkleRoot: '28bec1d35af480ba3884553d72694f6ba6c163a5c081d7e6edaec15f373f19af',
    ts: 1399713634,
    bits: 419465580,
    nonce: 1186968784,
    totalTX: 461,
    hashes:[
      '7d22e53bce1bbb3294d1a396c5acc45bdcc8f192cb492f0d9f55421fd4c62de1',
      '9d6d585fdaf3737b9a54aaee1dd003f498328d699b7dfb42dd2b44b6ebde2333',
      '8b61da3053d6f382f2145bdd856bc5dcf052c3a11c1784d3d51b2cbe0f6d0923',
      'd7bbaae4716cb0d329d755b707cee588cddc68601f99bc05fef1fabeb8dfe4a0',
      '7393f84cd04ca8931975c66282ebf1847c78d8de6c2578d4f9bae23bc6f30857',
      'ec8c51de3170301430ec56f6703533d9ea5b05c6fa7068954bcb90eed8c2ee5c',
      'c7c152869db09a5ae2291fa03142912d9d7aba75be7d491a8ac4230ee9a920cb',
      '5adbf04583354515a225f2c418de7c5cdac4cef211820c79717cd2c50412153f',
      '1f5e46b9da3a8b1241f4a1501741d3453bafddf6135b600b926e3f4056c6d564',
      '33825657ba32afe269819f01993bd77baba86379043168c94845d32370e53562' ],
    flags: new Buffer([ 245, 90, 0 ])
  }, 'merkleblock');
  var raw = block.toRaw('hex');

  it('should parse partial merkle tree', function() {
    assert(block.verify());
    assert.equal(block.tx.length, 2);
    assert.equal(
      block.tx[0],
      '7393f84cd04ca8931975c66282ebf1847c78d8de6c2578d4f9bae23bc6f30857');
    assert.equal(
      block.tx[1],
      'ec8c51de3170301430ec56f6703533d9ea5b05c6fa7068954bcb90eed8c2ee5c');
  });

  it('should decode/encode with parser/framer', function() {
    var b = bcoin.merkleblock(parser.parseMerkleBlock(new Buffer(raw, 'hex')));
    assert.equal(b.render().toString('hex'), raw);
  });

  it('should be verifiable', function() {
    var b = bcoin.merkleblock(parser.parseMerkleBlock(new Buffer(raw, 'hex')));
    assert(b.verify());
  });

  it('should be jsonified and unjsonified and still verify', function() {
    var json = block.toRaw();
    var b = bcoin.merkleblock.fromRaw(json);
    // FIXME
    //assert.equal(b.render(), json);
    assert(b.verify());
  });
});
