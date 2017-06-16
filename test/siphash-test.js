'use strict';

var assert = require('assert');
var siphash = require('../lib/crypto/siphash');
var siphash256 = siphash.siphash256;
var U64 = siphash.U64;

function toRaw(num) {
  var data = Buffer.allocUnsafe(8);
  data.writeUInt32LE(num.lo >>> 0, 0, true);
  data.writeUInt32LE(num.hi >>> 0, 4, true);
  return data;
};

describe('SipHash', function() {
  it('should perform siphash with no data', function() {
    var k0 = U64(0x07060504, 0x03020100).toRaw();
    var k1 = U64(0x0f0e0d0c, 0x0b0a0908).toRaw();
    var key = Buffer.concat([k0, k1]);
    assert.equal(toRaw(siphash256(Buffer.alloc(0), key)).toString('hex'), '310e0edd47db6f72');
  });

  it('should perform siphash with data', function() {
    var k0 = U64(0x07060504, 0x03020100).toRaw();
    var k1 = U64(0x0f0e0d0c, 0x0b0a0908).toRaw();
    var data = U64(0x07060504, 0x03020100).toRaw();
    var key = Buffer.concat([k0, k1]);
    assert.equal(toRaw(siphash256(data, key)).toString('hex'), '6224939a79f5f593');
  });

  it('should perform siphash with uint256', function() {
    var k0 = U64(0x07060504, 0x03020100).toRaw();
    var k1 = U64(0x0f0e0d0c, 0x0b0a0908).toRaw();
    var hash = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
    var key = Buffer.concat([k0, k1]);
    assert.equal(toRaw(siphash256(hash, key)).toString('hex'), 'ce7cf2722f512771');
  });
});
