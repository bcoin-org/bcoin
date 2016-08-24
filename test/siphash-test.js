'use strict';

var assert = require('assert');
var siphash = require('../lib/crypto/siphash');

describe('SipHash', function() {
  it('should perform siphash with no data', function() {
    var k0 = new Buffer(8);
    var k1 = new Buffer(8);
    siphash.write(k0, { hi: 0x07060504, lo: 0x03020100 }, 0);
    siphash.write(k1, { hi: 0x0F0E0D0C, lo: 0x0B0A0908 }, 0);
    // be:
    // assert.equal(siphash(k0, k1, new Buffer(0)).toString('hex'), '726fdb47dd0e0e31');
    // le:
    assert.equal(siphash(new Buffer(0), k0, k1).toString('hex'), '310e0edd47db6f72');
  });

  it('should perform siphash with data', function() {
    var k0 = new Buffer(8);
    var k1 = new Buffer(8);
    var data = new Buffer(8);
    siphash.write(k0, { hi: 0x07060504, lo: 0x03020100 }, 0);
    siphash.write(k1, { hi: 0x0F0E0D0C, lo: 0x0B0A0908 }, 0);
    siphash.write(data, { hi: 0x07060504, lo: 0x03020100 }, 0);
    // be:
    // assert.equal(siphash(k0, k1, data).toString('hex'), '93f5f5799a932462');
    // le:
    assert.equal(siphash(data, k0, k1).toString('hex'), '6224939a79f5f593');
  });

  it('should perform siphash with uint256', function() {
    var k0 = new Buffer(8);
    var k1 = new Buffer(8);
    siphash.write(k0, { hi: 0x07060504, lo: 0x03020100 }, 0);
    siphash.write(k1, { hi: 0x0F0E0D0C, lo: 0x0B0A0908 }, 0);
    var hash = new Buffer('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
    // be:
    // assert.equal(siphash(k0, k1, hash).toString('hex'), '7127512f72f27cce');
    // le:
    assert.equal(siphash(hash, k0, k1).toString('hex'), 'ce7cf2722f512771');
  });
});
