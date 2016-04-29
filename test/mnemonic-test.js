var bn = require('bn.js');
var bcoin = require('../')();
var utils = bcoin.utils;
var assert = require('assert');
var mnemonic1 = require('./data/mnemonic1').english;
var mnemonic2 = require('./data/mnemonic2');

describe('Mnemonic', function() {
  mnemonic1.forEach(function(data, i) {
    var entropy = new Buffer(data[0], 'hex');
    var mnemonic = data[1];
    var seed = new Buffer(data[2], 'hex');
    var xpriv = data[3];
    it('should create an english mnemonic (' + i + ')', function() {
      var mnem = new bcoin.hd.mnemonic({
        passphrase: 'TREZOR',
        lang: 'english',
        entropy: entropy
      });
      mnem.toSeed();
      assert.equal(mnem.phrase, mnemonic);
      assert.equal(mnem.toSeed().toString('hex'), seed.toString('hex'));
      var key = bcoin.hd.fromSeed(mnem);
      assert.equal(key.xprivkey, xpriv);
    });
  });
  // Disabled for now
  return;
  mnemonic2.forEach(function(data, i) {
    var entropy = new Buffer(data.entropy, 'hex');
    var mnemonic = data.mnemonic;
    var seed = new Buffer(data.seed, 'hex');
    var xpriv = data.bip32_xprv;
    it('should create a japanese mnemonic (' + i + ')', function() {
      var mnem = new bcoin.hd.mnemonic({
        passphrase: 'メートルガバヴァぱばぐゞちぢ十人十色',
        lang: 'japanese',
        entropy: entropy
      });
      mnem.toSeed();
      assert.equal(mnem.phrase, mnemonic);
      assert.equal(mnem.toSeed().toString('hex'), seed.toString('hex'));
      var key = bcoin.hd.fromSeed(mnem);
      assert.equal(key.xprivkey, xpriv);
    });
  });
});
