'use strict';

var assert = require('assert');
var HD = require('../lib/hd');

var mnemonic1 = require('./data/mnemonic1').english;
var mnemonic2 = require('./data/mnemonic2');

describe('Mnemonic', function() {
  mnemonic1.forEach(function(data, i) {
    var entropy = new Buffer(data[0], 'hex');
    var phrase = data[1];
    var seed = new Buffer(data[2], 'hex');
    var xpriv = data[3];
    it('should create an english mnemonic (' + i + ')', function() {
      var mnemonic, key;

      mnemonic = new HD.Mnemonic({
        language: 'english',
        entropy: entropy,
        passphrase: 'TREZOR'
      });

      assert.equal(mnemonic.getPhrase(), phrase);
      assert.equal(mnemonic.toSeed().toString('hex'), seed.toString('hex'));

      key = HD.fromMnemonic(mnemonic);
      assert.equal(key.toBase58(), xpriv);
    });
  });

  mnemonic2.forEach(function(data, i) {
    var entropy = new Buffer(data.entropy, 'hex');
    var phrase = data.mnemonic;
    var seed = new Buffer(data.seed, 'hex');
    var passphrase = data.passphrase;
    var xpriv = data.bip32_xprv;
    it('should create a japanese mnemonic (' + i + ')', function() {
      var mnemonic, key;

      mnemonic = new HD.Mnemonic({
        language: 'japanese',
        entropy: entropy,
        passphrase: passphrase
      });

      assert.equal(mnemonic.getPhrase(), phrase);
      assert.equal(mnemonic.toSeed().toString('hex'), seed.toString('hex'));

      key = HD.fromMnemonic(mnemonic);
      assert.equal(key.toBase58(), xpriv);
    });
  });

  it('should verify phrase', function() {
    var m1 = new HD.Mnemonic();
    var m2 = HD.Mnemonic.fromPhrase(m1.getPhrase());
    assert.deepEqual(m2.getEntropy(), m1.getEntropy());
    assert.equal(m2.bits, m1.bits);
    assert.equal(m2.language, m1.language);
    assert.deepEqual(m2.toSeed(), m1.toSeed());
  });
});
