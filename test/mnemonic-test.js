'use strict';

const assert = require('assert');
const HD = require('../lib/hd');

const mnemonic1 = require('./data/mnemonic1').english;
const mnemonic2 = require('./data/mnemonic2');

describe('Mnemonic', function() {
  mnemonic1.forEach((data, i) => {
    let entropy = Buffer.from(data[0], 'hex');
    let phrase = data[1];
    let seed = Buffer.from(data[2], 'hex');
    let xpriv = data[3];
    it('should create an english mnemonic (' + i + ')', () => {
      let mnemonic, key;

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

  mnemonic2.forEach((data, i) => {
    let entropy = Buffer.from(data.entropy, 'hex');
    let phrase = data.mnemonic;
    let seed = Buffer.from(data.seed, 'hex');
    let passphrase = data.passphrase;
    let xpriv = data.bip32_xprv;
    it('should create a japanese mnemonic (' + i + ')', () => {
      let mnemonic, key;

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

  it('should verify phrase', () => {
    let m1 = new HD.Mnemonic();
    let m2 = HD.Mnemonic.fromPhrase(m1.getPhrase());
    assert.deepEqual(m2.getEntropy(), m1.getEntropy());
    assert.equal(m2.bits, m1.bits);
    assert.equal(m2.language, m1.language);
    assert.deepEqual(m2.toSeed(), m1.toSeed());
  });
});
