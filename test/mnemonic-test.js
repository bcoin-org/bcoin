/* eslint-env mocha */

'use strict';

const assert = require('assert');
const HD = require('../lib/hd');

const mnemonic1 = require('./data/mnemonic1').english;
const mnemonic2 = require('./data/mnemonic2');

describe('Mnemonic', function() {
  mnemonic1.forEach((data, i) => {
    const entropy = Buffer.from(data[0], 'hex');
    const phrase = data[1];
    const seed = Buffer.from(data[2], 'hex');
    const xpriv = data[3];
    it(`should create an english mnemonic (${i})`, () => {
      const mnemonic = new HD.Mnemonic({
        language: 'english',
        entropy: entropy,
        passphrase: 'TREZOR'
      });

      assert.equal(mnemonic.getPhrase(), phrase);
      assert.equal(mnemonic.toSeed().toString('hex'), seed.toString('hex'));

      const key = HD.fromMnemonic(mnemonic);
      assert.equal(key.toBase58(), xpriv);
    });
  });

  mnemonic2.forEach((data, i) => {
    const entropy = Buffer.from(data.entropy, 'hex');
    const phrase = data.mnemonic;
    const seed = Buffer.from(data.seed, 'hex');
    const passphrase = data.passphrase;
    const xpriv = data.bip32_xprv;
    it(`should create a japanese mnemonic (${i})`, () => {
      const mnemonic = new HD.Mnemonic({
        language: 'japanese',
        entropy: entropy,
        passphrase: passphrase
      });

      assert.equal(mnemonic.getPhrase(), phrase);
      assert.equal(mnemonic.toSeed().toString('hex'), seed.toString('hex'));

      const key = HD.fromMnemonic(mnemonic);
      assert.equal(key.toBase58(), xpriv);
    });
  });

  it('should verify phrase', () => {
    const m1 = new HD.Mnemonic();
    const m2 = HD.Mnemonic.fromPhrase(m1.getPhrase());
    assert.deepEqual(m2.getEntropy(), m1.getEntropy());
    assert.equal(m2.bits, m1.bits);
    assert.equal(m2.language, m1.language);
    assert.deepEqual(m2.toSeed(), m1.toSeed());
  });
});
