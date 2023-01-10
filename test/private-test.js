/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');

describe('HDPrivateKey', function() {

  it('should construct the object using options', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);

    const options = {
      depth: hdprivatekey.depth,
      parentFingerPrint: hdprivatekey.parentFingerPrint,
      childIndex: hdprivatekey.childIndex,
      chainCode: hdprivatekey.chainCode,
      privateKey: hdprivatekey.privateKey,
      publicKey: hdprivatekey.publicKey
    };

    const hdpk2 = new HDPrivateKey(options);

    assert.strictEqual(hdpk2.depth, hdprivatekey.depth);
    assert.strictEqual(hdpk2.parentFingerPrint, hdprivatekey.parentFingerPrint);
    assert.strictEqual(hdpk2.childIndex, hdprivatekey.childIndex);
    assert.strictEqual(hdpk2.chainCode, hdprivatekey.chainCode);
    assert.strictEqual(hdpk2.privateKey.compare(hdprivatekey.privateKey), 0);
    assert.strictEqual(hdpk2.publicKey.compare(hdprivatekey.publicKey), 0);
  });

  it('should instantiate from options', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);

    const options = {
      depth: hdprivatekey.depth,
      parentFingerPrint: hdprivatekey.parentFingerPrint,
      childIndex: hdprivatekey.childIndex,
      chainCode: hdprivatekey.chainCode,
      privateKey: hdprivatekey.privateKey,
      publicKey: hdprivatekey.publicKey
    };

    const hdpk2 = HDPrivateKey.fromOptions(options);

    assert.strictEqual(hdpk2.depth, hdprivatekey.depth);
    assert.strictEqual(hdpk2.parentFingerPrint, hdprivatekey.parentFingerPrint);
    assert.strictEqual(hdpk2.childIndex, hdprivatekey.childIndex);
    assert.strictEqual(hdpk2.chainCode, hdprivatekey.chainCode);
    assert.strictEqual(hdpk2.privateKey.compare(hdprivatekey.privateKey), 0);
    assert.strictEqual(hdpk2.publicKey.compare(hdprivatekey.publicKey), 0);
  });

  it('should return valid key from xpubkey', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);

    let val = hdprivatekey.xpubkey('main');

    assert.strictEqual(val.startsWith('xpub'), true);
    assert.strictEqual(val.length, 111);
  });
});
