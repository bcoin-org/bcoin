/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');
const sinon = require('sinon');

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

    const val = hdprivatekey.xpubkey('main');

    assert.strictEqual(val.startsWith('xpub'), true);
    assert.strictEqual(val.length, 111);
  });

  it('should not call destroy on the internal hdPublicKey when destroy() is called', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);

    assert.strictEqual(hdprivatekey._hdPublicKey, null);

    let _calledDestroy = false;

    hdprivatekey._hdPublicKey = {
      destroy: () => {
        _calledDestroy = true;
      }
    };

    hdprivatekey.destroy();

    assert.strictEqual(_calledDestroy, false);
    assert.strictEqual(hdprivatekey._hdPublicKey, null);
  });

  it('should call destroy on the internal hdPublicKey when destroy(true) is called', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);

    assert.strictEqual(hdprivatekey._hdPublicKey, null);

    let _calledDestroy = false;

    hdprivatekey._hdPublicKey = {
      destroy: () => {
        _calledDestroy = true;
      }
    };

    hdprivatekey.destroy(true);

    assert.strictEqual(_calledDestroy, true);
    assert.strictEqual(hdprivatekey._hdPublicKey, null);
  });

  it('should call common.isAccount as expected', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const common = require('../lib/hd/common');

    const account = {}
    const spy = sinon.spy(common, 'isAccount');

    hdprivatekey.isAccount(account);

    sinon.assert.calledOnce(spy);
  });
});
