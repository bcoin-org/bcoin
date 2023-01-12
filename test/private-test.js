/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');
const sinon = require('sinon');

describe('HDPrivateKey', function() {
  it('should construct the object using options', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

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
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

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
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const val = hdprivatekey.xpubkey('main');

    assert.strictEqual(val.startsWith('xpub'), true);
    assert.strictEqual(val.length, 111);
  });

  it('should not call destroy on the internal hdPublicKey when destroy() is called', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

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
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

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
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());
    const common = require('../lib/hd/common');

    const account = {};
    const spy = sinon.spy(common, 'isAccount');

    hdprivatekey.isAccount(account);

    sinon.assert.calledOnce(spy);
  });

  it('should return false for isBase58() when first param is not a string', () => {
    assert.strictEqual(HDPrivateKey.isBase58([], 'main'), false);
  });

  it('should return false for isBase58() when first param has length less than 4', () => {
    assert.strictEqual(HDPrivateKey.isBase58('xpu', 'main'), false);
  });

  it('should return true from isBase58() when data is valid', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPrivate58');
    assert.strictEqual(HDPrivateKey.isBase58('xpubABC123', 'main'), true);
    stub.restore();
  });

  it('should return false from isBase58() if Network.fromPrivate58() throws an error', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPrivate58').throws();
    assert.strictEqual(HDPrivateKey.isBase58('xpubABC123', 'main'), false);
    stub.restore();
  });

  it('should return true from isValidPath() when path is valid', () => {
    assert.strictEqual(HDPrivateKey.isValidPath('m/0/0'), true);
  });

  it('should return false from isValidPath() when path is invalid', () => {
    assert.strictEqual(HDPrivateKey.isValidPath('this_is_not_a_path'), false);
  });

  it('should return false from isRaw() when first param is not a buffer', () => {
    assert.strictEqual(HDPrivateKey.isRaw([], 'main'), false);
  });

  it('should return false from isRaw() when first param has length less than 4', () => {
    assert.strictEqual(HDPrivateKey.isRaw(Buffer.from('xpu'), 'main'), false);
  });

  it('should return true from isRaw() when data is valid', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPrivate');
    assert.strictEqual(HDPrivateKey.isRaw(Buffer.from('xpubABC123'), 'main'), true);
    stub.restore();
  });

  it('should return false from isRaw() if Network.fromPrivate() throws an error', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPrivate').throws();
    assert.strictEqual(HDPrivateKey.isRaw(Buffer.from('xpubABC123'), 'main'), false);
    stub.restore();
  });

  it('should throw assertion error from equals() when first param is not an HDPrivateKey', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    assert.throws(() => {
      hdprivatekey.equals('not an HDPrivateKey');
    }, assert.AssertionError);
  });

  it('should return true from equals() when first param is an HDPrivateKey', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());
    assert.strictEqual(hdprivatekey.equals(hdprivatekey), true);
  });

  it('should throw an assertion error from compare() when first param is not an HDPrivateKey', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    assert.throws(() => {
      hdprivatekey.compare('not an HDPrivateKey');
    }, assert.AssertionError);
  });

  it('should return 0 from compare if the passed in key is equal', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);

    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2), 0);
  });

  it('should return a negative value from compare if the passed in key has a depth greater than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    hdprivatekey2.depth = hdprivatekey2.depth + randomNumber;

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a depth less than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    hdprivatekey2.depth = hdprivatekey2.depth - randomNumber;

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a parent fingerprint greater than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    hdprivatekey2.parentFingerPrint = hdprivatekey2.parentFingerPrint + randomNumber;

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a parent fingerprint less than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    hdprivatekey2.parentFingerPrint = hdprivatekey2.parentFingerPrint - randomNumber;

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a child index greater than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    hdprivatekey2.childIndex = hdprivatekey2.childIndex + randomNumber;

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a child index less than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    hdprivatekey2.childIndex = hdprivatekey2.childIndex - randomNumber;

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a chain code greater than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    hdprivatekey.chainCode = {
      compare: (chainCode) => {
        return -1;
      }
    };

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a chain code less than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    hdprivatekey.chainCode = {
      compare: (chainCode) => {
        return 1;
      }
    };

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a private key greater than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    hdprivatekey.privateKey = {
      compare: (key) => {
        return -1;
      }
    };

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a private key less than the original key', () => {
    const mnemonic = new Mnemonic();
    const phrase = mnemonic.getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    hdprivatekey.privateKey = {
      compare: (key) => {
        return 1;
      }
    };

    assert.strictEqual(hdprivatekey.compare(hdprivatekey2) > 0, true);
  });

  it('should throw an error if seed length * 8 is less than common.MIN_ENTROPY', () => {
    const common = require('../lib/hd/common');
    const seed = Buffer.alloc(common.MIN_ENTROPY / 8 - 1);

    try {
      HDPrivateKey.fromSeed(seed);
      assert(false, 'Expected an error');
    } catch (err) {
      assert(err);
    }
  });

  it('should throw an error if seed length * 8 is greater than common.MAX_ENTROPY', () => {
    const common = require('../lib/hd/common');
    const seed = Buffer.alloc(common.MAX_ENTROPY / 8 + 1);
    try {
      HDPrivateKey.fromSeed(seed);
      assert(false, 'Expected an error');
    } catch (err) {
      assert(err);
    }
  });

  it('should throw an error during fromSeed() if privateKeyVerify returns false', () => {
    const secp256k1 = require('bcrypto/lib/secp256k1');
    const stub = sinon.stub(secp256k1, 'privateKeyVerify').returns(false);
    const seed = Buffer.alloc(32);

    try {
      HDPrivateKey.fromSeed(seed);
      assert(false, 'Expected an error');
    } catch (err) {
      assert(err);
    }

    stub.restore();
  });

  it('should not throw an error during fromSeed() if privateKeyVerify returns true', () => {
    const secp256k1 = require('bcrypto/lib/secp256k1');
    const stub = sinon.stub(secp256k1, 'privateKeyVerify').returns(true);
    const seed = Buffer.alloc(32);

    try {
      HDPrivateKey.fromSeed(seed);
    } catch (err) {
      assert(false, 'Aargh! An error!');
    }

    stub.restore();
  });

  it('should return 82 from getSize()', () => {
    const hdprivatekey = new HDPrivateKey();
    assert.strictEqual(hdprivatekey.getSize(), 82);
  });

  it('should return a valid object from the static fromReader method', () => {
    const hdprivatekey = new HDPrivateKey();
    const secp256k1 = require('bcrypto/lib/secp256k1');
    const stub = sinon.stub(secp256k1, 'publicKeyCreate').returns(hdprivatekey._hdPublicKey);

    const br = require('bufio').read(hdprivatekey.toRaw('main'));

    const hdprivatekey2 = HDPrivateKey.fromReader(br, 'main');
    assert(hdprivatekey2 instanceof HDPrivateKey);
    stub.restore();
  });

  it('should return a valid object from the static fromRaw method', () => {
    const hdprivatekey = new HDPrivateKey();
    const secp256k1 = require('bcrypto/lib/secp256k1');
    const stub = sinon.stub(secp256k1, 'publicKeyCreate').returns(hdprivatekey._hdPublicKey);
    const hdprivatekey2 = HDPrivateKey.fromRaw(hdprivatekey.toRaw('main'), 'main');
    assert(hdprivatekey2 instanceof HDPrivateKey);
    stub.restore();
  });

  it('should throw an error from derive() if index out of range', () => {
    const hdprivatekey = new HDPrivateKey();
    try {
      hdprivatekey.derive(0xFFFFFFFF + 1);
      assert(false, 'Expected an error');
    } catch (err) {
      assert(err);
    }
  });

  it('should throw an error from derive() if depth too high', () => {
    const hdprivatekey = new HDPrivateKey();
    hdprivatekey.depth = 255;
    try {
      hdprivatekey.derive(0);
      assert(false, 'Expected an error');
    } catch (err) {
      assert(err);
    }
  });

  it('should recursively call derive() with a higher index if privateKeyTweakAdd throws an exception', () => {
    let phrase = new Mnemonic().getPhrase();
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase);

    phrase = new Mnemonic().getPhrase();
    const hdprivatekey2 = HDPrivateKey.fromPhrase(phrase);

    const secp256k1 = require('bcrypto/lib/secp256k1');
    const stub = sinon.stub(secp256k1, 'privateKeyTweakAdd').throws(new Error('test'));
    const stub2a = sinon.stub(hdprivatekey, 'derive').withArgs(0).callThrough().withArgs(1).returns(hdprivatekey2);

    const hdprivatekey3 = hdprivatekey.derive(0);
    assert(hdprivatekey3.privateKey.compare(hdprivatekey2.privateKey) === 0);

    stub.restore();
  });
});
