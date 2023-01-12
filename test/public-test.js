/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');
const HDPublicKey = require('../lib/hd/public');
const sinon = require('sinon');

describe('public-test', function() {
  const getOptions = (phrase) => {
    const hdprivatekey = HDPrivateKey.fromPhrase(phrase || new Mnemonic().getPhrase());

    return {
      depth: hdprivatekey.depth,
      parentFingerPrint: hdprivatekey.parentFingerPrint,
      childIndex: hdprivatekey.childIndex,
      chainCode: hdprivatekey.chainCode,
      publicKey: hdprivatekey.publicKey
    };
  };

  it('should generate from options correctly', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = new HDPublicKey(options);

    assert.strictEqual(publicKey.depth, options.depth);
    assert.strictEqual(publicKey.parentFingerPrint, options.parentFingerPrint);
    assert.strictEqual(publicKey.childIndex, options.childIndex);
    assert.strictEqual(publicKey.chainCode, options.chainCode);
    assert.strictEqual(publicKey.publicKey.compare(options.publicKey), 0);
  });

  it('should generate when static fromOptions is called', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);

    assert.strictEqual(publicKey.depth, options.depth);
    assert.strictEqual(publicKey.parentFingerPrint, options.parentFingerPrint);
    assert.strictEqual(publicKey.childIndex, options.childIndex);
    assert.strictEqual(publicKey.chainCode, options.chainCode);
    assert.strictEqual(publicKey.publicKey.compare(options.publicKey), 0);
  });

  it('should return this from toPublic', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = publicKey.toPublic();

    assert.strictEqual(publicKey, publicKey2);
  });

  it('should return null from xprivkey', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const xprivkey = publicKey.xprivkey('main');

    assert.strictEqual(xprivkey, null);
  });

  it('should reset all properties when you call destroy', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);

    publicKey.destroy();

    assert.strictEqual(publicKey.depth, 0);
    assert.strictEqual(publicKey.parentFingerPrint, 0);
    assert.strictEqual(publicKey.fingerPrint, -1);
    assert.strictEqual(publicKey.childIndex, 0);

    // assert that chainCode is a zeroed out buffer of 32 bytes
    assert.strictEqual(publicKey.chainCode.length, 32);
    assert.strictEqual(publicKey.chainCode.toString('hex'), '0000000000000000000000000000000000000000000000000000000000000000');

    // assert that publicKey is a zeroed out buffer of 33 bytes
    assert.strictEqual(publicKey.publicKey.length, 33);
    assert.strictEqual(publicKey.publicKey.toString('hex'), '000000000000000000000000000000000000000000000000000000000000000000');
  });

  it('should throw an error if derive() is called with an index that is out of range', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);

    assert.throws(() => {
      publicKey.derive(-1);
    }, Error);
  });

  it('should throw an error if derive() is called with an index where index & Common.HARDENED is true', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);

    assert.throws(() => {
      publicKey.derive(0x80000000);
    }, Error);
  });

  it('should throw an error if derive() is called with an index where index & Common.HARDENED is false, but hardened param is true', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);

    assert.throws(() => {
      publicKey.derive(0, true);
    }, Error);
  });

  it('should throw an error if derive() is called with a depth that is too high', () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);

    assert.throws(() => {
      publicKey.depth = 256;
      publicKey.derive(0, false);
    }, Error);
  });

  it('should recursively call derive() with a higher index if privateKeyTweakAdd throws an exception', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());
    const publicKey2 = HDPublicKey.fromOptions(getOptions(new Mnemonic().getPhrase()));

    const secp256k1 = require('bcrypto/lib/secp256k1');
    const stub = sinon.stub(secp256k1, 'publicKeyTweakAdd').throws(new Error('test'));
    sinon.stub(publicKey, 'derive').withArgs(0).callThrough().withArgs(1).returns(publicKey2);

    const publicKey3 = publicKey.derive(0);
    assert(publicKey3.compare(publicKey2) === 0);

    stub.restore();
  });

  it('should fail assertion if deriveAccount() is called and isAccount() is false', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    // mock common.isAccount() to return false
    const common = require('../lib/hd/common');
    const stub = sinon.stub(common, 'isAccount').returns(false);

    assert.throws(() => {
      publicKey.deriveAccount(1, 2, 3);
    }, Error);

    stub.restore();
  });

  it('should not fail assertion if deriveAccount() is called and isAccount() is true', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    // mock common.isAccount() to return true
    const common = require('../lib/hd/common');
    const stub = sinon.stub(common, 'isAccount').returns(true);

    assert.doesNotThrow(() => {
      publicKey.deriveAccount(1, 2, 3);
    });

    stub.restore();
  });

  it('should return true for isMaster when common.isMaster() returns true', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    const common = require('../lib/hd/common');
    const stub = sinon.stub(common, 'isMaster').returns(true);

    assert(publicKey.isMaster());

    stub.restore();
  });

  it('should return false for isMaster when common.isMaster() returns false', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    const common = require('../lib/hd/common');
    const stub = sinon.stub(common, 'isMaster').returns(false);

    assert(!publicKey.isMaster());

    stub.restore();
  });
});
