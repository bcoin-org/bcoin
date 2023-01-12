/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Mnemonic = require('../lib/hd/mnemonic');
const HDPrivateKey = require('../lib/hd/private');
const HDPublicKey = require('../lib/hd/public');

describe('public-test', function() {
  const getOptions = () => {
    const hdprivatekey = HDPrivateKey.fromPhrase(new Mnemonic().getPhrase());

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
});
