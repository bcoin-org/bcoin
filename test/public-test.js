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
    const stub2 = sinon.stub(publicKey, 'derive');
    stub2.withArgs(0).callThrough().withArgs(1).returns(publicKey2);

    const publicKey3 = publicKey.derive(0);
    assert(publicKey3.compare(publicKey2) === 0);

    stub.restore();
    stub2.restore();
  });

  it('should fail assertion if deriveAccount() is called and isAccount() is false', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    // mock common.isAccount() to return false
    const common = require('../lib/hd/common');

    if (common.isAccount.hasOwnProperty('restore'))
      common.isAccount.restore();

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

    if (common.isAccount.hasOwnProperty('restore'))
      common.isAccount.restore();

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

  it('should return true from isValidPath() when path is valid', () => {
    assert.strictEqual(HDPublicKey.isValidPath('m/0/0'), true);
  });

  it('should return false from isValidPath() when path is invalid', () => {
    assert.strictEqual(HDPublicKey.isValidPath('this_is_not_a_path'), false);
  });

  it('should return false from isRaw() when first param is not a buffer', () => {
    assert.strictEqual(HDPublicKey.isRaw([], 'main'), false);
  });

  it('should return false from isRaw() when first param has length less than 4', () => {
    assert.strictEqual(HDPublicKey.isRaw(Buffer.from('xpu'), 'main'), false);
  });

  it('should return true from isRaw() when data is valid', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPublic');
    assert.strictEqual(HDPublicKey.isRaw(Buffer.from('xpubABC123'), 'main'), true);
    stub.restore();
  });

  it('should return false from isRaw() if Network.fromPrivate() throws an error', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPublic').throws();
    assert.strictEqual(HDPublicKey.isRaw(Buffer.from('xpubABC123'), 'main'), false);
    stub.restore();
  });

  it('should return false for isBase58() when first param is not a string', () => {
    assert.strictEqual(HDPublicKey.isBase58([], 'main'), false);
  });

  it('should return false for isBase58() when first param has length less than 4', () => {
    assert.strictEqual(HDPublicKey.isBase58('xpu', 'main'), false);
  });

  it('should return true from isBase58() when data is valid', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPublic58');
    assert.strictEqual(HDPublicKey.isBase58('xpubABC123', 'main'), true);
    stub.restore();
  });

  it('should return false from isBase58() if Network.fromPrivate58() throws an error', () => {
    const Network = require('../lib/protocol/network');
    const stub = sinon.stub(Network, 'fromPublic58').throws();
    assert.strictEqual(HDPublicKey.isBase58('xpubABC123', 'main'), false);
    stub.restore();
  });

  it('should throw an assertion error from compare() when first param is not an HDPublicKey', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    assert.throws(() => {
      publicKey.compare('not an HDPublicKey');
    }, assert.AssertionError);
  });

  it('should return 0 from compare if the passed in key is equal', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    assert.strictEqual(publicKey.compare(publicKey2), 0);
  });

  it('should return a negative value from compare if the passed in key has a depth greater than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    publicKey2.depth = publicKey2.depth + randomNumber;

    assert.strictEqual(publicKey.compare(publicKey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a depth less than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    publicKey2.depth = publicKey2.depth - randomNumber;

    assert.strictEqual(publicKey.compare(publicKey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a parent fingerprint greater than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    publicKey2.parentFingerPrint = publicKey2.parentFingerPrint + randomNumber;

    assert.strictEqual(publicKey.compare(publicKey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a parent fingerprint less than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    publicKey2.parentFingerPrint = publicKey2.parentFingerPrint - randomNumber;

    assert.strictEqual(publicKey.compare(publicKey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a child index greater than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    publicKey2.childIndex = publicKey2.childIndex + randomNumber;

    assert.strictEqual(publicKey.compare(publicKey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a child index less than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    // Random number from 1 to 10
    const randomNumber = Math.floor(Math.random() * 10) + 1;
    publicKey2.childIndex = publicKey2.childIndex - randomNumber;

    assert.strictEqual(publicKey.compare(publicKey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a chain code greater than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.chainCode = {
      compare: (chainCode) => {
        return -1;
      }
    };

    assert.strictEqual(publicKey.compare(publicKey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a chain code less than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.chainCode = {
      compare: (chainCode) => {
        return 1;
      }
    };

    assert.strictEqual(publicKey.compare(publicKey2) > 0, true);
  });

  it('should return a negative value from compare if the passed in key has a private key greater than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.publicKey = {
      compare: (publicKey) => {
        return -1;
      }
    };

    assert.strictEqual(publicKey.compare(publicKey2) < 0, true);
  });

  it('should return a positive value from compare if the passed in key has a private key less than the original key', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.publicKey = {
      compare: (publicKey) => {
        return 1;
      }
    };

    assert.strictEqual(publicKey.compare(publicKey2) > 0, true);
  });

  it('should return 82 for getSize() for a public key', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());
    assert.strictEqual(publicKey.getSize(), 82);
  });

  it('should return a valid object from the static fromReader method', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());
    const br = require('bufio').read(publicKey.toRaw('main'));

    const publicKey2 = HDPublicKey.fromReader(br, 'main');

    assert(publicKey2 instanceof HDPublicKey);
    assert.strictEqual(publicKey2.version, publicKey.version);
    assert.strictEqual(publicKey2.depth, publicKey.depth);
    assert.strictEqual(publicKey2.parentFingerPrint, publicKey.parentFingerPrint);
    assert.strictEqual(publicKey2.childIndex, publicKey.childIndex);
    assert.strictEqual(publicKey2.chainCode.toString('hex'), publicKey.chainCode.toString('hex'));
    assert.strictEqual(publicKey2.publicKey.toString('hex'), publicKey.publicKey.toString('hex'));
  });

  it('should return a valid object from the static fromRaw method', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    const publicKey2 = HDPublicKey.fromRaw(publicKey.toRaw('main'), 'main');

    assert(publicKey2 instanceof HDPublicKey);
    assert.strictEqual(publicKey2.version, publicKey.version);
    assert.strictEqual(publicKey2.depth, publicKey.depth);
    assert.strictEqual(publicKey2.parentFingerPrint, publicKey.parentFingerPrint);
    assert.strictEqual(publicKey2.childIndex, publicKey.childIndex);
    assert.strictEqual(publicKey2.chainCode.toString('hex'), publicKey.chainCode.toString('hex'));
    assert.strictEqual(publicKey2.publicKey.toString('hex'), publicKey.publicKey.toString('hex'));
  });

  it('should return a valid json object from the toJSON method', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    const json = publicKey.toJSON();

    assert.strictEqual(json.xpubkey, publicKey.xpubkey('main'));
  });

  it('should create a valid object from the static fromJSON method', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    const json = publicKey.toJSON();

    const publicKey2 = HDPublicKey.fromJSON(json);

    assert(publicKey2 instanceof HDPublicKey);
    assert.strictEqual(publicKey2.version, publicKey.version);
    assert.strictEqual(publicKey2.depth, publicKey.depth);
    assert.strictEqual(publicKey2.parentFingerPrint, publicKey.parentFingerPrint);
    assert.strictEqual(publicKey2.childIndex, publicKey.childIndex);
    assert.strictEqual(publicKey2.chainCode.toString('hex'), publicKey.chainCode.toString('hex'));
    assert.strictEqual(publicKey2.publicKey.toString('hex'), publicKey.publicKey.toString('hex'));
  });

  it('should return a valid object from the instance fromJSON method', () => {
    const publicKey = HDPublicKey.fromOptions(getOptions());

    const json = publicKey.toJSON();

    const publicKey2 = new HDPublicKey();

    publicKey2.fromJSON(json);

    assert(publicKey2 instanceof HDPublicKey);
    assert.strictEqual(publicKey2.version, publicKey.version);
    assert.strictEqual(publicKey2.depth, publicKey.depth);
    assert.strictEqual(publicKey2.parentFingerPrint, publicKey.parentFingerPrint);
    assert.strictEqual(publicKey2.childIndex, publicKey.childIndex);
    assert.strictEqual(publicKey2.chainCode.toString('hex'), publicKey.chainCode.toString('hex'));
    assert.strictEqual(publicKey2.publicKey.toString('hex'), publicKey.publicKey.toString('hex'));
  });

  it('should return false from equals() if the depth does not match', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.depth = 1;

    assert.strictEqual(publicKey.equals(publicKey2), false);
  });

  it('should return false from equals() if the parentFingerPrint does not match', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.parentFingerPrint = 1;

    assert.strictEqual(publicKey.equals(publicKey2), false);
  });

  it('should return false from equals() if the child index does not match', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.childIndex = 1;

    assert.strictEqual(publicKey.equals(publicKey2), false);
  });

  it('should return false from equals() if the chain code does not match', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.chainCode = Buffer.alloc(32, 0x01);

    assert.strictEqual(publicKey.equals(publicKey2), false);
  });

  it('should return false from equals() if the public key does not match', () => {
    const options = getOptions();
    const publicKey = HDPublicKey.fromOptions(options);
    const publicKey2 = HDPublicKey.fromOptions(options);

    publicKey.publicKey = Buffer.alloc(33, 0x01);

    assert.strictEqual(publicKey.equals(publicKey2), false);
  });
});
