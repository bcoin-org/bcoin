'use strict';

const assert = require('bsert');
const p256 = require('../lib/p256');
const secp256k1 = require('../lib/secp256k1');
const random = require('../lib/random');
const vectors = require('./data/schnorr.json');

describe('Secp256k1+Schnorr', function() {
  const parsed = [];
  const valid = [];
  const invalid = [];

  // Parse test vectors.
  for (const [key_, pub_, msg_, sig_, result, comment_] of vectors) {
    const key = Buffer.from(key_, 'hex');
    const pub = Buffer.from(pub_, 'hex');
    const msg = Buffer.from(msg_, 'hex');
    const sig = Buffer.from(sig_, 'hex');
    const comment = comment_ || `should verify ${sig_.toLowerCase()}`;
    const batch = result ? valid : invalid;

    parsed.push([key, pub, msg, sig, result, comment]);
    batch.push([msg, sig, pub]);
  }

  for (const [key, pub, msg, sig, result, comment] of parsed) {
    it(comment, () => {
      if (key.length > 0) {
        assert(secp256k1.privateKeyVerify(key));
        assert.bufferEqual(secp256k1.publicKeyCreate(key), pub);
        assert.bufferEqual(secp256k1.schnorrSign(msg, key), sig);
      }

      assert.strictEqual(secp256k1.schnorrVerify(msg, sig, pub), result);
    });
  }

  it('should do batch verification', () => {
    assert.strictEqual(secp256k1.schnorrBatchVerify([]), true);
    assert.strictEqual(secp256k1.schnorrBatchVerify(valid), true);
  });

  it('should do fail batch verification', () => {
    for (const item of invalid) {
      assert.strictEqual(secp256k1.schnorrBatchVerify([item, ...valid]), false);
      assert.strictEqual(secp256k1.schnorrBatchVerify([...valid, item]), false);
    }
  });

  it('should handle uncompressed key properly', () => {
    // See: https://github.com/bcoin-org/bcrypto/issues/17
    const msg = Buffer.from(
      'cd3808fc5cbf9f2190d9b867b4498f234212984b8c879f296cf8e792b622a2f4',
      'hex');

    const sig = Buffer.from(''
      + '0df4be7f5fe74b2855b92082720e889038e15d8d747334fa3f300ef4ab1db1ee'
      + 'a56aa83d1d60809ff6703791736be87cfb6cbc5c4036aeed3b4ea4e6dab35090',
      'hex');

    const key = Buffer.from('04'
      + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
      + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
      'hex');

    assert.strictEqual(secp256k1.schnorrVerify(msg, sig, key), true);
    assert.strictEqual(secp256k1.schnorrBatchVerify([[msg, sig, key]]), true);
  });

  it('should be generalized for other curves', () => {
    if (!p256.schnorr)
      this.skip();

    const msg1 = Buffer.from(
      '3b3c4a629b78ca392e689526c445119ac9f27d7986e177764a1db2d9935f2832',
      'hex');

    const key1 = Buffer.from(
      '1bc2f148de5c165eb8b85d045e8dbe06ef576b38c656155259d4589dc5d87fd0',
      'hex');

    const pub1 = p256.publicKeyCreate(key1);
    const sig1 = p256.schnorr.sign(msg1, key1);

    const msg2 = p256.hash.digest(msg1);
    const key2 = p256.hash.digest(key1);
    const pub2 = p256.publicKeyCreate(key2);
    const sig2 = p256.schnorr.sign(msg2, key2);

    const batch = [
      [msg1, sig1, pub1],
      [msg2, sig2, pub2]
    ];

    assert.strictEqual(p256.schnorr.verify(...batch[0]), true);
    assert.strictEqual(p256.schnorr.verify(...batch[1]), true);
    assert.strictEqual(p256.schnorr.batchVerify(batch), true);
  });

  it('should verify some random signatures', () => {
    const batch = [];

    for (let i = 0; i < 10; i++) {
      const key = secp256k1.privateKeyGenerate();
      const pub = secp256k1.publicKeyCreate(key);
      const msg = random.randomBytes(32);
      const sig = secp256k1.schnorrSign(msg, key);

      assert(secp256k1.schnorrVerify(msg, sig, pub));

      batch.push([msg, sig, pub]);
    }

    assert(secp256k1.schnorrBatchVerify(batch));
  });
});
