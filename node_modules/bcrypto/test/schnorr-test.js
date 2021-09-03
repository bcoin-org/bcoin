'use strict';

const assert = require('bsert');
const schnorr = require('../lib/schnorr');
const secp256k1 = require('../lib/secp256k1');
const rng = require('../lib/random');
const vectors = require('./data/schnorr.json');

describe('Schnorr', function() {
  const valid = [];
  const invalid = [];

  for (const [key_, pub_, aux_, msg_, sig_, result, comment_] of vectors) {
    const key = Buffer.from(key_, 'hex');
    const pub = Buffer.from(pub_, 'hex');
    const aux = Buffer.from(aux_, 'hex');
    const msg = Buffer.from(msg_, 'hex');
    const sig = Buffer.from(sig_, 'hex');
    const text = sig_.slice(0, 32).toLowerCase() + '...';
    const comment = comment_ || `should verify ${text}`;
    const batch = result ? valid : invalid;

    batch.push([msg, sig, pub]);

    it(comment, () => {
      if (key.length > 0) {
        assert(schnorr.privateKeyVerify(key));
        assert.bufferEqual(schnorr.publicKeyCreate(key), pub);
        assert.bufferEqual(schnorr.sign(msg, key, aux), sig);
      }

      assert.strictEqual(schnorr.verify(msg, sig, pub), result);
    });
  }

  it('should do batch verification', () => {
    assert.strictEqual(schnorr.verifyBatch([]), true);
    assert.strictEqual(schnorr.verifyBatch(valid), true);

    for (const item of valid)
      assert.strictEqual(schnorr.verifyBatch([item]), true);
  });

  it('should do fail batch verification', () => {
    for (const item of invalid) {
      assert.strictEqual(schnorr.verifyBatch([item, ...valid]), false);
      assert.strictEqual(schnorr.verifyBatch([...valid, item]), false);
      assert.strictEqual(schnorr.verifyBatch([item]), false);
    }
  });

  it('should do HD derivation (additive)', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const tweak = rng.randomBytes(32);
    const cpriv = schnorr.privateKeyTweakAdd(priv, tweak);
    const cpub = schnorr.publicKeyTweakAdd(pub, tweak);

    assert.bufferEqual(schnorr.publicKeyCreate(cpriv), cpub);
  });

  it('should do HD derivation (multiplicative)', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const tweak = rng.randomBytes(32);
    const cpriv = schnorr.privateKeyTweakMul(priv, tweak);
    const cpub = schnorr.publicKeyTweakMul(pub, tweak);

    assert.bufferEqual(schnorr.publicKeyCreate(cpriv), cpub);
  });

  it('should convert key pair to ECDSA', () => {
    const priv = Buffer.from(
      'f7cbf630b0692ca8db4f85b9f8f0c7a5750be2ae6e57f1ea5dcc4b0a8280d8ac',
      'hex');

    const pub = Buffer.from(
      '99e47cdeb906a0474f255042a36e88b6de85e17f56f9efe070fe62b35ffb819b',
      'hex');

    const odd = Buffer.from([0x03]);

    // Should produce a point with odd Y.
    assert.bufferEqual(secp256k1.publicKeyCreate(priv),
                       Buffer.concat([odd, pub]));

    const jsonPriv = schnorr.privateKeyExport(priv);
    const jsonPub = schnorr.publicKeyExport(pub);
    const ecdsaPriv = secp256k1.privateKeyImport(jsonPriv);
    const ecdsaPub = secp256k1.publicKeyImport(jsonPub);

    // These calls must produce a sign-aware key pair such that G*a = A.
    assert.bufferEqual(secp256k1.publicKeyCreate(ecdsaPriv), ecdsaPub);

    // Private key is negated.
    assert.bufferEqual(ecdsaPriv,
      '083409cf4f96d35724b07a46070f385945a2fa3840f0ae51620613824db56895');

    // When normalized, the Y coordinate is even.
    assert.bufferEqual(ecdsaPub,
      '0299e47cdeb906a0474f255042a36e88b6de85e17f56f9efe070fe62b35ffb819b');

    // Should get our original privkey after negating.
    assert.bufferEqual(secp256k1.privateKeyNegate(ecdsaPriv), priv);

    // Should get our original pubkey.
    assert.bufferEqual(
      schnorr.publicKeyImport(secp256k1.publicKeyExport(ecdsaPub)), pub);

    // Basically a no-op.
    assert.bufferEqual(
      schnorr.privateKeyImport(secp256k1.privateKeyExport(ecdsaPriv)),
      ecdsaPriv);
  });

  it('should create point from uniform bytes (svdw)', () => {
    const preimages = [
      '9e37082b9af789b41c2ba96432f3f79f51d531521673f5175a54a061e2a11478',
      'e5289483991ee977b8e2484a4ac149959d0cdd17031e3178b09aef3cdcf7985b',
      'dce893a7bf082cfd41705a54f3655f41769cc460fc26491a4c293b2ffe6c33bf',
      'f2f1cd561fe906fa34858a5b3709d7fc716385f51ac405265e8fbd374db1feb1',
      'a95a64e37b3570836f8b812f4812f5d793e5830295c7498d0ca397589962b9e8',
      'fde160fe9ccdb26d7364ed20ff300d0cf275879ae2e47c2934d95e811658dcdb',
      '652787b609e5d62d8ebc36d6842a0dc4d3df282d079c5793f43652c7c334452a',
      '903b37385c8af3fd541a94497f2f9f3fba78af9123289b0d9124b55f75769a04',
      '0ce68e327210d93599ea8809cdd571792195c60f71ce78cb5b01f86125a70751',
      '5ad8fd744be966155b4b61fdd42bf3c865d91ceaf48767050c1af5199a99a35c',
      '0021ba1827fc5b25fc88688a5699922ed53bbe67affbd186d3cb8522addb2d26',
      'c4e9cda1b2cb90b1853daa9b890121f3dcb6fc04406ba35f274f4158cd7795d0',
      'e8409daf179f349fbac526e329b254c3156e5cd7d4ca79bcc0bf2f612d15ae6c',
      '085e7e426ae88df12e5284ca74f7137c9e96de77f6a1ae455d8029f28e88dd3d',
      '039dd4ccdbe06a46529a3d864d780a628f58561742602c6d0cf57b8ae45367b0',
      'db7ddd4d8ee09d5784dccab595a4629973b62b231e6e762e24edd0101568b5ce'
    ];

    const keys = [
      'daaa7ef2843538a98dda81b3ba1ba7286d2bd54c118be95f44658ef373f8110b',
      'bbd140c0a31994f23bdfdd87c59af34a8490415983d434f42981edbf83383f8f',
      '60d9735b8735394f72feebf38612652405b20b08d12876bf36a2a111eedb9572',
      '5b67e7e93701cbf25b5bc1b55e069fdbc65c39034aee0d8f74c0291a7972876d',
      'c0ecd02058427d00d5b98d547c2633f41cfdb3d9b54bf7ba2fee1b70fb421168',
      'c6b8abd785f0f7a456cd6bf163d80eeda3e8af1e70a09481099e9cbef4f12bcf',
      'a08e2771b6465a80876ead6003417221828c58d1eb1814230cd183614611a70f',
      '28b71ec0281f61d52c9e6354e1696828209fa2c9fc8562a511374c721fb7fee5',
      '1ba62579d23370e2a53c1137c7fdbc88a1d7919a8a3d805b27163aca53c0d19a',
      '5ca989025e4d256778b1c7463a78230e2f00b399f9fedce05d5e3bcf01f9e5dc',
      '682d934eb4b51cbaf826387f61ab3bcbf8a14d685efb57c3cd924d4381ac7fa7',
      'f0f3d7fc522e636ff5ee31ff46667646579dfa2ef7cf19895919d9e0319a31eb',
      'f78cf7978a03215d4b58dcb60a42d0f62b6939eb264ae97ee50f398b7785e032',
      '85f10de103b9afcc1bde65e9824bc393c6288c57294f614016591864122b283b',
      '2e16fda4a44781ae5513557d2ae27ec0e6ba851ea3e45d46c4cf2f581eb5ed94',
      '72735445a206eba746709ab0c0bbefb8c1a80141e28b797253b4ecdac054fcb9'
    ];

    for (let i = 0; i < 16; i++) {
      const preimage = Buffer.from(preimages[i], 'hex');
      const key = Buffer.from(keys[i], 'hex');

      assert.strictEqual(schnorr.publicKeyVerify(key), true);
      assert.bufferEqual(schnorr.publicKeyFromUniform(preimage), key);
    }
  });

  it('should invert elligator', () => {
    let priv, pub, bytes;

    for (;;) {
      priv = schnorr.privateKeyGenerate();
      pub = schnorr.publicKeyCreate(priv);

      try {
        bytes = schnorr.publicKeyToUniform(pub);
      } catch (e) {
        continue;
      }

      break;
    }

    const out = schnorr.publicKeyFromUniform(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should invert elligator squared', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const bytes = schnorr.publicKeyToHash(pub);
    const out = schnorr.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should test tweaking (1)', () => {
    for (let i = 0; i < 10; i++) {
      const priv = secp256k1.privateKeyGenerate();
      const pub = secp256k1.publicKeyCreate(priv);

      pub[0] = 0x02;

      const tweak = secp256k1.privateKeyGenerate();
      const result = secp256k1.publicKeyTweakAdd(pub, tweak);
      const negated = result[0] === 0x03;
      const xonly = pub.slice(1);
      const expect = result.slice(1);
      const yes = schnorr.publicKeyTweakCheck(xonly, tweak, expect, negated);

      assert.strictEqual(yes, true);

      const no = schnorr.publicKeyTweakCheck(xonly, tweak, expect, !negated);

      assert.strictEqual(no, false);
    }
  });

  it('should test tweaking (2)', () => {
    for (let i = 0; i < 10; i++) {
      const priv = schnorr.privateKeyGenerate();
      const pub = schnorr.publicKeyCreate(priv);
      const tweak = schnorr.privateKeyGenerate();
      const [expect, negated] = schnorr.publicKeyTweakSum(pub, tweak);
      const yes = schnorr.publicKeyTweakCheck(pub, tweak, expect, negated);

      assert.strictEqual(yes, true);

      const no = schnorr.publicKeyTweakCheck(pub, tweak, expect, !negated);

      assert.strictEqual(no, false);
    }
  });
});
