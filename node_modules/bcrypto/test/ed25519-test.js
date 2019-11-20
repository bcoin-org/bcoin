/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed25519 = require('../lib/ed25519');
const SHA512 = require('../lib/sha512');
const derivations = require('./data/ed25519.json');
const json = require('./data/ed25519-input.json');
const rfc8032 = require('./data/rfc8032-vectors.json');
const vectors = process.env.CI || ed25519.native ? json : json.slice(0, 128);

describe('EdDSA', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed25519.size);
    const secret = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(secret);

    assert(ed25519.publicKeyVerify(pub));

    const sig = ed25519.sign(msg, secret);
    assert(ed25519.verify(msg, sig, pub));

    sig[(Math.random() * sig.length) | 0] ^= 1;

    assert(!ed25519.verify(msg, sig, pub));

    assert.bufferEqual(
      ed25519.privateKeyImport(ed25519.privateKeyExport(secret)),
      secret);

    assert.bufferEqual(
      ed25519.privateKeyImportPKCS8(ed25519.privateKeyExportPKCS8(secret)),
      secret);

    assert.bufferEqual(
      ed25519.publicKeyImport(ed25519.publicKeyExport(pub)),
      pub);

    assert.bufferEqual(
      ed25519.publicKeyImportSPKI(ed25519.publicKeyExportSPKI(pub)),
      pub);
  });

  it('should disallow points at infinity', () => {
    // Fun fact about edwards curves: points
    // at infinity can actually be serialized.
    const msg = Buffer.from(
      '03d95e0b801ab94cfe723bc5243284a32b19a629b9cb36a8a46fcc000b6e7191',
      'hex');

    const sig = Buffer.from(''
      + '0100000000000000000000000000000000000000000000000000000000000000'
      + '0000000000000000000000000000000000000000000000000000000000000000'
      , 'hex');

    const pub = Buffer.from(
      'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
      'hex');

    assert(!ed25519.verify(msg, sig, pub));

    const inf = Buffer.from(
      '0100000000000000000000000000000000000000000000000000000000000000',
      'hex');

    assert(!ed25519.publicKeyVerify(inf));
    assert(!ed25519.verify(msg, sig, inf));
  });

  it('should do ECDH', () => {
    const alicePriv = ed25519.privateKeyGenerate();
    const alicePub = ed25519.publicKeyCreate(alicePriv);

    const bobPriv = ed25519.privateKeyGenerate();
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const bobSecret = ed25519.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const secret = aliceSecret;
    const xsecret = ed25519.publicKeyConvert(secret);
    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    assert.notBufferEqual(xsecret, secret);

    const xaliceSecret = ed25519.exchange(xbobPub, alicePriv);
    const xbobSecret = ed25519.exchange(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);
  });

  it('should do ECDH (with scalar)', () => {
    const aliceSeed = ed25519.privateKeyGenerate();
    const alicePriv = ed25519.privateKeyConvert(aliceSeed);
    const alicePub = ed25519.publicKeyFromScalar(alicePriv);

    assert.bufferEqual(alicePub, ed25519.publicKeyCreate(aliceSeed));

    const bobSeed = ed25519.privateKeyGenerate();
    const bobPriv = ed25519.privateKeyConvert(bobSeed);
    const bobPub = ed25519.publicKeyFromScalar(bobPriv);

    assert.bufferEqual(bobPub, ed25519.publicKeyCreate(bobSeed));

    const aliceSecret = ed25519.deriveWithScalar(bobPub, alicePriv);
    const bobSecret = ed25519.deriveWithScalar(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    const xaliceSecret = ed25519.exchangeWithScalar(xbobPub, alicePriv);
    const xbobSecret = ed25519.exchangeWithScalar(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xbobSecret);
  });

  it('should do ECDH (vector)', () => {
    const alicePriv = Buffer.from(
      '50ec6e55b18b882e06bdc12ff2f80f8f8fa68b04370b45439cf80b4e02610e1e',
      'hex');

    const bobPriv = Buffer.from(
      'c3fb48a8c4e961ab3edb799eea22ff1d07b803140734266748ea4c753dd3655d',
      'hex');

    const alicePub = ed25519.publicKeyCreate(alicePriv);
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const xsecret = Buffer.from(
      '4084c076e4ff79e8af71425c0c0b573057e9ebf36185ec8572ec161ddf6f2731',
      'hex');

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const xaliceSecret = ed25519.publicKeyConvert(aliceSecret);
    const bobSecret = ed25519.derive(alicePub, bobPriv);
    const xbobSecret = ed25519.publicKeyConvert(bobSecret);

    assert.notBufferEqual(aliceSecret, xsecret);
    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);

    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    const xaliceSecret2 = ed25519.exchange(xbobPub, alicePriv);
    const xbobSecret2 = ed25519.exchange(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret2, xsecret);
    assert.bufferEqual(xbobSecret2, xsecret);
  });

  it('should generate keypair and sign with additive tweak', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const child = ed25519.publicKeyTweakAdd(pub, tweak);
    const sig = ed25519.signTweakAdd(msg, key, tweak);

    assert(ed25519.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const childPriv = ed25519.scalarTweakAdd(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);
    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);
    assert(ed25519.verify(msg, sig2, child));

    const real = ed25519.scalarTweakAdd(ed25519.privateKeyConvert(key), Buffer.alloc(32, 0x00));
    const parent = ed25519.scalarTweakAdd(childPriv, ed25519.scalarNegate(tweak));
    assert.bufferEqual(parent, real);

    const tweakPub = ed25519.publicKeyFromScalar(tweak);
    const parentPub = ed25519.publicKeyAdd(childPub, ed25519.publicKeyNegate(tweakPub));
    assert.bufferEqual(parentPub, pub);
  });

  it('should generate keypair and sign with additive tweak (vector)', () => {
    const key = Buffer.from(
      'd0e9d24169a720d5e3d07f71bf68802ba365be3e85c3c20f974a8dd3e0c97f79',
      'hex');

    const pub = Buffer.from(
      'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
      'hex');

    const tweak = Buffer.from(
      'fff3c02b12bf6670ada449160e3e586043766dcc7beb12e804cc375a4cd319ff',
      'hex');

    const msg = Buffer.from(
      '03d95e0b801ab94cfe723bc5243284a32b19a629b9cb36a8a46fcc000b6e7191',
      'hex');

    const childExpect = Buffer.from(
      '1098877517226435d2ac8021b47fc87b4b8a9d15f6a19431eae10a6576c21837',
      'hex');

    const sigExpect = Buffer.from(''
      + '493d2b108b8350405d08672e6b5c3c6f9a5501aa07d4a44d40ae7f4d781fb146'
      + '941b4d9e7ac7a70e8fbf466ef806d791b431e6c832b4ad1d7310f45d5545200a'
      , 'hex');

    const child = ed25519.publicKeyTweakAdd(pub, tweak);
    const sig = ed25519.signTweakAdd(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should generate keypair and sign with multiplicative tweak', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const child = ed25519.publicKeyTweakMul(pub, tweak);

    assert(ed25519.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const sig = ed25519.signTweakMul(msg, key, tweak);

    const childPriv = ed25519.scalarTweakMul(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);
    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);
    assert(ed25519.verify(msg, sig2, child));

    const real = ed25519.scalarTweakAdd(ed25519.privateKeyConvert(key), Buffer.alloc(32, 0x00));
    const parent = ed25519.scalarTweakMul(childPriv, ed25519.scalarInverse(tweak));
    assert.bufferEqual(parent, real);
  });

  it('should generate keypair and sign with multiplicative tweak (vector)', () => {
    const key = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const pub = Buffer.from(
      'f921f787e3e4e829a4be69a499f06e69d7bddbb7f6a90ccfba785faebd8d7a02',
      'hex');

    const tweak = Buffer.from(
      '7623971ec36c8557a8b1debe80f5f305989d0e51b62805c88590ee5b586a648a',
      'hex');

    const msg = Buffer.from(
      'e4a733e761eb1d0263fd713e7f815c947b29ed5a9140fa893bf59b11e1c32b80',
      'hex');

    const childExpect = Buffer.from(
      '78103d0a0342dca9a5044834f6dcf9472b8c1c3308fc4b49b13d451ddb7792f0',
      'hex');

    const sigExpect = Buffer.from(''
      + '4d1fa52a9dada415d4fff323257cfbdbaa571164873bcbd3e88acbe0a12d7e46'
      + 'e8b45144ed4ef9db77ac7e453e78aa4cd038f189bcff20d62de3339f80e51c01'
      , 'hex');

    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const sig = ed25519.signTweakMul(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak_ = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const tweak = ed25519.scalarTweakMul(tweak_, ed25519.cofactor);
    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const child_ = ed25519.publicKeyTweakMul(
      ed25519.publicKeyTweakMul(pub, tweak_),
      ed25519.cofactor);

    assert.bufferEqual(child, child_);
    assert(ed25519.scalarVerify(tweak_));
    assert.notBufferEqual(child, pub);

    const sig = ed25519.signTweakMul(msg, key, tweak);

    const childPriv = ed25519.scalarTweakMul(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);
    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);
    assert(ed25519.verify(msg, sig2, child));
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor (vector)', () => {
    const key = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const pub = Buffer.from(
      'f921f787e3e4e829a4be69a499f06e69d7bddbb7f6a90ccfba785faebd8d7a02',
      'hex');

    const tweak_ = Buffer.from(
      '7623971ec36c8557a8b1debe80f5f305989d0e51b62805c88590ee5b586a648a',
      'hex');

    const msg = Buffer.from(
      'e4a733e761eb1d0263fd713e7f815c947b29ed5a9140fa893bf59b11e1c32b80',
      'hex');

    const childExpect = Buffer.from(
      'c616988e326d0b8be64e028942c68db3bc2f0808d5ca7c2e8b041e12b7b133fa',
      'hex');

    const sigExpect = Buffer.from(''
      + 'b958f47421ddb4fa1d012ab40a9b0c6d3850c85acf5ba313ffe77dd9b212f8a9'
      + '84ae985e13f77a441c012c5f3b16735de3a94bd2e3e72c80be6b41bbe2338305'
      , 'hex');

    const tweak = ed25519.scalarTweakMul(tweak_, ed25519.cofactor);
    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const sig = ed25519.signTweakMul(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should convert to montgomery and back', () => {
    const secret = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(secret);
    const sign = (pub[31] & 0x80) !== 0;
    const xpub = ed25519.publicKeyConvert(pub);
    const pub2 = ed25519.publicKeyDeconvert(xpub, sign);

    assert.bufferEqual(pub2, pub);
  });

  describe('ed25519 derivations', () => {
    for (const [i, test] of derivations.entries()) {
      it(`should compute correct a and A for secret #${i}`, () => {
        const secret = Buffer.from(test.secret_hex, 'hex');
        const priv = ed25519.privateKeyConvert(secret);
        const pub = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub));

        assert.bufferEqual(priv, Buffer.from(test.a_hex, 'hex'));
        assert.bufferEqual(pub, Buffer.from(test.A_hex, 'hex'));
      });
    }
  });

  describe('sign.input ed25519 test vectors', () => {
    const batch = [];

    // https://ed25519.cr.yp.to/software.html
    for (const [i, [secret_, pub_, msg_, sig_]] of vectors.entries()) {
      const secret = Buffer.from(secret_, 'hex');
      const pub = Buffer.from(pub_, 'hex');
      const msg = Buffer.from(msg_, 'hex');
      const sig = Buffer.from(sig_, 'hex');

      batch.push([msg, sig, pub]);

      it(`should pass ed25519 vector #${i}`, () => {
        const pub_ = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub_));

        assert.bufferEqual(pub_, pub);

        const sig_ = ed25519.sign(msg, secret);

        assert.bufferEqual(sig_, sig);

        assert(ed25519.verify(msg, sig, pub));

        let forged = Buffer.from([0x78]); // ord('x')

        if (msg.length > 0) {
          forged = Buffer.from(msg);
          forged[forged.length - 1] += 1;
        }

        assert(!ed25519.verify(forged, sig, pub));
      });
    }

    it('should do batch verification', () => {
      assert.strictEqual(ed25519.batchVerify(batch), true);
    });
  });

  describe('RFC 8032 vectors', () => {
    for (const [i, vector] of rfc8032.entries()) {
      if (!vector.algorithm.startsWith('Ed25519'))
        continue;

      let ph = null;
      let ctx = null;

      if (vector.algorithm === 'Ed25519ph') {
        ph = true;
      } else if (vector.algorithm === 'Ed25519ctx') {
        ctx = Buffer.from(vector.ctx, 'hex');
        ph = false;
      }

      let msg = Buffer.from(vector.msg, 'hex');

      if (ph)
        msg = SHA512.digest(msg);

      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      it(`should pass RFC 8032 vector (${vector.algorithm} #${i})`, () => {
        assert(ed25519.privateKeyVerify(priv));
        assert(ed25519.publicKeyVerify(pub));

        const sig_ = ed25519.sign(msg, priv, ph, ctx);

        assert.bufferEqual(sig_, sig);

        assert(ed25519.verify(msg, sig, pub, ph, ctx));
        assert(!ed25519.verify(msg, sig, pub, !ph, ctx));

        if (msg.length > 0) {
          const msg_ = Buffer.from(msg);
          msg_[Math.random() * msg_.length | 0] ^= 1;
          assert(!ed25519.verify(msg_, sig, pub, ph, ctx));
        }

        {
          const sig_ = Buffer.from(sig);
          sig_[Math.random() * sig_.length | 0] ^= 1;
          assert(!ed25519.verify(msg, sig_, pub, ph, ctx));
        }

        {
          const pub_ = Buffer.from(pub);
          pub_[Math.random() * pub_.length | 0] ^= 1;
          assert(!ed25519.verify(msg, sig, pub_, ph, ctx));
        }

        if (ctx && ctx.length > 0) {
          const ctx_ = Buffer.from(ctx);
          ctx_[Math.random() * ctx_.length | 0] ^= 1;
          assert(!ed25519.verify(msg, sig, pub, ph, ctx_));
          assert(!ed25519.verify(msg, sig, pub, ph, null));
        } else {
          const ctx_ = Buffer.alloc(1);
          assert(!ed25519.verify(msg, sig, pub, true, ctx_));
          assert(!ed25519.verify(msg, sig, pub, false, ctx_));
        }
      });
    }
  });

  it('should test serialization formats', () => {
    const priv = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(priv);
    const rawPriv = ed25519.privateKeyExport(priv);
    const rawPub = ed25519.publicKeyExport(pub);

    assert.bufferEqual(ed25519.privateKeyImport(rawPriv), priv);
    assert.bufferEqual(ed25519.publicKeyImport(rawPub), pub);

    const jsonPriv = ed25519.privateKeyExportJWK(priv);
    const jsonPub = ed25519.publicKeyExportJWK(pub);

    assert.bufferEqual(ed25519.privateKeyImportJWK(jsonPriv), priv);
    assert.bufferEqual(ed25519.publicKeyImportJWK(jsonPub), pub);

    const asnPriv = ed25519.privateKeyExportPKCS8(priv);
    const asnPub = ed25519.publicKeyExportSPKI(pub);

    assert.bufferEqual(ed25519.privateKeyImportPKCS8(asnPriv), priv);
    assert.bufferEqual(ed25519.publicKeyImportSPKI(asnPub), pub);
  });
});
