'use strict';

const assert = require('bsert');
const secp256k1 = require('../lib/secp256k1');
const vectors1 = require('./data/secp256k1-1.json'); // bcoin
const vectors2 = require('./data/secp256k1-2.json'); // hsd
const vectors3 = require('./data/secp256k1-3.json'); // script
const vectors4 = require('./data/secp256k1-4.json'); // tx

describe('Secp256k1', function() {
  for (const vectors of [vectors1, vectors2, vectors3, vectors4]) {
    for (const vector of vectors.public_key_create) {
      const key = Buffer.from(vector.key, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.key.slice(0, 32) + '...';

      it(`should create public key from private key: ${text}`, () => {
        assert.bufferEqual(secp256k1.publicKeyCreate(key, compress), result);
      });
    }

    for (const vector of vectors.public_key_convert) {
      const key = Buffer.from(vector.key, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.key.slice(0, 32) + '...';

      it(`should convert public key: ${text}`, () => {
        assert.bufferEqual(secp256k1.publicKeyConvert(key, compress), result);
      });
    }

    for (const vector of vectors.public_key_tweak_add) {
      const key = Buffer.from(vector.key, 'hex');
      const tweak = Buffer.from(vector.tweak, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.key.slice(0, 32) + '...';

      it(`should tweak public key: ${text}`, () => {
        assert.bufferEqual(
          secp256k1.publicKeyTweakAdd(key, tweak, compress),
          result);
      });
    }

    for (const vector of vectors.private_key_tweak_add) {
      const key = Buffer.from(vector.key, 'hex');
      const tweak = Buffer.from(vector.tweak, 'hex');
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.key.slice(0, 32) + '...';

      it(`should tweak private key: ${text}`, () => {
        assert.bufferEqual(secp256k1.privateKeyTweakAdd(key, tweak), result);
      });
    }

    for (const vector of vectors.derive) {
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.pub.slice(0, 32) + '...';

      it(`should perform ECDH: ${text}`, () => {
        assert.bufferEqual(secp256k1.derive(pub, priv, compress), result);
      });
    }

    for (const vector of vectors.public_key_verify) {
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;
      const text = vector.key.slice(0, 32) + '...';

      it(`should verify public key: ${text}`, () => {
        assert.strictEqual(secp256k1.publicKeyVerify(key), result);
      });
    }

    for (const vector of vectors.private_key_verify) {
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;
      const text = vector.key.slice(0, 32) + '...';

      it(`should verify private key: ${text}`, () => {
        assert.strictEqual(secp256k1.privateKeyVerify(key), result);
      });
    }

    for (const vector of vectors.verify) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;
      const text = vector.sig.slice(0, 32) + '...';

      it(`should verify R/S signature: ${text}`, () => {
        assert.strictEqual(secp256k1.verify(msg, sig, key), result);
      });
    }

    for (const vector of vectors.verify_der) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;
      const text = vector.sig.slice(0, 32) + '...';

      it(`should verify DER signature: ${text}`, () => {
        assert.strictEqual(secp256k1.verifyDER(msg, sig, key), result);
      });
    }

    for (const vector of vectors.recover) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const param = vector.param;
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.sig.slice(0, 32) + '...';

      it(`should recover key from R/S signature: ${text}`, () => {
        assert.bufferEqual(
          secp256k1.recover(msg, sig, param, compress),
          result);
      });
    }

    for (const vector of vectors.recover_der) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const param = vector.param;
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.sig.slice(0, 32) + '...';

      it(`should recover key from DER signature: ${text}`, () => {
        assert.bufferEqual(
          secp256k1.recoverDER(msg, sig, param, compress),
          result);
      });
    }

    for (const vector of vectors.from_der) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.sig.slice(0, 32) + '...';

      it(`should convert DER to R/S: ${text}`, () => {
        assert.bufferEqual(secp256k1.signatureImport(sig), result);
      });
    }

    for (const vector of vectors.to_der) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = Buffer.from(vector.result, 'hex');
      const text = vector.sig.slice(0, 32) + '...';

      it(`should convert R/S to DER: ${text}`, () => {
        assert.bufferEqual(secp256k1.signatureExport(sig), result);
      });
    }

    for (const vector of vectors.is_low_s) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = vector.result;
      const text = vector.sig.slice(0, 32) + '...';

      it(`should test S value (R/S): ${text}`, () => {
        assert.strictEqual(secp256k1.isLowS(sig), result);
      });
    }

    for (const vector of vectors.is_low_der) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = vector.result;
      const text = vector.sig.slice(0, 32) + '...';

      it(`should test S value (DER): ${text}`, () => {
        assert.strictEqual(secp256k1.isLowDER(sig), result);
      });
    }
  }
});
