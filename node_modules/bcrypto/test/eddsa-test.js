'use strict';

const assert = require('bsert');
const fs = require('fs');
const ed25519 = require('../lib/ed25519');
const x25519 = require('../lib/x25519');
const ed448 = require('../lib/ed448');
const x448 = require('../lib/x448');

const curves = [
  [ed25519, x25519],
  [ed448, x448]
];

describe('EdDSA', function() {
  const getVectors = (curve) => {
    const id = curve.id.toLowerCase();
    const file = `${__dirname}/data/sign/${id}.json`;
    const text = fs.readFileSync(file, 'utf8');
    const vectors = JSON.parse(text);

    return vectors.map((vector) => {
      return vector.map((item) => {
        if (typeof item !== 'string')
          return item;
        return Buffer.from(item, 'hex');
      });
    });
  };

  for (const [curve, x] of curves) {
    describe(curve.id, () => {
      const batch = [];

      for (const [i, vector] of getVectors(curve).entries()) {
        const [
          priv,
          scalar,
          prefix,
          reduced,
          pub,
          tweak,
          privAdd,
          privMul,
          privNeg,
          privInv,
          pubAdd,
          pubMul,
          pubNeg,
          pubDbl,
          pubConv,
          ,
          ,
          ,
          ,
          msg,
          ph,
          sig,
          sigAdd,
          sigMul,
          other,
          edSecret,
          montSecret
        ] = vector;

        if (!ph)
          batch.push([msg, sig, pub]);

        it(`should create and tweak key (${i}) (${curve.id})`, () => {
          assert(curve.privateKeyVerify(priv));
          assert(curve.publicKeyVerify(pub));

          const [scalar_, prefix_] = curve.privateKeyExpand(priv);
          const tweakNeg = curve.scalarNegate(tweak);
          const tweakInv = curve.scalarInvert(tweak);
          const sign = (pub[curve.size - 1] & 0x80) !== 0;
          const inf = Buffer.alloc(curve.size, 0x00);
          inf[0] = 0x01;

          assert.bufferEqual(curve.publicKeyCreate(priv), pub);
          assert.bufferEqual(curve.publicKeyFromScalar(scalar), pub);
          assert.bufferEqual(scalar_, scalar);
          assert.bufferEqual(prefix_, prefix);
          assert.bufferEqual(curve.scalarReduce(scalar), reduced);
          assert.bufferEqual(curve.scalarTweakAdd(scalar, tweak), privAdd);
          assert.bufferEqual(curve.scalarTweakAdd(privAdd, tweakNeg), reduced);
          assert.bufferEqual(curve.scalarTweakMul(scalar, tweak), privMul);
          assert.bufferEqual(curve.scalarTweakMul(privMul, tweakInv), reduced);
          assert.bufferEqual(curve.scalarNegate(scalar), privNeg);
          assert.bufferEqual(curve.scalarInvert(scalar), privInv);
          assert.bufferEqual(curve.publicKeyTweakAdd(pub, tweak), pubAdd);
          assert.bufferEqual(curve.publicKeyTweakAdd(pubAdd, tweakNeg), pub);
          assert.bufferEqual(curve.publicKeyTweakMul(pub, tweak), pubMul);
          assert.bufferEqual(curve.publicKeyTweakMul(pubMul, tweakInv), pub);
          assert.bufferEqual(curve.publicKeyNegate(pub), pubNeg);
          assert.bufferEqual(curve.publicKeyCombine([pub, pub]), pubDbl);
          assert.bufferEqual(curve.publicKeyCombine([pubDbl, pubNeg]), pub);
          assert.bufferEqual(curve.publicKeyCombine([pub, pubNeg, pub]), pub);
          assert.bufferEqual(curve.privateKeyConvert(priv), scalar);
          assert.bufferEqual(curve.publicKeyConvert(pub), pubConv);
          assert.bufferEqual(x.publicKeyConvert(pubConv, sign), pub);

          assert.bufferEqual(curve.publicKeyCombine([]), inf);
          assert.bufferEqual(curve.publicKeyCombine([pub, pubNeg]), inf);
        });

        it(`should reserialize key (${i}) (${curve.id})`, () => {
          const rawPriv = curve.privateKeyExport(priv);
          const rawPub = curve.publicKeyExport(pub);

          assert.bufferEqual(curve.privateKeyImport(rawPriv), priv);
          assert.bufferEqual(curve.publicKeyImport(rawPub), pub);
        });

        it(`should derive shared secret (${i}) (${curve.id})`, () => {
          const otherConv = curve.privateKeyConvert(other);

          assert.bufferEqual(curve.derive(pub, other), edSecret);
          assert.bufferEqual(curve.deriveWithScalar(pub, otherConv), edSecret);
          assert.bufferEqual(x.derive(pubConv, otherConv), montSecret);
        });

        it(`should sign and verify (${i}) (${curve.id})`, () => {
          const sig2 = curve.sign(msg, priv, ph);
          const sig3 = curve.signWithScalar(msg, scalar, prefix, ph);

          assert.bufferEqual(sig2, sig);
          assert.bufferEqual(sig3, sig);

          assert(curve.verify(msg, sig, pub, ph));
          assert(curve.verifySingle(msg, sig, pub, ph));

          msg[0] ^= 1;

          assert(!curve.verify(msg, sig, pub, ph));
          assert(!curve.verifySingle(msg, sig, pub, ph));

          msg[0] ^= 1;
          sig[0] ^= 1;

          assert(!curve.verify(msg, sig, pub, ph));
          assert(!curve.verifySingle(msg, sig, pub, ph));

          sig[0] ^= 1;
          pub[0] ^= 1;

          assert(!curve.verify(msg, sig, pub, ph));
          assert(!curve.verifySingle(msg, sig, pub, ph));

          pub[0] ^= 1;

          assert(curve.verify(msg, sig, pub, ph));
          assert(curve.verifySingle(msg, sig, pub, ph));
        });

        it(`should batch verify (${i}) (${curve.id})`, () => {
          assert(curve.verifyBatch([], ph), true);
          assert(curve.verifyBatch([[msg, sig, pub]], ph));

          msg[0] ^= 1;

          assert(!curve.verifyBatch([[msg, sig, pub]], ph));

          msg[0] ^= 1;
        });

        it(`should sign and verify with tweak add (${i}) (${curve.id})`, () => {
          const sig = curve.signTweakAdd(msg, priv, tweak, ph);

          assert.bufferEqual(sig, sigAdd);

          assert(curve.verify(msg, sig, pubAdd, ph));
          assert(curve.verifySingle(msg, sig, pubAdd, ph));

          msg[0] ^= 1;

          assert(!curve.verify(msg, sig, pubAdd, ph));
          assert(!curve.verifySingle(msg, sig, pubAdd, ph));

          msg[0] ^= 1;
          sig[0] ^= 1;

          assert(!curve.verify(msg, sig, pubAdd, ph));
          assert(!curve.verifySingle(msg, sig, pubAdd, ph));

          sig[0] ^= 1;
          pubAdd[0] ^= 1;

          assert(!curve.verify(msg, sig, pubAdd, ph));
          assert(!curve.verifySingle(msg, sig, pubAdd, ph));

          pubAdd[0] ^= 1;

          assert(curve.verify(msg, sig, pubAdd, ph));
          assert(curve.verifySingle(msg, sig, pubAdd, ph));
        });

        it(`should sign and verify with tweak mul (${i}) (${curve.id})`, () => {
          const sig = curve.signTweakMul(msg, priv, tweak, ph);

          assert.bufferEqual(sig, sigMul);

          assert(curve.verify(msg, sig, pubMul, ph));
          assert(curve.verifySingle(msg, sig, pubMul, ph));

          msg[0] ^= 1;

          assert(!curve.verify(msg, sig, pubMul, ph));
          assert(!curve.verifySingle(msg, sig, pubMul, ph));

          msg[0] ^= 1;
          sig[0] ^= 1;

          assert(!curve.verify(msg, sig, pubMul, ph));
          assert(!curve.verifySingle(msg, sig, pubMul, ph));

          sig[0] ^= 1;
          pubMul[0] ^= 1;

          assert(!curve.verify(msg, sig, pubMul, ph));
          assert(!curve.verifySingle(msg, sig, pubMul, ph));

          pubMul[0] ^= 1;

          assert(curve.verify(msg, sig, pubMul, ph));
          assert(curve.verifySingle(msg, sig, pubMul, ph));
        });
      }

      it(`should batch verify (${curve.id})`, () => {
        const [msg] = batch[0];

        assert(curve.verifyBatch(batch));

        if (msg.length > 0) {
          msg[0] ^= 1;
          assert(!curve.verifyBatch(batch));
          msg[0] ^= 1;
        }
      });
    });
  }
});
