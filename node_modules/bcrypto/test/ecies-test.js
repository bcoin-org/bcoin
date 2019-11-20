/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');

const parts = process.version.split(/[^\d]/);
const NODE_MAJOR = parts[1] >>> 0;

const ECDSA = (() => {
  if (!process.env.NODE_BACKEND || process.env.NODE_BACKEND === 'native') {
    if (NODE_MAJOR >= 10)
      return require('../lib/native/ecdsa');
  }
  return require('../lib/js/ecdsa');
})();

const random = require('../lib/random');
const SHA256 = require('../lib/sha256');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = new ECDSA('SECP256K1', require('../lib/sha256'));
const secp256k1n = require('../lib/secp256k1');
const ed25519 = require('../lib/ed25519');
const ed448 = require('../lib/ed448');
const x25519 = require('../lib/x25519');
const x448 = require('../lib/x448');
const ecies = require('../lib/ecies');
const vectors = require('./data/ecies.json');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1,
  secp256k1n,
  ed25519,
  ed448,
  x25519,
  x448
];

const curveMap = {
  P192: p192,
  P224: p224,
  P256: p256,
  P384: p384,
  P521: p521,
  SECP256K1: secp256k1n,
  ED25519: ed25519,
  ED448: ed448,
  X25519: x25519,
  X448: x448
};

describe('ECIES', function() {
  this.timeout(15000);

  for (const withKey of [true, false]) {
    for (const curve of curves) {
      it(`should encrypt and decrypt (${curve.id})`, () => {
        const alicePriv = curve.privateKeyGenerate();
        const bobPriv = curve.privateKeyGenerate();
        const bobPub = curve.publicKeyCreate(bobPriv);

        const msg = random.randomBytes(Math.random() * 100 | 0);
        const ct = ecies.encrypt(
          curve,
          SHA256,
          msg,
          bobPub,
          withKey ? alicePriv : null
        );

        assert.notBufferEqual(ct, msg);
        assert(ct.length > msg.length);

        const pt = ecies.decrypt(curve, SHA256, ct, bobPriv);
        assert.bufferEqual(pt, msg);

        assert.throws(() => {
          ecies.decrypt(curve, SHA256, ct, alicePriv);
        });

        ct[1] ^= 1;
        assert.throws(() => {
          ecies.decrypt(curve, SHA256, ct, bobPriv);
        });
        ct[1] ^= 1;
      });
    }
  }

  for (const vector of vectors) {
    const curve = curveMap[vector.curve];
    const hash = SHA256;
    const ct = Buffer.from(vector.msg, 'hex');
    const priv = Buffer.from(vector.priv, 'hex');
    const expect = Buffer.from(vector.expect, 'hex');

    it(`should decrypt (${curve.id})`, () => {
      const pt = ecies.decrypt(curve, hash, ct, priv);
      assert.bufferEqual(pt, expect);
    });
  }
});
