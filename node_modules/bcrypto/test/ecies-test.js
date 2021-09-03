'use strict';

const assert = require('bsert');
const fs = require('fs');
const path = require('path');
const RNG = require('./util/rng');
const SHA256 = require('../lib/sha256');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = require('../lib/secp256k1');
const ed25519 = require('../lib/ed25519');
const ed448 = require('../lib/ed448');
const x25519 = require('../lib/x25519');
const x448 = require('../lib/x448');
const ecies = require('../lib/ecies');
const PATH = path.join(__dirname, 'data', 'ies');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1,
  ed25519,
  ed448,
  x25519,
  x448
];

describe('ECIES', function() {
  const rng = new RNG();

  for (const curve of curves) {
    it(`should encrypt and decrypt (${curve.id})`, () => {
      const alicePriv = rng.privateKeyGenerate(curve);
      const bobPriv = rng.privateKeyGenerate(curve);
      const bobPub = curve.publicKeyCreate(bobPriv);

      const msg = rng.randomBytes(rng.randomRange(0, 100));
      const ct = ecies.encrypt(curve, SHA256, msg, bobPub, alicePriv);

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

  for (const curve of curves) {
    const file = path.join(PATH, `${curve.id.toLowerCase()}.json`);
    const text = fs.readFileSync(file, 'utf8');
    const vectors = JSON.parse(text);

    for (const [i, json] of vectors.entries()) {
      const vector = json.map(item => Buffer.from(item, 'hex'));
      const [, bob,, msg, ct] = vector;

      it(`should decrypt ciphertext #${i + 1} (${curve.id})`, () => {
        const pt = ecies.decrypt(curve, SHA256, ct, bob);
        assert.bufferEqual(pt, msg);
      });
    }
  }
});
