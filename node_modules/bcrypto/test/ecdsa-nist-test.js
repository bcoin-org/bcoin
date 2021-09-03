'use strict';

// Vectors from:
// http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip

const assert = require('bsert');
const {padLeft} = require('../lib/encoding/util');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const keyVectors = require('./data/ecdsa-nist/KeyPair.json');
const pkvVectors = require('./data/ecdsa-nist/PKV.json');
const genVectors = require('./data/ecdsa-nist/SigGen.json');
const verVectors = require('./data/ecdsa-nist/SigVer.json');

const curves = {
  'P-192': p192,
  'P-224': p224,
  'P-256': p256,
  'P-384': p384,
  'P-521': p521
};

const hashes = {
  'SHA-1': SHA1,
  'SHA-224': SHA224,
  'SHA-256': SHA256,
  'SHA-384': SHA384,
  'SHA-512': SHA512
};

const parsePriv = (vector, curve) => {
  return padLeft(Buffer.from(vector.d, 'hex'), curve.size);
};

const parsePub = (vector, curve) => {
  const form = Buffer.from([0x04]);
  const Qx = padLeft(Buffer.from(vector.Qx, 'hex'), curve.size);
  const Qy = padLeft(Buffer.from(vector.Qy, 'hex'), curve.size);

  return Buffer.concat([form, Qx, Qy]);
};

const parseSig = (vector, curve) => {
  const R = padLeft(Buffer.from(vector.R, 'hex'), curve.size);
  const S = padLeft(Buffer.from(vector.S, 'hex'), curve.size);

  return Buffer.concat([R, S]);
};

const parseMsg = (vector, hash) => {
  return hash.digest(Buffer.from(vector.Msg, 'hex'));
};

describe('ECDSA-NIST', function() {
  this.timeout(15000);

  for (const vector of keyVectors) {
    const curve = curves[vector.Curve];
    const text = vector.d.slice(0, 32) + '...';

    if (!curve)
      continue;

    it(`should generate key: ${text} (${curve.id})`, () => {
      const priv = parsePriv(vector, curve);
      const pub = parsePub(vector, curve);

      assert.bufferEqual(curve.publicKeyCreate(priv, false), pub);
    });
  }

  for (const vector of pkvVectors) {
    const curve = curves[vector.Curve];
    const text = vector.Qx.slice(0, 32) + '...';

    if (!curve)
      continue;

    // Both openssl and bcrypto fail on these.
    // NIST broke their test vectors? (If so,
    // they _really_ broke them. The keys don't
    // satisfy the curve equation).
    if (curve.id === 'P521')
      continue;

    it(`should validate key: ${text} (${curve.id})`, () => {
      const pub = parsePub(vector, curve);

      assert.strictEqual(curve.publicKeyVerify(pub), vector.Result[0] === 'P');
    });
  }

  for (const vector of genVectors) {
    const curve = curves[vector.Curve];
    const hash = hashes[vector.Hash];
    const text = vector.R.slice(0, 32) + '...';

    if (!curve || !hash)
      continue;

    // See above.
    if (curve.id === 'P521')
      continue;

    it(`should generate signature: ${text} (${curve.id})`, () => {
      const priv = parsePriv(vector, curve);
      const msg = parseMsg(vector, hash);
      const pub = parsePub(vector, curve);
      const sig = parseSig(vector, curve);

      // If we allowed for arbitrary `k` values we could do:
      //
      //   const k = Buffer.from(vector.k, 'hex');
      //   assert.bufferEqual(curve.sign(msg, priv, k), sig);

      assert.bufferEqual(curve.publicKeyCreate(priv, false), pub);
      assert.strictEqual(curve.verify(msg, sig, pub), true);
    });
  }

  for (const vector of verVectors) {
    const curve = curves[vector.Curve];
    const hash = hashes[vector.Hash];
    const text = vector.R.slice(0, 32) + '...';

    if (!curve || !hash)
      continue;

    // See above.
    if (curve.id === 'P521')
      continue;

    it(`should verify signature: ${text} (${curve.id})`, () => {
      const msg = parseMsg(vector, hash);
      const pub = parsePub(vector, curve);
      const sig = parseSig(vector, curve);

      assert.strictEqual(curve.verify(msg, sig, pub), vector.Result[0] === 'P');
    });
  }
});
