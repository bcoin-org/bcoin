'use strict';

const assert = require('bsert');
const {padLeft} = require('../lib/encoding/util');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = require('../lib/secp256k1');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const x509 = require('../lib/encoding/x509');
const ecdsaVectors = require('./data/wycheproof/ecdsa_test.json');
const ecdhVectors = require('./data/wycheproof/ecdh_test.json');

const curves = {
  'secp224r1': p224,
  'secp256r1': p256,
  'secp384r1': p384,
  'secp521r1': p521,
  'secp256k1': secp256k1
};

const hashes = {
  'SHA-1': SHA1,
  'SHA-224': SHA224,
  'SHA-256': SHA256,
  'SHA-384': SHA384,
  'SHA-512': SHA512
};

function parsePublic(raw) {
  const spki = x509.SubjectPublicKeyInfo.decode(raw);
  return spki.publicKey.rightAlign();
}

describe('ECDSA-Wycheproof', function() {
  this.timeout(30000);

  for (const group of ecdsaVectors.testGroups) {
    const curve = curves[group.key.curve];

    if (!curve)
      continue;

    const pub = Buffer.from(group.key.uncompressed, 'hex');
    const hash = hashes[group.sha];

    for (const test of group.tests) {
      const text = test.sig.slice(0, 32) + '...';

      it(`should verify signature ${text} (${hash.id})`, () => {
        const msg = hash.digest(Buffer.from(test.msg, 'hex'));
        const sig = Buffer.from(test.sig, 'hex');
        const res = test.result !== 'invalid';

        assert.strictEqual(curve.verifyDER(msg, sig, pub), res);
      });
    }
  }

  for (const group of ecdhVectors.testGroups) {
    const curve = curves[group.curve];

    if (!curve)
      continue;

    for (const test of group.tests) {
      const text = test.public.slice(0, 32) + '...';

      it(`should perform ECDH ${text}`, () => {
        const pub = parsePublic(Buffer.from(test.public, 'hex'));
        const priv = padLeft(Buffer.from(test.private, 'hex'), curve.size);
        const shared = Buffer.from(test.shared, 'hex');

        if (shared.length === 0)
          assert.throws(() => curve.derive(pub, priv));
        else
          assert.bufferEqual(curve.derive(pub, priv).slice(1), shared);
      });
    }
  }
});
