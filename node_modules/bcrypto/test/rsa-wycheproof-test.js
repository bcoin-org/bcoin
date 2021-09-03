'use strict';

const assert = require('bsert');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const rsa = require('../lib/rsa');
const pkcs1Vectors = require('./data/wycheproof/rsa_signature_test.json');
const pssVectors = require('./data/wycheproof/rsa_pss_misc_test.json');

const hashes = {
  'SHA-1': SHA1,
  'SHA-224': SHA224,
  'SHA-256': SHA256,
  'SHA-384': SHA384,
  'SHA-512': SHA512
};

function parseHex(str) {
  if (str.length & 1)
    str = '0' + str;
  return Buffer.from(str, 'hex');
}

describe('RSA-Wycheproof', function() {
  this.timeout(30000);

  for (const group of pkcs1Vectors.testGroups) {
    const hash = hashes[group.sha];

    for (const test of group.tests) {
      const text = test.sig.slice(0, 32) + '...';

      it(`should verify PKCS1v1.5 signature ${text} (${hash.id})`, () => {
        const msg = hash.digest(parseHex(test.msg));
        const sig = parseHex(test.sig);

        let res = test.result !== 'invalid';

        // We require the null.
        if (test.tcId === 8)
          res = false;

        const pub = rsa.publicKeyImport({
          n: parseHex(group.n),
          e: parseHex(group.e)
        });

        assert.strictEqual(rsa.verify(hash, msg, sig, pub), res);
      });
    }
  }

  for (const group of pssVectors.testGroups) {
    const hash = hashes[group.sha];

    if (group.sha !== group.mgfSha)
      continue;

    for (const test of group.tests) {
      const text = test.sig.slice(0, 32) + '...';

      it(`should verify PSS signature ${text} (${hash.id})`, () => {
        const msg = hash.digest(parseHex(test.msg));
        const sig = parseHex(test.sig);
        const res = test.result !== 'invalid';

        const pub = rsa.publicKeyImport({
          n: parseHex(group.n),
          e: parseHex(group.e)
        });

        assert.strictEqual(rsa.verifyPSS(hash, msg, sig, pub, group.sLen), res);
      });
    }
  }
});
