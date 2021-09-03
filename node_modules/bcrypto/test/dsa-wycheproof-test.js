'use strict';

const assert = require('bsert');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const dsa = require('../lib/dsa');
const vectors = require('./data/wycheproof/dsa_test.json');

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

describe('DSA-Wycheproof', function() {
  this.timeout(30000);

  for (const group of vectors.testGroups) {
    const hash = hashes[group.sha];

    for (const test of group.tests) {
      const text = test.sig.slice(0, 32) + '...';

      it(`should verify signature ${text} (${hash.id})`, () => {
        const msg = hash.digest(parseHex(test.msg));
        const sig = parseHex(test.sig);

        let res = test.result !== 'invalid';

        if (test.flags.includes('NoLeadingZero'))
          res = false;

        const pub = dsa.publicKeyImport({
          p: parseHex(group.key.p),
          q: parseHex(group.key.q),
          g: parseHex(group.key.g),
          y: parseHex(group.key.y)
        });

        assert.strictEqual(dsa.verifyDER(msg, sig, pub), res);
      });
    }
  }
});
