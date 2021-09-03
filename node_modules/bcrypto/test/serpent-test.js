'use strict';

const assert = require('bsert');
const Serpent = require('../lib/js/ciphers/serpent');
const cipher = require('../lib/cipher');

// See: https://github.com/aead/serpent/blob/master/vectors_test.go
const vectors = [
  // test vectors for 128 bit key from
  // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
  [ // Set 1, vector#  0
    128,
    '80000000000000000000000000000000',
    '00000000000000000000000000000000',
    '264e5481eff42a4606abda06c0bfda3d',
    '5ad4cbb83022e1dd365154ac50e1e624'
  ],
  [ // Set 1, vector#  1
    128,
    '40000000000000000000000000000000',
    '00000000000000000000000000000000',
    '4a231b3bc727993407ac6ec8350e8524',
    '6a27f1feafa46ae562a36f02f677dd88'
  ],
  // test vectors for 192 bit key from
  // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors
  [ // Set 1, vector#  0
    192,
    '800000000000000000000000000000000000000000000000',
    '00000000000000000000000000000000',
    '9e274ead9b737bb21efcfca548602689',
    '32fb7094392eee35790433f2de4c6c9f'
  ],
  [ // Set 1, vector#  3
    192,
    '100000000000000000000000000000000000000000000000',
    '00000000000000000000000000000000',
    'bec1e37824cf721e5d87f6cb4ebfb9be',
    '0f899aeaecc5f0657d201fa94fd6c753'
  ],
  // test vectors for 256 bit key from
  // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
  [ // Set 3, vector#  1
    256,
    '0101010101010101010101010101010101010101010101010101010101010101',
    '01010101010101010101010101010101',
    'ec9723b15b2a6489f84c4524fffc2748',
    '5f2a725e4cea6515346cb276fffc585a'
  ],
  [ // Set 3, vector#  2
    256,
    '0202020202020202020202020202020202020202020202020202020202020202',
    '02020202020202020202020202020202',
    '1187f485538514476184e567da0421c7',
    '7fe50a353600ae7af8ee5b0e40336ef0'
  ]
];

describe('Serpent', function() {
  for (const [bits, key, plaintext, ciphertext, padding] of vectors) {
    const k = Buffer.from(key, 'hex');
    const pt = Buffer.from(plaintext, 'hex');
    const ct = Buffer.from(ciphertext, 'hex');
    const pad = Buffer.from(padding, 'hex');
    const ect = Buffer.concat([ct, pad]);
    const name = `SERPENT-${bits}`;
    const text = ciphertext.slice(0, 32) + '...';

    it(`should compute vector ${text}`, () => {
      const s = new Serpent(bits).init(k);
      const out = Buffer.alloc(16);

      s.encrypt(out, 0, pt, 0);
      assert.bufferEqual(out, ct);

      s.decrypt(out, 0, ct, 0);
      assert.bufferEqual(out, pt);

      assert.bufferEqual(cipher.encrypt(name, k, null, pt), ct);
      assert.bufferEqual(cipher.decrypt(name, k, null, ct), pt);

      assert.bufferEqual(cipher.encrypt(`${name}-ECB`, k, null, pt), ect);
      assert.bufferEqual(cipher.decrypt(`${name}-ECB`, k, null, ect), pt);

      {
        const c = new cipher.Cipher(`${name}-ECB`).init(k);
        const d = new cipher.Decipher(`${name}-ECB`).init(k);

        c.setAutoPadding(false);
        d.setAutoPadding(false);

        assert.bufferEqual(c.update(pt), ct);
        assert.bufferEqual(d.update(ct), pt);

        c.final();
        d.final();
      }
    });
  }
});
