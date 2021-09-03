'use strict';

const assert = require('bsert');
const cipher = require('../lib/cipher');

const vectors = [
  [
    '04ac4f73a09bd2f1c727f1d362616de9',
    '826fdeb41c5c2822a0ecef20b78540c8',
    'df5331ee5ffa9e46d6217ba2395a9d4c',
    '603d4499efdb7bfcd5095624125984e1436ca20baa98f456e1fdfa',
    'a723415ce8094b6fc057228f499f5a014328b5d2bbc11c2b5e6b39'
  ],
  [
    'ef64fe2abe069fa4ad154df60c85bdf5',
    '434ce6a9b2525c0af02dce5ca032db17',
    '22c4b603adbdedac6c3bbffe5591fddf',
    'da5b8b3b58438f0c320f795d113d9021748ddc52f4a9203260c830',
    '91a0945cfa59134797167a260d176289fed5563db0a0f2a8c0fb36'
  ],
  [
    '5d08119ad85a7a82d9e9d2abd4eea8ff',
    '3757f11123d68836fd567332433267c4',
    'b4205c7603869bcb51c699afe494f95a',
    'dc2e6bb9c6fef441401d329ecfe47b1a76a1e4f9441ef297f48535d233ce68d3',
    '7e0b7ed2ec7ed7e812264a23d54696d93c5a406508fcbd8990c72953862c9fee'
  ],
  [
    'f1055779565f140239375db28e78576b',
    '4842b8f0d0791cea0064eb63d8e2dc3c',
    '8d2b672c79e6a25ae487294566ad0829',
    '93d76a108068c626a85d442b5e4c1b22b4748709f2e431918bbf3aba52d7b720',
    'f62006e3e055261017c11be5040ec6552ece86f8005947d6c48a2bbf85bdd553'
  ]
];

describe('XTS', function() {
  const alg = 'AES-128-XTS';

  for (const [i, item] of vectors.entries()) {
    const k1 = Buffer.from(item[0], 'hex');
    const k2 = Buffer.from(item[1], 'hex');
    const sector = Buffer.from(item[2], 'hex');
    const pt1 = Buffer.from(item[3], 'hex');
    const ct1 = Buffer.from(item[4], 'hex');
    const k = Buffer.concat([k1, k2]);

    it(`should pass ${alg} vector #${i + 1}`, () => {
      const c = new cipher.Cipher(alg).init(k, sector);
      const d = new cipher.Decipher(alg).init(k, sector);

      const ct2 = Buffer.concat([
        c.update(pt1),
        c.final()
      ]);

      const pt2 = Buffer.concat([
        d.update(ct1),
        d.final()
      ]);

      assert.bufferEqual(ct2, ct1);
      assert.bufferEqual(pt2, pt1);
    });
  }
});
