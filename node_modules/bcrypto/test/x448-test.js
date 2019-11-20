'use strict';

const assert = require('bsert');
const pem = require('../lib/encoding/pem');
const ed448 = require('../lib/ed448');
const x448 = require('../lib/x448');

const vectors = [
  // From RFC 7748
  [
    Buffer.from('06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9'
              + '814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086', 'hex'),
    Buffer.from('3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121'
              + '700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3', 'hex'),
    Buffer.from('ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f'
              + 'e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f', 'hex')
  ],
  [
    Buffer.from('0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b'
              + '165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db', 'hex'),
    Buffer.from('203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5'
              + '38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f', 'hex'),
    Buffer.from('884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7'
              + 'ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d', 'hex')
  ]
];

// From RFC 7748
const intervals = [
  Buffer.from('3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a'
            + '4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113', 'hex'),
  Buffer.from('cca03d8ed3f54baf8d1aa088b1f24bc68aed538d06485f025f17a543'
            + '1ded28f256d34f6bdd3d63cc5e047c458e81385519a92999bddc2653', 'hex'),
  Buffer.from('aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4'
            + 'af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38', 'hex'),
  Buffer.from('077f453681caca3693198420bbe515cae0002472519b3e67661a7e89'
            + 'cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37', 'hex')
];

const privPem = `
-----BEGIN PRIVATE KEY-----
MEYCAQAwBQYDK2VvBDoEODS/v+7SdfH9nVquDWbSj5PvcABLtBO6uSnsiTVc6xTu
u86nXUP4rZhJ7ZYJSa/szpJMMFnnRQrh
-----END PRIVATE KEY-----
`;

const pubPem = `
-----BEGIN PUBLIC KEY-----
MEIwBQYDK2VvAzkAIakuL8JOtTmPmNj+Hj9Vk2pTl7WknxmyyRh4xTHBoodB/iqn
pDWiqkjsYdlUUGH7se0wSZW3+AU=
-----END PUBLIC KEY-----
`;

describe('X448', function() {
  for (const [pub, key, expect] of vectors) {
    it(`should compute secret: ${expect.toString('hex')}`, () => {
      const result = x448.derive(pub, key);
      assert.bufferEqual(result, expect);
    });
  }

  it('should do repeated scalar multiplication', () => {
    let k = Buffer.alloc(56, 0x00);
    let u = Buffer.alloc(56, 0x00);
    let i = 0;

    k[0] = 5;
    u[0] = 5;

    for (; i < 1; i++)
      [u, k] = [k, x448.derive(u, k)];

    assert.bufferEqual(k, intervals[0]);

    for (; i < 100; i++)
      [u, k] = [k, x448.derive(u, k)];

    assert.bufferEqual(k, intervals[1]);

    if (ed448.native) {
      for (; i < 1000; i++)
        [u, k] = [k, x448.derive(u, k)];

      assert.bufferEqual(k, intervals[2]);
    }

    // for (; i < 1000000; i++)
    //   [u, k] = [k, x448.derive(u, k)];
    //
    // assert.bufferEqual(k, intervals[3]);
  });

  for (let i = 0; i < 20; i++) {
    it(`should exchange keys after point conversion (${i})`, () => {
      const scalar = ed448.scalarGenerate();
      const edPub = ed448.publicKeyFromScalar(scalar);
      const tweak = ed448.scalarGenerate();
      const edPoint = ed448.deriveWithScalar(edPub, tweak);
      const pub = ed448.publicKeyConvert(edPub);
      const expect = ed448.publicKeyConvert(edPoint);
      const result = x448.derive(pub, tweak);

      assert.bufferEqual(result, expect);
    });
  }

  it('should do scalar base multiplication (edwards)', () => {
    const expect = '61a50c522f8c9e75eb88cc09a28b23954a63e6409d6d517ffcacf70d'
                 + '1e10d87cd107cbf6f4375307d10bc2ca7a116733e50d3c4191be7ab1';

    let key = Buffer.alloc(56, 0x00);

    key[0] = 1;

    for (let i = 0; i < 20; i++)
      key = x448.publicKeyCreate(key);

    assert.bufferEqual(key, expect, 'hex');
  });

  it('should do scalar base multiplication (mont)', () => {
    const expect = '61a50c522f8c9e75eb88cc09a28b23954a63e6409d6d517ffcacf70d'
                 + '1e10d87cd107cbf6f4375307d10bc2ca7a116733e50d3c4191be7ab1';

    let key = Buffer.alloc(56, 0x00);

    key[0] = 1;

    for (let i = 0; i < 20; i++)
      key = x448._scalarBaseMul(key);

    assert.bufferEqual(key, expect, 'hex');
  });

  it('should test x448 api', () => {
    const alicePriv = x448.privateKeyGenerate();
    const alicePub = x448.publicKeyCreate(alicePriv);
    const bobPriv = x448.privateKeyGenerate();
    const bobPub = x448.publicKeyCreate(bobPriv);

    assert(x448.privateKeyVerify(alicePriv));
    assert(x448.privateKeyVerify(bobPriv));
    assert(x448.publicKeyVerify(alicePub));
    assert(x448.publicKeyVerify(bobPub));

    assert(alicePriv.length === 56);
    assert(alicePub.length === 56);

    const aliceSecret = x448.derive(bobPub, alicePriv);
    const bobSecret = x448.derive(alicePub, bobPriv);

    assert(aliceSecret.length === 56);

    assert.bufferEqual(aliceSecret, bobSecret);

    const rawPriv = x448.privateKeyExport(alicePriv);
    const rawPub = x448.publicKeyExport(alicePub);

    assert.bufferEqual(x448.privateKeyImport(rawPriv), alicePriv);
    assert.bufferEqual(x448.publicKeyImport(rawPub), alicePub);

    const jsonPriv = x448.privateKeyExportJWK(alicePriv);
    const jsonPub = x448.publicKeyExportJWK(alicePub);

    assert.bufferEqual(x448.privateKeyImportJWK(jsonPriv), alicePriv);
    assert.bufferEqual(x448.publicKeyImportJWK(jsonPub), alicePub);

    const asnPriv = x448.privateKeyExportPKCS8(alicePriv);
    const asnPub = x448.publicKeyExportSPKI(alicePub);

    assert.bufferEqual(x448.privateKeyImportPKCS8(asnPriv), alicePriv);
    assert.bufferEqual(x448.publicKeyImportSPKI(asnPub), alicePub);

    const asnPriv2 = pem.fromPEM(privPem, 'PRIVATE KEY');
    const asnPub2 = pem.fromPEM(pubPem, 'PUBLIC KEY');

    assert.bufferEqual(x448.publicKeyImportSPKI(asnPub2),
      x448.publicKeyCreate(x448.privateKeyImportPKCS8(asnPriv2)));
  });
});
