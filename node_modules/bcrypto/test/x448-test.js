'use strict';

const assert = require('bsert');
const RNG = require('./util/rng');
const SHAKE256 = require('../lib/shake256');
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

const scalarVectors = [
  [
    Buffer.from('98843ebbc7f4015310b67915a46f301b790584263d6b07e160e59b54'
              + 'e6b44d8b4237fcde0e639b6f201a06395b1dedbce4ccc3bcf60755fd', 'hex'),
    Buffer.from('689b6ede1cba22e902745a576122e68138cbec6e30724b0e23e96613'
              + '0f4997cb49d90efaf9aa1924b79b722e8a02034cf47d99589ff85ea4', 'hex'),
    Buffer.from('3a8d488589e4fd619d7792bf156241792aeeed476f61d18264fae7b1'
              + '69b7a26a33315565988aae139abb02953c7d06b0e7ee837087e75280', 'hex')
  ],
  [
    Buffer.from('b81f7738b6dd3700b0e8390bd312b85fa5b0c9e458454380afbe3c6a'
              + '15208f9454a67c6220d54a66d88e7f7402f5c837f27af301548f568b', 'hex'),
    Buffer.from('6819c4ec65ed839b7bee92f429f066708f385becac88fb26bc279261'
              + '155f18cf8cddb3c7ee5082ee71fb9bd77a7fe3d5a85f6b823a2b9397', 'hex'),
    Buffer.from('5df6135e61e0f93ff856b67f52936f3e486ca3540062edc7d455a79a'
              + 'e9e71bf4eccf515f583cc4f6871be28c1f23a8548814ff8fd24ab2fc', 'hex')
  ],
  [
    Buffer.from('c81e6f898e13881954cf72d5e3271b2e67b0638248b4146dedd5d7ea'
              + 'b127d52248d8019590962fd63f2dee3c31b5360c83ea881d31502c94', 'hex'),
    Buffer.from('0c38db0afc0aebc1509119879e42e3352620ba3c1add4a4a42ae4eda'
              + 'db207936d7a5978e567dbd6d05669820448bc0017923deb37bf283cf', 'hex'),
    Buffer.from('06dd50fe0d7196d0d7f7c6c24b6040bdc0c8c2b8ef3c3c751d25d5bd'
              + 'e4f13ccdcd526b7f307d8e127b7b33b4fe750d19085fe07d2acb837d', 'hex')
  ],
  [
    Buffer.from('28095e2a964e1327ee2b7da011328be7a09478a84ff2d55a0cfe0c35'
              + '153661286691e6d9d4f65a41ef5f1bb6f8e7e22db9a7f8827c03b2d6', 'hex'),
    Buffer.from('f8cf547af2439a9b0a871ec28235d1c6eaace7d69665be9fe51a07eb'
              + 'e6a9c9978dd7c3970d53c3c31097437dbbbe9c3e4838c2640917e487', 'hex'),
    Buffer.from('41850d53f50aa5e298a40586b251aee90f1fbe20bb85ce04c5bd57dc'
              + 'b2a6b70a62324e1e183f3e2aa92687faf0e4268265e015653ba1da96', 'hex')
  ],
  [
    Buffer.from('c872419cfb4325e23d48568f23105fce20458561c0f6b011ce99d3a0'
              + 'e74bbccecfb3f5836677d4fcf5f4f113e76cc0eae97f53f02e726d98', 'hex'),
    Buffer.from('98f75191ac8ea880ae516b6a5a7760f652cc7c98c9db037a8e19de23'
              + 'ff2baf1bb4c1a979422965311ca7ee4b0f36b6dfa66df575aa6ea7c6', 'hex'),
    Buffer.from('bdfea1b2feeb9ac78981cec17d046bc2a5113899dd422e5e32ab4b3e'
              + 'e9618e91839d1e9351e350fd855de230c6138e70a3d7cdb2fbb91356', 'hex')
  ]
];

describe('X448', function() {
  const rng = new RNG();

  for (const [pub, key, expect] of vectors) {
    it(`should compute secret: ${expect.toString('hex', 0, 16)}...`, () => {
      const result = x448.derive(pub, key);
      assert.bufferEqual(result, expect);
    });
  }

  for (const [scalar, tweak, expect] of scalarVectors) {
    it(`should convert secret: ${expect.toString('hex', 0, 16)}...`, () => {
      const edPub = ed448.publicKeyFromScalar(scalar);
      const edPoint = ed448.deriveWithScalar(edPub, tweak);
      const pub = ed448.publicKeyConvert(edPub);
      const result = ed448.publicKeyConvert(edPoint);

      assert.bufferEqual(result, expect);
      assert.bufferEqual(x448.derive(pub, tweak), expect);
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

  it('should reject small order points', () => {
    const small = [
      // 0 (order 1)
      ['00000000000000000000000000000000000000000000000000000000',
       '00000000000000000000000000000000000000000000000000000000'].join(''),
      // 1 (order 2, invalid, rejected)
      ['01000000000000000000000000000000000000000000000000000000',
       '00000000000000000000000000000000000000000000000000000000'].join(''),
      // p - 1 (order 4)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff'].join(''),
      // p (order 1)
      ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff'].join(''),
      // p + 1 (order, invalid, rejected)
      ['00000000000000000000000000000000000000000000000000000000',
       'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'].join('')
    ];

    const key = x448.privateKeyGenerate();

    for (const str of small) {
      const pub = Buffer.from(str, 'hex');

      assert.throws(() => x448.derive(pub, key), {
        message: /^Invalid (point|public key)\.$/
      });
    }
  });

  it('should test small order points', () => {
    const small = [
      // 0 (order 1)
      ['00000000000000000000000000000000000000000000000000000000',
       '00000000000000000000000000000000000000000000000000000000'].join(''),
      // p - 1 (order 4)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff'].join(''),
      // p (order 1)
      ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff'].join('')
    ];

    for (const str of small) {
      const pub = Buffer.from(str, 'hex');

      assert(x448.publicKeyVerify(pub));
      assert(x448.publicKeyIsSmall(pub));
      assert(x448.publicKeyHasTorsion(pub));
    }

    {
      const priv = x448.privateKeyGenerate();
      const pub = x448.publicKeyCreate(priv);

      assert(x448.publicKeyVerify(pub));
      assert(!x448.publicKeyIsSmall(pub));
      assert(!x448.publicKeyHasTorsion(pub));
    }
  });

  it('should do convert to edwards and back', () => {
    const priv = x448.privateKeyGenerate();
    const pub = x448.publicKeyCreate(priv);
    const ed = x448.publicKeyConvert(pub, false);
    const mont = ed448.publicKeyConvert(ed);

    assert.bufferEqual(mont, pub);
  });

  it('should do elligator2', () => {
    const u1 = Buffer.from(''
      + '72ad074f3dbfbb3927125fab1f4023a408adc0ab1cbbbd6556615e3d'
      + '67501a428120ac1556a467734b1ad6820734d2100f0ed88510bd3e14', 'hex');

    const p1 = x448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, ''
      + '6bd0c1ee9599249bff3276e2a8279bea5e62e47f6507656826fe0182'
      + '3a0580129b6df46dabe81c7559a7028344b50da7682423586d6e80dd');

    const u2 = x448.publicKeyToUniform(p1, rng.randomInt() & 1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2, rng.randomInt() & 1);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should test random oracle encoding', () => {
    const bytes = SHAKE256.digest(Buffer.from('turn me into a point'), 112);
    const pub = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + 'bbf9b3970b4f192c2615dd66abbfe4f51b2b695da44d1578389de049'
      + '043d83433a011ef906f7154c96fefd592d1981283fb99e8925a45f30');
  });

  it('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHAKE256.digest(Buffer.from('turn me into a point'), 56);
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + '6fee3c18014c2c61dc1bc145c224d2b5c2e48ccbb41e007927d08435'
      + '6dd0a932c189fa810622612d982a0326760c6e74b39866bbd905f9df');
  });

  if (x448.native === 2) {
    const native = x448;
    const curve = require('../lib/js/x448');

    it('should invert elligator (native vs. js)', () => {
      const priv = native.privateKeyGenerate();
      const pub = native.publicKeyCreate(priv);

      for (let i = 0; i < 2; i++) {
        let bytes1 = null;
        let bytes2 = null;

        try {
          bytes1 = native.publicKeyToUniform(pub, i);
        } catch (e) {
          ;
        }

        try {
          bytes2 = curve.publicKeyToUniform(pub, i);
        } catch (e) {
          ;
        }

        if (!bytes1) {
          assert(!bytes2);
          continue;
        }

        assert(bytes2);
        assert.bufferEqual(bytes1, bytes2);
        assert.bufferEqual(native.publicKeyFromUniform(bytes1), pub);
      }

      const bytes = native.publicKeyToHash(pub, 0);

      assert.bufferEqual(native.publicKeyFromHash(bytes), pub);
    });
  }

  it('should invert elligator squared', () => {
    const priv = x448.privateKeyGenerate();
    const pub = x448.publicKeyCreate(priv);
    const bytes = x448.publicKeyToHash(pub, 0);
    const out = x448.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should do elligator squared with torsion points', () => {
    const small = [
      ['00000000000000000000000000000000000000000000000000000000',
       '00000000000000000000000000000000000000000000000000000000'].join(''),
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff'].join('')
    ];

    for (let i = 0; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');
      const bytes = x448.publicKeyToHash(pub, 0);
      const out = x448.publicKeyFromHash(bytes);

      assert.bufferEqual(out, pub);
    }
  });

  it('should do covert ecdh', () => {
    const alicePriv = x448.privateKeyGenerate();
    const alicePub = x448.publicKeyCreate(alicePriv);
    const bobPriv = x448.privateKeyGenerate();
    const bobPub = x448.publicKeyCreate(bobPriv);
    const alicePreimage = x448.publicKeyToHash(alicePub, 2); // Add 4-torsion.
    const alicePub2 = x448.publicKeyFromHash(alicePreimage);
    const bobPreimage = x448.publicKeyToHash(bobPub, 1); // Add 2-torsion.
    const bobPub2 = x448.publicKeyFromHash(bobPreimage);

    assert(!x448.publicKeyHasTorsion(alicePub));
    assert(!x448.publicKeyHasTorsion(bobPub));
    assert(x448.publicKeyHasTorsion(alicePub2));
    assert(x448.publicKeyHasTorsion(bobPub2));

    const aliceSecret = x448.derive(bobPub, alicePriv);
    const bobSecret = x448.derive(alicePub, bobPriv);
    const aliceSecret2 = x448.derive(bobPub2, alicePriv);
    const bobSecret2 = x448.derive(alicePub2, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);
    assert.bufferEqual(aliceSecret2, bobSecret2);
    assert.bufferEqual(aliceSecret, aliceSecret2);
    assert.bufferEqual(bobSecret, bobSecret2);
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
  });
});
