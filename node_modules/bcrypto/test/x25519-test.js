'use strict';

const assert = require('bsert');
const RNG = require('./util/rng');
const SHA256 = require('../lib/sha256');
const SHA512 = require('../lib/sha512');
const ed25519 = require('../lib/ed25519');
const x25519 = require('../lib/x25519');

const vectors = [
  // From: https://github.com/golang/crypto/blob/master/curve25519/testvectors_test.go
  [
    Buffer.from('db5f32b7f841e7a1a00968effded12735fc47a3eb13b579aacadeae80939a7dd', 'hex'),
    Buffer.from('668fb9f76ad971c81ac900071a1560bce2ca00cac7e67af99348913761434014', 'hex'),
    Buffer.from('090d85e599ea8e2beeb61304d37be10ec5c905f9927d32f42a9a0afb3e0b4074', 'hex')
  ],
  [
    Buffer.from('090d0701f8fde28f70043b83f2346225419b18a7f27e9e3d2bfd04e10f3d213e', 'hex'),
    Buffer.from('636695e34f75b9a279c8706fad1289f2c0b1e22e16f8b8861729c10a582958af', 'hex'),
    Buffer.from('bf26ec7ec413061733d44070ea67cab02a85dc1be8cfe1ff73d541cc08325506', 'hex')
  ],
  [
    Buffer.from('f8a8421c7d21a92db3ede979e1fa6acb062b56b1885c71c51153ccb880ac7315', 'hex'),
    Buffer.from('734181cd1a9406522a56fe25e43ecbf0295db5ddd0609b3c2b4e79c06f8bd46d', 'hex'),
    Buffer.from('1176d01681f2cf929da2c7a3df66b5d7729fd422226fd6374216bf7e02fd0f62', 'hex')
  ],
  [
    Buffer.from('d3ead07a0008f44502d5808bffc8979f25a859d5adf4312ea487489c30e01b3b', 'hex'),
    Buffer.from('1f70391f6ba858129413bd801b12acbf662362825ca2509c8187590a2b0e6172', 'hex'),
    Buffer.from('f8482f2e9e58bb067e86b28724b3c0a3bbb5073e4c6acd93df545effdbba505f', 'hex')
  ],
  [
    Buffer.from('4d254c8083d87f1a9b3ea731efcff8a6f2312d6fed680ef829185161c8fc5060', 'hex'),
    Buffer.from('3a7ae6cf8b889d2b7a60a470ad6ad999206bf57d9030ddf7f8680c8b1a645daa', 'hex'),
    Buffer.from('47b356d5818de8efac774b714c42c44be68523dd57dbd73962d5a52631876237', 'hex')
  ],
  [
    Buffer.from('6ab95d1abe68c09b005c3db9042cc91ac849f7e94a2a4a9b893678970b7b95bf', 'hex'),
    Buffer.from('203161c3159a876a2beaec29d2427fb0c7c30d382cd013d27cc3d393db0daf6f', 'hex'),
    Buffer.from('11edaedc95ff78f563a1c8f15591c071dea092b4d7ecaac8e0387b5a160c4e5d', 'hex')
  ],
  [
    Buffer.from('2e784e04ca0073336256a839255ed2f7d4796a64cdc37f1eb0e5c4c8d1d1e0f5', 'hex'),
    Buffer.from('13d65491fe75f203a008b4415abc60d532e695dbd2f1e803accb34b2b72c3d70', 'hex'),
    Buffer.from('563e8c9adaa7d73101b0f2ead3cae1ea5d8fcd5cd36080bb8e6ec03d61450917', 'hex')
  ],
  [
    Buffer.from('8b549b2df642d3b25fe8380f8cc4375f99b7bb4d275f779f3b7c81b8a2bbc129', 'hex'),
    Buffer.from('686f7da93bf268e588069831f047163f33589989d0826e9808fb678ed57e6749', 'hex'),
    Buffer.from('01476965426b6171749a8add9235025ce5f557fe4009f7393044ebbb8ae95279', 'hex')
  ],
  [
    Buffer.from('8b6b9d08f61fc91fe8b32953c42340f007b571dcb0a56d10724ecef9950cfb25', 'hex'),
    Buffer.from('82d61ccedc806a6060a3349a5e87cbc7ac115e4f87776250ae256098a7c44959', 'hex'),
    Buffer.from('9c49941f9c4f1871fa4091fed716d34999c95234edf2fdfba6d14a5afe9e0558', 'hex')
  ],
  [
    Buffer.from('1acd292784f47919d455f887448358610bb9459670eb99dee46005f689ca5fb6', 'hex'),
    Buffer.from('7dc76404831397d5884fdf6f97e1744c9eb118a31a7b23f8d79f48ce9cad154b', 'hex'),
    Buffer.from('00f43c022e94ea3819b036ae2b36b2a76136af628a751fe5d01e030d44258859', 'hex')
  ],
  [
    Buffer.from('55caff2181f2136b0ed0e1e2994448e16cc970646a983d140dc4eab3d94c284e', 'hex'),
    Buffer.from('fbc4511d23a682ae4efd08c8179c1c067f9c8be79bbc4eff5ce296c6bc1ff445', 'hex'),
    Buffer.from('ae39d816532345794d2691e0801caa525fc3634d402ce9580b3338b46f8bb972', 'hex')
  ],
  [
    Buffer.from('57733f2d869690d0d2edaec9523daa2da95445f44f5783c1faec6c3a982818f3', 'hex'),
    Buffer.from('4e060ce10cebf095098716c86619eb9f7df66524698ba7988c3b9095d9f50134', 'hex'),
    Buffer.from('a61e74552cce75f5e972e424f2ccb09c83bc1b67014748f02c371a209ef2fb2c', 'hex')
  ],
  [
    Buffer.from('6797c2e7dc92ccbe7c056bec350ab6d3bd2a2c6bc5a807bbcae1f6c2af803644', 'hex'),
    Buffer.from('5c492cba2cc892488a9ceb9186c2aac22f015bf3ef8d3ecc9c4176976261aab1', 'hex'),
    Buffer.from('fcf307dfbc19020b28a6618c6c622f317e45967dacf4ae4a0a699a10769fde14', 'hex')
  ],
  [
    Buffer.from('2c75d85142ecad3e69447004540c1c23548fc8f486251b8a19463f3df6f8ac61', 'hex'),
    Buffer.from('ea33349296055a4e8b192e3c23c5f4c844282a3bfc19ecc9dc646a42c38dc248', 'hex'),
    Buffer.from('5dcab68973f95bd3ae4b34fab949fb7fb15af1d8cae28cd699f9c1aa3337342f', 'hex')
  ],
  [
    Buffer.from('f7cae18d8d36a7f56117b8b70e2552277ffc99df8756b5e138bf6368bc87f74c', 'hex'),
    Buffer.from('4f2979b1ec8619e45c0a0b2b520934541ab94407b64d190a76f32314efe184e7', 'hex'),
    Buffer.from('e4e634ebb4fb664fe8b2cfa1615f00e6466fff732ce1f8a0c8d2727431d16f14', 'hex')
  ],
  [
    Buffer.from('3c235edc02f9115641dbf516d5de8a735d6e53e22aa2ac143656045ff2e95249', 'hex'),
    Buffer.from('f5d8a927901d4fa4249086b7ffec24f5297d80118e4ac9d3fc9a8237951e3b7f', 'hex'),
    Buffer.from('ab9515ab14af9d270e1dae0c5680cbc8880bd8a8e7eb67b4da42a661961efc0b', 'hex')
  ],
  // From RFC 7748
  [
    Buffer.from('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c', 'hex'),
    Buffer.from('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4', 'hex'),
    Buffer.from('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552', 'hex')
  ],
  [
    Buffer.from('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493', 'hex'),
    Buffer.from('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d', 'hex'),
    Buffer.from('95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957', 'hex')
  ]
];

// From RFC 7748
const intervals = [
  Buffer.from('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079', 'hex'),
  Buffer.from('684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51', 'hex'),
  Buffer.from('7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424', 'hex')
];

const scalarVectors = [
  [
    Buffer.from('60687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2965', 'hex'),
    Buffer.from('2832db6c2c0a6235fb1397e8225ea85e0f0e6e8c7b126d0016ccbde0e667155e', 'hex'),
    Buffer.from('b278f833def9281b8147b16b91d3234a97edd5ebdab92037b5bb74daa6428862', 'hex')
  ],
  [
    Buffer.from('10771355e46cd47c71ed1721fd5319b383cca3a1f9fce3aa1c8cd3bd37af2057', 'hex'),
    Buffer.from('f815c0d3ebe314fad720a08b839a004c2e6386f5aecc19ec74807d1920cb6a6b', 'hex'),
    Buffer.from('2affba2f5b84ebbd4e027557332d86fac418154a12dd87f79a3543f957e28362', 'hex')
  ],
  [
    Buffer.from('306da11fe3ab3d0eaaddb418ccb49b5426d5c2504f526f7766580f6e45984e7b', 'hex'),
    Buffer.from('4091a5c79ffdc79883036503ca551673c09deec28df432a8d88debc7fa2ec95e', 'hex'),
    Buffer.from('631e3c086374f3b59280d855fbb073161c69cfa9da1806f2259df078aaaa247a', 'hex')
  ],
  [
    Buffer.from('581adcb5797c2eff1ba0460af9324ac6df5b6ffb66be6df2547872c2f29ba442', 'hex'),
    Buffer.from('689b711ce5d3749ece29463110b6164dbb28dda28902586bf66e865e8c29c350', 'hex'),
    Buffer.from('fed8c10094ac77b1f3c9a3e85d425d78cc4ade141e09e3018abe96b4cc433670', 'hex')
  ],
  [
    Buffer.from('486e6acef5953a6a2087d8dd7d38a49b3ca0627d8ab339872ce56c5bd3b5a152', 'hex'),
    Buffer.from('f03587bc89fe4882c7c889302511ffd738d136129b9f5be4c492cb4948a93a49', 'hex'),
    Buffer.from('08a6638d9e1a1af96286ae6ff43d7b691ad39cc0a132c68507e10bbb232c666d', 'hex')
  ]
];

describe('X25519', function() {
  const rng = new RNG();

  for (const [pub, key, expect] of vectors) {
    it(`should compute secret: ${expect.toString('hex', 0, 16)}...`, () => {
      const result = x25519.derive(pub, key);
      assert.bufferEqual(result, expect);
    });
  }

  for (const [scalar, tweak, expect] of scalarVectors) {
    it(`should convert secret: ${expect.toString('hex', 0, 16)}...`, () => {
      const edPub = ed25519.publicKeyFromScalar(scalar);
      const edPoint = ed25519.deriveWithScalar(edPub, tweak);
      const pub = ed25519.publicKeyConvert(edPub);
      const result = ed25519.publicKeyConvert(edPoint);

      assert.bufferEqual(result, expect);
      assert.bufferEqual(x25519.derive(pub, tweak), expect);
    });
  }

  it('should do repeated scalar multiplication', () => {
    let k = Buffer.alloc(32, 0x00);
    let u = Buffer.alloc(32, 0x00);
    let i = 0;

    k[0] = 9;
    u[0] = 9;

    for (; i < 1; i++)
      [u, k] = [k, x25519.derive(u, k)];

    assert.bufferEqual(k, intervals[0]);

    for (; i < 1000; i++)
      [u, k] = [k, x25519.derive(u, k)];

    assert.bufferEqual(k, intervals[1]);

    // for (; i < 1000000; i++)
    //   [u, k] = [k, x25519.derive(u, k)];
    //
    // assert.bufferEqual(k, intervals[2]);
  });

  for (let i = 0; i < 20; i++) {
    it(`should exchange keys after point conversion (${i})`, () => {
      const scalar = ed25519.scalarGenerate();
      const edPub = ed25519.publicKeyFromScalar(scalar);
      const tweak = ed25519.scalarGenerate();
      const edPoint = ed25519.deriveWithScalar(edPub, tweak);
      const pub = ed25519.publicKeyConvert(edPub);
      const expect = ed25519.publicKeyConvert(edPoint);
      const result = x25519.derive(pub, tweak);

      assert.bufferEqual(result, expect);
    });
  }

  it('should do scalar base multiplication (edwards)', () => {
    const expect =
      '89161fde887b2b53de549af483940106ecc114d6982daa98256de23bdf77661a';

    let key = Buffer.alloc(32, 0x00);

    key[0] = 1;

    for (let i = 0; i < 200; i++)
      key = x25519.publicKeyCreate(key);

    assert.bufferEqual(key, expect, 'hex');
  });

  it('should ignore high bit', () => {
    const s = rng.randomBytes(32);
    const u = rng.randomBytes(32);

    u[31] &= 0x7f;
    const hi0 = x25519.derive(u, s);

    u[31] |= 0x80;
    const hi1 = x25519.derive(u, s);

    assert.bufferEqual(hi0, hi1);
  });

  it('should reject small order points', () => {
    // Full list from: https://cr.yp.to/ecdh.html
    //
    // See also:
    // https://github.com/jedisct1/libsodium/blob/cec56d8/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L17
    // https://eprint.iacr.org/2017/806.pdf
    const small = [
      // 0 (order 1 & 2)
      '0000000000000000000000000000000000000000000000000000000000000000',
      // 1 (order 4)
      '0100000000000000000000000000000000000000000000000000000000000000',
      // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
      'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
      // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
      '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
      // p - 1 (invalid)
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // p (order 1 & 2)
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // p + 1 (order 4)
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
      // The hi bit is unset for these:
      // p + 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
      // 'cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880',
      // p + 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
      // '4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7',
      // 2 * p - 1 (invalid)
      // 'd9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      // 2 * p (order 1 & 2)
      // 'daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      // 2 * p + 1 (order 4)
      // 'dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    ];

    const key = x25519.privateKeyGenerate();

    for (const str of small) {
      const pub = Buffer.from(str, 'hex');

      assert.throws(() => x25519.derive(pub, key), {
        message: /^Invalid (point|public key)\.$/
      });
    }
  });

  it('should test small order points', () => {
    const small = [
      // 0 (order 1 & 2)
      '0000000000000000000000000000000000000000000000000000000000000000',
      // 1 (order 4)
      '0100000000000000000000000000000000000000000000000000000000000000',
      // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
      'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
      // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
      '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
      // p - 1 (invalid)
      // 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // p (order 1 & 2)
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // p + 1 (order 4)
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
    ];

    for (const str of small) {
      const pub = Buffer.from(str, 'hex');

      assert(x25519.publicKeyVerify(pub));
      assert(x25519.publicKeyIsSmall(pub));
      assert(x25519.publicKeyHasTorsion(pub));
    }

    {
      const priv = x25519.privateKeyGenerate();
      const pub = x25519.publicKeyCreate(priv);

      assert(x25519.publicKeyVerify(pub));
      assert(!x25519.publicKeyIsSmall(pub));
      assert(!x25519.publicKeyHasTorsion(pub));
    }
  });

  it('should do convert to edwards and back', () => {
    const priv = x25519.privateKeyGenerate();
    const pub = x25519.publicKeyCreate(priv);
    const ed = x25519.publicKeyConvert(pub, false);
    const mont = ed25519.publicKeyConvert(ed);

    assert.bufferEqual(mont, pub);
  });

  it('should do elligator2', () => {
    const u1 = rng.randomBytes(32);
    const p1 = x25519.publicKeyFromUniform(u1);
    const u2 = x25519.publicKeyToUniform(p1, rng.randomInt() & 1);
    const p2 = x25519.publicKeyFromUniform(u2);
    const u3 = x25519.publicKeyToUniform(p2, rng.randomInt() & 1);
    const p3 = x25519.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should test random oracle encoding', () => {
    const bytes = SHA512.digest(Buffer.from('turn me into a point'));
    const pub = x25519.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub,
      '88ddc62a46c484db54b6d6cb6badb173e0e7d9785385691443233983865acc4d');
  });

  it('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHA256.digest(Buffer.from('turn me into a point'));
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = x25519.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub,
      '7b9965e30b586bab509c34d657d8be30fad1b179470f2f70a6c728092e000062');
  });

  if (x25519.native === 2) {
    const native = x25519;
    const curve = require('../lib/js/x25519');

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

        bytes1[31] &= ~0x80;
        bytes2[31] &= ~0x80;

        assert.bufferEqual(bytes1, bytes2);
        assert.bufferEqual(native.publicKeyFromUniform(bytes1), pub);
      }

      const bytes = native.publicKeyToHash(pub, 0);

      assert.bufferEqual(native.publicKeyFromHash(bytes), pub);
    });
  }

  it('should invert elligator squared', () => {
    const priv = x25519.privateKeyGenerate();
    const pub = x25519.publicKeyCreate(priv);
    const bytes = x25519.publicKeyToHash(pub, 0);
    const out = x25519.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should do elligator squared with torsion points', () => {
    const small = [
      '0000000000000000000000000000000000000000000000000000000000000000',
      '0100000000000000000000000000000000000000000000000000000000000000',
      'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
      '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'
    ];

    for (const str of small) {
      const pub = Buffer.from(str, 'hex');
      const bytes = x25519.publicKeyToHash(pub, 0);
      const out = x25519.publicKeyFromHash(bytes);

      assert.bufferEqual(out, pub);
    }
  });

  it('should do covert ecdh', () => {
    const alicePriv = x25519.privateKeyGenerate();
    const alicePub = x25519.publicKeyCreate(alicePriv);
    const bobPriv = x25519.privateKeyGenerate();
    const bobPub = x25519.publicKeyCreate(bobPriv);
    const alicePreimage = x25519.publicKeyToHash(alicePub, 7); // Add 8-torsion.
    const alicePub2 = x25519.publicKeyFromHash(alicePreimage);
    const bobPreimage = x25519.publicKeyToHash(bobPub, 2); // Add 4-torsion.
    const bobPub2 = x25519.publicKeyFromHash(bobPreimage);

    assert(!x25519.publicKeyHasTorsion(alicePub));
    assert(!x25519.publicKeyHasTorsion(bobPub));
    assert(x25519.publicKeyHasTorsion(alicePub2));
    assert(x25519.publicKeyHasTorsion(bobPub2));

    const aliceSecret = x25519.derive(bobPub, alicePriv);
    const bobSecret = x25519.derive(alicePub, bobPriv);
    const aliceSecret2 = x25519.derive(bobPub2, alicePriv);
    const bobSecret2 = x25519.derive(alicePub2, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);
    assert.bufferEqual(aliceSecret2, bobSecret2);
    assert.bufferEqual(aliceSecret, aliceSecret2);
    assert.bufferEqual(bobSecret, bobSecret2);
  });

  it('should test x25519 api', () => {
    const alicePriv = x25519.privateKeyGenerate();
    const alicePub = x25519.publicKeyCreate(alicePriv);
    const bobPriv = x25519.privateKeyGenerate();
    const bobPub = x25519.publicKeyCreate(bobPriv);

    assert(x25519.privateKeyVerify(alicePriv));
    assert(x25519.privateKeyVerify(bobPriv));
    assert(x25519.publicKeyVerify(alicePub));
    assert(x25519.publicKeyVerify(bobPub));

    assert(alicePriv.length === 32);
    assert(alicePub.length === 32);

    const aliceSecret = x25519.derive(bobPub, alicePriv);
    const bobSecret = x25519.derive(alicePub, bobPriv);

    assert(aliceSecret.length === 32);

    assert.bufferEqual(aliceSecret, bobSecret);

    const rawPriv = x25519.privateKeyExport(alicePriv);
    const rawPub = x25519.publicKeyExport(alicePub);

    assert.bufferEqual(x25519.privateKeyImport(rawPriv), alicePriv);
    assert.bufferEqual(x25519.publicKeyImport(rawPub), alicePub);
  });
});
