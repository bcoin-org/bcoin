'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed25519 = require('../lib/ed25519');
const x25519 = require('../lib/x25519');
const SHA256 = require('../lib/sha256');
const SHA512 = require('../lib/sha512');
const derivations = require('./data/ed25519.json');
const json = require('./data/ed25519-input.json');
const rfc8032 = require('./data/rfc8032-vectors.json');
const {env} = process;
const vectors = env.CI || ed25519.native === 2 ? json : json.slice(0, 128);

describe('Ed25519', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed25519.size);
    const secret = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(secret);

    assert(ed25519.publicKeyVerify(pub));

    const sig = ed25519.sign(msg, secret);

    assert(ed25519.verify(msg, sig, pub));

    sig[0] ^= 1;

    assert(!ed25519.verify(msg, sig, pub));

    assert.bufferEqual(
      ed25519.privateKeyImport(ed25519.privateKeyExport(secret)),
      secret);
  });

  it('should allow points at infinity', () => {
    // Fun fact about edwards curves: points
    // at infinity can actually be serialized.
    const msg = Buffer.from(
      '03d95e0b801ab94cfe723bc5243284a32b19a629b9cb36a8a46fcc000b6e7191',
      'hex');

    const sig = Buffer.from(''
      + '0100000000000000000000000000000000000000000000000000000000000000'
      + '0000000000000000000000000000000000000000000000000000000000000000'
      , 'hex');

    const pub = Buffer.from(
      'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
      'hex');

    assert(!ed25519.verify(msg, sig, pub));

    const inf = Buffer.from(
      '0100000000000000000000000000000000000000000000000000000000000000',
      'hex');

    assert(ed25519.publicKeyVerify(inf));
    assert(ed25519.publicKeyIsInfinity(inf));
    assert(ed25519.scalarIsZero(sig.slice(32)));
    assert(ed25519.verify(msg, sig, inf));
  });

  it('should fail to validate malleated keys', () => {
    // x = 0, y = 1, sign = 1
    const hex1 = '01000000000000000000000000000000'
               + '00000000000000000000000000000080';

    // x = 0, y = -1, sign = 1
    const hex2 = 'ecffffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffffffff';

    const key1 = Buffer.from(hex1, 'hex');
    const key2 = Buffer.from(hex2, 'hex');

    assert(!ed25519.publicKeyVerify(key1));
    assert(!ed25519.publicKeyVerify(key2));

    key1[31] &= ~0x80;
    key2[31] &= ~0x80;

    assert(ed25519.publicKeyVerify(key1));
    assert(ed25519.publicKeyVerify(key2));
  });

  it('should validate small order points', () => {
    const small = [
      // 0 (order 1)
      '0100000000000000000000000000000000000000000000000000000000000000',
      // 0 (order 2)
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // 1 (order 4)
      '0000000000000000000000000000000000000000000000000000000000000080',
      '0000000000000000000000000000000000000000000000000000000000000000',
      // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
      // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'
    ];

    const key = ed25519.scalarGenerate();

    for (let i = 0; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(ed25519.publicKeyVerify(pub));
      assert.throws(() => ed25519.deriveWithScalar(pub, key));
    }
  });

  it('should test small order points', () => {
    const small = [
      // 0 (order 1)
      '0100000000000000000000000000000000000000000000000000000000000000',
      // 0 (order 2)
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // 1 (order 4)
      '0000000000000000000000000000000000000000000000000000000000000080',
      '0000000000000000000000000000000000000000000000000000000000000000',
      // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
      // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'
    ];

    {
      const pub = Buffer.from(small[0], 'hex');

      assert(ed25519.publicKeyIsInfinity(pub));
      assert(!ed25519.publicKeyIsSmall(pub));
      assert(!ed25519.publicKeyHasTorsion(pub));
    }

    for (let i = 1; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(!ed25519.publicKeyIsInfinity(pub));
      assert(ed25519.publicKeyIsSmall(pub));
      assert(ed25519.publicKeyHasTorsion(pub));
    }

    {
      const priv = ed25519.privateKeyGenerate();
      const pub = ed25519.publicKeyCreate(priv);

      assert(!ed25519.publicKeyIsInfinity(pub));
      assert(!ed25519.publicKeyIsSmall(pub));
      assert(!ed25519.publicKeyHasTorsion(pub));
    }
  });

  it('should test scalar zero', () => {
    // n = 0
    const hex1 = 'edd3f55c1a631258d69cf7a2def9de14'
               + '00000000000000000000000000000010';

    // n - 1 = -1
    const hex2 = 'ecd3f55c1a631258d69cf7a2def9de14'
               + '00000000000000000000000000000010';

    assert(ed25519.scalarIsZero(Buffer.alloc(32, 0x00)));
    assert(!ed25519.scalarIsZero(Buffer.alloc(32, 0x01)));

    assert(ed25519.scalarIsZero(Buffer.from(hex1, 'hex')));
    assert(!ed25519.scalarIsZero(Buffer.from(hex2, 'hex')));
  });

  it('should validate signatures with small order points', () => {
    const json = [
      // (-1, -1)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        '0100000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0100000000000000000000000000000000000000000000000000000000000000',
        true,
        true
      ],

      // (-1, -1)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        '0100000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
        false,
        false
      ],

      // (0, 0)
      [
        'afe9a024a60f51dadb0353824aba4ee1395a0eda2bb27348768472f948b6c0db',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        false,
        true
      ],

      // (0, 1)
      [
        'ccc1291d1c67dcbb960894b4b9d4a9e2240d15bcb4d9fbcfce72b214ea6fad88',
        '0000000000000000000000000000000000000000000000000000000000000080',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        false,
        true
      ],

      // (1, 1)
      [
        '111fe159fd919f9569a0732de49c0f03e75f93e221edaf1e9c3ead59fa742527',
        '0000000000000000000000000000000000000000000000000000000000000080',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (1, 2)
      [
        'cafea1043bb0f7c3600772f5e3e4710f2d9d2e8e2043496125975fb169c5a2e5',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (1, 3)
      [
        '70e7cfc26ae590053b2234614a1323fca01dd3f3965f58b4b40ae7ed4858f341',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (2, 2)
      [
        'd01dc52fbbf471b81bb8592d7461ad459f7cf74da0e8d027fcf2932aeb03a468',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        false,
        true
      ],

      // (2, 5)
      [
        'ea6ca21cc5e5da0363ce87883412ed774a11eed97068920030e13b9c984f21e1',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000000',
        false,
        true
      ],

      // (4, 6)
      [
        'f9ff9b3dbbf2b6dc3d5d49fbd6fe03ec0bc014abcee4a04134cd9043dbe33237',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
        '0000000000000000000000000000000000000000000000000000000000000000',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
        true,
        true
      ]
    ];

    const vectors = [];

    for (const [m, r, s, p, r1, r2] of json) {
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      vectors.push([msg, sig, pub, r1, r2]);
    }

    const batch = [];

    for (const [msg, sig, pub, res1, res2] of vectors) {
      assert.strictEqual(ed25519.verify(msg, sig, pub), res1);
      assert.strictEqual(ed25519.verifySingle(msg, sig, pub), res2);

      if (res2)
        batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed25519.verifyBatch(batch), true);
  });

  it('should validate signatures with torsion components', () => {
    const json = [
      // (0, 0)
      [
        'ea3001a37ed97f712b5ccac99a46ee3c1bd55dfa4489c169b91a284c94cf6870',
        '2974febee11b1373fbec0546ab43ec72f62777ff2d476f590fe98e2bb0adc4fd',
        'ee089ecff4a991e098c51638ce220a146dbd29be75dddae996d746c44286440e',
        '66c2d7d3b5a0264fb039b6d1d735192ff7157a664fe87ed15c254dc59fa14067',
        true,
        true
      ],

      // (0, 1)
      [
        '567c6518fa1cfac1f48878034b028e62325b80f8c556dfe1018dc2b9c3a96d0b',
        'a3d0566b5714e5de2e46d928ff09d1a7b1bf7d539503f2bfb351771b6e643674',
        '227319f7f4e72d996bcfe4461a66d71f70e2944e50dd1d86ebd7a065f2549f00',
        '884e2fb0e43cfe5252ff71404fcb2985e0a428670a3d75c844b2cc54bf751c14',
        false,
        true
      ],

      // (0, 1)
      [
        '1984db29072800cb09ff16971af888746d8d94998175ce7c02ce020c0b2e3ecd',
        '7467982669dee781d1a6e0c1df56f5a306256b153c1a44c2823f488b524979e5',
        '333a6ef747af4b8f17855ffdd813e8ff55d4d76b71d059c8213b763bdd41fd0c',
        'a7c4cb985dce43fa2ed7449bab14c646392c195d2e47808e586d1056659b9dd0',
        false,
        true
      ],

      // (1, 1)
      [
        '2a8c1b6cb31ef9f741ed13877bb59c1e17396b48519f5b0754635d8ec86c98ae',
        '5bc95e8daaa4fad481188ee87a29119dc3fc68ad2a059332173cb313f1301eb5',
        '89589b3efbcad293bd3ba337de613b779b70c2f2cc8656b538459988290fa208',
        'a2148a3e153c374b623f3342c9e7c36c2edaae0b8e3fa84f0134510da82045b5',
        true,
        true
      ],

      // (1, 1)
      [
        'cd383acf53cbfe295aee065c26fca46ca9aa86029e3d3fc90fc7c5cc21d9ce93',
        '92c316d4cbac2d9510dd1010f4a3837afec490038590d39ba1e391ce416a0008',
        '210d0615fa72b60e6b8abada74f8270953cf4717cb74de9c97940fec8e911906',
        'd6ffa0f51ffd05af7d45204f1d4056ba25ab995ca8eb01456a73ef26b5ec387d',
        false,
        true
      ],

      // (1, 2)
      [
        '48f2729c8a13616b8b0db7eacb553656ef5c39fb62dd6a05abffdfe53dfeec81',
        'c453b2478fc5bdfe3c8fd7d69d49185aa692612cb40f435a9bf8d9d7a8325a74',
        '08898cf81ff73ac863eed98800822cf27fcc9602218c2476114456ab5988b50d',
        'e44163cfc9c9ea02e35ba0fc8954cfc507b870e065ae853237bc76f83d5f8462',
        true,
        true
      ],

      // (1, 2)
      [
        'cdfb29c9b5a7f7b340739b8f4baf39300bd3d312ef4ae2a0c63309b7b85ec1ab',
        '26726e6488e2d1b99cd0fb568d6e50c1fe0e6d9f15104e7e59f8c3503468f7d4',
        'f7a4c3e9b54e81fbe527adde9161f81533132835e69c97f2ade7cce88677ca06',
        'cac20c3e0629d24031d4cb2cdb0e3730e5872aa4c4438e635713ad2e6917f35d',
        false,
        true
      ],

      // (1, 3)
      [
        '44975fe9ac5860e0adb44fd9da2601561ee9e2bd0d9330e8de6099218a44c4a1',
        'ffa0aa4312edb6747cef1d9d741491e190b232d46b303faf13dfda4ce3ccc186',
        '6dbdae5f7214efa4e0167eac864838b9ccb6a918e7879e3f8e92c3b3a1deee08',
        '489f4c34ae338622ed3e6dd133562f883c6871736df1aa0fe896d5e1214763a9',
        false,
        true
      ],

      // (2, 2)
      [
        '1e8f7bf9b6bbc6f44f4d0dad6d4ac73dd22df672a80b3b43009be13fdb90e6e9',
        '51c1dd5b9341dc93e9fb1d513f928d47a7fac5094316687ef569aeab728f0ad6',
        '6d258d8bcc0c7be0687c6ee3572fdb3df4188893462052aabd6bd7750ed2c209',
        '6a0c515aef13743ff0583cb4f7eace9bfce78d6a736a819b2c33f6f611aceffd',
        true,
        true
      ],

      // (2, 2)
      [
        '4892f822507861306a5eae42994ecd4ab67c0792f40595feb00a53345975269d',
        '7326662b35af2dcb8bc2208c8d1c266dd649075a251c7d6a5cd122fe41e4a96c',
        '8176e3769b3045e96f0379a78238b189984394fa91adf21046be3d29d317cb03',
        'b666f127f6bb54322d0ab1f36325ae9aeb6d33bfb27dac09721d00a7013b715b',
        false,
        true
      ],

      // (2, 5)
      [
        'a3865d3ba7c56bc4a939ffc4073c7df6a3489646a0742532d27a75a369991b0d',
        '0457d9578c8c349e5775667c48f6f295fee3d0dc9e9cac2c97a3829dda444c68',
        'd15945e767da3d1d7c774a31e85657b466348fb964ef486d765b3673cfa4ab0e',
        'f6d8e06fac3582ebcedbaa7c6092eae6bb876f157758a4a25017e44de5bc58d8',
        false,
        true
      ],

      // (4, 6)
      [
        '495f28fc18822be697001eab9ddd6deac91da5f4ba907be8f6cb71c3a330a08c',
        '6937da177a34ec59d03aa4bb97f85029521d89dabdea024c2e2347aa5cd4cc16',
        '93d0e2b229abc79ead84c4eadaab388cdcc99f4b9e912fd040190f2888f85d07',
        'e984754a3e1d218a12aa4bd8497dc11fa7eb094dc5cc5962a775df2dc4a430d0',
        false,
        true
      ]
    ];

    const vectors = [];

    for (const [m, r, s, p, r1, r2] of json) {
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      vectors.push([msg, sig, pub, r1, r2]);
    }

    const batch = [];

    for (const [msg, sig, pub, res1, res2] of vectors) {
      assert.strictEqual(ed25519.verify(msg, sig, pub), res1);
      assert.strictEqual(ed25519.verifySingle(msg, sig, pub), res2);
      assert(!ed25519.publicKeyIsSmall(pub));
      assert(ed25519.publicKeyHasTorsion(pub));

      batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed25519.verifyBatch(batch), true);
  });

  it('should reject non-canonical R value', () => {
    const json = [
      '9323f5ce965d97fd569c9af87dfe70ae599f6e178e63f210f7d8a0e15d98b0ef',
      'e9170093b59dff6472fc2705d576d1e0d51880c5ccc51ab2bf3531c0bf505ca5',
      '4d993bd274ce76684af9a6fef3a899ac4f2568fd501f3e5685d57b8c6e993200',
      'e3555db00fad12998e0d4d107e6b78d541f4f796bd747a25fc66e52ec68de8fe'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed25519.verify(msg, sig, pub), false);
    assert.strictEqual(ed25519.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical S value', () => {
    const json = [
      'f36eb2b77b4a45381753b3911a1d209384b591a64172968dd2dd0983a82fb835',
      'bf06a03fb431df03ddf943a0423ba3a96e1e08d3d8c35c40f31a19f476780e12',
      '52d25d60730fc3752f2795721ac98dbc2c1df63f10b7f9a007552bbf8db69d15',
      'd8c6f482b515dd8443d1835f6ed31bf3afe8a588d59617e26a18495d8824aa6d'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed25519.verify(msg, sig, pub), false);
    assert.strictEqual(ed25519.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical key', () => {
    const json = [
      '380b028b7e0124a0add4ee2b579b36851e0d739089b275648ea289185fd8cdb0',
      '6170b83c58abc3cd3e3d7c0df5a789d0d3b63b608c84f2cf8ebe3d0635422309',
      'a78437dec59823120b16d782b1c787273f8aee12c70dc3f0cc7efd508684060e',
      'c26ba75556c9a6124a9d1a5168ec71458009b8b5650593ea7264974511397c48'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed25519.verify(msg, sig, pub), false);
    assert.strictEqual(ed25519.verifySingle(msg, sig, pub), false);
  });

  it('should expand key', () => {
    const secret = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const [key, prefix] = ed25519.privateKeyExpand(secret);

    assert.bufferEqual(key,
      '00f8b1bd40cbf4c9642270f5b4eb4645514097f8ebe31c9f08be5e4fee6f9d5b',
      'hex');

    assert.bufferEqual(prefix,
      '93e1f48384097145d1981875ef22a4e64dc47e43e997beb9894a4603e09cc290',
      'hex');

    assert.bufferEqual(ed25519.privateKeyConvert(secret), key);
  });

  it('should do ECDH', () => {
    const alicePriv = ed25519.privateKeyGenerate();
    const alicePub = ed25519.publicKeyCreate(alicePriv);

    const bobPriv = ed25519.privateKeyGenerate();
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const bobSecret = ed25519.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const secret = aliceSecret;
    const xsecret = ed25519.publicKeyConvert(secret);
    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    assert.notBufferEqual(xsecret, secret);

    const xaliceSecret = x25519.derive(xbobPub,
      ed25519.privateKeyConvert(alicePriv));

    const xbobSecret = x25519.derive(xalicePub,
      ed25519.privateKeyConvert(bobPriv));

    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);
  });

  it('should do ECDH (with scalar)', () => {
    const aliceSeed = ed25519.privateKeyGenerate();
    const alicePriv = ed25519.privateKeyConvert(aliceSeed);
    const alicePub = ed25519.publicKeyFromScalar(alicePriv);

    assert.bufferEqual(alicePub, ed25519.publicKeyCreate(aliceSeed));

    const bobSeed = ed25519.privateKeyGenerate();
    const bobPriv = ed25519.privateKeyConvert(bobSeed);
    const bobPub = ed25519.publicKeyFromScalar(bobPriv);

    assert.bufferEqual(bobPub, ed25519.publicKeyCreate(bobSeed));

    const aliceSecret = ed25519.deriveWithScalar(bobPub, alicePriv);
    const bobSecret = ed25519.deriveWithScalar(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    const xaliceSecret = x25519.derive(xbobPub, alicePriv);
    const xbobSecret = x25519.derive(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xbobSecret);
  });

  it('should do ECDH (vector)', () => {
    const alicePriv = Buffer.from(
      '50ec6e55b18b882e06bdc12ff2f80f8f8fa68b04370b45439cf80b4e02610e1e',
      'hex');

    const bobPriv = Buffer.from(
      'c3fb48a8c4e961ab3edb799eea22ff1d07b803140734266748ea4c753dd3655d',
      'hex');

    const alicePub = ed25519.publicKeyCreate(alicePriv);
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const xsecret = Buffer.from(
      '4084c076e4ff79e8af71425c0c0b573057e9ebf36185ec8572ec161ddf6f2731',
      'hex');

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const xaliceSecret = ed25519.publicKeyConvert(aliceSecret);
    const bobSecret = ed25519.derive(alicePub, bobPriv);
    const xbobSecret = ed25519.publicKeyConvert(bobSecret);

    assert.notBufferEqual(aliceSecret, xsecret);
    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);

    const xalicePub = ed25519.publicKeyConvert(alicePub);
    const xbobPub = ed25519.publicKeyConvert(bobPub);

    const xaliceSecret2 = x25519.derive(xbobPub,
      ed25519.privateKeyConvert(alicePriv));

    const xbobSecret2 = x25519.derive(xalicePub,
      ed25519.privateKeyConvert(bobPriv));

    assert.bufferEqual(xaliceSecret2, xsecret);
    assert.bufferEqual(xbobSecret2, xsecret);
  });

  it('should generate keypair and sign with additive tweak', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const child = ed25519.publicKeyTweakAdd(pub, tweak);
    const sig = ed25519.signTweakAdd(msg, key, tweak);

    assert(ed25519.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const childPriv = ed25519.scalarTweakAdd(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);

    assert(ed25519.verify(msg, sig2, child));

    const real = ed25519.scalarReduce(ed25519.privateKeyConvert(key));
    const parent = ed25519.scalarTweakAdd(childPriv, ed25519.scalarNegate(tweak));

    assert.bufferEqual(parent, real);

    const tweakPub = ed25519.publicKeyFromScalar(tweak);
    const parentPub = ed25519.publicKeyCombine([childPub, ed25519.publicKeyNegate(tweakPub)]);

    assert.bufferEqual(parentPub, pub);
  });

  it('should generate keypair and sign with additive tweak (vector)', () => {
    const key = Buffer.from(
      'd0e9d24169a720d5e3d07f71bf68802ba365be3e85c3c20f974a8dd3e0c97f79',
      'hex');

    const pub = Buffer.from(
      'b85ea579c036d355451fc523b9e760a9a0bc21bbeda4fb86df90acdbcd39b410',
      'hex');

    const tweak = Buffer.from(
      'fff3c02b12bf6670ada449160e3e586043766dcc7beb12e804cc375a4cd319ff',
      'hex');

    const msg = Buffer.from(
      '03d95e0b801ab94cfe723bc5243284a32b19a629b9cb36a8a46fcc000b6e7191',
      'hex');

    const childExpect = Buffer.from(
      '1098877517226435d2ac8021b47fc87b4b8a9d15f6a19431eae10a6576c21837',
      'hex');

    const sigExpect = Buffer.from(''
      + '493d2b108b8350405d08672e6b5c3c6f9a5501aa07d4a44d40ae7f4d781fb146'
      + '941b4d9e7ac7a70e8fbf466ef806d791b431e6c832b4ad1d7310f45d5545200a'
      , 'hex');

    const child = ed25519.publicKeyTweakAdd(pub, tweak);
    const sig = ed25519.signTweakAdd(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should generate keypair and sign with multiplicative tweak', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const child = ed25519.publicKeyTweakMul(pub, tweak);

    assert(ed25519.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const sig = ed25519.signTweakMul(msg, key, tweak);

    const childPriv = ed25519.scalarTweakMul(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);

    assert(ed25519.verify(msg, sig2, child));

    const real = ed25519.scalarReduce(ed25519.privateKeyConvert(key));
    const parent = ed25519.scalarTweakMul(childPriv, ed25519.scalarInvert(tweak));

    assert.bufferEqual(parent, real);
  });

  it('should generate keypair and sign with multiplicative tweak (vector)', () => {
    const key = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const pub = Buffer.from(
      'f921f787e3e4e829a4be69a499f06e69d7bddbb7f6a90ccfba785faebd8d7a02',
      'hex');

    const tweak = Buffer.from(
      '7623971ec36c8557a8b1debe80f5f305989d0e51b62805c88590ee5b586a648a',
      'hex');

    const msg = Buffer.from(
      'e4a733e761eb1d0263fd713e7f815c947b29ed5a9140fa893bf59b11e1c32b80',
      'hex');

    const childExpect = Buffer.from(
      '78103d0a0342dca9a5044834f6dcf9472b8c1c3308fc4b49b13d451ddb7792f0',
      'hex');

    const sigExpect = Buffer.from(''
      + '4d1fa52a9dada415d4fff323257cfbdbaa571164873bcbd3e88acbe0a12d7e46'
      + 'e8b45144ed4ef9db77ac7e453e78aa4cd038f189bcff20d62de3339f80e51c01'
      , 'hex');

    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const sig = ed25519.signTweakMul(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor', () => {
    const cofactor = Buffer.alloc(32, 0x00);
    cofactor[0] = 8;

    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak_ = ed25519.scalarGenerate();
    const msg = random.randomBytes(32);
    const tweak = ed25519.scalarTweakMul(tweak_, cofactor);
    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const child_ = ed25519.publicKeyTweakMul(
      ed25519.publicKeyTweakMul(pub, tweak_),
      cofactor);

    assert.bufferEqual(child, child_);
    assert(ed25519.scalarVerify(tweak_));
    assert.notBufferEqual(child, pub);

    const sig = ed25519.signTweakMul(msg, key, tweak);

    const childPriv = ed25519.scalarTweakMul(ed25519.privateKeyConvert(key), tweak);
    const childPub = ed25519.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed25519.verify(msg, sig, child));

    const sig2 = ed25519.signWithScalar(msg, childPriv, msg);

    assert(ed25519.verify(msg, sig2, child));
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor (vector)', () => {
    const cofactor = Buffer.alloc(32, 0x00);
    cofactor[0] = 8;

    const key = Buffer.from(
      '5bc1d80b378c350663a6862f21599ee3b09fb4255a0dfad3d907d5ca7ab2b223',
      'hex');

    const pub = Buffer.from(
      'f921f787e3e4e829a4be69a499f06e69d7bddbb7f6a90ccfba785faebd8d7a02',
      'hex');

    const tweak_ = Buffer.from(
      '7623971ec36c8557a8b1debe80f5f305989d0e51b62805c88590ee5b586a648a',
      'hex');

    const msg = Buffer.from(
      'e4a733e761eb1d0263fd713e7f815c947b29ed5a9140fa893bf59b11e1c32b80',
      'hex');

    const childExpect = Buffer.from(
      'c616988e326d0b8be64e028942c68db3bc2f0808d5ca7c2e8b041e12b7b133fa',
      'hex');

    const sigExpect = Buffer.from(''
      + 'b958f47421ddb4fa1d012ab40a9b0c6d3850c85acf5ba313ffe77dd9b212f8a9'
      + '84ae985e13f77a441c012c5f3b16735de3a94bd2e3e72c80be6b41bbe2338305'
      , 'hex');

    const tweak = ed25519.scalarTweakMul(tweak_, cofactor);
    const child = ed25519.publicKeyTweakMul(pub, tweak);
    const sig = ed25519.signTweakMul(msg, key, tweak);

    assert.bufferEqual(child, childExpect);
    assert.bufferEqual(sig, sigExpect);

    assert(ed25519.verify(msg, sig, child));
  });

  it('should modulo scalar', () => {
    const scalar0 = Buffer.alloc(32, 0x00);
    const mod0 = ed25519.scalarReduce(scalar0);

    assert.bufferEqual(mod0,
      '0000000000000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar1 = Buffer.alloc(32, 0x00);

    scalar1[0] = 0x0a;

    const mod1 = ed25519.scalarReduce(scalar1);

    assert.bufferEqual(mod1,
      '0a00000000000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar2 = Buffer.alloc(32, 0xff);
    const mod2 = ed25519.scalarReduce(scalar2);

    assert.bufferEqual(mod2,
      '1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f',
      'hex');
  });

  it('should convert to montgomery and back', () => {
    const secret = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(secret);
    const sign = (pub[31] & 0x80) !== 0;
    const xpub = ed25519.publicKeyConvert(pub);
    const pub2 = x25519.publicKeyConvert(xpub, sign);

    assert.bufferEqual(pub2, pub);
  });

  it('should do elligator2 (edwards)', () => {
    const u1 = random.randomBytes(32);
    const p1 = ed25519.publicKeyFromUniform(u1);
    const u2 = ed25519.publicKeyToUniform(p1, random.randomInt() & 1);
    const p2 = ed25519.publicKeyFromUniform(u2);
    const u3 = ed25519.publicKeyToUniform(p2, random.randomInt() & 1);
    const p3 = ed25519.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should do elligator2 (mont)', () => {
    const u1 = random.randomBytes(32);
    const p1 = x25519.publicKeyFromUniform(u1);
    const u2 = x25519.publicKeyToUniform(p1, random.randomInt() & 1);
    const p2 = x25519.publicKeyFromUniform(u2);
    const u3 = x25519.publicKeyToUniform(p2, random.randomInt() & 1);
    const p3 = x25519.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should do elligator2 on curve25519 basepoint', () => {
    const p = Buffer.alloc(32, 0x00);
    p[0] = 9;

    const u = x25519.publicKeyToUniform(p, 0);
    const b = u[31] & 0x80;

    u[31] &= ~0x80;

    assert.bufferEqual(u,
      'b9762dadc1db2944f08aeb419d76f6b19e66fd47ec1076dfe7a7a1c4e0f0a92b');

    u[31] |= b;

    const q = x25519.publicKeyFromUniform(u);

    assert.bufferEqual(q, p);
  });

  it('should do elligator2 (vector)', () => {
    const u1 = Buffer.from(
      'be6d3d8d621562f8e1e9fdd93a760e7e7f27b93c0879a5414525b59bded49b61',
      'hex');

    const p1 = ed25519.publicKeyFromUniform(u1);

    assert.bufferEqual(p1,
      'cc2947ef03b978b3c7b418e2acdf52bc26f51457d7b21730c551bbcf4cb2e27d');

    const u2 = ed25519.publicKeyToUniform(p1, 0);

    u2[31] &= ~0x80;
    assert.bufferEqual(u2, u1);

    const p2 = ed25519.publicKeyFromUniform(u2);

    const u3 = ed25519.publicKeyToUniform(p2, 0);

    u3[31] &= ~0x80;
    assert.bufferEqual(u3, u1);

    const p3 = ed25519.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should invert elligator2 on troublesome point', () => {
    const p = Buffer.from(
      '6da9f400aefa72f6510793baaee019971b66114230d43802858f6e776fef7658',
      'hex');

    const u = x25519.publicKeyToUniform(p, 1);

    u[31] &= ~0x80;

    assert.bufferEqual(u,
      '65ec0b839037aed89162a872de9ae7e6effdc53a6d81ddf1f1965bf088a82d1a');
  });

  it('should pass elligator2 test vectors', () => {
    const preimages = [
      'ce8d733f2e31426d9c746463b545743c9ccca0bce5d106eaaca6e7dd59903aaa',
      'e8bb024c443213d566d9f3ad84e836e8309716981b4b9a60b40715c608da7e81',
      'be61a5fa1f36e7f85f7f54ca5088f5dca9361d3f0d34a6d0312d54aad6adeb96',
      'ed7917578f568fa2b20e8f7754fb4e643373d23a793ce528e054621222ab5891',
      '7bfad8410cacaa8c58e2b5624ef8c95b2f57e53e7702aae6374f3ac0b4787e47',
      '59b68382ceb7a71d10b118405c3dc3952e7215df3a4d4dd0178d8321bc0fcd9d',
      '676266d7cf7c5bc608215de592e6dd1e7922c01670191227197ed3356cf90cc6',
      '3872e840b5200b3a288e19867e9bd0a2b95ba841dd98ea8172540ed4576ac711',
      '69b29c580bebd2a1760edaf92da8b36c6d3d8f011dacc809598cd7cdd8a77814',
      '94bd595621de73d5e13b495d76d63148caecfda84943d2ce41599f52cba85760',
      'c00f79e923e66920eb42fd0107e8d0f56574654fffad6975f75b99f7c2c20b36',
      '0d1e5643436baf470977af896c7d7bb071ca26e23be06655dc9473200284f692',
      '904470ba572cca8b5bb7c717a0c572421da2a0dce63efd88af4635782f5994b7',
      'ee7722c827e2fb6ea6022b9eaf29ae4d7507c759fd5ca890011e5ca43fedf9f9',
      '8bd98284e596550d3f1ebcf64cb424e0ba1b2d1c4fc42e7d13c983f6abcb3de0',
      '768ae2764e1e9510be8b9a274a2705c808f2927d94a7a6ac90b8cf44909be380'
    ];

    const keys = [
      'aa5228edd5b5712fcf5c63b9c799d87ebfabdae7b1d71715929dfeeb45eb807c',
      '27843ba9ac2c896f4041690a90bbdbf39ef59194b386dc1d9cf190c892b1ace8',
      '5c4f1e1ea730b5ff8933147715075c1d1e01f9ffbf237c876d5a3a9dbfa778cc',
      '5285c85bb0079b003a90a2333e8ed85d39b7db472f34016e31edbf13a6ea6d1e',
      '8726d10374943ee7eedb962bc18b0480a413abd6cb47b915879b9eb472b3683f',
      'b355c40d935b4393cbd2d5789ba49deecf36e96e9b8b0df40d06406a5a03733b',
      '0a4abfafa7c77ac17ede7c097bc5e70476b4bc69bf31b7f0db4187faafa1c32a',
      '866cb2ede2364b3850da623ebbd8cb4bad7571e0a725af664f07e2cb744e5b3f',
      'c8e0fe848e6849937b04607d8d00a78cff4389c924577f55b735870909d2691c',
      'd8b82662d66b92ed79da8703edfdf5fdd71a154dc78d4ae9bc5b294573588bdb',
      'b6f7ddc10ae8862955f754df14dccd87960c883c3f8fc39cf02550f958d746b1',
      '3da8ce0962787688cb320b110fc4302182109d6bcaa68064de47b690973ba533',
      'd3616a04533601331c05007dd151287346ce5a249891f59eec8bb9372a865cdb',
      'f21c8394137b86d329280282132bb7a569e7370a6ca8d5a6c5f86f1bd254921a',
      '0ed3628cfd4b30e1a4b192b8b16d0a43cedca07188bcfd352eca0d5cdaa44257',
      '9aeddf05ab71e45852672b633ef2e5d4c303e7affdb2df2392d55023076e4ac6'
    ];

    const points = [
      'ec978aaddd8fd2bfe987e9b2e3e1083f303431f7ee6e5b29bcb3ecf744ccfa3e',
      'dcf620b77330dfc9bce7d77093aac3594e139a9851097bdf11ce8fcfaae18f63',
      'b7f58aec6bd754fb7456135d810ac1c2b69fa1a276a25d941fd7fd5c02ed3e43',
      'e0925a616f223b7589bd542588d42959c0c53851dc8231ee179236d6266e1353',
      '38ffba37f3095bc758969197b42c40bcf22441aadbe6f8bcebefc47d758d1e22',
      '2f35db22c344d2826381be3ed661fc69cf0b5cd54f4fae6fc8f6be9174da5d4b',
      'b656a3e7f2273e61696c3376179d77a1e4f91196d72a421c534e8534661ffb72',
      'ecc691345f1ee99bf872993b18053a8073bf73eadbb86ab98a797d686b7fa874',
      '2cae64bb13fcb701c591275e79e76102d13e1954ab1de5cd4fea6b67a43fa554',
      '8726f0bb61920141232cf679c8bf15cd10329938a3bf933d48219e865eb37644',
      'dc3a40fd223dce48e77db79a0d34db2d4dc9ad66524eda675457e9c93d525f69',
      '099d506b660cc05adaeb80212b6a51d68828bd521eb2ee2bd42f2ba448a0ec58',
      'e417e21c87dcae13080477c21e98992b8fb6ce328987ca314a1bf102a0612d25',
      '0d87c1859ff5daeda2420d375616205686cf867a1d20f0ab9accd8209de7263a',
      '3423d200e1ef4ef2b44a7dbb75083c5d5b37e8bfa71cee1a0ae56d093a1f9064',
      '6a221198a110c0717e2f956501265710b02e09a903002f8d3f8261d6396a4b2a'
    ];

    const raws1 = [
      'ce8d733f2e31426d9c746463b545743c9ccca0bce5d106eaaca6e7dd59903a2a',
      'e8bb024c443213d566d9f3ad84e836e8309716981b4b9a60b40715c608da7e01',
      '4a19330a4af640e5f4bb0d6f89be4c850e2e59cc28d803c0030f369e97b4c03f',
      'ed7917578f568fa2b20e8f7754fb4e643373d23a793ce528e054621222ab5811',
      '2bbeda49141a3e68d104753352225006ea04a710e2cedd287744fdef15d2340b',
      '59b68382ceb7a71d10b118405c3dc3952e7215df3a4d4dd0178d8321bc0fcd1d',
      '676266d7cf7c5bc608215de592e6dd1e7922c01670191227197ed3356cf90c46',
      '3872e840b5200b3a288e19867e9bd0a2b95ba841dd98ea8172540ed4576ac711',
      '69b29c580bebd2a1760edaf92da8b36c6d3d8f011dacc809598cd7cdd8a77814',
      'ce09fc332077771e0a168267dfb3680884741b355cf58d75b81721108bf47261',
      'f86dbf8ca3778b1c708a5f481ee9fb69ab653a624bd2acaa52c62cc908bba91f',
      '0d1e5643436baf470977af896c7d7bb071ca26e23be06655dc9473200284f612',
      '84e6dbb7581cc39a6d9ca796aa833b11aa22d38e2d2cc146c8be2537ab673732',
      'ee7722c827e2fb6ea6022b9eaf29ae4d7507c759fd5ca890011e5ca43fedf979',
      '3d9fa7b6e16dcebc4e11617863963f2c282e855aeb5d6679f580e8f9bd17da14',
      'b6a7cba2b0fe82e547130d147927ed4152f1062de0de376799e600bfb674e61a'
    ];

    const raws2 = [
      'ce8d733f2e31426d9c746463b545743c9ccca0bce5d106eaaca6e7dd59903a2a',
      '0544fdb3bbcdec2a99260c527b17c917cf68e967e4b4659f4bf8ea39f725817e',
      'a3e6ccf5b509bf1a0b44f2907641b37af1d1a633d727fc3ffcf0c961684b3f40',
      '0086e8a870a9705d4df17088ab04b19bcc8c2dc586c31ad71fab9deddd54a76e',
      'c24125b6ebe5c1972efb8accadddaff915fb58ef1d3122d788bb0210ea2dcb74',
      '59b68382ceb7a71d10b118405c3dc3952e7215df3a4d4dd0178d8321bc0fcd1d',
      '676266d7cf7c5bc608215de592e6dd1e7922c01670191227197ed3356cf90c46',
      'b58d17bf4adff4c5d771e67981642f5d46a457be2267157e8dabf12ba895386e',
      '844d63a7f4142d5e89f12506d2574c9392c270fee25337f6a67328322758876b',
      '1ff603ccdf8888e1f5e97d98204c97f77b8be4caa30a728a47e8deef740b8d1e',
      'f59140735c8874e38f75a0b7e1160496549ac59db42d5355ad39d336f7445660',
      '0d1e5643436baf470977af896c7d7bb071ca26e23be06655dc9473200284f612',
      '69192448a7e33c6592635869557cc4ee55dd2c71d2d33eb93741dac85498c84d',
      'ff87dd37d81d049159fdd46150d651b28af838a602a3576ffee1a35bc0120606',
      '3d9fa7b6e16dcebc4e11617863963f2c282e855aeb5d6679f580e8f9bd17da14',
      'b6a7cba2b0fe82e547130d147927ed4152f1062de0de376799e600bfb674e61a'
    ];

    const un = (r) => {
      r = Buffer.from(r);
      r[31] &= ~0x80;
      return r;
    };

    for (let i = 0; i < 16; i++) {
      const preimage = Buffer.from(preimages[i], 'hex');
      const key = Buffer.from(keys[i], 'hex');
      const point = Buffer.from(points[i], 'hex');
      const raw1 = Buffer.from(raws1[i], 'hex');
      const raw2 = Buffer.from(raws2[i], 'hex');

      assert.strictEqual(ed25519.publicKeyVerify(key), true);
      assert.bufferEqual(ed25519.publicKeyFromUniform(preimage), key);
      assert.bufferEqual(x25519.publicKeyFromUniform(preimage), point);
      assert.bufferEqual(un(ed25519.publicKeyToUniform(key, i & 1)), raw1);
      assert.bufferEqual(un(x25519.publicKeyToUniform(point, i & 1)), raw2);
      assert.bufferEqual(ed25519.publicKeyFromUniform(raw1), key);
      assert.bufferEqual(x25519.publicKeyFromUniform(raw2), point);
    }
  });

  it('should test random oracle encoding', () => {
    const bytes = SHA512.digest(Buffer.from('turn me into a point'));
    const pub = ed25519.publicKeyFromHash(bytes, true);
    const point = x25519.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub,
      '37e3fe7969358395d6de5062f5a2ae4d80f88331a844bcd2058a1f3e2652e0e6');

    assert.bufferEqual(point,
      '88ddc62a46c484db54b6d6cb6badb173e0e7d9785385691443233983865acc4d');

    assert.strictEqual(ed25519.publicKeyVerify(pub), true);
    assert.bufferEqual(ed25519.publicKeyConvert(pub), point);
    assert.bufferEqual(x25519.publicKeyConvert(point, true), pub);
  });

  it('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHA256.digest(Buffer.from('turn me into a point'));
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = ed25519.publicKeyFromHash(bytes, true);
    const point = x25519.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub,
      '5694d147542d2c08657a203cea81c6f0e39caa5219a2eeb0dedc37e59cd31e40');

    assert.bufferEqual(point,
      '7b9965e30b586bab509c34d657d8be30fad1b179470f2f70a6c728092e000062');

    assert.strictEqual(ed25519.publicKeyVerify(pub), true);
    assert.bufferEqual(ed25519.publicKeyConvert(pub), point);
    assert.bufferEqual(x25519.publicKeyConvert(point, false), pub);
  });

  if (x25519.native === 2) {
    const native = ed25519;
    const curve = require('../lib/js/ed25519');

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
    const priv = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(priv);
    const bytes = ed25519.publicKeyToHash(pub, 0);
    const out = ed25519.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should test equivalence edge cases', () => {
    const inf = ed25519.publicKeyCombine([]);
    const x = Buffer.alloc(32, 0x00);
    const e = Buffer.from('ecffffffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffffff7f', 'hex');

    assert.bufferEqual(ed25519.publicKeyConvert(e), x);
    assert.bufferEqual(x25519.publicKeyConvert(x, false), e);
    assert.throws(() => ed25519.publicKeyConvert(inf));
  });

  describe('ed25519 derivations', () => {
    for (const [i, test] of derivations.entries()) {
      it(`should compute correct a and A for secret #${i}`, () => {
        const secret = Buffer.from(test.secret_hex, 'hex');
        const priv = ed25519.privateKeyConvert(secret);
        const pub = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub));

        assert.bufferEqual(priv, Buffer.from(test.a_hex, 'hex'));
        assert.bufferEqual(pub, Buffer.from(test.A_hex, 'hex'));
      });
    }
  });

  describe('sign.input ed25519 test vectors', () => {
    const batch = [];

    // https://ed25519.cr.yp.to/software.html
    for (const [i, [secret_, pub_, msg_, sig_]] of vectors.entries()) {
      const secret = Buffer.from(secret_, 'hex');
      const pub = Buffer.from(pub_, 'hex');
      const msg = Buffer.from(msg_, 'hex');
      const sig = Buffer.from(sig_, 'hex');

      batch.push([msg, sig, pub]);

      it(`should pass ed25519 vector #${i}`, () => {
        const pub_ = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub_));

        assert.bufferEqual(pub_, pub);

        const sig_ = ed25519.sign(msg, secret);

        assert.bufferEqual(sig_, sig);

        assert(ed25519.verify(msg, sig, pub));
        assert(ed25519.verifySingle(msg, sig, pub));

        let forged = Buffer.from([0x78]); // ord('x')

        if (msg.length > 0) {
          forged = Buffer.from(msg);
          forged[forged.length - 1] += 1;
        }

        assert(!ed25519.verify(forged, sig, pub));
        assert(!ed25519.verifySingle(forged, sig, pub));
        assert(!ed25519.verifyBatch([[forged, sig, pub]]));
      });
    }

    it('should do batch verification', () => {
      const [msg] = batch[0];

      assert.strictEqual(ed25519.verifyBatch([]), true);
      assert.strictEqual(ed25519.verifyBatch(batch), true);

      if (msg.length > 0) {
        msg[0] ^= 1;
        assert.strictEqual(ed25519.verifyBatch(batch), false);
        msg[0] ^= 1;
      }
    });
  });

  describe('RFC 8032 vectors', () => {
    for (const [i, vector] of rfc8032.entries()) {
      if (!vector.algorithm.startsWith('Ed25519'))
        continue;

      let ph = null;
      let ctx = null;

      if (vector.algorithm === 'Ed25519ph') {
        ph = true;
      } else if (vector.algorithm === 'Ed25519ctx') {
        ctx = Buffer.from(vector.ctx, 'hex');
        ph = false;
      }

      let msg = Buffer.from(vector.msg, 'hex');

      if (ph)
        msg = SHA512.digest(msg);

      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      it(`should pass RFC 8032 vector (${vector.algorithm} #${i})`, () => {
        assert(ed25519.privateKeyVerify(priv));
        assert(ed25519.publicKeyVerify(pub));

        const sig_ = ed25519.sign(msg, priv, ph, ctx);

        assert.bufferEqual(sig_, sig);

        assert(ed25519.verify(msg, sig, pub, ph, ctx));
        assert(!ed25519.verify(msg, sig, pub, !ph, ctx));

        if (msg.length > 0) {
          const msg_ = Buffer.from(msg);
          msg_[i % msg_.length] ^= 1;
          assert(!ed25519.verify(msg_, sig, pub, ph, ctx));
          assert(!ed25519.verifyBatch([[msg_, sig, pub]], ph, ctx));
        }

        {
          const sig_ = Buffer.from(sig);
          sig_[i % sig_.length] ^= 1;
          assert(!ed25519.verify(msg, sig_, pub, ph, ctx));
        }

        {
          const pub_ = Buffer.from(pub);
          pub_[i % pub_.length] ^= 1;
          assert(!ed25519.verify(msg, sig, pub_, ph, ctx));
        }

        if (ctx && ctx.length > 0) {
          const ctx_ = Buffer.from(ctx);
          ctx_[i % ctx_.length] ^= 1;
          assert(!ed25519.verify(msg, sig, pub, ph, ctx_));
          assert(!ed25519.verify(msg, sig, pub, ph, null));
        } else {
          const ctx_ = Buffer.alloc(1);
          assert(!ed25519.verify(msg, sig, pub, true, ctx_));
          assert(!ed25519.verify(msg, sig, pub, false, ctx_));
        }
      });
    }
  });

  it('should do covert ecdh', () => {
    const alicePriv = ed25519.privateKeyGenerate();
    const alicePub = ed25519.publicKeyCreate(alicePriv);
    const bobPriv = ed25519.privateKeyGenerate();
    const bobPub = ed25519.publicKeyCreate(bobPriv);
    const alicePreimage = ed25519.publicKeyToHash(alicePub, 7); // Add 8-torsion.
    const alicePub2 = ed25519.publicKeyFromHash(alicePreimage);
    const bobPreimage = ed25519.publicKeyToHash(bobPub, 2); // Add 4-torsion.
    const bobPub2 = ed25519.publicKeyFromHash(bobPreimage);

    assert(!ed25519.publicKeyHasTorsion(alicePub));
    assert(!ed25519.publicKeyHasTorsion(bobPub));
    assert(ed25519.publicKeyHasTorsion(alicePub2));
    assert(ed25519.publicKeyHasTorsion(bobPub2));

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const bobSecret = ed25519.derive(alicePub, bobPriv);
    const aliceSecret2 = ed25519.derive(bobPub2, alicePriv);
    const bobSecret2 = ed25519.derive(alicePub2, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);
    assert.bufferEqual(aliceSecret2, bobSecret2);
    assert.bufferEqual(aliceSecret, aliceSecret2);
    assert.bufferEqual(bobSecret, bobSecret2);
  });

  it('should test serialization formats', () => {
    const priv = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(priv);
    const rawPriv = ed25519.privateKeyExport(priv);
    const rawPub = ed25519.publicKeyExport(pub);

    assert.bufferEqual(ed25519.privateKeyImport(rawPriv), priv);
    assert.bufferEqual(ed25519.publicKeyImport(rawPub), pub);
  });
});
