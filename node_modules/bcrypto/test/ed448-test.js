'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed448 = require('../lib/ed448');
const x448 = require('../lib/x448');
const SHAKE256 = require('../lib/shake256');
const rfc8032 = require('./data/rfc8032-vectors.json');

describe('Ed448', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed448.size);
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);

    assert(ed448.publicKeyVerify(pub));

    const sig = ed448.sign(msg, secret);

    assert(ed448.verify(msg, sig, pub));

    sig[0] ^= 1;

    assert(!ed448.verify(msg, sig, pub));

    assert.bufferEqual(
      ed448.privateKeyImport(ed448.privateKeyExport(secret)),
      secret);
  });

  it('should allow points at infinity', () => {
    // Fun fact about edwards curves: points
    // at infinity can actually be serialized.
    const msg = Buffer.from(''
      + 'bd0f6a3747cd561bdddf4640a332461a'
      + '4a30a12a434cd0bf40d766d9c6d458e5'
      + '512204a30c17d1f50b5079631f64eb31'
      + '12182da3005835461113718d1a5ef944',
      'hex');

    const sig = Buffer.from(''
      + '01000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '0000',
      'hex');

    const pub = Buffer.from(''
      + 'df9705f58edbab802c7f8363cfe5560a'
      + 'b1c6132c20a9f1dd163483a26f8ac53a'
      + '39d6808bf4a1dfbd261b099bb03b3fb5'
      + '0906cb28bd8a081f00',
      'hex');

    assert(!ed448.verify(msg, sig, pub));

    const inf = Buffer.from(''
      + '01000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '00000000000000000000000000000000'
      + '000000000000000000',
      'hex');

    assert(ed448.publicKeyVerify(inf));
    assert(ed448.publicKeyIsInfinity(inf));
    assert(ed448.scalarIsZero(sig.slice(57, 57 + 56)));
    assert(ed448.verify(msg, sig, inf));
  });

  it('should fail to validate malleated keys', () => {
    // x = 0, y = 1, sign = 1
    const hex1 = '0100000000000000000000000000'
               + '0000000000000000000000000000'
               + '0000000000000000000000000000'
               + '000000000000000000000000000080';

    // x = 0, y = -1, sign = 1
    const hex2 = 'feffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffff'
               + 'feffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffffff80';

    const key1 = Buffer.from(hex1, 'hex');
    const key2 = Buffer.from(hex2, 'hex');

    assert(!ed448.publicKeyVerify(key1));
    assert(!ed448.publicKeyVerify(key2));

    key1[56] &= ~0x80;
    key2[56] &= ~0x80;

    assert(ed448.publicKeyVerify(key1));
    assert(ed448.publicKeyVerify(key2));
  });

  it('should test scalar zero', () => {
    // n = 0
    const hex1 = 'f34458ab92c27823558fc58d72c2'
               + '6c219036d6ae49db4ec4e923ca7c'
               + 'ffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffff3f';

    // n - 1 = -1
    const hex2 = 'f24458ab92c27823558fc58d72c2'
               + '6c219036d6ae49db4ec4e923ca7c'
               + 'ffffffffffffffffffffffffffff'
               + 'ffffffffffffffffffffffffff3f';

    assert(ed448.scalarIsZero(Buffer.alloc(56, 0x00)));
    assert(!ed448.scalarIsZero(Buffer.alloc(56, 0x01)));

    assert(ed448.scalarIsZero(Buffer.from(hex1, 'hex')));
    assert(!ed448.scalarIsZero(Buffer.from(hex2, 'hex')));
  });

  it('should validate small order points', () => {
    const small = [
      // 0, c (order 1)
      ['01000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join(''),
      // 0, -c (order 2, rejected)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff00'].join(''),
      // c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000080'].join(''),
      // -c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join('')
    ];

    const key = ed448.scalarGenerate();

    for (let i = 0; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(ed448.publicKeyVerify(pub));
      assert.throws(() => ed448.deriveWithScalar(pub, key));
    }
  });

  it('should test small order points', () => {
    const small = [
      // 0, c (order 1)
      ['01000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join(''),
      // 0, -c (order 2, rejected)
      ['feffffffffffffffffffffffffffffffffffffffffffffffffffffff',
       'feffffffffffffffffffffffffffffffffffffffffffffffffffffff00'].join(''),
      // c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000080'].join(''),
      // -c, 0 (order 4)
      ['00000000000000000000000000000000000000000000000000000000',
       '0000000000000000000000000000000000000000000000000000000000'].join('')
    ];

    {
      const pub = Buffer.from(small[0], 'hex');

      assert(ed448.publicKeyIsInfinity(pub));
      assert(!ed448.publicKeyIsSmall(pub));
      assert(!ed448.publicKeyHasTorsion(pub));
    }

    for (let i = 1; i < small.length; i++) {
      const str = small[i];
      const pub = Buffer.from(str, 'hex');

      assert(!ed448.publicKeyIsInfinity(pub));
      assert(ed448.publicKeyIsSmall(pub));
      assert(ed448.publicKeyHasTorsion(pub));
    }

    {
      const priv = ed448.privateKeyGenerate();
      const pub = ed448.publicKeyCreate(priv);

      assert(!ed448.publicKeyIsInfinity(pub));
      assert(!ed448.publicKeyIsSmall(pub));
      assert(!ed448.publicKeyHasTorsion(pub));
    }
  });

  it('should validate signatures with small order points', () => {
    const json = [
      // (-1, -1)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        true,
        true
      ],

      // (-1, -1)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00',
        false,
        false
      ],

      // (0, 0)
      [
        '56d69147eb80b6d3c1a909aa74286ee8e69729152de2ffb1cf10670b6893e8e8e0f22d85144c3073ef0d3dac36577eaaae42d7d9f65b6d6e05',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        true,
        true
      ],

      // (0, 1)
      [
        '8e1ea3e1a3fc6849154b8def1158c3112c89027eafe01e0f81ca0c62abbad6f110c72bc6be497a3eedda1b558f296326b385f56a7d1ce7e6bc',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        false,
        true
      ],

      // (1, 0)
      [
        '8e1ea3e1a3fc6849154b8def1158c3112c89027eafe01e0f81ca0c62abbad6f110c72bc6be497a3eedda1b558f296326b385f56a7d1ce7e6bc',
        'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        true,
        true
      ],

      // (1, 1)
      [
        'c9e836c4fb92425ab41261ef55a9ca7187fa31278ebf5a73101542298ec49e8102b3d554abc9bdcf35f5c7bea7ea48e960cc41ef694d08cd39',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
        false,
        true
      ],

      // (1, 2)
      [
        'd131c7443a0fe4389c1e81db609b1098ddb2716d80507c696b6c44b7989db3a218e635ce9214bb1fa3e438e2733a107d3f90f16fbecf6f564f',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
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
      assert.strictEqual(ed448.verify(msg, sig, pub), res1);
      assert.strictEqual(ed448.verifySingle(msg, sig, pub), res2);

      if (res2)
        batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed448.verifyBatch(batch), true);
  });

  it('should validate signatures with torsion components', () => {
    const json = [
      // (0, 0)
      [
        '2a596cd0f0326747960ff7f36014472dd2faaff3e137f1d7bd7625ca1a632c86ea9c2a12c2111a4b682f8a69051f553777db77a93f287e991b',
        '848aa10e0baf75c788c9ae5aa59239cdc9eeadec4465e404f6d79064020cf5056ea5f9c9af78d0894db751c3ad2e6607a58f9f88d31536c300',
        '8e7a1f893fdf95fbde0980ae999167ac6090255c0453c7631c1a28e9810c6a4e2e0ab3215d8767181052fc86ab8808d5c19d1de6b049963400',
        '4b84907faf16cda003cf134b162d400a864fb300f9ad09b33d5f6b5679b5e7b653017d0893d47137668ebe4015176f3d54b9f00af047f14080',
        true,
        true
      ],

      // (0, 0)
      [
        '6998833d4e3dd4a7f7049e8e334ea7204ed7fef0b094e898b5d126239c953f9fc306982d1946561d0a799cdd0ea84465dd7c133b518ac1e3ba',
        'c7e1d289b350b1924ffdf2e81e6ef8bc29984a9066983b091b1d26772ede920f6720f5fee5c564e2571a170bb7d92f776393a7d50100729000',
        '2ed4a2ecca6c445af18026482e515596ffeb632c48e5e4d03d0a244f4141463b4ab4987459730447fa00fde0333c249d9158295670179a2000',
        '8b7ab2c01bed9b08a4c14fae468c0f701d82cfe4e470b9f5af682c58b15679961e841abe551eec528be5cb50201ae740a71e6e9457eb656680',
        false,
        true
      ],

      // (0, 1)
      [
        'c63f7c1e3cd8a7fcef1c4667a40c42f29d547cc4648799e324f7d23a7b0ea79c3940f00001b56ff59bea114c56e219082efc21714ce8b50afc',
        '521f59fa4c4cd55f47ecca8c95a9ea835a939db0636eefefa057521bce1ac53809f03f64f2ba901e0bc2218a6044486ca0eeb5212ee4adc500',
        'f4b99f1dc93be7d9ef2eb98c68169b368ccff3a65a7b370d5320c5b48edde50ae060f65862db08dfbeb24d8d8164024740c67240ebd32f2100',
        '05cad01e0be214e8a720a789e6e195aa8613f12010754769fe5440ddb3b67563406fde3890d22aa2867ece11ce9121dffaeeebd44b44346000',
        false,
        true
      ],

      // (1, 1)
      [
        '9f3c41e784fc34a6040e3fbc56fb7a133a47f96067c22d6f5dcd95c3eeddeae330980748470eceba52e46983a662fbf753bcde3b0d39eeff1f',
        'caf7da877bef663ad35841d31aab19d87ea4c0b551120631d8641b3f4fcf43460c222e4f83f5b18697be269ba5af1dde9b0ff96baa8d3d1d00',
        'faff63d451d3a7f1de112b37bc7a991a022bf876b5f9f1a10c4c493e9e33e78689064166a166739bf7ae5bd7b52541af9b775cff76304b3200',
        '8818a84042578578f2f96c01146b4067ed21ddd4f725caa988422c513123e728bbb54dae863e264b46774944fe3ab0eeff67f07d619d629500',
        true,
        true
      ],

      // (1, 1)
      [
        '8079b84b8476da19ae62721e5b8eca9e14d8f5cc2c09b34624530e7f2f61ab2a9824127183d674893686ab79d22552f6397616a759bb512d58',
        'b9cf91018948f955c3df0752f075c0c3553be8f0a380b4a5692d0c513f632e7b700f8b2183d987d81efb4449f0b32766b2034a54837cbc1180',
        'fa8eb259a60bcb2107f4aa5d7c33fb2f61b9b0110a018fbd7acf4d14ce2ad54065c5defb9311ee8c7fa4b83d927aa625f4d2932b17cc9a1200',
        'bd38ceea0e894dd3c6c21324161f350bcc553765092d81e287cdc368908de825e4b74e8dc142b2fe435ec557780d2d4fecbb5c93ff10609780',
        false,
        true
      ],

      // (1, 2)
      [
        'eaaedfadb7591be2f32303d1483f0f322f7bcc14124a4e1577d9bcfe454f00352e6362c1c66dd2b0cadeb2535af6d19850a27a5e47217e8fef',
        '37ccae0439012245098ef808df88472df479fee60bbe8fe899248096c09ee5296f8a25d16bfb4365be77b34e6df8da1110f8fcf0e6151c2a80',
        '8800d4ce199f99a94b7abf0246780cde0b2f559f922af849073cd47c09d01384c330f2e5234cd749f0a8f95625f8119ab8a34c9d6fb11e2100',
        '470b5f5ea3f7b3ad61dffcb3f17fb5532fbe5428ce501d11ad0db9294947322c6eaaba06450732ba851fd2ffbf7a22d645e906d40f83980c80',
        true,
        true
      ],

      // (1, 2)
      [
        'f2a8a2825f0e8b6d3629787039674a626e809cf65b6755b37263645c4f1a5031e5ed789299c0b7ff4d27eae2818a261a5b9e779585f46e1e07',
        'af881c54bd8dc2b8dba024b3939ebce13f9394287282f13017c89b99786d586ca5ea71a215caae44041a646689f386c4047ed656bab0cda980',
        '18923a6ce396d90cdfe147ee8c01f3f94cd4b8a6ebf9a49f33339e4e76b1d8b325800c474e1b904e913a6277c33024778d2e33d5106b051900',
        'bca27341df8ecd9c6be51cef237d13aa0caf86c1ea1eccb382c10b480b89d7b12a2c3f3b575f002a2c0baf015c41bd1adf023d103dce8e1700',
        false,
        true
      ],

      // (2, 2)
      [
        '66fe3f2570c564837d4877ebbc4acbf19e83af3f68c904ab751b2a3dd6578fdc7e9f1b6626f6b0ef5bf653a2fd97d41b214c38cf022d74aa59',
        'b85a45f025d112bc923942842ffb548539cb99afa2f8bf727486cc053667452c016ceef72f6695fae2d2e98b1bd2c0ad1c106e112cab924c00',
        '1579a45a05056bb4f8e3f40b7710b55c5f23c35f98efefb8cdf8e2666a96c23ca7fa2c8b7c1003a5cf64695db0e0eb95617f165ebaa7633a00',
        '4e7d7ab89f6938959bb4ee9b7aded93c596e758feae5c910055cd5f1c577df04f7871837b0b6ba2210918284a6aa588c88be8f40e55d82dd80',
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
      assert.strictEqual(ed448.verify(msg, sig, pub), res1);
      assert.strictEqual(ed448.verifySingle(msg, sig, pub), res2);
      assert(!ed448.publicKeyIsSmall(pub));
      assert(ed448.publicKeyHasTorsion(pub));

      batch.push([msg, sig, pub]);
    }

    batch.sort(() => Math.random() > 0.5 ? 1 : -1);

    assert.strictEqual(ed448.verifyBatch(batch), true);
  });

  it('should reject non-canonical R value', () => {
    const json = [
      '3dea88afc3a2802ef17ba72a90c512924902de5777df89a9ff7a4dd580e84fbc25bf33fa7b03e21002391a07ea170f57bd8b1b888ed2c3b568',
      '7a49c363d75f51ad32fa5952631e30285bbc954b1ed44612e23dba86d7430a6e398912fc88f6d3fabfbe05971aa5f11098b87eac97a8664c01',
      '07fa7072b4eab22219df35fffb85c91d1e67079d44e2aa8dee7d03dba792ff8309815efcab7ee04931790975854105d94f16beac4f67cb1500',
      'a675030aaf9ffcf7cd49d415b70582b08963b7ae22af601ed61436815164b91d10f86e9a8276d6f5a8a99f3c557eee161dd85ed2a5ab8b4700'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical S value', () => {
    const json = [
      'd5158e4e16d9ea0d584245abcde079bdbdaa6658a30fc4ed7ae23bebe364037ade875736879557b00cbe19f2d53979e336882bff5f3390547d',
      'bbad6011448fc0f16527340aa35ff00ffd621b6b4035a3315f404e5294ee9159526617153801c8e8dfd939475d945f689d3a4e2b642be45900',
      '0e2284ac9848c25e0efa26971fd79c514c6e076dc824fb63ebda9cf8a363916bf023eeea94f9f28b8c109937ce1a6dd32e0775b59e39d14100',
      '1eb228ad82bf5d96c4c5f197169d4131de8732df5ce5b22dd9e9e1b9b3ed7417071e840a7582fc6b366ede96c9b7d79e066e963098c4402380'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should reject non-canonical key', () => {
    const json = [
      '1e9b34e04e51dd6da9c0dbcb7509d4408f25da9b47afa2734d36e6a7a40a3283e52e98e4f5e77fe07d0ba997aadb95cd78bb8dc3a1b1cc298c',
      '0b45ed34130a4966033f99ccf1d20d53031a147d6a55dabc9d8c65398e381a951cba6a47a591fb42abad1c6b446dc60cb8c81d9acc43fe5880',
      'efea554ad7a2b66e696f9382dcbd08aa6c7d65ab04d1fa41ac91c50c7a18b7b353e2bfac2a2414feb2f2084a5c17a513f5f877480b6cb63000',
      'a6e5c2c10b05a26c7502d3d1d7e5e59e9c96d9fe5151be56d8ccd429e97501a48f4f6f18d15c6fe244569672f789c290b2cb6dffec255f6100'
    ];

    const [m, r, s, p] = json;
    const msg = Buffer.from(m, 'hex');
    const sig = Buffer.from(r + s, 'hex');
    const pub = Buffer.from(p, 'hex');

    assert.strictEqual(ed448.verify(msg, sig, pub), false);
    assert.strictEqual(ed448.verifySingle(msg, sig, pub), false);
  });

  it('should expand key', () => {
    const secret = Buffer.from(''
      + 'a18d4e50f52e78a24e68288b3496'
      + 'd8881066a65b970ded82aac98b59'
      + '8d062648daf289640c830e9098af'
      + '286e8d1a19c7a1623c05d817d78c'
      + '3d', 'hex');

    const [key, prefix] = ed448.privateKeyExpand(secret);

    assert.bufferEqual(key, ''
      + '041a89beaebf4c118b34b4aa66afa8a150c464ca9c3eb46b15c599e4'
      + '3a9439e9131cd01b2c146d8b47d0d590f3938887db82e1334d43b9f2',
      'hex');

    assert.bufferEqual(prefix, '26'
      + 'a3b2541854b72b95c11775490069c50c5ccf64d94ae3648221a7c254'
      + '539834d04102266838a5c75ca340d885a3c318acc0f7dd6b5e398dbb',
      'hex');

    assert.bufferEqual(ed448.privateKeyConvert(secret), key);
  });

  it('should do ECDH', () => {
    const alicePriv = ed448.privateKeyGenerate();
    const alicePub = ed448.publicKeyCreate(alicePriv);

    const bobPriv = ed448.privateKeyGenerate();
    const bobPub = ed448.publicKeyCreate(bobPriv);

    const aliceSecret = ed448.derive(bobPub, alicePriv);
    const bobSecret = ed448.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const secret = aliceSecret;
    const xsecret = ed448.publicKeyConvert(secret);
    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    assert.notBufferEqual(xsecret, secret);

    const xaliceSecret = x448.derive(xbobPub,
      ed448.privateKeyConvert(alicePriv));

    const xbobSecret = x448.derive(xalicePub,
      ed448.privateKeyConvert(bobPriv));

    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);
  });

  it('should do ECDH (with scalar)', () => {
    const aliceSeed = ed448.privateKeyGenerate();
    const alicePriv = ed448.privateKeyConvert(aliceSeed);
    const alicePub = ed448.publicKeyFromScalar(alicePriv);

    assert.bufferEqual(alicePub, ed448.publicKeyCreate(aliceSeed));

    const bobSeed = ed448.privateKeyGenerate();
    const bobPriv = ed448.privateKeyConvert(bobSeed);
    const bobPub = ed448.publicKeyFromScalar(bobPriv);

    assert.bufferEqual(bobPub, ed448.publicKeyCreate(bobSeed));

    const aliceSecret = ed448.deriveWithScalar(bobPub, alicePriv);
    const bobSecret = ed448.deriveWithScalar(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    const xaliceSecret = x448.derive(xbobPub, alicePriv);
    const xbobSecret = x448.derive(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xbobSecret);
  });

  it('should do ECDH (vector)', () => {
    const pub = Buffer.from(''
      + '93890d139f2e5fedfdaa552aae92'
      + 'e5cc5c716719c28a2e2273962d10'
      + 'a83fc02f0205b1e2478239e4a267'
      + 'f5edd9489a3556f48df899424b4b'
      + '00', 'hex');

    const priv = Buffer.from(''
      + 'a18d4e50f52e78a24e68288b3496'
      + 'd8881066a65b970ded82aac98b59'
      + '8d062648daf289640c830e9098af'
      + '286e8d1a19c7a1623c05d817d78c'
      + '3d', 'hex');

    const xsecret = Buffer.from(''
      + 'e198182f06c67c8fe5e080088d5c'
      + '5b23be7c46782ed24774feeba6fb'
      + '37536ada82b71564818fa3df6af8'
      + '22af3dd09dd0529518b42a3d9655', 'hex');

    const secret2 = ed448.derive(pub, priv);
    const xsecret2 = ed448.publicKeyConvert(secret2);

    assert.notBufferEqual(secret2, xsecret);
    assert.bufferEqual(xsecret2, xsecret);

    const xpub = ed448.publicKeyConvert(pub);
    const xsecret3 = x448.derive(xpub, ed448.privateKeyConvert(priv));

    assert.bufferEqual(xsecret3, xsecret);
  });

  it('should generate keypair and sign with additive tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakAdd(pub, tweak);
    const sig = ed448.signTweakAdd(msg, key, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const childPriv = ed448.scalarTweakAdd(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));

    const real = ed448.scalarReduce(ed448.privateKeyConvert(key));
    const parent = ed448.scalarTweakAdd(childPriv, ed448.scalarNegate(tweak));

    assert.bufferEqual(parent, real);

    const tweakPub = ed448.publicKeyFromScalar(tweak);
    const parentPub = ed448.publicKeyCombine([childPub, ed448.publicKeyNegate(tweakPub)]);

    assert.bufferEqual(parentPub, pub);
  });

  it('should generate keypair and sign with multiplicative tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakMul(pub, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const sig = ed448.signTweakMul(msg, key, tweak);

    const childPriv = ed448.scalarTweakMul(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));

    const real = ed448.scalarReduce(ed448.privateKeyConvert(key));
    const parent = ed448.scalarTweakMul(childPriv, ed448.scalarInvert(tweak));

    assert.bufferEqual(parent, real);
  });

  it('should generate keypair and sign with multiplicative tweak * cofactor', () => {
    const cofactor = Buffer.alloc(56, 0x00);
    cofactor[0] = 4;

    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak_ = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const tweak = ed448.scalarTweakMul(tweak_, cofactor);
    const child = ed448.publicKeyTweakMul(pub, tweak);
    const child_ = ed448.publicKeyTweakMul(
      ed448.publicKeyTweakMul(pub, tweak_),
      cofactor);

    assert.bufferEqual(child, child_);
    assert(ed448.scalarVerify(tweak_));
    assert.notBufferEqual(child, pub);

    const sig = ed448.signTweakMul(msg, key, tweak);

    const childPriv = ed448.scalarTweakMul(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);

    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);

    assert(ed448.verify(msg, sig2, child));
  });

  it('should modulo scalar', () => {
    const scalar0 = Buffer.alloc(56, 0x00);
    const mod0 = ed448.scalarReduce(scalar0);

    assert.bufferEqual(mod0, ''
      + '00000000000000000000000000000000000000000000000000000000'
      + '00000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar1 = Buffer.alloc(56, 0x00);

    scalar1[0] = 0x0a;

    const mod1 = ed448.scalarReduce(scalar1);

    assert.bufferEqual(mod1, ''
      + '0a000000000000000000000000000000000000000000000000000000'
      + '00000000000000000000000000000000000000000000000000000000',
      'hex');

    const scalar2 = Buffer.alloc(56, 0xff);
    const mod2 = ed448.scalarReduce(scalar2);

    assert.bufferEqual(mod2, ''
      + '33ec9e52b5f51c72abc2e9c835f64c7abf25a744d992c4ee5870d70c'
      + '02000000000000000000000000000000000000000000000000000000',
      'hex');
  });

  it('should convert to montgomery (vector)', () => {
    const pub = Buffer.from(''
      + '3167a5f7ce692bcf3af9094f792c'
      + 'b3618ea034371703a3ffd222254e'
      + '6edba0156aa236c2b3ef406e700c'
      + '55a0beff8e141348cfd354682321'
      + '00', 'hex');

    const xpub = Buffer.from(''
      + '5c8ae0100ddb3f5320924bef698c'
      + 'd78fa7456b6d9b5af66a9a99b5d2'
      + 'a7f7e789a81e2f539b24c69bdf4f'
      + '4f1cfcb881a5e9205e21ca27ff25', 'hex');

    const xpub2 = ed448.publicKeyConvert(pub);

    assert.bufferEqual(xpub2, xpub);
  });

  it('should convert to montgomery and back', () => {
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);
    const sign = (pub[56] & 0x80) !== 0;
    const xpub = ed448.publicKeyConvert(pub);
    const pub2 = x448.publicKeyConvert(xpub, sign);

    assert.bufferEqual(pub2, pub);
  });

  it('should sign and verify (vector)', () => {
    const priv = Buffer.from(''
      + 'd65df341ad13e008567688baedda8e9d'
      + 'cdc17dc024974ea5b4227b6530e339bf'
      + 'f21f99e68ca6968f3cca6dfe0fb9f4fa'
      + 'b4fa135d5542ea3f01',
      'hex');

    const pub = Buffer.from(''
      + 'df9705f58edbab802c7f8363cfe5560a'
      + 'b1c6132c20a9f1dd163483a26f8ac53a'
      + '39d6808bf4a1dfbd261b099bb03b3fb5'
      + '0906cb28bd8a081f00',
      'hex');

    const msg = Buffer.from(''
      + 'bd0f6a3747cd561bdddf4640a332461a'
      + '4a30a12a434cd0bf40d766d9c6d458e5'
      + '512204a30c17d1f50b5079631f64eb31'
      + '12182da3005835461113718d1a5ef944',
      'hex');

    const sig = Buffer.from(''
      + '554bc2480860b49eab8532d2a533b7d5'
      + '78ef473eeb58c98bb2d0e1ce488a98b1'
      + '8dfde9b9b90775e67f47d4a1c3482058'
      + 'efc9f40d2ca033a0801b63d45b3b722e'
      + 'f552bad3b4ccb667da350192b61c508c'
      + 'f7b6b5adadc2c8d9a446ef003fb05cba'
      + '5f30e88e36ec2703b349ca229c267083'
      + '3900',
      'hex');

    const pub2 = ed448.publicKeyCreate(priv);

    assert.bufferEqual(pub2, pub);

    const sig2 = ed448.sign(msg, priv);

    assert.bufferEqual(sig2, sig);

    const result = ed448.verify(msg, sig, pub);

    assert.strictEqual(result, true);
  });

  it('should do elligator2 (edwards)', () => {
    const u1 = Buffer.from(''
      + '72ad074f3dbfbb3927125fab1f4023a408adc0ab1cbbbd6556615e3d'
      + '67501a428120ac1556a467734b1ad6820734d2100f0ed88510bd3e14', 'hex');

    const p1 = ed448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, ''
      + '7a6367f2fe07d45f2e34e17c66742f9ec4bdfb04c2b61a2935337751'
      + '57eff6f1c34bad5ea04021cf5c33099553e23afa48ca2455d070aeda80', 'hex');

    const u2 = ed448.publicKeyToUniform(p1, random.randomInt() & 1);
    const p2 = ed448.publicKeyFromUniform(u2);
    const u3 = ed448.publicKeyToUniform(p2, random.randomInt() & 1);
    const p3 = ed448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should do elligator2 (mont)', () => {
    const u1 = Buffer.from(''
      + '72ad074f3dbfbb3927125fab1f4023a408adc0ab1cbbbd6556615e3d'
      + '67501a428120ac1556a467734b1ad6820734d2100f0ed88510bd3e14', 'hex');

    const p1 = x448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, ''
      + '6bd0c1ee9599249bff3276e2a8279bea5e62e47f6507656826fe0182'
      + '3a0580129b6df46dabe81c7559a7028344b50da7682423586d6e80dd');

    const u2 = x448.publicKeyToUniform(p1, random.randomInt() & 1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2, random.randomInt() & 1);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should test elligator2 exceptional case (r=1)', () => {
    const u1 = Buffer.alloc(56, 0x00);

    u1[0] = 1;

    const p1 = x448.publicKeyFromUniform(u1);

    assert.bufferEqual(p1, Buffer.alloc(56, 0x00));

    const u2 = x448.publicKeyToUniform(p1, 1);
    const p2 = x448.publicKeyFromUniform(u2);
    const u3 = x448.publicKeyToUniform(p2, 1);
    const p3 = x448.publicKeyFromUniform(u3);

    assert.bufferEqual(p1, p2);
    assert.bufferEqual(p2, p3);
  });

  it('should pass elligator2 test vectors', () => {
    const preimages = [
      '55bbb23580f1d9136a63216273c9bcf0bae1bbf419582da807852a6f',
      '899269e872fe160eef71b68bdca7b09daf2d3719e64c5272f7da95fe',
      'a6dfc9c328021b8f3b970a64e6fc92cb3ea3e8455cd4134a8e1f6f13',
      '78b6b75bbeb56d172172390bf334bce739829d574101b9a9abd1d58f',
      'b6683e14bfb704b4a30198b1e749f281e0cbeb66bd8f7dc552d23a9b',
      '4737406664797e5de0653325367f1d7cfcddb7c497a389b361a3c6ea',
      'ecaedcf561a9cef24982fe697488d2b700f0f493448a5aca40eba5f1',
      'c1f1f075dfabd61e30aaa8847bb0a902f5b574711ae6dac9fdc6be69',
      '50937d89815b443e2477f2162a1702917f2682e135fd24f724be52a5',
      'dada6f1ca3025df5ef82312ffb4646803a33eb3d18cccae0fb5e0479',
      '4f9a896a88e2a2963abc7c0a94e18c1717be750cfab942ba22b7cc0b',
      '70887f016bd2f5d7e3b5e126249540070b5f15a444b32eeb1723ce6a',
      'bd9c5aef37a124870e080fcebedb9c3032b63a2bb72d597dcb65a5ca',
      '5e284d17ced9c66ea8117010539f7b07e8e30fdf928404adf9144156',
      'b139cd9385765b671ce55a160e33a7a92dd13f5597e4cec9c2ab180d',
      '4ccb33c7cd264aeb395633b6355eedcf8cca76b2e399a1c7797e8722',
      '5670eb921cc7b541851813a633253fb3946e708c93c25f0d4c3e4c80',
      'ba7d09398acf3b7b9480f0d9aef02bfd19646a83da70d6b0875198a2',
      'd7d47ee430a0b43ef9211af3b1daa7b3888753a9fb37ec3b5d0935be',
      'c17d0d87552132883d8d4cff00b4f36492f6aa6de539b5cf1fc0d42f',
      '0ef530a2ff1ea154c96b244922fb5c864a5d2874018e9ebd09447194',
      '75f034eda72807ab4dd6cee45fc88f0ca07c25f8117989180ac97344',
      'b9b29fa849a9027856fa7fff40d2ef62815f7baead52b0a77e800118',
      '39d6a52e86fcf25df8ee9043a73fccedce991bfb0c49b4fbb322e53f',
      '9013bc5081d011bd320a9d1ba09697a05d6271c23341ad845ff137d3',
      'eda3c7c11e7f7a0768629b79ff46082407506d125a612f2b0e634b06',
      '854528c50f346f4aeff449200b481a2a84a58c992330ecb8622b1580',
      '76c8e99207f8cbbec61c157f22e38c8af7236b8b05eb1cf1a21c44ac',
      '5edc2f840a499148c180d04b051e9c5c6673766fc0c03d6c151d5978',
      'a3092a221af48901a2210fcc8c71bc3a0147d82f35b99b27dbf85b87',
      'c6fbc5d666c845ab267529300a5ef0b3f04f016d92349110bd2d1298',
      '3f74b4c95ac7836bbc0e7f6b38622543bc26b4dc8b407bb4c9532b4e'
    ];

    const keys = [
      'cb8471e3827fd46943baecb484e1d50cc814a57dc113af9451ed1503',
      '393e8b6b31b3930fc5d11875530d85d52498fec171f1cee9695c147980',
      'add93147dbc0b9edfc6afb28841ced3e39d33a607ae4cc1d66fffb38',
      'af2e259c98ff53cf02541169ddb7d8328eec8e0e167ae2f72c62ded680',
      '4f98fab184bdc339928d5a5fb787c3d3f3d0da83966d5af039d69dae',
      '746dcf3d0db4b180e1a1bd2d10d72c5512da161808f71595db5be7f480',
      '9728a9d4721a41378efd2dda70ca8c9b2cd9134e73f673afd7bc2a96',
      'f159d7aa50758b3a58c02b6e743a433d106882e8444403457174cfea00',
      'ca5667784809d584970ab8da95047525bc100b545a9658227aad13a8',
      'd257a275884b1b8ff6573e0808830a0083d03bc59b877a1d0395eab280',
      '9a9168e08f040a28c1347b28504bdfb2e59f675f83d0a31032358849',
      '7eaf4c18de88454ec5f4464f87db3f8490764fa73b95a3dabb1e1b1280',
      '8bf617e4b9b7584e52bd07bc25c73e0aac6dd19e0bc07cece6e5dc05',
      'c2f5fd6259950e4ab0f1e0f99412654848f227bd21dce84b1af3d38700',
      'c352c732576624ed869a94a6fa2776851a4226fa6a317c3753526c2f',
      'da6e34a7dc85b15b56809b39b96fef692c8260dfb5deece4608bdb1500',
      '6ea74c40212fea12ae1e44c7de47f8685c599870f6b7811d06f93e16',
      '7691ab72034a22ee54fe235f0e459fcca370d650e25c9d49fe24f40680',
      'c4634085821fc9e788142b5591837d60a6ca5218b6b0a7342f29ce29',
      '66a159ec9cbae22c5671ca8975eef57a34edf2b8f7713763b9c4d63c80',
      '4d7872140399abf07eb5b9851f34636b4d1d462f4e5a4a5fad964b04',
      'ef2da42c21d338663d0e3647509c390b50fadbe7833741a8c41a140680',
      '74284f4ef15824fece744c5ae92514f5f3bf0353f575c8c2f7454d0f',
      '41658c002499bd480cb8cc0846296fc919d051614879e03a3fe6d4ed80',
      '4c16c6fd4853b6c783b15a98a9270d2162547f3f6646e1a097bff06a',
      '23e253c893fe744a44e48783fc4df43b383e1348290ae29adb66c59a80',
      '0b6fd98eace4e31a33ec2943a1e5bd62d648b5b4ec289a64b9cf3a6a',
      'b7d9f1e2a8b691f3cb030f394b62cdc0f45978070f2e80e284d86bc300',
      'be4f171430401b1b625075ea1c3a71c715d0e43206bdc1b3193b600b',
      'e31f8beb031d9169b6f9b52b394a1c4ae2edf812a294dd305ba3723280',
      'b9656dfaf27aba54b3b5a69e83c503397cddef441000a56347f61e8b',
      '2b3c0456a50d9340ed74f5e3d7ddeeaccddd3bcca8d592448d370b3080'
    ];

    const points = [
      'fe4a695f579ef7ab2c2c87090c9fa401011dc1447ab3a79bfc585c3e',
      '1c38f3f0150f55037cc681191337125f86fe7da13de741bceb73d775',
      '7f068b2938067deef0cb9e29245e3adb769fa08fec66c0226bf2a4c3',
      '754bbf97167955acbf4736347585012549e21f5fbe715eb8ac46b383',
      '43e16424c53465f04f7dc852f8fb722fe91798d1791eaad587c8e140',
      'f548be89f91f7e390a87e80fa6e93e07e0ca66aef028627cb394b6a3',
      'abbe384107958636e24a6f4e15b35166a46403e57651437d57f35f11',
      '53a375d283cdded4430145a442aff768ef64d25aa0857e61793de06e',
      '16f026e8de215059ecf14f4a1be6253b7b10b36b55cc5e77caf870f9',
      '0391b06a0193eee73e9ec60f284ca78adbd4387b1eab266f70a6c7a6',
      'a928cfafba476f44cc4307faf39f8403f41caa42968974dcc554213f',
      '05569e1125025a938590032a917077ce8cc0dd5e8951b6a435db7d58',
      '82ff568b14f314b419ec39315b5fec4bd23f0e24a50143ed84e041ec',
      'cb6092c3532ba73670f6db59d6d1e58dc883863916c056b8520b002d',
      'cf1e4fab463c5c088a6986ecf8dcca9ea66c870810dd7c094c6585bf',
      '5c98d98b0a35b7f1c30015bf5d87fe9e7ef58000ab068b8c0e1ba74f',
      '5cecfd6acbe600ea9f3b09f222fc0a2b2e5f8ff065bdbb5a5d7b2f74',
      'd0510ee85b657f4a4d75fbe6951057256b4baa1d2964c7ad5b77033b',
      '04191a0552baf4958979c53e5819974c90e6f18b1bf88a3b4898bfde',
      'd811854af00a02b0d5f733ca5d900eacf6e829d6adc67be6c9aab79c',
      '83d1eec082d8e5c8306e10a64d5e86b5ccb935e580fda2d9e674dedb',
      '7c2915cd2b4d233da0ab57c6eece1dc8e9cfa5b416ad87e23249c1e2',
      'aca57392916a690cf75764174d83d2fae089c1b20282644bb9fcf592',
      '074a0918942f22a9d08bab553d001bd13e3d031d4afbb0fb4c56a8f1',
      'd69b7036b5973fbf92e100a5740eeebd917ba3f1bf89b5f31a882fb0',
      '0f5b93f73fd964120f9965ea0185734b03b8e107c65acf3075aaeb4d',
      'ca3bf1cb1ec35c028e34041cacab17b3817cefdd9fce99c526e9e85a',
      '322d6aa047224f3ec861ca240f58f8200b83e072f995e4144a367501',
      '3398c9bd6daf79600120db81225c942b43654c301dc84d03f9c232e5',
      '52e64c978cb8bf32ab6bd1bc4a815bedf2822889237ee3774fdabc8f',
      '785a70cb073f38eb60c054f349014c8c4431f39f6fd26a899f270627',
      'af08c7d774f1aa2511b782669b574c11ca54aad7ff9b326855177d88'
    ];

    const raws1 = [
      '55bbb23580f1d9136a63216273c9bcf0bae1bbf419582da807852a6f',
      '899269e872fe160eef71b68bdca7b09daf2d3719e64c5272f7da95fe',
      'a6dfc9c328021b8f3b970a64e6fc92cb3ea3e8455cd4134a8e1f6f13',
      '78b6b75bbeb56d172172390bf334bce739829d574101b9a9abd1d58f',
      'b6683e14bfb704b4a30198b1e749f281e0cbeb66bd8f7dc552d23a9b',
      '4737406664797e5de0653325367f1d7cfcddb7c497a389b361a3c6ea',
      'ecaedcf561a9cef24982fe697488d2b700f0f493448a5aca40eba5f1',
      'c1f1f075dfabd61e30aaa8847bb0a902f5b574711ae6dac9fdc6be69',
      '50937d89815b443e2477f2162a1702917f2682e135fd24f724be52a5',
      'dada6f1ca3025df5ef82312ffb4646803a33eb3d18cccae0fb5e0479',
      '652165998c34a072151fa8bb851cf99bdd5d405972c03da57620dfa4',
      'bde46116a7e8869afa8d44e4780254551a29130b0d0faedea565b2b5',
      'cf5cf511793eeac5dd92f1ab8298caa91cb1d1bbbee98ca3378da89d',
      'c3bc728fefe1c07dbae65df599047669320ddc77522dcb7dc698f062',
      'b139cd9385765b671ce55a160e33a7a92dd13f5597e4cec9c2ab180d',
      '4ccb33c7cd264aeb395633b6355eedcf8cca76b2e399a1c7797e8722',
      '123862213086a5ac72352997b7fa6a3dc044d7b1b05fa90eb3df88ab',
      '6d6c147067d5cc6d70feceaaa516f705ea2dd175caef47017106e0b9',
      'f9e8ddcd1c8e69d69013595f73bca48002abd28d98707b657a5739ee',
      'ac19c731e554f24e7a4934230de062a9c15542616998a5073b690eaf',
      'd09463ec1a4985f7d0a073cfe2ede57320f87ac8ccdc1427f231df25',
      '2675152e37ab41769c044a012782c914084fe1e7f1d3ce2daa245b6d',
      'b9b29fa849a9027856fa7fff40d2ef62815f7baead52b0a77e800118',
      '39d6a52e86fcf25df8ee9043a73fccedce991bfb0c49b4fbb322e53f',
      '9013bc5081d011bd320a9d1ba09697a05d6271c23341ad845ff137d3',
      'eda3c7c11e7f7a0768629b79ff46082407506d125a612f2b0e634b06',
      '854528c50f346f4aeff449200b481a2a84a58c992330ecb8622b1580',
      '76c8e99207f8cbbec61c157f22e38c8af7236b8b05eb1cf1a21c44ac',
      'd6affe21ea6a4ce98c3c5313e26f4d236d5cf2f390b64970b9db5077',
      '4824dac4751803f9cbb1e451771de0f0593e67a30b095752afb964b1',
      'c6fbc5d666c845ab267529300a5ef0b3f04f016d92349110bd2d1298',
      '3f74b4c95ac7836bbc0e7f6b38622543bc26b4dc8b407bb4c9532b4e'
    ];

    const raws2 = [
      'aa444dca7f0e26ec959cde9d8c36430f451e440be6a7d257f87ad590',
      '756d96178d01e9f1108e497423584f6250d2c8e619b3ad8d08256a01',
      '9b4c116dc6f60edb414e18d06ccc00a91e1fb875f1279825d4148ad2',
      'bccab1cfa1dfc513a3ea95796d60416125f7d29c132730476f388982',
      'e1a81967d83f3b8ddd0a98f8788f95cfe7a2800af91f89331ea1bdde',
      'aa6b137b54d63fdb192b6948c73b12c2a4f51d8392c4e49e7dae9ca7',
      '1351230a9e56310db67d01968b772d48ff0f0b6cbb75a535bf145a0e',
      '3d0e0f8a205429e1cf55577b844f56fd0a4a8b8ee519253602394196',
      '5fc8a5e851a4d82b2855f3245b5d08437ac16d9dad0d44160a58e7e4',
      '579b17561f2967a0ecddb005a276bad9cf39c1537355df9f01d738a1',
      '9ade9a6673cb5f8deae057447ae3066422a2bfa68d3fc25a89df205b',
      '411b9ee9581779650572bb1b87fdabaae5d6ecf4f2f051215a9a4d4a',
      'cf5cf511793eeac5dd92f1ab8298caa91cb1d1bbbee98ca3378da89d',
      'c3bc728fefe1c07dbae65df599047669320ddc77522dcb7dc698f062',
      'b139cd9385765b671ce55a160e33a7a92dd13f5597e4cec9c2ab180d',
      '4ccb33c7cd264aeb395633b6355eedcf8cca76b2e399a1c7797e8722',
      '5670eb921cc7b541851813a633253fb3946e708c93c25f0d4c3e4c80',
      'ba7d09398acf3b7b9480f0d9aef02bfd19646a83da70d6b0875198a2',
      'f9e8ddcd1c8e69d69013595f73bca48002abd28d98707b657a5739ee',
      'ac19c731e554f24e7a4934230de062a9c15542616998a5073b690eaf',
      'f10acf5d00e15eab3694dbb6dd04a379b5a2d78bfe716142f6bb8e6b',
      '890fcb1258d7f854b229311ba03770f35f83da07ee8676e7f5368cbb',
      '67b31e0a1c4bd033bd75f8fbb795e7edafa42bfad5c8cbaab08b43b4',
      'a01e5435ff02e4440c5592d8dd74cd446092a5a14325440333c8f43d',
      'c8eb8b275f84482b466a29ed95da63db6b3fa6e8d836ac0f6a395fd8',
      '1b82e4c68eca1746f73cbd0c998024057868ee43ebca73cdfc8bb644',
      '8a00038a1ebe477d53beefd94b3ce5201c5c1c35a6fbe09d03da8f4a',
      '80927892bc6739da812c7359820c36be0b298b4126ece22fd8e56822',
      '295001de1595b31673c3acec1d90b2dc92a30d0c6f49b68f4624af88',
      'b6db253b8ae7fc06344e1bae88e21f0fa6c1985cf4f6a8ad50469b4e',
      '98c32846b88a430c40e1f02116973a46b2baa343d35acf604bb8e83a',
      'ca9281c5aebadc3d755ab177a39b5c7097aab6386bd4f8acef0df61c'
    ];

    for (let i = 0; i < 32; i += 2) {
      const preimage = Buffer.from(preimages[i] + preimages[i + 1], 'hex');
      const key = Buffer.from(keys[i] + keys[i + 1], 'hex');
      const point = Buffer.from(points[i] + points[i + 1], 'hex');
      const raw1 = Buffer.from(raws1[i] + raws1[i + 1], 'hex');
      const raw2 = Buffer.from(raws2[i] + raws2[i + 1], 'hex');

      assert.strictEqual(ed448.publicKeyVerify(key), true);
      assert.bufferEqual(ed448.publicKeyFromUniform(preimage), key);
      assert.bufferEqual(x448.publicKeyFromUniform(preimage), point);
      assert.bufferEqual(ed448.publicKeyToUniform(key, (i / 2) & 1), raw1);
      assert.bufferEqual(x448.publicKeyToUniform(point, (i / 2) & 1), raw2);
      assert.bufferEqual(ed448.publicKeyFromUniform(raw1), key);
      assert.bufferEqual(x448.publicKeyFromUniform(raw2), point);
    }
  });

  it('should test random oracle encoding', () => {
    const bytes = SHAKE256.digest(Buffer.from('turn me into a point'), 112);
    const pub = ed448.publicKeyFromHash(bytes, true);
    const point = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + '10a221305c533586c7e3d0de886817f26300654540974051f4c4dbd3'
      + 'bdba79f6c6c52deb0ddbe4cdedfc8ba33f31f69913f8a35bae3d05d7'
      + '80');

    assert.bufferEqual(point, ''
      + 'bbf9b3970b4f192c2615dd66abbfe4f51b2b695da44d1578389de049'
      + '043d83433a011ef906f7154c96fefd592d1981283fb99e8925a45f30');

    assert.strictEqual(ed448.publicKeyVerify(pub), true);
    assert.strictEqual(x448.publicKeyVerify(point), true);
  });

  it('should test random oracle encoding (doubling)', () => {
    const bytes0 = SHAKE256.digest(Buffer.from('turn me into a point'), 56);
    const bytes = Buffer.concat([bytes0, bytes0]);
    const pub = ed448.publicKeyFromHash(bytes, true);
    const point = x448.publicKeyFromHash(bytes, true);

    assert.bufferEqual(pub, ''
      + 'a0eb4debe891d48d0a231f845d8cdcbe20887bf3feb4d01b00dbf7b2'
      + '83e21582a3e92d0b8cad7c12b42e1e1189ae785b572f25805ab7ae35'
      + '00');

    assert.bufferEqual(point, ''
      + '6fee3c18014c2c61dc1bc145c224d2b5c2e48ccbb41e007927d08435'
      + '6dd0a932c189fa810622612d982a0326760c6e74b39866bbd905f9df');

    assert.strictEqual(ed448.publicKeyVerify(pub), true);
    assert.strictEqual(x448.publicKeyVerify(point), true);
  });

  if (ed448.native === 2) {
    const native = ed448;
    const curve = require('../lib/js/ed448');

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
    const priv = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(priv);
    const bytes = ed448.publicKeyToHash(pub, 0);
    const out = ed448.publicKeyFromHash(bytes);

    assert.bufferEqual(out, pub);
  });

  it('should test equivalence edge cases', () => {
    const inf = ed448.publicKeyCombine([]);
    const x = Buffer.alloc(56, 0x00);
    const e = Buffer.from('feffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffff'
                        + 'feffffffffffffffffffffffffff'
                        + 'ffffffffffffffffffffffffffff00', 'hex');

    assert.bufferEqual(ed448.publicKeyConvert(e), x);
    assert.bufferEqual(x448.publicKeyConvert(x, false), inf);
    assert.throws(() => ed448.publicKeyConvert(inf));
  });

  describe('RFC 8032 vectors', () => {
    const batch = [];

    for (const [i, vector] of rfc8032.entries()) {
      if (!vector.algorithm.startsWith('Ed448'))
        continue;

      const ph = vector.algorithm === 'Ed448ph';
      const ctx = vector.ctx != null
                ? Buffer.from(vector.ctx, 'hex')
                : null;

      let msg = Buffer.from(vector.msg, 'hex');

      if (ph)
        msg = SHAKE256.digest(msg, 64);

      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      if (ph === false && ctx === null)
        batch.push([msg, sig, pub]);

      it(`should pass RFC 8032 vector (${vector.algorithm} #${i})`, () => {
        assert(ed448.privateKeyVerify(priv));
        assert(ed448.publicKeyVerify(pub));

        const sig_ = ed448.sign(msg, priv, ph, ctx);

        assert.bufferEqual(sig_, sig);

        assert(ed448.verify(msg, sig, pub, ph, ctx));
        assert(!ed448.verify(msg, sig, pub, !ph, ctx));

        if (msg.length > 0) {
          const msg_ = Buffer.from(msg);
          msg_[i % msg_.length] ^= 1;
          assert(!ed448.verify(msg_, sig, pub, ph, ctx));
          assert(!ed448.verifyBatch([[msg_, sig, pub]], ph, ctx));
        }

        {
          const sig_ = Buffer.from(sig);
          sig_[i % sig_.length] ^= 1;
          assert(!ed448.verify(msg, sig_, pub, ph, ctx));
        }

        {
          const pub_ = Buffer.from(pub);
          pub_[i % pub_.length] ^= 1;
          assert(!ed448.verify(msg, sig, pub_, ph, ctx));
        }

        if (ctx && ctx.length > 0) {
          const ctx_ = Buffer.from(ctx);
          ctx_[i % ctx_.length] ^= 1;
          assert(!ed448.verify(msg, sig, pub, ph, ctx_));
          assert(!ed448.verify(msg, sig, pub, ph, null));
        } else {
          const ctx_ = Buffer.alloc(1);
          assert(!ed448.verify(msg, sig, pub, true, ctx_));
          assert(!ed448.verify(msg, sig, pub, false, ctx_));
        }
      });
    }

    it('should do batch verification', () => {
      const [msg] = batch[0];

      assert.strictEqual(ed448.verifyBatch([]), true);
      assert.strictEqual(ed448.verifyBatch(batch), true);

      if (msg.length > 0) {
        msg[0] ^= 1;
        assert.strictEqual(ed448.verifyBatch(batch), false);
        msg[0] ^= 1;
      }
    });
  });

  it('should do covert ecdh', () => {
    const alicePriv = ed448.privateKeyGenerate();
    const alicePub = ed448.publicKeyCreate(alicePriv);
    const bobPriv = ed448.privateKeyGenerate();
    const bobPub = ed448.publicKeyCreate(bobPriv);
    const alicePreimage = ed448.publicKeyToHash(alicePub, 1); // Add 2-torsion.
    const alicePub2 = ed448.publicKeyFromHash(alicePreimage);
    const bobPreimage = ed448.publicKeyToHash(bobPub, 2); // Add 4-torsion.
    const bobPub2 = ed448.publicKeyFromHash(bobPreimage);

    assert(!ed448.publicKeyHasTorsion(alicePub));
    assert(!ed448.publicKeyHasTorsion(bobPub));
    assert(ed448.publicKeyHasTorsion(alicePub2));
    assert(ed448.publicKeyHasTorsion(bobPub2));

    const aliceSecret = ed448.derive(bobPub, alicePriv);
    const bobSecret = ed448.derive(alicePub, bobPriv);
    const aliceSecret2 = ed448.derive(bobPub2, alicePriv);
    const bobSecret2 = ed448.derive(alicePub2, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);
    assert.bufferEqual(aliceSecret2, bobSecret2);
    assert.bufferEqual(aliceSecret, aliceSecret2);
    assert.bufferEqual(bobSecret, bobSecret2);
  });

  it('should test serialization formats', () => {
    const priv = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(priv);
    const rawPriv = ed448.privateKeyExport(priv);
    const rawPub = ed448.publicKeyExport(pub);

    assert.bufferEqual(ed448.privateKeyImport(rawPriv), priv);
    assert.bufferEqual(ed448.publicKeyImport(rawPub), pub);
  });
});
