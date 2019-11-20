/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');

const parts = process.version.split(/[^\d]/);
const NODE_MAJOR = parts[1] >>> 0;

const ECDSA = (() => {
  if (!process.env.NODE_BACKEND || process.env.NODE_BACKEND === 'native') {
    if (NODE_MAJOR >= 10)
      return require('../lib/native/ecdsa');
  }
  return require('../lib/js/ecdsa');
})();

const random = require('../lib/random');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = new ECDSA('SECP256K1', require('../lib/sha256'));
const secp256k1n = require('../lib/secp256k1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1,
  secp256k1n
];

describe('ECDSA', function() {
  this.timeout(15000);

  for (const ec of curves) {
    it(`should generate keypair and sign DER (${ec.id})`, () => {
      const msg = random.randomBytes(ec.size);
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const pubu = ec.publicKeyConvert(pub, false);

      const sig = ec.signDER(msg, priv);
      assert(ec.verifyDER(msg, sig, pub));
      assert(ec.verifyDER(msg, sig, pubu));
      msg[0] ^= 1;
      assert(!ec.verifyDER(msg, sig, pub));
      assert(!ec.verifyDER(msg, sig, pubu));
      msg[0] ^= 1;
      assert(ec.verifyDER(msg, sig, pub));
      assert(ec.verifyDER(msg, sig, pubu));
      pub[2] ^= 1;
      assert(!ec.verifyDER(msg, sig, pub));
      assert(ec.verifyDER(msg, sig, pubu));
      pub[2] ^= 1;

      for (const c of [false, true]) {
        assert.bufferEqual(
          ec.privateKeyImport(ec.privateKeyExport(priv, c)),
          priv);

        assert.bufferEqual(
          ec.privateKeyImportPKCS8(ec.privateKeyExportPKCS8(priv, c)),
          priv);

        assert.bufferEqual(
          ec.privateKeyImportJWK(ec.privateKeyExportJWK(priv)),
          priv);

        for (const p of [pub, pubu]) {
          assert.bufferEqual(
            ec.publicKeyImport(ec.publicKeyExport(p, c), c),
            c ? pub : pubu);

          assert.bufferEqual(
            ec.publicKeyImportSPKI(ec.publicKeyExportSPKI(p, c), c),
            c ? pub : pubu);

          assert.bufferEqual(
            ec.publicKeyImportJWK(ec.publicKeyExportJWK(p), c),
            c ? pub : pubu);
        }
      }
    });

    it(`should generate keypair and sign RS (${ec.id})`, () => {
      const msg = random.randomBytes(ec.size);
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const pubu = ec.publicKeyConvert(pub, false);

      const sig = ec.sign(msg, priv);
      assert(ec.verify(msg, sig, pub));
      assert(ec.verify(msg, sig, pubu));
      sig[0] ^= 1;
      assert(!ec.verify(msg, sig, pub));
      assert(!ec.verify(msg, sig, pubu));
      sig[0] ^= 1;
      assert(ec.verify(msg, sig, pub));
      assert(ec.verify(msg, sig, pubu));
      pub[2] ^= 1;
      assert(!ec.verify(msg, sig, pub));
      assert(ec.verify(msg, sig, pubu));
    });

    it(`should fail with padded key (${ec.id})`, () => {
      const msg = random.randomBytes(ec.size);
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const pubu = ec.publicKeyConvert(pub, false);

      const sig = ec.sign(msg, priv);

      assert(ec.verify(msg, sig, pub));
      assert(ec.verify(msg, sig, pubu));

      const pad = (a, b) => Buffer.concat([a, Buffer.from([b])]);

      assert(!ec.verify(msg, sig, pad(pub, 0x00)));
      assert(!ec.verify(msg, sig, pad(pubu, 0x00)));
      assert(!ec.verify(msg, sig, pad(pub, 0x01)));
      assert(!ec.verify(msg, sig, pad(pubu, 0x01)));
      assert(!ec.verify(msg, sig, pad(pub, 0xff)));
      assert(!ec.verify(msg, sig, pad(pubu, 0xff)));

      if (pub[0] === 0x02)
        pubu[0] = 0x06;
      else
        pubu[0] = 0x07;

      assert(ec.verify(msg, sig, pubu));

      if (pub[0] === 0x02)
        pubu[0] = 0x07;
      else
        pubu[0] = 0x06;

      assert(!ec.verify(msg, sig, pubu));

      const zero = Buffer.alloc(0);

      assert(!ec.verify(zero, sig, pub));
      assert(!ec.verify(msg, zero, pub));
      assert(!ec.verify(msg, sig, zero));
    });

    it(`should do additive tweak (${ec.id})`, () => {
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const tweak = random.randomBytes(ec.size);

      tweak[0] = 0x00;

      const tpriv = ec.privateKeyTweakAdd(priv, tweak);
      const tpub = ec.publicKeyTweakAdd(pub, tweak);
      const zpub = ec.publicKeyCreate(tpriv);

      assert.bufferEqual(tpub, zpub);

      const msg = random.randomBytes(ec.size);

      const sig = ec.sign(msg, tpriv);
      assert(ec.verify(msg, sig, tpub));

      const der = ec.signDER(msg, tpriv);
      assert(ec.verifyDER(msg, der, tpub));

      const parent = ec.privateKeyTweakAdd(tpriv, ec.privateKeyNegate(tweak));
      assert.bufferEqual(parent, priv);

      const tweakPub = ec.publicKeyCreate(tweak);
      const parentPub = ec.publicKeyAdd(tpub, ec.publicKeyNegate(tweakPub));
      assert.bufferEqual(parentPub, pub);
    });

    it(`should do multiplicative tweak (${ec.id})`, () => {
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const tweak = random.randomBytes(ec.size);

      tweak[0] = 0x00;

      const tpriv = ec.privateKeyTweakMul(priv, tweak);
      const tpub = ec.publicKeyTweakMul(pub, tweak);
      const zpub = ec.publicKeyCreate(tpriv);

      assert.bufferEqual(tpub, zpub);

      const msg = random.randomBytes(ec.size);

      const sig = ec.sign(msg, tpriv);
      assert(ec.verify(msg, sig, tpub));

      const der = ec.signDER(msg, tpriv);
      assert(ec.verifyDER(msg, der, tpub));

      const parent = ec.privateKeyTweakMul(tpriv, ec.privateKeyInverse(tweak));
      assert.bufferEqual(parent, priv);
    });

    it(`should do ECDH (${ec.id})`, () => {
      const alicePriv = ec.privateKeyGenerate();
      const alicePub = ec.publicKeyCreate(alicePriv);
      const bobPriv = ec.privateKeyGenerate();
      const bobPub = ec.publicKeyCreate(bobPriv);

      const aliceSecret = ec.derive(bobPub, alicePriv);
      const bobSecret = ec.derive(alicePub, bobPriv);

      assert.bufferEqual(aliceSecret, bobSecret);
    });

    it('should generate keypair, sign DER and recover', () => {
      if (ec.id === 'P521')
        this.skip();

      const msg = random.randomBytes(ec.size);
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const pubu = ec.publicKeyConvert(pub, false);

      const {
        signature,
        recovery
      } = ec.signRecoverableDER(msg, priv);

      assert(ec.verifyDER(msg, signature, pub));
      assert(ec.verifyDER(msg, signature, pubu));

      const rpub = ec.recoverDER(msg, signature, recovery, true);
      const rpubu = ec.recoverDER(msg, signature, recovery, false);

      assert.bufferEqual(rpub, pub);
      assert.bufferEqual(rpubu, pubu);
    });

    it('should test serialization formats', () => {
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const rawPriv = ec.privateKeyExport(priv);
      const rawPub = ec.publicKeyExport(pub);

      assert.bufferEqual(ec.privateKeyImport(rawPriv), priv);
      assert.bufferEqual(ec.publicKeyImport(rawPub), pub);

      const jsonPriv = ec.privateKeyExportJWK(priv);
      const jsonPub = ec.publicKeyExportJWK(pub);

      assert.bufferEqual(ec.privateKeyImportJWK(jsonPriv), priv);
      assert.bufferEqual(ec.publicKeyImportJWK(jsonPub), pub);

      const asnPriv = ec.privateKeyExportPKCS8(priv);
      const asnPub = ec.publicKeyExportSPKI(pub);

      assert.bufferEqual(ec.privateKeyImportPKCS8(asnPriv), priv);
      assert.bufferEqual(ec.publicKeyImportSPKI(asnPub), pub);
    });
  }

  describe('RFC6979 vector', function() {
    function test(opt) {
      const curve = opt.curve;
      const key = Buffer.from(opt.key, 'hex');
      const pub = Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(opt.pub.x, 'hex'),
        Buffer.from(opt.pub.y, 'hex')
      ]);

      for (const c of opt.cases) {
        const hash = c.hash;
        const msg = Buffer.from(c.message, 'binary');
        const cr = Buffer.from(c.r, 'hex');
        const cs = Buffer.from(c.s, 'hex');
        const sig = Buffer.concat([cr, cs]);

        const desc = `should not fail on "${opt.name}" `
                   + `and hash ${hash.id} on "${c.message}"`;

        it(desc, () => {
          const dgst = hash.digest(msg);
          const sign = curve.sign(dgst, key);
          const r = sign.slice(0, curve.size);

          if (!c.custom && curve.native === 0)
            assert.bufferEqual(r, cr);

          assert(curve.publicKeyVerify(pub), 'Invalid public key');
          assert(curve.verify(dgst, sign, pub), 'Invalid signature (1)');
          assert(curve.verify(dgst, sig, pub), 'Invalid signature (2)');
        });
      }
    }

    test({
      name: 'ECDSA, 192 Bits (Prime Field)',
      curve: p192,
      key: '6fab034934e4c0fc9ae67f5b5659a9d7d1fefd187ee09fd4',
      pub: {
        x: 'ac2c77f529f91689fea0ea5efec7f210d8eea0b9e047ed56',
        y: '3bc723e57670bd4887ebc732c523063d0a7c957bc97c1c43'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: 'a1f00dad97aeec91c95585f36200c65f3c01812aa60378f5',
          s: 'e07ec1304c7c6c9debbe980b9692668f81d4de7922a0f97a'
        },
        {
          message: 'sample',
          hash: SHA256,
          custom: false,
          r: '4b0b8ce98a92866a2820e20aa6b75b56382e0f9bfd5ecb55',
          s: 'ccdb006926ea9565cbadc840829d8c384e06de1f1e381b85'
        },
        {
          message: 'test',
          hash: SHA224,
          custom: true,
          r: '6945a1c1d1b2206b8145548f633bb61cef04891baf26ed34',
          s: 'b7fb7fdfc339c0b9bd61a9f5a8eaf9be58fc5cba2cb15293'
        },
        {
          message: 'test',
          hash: SHA256,
          custom: false,
          r: '3a718bd8b4926c3b52ee6bbe67ef79b18cb6eb62b1ad97ae',
          s: '5662e6848a4a19b1f1ae2f72acd4b8bbe50f1eac65d9124f'
        }
      ]
    });

    test({
      name: 'ECDSA, 224 Bits (Prime Field)',
      curve: p224,
      key: 'f220266e1105bfe3083e03ec7a3a654651f45e37167e88600bf257c1',
      pub: {
        x: '00cf08da5ad719e42707fa431292dea11244d64fc51610d94b130d6c',
        y: 'eeab6f3debe455e3dbf85416f7030cbd94f34f2d6f232c69f3c1385a'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: '1cdfe6662dde1e4a1ec4cdedf6a1f5a2fb7fbd9145c12113e6abfd3e',
          s: 'a6694fd7718a21053f225d3f46197ca699d45006c06f871808f43ebc'
        },
        {
          message: 'sample',
          hash: SHA256,
          custom: false,
          r: '61aa3da010e8e8406c656bc477a7a7189895e7e840cdfe8ff42307ba',
          s: 'bc814050dab5d23770879494f9e0a680dc1af7161991bde692b10101'
        },
        {
          message: 'test',
          hash: SHA224,
          custom: true,
          r: 'c441ce8e261ded634e4cf84910e4c5d1d22c5cf3b732bb204dbef019',
          s: '902f42847a63bdc5f6046ada114953120f99442d76510150f372a3f4'
        },
        {
          message: 'test',
          hash: SHA256,
          custom: false,
          r: 'ad04dde87b84747a243a631ea47a1ba6d1faa059149ad2440de6fba6',
          s: '178d49b1ae90e3d8b629be3db5683915f4e8c99fdf6e666cf37adcfd'
        }
      ]
    });

    test({
      name: 'ECDSA, 256 Bits (Prime Field)',
      curve: p256,
      key: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
      pub: {
        x: '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6',
        y: '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: '53b2fff5d1752b2c689df257c04c40a587fababb3f6fc2702f1343af7ca9aa3f',
          s: 'b9afb64fdc03dc1a131c7d2386d11e349f070aa432a4acc918bea988bf75c74c'
        },
        {
          message: 'sample',
          hash: SHA256,
          custom: false,
          r: 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
          s: 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'
        },
        {
          message: 'test',
          hash: SHA224,
          custom: true,
          r: 'c37edb6f0ae79d47c3c27e962fa269bb4f441770357e114ee511f662ec34a692',
          s: 'c820053a05791e521fcaad6042d40aea1d6b1a540138558f47d0719800e18f2d'
        },
        {
          message: 'test',
          hash: SHA256,
          custom: false,
          r: 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367',
          s: '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083'
        }
      ]
    });

    test({
      name: 'ECDSA, 384 Bits (Prime Field)',
      curve: p384,
      key: '6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa4774078713' +
           '7d896d5724e4c70a825f872c9ea60d2edf5',
      pub: {
        x: 'ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b30' +
           '0c64def8f0ea9055866064a254515480bc13',
        y: '8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f' +
           '1c9db1288b231c3ae0d4fe7344fd2533264720'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: '42356e76b55a6d9b4631c865445dbe54e056d3b3431766d05092447' +
             '93c3f9366450f76ee3de43f5a125333a6be060122',
          s: '9da0c81787064021e78df658f2fbb0b042bf304665db721f077a429' +
             '8b095e4834c082c03d83028efbf93a3c23940ca8d'
        },
        {
          message: 'sample',
          hash: SHA384,
          custom: false,
          r: '94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d6' +
             '4c4ea95ad133c81a648152e44acf96e36dd1e80fabe46',
          s: '99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b' +
             '6351d0a3a94fa329c145786e679e7b82c71a38628ac8'
        },
        {
          message: 'test',
          hash: SHA384,
          custom: false,
          r: '8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36a' +
             'b775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db',
          s: 'ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13' +
             '173923e06a739f040649a667bf3b828246baa5a5'
        }
      ]
    });

    test({
      name: 'ECDSA, 521 Bits (Prime Field)',
      curve: p521,
      key: '0' +
           '0fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75' +
           'caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b' +
           '83538',
      pub: {
        x: '0' +
           '1894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd3' +
           '71123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f502' +
           '3a4',
        y: '0' +
           '0493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a2' +
           '8a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA384,
          custom: true,
          r: '0' +
             '1ea842a0e17d2de4f92c15315c63ddf72685c18195c2bb95e572b9c5136ca4' +
             'b4b576ad712a52be9730627d16054ba40cc0b8d3ff035b12ae75168397f5' +
             'd50c67451',
          s: '0' +
             '1f21a3cee066e1961025fb048bd5fe2b7924d0cd797babe0a83b66f1e35ee' +
             'af5fde143fa85dc394a7dee766523393784484bdf3e00114a1c857cde1aa2' +
             '03db65d61'
        },
        {
          message: 'sample',
          hash: SHA512,
          custom: false,
          r: '00' +
             'c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f1' +
             '74e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e3' +
             '77fa',
          s: '00' +
             '617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af2' +
             '82623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4' +
             'a67a'
        },
        {
          message: 'test',
          hash: SHA512,
          custom: false,
          r: '0' +
             '13e99020abf5cee7525d16b69b229652ab6bdf2affcaef38773b4b7d087' +
             '25f10cdb93482fdcc54edcee91eca4166b2a7c6265ef0ce2bd7051b7cef945' +
             'babd47ee6d',
          s: '0' +
             '1fbd0013c674aa79cb39849527916ce301c66ea7ce8b80682786ad60f98' +
             'f7e78a19ca69eff5c57400e3b3a0ad66ce0978214d13baf4e9ac60752f7b15' +
             '5e2de4dce3'
        }
      ]
    });
  });

  describe('Maxwell\'s trick', function() {
    const msg =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    const vectors = [
      {
        curve: p256,
        pub: '041548fc88953e06cd34d4b300804c5322cb48c24aaaa4d0' +
             '7a541b0f0ccfeedeb0ae4991b90519ea405588bdf699f5e6' +
             'd0c6b2d5217a5c16e8371062737aa1dae1',
        message: msg,
        sig: '3006020106020104',
        result: true
      },
      {
        curve: p256,
        pub: '04ad8f60e4ec1ebdb6a260b559cb55b1e9d2c5ddd43a41a2' +
             'd11b0741ef2567d84e166737664104ebbc337af3d861d352' +
             '4cfbc761c12edae974a0759750c8324f9a',
        message: msg,
        sig: '3006020106020104',
        result: true
      },
      {
        curve: p256,
        pub: '0445bd879143a64af5746e2e82aa65fd2ea07bba4e355940' +
             '95a981b59984dacb219d59697387ac721b1f1eccf4b11f43' +
             'ddc39e8367147abab3084142ed3ea170e4',
        message: msg,
        sig: '301502104319055358e8617b0c46353d039cdaae020104',
        result: true
      },
      {
        curve: p256,
        pub: '040feb5df4cc78b35ec9c180cc0de5842f75f088b4845697' +
             '8ffa98e716d94883e1e6500b2a1f6c1d9d493428d7ae7d9a' +
             '8a560fff30a3d14aa160be0c5e7edcd887',
        message: msg,
        sig: '301502104319055358e8617b0c46353d039cdaae020104',
        result: false
      },
      {
        curve: p384,
        pub: '0425e299eea9927b39fa92417705391bf17e8110b4615e9e' +
             'b5da471b57be0c30e7d89dbdc3e5da4eae029b300344d385' +
             '1548b59ed8be668813905105e673319d59d32f574e180568' +
             '463c6186864888f6c0b67b304441f82aab031279e48f047c31',
        message: msg,
        sig: '3006020103020104',
        result: true
      },
      {
        curve: p384,
        pub: '04a328f65c22307188b4af65779c1d2ec821c6748c6bd8dc' +
             '0e6a008135f048f832df501f7f3f79966b03d5bef2f187ec' +
             '34d85f6a934af465656fb4eea8dd9176ab80fbb4a27a649f' +
             '526a7dfe616091b78d293552bc093dfde9b31cae69d51d3afb',
        message: msg,
        sig: '3006020103020104',
        result: true
      },
      {
        curve: p384,
        pub: '04242e8585eaa7a28cc6062cab4c9c5fd536f46b17be1728' +
             '288a2cda5951df4941aed1d712defda023d10aca1c5ee014' +
             '43e8beacd821f7efa27847418ab95ce2c514b2b6b395ee73' +
             '417c83dbcad631421f360d84d64658c98a62d685b220f5aad4',
        message: msg,
        sig: '301d0218389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68e020104',
        result: true
      },
      {
        curve: p384,
        pub: '04cdf865dd743fe1c23757ec5e65fd5e4038b472ded2af26' +
             '1e3d8343c595c8b69147df46379c7ca40e60e80170d34a11' +
             '88dbb2b6f7d3934c23d2f78cfb0db3f3219959fad63c9b61' +
             '2ef2f20d679777b84192ce86e781c14b1bbb77eacd6e0520e2',
        message: msg,
        sig: '301d0218389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68e020104',
        result: false
      }
    ];

    for (const [i, vector] of vectors.entries()) {
      it(`should pass on vector #${i}`, () => {
        const curve = vector.curve;
        const key = Buffer.from(vector.pub, 'hex');
        const msg = Buffer.from(vector.message, 'hex');
        const sig = Buffer.from(vector.sig, 'hex');

        const actual = curve.verifyDER(msg, sig, key);
        assert.strictEqual(actual, vector.result);
      });
    }
  });

  // https://github.com/indutny/elliptic/issues/78
  const lax = {
    msg: 'de17556d2111ef6a964c9c136054870495b005b3942ad7b626'
       + '28af00293b9aa8',
    sig: '3045022100a9379b66c22432585cb2f5e1e85736c69cf5fdc9'
       + 'e1033ad583fc27f0b7c561d802202c7b5d9d92ceca742829ff'
       + 'be28ba6565faa8f94556cb091cbc39d2f11d45946700',
    pub: '04650a9a1deb523f636379ec70c29b3e1e832e314dea0f7911'
       + '60f3dba628f4f509360e525318bf7892af9ffe2f585bf7b264'
       + 'aa31792744ec1885ce17f3b1ef50f3'
  };

  for (const curve of [secp256k1, secp256k1n]) {
    const msg = Buffer.from(lax.msg, 'hex');
    const sig = Buffer.from(lax.sig, 'hex');
    const pub = Buffer.from(lax.pub, 'hex');

    it('should verify lax signature', () => {
      assert.strictEqual(curve.verifyDER(msg, sig, pub), true);
    });
  }

  for (const curve of [secp256k1, secp256k1n]) {
    it('should recover the public key from a signature', () => {
      const priv = curve.privateKeyGenerate();
      const pub = curve.publicKeyCreate(priv, true);
      const msg = Buffer.alloc(32, 0x01);
      const sig = curve.sign(msg, priv);

      let found = false;

      for (let i = 0; i < 4; i++) {
        const r = curve.recover(msg, sig, i, true);

        if (!r)
          continue;

        if (r.equals(pub)) {
          found = true;
          break;
        }
      }

      assert(found, 'the keys should match');
    });

    it('should fail to recover key when no quadratic residue available', () => {
      const msg = Buffer.from(
        'f75c6b18a72fabc0f0b888c3da58e004f0af1fe14f7ca5d8c897fe164925d5e9',
        'hex');

      const r = Buffer.from(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
        'hex');

      const s = Buffer.from(
        '8887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3',
        'hex');

      const sig = Buffer.concat([r, s]);

      assert.strictEqual(curve.recover(msg, sig, 0), null);
    });
  }

  it('should generate keypair, sign RS and recover', () => {
    const msg = random.randomBytes(secp256k1n.size);
    const priv = secp256k1n.privateKeyGenerate();
    const pub = secp256k1n.publicKeyCreate(priv);
    const pubu = secp256k1n.publicKeyConvert(pub, false);

    const {
      signature,
      recovery
    } = secp256k1n.signRecoverable(msg, priv);

    assert(secp256k1n.verify(msg, signature, pub));
    assert(secp256k1n.verify(msg, signature, pubu));

    const rpub = secp256k1n.recover(msg, signature, recovery, true);
    const rpubu = secp256k1n.recover(msg, signature, recovery, false);

    assert.bufferEqual(rpub, pub);
    assert.bufferEqual(rpubu, pubu);
  });

  it('should sign zero-length message', () => {
    const msg = Buffer.alloc(0);
    const key = p256.privateKeyGenerate();
    const pub = p256.publicKeyCreate(key);
    const sig = p256.sign(msg, key);
    assert(p256.verify(msg, sig, pub));
  });
});
