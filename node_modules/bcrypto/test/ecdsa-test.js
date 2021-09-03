'use strict';

const assert = require('bsert');
const fs = require('fs');
const rng = require('../lib/random');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = require('../lib/secp256k1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const {isStrictDER} = require('./util/bip66');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1
];

describe('ECDSA', function() {
  this.timeout(15000);

  for (const ec of curves) {
    describe(ec.id, () => {
      it(`should generate keypair and sign DER (${ec.id})`, () => {
        const msg = rng.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const sig = ec.signDER(msg, priv);

        if (ec.size <= 32)
          assert(isStrictDER(sig));

        assert(ec.isLowDER(sig));
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

          for (const p of [pub, pubu]) {
            assert.bufferEqual(
              ec.publicKeyImport(ec.publicKeyExport(p), c),
              c ? pub : pubu);
          }
        }
      });

      it(`should generate keypair and sign RS (${ec.id})`, () => {
        const msg = rng.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const sig = ec.sign(msg, priv);

        assert(ec.isLowS(sig));
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
        const msg = rng.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const sig = ec.sign(msg, priv);

        assert(ec.isLowS(sig));
        assert(ec.verify(msg, sig, pub));
        assert(ec.verify(msg, sig, pubu));

        const pad = (a, b) => Buffer.concat([a, Buffer.from([b])]);

        assert(!ec.verify(msg, sig, pad(pub, 0x00)));
        assert(!ec.verify(msg, sig, pad(pubu, 0x00)));
        assert(!ec.verify(msg, sig, pad(pub, 0x01)));
        assert(!ec.verify(msg, sig, pad(pubu, 0x01)));
        assert(!ec.verify(msg, sig, pad(pub, 0xff)));
        assert(!ec.verify(msg, sig, pad(pubu, 0xff)));

        pubu[0] = 0x06 | (pub[0] & 1);

        assert(ec.verify(msg, sig, pubu));

        pubu[0] = 0x06 | (pub[0] ^ 1);

        assert(!ec.verify(msg, sig, pubu));

        const zero = Buffer.alloc(0);

        assert(!ec.verify(zero, sig, pub));
        assert(!ec.verify(msg, zero, pub));
        assert(!ec.verify(msg, sig, zero));
      });

      it(`should do additive tweak (${ec.id})`, () => {
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const tweak = rng.randomBytes(ec.size);

        tweak[0] = 0x00;

        const tpriv = ec.privateKeyTweakAdd(priv, tweak);
        const tpub = ec.publicKeyTweakAdd(pub, tweak);
        const zpub = ec.publicKeyCreate(tpriv);

        assert.bufferEqual(tpub, zpub);

        const msg = rng.randomBytes(ec.size);

        const sig = ec.sign(msg, tpriv);

        assert(ec.isLowS(sig));
        assert(ec.verify(msg, sig, tpub));

        const der = ec.signDER(msg, tpriv);

        if (ec.size <= 32)
          assert(isStrictDER(der));

        assert(ec.isLowDER(der));
        assert(ec.verifyDER(msg, der, tpub));

        const parent = ec.privateKeyTweakAdd(tpriv, ec.privateKeyNegate(tweak));

        assert.bufferEqual(parent, priv);

        const tweakPub = ec.publicKeyCreate(tweak);
        const parentPub = ec.publicKeyCombine([tpub, ec.publicKeyNegate(tweakPub)]);

        assert.bufferEqual(parentPub, pub);
      });

      it(`should do multiplicative tweak (${ec.id})`, () => {
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const tweak = rng.randomBytes(ec.size);

        tweak[0] = 0x00;

        const tpriv = ec.privateKeyTweakMul(priv, tweak);
        const tpub = ec.publicKeyTweakMul(pub, tweak);
        const zpub = ec.publicKeyCreate(tpriv);

        assert.bufferEqual(tpub, zpub);

        const msg = rng.randomBytes(ec.size);

        const sig = ec.sign(msg, tpriv);

        assert(ec.isLowS(sig));
        assert(ec.verify(msg, sig, tpub));

        const der = ec.signDER(msg, tpriv);

        if (ec.size <= 32)
          assert(isStrictDER(der));

        assert(ec.isLowDER(der));
        assert(ec.verifyDER(msg, der, tpub));

        const parent = ec.privateKeyTweakMul(tpriv, ec.privateKeyInvert(tweak));

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

      it(`should generate keypair, sign DER and recover (${ec.id})`, () => {
        const msg = rng.randomBytes(ec.size);
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const pubu = ec.publicKeyConvert(pub, false);

        const [
          signature,
          recovery
        ] = ec.signRecoverableDER(msg, priv);

        if (ec.size <= 32)
          assert(isStrictDER(signature));

        assert(ec.verifyDER(msg, signature, pub));
        assert(ec.verifyDER(msg, signature, pubu));

        const rpub = ec.recoverDER(msg, signature, recovery, true);
        const rpubu = ec.recoverDER(msg, signature, recovery, false);

        assert.bufferEqual(rpub, pub);
        assert.bufferEqual(rpubu, pubu);
      });

      it(`should test serialization formats (${ec.id})`, () => {
        const priv = ec.privateKeyGenerate();
        const pub = ec.publicKeyCreate(priv);
        const rawPriv = ec.privateKeyExport(priv);
        const rawPub = ec.publicKeyExport(pub);

        assert.bufferEqual(ec.privateKeyImport(rawPriv), priv);
        assert.bufferEqual(ec.publicKeyImport(rawPub), pub);
      });
    });
  }

  describe('RFC6979 vector', () => {
    const test = (opt) => {
      const curve = opt.curve;
      const key = Buffer.from(opt.key, 'hex');
      const pub = Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(opt.pub.x, 'hex'),
        Buffer.from(opt.pub.y, 'hex')
      ]);

      for (const c of opt.cases) {
        const hash = c.hash;
        const preimage = Buffer.from(c.message, 'binary');
        const r = Buffer.from(c.r, 'hex');
        const s = Buffer.from(c.s, 'hex');
        const sig = Buffer.concat([r, s]);

        const desc = `should not fail on "${opt.name}" `
                   + `and hash ${hash.id} on "${c.message}"`;

        it(desc, () => {
          const msg = hash.digest(preimage);
          const sig2 = curve.sign(msg, key);

          if (!c.custom)
            assert.bufferEqual(sig2, curve.signatureNormalize(sig));

          assert(curve.isLowS(sig2));
          assert(curve.publicKeyVerify(pub), 'Invalid public key');
          assert(curve.verify(msg, sig2, pub), 'Invalid signature (1)');
          assert(curve.verify(msg, sig, pub), 'Invalid signature (2)');
        });
      }
    };

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
      key: '6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba'
         + '9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5',
      pub: {
        x: 'ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e'
         + '06aae5286b300c64def8f0ea9055866064a254515480bc13',
        y: '8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9'
         + 'f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA224,
          custom: true,
          r: '42356e76b55a6d9b4631c865445dbe54e056d3b3431766d0'
           + '509244793c3f9366450f76ee3de43f5a125333a6be060122',
          s: '9da0c81787064021e78df658f2fbb0b042bf304665db721f'
           + '077a4298b095e4834c082c03d83028efbf93a3c23940ca8d'
        },
        {
          message: 'sample',
          hash: SHA384,
          custom: false,
          r: '94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa7'
           + '3d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46',
          s: '99ef4aeb15f178cea1fe40db2603138f130e740a19624526'
           + '203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8'
        },
        {
          message: 'test',
          hash: SHA384,
          custom: false,
          r: '8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36'
           + 'ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db',
          s: 'ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b'
           + '827c2f13173923e06a739f040649a667bf3b828246baa5a5'
        }
      ]
    });

    test({
      name: 'ECDSA, 521 Bits (Prime Field)',
      curve: p521,
      key: '00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75ca'
        +  'a896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538',
      pub: {
        x: '01894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd37'
         + '1123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a4',
        y: '00493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28'
         + 'a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5'
      },
      cases: [
        {
          message: 'sample',
          hash: SHA384,
          custom: true,
          r: '01ea842a0e17d2de4f92c15315c63ddf72685c18195c2bb95e572b9c5136ca4b4b'
           + '576ad712a52be9730627d16054ba40cc0b8d3ff035b12ae75168397f5d50c67451',
          s: '01f21a3cee066e1961025fb048bd5fe2b7924d0cd797babe0a83b66f1e35eeaf5f'
           + 'de143fa85dc394a7dee766523393784484bdf3e00114a1c857cde1aa203db65d61'
        },
        {
          message: 'sample',
          hash: SHA512,
          custom: false,
          r: '00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f17'
           + '4e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa',
          s: '00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af28'
           + '2623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a'
        },
        {
          message: 'test',
          hash: SHA512,
          custom: false,
          r: '013e99020abf5cee7525d16b69b229652ab6bdf2affcaef38773b4b7d08725f10c'
           + 'db93482fdcc54edcee91eca4166b2a7c6265ef0ce2bd7051b7cef945babd47ee6d',
          s: '01fbd0013c674aa79cb39849527916ce301c66ea7ce8b80682786ad60f98f7e78a'
           + '19ca69eff5c57400e3b3a0ad66ce0978214d13baf4e9ac60752f7b155e2de4dce3'
        }
      ]
    });
  });

  describe('Custom Vectors', () => {
    const getVectors = (curve) => {
      const id = curve.id.toLowerCase();
      const file = `${__dirname}/data/sign/${id}.json`;
      const text = fs.readFileSync(file, 'utf8');
      const vectors = JSON.parse(text);

      return vectors.map((vector) => {
        return vector.map((item) => {
          if (typeof item !== 'string')
            return item;
          return Buffer.from(item, 'hex');
        });
      });
    };

    for (const curve of curves) {
      for (const [i, vector] of getVectors(curve).entries()) {
        const [
          priv,
          pub,
          tweak,
          privAdd,
          privMul,
          privNeg,
          privInv,
          pubAdd,
          pubMul,
          pubNeg,
          pubDbl,
          pubConv,
          pubHybrid,
          ,
          ,
          ,
          ,
          msg,
          sig,
          der,
          param,
          other,
          secret
        ] = vector;

        it(`should create and tweak key (${i}) (${curve.id})`, () => {
          assert(curve.privateKeyVerify(priv));
          assert(curve.publicKeyVerify(pub));
          assert(curve.publicKeyVerify(pubConv));
          assert(curve.publicKeyVerify(pubHybrid));

          const tweakNeg = curve.privateKeyNegate(tweak);
          const tweakInv = curve.privateKeyInvert(tweak);

          assert.bufferEqual(curve.publicKeyCreate(priv), pub);
          assert.bufferEqual(curve.privateKeyTweakAdd(priv, tweak), privAdd);
          assert.bufferEqual(curve.privateKeyTweakAdd(privAdd, tweakNeg), priv);
          assert.bufferEqual(curve.privateKeyTweakMul(priv, tweak), privMul);
          assert.bufferEqual(curve.privateKeyTweakMul(privMul, tweakInv), priv);
          assert.bufferEqual(curve.privateKeyNegate(priv), privNeg);
          assert.bufferEqual(curve.privateKeyInvert(priv), privInv);
          assert.bufferEqual(curve.publicKeyTweakAdd(pub, tweak), pubAdd);
          assert.bufferEqual(curve.publicKeyTweakAdd(pubAdd, tweakNeg), pub);
          assert.bufferEqual(curve.publicKeyTweakMul(pub, tweak), pubMul);
          assert.bufferEqual(curve.publicKeyTweakMul(pubMul, tweakInv), pub);
          assert.bufferEqual(curve.publicKeyNegate(pub), pubNeg);
          assert.bufferEqual(curve.publicKeyCombine([pub, pub]), pubDbl);
          assert.bufferEqual(curve.publicKeyCombine([pubDbl, pubNeg]), pub);
          assert.bufferEqual(curve.publicKeyCombine([pub, pubNeg, pub]), pub);
          assert.bufferEqual(curve.publicKeyCreate(priv, false), pubConv);
          assert.bufferEqual(curve.publicKeyConvert(pub, false), pubConv);
          assert.bufferEqual(curve.publicKeyConvert(pubConv, true), pub);

          assert.throws(() => curve.publicKeyCombine([pub, pubNeg]));
        });

        it(`should reserialize key (${i}) (${curve.id})`, () => {
          const rawPriv = curve.privateKeyExport(priv);
          const rawPub = curve.publicKeyExport(pub);

          assert.bufferEqual(curve.privateKeyImport(rawPriv), priv);
          assert.bufferEqual(curve.publicKeyImport(rawPub), pub);
        });

        it(`should check signature (${i}) (${curve.id})`, () => {
          if (curve.size <= 32)
            assert(isStrictDER(der));

          assert(curve.isLowS(sig));
          assert(curve.isLowDER(der));
          assert(curve.signatureExport(sig), der);
          assert(curve.signatureImport(der), sig);
        });

        it(`should recover public key (${i}) (${curve.id})`, () => {
          assert.bufferEqual(curve.recover(msg, sig, param), pub);
          assert.bufferEqual(curve.recoverDER(msg, der, param), pub);
          assert.bufferEqual(curve.recover(msg, sig, param, false), pubConv);
          assert.bufferEqual(curve.recoverDER(msg, der, param, false), pubConv);
        });

        it(`should derive shared secret (${i}) (${curve.id})`, () => {
          assert.bufferEqual(curve.derive(pub, other), secret);
          assert.bufferEqual(curve.derive(pubConv, other), secret);
          assert.bufferEqual(curve.derive(pubHybrid, other), secret);
        });

        it(`should sign and verify (${i}) (${curve.id})`, () => {
          const sig2 = curve.sign(msg, priv);
          const [sig3, param2] = curve.signRecoverable(msg, priv);
          const der2 = curve.signDER(msg, priv);
          const [der3, param3] = curve.signRecoverableDER(msg, priv);

          if (curve.size <= 32) {
            assert(isStrictDER(der2));
            assert(isStrictDER(der3));
          }

          assert.bufferEqual(sig2, sig);
          assert.bufferEqual(sig3, sig);
          assert.strictEqual(param2, param);
          assert.bufferEqual(der2, der);
          assert.bufferEqual(der3, der);
          assert.strictEqual(param3, param);

          assert(curve.verify(msg, sig, pub));
          assert(curve.verifyDER(msg, der, pub));
          assert(curve.verify(msg, sig, pubConv));
          assert(curve.verifyDER(msg, der, pubConv));
          assert(curve.verify(msg, sig, pubHybrid));
          assert(curve.verifyDER(msg, der, pubHybrid));

          msg[0] ^= 1;

          assert(!curve.verify(msg, sig, pub));
          assert(!curve.verifyDER(msg, der, pub));

          msg[0] ^= 1;
          sig[0] ^= 1;
          der[0] ^= 1;

          assert(!curve.verify(msg, sig, pub));
          assert(!curve.verifyDER(msg, der, pub));

          sig[0] ^= 1;
          der[0] ^= 1;
          pub[2] ^= 1;

          assert(!curve.verify(msg, sig, pub));
          assert(!curve.verifyDER(msg, der, pub));

          pub[2] ^= 1;

          assert(curve.verify(msg, sig, pub));
          assert(curve.verifyDER(msg, der, pub));
        });

        it(`should sign and verify schnorr (${i}) (${curve.id})`, () => {
          if (curve.id === 'P224')
            this.skip();

          const pubu = curve.publicKeyConvert(pub, false);
          const msg = Buffer.alloc(32, 0xaa);
          const sig = curve.schnorrSign(msg, priv);

          assert(curve.schnorrVerify(msg, sig, pub));
          assert(curve.schnorrVerify(msg, sig, pubu));
          assert(curve.schnorrVerifyBatch([]));
          assert(curve.schnorrVerifyBatch([[msg, sig, pub]]));

          msg[0] ^= 1;

          assert(!curve.schnorrVerify(msg, sig, pub));
          assert(!curve.schnorrVerifyBatch([[msg, sig, pub]]));

          msg[0] ^= 1;
          sig[0] ^= 1;

          assert(!curve.schnorrVerify(msg, sig, pub));
          assert(!curve.schnorrVerifyBatch([[msg, sig, pub]]));

          sig[0] ^= 1;
          pub[2] ^= 1;

          assert(!curve.schnorrVerify(msg, sig, pub));
          assert(!curve.schnorrVerifyBatch([[msg, sig, pub]]));

          pub[2] ^= 1;

          assert(curve.schnorrVerify(msg, sig, pub));
          assert(curve.schnorrVerifyBatch([[msg, sig, pub]]));
        });
      }
    }
  });

  describe('Maxwell\'s trick', () => {
    const msg =
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    const vectors = [
      {
        curve: p256,
        pub: '041548fc88953e06cd34d4b300804c5322cb48c24aaaa4d0'
           + '7a541b0f0ccfeedeb0ae4991b90519ea405588bdf699f5e6'
           + 'd0c6b2d5217a5c16e8371062737aa1dae1',
        message: msg,
        sig: '3006020106020104',
        result: true
      },
      {
        curve: p256,
        pub: '04ad8f60e4ec1ebdb6a260b559cb55b1e9d2c5ddd43a41a2'
           + 'd11b0741ef2567d84e166737664104ebbc337af3d861d352'
           + '4cfbc761c12edae974a0759750c8324f9a',
        message: msg,
        sig: '3006020106020104',
        result: true
      },
      {
        curve: p256,
        pub: '0445bd879143a64af5746e2e82aa65fd2ea07bba4e355940'
           + '95a981b59984dacb219d59697387ac721b1f1eccf4b11f43'
           + 'ddc39e8367147abab3084142ed3ea170e4',
        message: msg,
        sig: '301502104319055358e8617b0c46353d039cdaae020104',
        result: true
      },
      {
        curve: p256,
        pub: '040feb5df4cc78b35ec9c180cc0de5842f75f088b4845697'
           + '8ffa98e716d94883e1e6500b2a1f6c1d9d493428d7ae7d9a'
           + '8a560fff30a3d14aa160be0c5e7edcd887',
        message: msg,
        sig: '301502104319055358e8617b0c46353d039cdaae020104',
        result: false
      },
      {
        curve: p384,
        pub: '0425e299eea9927b39fa92417705391bf17e8110b4615e9e'
           + 'b5da471b57be0c30e7d89dbdc3e5da4eae029b300344d385'
           + '1548b59ed8be668813905105e673319d59d32f574e180568'
           + '463c6186864888f6c0b67b304441f82aab031279e48f047c31',
        message: msg,
        sig: '3006020103020104',
        result: true
      },
      {
        curve: p384,
        pub: '04a328f65c22307188b4af65779c1d2ec821c6748c6bd8dc'
           + '0e6a008135f048f832df501f7f3f79966b03d5bef2f187ec'
           + '34d85f6a934af465656fb4eea8dd9176ab80fbb4a27a649f'
           + '526a7dfe616091b78d293552bc093dfde9b31cae69d51d3afb',
        message: msg,
        sig: '3006020103020104',
        result: true
      },
      {
        curve: p384,
        pub: '04242e8585eaa7a28cc6062cab4c9c5fd536f46b17be1728'
           + '288a2cda5951df4941aed1d712defda023d10aca1c5ee014'
           + '43e8beacd821f7efa27847418ab95ce2c514b2b6b395ee73'
           + '417c83dbcad631421f360d84d64658c98a62d685b220f5aad4',
        message: msg,
        sig: '301d0218389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68e020104',
        result: true
      },
      {
        curve: p384,
        pub: '04cdf865dd743fe1c23757ec5e65fd5e4038b472ded2af26'
           + '1e3d8343c595c8b69147df46379c7ca40e60e80170d34a11'
           + '88dbb2b6f7d3934c23d2f78cfb0db3f3219959fad63c9b61'
           + '2ef2f20d679777b84192ce86e781c14b1bbb77eacd6e0520e2',
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

        if (curve.size <= 32)
          assert(isStrictDER(sig));

        assert.strictEqual(actual, vector.result);
      });
    }
  });

  describe('Specific Cases', () => {
    it('should verify lax signature', () => {
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

      const msg = Buffer.from(lax.msg, 'hex');
      const sig = Buffer.from(lax.sig, 'hex');
      const pub = Buffer.from(lax.pub, 'hex');

      assert(!isStrictDER(sig));
      assert(secp256k1.isLowDER(sig));

      assert.strictEqual(secp256k1.verifyDER(msg, sig, pub), true);
    });

    it('should recover the public key from a signature', () => {
      const priv = secp256k1.privateKeyGenerate();
      const pub = secp256k1.publicKeyCreate(priv, true);
      const msg = Buffer.alloc(32, 0x01);
      const sig = secp256k1.sign(msg, priv);

      let found = false;

      for (let i = 0; i < 4; i++) {
        const r = secp256k1.recover(msg, sig, i, true);

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

      assert.strictEqual(secp256k1.recover(msg, sig, 0), null);
      assert.strictEqual(secp256k1.recover(msg, sig, 1), null);
      assert.strictEqual(secp256k1.recover(msg, sig, 2), null);
      assert.strictEqual(secp256k1.recover(msg, sig, 3), null);
    });

    it('should normalize high S signature', () => {
      const der = Buffer.from(''
        + '304502203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562'
        + 'e9afde2c022100ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485f'
        + 'cf2ce0d03b2ef0',
        'hex');

      const hi = Buffer.from(''
        + '3e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c'
        + 'ab1e3da73d67e32045a20e0b999e049978ea8d6ee5480d485fcf2ce0d03b2ef0',
        'hex');

      const lo = Buffer.from(''
        + '3e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c'
        + '54e1c258c2981cdfba5df1f46661fb6541c44f77ca0092f3600331abfffb1251',
        'hex');

      assert(isStrictDER(der));
      assert(!secp256k1.isLowDER(der));
      assert(!secp256k1.isLowS(hi));
      assert.bufferEqual(secp256k1.signatureExport(hi), der);
      assert.bufferEqual(secp256k1.signatureImport(der), hi);
      assert.bufferEqual(secp256k1.signatureNormalize(hi), lo);
      assert.bufferEqual(secp256k1.signatureNormalizeDER(der),
                         secp256k1.signatureExport(lo));
    });

    it('should generate keypair, sign RS and recover', () => {
      const msg = rng.randomBytes(secp256k1.size);
      const priv = secp256k1.privateKeyGenerate();
      const pub = secp256k1.publicKeyCreate(priv);
      const pubu = secp256k1.publicKeyConvert(pub, false);

      const [
        signature,
        recovery
      ] = secp256k1.signRecoverable(msg, priv);

      assert(secp256k1.isLowS(signature));
      assert(secp256k1.verify(msg, signature, pub));
      assert(secp256k1.verify(msg, signature, pubu));

      const rpub = secp256k1.recover(msg, signature, recovery, true);
      const rpubu = secp256k1.recover(msg, signature, recovery, false);

      assert.bufferEqual(rpub, pub);
      assert.bufferEqual(rpubu, pubu);
    });

    it('should sign zero-length message', () => {
      const msg = Buffer.alloc(0);
      const key = p256.privateKeyGenerate();
      const pub = p256.publicKeyCreate(key);
      const sig = p256.sign(msg, key);

      assert(p256.isLowS(sig));
      assert(p256.verify(msg, sig, pub));
    });
  });

  describe('Maps', () => {
    const invert = (curve, point) => {
      const out = [];

      for (let i = 0; i < 4; i++) {
        let u;

        try {
          u = curve.publicKeyToUniform(point, i);
        } catch (e) {
          u = null;
        }

        out.push(u);
      }

      return out;
    };

    const equal = (items, expect) => {
      assert(Array.isArray(items));
      assert(Array.isArray(expect));
      assert(items.length === expect.length);

      for (let i = 0; i < items.length; i++) {
        assert(items[i] === null || Buffer.isBuffer(items[i]));
        assert(expect[i] === null || typeof expect[i] === 'string');

        if (expect[i] === null) {
          assert.strictEqual(items[i], null);
          continue;
        }

        assert(Buffer.isBuffer(items[i]));
        assert.bufferEqual(items[i], expect[i], 'hex');
      }
    };

    it('should create point from uniform bytes (sswu)', () => {
      const preimages = [
        '35b83b4ecbe82852b8ea85b22457bd394b9345bca6279040018e13cc2c129d28',
        '5718a83b1ddccc89f2d3f542582cedb952acfaa9dba017989fe834770f268c9b',
        'a5e2705cb7738969770abb57e45b9e928989e5897cda3e94911463ec15bfe54e',
        '427873e1671955d3e6dbefcc6288f965606f5b4f4bd4839d55eea01ffd5e995a',
        '65916f9c9569edf1ce4be95d534540f00ae71709a8f1ec639d19deb2ab03fbe9',
        'd60b38410ad3eee1032097a1695f9a145257b707fc9887f4ee4648c962dd060b',
        '03823aa8a0ed65157cc47038f2cbe7a874414ed39a69704a570137352a6abc48',
        '54b8cdf2d6baa8aef27d824b8b07e0aef4ea502006abf4116ab27b982d954668',
        'e0b5962874d9d82eb0babe9a84e8ce9eeb18897fe7201fd229061f221f16f263',
        'e9e774c37a0e1f8f5180ca2bae373048d967c7c167678ea71b306228925e4d17',
        '8a5ad9ed6aacd537097d8446094e64928a2d4d74a5d33b2d1a1e1058215898e8',
        '1e8ffa3cf7d14b20afabb2d7e80ce1f292bfd9f5bf53fcb7951be7aec8a3ad61',
        '63cd876bf3d1457aec631c644d56920dd3db2668099c68f9cdc717425b088fba',
        '28b6ad8f403e5706188c4a593afd0c858ee9073afc7d320b31a0cf58ffb74387',
        '071c320d9d8fea6d4d0155b8ba07d681ffbc7b3f43c2ea7afa0d5b3c8d4a940b',
        'd88cc0e48fb5ff30361ae72180f1fc19e0ec0872e1ecd65f75e81538ebe64718'
      ];

      const keys = [
        '02a01642e1514f0e1e8fd77d4b936588fc032c284fb9a1ed0b2f0adf9f7fa8f26f',
        '03594ac428fdafe620642cdc6003cbe6c53945f2313241dec0c126729fa5678895',
        '028f50157f1ad5c595299df91d09bc6f06b28e02bd671068d5b8ef36025f285f73',
        '02c1ca386637a6996ae52908c9c9843a6631f1cc6e9ee401ddf4bec7cc6b27a5d6',
        '03856b6f8b410380a8a3b85e633d0c793ae2ab18d53a891a8a0811cd669b45ad39',
        '032bd1a6a1a58f5266bfa2a9a5827c57982812c2d03b218ba48f09557f14d1c2d8',
        '02676e6d384f2ed89140c28f470db42203cae775a006154c0f5240afd40659016b',
        '02093d0e85f000e3cabb216c6e3ef5373f7f81af95ac5b1e40710288b29b4af5f1',
        '033c7ff421c31fad987f43b5f7ec9cc2f05d9a6370bb27cebbb6b0dace33721b52',
        '035a4848053a7cc0e941e8b1a07cf244d7cd74f3f4c85d4431fc9e2356a05933c2',
        '02d97edf59aeb90a26a055ee35668d11c15109c695eedd212859bcfa2a93de887f',
        '036f47ef3e1db92872297f2e96bd409ca4008231024573612873649f2c06e6f8c7',
        '026dfed33e82cb01df4a7121ba640bf0e8f07fcde93bef0e624a7c844aa72edcf4',
        '03d919eb293fa8556929cd900a9ed216536108010a2d7b2869d3fa2e4354f6b6d4',
        '03a58e4d908391a74e3ba161d1e9d717bd9657937b306be961abafc21cfb47c396',
        '02f7000a51ed76f9fee8a7c5bbd9e9ccedb8078be00407a47de00f0072af53be7e'
      ];

      for (let i = 0; i < 16; i++) {
        const preimage = Buffer.from(preimages[i], 'hex');
        const key = Buffer.from(keys[i], 'hex');

        assert.strictEqual(p256.publicKeyVerify(key), true);
        assert.bufferEqual(p256.publicKeyFromUniform(preimage), key);
      }
    });

    it('should do random oracle encoding (sswu)', () => {
      const bytes = SHA512.digest(Buffer.from('turn me into a point'));
      const pub = p256.publicKeyFromHash(bytes);

      assert.strictEqual(p256.publicKeyVerify(pub), true);

      assert.bufferEqual(pub,
        '02b84b65815d61a50646b891ccf7e4c80c66c0d7eafbce5d3e5f17de02a16748da');
    });

    it('should test sswu inversion', () => {
      const points = [
        '03d4e98f72e5297cf6b8524cdb4e376159d938fa509d838cdfcfbb8118cc9d4d68',
        '022351ee8eef9ac7cdd83137634a17b36661dfb124031b5d96a252e42ba3fe60a8',
        '02a2fdaf95ba9d08e5ce394b6ad5ba7b3a301684c450d1826ea1f5851254104c92',
        '0365fc3c35cc7355d057f283b100d6262e54ccf124a4de44f12932b94b3e7f926b',
        '02ce8880c3b2d2751dff85a0c38ac160bed37790a738998a90501d01651a383095',
        '02378a5d28e723261056ce893d68055bc3490d257a469d953bfe50bf75ad199741',
        '03af56385618d677e5a84f42ee3098b254569da7aa71714e06de3ebfe376fc3df9',
        '02c5966a274e918c3209fb68cbfad09973d0ea529932c343aa98931947bcc32e07',
        '02b2d43d621edfdaa4c0041b2bed9208e56d4a067400c51f3b61d6da7f6c1470dd',
        '02256515f6fa166b25eb2c96930a083c75ef5fbd8a1285ae9e0cd39935acc56ae2',
        '02b7ffd48508c7acef95d243c093a20895d6daecb7ae66cd284dca7240919959ff',
        '036619b9c0409b593fbd47dad2fff8d61cd1956d7ba1062f545f638e26ceb85e63',
        '0286380443420a28d7efc700b6ae88319431bf9094b5e36cfe987b46c128b3a508',
        '0391cd16cd61348ec734206e28aab542b3cb1bb899abe9a2a07ddbc7bda2836bdb',
        '0230cb9f78a927c3b59445683fac880d14572f9381b3fb4bf488eb23c8a3395226',
        '02dc6631462b3c0befc9fe2edb05101c1dd77ddb1b3252bd3645bfef56b68206bb',
        '021a7d8c905d1bbcc6d65f7770e33ae542e55e4a5a759abacdc8db36e824115a55',
        '02aaa95e61bb232cea60a950fddc31c2069a896b00921c0de596828096b48429a9',
        '0329d4949d3aafedebfe07d53cef85115917ee04e1b5ef54fe0749835b8e407eac',
        '034c9f12b1dce890b25676a2b92070158a1f5e6cd1ba4bf7255ed2961b55309153'
      ];

      const expect = [
        [
          null,
          null,
          null,
          null
        ],
        [
          null,
          '326bf69614950f07d07c907e510ea4e31a90c0f401a5a7e7e616f8704fddf77e',
          'e26eb65a779d9db778ed053a32c56b06d0be1bf4cac1b3b868730bf975007ec8',
          null
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          '6515e139a57d184d151bf514eb9b210b72be514115bfb4a750230ab5ba1c3bf9',
          null,
          null,
          'dfd1acfb77363a81e347b0e5990bf762171ce48fc380071b19e0422892837937'
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          null,
          'de8abc89ec6bdfa0ce6f4bd00d21717f951c811e3918401f10c071e7fc0c2bb9',
          '0e235e38d8252d17bd71709d42d9a123930afd128f256c1acda7dab311b9ebb5',
          null
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          'a206069fb24a49af0b057385bda9404bd4fe8c17c9fab962560ec87eb72f3446',
          null,
          null,
          '98eeeba60834726daca955c157ec67416bc77faf28c152c854782f32760d5d60'
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          'ec9d52ca1abdd8ec22b7b5b83dc7f34c1121df077cbcc2724c365a29ac103190',
          null,
          null,
          '1966ecdd34a8068c66644e318e043329addf0233f095761cd5679438949fdc44'
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          null,
          'db40134a1c4e28f8619805dc9b02fe3edfeb2bf9e9d6bf75055302fa0ba91174',
          'f70e0b9e30030ab322aa4c0036e84f0da4a0dfca40c4674750301005d40083b6',
          null
        ],
        [
          '676d711ed3714cc8da329489a90044ea1e26ea65956514d8fd0eea779d7b9bb7',
          null,
          null,
          'b6c93a91c76345f1eb9f7de34a0896183d069ad848dffa5d77c787c15b0254eb'
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          'f27894f63c7dd663588fe428a062ed24fd84851ffe90f8f61a72833457c1b45c',
          '9c8a1606e03ba17e5d273eb8bfe69a155b784b6c03b846b3546fa47399e48c10',
          '36ea9ade396d761da7c69e144aa608485c9a4b4468c947e10c482c15eb1cfaaa',
          'ce205f10f1b610305e54961d3977eae7c944decd574a24a878c8d140507ccf8a'
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          '32106502abb3d06a3aaf44ef5618e3467e0ef277ca440209c1a88f583ecc0171',
          'd969acc42c30655a59eafc338f93693072f2f38991d5e72defd84e7ceca9bd7b',
          '9a16d70312e7aca7972abbe9835db134fcd2a5a2865b1aaa16f2c15c51968f73',
          '1bc2b0fcffe23c6f83683cdc25286badd9db0f789a8f8bd40bca16d366edfb13'
        ],
        [
          null,
          null,
          null,
          null
        ]
      ];

      assert(expect.length === 20);

      for (let i = 0; i < 20; i++) {
        const point = Buffer.from(points[i], 'hex');

        equal(invert(p256, point), expect[i]);
      }
    });

    it('should create point from uniform bytes (svdw)', () => {
      const preimages = [
        '9e37082b9af789b41c2ba96432f3f79f51d531521673f5175a54a061e2a11478',
        'e5289483991ee977b8e2484a4ac149959d0cdd17031e3178b09aef3cdcf7985b',
        'dce893a7bf082cfd41705a54f3655f41769cc460fc26491a4c293b2ffe6c33bf',
        'f2f1cd561fe906fa34858a5b3709d7fc716385f51ac405265e8fbd374db1feb1',
        'a95a64e37b3570836f8b812f4812f5d793e5830295c7498d0ca397589962b9e8',
        'fde160fe9ccdb26d7364ed20ff300d0cf275879ae2e47c2934d95e811658dcdb',
        '652787b609e5d62d8ebc36d6842a0dc4d3df282d079c5793f43652c7c334452a',
        '903b37385c8af3fd541a94497f2f9f3fba78af9123289b0d9124b55f75769a04',
        '0ce68e327210d93599ea8809cdd571792195c60f71ce78cb5b01f86125a70751',
        '5ad8fd744be966155b4b61fdd42bf3c865d91ceaf48767050c1af5199a99a35c',
        '0021ba1827fc5b25fc88688a5699922ed53bbe67affbd186d3cb8522addb2d26',
        'c4e9cda1b2cb90b1853daa9b890121f3dcb6fc04406ba35f274f4158cd7795d0',
        'e8409daf179f349fbac526e329b254c3156e5cd7d4ca79bcc0bf2f612d15ae6c',
        '085e7e426ae88df12e5284ca74f7137c9e96de77f6a1ae455d8029f28e88dd3d',
        '039dd4ccdbe06a46529a3d864d780a628f58561742602c6d0cf57b8ae45367b0',
        'db7ddd4d8ee09d5784dccab595a4629973b62b231e6e762e24edd0101568b5ce'
      ];

      const keys = [
        '02daaa7ef2843538a98dda81b3ba1ba7286d2bd54c118be95f44658ef373f8110b',
        '03bbd140c0a31994f23bdfdd87c59af34a8490415983d434f42981edbf83383f8f',
        '0360d9735b8735394f72feebf38612652405b20b08d12876bf36a2a111eedb9572',
        '035b67e7e93701cbf25b5bc1b55e069fdbc65c39034aee0d8f74c0291a7972876d',
        '02c0ecd02058427d00d5b98d547c2633f41cfdb3d9b54bf7ba2fee1b70fb421168',
        '03c6b8abd785f0f7a456cd6bf163d80eeda3e8af1e70a09481099e9cbef4f12bcf',
        '02a08e2771b6465a80876ead6003417221828c58d1eb1814230cd183614611a70f',
        '0228b71ec0281f61d52c9e6354e1696828209fa2c9fc8562a511374c721fb7fee5',
        '031ba62579d23370e2a53c1137c7fdbc88a1d7919a8a3d805b27163aca53c0d19a',
        '025ca989025e4d256778b1c7463a78230e2f00b399f9fedce05d5e3bcf01f9e5dc',
        '02682d934eb4b51cbaf826387f61ab3bcbf8a14d685efb57c3cd924d4381ac7fa7',
        '02f0f3d7fc522e636ff5ee31ff46667646579dfa2ef7cf19895919d9e0319a31eb',
        '02f78cf7978a03215d4b58dcb60a42d0f62b6939eb264ae97ee50f398b7785e032',
        '0385f10de103b9afcc1bde65e9824bc393c6288c57294f614016591864122b283b',
        '022e16fda4a44781ae5513557d2ae27ec0e6ba851ea3e45d46c4cf2f581eb5ed94',
        '0272735445a206eba746709ab0c0bbefb8c1a80141e28b797253b4ecdac054fcb9'
      ];

      for (let i = 0; i < 16; i++) {
        const preimage = Buffer.from(preimages[i], 'hex');
        const key = Buffer.from(keys[i], 'hex');

        assert.strictEqual(secp256k1.publicKeyVerify(key), true);
        assert.bufferEqual(secp256k1.publicKeyFromUniform(preimage), key);
      }
    });

    it('should do random oracle encoding (svdw)', () => {
      const bytes = SHA512.digest(Buffer.from('turn me into a point'));
      const pub = secp256k1.publicKeyFromHash(bytes);

      assert.strictEqual(secp256k1.publicKeyVerify(pub), true);

      assert.bufferEqual(pub,
        '032287235856654cff0bf82466518bb9e7eaef62632c4805b3c76f8a6675f2a1df');
    });

    it('should test svdw inversion', () => {
      const points = [
        '025026a32a3c4f9c3b07458fd0c04e80f4c8eef8e1ffea0c26e42620851a5743ce',
        '02009e116799afa712903f268d1794b8b7c7b846b61e2df905c86d9b70a29e96ad',
        '03be7094c49db5549c0482783ad07aea50f71041ead8fc7f36aa86f489ca414bdb',
        '03b33342e5c1de6893a9cd83f0302b0f4c4519a4128e7707e9ab725c31c04a2e6a',
        '029ff72faf2640dc24c8309df40af02e3003abe1439e4ab1606ecd5eddc9f9d84a',
        '03e0a64cacced01f40e19b6b5ac57fae56637560d389126e9bc6e34a2da3c00248',
        '02bf2182aa75a46937ec099475f3993ce7940d71c95ead8dacbb11e9ace4fa3d79',
        '024fc878ff413bf2b90c37237be726a4eb627b1dbb33f9dfab802220cd2ec51daa',
        '038a5c8dc137cf10d920c07b1331febfa0fe760a1398afe6222c97f4119aa36639',
        '02f718221402f454a33651862d92d4cdd9161bd04a0ad32df333a30e85aab191ef',
        '030143c7400d6ee8baa93317fd352c841abd7befa6742e8361edc650607d8fa0e1',
        '03ebf0b5096ad7898a8c90c6c0e33b559103f1e2a1b6378eb999525142f70d9e4e',
        '03b6ead1c8aa5d1be5d59f6852e15d7aa49f372e786330c24147a82445eccad400',
        '033b623a99d823d62742ebb17f1808c18b59d3590f0f836686bbe08b1a1a928e5a',
        '03f8f15ae9bc58b9419d1d912f05af790585139c7358e51c75aa1de2d3680985ad',
        '03b4241ad32782155c3d9a6f274df12a59dcc3580549f014040f8bea8e7deea54b',
        '0331829115e3b22693ef879818fd90ce2a4ae4c5ca69bf0378ffc1809cc098373b',
        '02d9a8c364392176e894b288deea0a6d1977f253009d1197ad7a75a2b2b72ae6b6',
        '030945bebdd4e95e68950e41eb2e249ffcd44b0f155aa0cf1b7556b6efa2fad0b2',
        '02bf3b977879c84583c1a11c1243cf9d819bb78d4193f9190f9c967eae6cb98087'
      ];

      const expect = [
        [
          null,
          null,
          '889912f187429a9a266bccb5231babf47f3e230c6642c6527c8f709399cd15cc',
          '3c7f8118dd50b399f3ca5e9770b2e1f01cf4c06fd46068829d7be1eed6a46e16'
        ],
        [
          'a6a51f6b6afd57964d18bd8283715141811a928afc1c919a5b4df8b786fe025a',
          '94a61be369070bfbb04dd6b0d5d128e4c3996429c3c98f5db7fd3f729afe707a',
          null,
          null
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          'bbc9772038407a7437798ca402aaf73eee98112893270128e9f8c8f8b09e69b8',
          null,
          null,
          null
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          '3772e64bbdc6cd3dd2047333086ccccf00cbd33bad881de57e98ffedc895134a',
          null,
          null,
          null
        ],
        [
          '9ba07f2e4029e57396af0e90ed30e228cdde949091e1f9c522d0eb7cfaa60358',
          'd668ff2f9adb45ac426dd1ff639553e034cc8338ded0f7f913ea1eabc4bcb7f2',
          null,
          null
        ],
        [
          '71f793e29b1c77d1dcc52231e035326e216a6635324858426b14e72ea129e649',
          '4fb56ebee6a9eb4c23dd6ac4632f7842d766010276d0c6f220c30066313b9b11',
          null,
          null
        ],
        [
          '304964b8cad554f261f55f27d13e2ffd5de04c83eaaff2cbb7fdc87a5ffe5b96',
          'bfa8cd1432f9852b282c66b0083ba2eb26c944df2112b7df51cfaf3035f40ad8',
          '9bdc821569a7e49e2b802f61cd3ae93dcdc10899077087e57693c231d8489136',
          'ce42298cd5389bdfc919a4667b49ad006a09c1ea1dbabc4cb4386691c82a94d0'
        ],
        [
          'bb5da611dc28804c6da3e7dc38afb29d43f62f8793c1365bc90bf1678a760665',
          null,
          null,
          null
        ],
        [
          '6cd16e3b75e7b1df5efb01c7509eb1d5219df5052ceb2c045dba0c58395c0d8d',
          null,
          '36eaf212f5b86f83894f6b72efa0e48ff32260b440200792b0c5aca00ee1a4f5',
          '8d99da53bd96310e8d4c2f28fcfcbe5c80ee0c0b86d9dc448496515a91a14c2b'
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          '971e685c0c05be85ca1ce7ee40b2e2c3ed9f5c10dc9b908bc7d4845ac9989669',
          null,
          null,
          null
        ],
        [
          '157aaa6b2ac72baef94ea80ba4ebc1a45fa4c375cb9bdf13184332ee4cde74d3',
          null,
          '572ba4a654ea12279c0e2015f230ec7ea3e8152b0901e82eb95fe670ff2e32bd',
          '5b8a178fdab6d6e34f774b30912bfb588effe97c416b7b7dac7e8ad786ef800b'
        ],
        [
          null,
          null,
          null,
          null
        ],
        [
          'd77243029d81af007a8d3ac6134fe5ee2fba9174ad8ac538b02ba1a300d583e7',
          '70a4b897f9a5cedaa8683a878ab73bb8bf42e9178ae99dd7fc32137238eeadcd',
          '3f9ad83aaa64495cb6d8e0b65f8e4fed8904f12d9895c634c3f1496393b6ec4f',
          'c93220898109d50c8c91f31fe21d388bfe37b5127075115418eef67fa15b5f1f'
        ],
        [
          'e11839345f32c147d9433d8070507b8e58c674ecf7f80cb10e895f901f062078',
          null,
          null,
          null
        ],
        [
          '71150ca1b3435594cc920c0f4476be55767d14a59dc7a7df728bf3d28f69154f',
          '13d44e1ff3a6615d441c60240f126088587009553cb4ebd4c8f0fd08b86bb83d',
          null,
          null
        ],
        [
          null,
          null,
          null,
          null
        ]
      ];

      assert(expect.length === 20);

      for (let i = 0; i < 20; i++) {
        const point = Buffer.from(points[i], 'hex');

        equal(invert(secp256k1, point), expect[i]);
      }
    });

    it('should invert elligator', () => {
      for (const curve of curves) {
        let priv, pub, bytes;

        for (;;) {
          priv = curve.privateKeyGenerate();
          pub = curve.publicKeyCreate(priv);

          try {
            bytes = curve.publicKeyToUniform(pub);
          } catch (e) {
            continue;
          }

          break;
        }

        const out = curve.publicKeyFromUniform(bytes);

        assert.bufferEqual(out, pub);
      }
    });

    if (secp256k1.native === 2) {
      const curves = [
        [p192, require('../lib/js/p192')],
        [p224, require('../lib/js/p224')],
        [p256, require('../lib/js/p256')],
        [p384, require('../lib/js/p384')],
        [p521, require('../lib/js/p521')],
        [secp256k1, require('../lib/js/secp256k1')]
      ];

      it('should invert elligator (native vs. js)', () => {
        for (const [native, curve] of curves) {
          const priv = native.privateKeyGenerate();
          const pub = native.publicKeyCreate(priv);

          for (let i = 0; i < 4; i++) {
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

            if (curve.id === 'P521') {
              bytes1[0] &= 1;
              bytes2[0] &= 1;
            }

            assert.bufferEqual(bytes1, bytes2);
            assert.bufferEqual(native.publicKeyFromUniform(bytes1), pub);
          }

          const bytes = native.publicKeyToHash(pub);

          assert.bufferEqual(native.publicKeyFromHash(bytes), pub);
        }
      });
    }

    it('should invert elligator squared', () => {
      for (const curve of curves) {
        const priv = curve.privateKeyGenerate();
        const pub = curve.publicKeyCreate(priv);
        const bytes = curve.publicKeyToHash(pub);
        const out = curve.publicKeyFromHash(bytes);

        assert.bufferEqual(out, pub);
      }
    });
  });

  describe('Canonical', () => {
    it('should reject non-canonical R value', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0372fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fca2a8bffd82f19b14ab6a9',
         'b76d75ddf62cc06f7ef5d98158c96bad9c1b482656ca'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['02',
         '01c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205061'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      assert(!p521.verify(msg, sig, pub));
    });

    it('should reject non-canonical S value', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['026eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff3f23f8c0bc4395efc7db3d',
         '9d889cfe91b0125663ac64d819f31dac1fd28fe518a3'].join(''),
        ['02',
         '01c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205061'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      assert(!p521.verify(msg, sig, pub));
    });

    it('should reject non-canonical X coordinate (compressed)', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['02',
         '03c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205060'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      assert(!p521.publicKeyVerify(pub));
      assert(!p521.verify(msg, sig, pub));
    });

    it('should reject non-canonical X coordinate', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['04',
         '03c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205060',
         '010ca5c0e1e861801cdc800cb07584027b332ecfe4a6',
         '152a9c0b7e09a18c14da428791ce6448743401b29724',
         '39969786a068a30f6690dec00c9e1a9149cdd87dfda8'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      assert(!p521.publicKeyVerify(pub));
      assert(!p521.verify(msg, sig, pub));
    });

    it('should reject non-canonical Y coordinate', () => {
      const json = [
        ['2987f61715244cfb7e613770ec59bbd4eeb48d9f3b4a',
         '66cdb056acb82e75b1157b8538092ac43632541d8045',
         'd5a334d9063ff2c27e26cac1673bab85e9d1a4990d2f'].join(''),
        ['0172fb58279be153963a356a3c154e4aad826db0fb4f',
         'd156cc1ebe1cb937fd499fcfd90578546fea1adf36dd',
         'b6247ed4505c84b9b53d4fe5111ab03de4fcb6edf2c1'].join(''),
        ['006eb96e4a6f3674ed254b915ac3241472ee8085e822',
         'e925e0d42711e5eed113ff44d27239388466595c5b71',
         '9c3fa5f4ebdfd6a099f3db3bd244623c68b3feacb49a'].join(''),
        ['04',
         '01c0c2cbc731e95d2086a9208c93febcbb72d95c2a37',
         'cde565df74d78b2dbfb90abe5540dbd5790c9a0683a8',
         'a01a7f2b342df7d660513d6f6532f861bb8c2d205061',
         '030ca5c0e1e861801cdc800cb07584027b332ecfe4a6',
         '152a9c0b7e09a18c14da428791ce6448743401b29724',
         '39969786a068a30f6690dec00c9e1a9149cdd87dfda7'].join('')
      ];

      const [m, r, s, p] = json;
      const msg = Buffer.from(m, 'hex');
      const sig = Buffer.from(r + s, 'hex');
      const pub = Buffer.from(p, 'hex');

      assert(!p521.publicKeyVerify(pub));
      assert(!p521.verify(msg, sig, pub));
    });

    it('should reject non-canonical X coordinate (compressed)', () => {
      const json = [
        '02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30',
        '03fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30'
      ];

      for (const str of json) {
        const pub = Buffer.from(str, 'hex');

        assert(!secp256k1.publicKeyVerify(pub));
      }
    });

    it('should reject non-canonical X coordinate (compressed)', () => {
      const json = [
        '02ffffffff00000001000000000000000000000001000000000000000000000004',
        '03ffffffff00000001000000000000000000000001000000000000000000000004'
      ];

      for (const str of json) {
        const pub = Buffer.from(str, 'hex');

        assert(!p256.publicKeyVerify(pub));
      }
    });
  });
});
