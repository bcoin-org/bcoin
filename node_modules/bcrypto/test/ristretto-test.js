'use strict';

const assert = require('bsert');
const elliptic = require('../lib/js/elliptic');
const Ristretto = require('../lib/js/ristretto');
const SHA512 = require('../lib/sha512');
const rng = require('../lib/random');
const extra = require('./util/curves');
const {curves} = elliptic;

describe('Ristretto', function() {
  it('should decode and encode ristretto points (ed25519)', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);

    // https://ristretto.group/test_vectors/ristretto255.html
    const json = [
      // This is the identity point
      '0000000000000000000000000000000000000000000000000000000000000000',
      // This is the basepoint
      'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
      // These are small multiples of the basepoint
      '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919',
      '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259',
      'da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57',
      'e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e',
      'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403',
      '44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d',
      '903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c',
      '02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031',
      '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f',
      'bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42',
      'e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460',
      'aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f',
      '46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e',
      'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e'
    ];

    const points = [];

    let p = curve.point();

    for (let i = 0; i < 16; i++) {
      const raw = Buffer.from(json[i], 'hex');
      const q = ristretto.decode(raw);

      assert.strictEqual(ristretto.eq(q, p), true);
      assert.strictEqual(q.mulH().eq(p.mulH()), true);
      assert.bufferEqual(ristretto.encode(p), raw);

      assert.strictEqual(ristretto.isInfinity(q), i === 0);
      assert.strictEqual(ristretto.isInfinity(p), i === 0);

      points.push(p);

      p = p.add(curve.g);
    }

    const batched = ristretto.encodeBatch(points);

    for (let i = 0; i < 16; i++) {
      const q = ristretto.decode(batched[i]);
      const p = points[i].dbl();

      assert.strictEqual(ristretto.eq(q, p), true);
      assert.strictEqual(q.mulH().eq(p.mulH()), true);
    }
  });

  it('should fail to decode bad points (ed25519)', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);

    // https://ristretto.group/test_vectors/ristretto255.html
    const json = [
      // These are all bad because they're non-canonical field encodings.
      '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      // These are all bad because they're negative field elements.
      '0100000000000000000000000000000000000000000000000000000000000000',
      '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20',
      'c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562',
      'c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78',
      '47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24',
      'f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72',
      '87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309',
      // These are all bad because they give a nonsquare x^2.
      '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
      '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
      'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
      'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
      '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
      'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
      '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
      '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',
      // These are all bad because they give a negative xy value.
      '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
      'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
      'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
      '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
      '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
      '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
      '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
      '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',
      // This is s = -1, which causes y = 0.
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
    ];

    for (const str of json) {
      const raw = Buffer.from(str, 'hex');

      assert.throws(() => ristretto.decode(raw));
    }
  });

  it('should encode and decode ristretto points (ed448-alt)', () => {
    const curve = new curves.ISO448();
    const ristretto = new Ristretto(curve);

    // https://sourceforge.net/p/ed448goldilocks/code/ci/master/tree/test/ristretto_vectors.inc.cxx
    const json = [
      '00000000000000000000000000000000000000000000000000000000',
      '00000000000000000000000000000000000000000000000000000000',
      '66666666666666666666666666666666666666666666666666666666',
      '33333333333333333333333333333333333333333333333333333333',
      'c898eb4f87f97c564c6fd61fc7e49689314a1f818ec85eeb3bd5514a',
      'c816d38778f69ef347a89fca817e66defdedce178c7cc709b2116e75',
      'a0c09bf2ba7208fda0f4bfe3d0f5b29a543012306d43831b5adc6fe7',
      'f8596fa308763db15468323b11cf6e4aeb8c18fe44678f44545a69bc',
      'b46f1836aa287c0a5a5653f0ec5ef9e903f436e21c1570c29ad9e5f5',
      '96da97eeaf17150ae30bcb3174d04bc2d712c8c7789d7cb4fda138f4',
      '1c5bbecf4741dfaae79db72dface00eaaac502c2060934b6eaaeca6a',
      '20bd3da9e0be8777f7d02033d1b15884232281a41fc7f80eed04af5e',
      '86ff0182d40f7f9edb7862515821bd67bfd6165a3c44de95d7df79b8',
      '779ccf6460e3c68b70c16aaa280f2d7b3f22d745b97a89906cfc476c',
      '502bcb6842eb06f0e49032bae87c554c031d6d4d2d7694efbf9c468d',
      '48220c50f8ca28843364d70cee92d6fe246e61448f9db9808b3b2408',
      '0c9810f1e2ebd389caa789374d78007974ef4d17227316f40e578b33',
      '6827da3f6b482a4794eb6a3975b971b5e1388f52e91ea2f1bcb0f912',
      '20d41d85a18d5657a29640321563bbd04c2ffbd0a37a7ba43a4f7d26',
      '3ce26faf4e1f74f9f4b590c69229ae571fe37fa639b5b8eb48bd9a55',
      'e6b4b8f408c7010d0601e7eda0c309a1a42720d6d06b5759fdc4e1ef',
      'e22d076d6c44d42f508d67be462914d28b8edce32e7094305164af17',
      'be88bbb86c59c13d8e9d09ab98105f69c2d1dd134dbcd3b0863658f5',
      '3159db64c0e139d180f3c89b8296d0ae324419c06fa87fc7daaf34c1',
      'a456f9369769e8f08902124a0314c7a06537a06e32411f4f93415950',
      'a17badfa7442b6217434a3a05ef45be5f10bd7b2ef8ea00c431edec5',
      '186e452c4466aa4383b4c00210d52e7922dbf9771e8b47e229a9b7b7',
      '3c8d10fd7ef0b6e41530f91f24a3ed9ab71fa38b98b2fe4746d51d68',
      '4ae7fdcae9453f195a8ead5cbe1a7b9699673b52c40ab27927464887',
      'be53237f7f3a21b938d40d0ec9e15b1d5130b13ffed81373a53e2b43',
      '841981c3bfeec3f60cfeca75d9d8dc17f46cf0106f2422b59aec580a',
      '58f342272e3a5e575a055ddb051390c54c24c6ecb1e0aceb075f6056'
    ];

    const points = [];

    let p = curve.point();

    for (let i = 0; i < json.length; i += 2) {
      const str = json[i] + json[i + 1];
      const raw = Buffer.from(str, 'hex');
      const q = ristretto.decode(raw);

      assert.strictEqual(ristretto.eq(q, p), true);
      assert.strictEqual(q.mulH().eq(p.mulH()), true);
      assert.bufferEqual(ristretto.encode(p), raw);

      points.push(p);

      p = p.add(curve.g);
    }

    const batched = ristretto.encodeBatch(points);

    for (let i = 0; i < 16; i++) {
      const q = ristretto.decode(batched[i]);
      const p = points[i].dbl();

      assert.strictEqual(ristretto.eq(q, p), true);
      assert.strictEqual(q.mulH().eq(p.mulH()), true);
    }
  });

  it('should encode and decode ristretto points (ed448)', () => {
    const curve = new curves.ED448();
    const ristretto = new Ristretto(curve);

    // Self-generated.
    const json = [
      '00000000000000000000000000000000000000000000000000000000',
      '00000000000000000000000000000000000000000000000000000000',
      'f076235a633f5630d25213340b591c51d9735a73da5d686baeb21188',
      '2b5e778ca4f8de1aa8cb205902d3dfa9f6e9837c588de05c0ad30493',
      '56d7cce160ec2b3a4049edfc32371ba732b8a236b5cb626d01397f66',
      '72f9db631e0737ff743aaec6723420ebead8042e09f4253f7f0beaf6',
      '2ad64e1f8a7dd168b882f1c3499d52d73245ae8d0117a187190a027c',
      'a3a9313ad91617f92c21a2c79de71c43a211a663ec7317c6c20a059b',
      'd22d2cde5648cceee9dfd92effd5b1786a9f995904113b2c81330265',
      '816c1ce94a855fc2f2bea1ec08e97a54f7258d74479881f853ec2117',
      '1eb3f31fb70318d331ab32c5d5b9836c0fff526028232764d3cf5864',
      '3f53426241f861d69723b95e5f3da5af3fce506dcc38bd44840f4d16',
      'a044cfe02c5a6980046797a98bc413ba1099c4ff4c1329b6aa8f2f42',
      'a1f327dcf1ad8fb6bb9d88c728c5c02b7e9a19d916f1c0cec206356b',
      'c65319c247ca2c87319b6957849f6af904ca0c6b1707ccf768ef04ae',
      '5a896b241ce9c7de7a055a2c0a30073f673163de963a1aaa427fe4c4',
      'd61476c1d965c9fd2688fac3c61b7cd132ab8f24f6fb7db76214102f',
      '9c24faec2ada8218b8c4b0d2f48a64732adc4ffbd0eab3c317397c40',
      'b862dc86350376004cf14612b882b52735029dc71f75623717c7bd17',
      'ae9963a1c6d6b23bfa1632070b364b02be8442e8b6546c5d4997fd33',
      'fc89c6ca3bda12be8be87a8ef2150b6fc1ae9553832571dc2d1f920b',
      '5637ba9b47236aaff941a06af88a8e40b9aad8c04ec213e58940d5ee',
      '9882d1001ee07c9413e49ab4fba65269e09dc77895ae525852de4825',
      '7dd7ce61ec9d821a1b1db2a33f7ca1ba1f1c9eb7d108ca47f4a2f0ec',
      '56d7c6fd8f009a22062d34504498ca9d21f8174eb9d13ab88af62a2d',
      '83c7b89828493e77a9c6c50018b338de60531737f7f43bb6f8dd9b5d',
      '082650f2ee0e41450c187a691eb8a6e53533bc4bb56bb65dfe2a8bee',
      '671ce1c4adbd9c7a641c03c4a9132596d2ee62be845aa7e2daf560f7',
      '76dac2a249eee2f7fabe4018fb66e58c82d3716dee1cb356bbf2d029',
      '29ffbc74a438544cdca51a557f6706e220417baa97891c0a4d397eac',
      'e47841c8a4f5b59b59903dc02fedb5944d7d843d625d7f3015d0cca0',
      '977690f8217b98bb57dafdaac15f276cef4aac9b4a3e163b07216468'
    ];

    const points = [];

    let p = curve.point();

    for (let i = 0; i < json.length; i += 2) {
      const str = json[i] + json[i + 1];
      const raw = Buffer.from(str, 'hex');
      const q = ristretto.decode(raw);

      assert.strictEqual(ristretto.eq(q, p), true);
      assert.strictEqual(q.mulH().eq(p.mulH()), true);
      assert.bufferEqual(ristretto.encode(p), raw);

      points.push(p);

      p = p.add(curve.g);
    }

    const batched = ristretto.encodeBatch(points);

    for (let i = 0; i < 16; i++) {
      const q = ristretto.decode(batched[i]);
      const p = points[i].dbl();

      assert.strictEqual(ristretto.eq(q, p), true);
      assert.strictEqual(q.mulH().eq(p.mulH()), true);
    }
  });

  it('should decode and encode ristretto points (h = 8, a = -1)', () => {
    const m221 = new curves.M221();
    const curve = m221.toEdwards(m221.field(-1));
    const ristretto = new Ristretto(curve);

    let p = curve.point();

    for (let i = 0; i < 16; i++) {
      const raw = ristretto.encode(p);
      const q = ristretto.decode(raw);

      assert.strictEqual(ristretto.eq(q, p), true);
      assert.strictEqual(q.mulH().eq(p.mulH()), true);
      assert.bufferEqual(ristretto.encode(q), raw);

      p = p.add(curve.g);
    }
  });

  it('should decode and encode ristretto points (extra curves)', () => {
    for (const curve of [new extra.ED1174(),
                         new extra.E222(),
                         new extra.E382(),
                         new extra.E521(),
                         new extra.MDC()]) {
      const ristretto = new Ristretto(curve);

      let p = curve.point();

      for (let i = 0; i < 16; i++) {
        const raw = ristretto.encode(p);
        const q = ristretto.decode(raw);

        assert.strictEqual(ristretto.eq(q, p), true);
        assert.strictEqual(q.mulH().eq(p.mulH()), true);
        assert.bufferEqual(ristretto.encode(q), raw);

        p = p.add(curve.g);
      }
    }
  });

  it('should compute elligator (extra curves)', () => {
    for (const curve of [new extra.ED1174(),
                         new extra.E222(),
                         new extra.E382(),
                         new extra.E521(),
                         new extra.MDC()]) {
      const ristretto = new Ristretto(curve);

      for (let i = 0; i < 16; i++) {
        const r0 = curve.randomField(rng);
        const p0 = ristretto.pointFromUniform(r0);

        let total = 0;

        for (let j = 0; j < 8; j++) {
          let r1;

          try {
            r1 = ristretto.pointToUniform(p0, j);
          } catch (e) {
            continue;
          }

          const p1 = ristretto.pointFromUniform(r1);

          assert.strictEqual(ristretto.eq(p1, p0), true);
          assert.strictEqual(p1.mulH().eq(p0.mulH()), true);

          total += 1;
        }

        assert(total >= 1);
      }
    }
  });

  it('should compute elligator (ed25519)', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);

    // https://ristretto.group/test_vectors/ristretto255.html
    const labels = [
      'Ristretto is traditionally a short shot of espresso coffee',
      'made with the normal amount of ground coffee but extracted with',
      'about half the amount of water in the same amount of time',
      'by using a finer grind.',
      'This produces a concentrated shot of coffee per volume.',
      'Just pulling a normal shot short will produce a weaker shot',
      'and is not a Ristretto as some believe.'
    ];

    const points = [
      '3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46',
      'f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b',
      '006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826',
      'f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a',
      'ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179',
      'e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628',
      '80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065'
    ];

    for (let i = 0; i < 7; i++) {
      const label = Buffer.from(labels[i], 'binary');
      const point = Buffer.from(points[i], 'hex');
      const out = ristretto.pointFromHash(SHA512.digest(label));

      assert.bufferEqual(ristretto.encode(out), point);
    }
  });

  it('should compute elligator (ed25519, non-uniform)', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);

    // https://github.com/dalek-cryptography/curve25519-dalek/blob/9a62386/src/ristretto.rs#L1232
    const bytes = [
      'b8f98731fd7b597143a006ef0769d329c0f9b939096646c60f7f071aa0668647',
      'e50ef1e34b09763c8099e215b7d95b886200e79c7c4d528b8e86a4a9a93efa34',
      '736d24dcb4df6306cca9131da9445417156dbd957fcd5b66ac2370238645ba22',
      '1031606babc7a4098110403ef13f84add1a070d769329d51fd69019ae5197853',
      '9c83a1a2ecfb05bba7ab11b294d25acf56154fa1a7d7ea0188f2b6f826554f56',
      'fbb17c3612654bebf5ba132e859de5400a88b5b94e90fea789316b0a3d0a1519',
      'e8c11444f04dba4db7282c56961fc6d44c5103d9c5087e807e98a4d0992cbd4d',
      'ade595b125e61e453d38acbedb73a7c247863b4b1cf4761aa26140100fbd1e40',
      '6a473d6bfa752a975bcad46434bcbe157dda1f12fdf1a08539f203a4bd446f4b',
      '70ccb65adcc67849ad6bc111e328a224968deb37acb70c27c2882b99f4765b59',
      '6f18cb7bfebd0ba233c4a388cc8f0ade217051cd222308425a06a43aaab12219',
      'e1b71e34ec5206b76d19e3b5195229c1504da150f2cb4fcc88f5836eed6a033a',
      'cff626381e56b05a1bc83d2add1b38d24fb2bd7844c178a74db935c57c80bf7e',
      '0188d750f02e3f9310f4e6cf52bd4a326aa98a561e83d6caa67dfbe462182415',
      'd2cfe4389b74cf3654c3fbd7f9c7744b6defc4fbc2f6fce446929c231927f104',
      '22747b0908285dbd0967396742e303029d6b86dbca4ae69a4e6bdbc3d60e5450'
    ];

    const images = [
      'b09ded61421d8ca6a85e1a9dd4d8e5a0c3f6e8efa9703fc1402098450bbef656',
      'ea8d4dcbb5e1fa4aab3e0f764ed49613830ebceec2f48d8aa6a2537ae4c9131a',
      'e8e7335c05a85024adb36844ba9544288caa1b67638c15f22b3efa86d0ff3d59',
      'd0788c81b1b3ed9ffca01c0dce05d3f1c0da016182f114a9772ef61d4f504d54',
      'ca0bec913a0cb59dd106d5584b930b77bf8b2f8e212499c1dfb7b208cd78f86e',
      '1a42e743cbaf748220883efdd72e05d6a6f86cedd847f4ad488552068ff06829',
      '289d6660c9dfc8c596b56a53677e8f2191e64e06ab92d28f7005f517b78a1278',
      'dc251bcbefc4b0832542bcf3b9fa7117a7d39af3a8d736ab9f24c3510d962b2b',
      'e879b0deb7c49f5aeec1693465a7f4aa7972c406439850b9dd075369b0d0e079',
      'e2b5b734f1a33db3ddcfdc49f5f219ec4354b3dea73ea7b620095c1ea57fcc44',
      'e27710f2c88bf0570bde5c929cf32e77413b01f85cb732af5728ce35d0dc940d',
      '46f04f70369de4924a7ad858e83e9e0d0e927375b0de5ae1f4175ebe96078860',
      '1647f1672dc1c390b7659a322744316e332c3e00e5714851a81d496a66288418',
      'c4856b0b82694a21ccab85ddaec1f12426b3c46bdbb9b5fde42f9b2ae749294e',
      '3affe1c573d0a08f27c552458feb5caa4a28390babe31ab9d9cf5ab9c5be233c',
      '582b5c76df886991eeba7308d67099fd266ccde69d820b426555fd6e6e0e9470'
    ];

    const totals = [
      3,
      5,
      2,
      4,
      4,
      5,
      5,
      4,
      7,
      5,
      4,
      5,
      6,
      4,
      5,
      6
    ];

    for (let i = 0; i < 16; i++) {
      const raw = Buffer.from(bytes[i], 'hex');
      const image = Buffer.from(images[i], 'hex');
      const r0 = curve.decodeUniform(raw);
      const p0 = ristretto.pointFromUniform(r0);

      assert.bufferEqual(ristretto.encode(p0), image);

      let total = 0;

      for (let j = 0; j < 8; j++) {
        let r1;

        try {
          r1 = ristretto.pointToUniform(p0, j);
        } catch (e) {
          continue;
        }

        const p1 = ristretto.pointFromUniform(r1);

        assert.strictEqual(ristretto.eq(p1, p0), true);
        assert.strictEqual(p1.mulH().eq(p0.mulH()), true);

        total += 1;
      }

      assert.strictEqual(total, totals[i]);
    }
  });

  it('should compute elligator (ed25519, sodium)', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);

    // https://github.com/jedisct1/libsodium/blob/6d9e2f0/test/default/core_ristretto255.c#L65
    const bytes = [
      '5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1',
      '4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6',
      'f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27',
      '0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38',
      '8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c',
      '27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c',
      'ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2',
      '150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf',
      '165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767',
      '5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413',
      'a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2',
      '979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c',
      '2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c7462',
      '2c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982'
    ];

    const images = [
      '3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46',
      'f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b',
      '006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826',
      'f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a',
      'ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179',
      'e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628',
      '80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065'
    ];

    const eddsa = [
      'ce53ca6753e489c4c98c1afdf67f77778f47225ccac1a231660498a59afe4291',
      '8d7c30740697f5b2b75c2929c27334f02b9d9ee4890d52a9e7aac70335061a4d',
      '25f787c173e53d26727f2db890e8d0573af90132670e8ff767a81286b8805b73',
      '9aceed132e259546ef3b9ac1d54e0505dcb21873c713a7e36f10b2b0b17bbfe1',
      '2542f5ad1c04f28a8a30fd65b4722a4a2c6ead87578d51664d6605159a0d267a',
      '3894670e5b7e31a9041eed25a94f8c7075d7d2fa4fed11b9919e873873208d52',
      '1b3615bf100d9f8f605b49a156c5c6a5e752d20afee0b9fc50a77126aea74603'
    ];

    for (let i = 0; i < 14; i += 2) {
      const raw = Buffer.from(bytes[i] + bytes[i + 1], 'hex');
      const image = Buffer.from(images[i / 2], 'hex');
      const pub = Buffer.from(eddsa[i / 2], 'hex');
      const out = ristretto.pointFromHash(raw);

      assert.bufferEqual(ristretto.encode(out), image);
      assert.bufferEqual(out.encode(), pub);
    }
  });

  it('should compute elligator (ed448-alt, non-uniform)', () => {
    const curve = new curves.ISO448();
    const ristretto = new Ristretto(curve);

    // https://sourceforge.net/p/ed448goldilocks/code/ci/master/tree/test/ristretto_vectors.inc.cxx
    const bytes = [
      '2d86a142338de274806354c43e29af705aa9a1893e6fd3ee2e9522c9',
      'ceb40be2441bac8a4f780643438925d79146988b1ca112da714de92a',
      'ee798ee086de1f5a57a2ca28db8451d306cbb9ee2227c497f4a67a69',
      '06d7ebbc7aa85f946ff9dff79e1b7e88d97e3ad4a4e0a12032323ab7',
      '2e1b1093b3477597664649b0b7c6ac1f9bb75dd9fdb50896cbaa0615',
      'c525436d6254ec13d9190ea425e5ba80eefc259bcd1e2a5af00e8a9e',
      '8a593fb99c04b5c050c90dc790936589415b9bd6783d9e925e634b87',
      '814fd1da2a36cd8045bb6c36d67eb82c178401356be840429c780c70',
      '80b25ffcfbd80b83a786c1076d3a23d85049fd4c519192a7d1e85238',
      '936e1c092215c80b2d9dd13d8849829d7f6a382a5ace05166e4b085b',
      'c1157732c6d2baf448887a1c4a2a90b40b07840ff962da1f7191058c',
      'b937dfe5ceb25e344e33fc9df0c68e99cb3507aafeb9a6c96675bbf1',
      'a5509877a2bbe80d07c23b26467385f97c16be4882400f31800e15dd',
      '439e523443cf94688859b762643d64beda91f750ac6e0016afafd309',
      'bd9be4e92093cf244079a6ff63ad01e19cae6d8065ed83bb052e14e2',
      '39048e3b8aeb90e935bebe29241e344dc90d31d04e99d6a1adca8b38',
      'c35efbe1abee01f9e45e0384fa2f943a6e8f5611864b555f186c7cf8',
      'e34cc627cba585fbcfc42684eb30be62235c1e10e882ca4219a8c485',
      '3c300fedd9866f6afabc143e1f730af6eadac0207e008888b6eb79a2',
      'f7e6e67ed01e71af64777b90bf610a5e36cad0cd88ef883a9b6ab813',
      '11f82f21e4616436e69ed8e35703cccd1f65aa75f07e8afaa33529cc',
      '2258eb2b0fb182710ffc67d1e0d0de373d4fd2d5b17b58b3c7d47312',
      '3dbdcf91e835a830fd8af9c69dc13066df1e24448b9178a099bb0757',
      '3efec48eab2c119bcbbb828d20c1647d4231dfeb9bd086f26db77e71',
      'ac8bf3020a1c733a591092b67a3223ca2fab6453d225ba832e34d0c4',
      'bfca952be32d3976ca738c5ab3ddc9c7627078418372db770f17b55c',
      'f6c55d6b4697d6f83d6eccc4db2f72f8f2f67e7524ff91d6f6c8a756',
      'ab03967a64894271e71e71d895729f0631fd7c0de1c273c090924323',
      '9b300376a4b95ea2024bdbd97a9693c3f60ae0bbdbdafc4709278b65',
      '34c8a2d5ff9bb3d210d949d5bf094919b90d2f0ff982ed927995dc60',
      '90957d597810b27b849a691f5d27d548963d354ae9e29ad59a230a15',
      '5aaa6fe7c54c82d50814d8fdcd2d3bb1e553a841f971d724a4647aba'
    ];

    const images = [
      'a6993b5a6cbb40716eb2afa153052775d255ff2f644e2f9132b404fc',
      '806808094043f7a2e47c0ad9272f53332d21f40770d660a8f1f1ed23',
      'de6a9282ee9f8fa9b02ca95ed4bf7f87b71fc364bc75d571f2e9a707',
      'f71666b2df0655f2002e1c84239eed70ded8a692af39520338c7c9ef',
      '02510b4c16a701a16882b51ec5d14e25185b7a8cd312c3cfc07c1100',
      '40d001ad590ad72dc30774d82b1a91b9e36c423e937d264b2d99d6b6',
      '9c647b771c288264e80fc8114c58db46e8f0666c10d7f56ba856ae67',
      '092aa88c4216652e6a129c1b4090caabe39afd352be4dc4099819c59',
      '06e91629ce93486ad3a7e729f01c4d294a4bdeefaf483204c167dfe8',
      'f0c9d232506fa521f5300e19a0004324508b390a6f25814fc8683aa4',
      '681177b076c9e553c7e57a22e7590596e3482de23f2855a8af82cc51',
      '6c52a93735ed3dde91b8210bad64b17d0c1d7c14ccc1526cc4140f11',
      '6805631c06f6d0b5ccf71fea2e4cdf3ea3104a44a821205a25014c9a',
      '17ac4333bbf6bb289b4257ccd7f7bb11e5c4ddd86da95319dc47044d',
      '4c0e8930ee39f2a743d179745b4c940ff58f53995732313d7ee78ca2',
      'deca42a48f0040c79a7ed547000b208b9594cec4e3e9df5c0138b8aa',
      '48c33a476605fe0fbb33d37b672aac14d7c62b8456d277608fc2906d',
      '03871d3959dd4a4cafabe7c25b6f59c9a9d17c724d97555298c9df3f',
      '0a0c089d505d30d1ce91cf3696ca7610a4e54af6f605cd68ff303cb5',
      '0bbdbab9903651ed6bdc35f2a80bc764e350f8a23f7003dcd3aa364f',
      '56213f803979ce0033a2aa9bccb8513b820b1552e81475864a48fe60',
      'e92273a8f2e57a77b81af1746e42e647ccc6fa54e0d07cdd3376c239',
      'f48fa882b52f79f18f33acfc23715e8f3e6ccf8ea87a3fc071cdb1eb',
      'd296f29e831578a921291d3c801352594596a17d2768e2c28632137d',
      'aa3b6c33c27a5a25f9452030567332e1705bdf7245efd898602ccf79',
      '934ca740ed8a12c7ee821e9922521ab8bfca3a1db916e46678c51f81',
      'ba1cfdca844f16716a77ba747a1f46d29ffa903a74e5f214fbef0667',
      '677dcf9bb02af7e34d2702eadbbe80ebcf944c2a542a983559d9248a',
      '50dfb7e79292f3b04e0d5c738af2bac6dadf00e5377bbfc1e713e1da',
      '5fa1a3c2fd4b10810d99cf8fca91373e478a84abcd65dff9273c13f1',
      'e4e1a48d1d72e2723b0909f97fcd570ddf8cdc47df6dfa6a8d67454f',
      '6b446dbff3411c571cf0771406f68cb9a3403470d636e5a6ce1b84cc'
    ];

    const totals = [
      2,
      2,
      2,
      3,
      1,
      3,
      3,
      3,
      1,
      3,
      1,
      3,
      2,
      3,
      2,
      3
    ];

    for (let i = 0; i < 32; i += 2) {
      const raw = Buffer.from(bytes[i] + bytes[i + 1], 'hex');
      const image = Buffer.from(images[i] + images[i + 1], 'hex');
      const r0 = curve.decodeUniform(raw);
      const p0 = ristretto.pointFromUniform(r0);

      assert.bufferEqual(ristretto.encode(p0), image);

      let total = 0;

      for (let j = 0; j < 4; j++) {
        let r1;

        try {
          r1 = ristretto.pointToUniform(p0, j);
        } catch (e) {
          continue;
        }

        const p1 = ristretto.pointFromUniform(r1);

        assert.strictEqual(ristretto.eq(p1, p0), true);
        assert.strictEqual(p1.mulH().eq(p0.mulH()), true);

        total += 1;
      }

      assert.strictEqual(total, totals[i / 2]);
    }
  });

  it('should compute elligator (ed448, non-uniform)', () => {
    const curve = new curves.ED448();
    const ristretto = new Ristretto(curve);

    // Self-generated.
    const bytes = [
      '2d86a142338de274806354c43e29af705aa9a1893e6fd3ee2e9522c9',
      'ceb40be2441bac8a4f780643438925d79146988b1ca112da714de92a',
      'ee798ee086de1f5a57a2ca28db8451d306cbb9ee2227c497f4a67a69',
      '06d7ebbc7aa85f946ff9dff79e1b7e88d97e3ad4a4e0a12032323ab7',
      '2e1b1093b3477597664649b0b7c6ac1f9bb75dd9fdb50896cbaa0615',
      'c525436d6254ec13d9190ea425e5ba80eefc259bcd1e2a5af00e8a9e',
      '8a593fb99c04b5c050c90dc790936589415b9bd6783d9e925e634b87',
      '814fd1da2a36cd8045bb6c36d67eb82c178401356be840429c780c70',
      '80b25ffcfbd80b83a786c1076d3a23d85049fd4c519192a7d1e85238',
      '936e1c092215c80b2d9dd13d8849829d7f6a382a5ace05166e4b085b',
      'c1157732c6d2baf448887a1c4a2a90b40b07840ff962da1f7191058c',
      'b937dfe5ceb25e344e33fc9df0c68e99cb3507aafeb9a6c96675bbf1',
      'a5509877a2bbe80d07c23b26467385f97c16be4882400f31800e15dd',
      '439e523443cf94688859b762643d64beda91f750ac6e0016afafd309',
      'bd9be4e92093cf244079a6ff63ad01e19cae6d8065ed83bb052e14e2',
      '39048e3b8aeb90e935bebe29241e344dc90d31d04e99d6a1adca8b38',
      'c35efbe1abee01f9e45e0384fa2f943a6e8f5611864b555f186c7cf8',
      'e34cc627cba585fbcfc42684eb30be62235c1e10e882ca4219a8c485',
      '3c300fedd9866f6afabc143e1f730af6eadac0207e008888b6eb79a2',
      'f7e6e67ed01e71af64777b90bf610a5e36cad0cd88ef883a9b6ab813',
      '11f82f21e4616436e69ed8e35703cccd1f65aa75f07e8afaa33529cc',
      '2258eb2b0fb182710ffc67d1e0d0de373d4fd2d5b17b58b3c7d47312',
      '3dbdcf91e835a830fd8af9c69dc13066df1e24448b9178a099bb0757',
      '3efec48eab2c119bcbbb828d20c1647d4231dfeb9bd086f26db77e71',
      'ac8bf3020a1c733a591092b67a3223ca2fab6453d225ba832e34d0c4',
      'bfca952be32d3976ca738c5ab3ddc9c7627078418372db770f17b55c',
      'f6c55d6b4697d6f83d6eccc4db2f72f8f2f67e7524ff91d6f6c8a756',
      'ab03967a64894271e71e71d895729f0631fd7c0de1c273c090924323',
      '9b300376a4b95ea2024bdbd97a9693c3f60ae0bbdbdafc4709278b65',
      '34c8a2d5ff9bb3d210d949d5bf094919b90d2f0ff982ed927995dc60',
      '90957d597810b27b849a691f5d27d548963d354ae9e29ad59a230a15',
      '5aaa6fe7c54c82d50814d8fdcd2d3bb1e553a841f971d724a4647aba'
    ];

    const images = [
      '8e1e9ccdc22a8aee0a1405e34d7e6625ef778539cc147e7207967885',
      '4aafcd1b5f737619744e404278e27f5eb68695ab61a590174cb102bc',
      '7aba9d19dc089cf65e9a35bef9f685ae610b845997b6e1cff84604d2',
      '9be55f05f735acc045bd8f2b227194c2ccc0bbdd3a2716941ba1e086',
      '6891b7096cc0809eed0d784eb4f1563ebc268827421fdf5f18d57574',
      '6c3d3a3355876e9d4c5679d37760118e11457b7170c7eb605c2218aa',
      '6edb77c0bde72d8d733e9982fc2a79893bdd2628d8ab6e88b677eb0f',
      'cf9ea67751c034e4cb79c8c047ffd1df2b19bb562cf8f112b39e84ae',
      'f8b2aaca30a3f743e42a7db277038e7738c3323e4d779af3f7c746dd',
      'e60e93667f75f099fa33efd262c3492f0d90acac6bd2f410a8a43df0',
      '5e9f7ae725fa316af298dbc7d8d7321396f210f1a7dbec23d6e2da0f',
      '59777e3f7556f7b4e016bd205518c6f4c56d4340c75062b08021bc1c',
      'a237d70a72a80e6c2d2005ee01af4caa1068fc16324116fc65b9cd36',
      '09ff1b28cec9062e85f09cc75fb1f6ecea049a1b1b41e519bc50580a',
      '4cafad527895977f7f1a2ab9643248364489f7c4a481cbcd0235c509',
      '4a0d94ae2aa6339dbf844884a32a13e458656aacf9d5c6224f86c1bc',
      'a080a9b88f72db5ed9e45d4d71abfe43caf023573f8a0b86affcb32c',
      'bca1235f81a2efdfcf1f4e3a7abf342ad7f09b9289c5f1865d1bbe88',
      'fe3d16fa8e62978923c1c5f3575dcfd82b67e91674e273d6e1cf86a6',
      '43364d04ad191cae2d3ac8dcb28ce8ec00cda54618f1844ed674e26e',
      'ca1a60112194d4ea0b0047a4064f3a972376d3c9427d24024935812c',
      'ad8da230533256d27ac1439e0a36089fcb8666191335578d0e55e28c',
      'aad90679d2180703880f5a8ea287d2a5b7f16927c4663b0f4183952b',
      'e9425616829e688419a5f1b8743b3a667ae675f298f3d6a3d3bfe03c',
      'b06a3bffee8d4a8dd653a818c6b761c90c40e82f1e5d8e0c5d4fcba5',
      'b0f3eb77bcb8f7895e99c6bd4983b3eeeba1bdf128e5e1770835a711',
      '8cc8c3727d78444a453d369bbb63dd4a5aee95f10a86acd6589b42bd',
      '66cd78ec9805b12288f6f2f49ea77827fc61e8178b8c3f2b697eb548',
      'a870bc008019f911aa92fa129a0e0d691fc904c85e8c8358ddddbad2',
      '8190cbb1e83f0297a2e5226d0a026eea8355cd989ac742e530182279',
      '728f51a1cc7e6c52e77fb8ff53fd3dd02f5402c65901fe8c443c8063',
      '6808ea767a96d67610c37a0b90a31e81267df42c8cfa377e83dc6c2e'
    ];

    const totals = [
      2,
      3,
      3,
      3,
      3,
      2,
      2,
      3,
      2,
      2,
      2,
      2,
      4,
      3,
      2,
      2
    ];

    for (let i = 0; i < 32; i += 2) {
      const raw = Buffer.from(bytes[i] + bytes[i + 1], 'hex');
      const image = Buffer.from(images[i] + images[i + 1], 'hex');
      const r0 = curve.decodeUniform(raw);
      const p0 = ristretto.pointFromUniform(r0);

      assert.bufferEqual(ristretto.encode(p0), image);

      let total = 0;

      for (let j = 0; j < 4; j++) {
        let r1;

        try {
          r1 = ristretto.pointToUniform(p0, j);
        } catch (e) {
          continue;
        }

        const p1 = ristretto.pointFromUniform(r1);

        assert.strictEqual(ristretto.eq(p1, p0), true);
        assert.strictEqual(p1.mulH().eq(p0.mulH()), true);

        total += 1;
      }

      assert.strictEqual(total, totals[i / 2]);
    }
  });

  it('should multiply by random scalar', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);
    const k = curve.randomScalar(rng);
    const g = ristretto.decode(ristretto.encode(curve.g)).normalize();
    const p1 = curve.g.mul(k);
    const p2 = g.mul(k);

    assert.strictEqual(ristretto.eq(p1, p2), true);
    assert.strictEqual(p1.mulH().eq(p2.mulH()), true);
  });

  it('should invert elligator with random point', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);

    for (;;) {
      const p = curve.randomPoint(rng);

      let r;
      try {
        r = ristretto.pointToUniform(p, rng.randomInt());
      } catch (e) {
        continue;
      }

      const q = ristretto.pointFromUniform(r);

      assert.strictEqual(ristretto.eq(p, q), true);
      assert.strictEqual(p.mulH().eq(q.mulH()), true);

      break;
    }
  });

  it('should invert elligator squared', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);
    const p = ristretto.randomPoint(rng);
    const r = ristretto.pointToHash(p, rng);
    const q = ristretto.pointFromHash(r);

    assert.strictEqual(ristretto.eq(p, q), true);
    assert.strictEqual(p.mulH().eq(q.mulH()), true);
  });

  it('should test non-invertible points', () => {
    const curve = new curves.ED25519();
    const ristretto = new Ristretto(curve);

    const points = [
      // primary subgroup
      [
        '7a90edb72d6fc77bf161957219eab09ca98a289072459ca80e68361839c35ad0',
        '2012a6a4de76d400bee99d2d96f7a67d9f6ae470c67881f132eb28a1b1136c3f'
      ],
      [
        '1c77e2edeb17a3de6c1b5361ed3fdb63636b5934c1844094fe2d755ad9155925',
        '5ce6d04920e261f5b1413e07a50dca8c1ae6233d40ba1aec4edf2fa0419b27e5'
      ],
      [
        '5e74d84b00bc8077ff1c5b51fc5df43a775006d45b4514ea62aaab6bbcdeebd4',
        '566c2a053339b921965876abc42199b8c46b7972fb4f5c4df07d0c81470c4f73'
      ],
      [
        '2253c4294e8b28735dfb24996c9a59000c528ad2edfdfb623e7b68927c285a34',
        '31a0a4f075cf1b0bda54f107096c8190cdf103aeecbe5bf6b13f301c5ab827b0'
      ],
      // ristretto 4-torsion subgroup
      [
        '281714913701e599a22134ac3dd9809fcdec9788d6ed58cf0859b730dbdd0b50',
        '1bccfc27742c8ba31c2a3ded7bc91d0b431a78406e9cb1dc2e3364e330d439b4'
      ],
      [
        '296a6d84f9d3bcbb88ec89152b50a831780348feedd4e8a0640b66ccfcabcc06',
        '6898011a7c5ca2fdcfcd189e6a4c57a767caf8a0b3bfa49a89fc215c1752c7e7'
      ],
      [
        '73c4e2729f3d22578f2791ac10bdaf02d0f689595e7e6ebe8fac29aab294a94c',
        '088740fa9facbbe7bc5e251971098a5b249625e6017c1280fc1097efae6f13c4'
      ],
      [
        '57a79d8c7c06576f48a8a15d39b2cfd3119a8f6dc7b7a1f798be66167ff07bce',
        '181cce40842aa589aaaed0c227d75f1e724a5f9f790bab26fe1446de8c5f1170'
      ]
    ];

    for (const json of points) {
      const p = curve.pointFromJSON(json);

      assert.throws(() => ristretto.pointToUniform(p, 0), {
        message: 'Invalid point.'
      });
    }
  });
});
