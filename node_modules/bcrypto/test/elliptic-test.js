'use strict';

const assert = require('bsert');
const BN = require('../lib/bn');
const EDDSA = require('../lib/js/eddsa');
const ECDH = require('../lib/js/ecdh');
const SHA512 = require('../lib/sha512');
const SHAKE256 = require('../lib/shake256');
const elliptic = require('../lib/js/elliptic');
const rng = require('../lib/random');
const extra = require('./util/curves');

const {
  ShortCurve,
  EdwardsCurve,
  curves
} = elliptic;

function checkCurve(curve) {
  // Verify basepoint order.
  assert(!curve.g.isInfinity(), 'Must have base point.');
  assert(curve.g.validate(), 'Invalid base point.');
  assert(!curve.n.isZero(), 'Must have order.');
  assert(!curve.g.hasTorsion(), 'Base point must be a generator.');
  assert(curve.isElliptic(), 'Curve must be elliptic.');

  // G * (N + 1) = G
  const g = curve.g.toJ();
  const a = g.toP();
  const k = curve.n.addn(1);
  const b = k.bitLength();

  let p = g;
  let q = curve.jpoint();

  assert(p.validate());
  assert(q.validate());

  // Test right-to-left multiplication.
  for (let i = 0; i < b; i++) {
    if (k.utestn(i)) {
      q = q.add(p);
      assert(q.validate());
    }

    p = p.dbl();
    assert(p.validate());
  }

  assert(!q.isInfinity());
  assert(q.eq(g));
  assert(q.encode().equals(g.encode()));

  // Test ladder.
  if (curve.type === 'mont')
    assert(g.mulBlind(k.muln(2), rng).eq(g.dbl()));

  // Test fixed NAF multiplication.
  if (curve.g.pre && b === curve.scalarBits)
    assert(curve._fixedNafMul(curve.g, k).eq(g));

  // Test wNAF multiplication.
  assert(curve._wnafMul(5, g, k).eq(g));

  // Test wNAF multiplication (precomp).
  assert(curve._wnafMul(5, curve.g, k).eq(g));

  // Test Shamir's trick.
  assert(curve._wnafMulAdd(5, [g, g], [k, k]).eq(g.dbl()));

  // Test Shamir's trick (precomp).
  assert(curve._wnafMulAdd(5, [curve.g, a], [k, k]).eq(g.dbl()));

  // Test Shamir's trick (precomp + JSF).
  assert(curve._wnafMulAdd(5, [curve.g, a, a], [k, k, k]).eq(g.dbl().add(g)));

  // Check torsion points.
  for (const p of curve.torsion) {
    assert(p.validate());
    assert(p.isInfinity() || p.isSmall());
  }

  // Check torsion sorting.
  if (curve.h.cmpn(1) === 0 || !curve.torsion[1].isInfinity()) {
    switch (curve.id === 'TWIST448' ? 2 : curve.torsion.length) {
      case 8:
        assert.strictEqual(curve.torsion[7].order().toNumber(), 8);
        assert.strictEqual(curve.torsion[6].order().toNumber(), 8);
        assert.strictEqual(curve.torsion[5].order().toNumber(), 8);
        assert.strictEqual(curve.torsion[4].order().toNumber(), 8);
        assert(curve.torsion[4].cmp(curve.torsion[3]) > 0);
      case 4:
        assert.strictEqual(curve.torsion[3].order().toNumber(), 4);
        assert.strictEqual(curve.torsion[2].order().toNumber(), 4);
        assert(curve.torsion[2].cmp(curve.torsion[1]) > 0);
      case 2:
        assert(curve.torsion[1].isOrder2());
        assert.strictEqual(curve.torsion[1].order().toNumber(), 2);
        assert(curve.torsion[1].cmp(curve.torsion[0]) > 0);
      case 1:
        assert(!curve.torsion[0].isOrder2());
        assert.strictEqual(curve.torsion[0].order().toNumber(), 1);
        break;
      default:
        assert(false);
        break;
    }
  }
}

function checkMont(curve) {
  // Verify basepoint order.
  assert(!curve.g.isInfinity(), 'Must have base point.');
  assert(!curve.n.isZero(), 'Must have order.');

  // G * (N + 1) = G
  const k = curve.n.addn(1);
  const g = curve.g.toX();

  // Test multiplication.
  assert(g.mul(k).eq(g));

  // Test montgomery ladder.
  assert(g.mulBlind(k, rng).eq(g));
}

function sanityCheck(curve) {
  if (curve.type === 'mont')
    checkMont(curve);

  return checkCurve(curve);
}

describe('Elliptic', function() {
  if (process.env.BMOCHA_VALGRIND)
    this.skip();

  describe('Vectors', () => {
    const test = (curve, vector) => {
      it(`should test curve ${curve.id}`, () => {
        // Quick sanity test.
        const p = curve.g;
        const j = curve.g.toJ();
        const tp = p.dbl().add(p);
        const tj = j.dbl().add(j);

        assert(p.add(p).eq(p.dbl()));
        assert(j.add(j).eq(j.dbl()));
        assert(j.add(p).eq(j.dbl()));

        assert(p.dbl().validate());
        assert(j.dbl().validate());

        assert(p.dbl().eq(p.add(p)));
        assert(j.dbl().eq(j.add(j)));
        assert(p.dbl().eq(p.add(p)));
        assert(j.dbl().eq(j.add(j)));
        assert(p.dbl().eq(p.dbl()));
        assert(j.dbl().eq(j.dbl()));

        assert(p.add(p).add(p).eq(tp));
        assert(j.add(j).add(j).eq(tj));

        // Slow sanity test.
        sanityCheck(curve);

        for (let i = 0; i < 2; i++) {
          const ak = new BN(vector.a.k, 16);
          const g = curve.g;
          const ap = g.mul(ak);

          assert(ap.validate());
          assert.equal(ap.getX().toString(16), vector.a.x);
          assert.equal(ap.getY().toString(16), vector.a.y);

          assert(g.mul(ak).eq(ap));
          assert(g.mulBlind(ak).eq(ap));
          assert(g.mulBlind(ak, rng).eq(ap));

          const bk = new BN(vector.b.k, 16);
          const bp = g.mul(bk);

          assert(bp.validate());
          assert.equal(bp.getX().toString(16), vector.b.x);
          assert.equal(bp.getY().toString(16), vector.b.y);

          assert(g.mul(bk).eq(bp));
          assert(g.mulBlind(bk).eq(bp));
          assert(g.mulBlind(bk, rng).eq(bp));

          const p1 = bp.mul(ak);
          const p2 = ap.mul(bk);

          assert(p1.validate());
          assert(p1.eq(p2));
          assert.equal(p1.getX().toString(16), vector.s.x);
          assert.equal(p1.getY().toString(16), vector.s.y);

          assert(bp.mul(ak).eq(p1));
          assert(ap.mul(bk).eq(p1));
          assert(ap.mulBlind(bk).eq(p1));
          assert(ap.mulBlind(bk, rng).eq(p1));

          const p3 = bp.mulBlind(ak);
          const p4 = ap.mulBlind(bk);

          assert(p3.validate());
          assert(p3.eq(p4));
          assert.equal(p3.getX().toString(16), vector.s.x);
          assert.equal(p3.getY().toString(16), vector.s.y);

          assert(bp.mul(ak).eq(p3));
          assert(ap.mul(bk).eq(p3));
          assert(bp.mulBlind(ak).eq(p3));
          assert(bp.mulBlind(ak, rng).eq(p3));
          assert(ap.mulBlind(bk).eq(p3));
          assert(ap.mulBlind(bk, rng).eq(p3));

          if (curve.type !== 'mont') {
            assert(curve.decodePoint(ap.encode()).eq(ap));
            assert(curve.decodePoint(bp.encode()).eq(bp));
            assert(curve.decodePoint(p1.encode()).eq(p1));
            assert(curve.decodePoint(p2.encode()).eq(p2));
            assert(curve.decodePoint(p3.encode()).eq(p3));
            assert(curve.decodePoint(p4.encode()).eq(p4));
          }

          curve.precompute(rng);
        }

        if (curve.type === 'mont') {
          const ak = new BN(vector.a.k, 16);
          const as = new BN(vector.a.y, 16).isOdd();
          const bs = new BN(vector.b.y, 16).isOdd();
          const ss = new BN(vector.s.y, 16).isOdd();
          const g = curve.g.toX();
          const ap = g.mul(ak);

          assert(g.dbl().eq(g.mul(new BN(2))));

          assert(ap.validate());
          assert.equal(ap.getX().toString(16), vector.a.x);
          assert.equal(ap.getY(as).toString(16), vector.a.y);

          assert(g.mul(ak).eq(ap));
          assert(g.mulBlind(ak).eq(ap));
          assert(g.mulBlind(ak, rng).eq(ap));

          const bk = new BN(vector.b.k, 16);
          const bp = g.mul(bk);

          assert(bp.validate());
          assert.equal(bp.getX().toString(16), vector.b.x);
          assert.equal(bp.getY(bs).toString(16), vector.b.y);

          assert(g.mul(bk).eq(bp));
          assert(g.mulBlind(bk).eq(bp));
          assert(g.mulBlind(bk, rng).eq(bp));

          const p1 = bp.mul(ak);
          const p2 = ap.mul(bk);

          assert(p1.validate());
          assert(p1.eq(p2));
          assert.equal(p1.getX().toString(16), vector.s.x);
          assert.equal(p1.getY(ss).toString(16), vector.s.y);

          assert(bp.mul(ak).eq(p1));
          assert(ap.mul(bk).eq(p1));
          assert(ap.mulBlind(bk).eq(p1));
          assert(ap.mulBlind(bk, rng).eq(p1));

          const p3 = bp.mulBlind(ak);
          const p4 = ap.mulBlind(bk);

          assert(p3.validate());
          assert(p3.eq(p4));
          assert.equal(p3.getX().toString(16), vector.s.x);
          assert.equal(p3.getY(ss).toString(16), vector.s.y);

          assert(bp.mul(ak).eq(p3));
          assert(ap.mul(bk).eq(p3));
          assert(bp.mulBlind(ak).eq(p3));
          assert(bp.mulBlind(ak, rng).eq(p3));
          assert(ap.mulBlind(bk).eq(p3));
          assert(ap.mulBlind(bk, rng).eq(p3));

          assert(curve.decodeX(ap.encode()).eq(ap));
          assert(curve.decodeX(bp.encode()).eq(bp));
          assert(curve.decodeX(p1.encode()).eq(p1));
          assert(curve.decodeX(p2.encode()).eq(p2));
          assert(curve.decodeX(p3.encode()).eq(p3));
          assert(curve.decodeX(p4.encode()).eq(p4));
        }
      });
    };

    test(new curves.P192(), {
      a: {
        k: 'e8c74e99092a9c2ef5c9d0826697ba7b0dfab11ab17c059d',
        x: 'c6e75a4b307136b15e6fcd818f7293172daed8a6ee60322c',
        y: 'c9f41596800c4ccf49fb1c269f884a3d579d12a27f9b2d96'
      },
      b: {
        k: '5d41ac4d405c63962e4e54012641c786a9159ce76459815a',
        x: '90fe10587acc6225b838c713b5b57229350e101ee617cc12',
        y: '802b7be71b58520f10a34645fcaa5d5f60b3f810d24b997c'
      },
      s: {
        x: '9f2dece64a07592fb7decd76a9d05b5a20625518791a199f',
        y: 'e8741f00bef890a7e4ae24553206cae441031968df5ec32c'
      }
    });

    test(new curves.P224(), {
      a: {
        k: 'abb9950e547809ad079ba8fde54779758933b032ec672b295a9deaf6',
        x: '534394a69b2691518977f518e7beed689f6fd9c27d0dc1f6d32d2c3b',
        y: '29cf860ff12256838a40a67d73adf4122be7c2df1bbca7f75c14ceb0'
      },
      b: {
        k: '4745aa8211b380bdc4b255c2c6da9b99d906b5b18e2290a99f195d67',
        x: '9ea0592b17e215614e1f183250dfa34c749ff0d8a5226c3258042e2e',
        y: '71a37e1e2dd0c89e3a0188bbb715a2aa945c38fb0f3335d8727ac7ac'
      },
      s: {
        x: 'ca2597e841478ae363e20a8b081676c201aef595036df5d3633b8f5f',
        y: 'f1c70b6d66af764eb5b0ccc586e7a8639396204ff0cafe998d3d07b6'
      }
    });

    test(new curves.P256(), {
      a: {
        k: '7d31b3980a670adb31fd5943b87453e7c19e30b90be2f6fe1698e0f5796df55e',
        x: '647293c0e08ae35140ba371f67883bfc848ead975e27dd7f8a6db2a259bc2e1b',
        y: 'aba8d40f11322dcd93d1d88b9907cd9e0c15be4a50f7850cca86c0e9492c1bf3'
      },
      b: {
        k: '05a0d3d015d0c82732b29c4c5e671c623b3360c58490baa84e3e43ca8d596097',
        x: '7040bad247e0508acde9df1b495304808c6b87428a0cd4a5e4940c63ab0abd34',
        y: 'd4be56bb2eadc8be86880bbbc8c13dd2e36096b1f3377679129f4a40526bb8f6'
      },
      s: {
        x: 'ee80975a3db44157e862133724380f84169059a3ab8bac331f4c4892a9119182',
        y: 'e37df17f1e7064d1b12a192ae65ca6ca20ffc470d88d91b66f94da700e107cd4'
      }
    });

    test(new curves.P384(), {
      a: {
        k: 'f1ac3d7aa847c2235e393fdbe353d4408bf603207da7918eda6c9c9d66db6e04f9d13bad8b554a04b690bcbfc125c540',
        x: 'eb4aec872170c5b79205de6ba8b0196cc3d8c75e4291eff800ba3dcf88a581a5281b3b860586147b6d926bf6829f4ac5',
        y: 'e12abdd483df66b6b7c210ee927d549e6eb58a2ce66b2abe41cab3eb05743c05802d580752f09c4872e86f5965ce2f22'
      },
      b: {
        k: '79fba6a1a13caa899d9829ba5c5a0431a954980a559b747c11071816babb13868744800879dbcdfb40120087917da3e0',
        x: '63b9eb16e3c999692b5ec009863cb57e8fb849659eac50b507ee651f3d1b93869a956386e31c11574cc948ceae95a704',
        y: '8a116cb2bc9fe827fb7c6cb9af4649fd278e2c0af7dcecb062f17c716049cc57a975028bbaf57987f35fc4f1ac9803ff'
      },
      s: {
        x: 'e79e3a3c14c5405b74dcd86fdd1d03b81e7a8c394fe451d104ca3f99e3f57a674e548f61dfde54fd9ed6558ea62c9ade',
        y: '1213c4a9e0b996824455694d9af2a7573ff00dc35cdb1decce45931c089d2f9d1b07c85500af3d6ec6e70f8834759c87'
      }
    });

    test(new curves.P521(), {
      a: {
        k: '007783085a324b70832c4d6e5607d25fb291459bf9d7c620f658d8f01903861dcfba056756cad95a6628cf0084eb778baddbe71a47f177e3e09c0f278b8585dd7ea4',
        x: '3654feaa311aae18d74d021f3fb12c9ba193b1673a298aadce1214f17d41640f222650b66dec1fe98559a4e9b0a3f4523099f98371c808cf6360fae7258b166192',
        y: '12c4c3fc89547a2697b567b9fb226b204336faa06e963751baad4000e16105a5230d890f2e867ee9fe3538e6babc442688850d5bb469035621ad38d45724d7ca3fd'
      },
      b: {
        k: '01891acf4771cf31fae03c1c1e37e4fa7cfba3cc53ce3941d9cbc5cf57c2a2a0524ecf805418485e2157f900f7a4d490dd97f3191b1bf1b27fe50a190196d2517b79',
        x: '121936da291d82d91a2a2c7b5395b0fa1b5ec78c7997f2947ff2c818f737df8c62583d4b9833b3889616c483cde977e79b593c0f03b497e40e0412ca04ed6e518e',
        y: '10afd2ae9c4a86a7bb732270da25504d1ffbba1805386bb83acbd25b085419ccda4c56bf3af4fa62b4060a333718e199d73e6830f81c0e7beb2ffd959acf3bb7512'
      },
      s: {
        x: '1b0d33c6c257eaf624fa379ce1db07e47910dde06f9e60568a17372439ab058873d9c29a220631b9873ed451e911ff6069f95f68c6ac6dfb69f5133437b31e0194d',
        y: '12b6bc4b6cc2da4584489f2179ccd70c016a746f1acd67c4bd040fb9a048ddc100d08240b3ffea8a8054fac4307ef10f66e8fad2986f2fddf41092847b40de38e41'
      }
    });

    test(new curves.SECP256K1(), {
      a: {
        k: 'f40749b74e7454a808fe318349129d7956bfe4df271d7ad31b3daf9866d538b6',
        x: 'eef57567a6beda8b2307bdb2e2d64649ca3da5e99b0e6e600b258ed7fc5c6432',
        y: '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
      },
      b: {
        k: 'b13d3ceda8e56c900005788a822a432a42cadd11f690a260c71418eb8e44d683',
        x: 'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
        y: 'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
      },
      s: {
        x: '42fb130736618fcf3b70c6b44d8317fd754ec46b8ad4cd83b75571374b33a268',
        y: 'd920e5c9a283600917e38540bcebea9e56543c30055958b60fca0a4ff26ad8db'
      }
    });

    test(new curves.X25519(), {
      a: {
        k: '4041c0f90e24de439869dc636e15f78dab1437652918cd23f24bf267838e5920',
        x: '4e855a3acc67d76456afc5a2c854bb4ee83f0df16d3010e9cfeb02854b518370',
        y: '6069949d58d70d9b62ce29e09bb28f17d85698f6f77f34abf6db24eb58e01d14'
      },
      b: {
        k: '660dd8004c28dc548c341e3b9e39faad2fef0ce77fbc56beed9c016689cb9468',
        x: '2820cf502c9d9e227c785b4c58c0911cd3b6421c507f6a54dab413b0488ab82d',
        y: '243f45f6f3822a93121cd88e36c7ffbfdec7c706c5278e09cd5b189f60e191c4'
      },
      s: {
        x: '1af9818fd4ea2348a3695c730e647d4f0cbe9ad193e4d1d37b653afbc1ca27ed',
        y: '6895d8b2bc9f023da982e5b3dae1d7c980317060bae54207322b376748efc2a8'
      }
    });

    test(new curves.ED25519(), {
      a: {
        k: '0041c0f90e24de439869dc636e15f78dab1437652918cd23f24bf267838e5923',
        x: '7143fec2823a20e85bbfedff1a30468136983c8b32c09bba6991f4055b213613',
        y: '3b1dd63ace37221fd9bc0d11b2196938c32d92bf04aff3913bfb90b5489e19bf'
      },
      b: {
        k: '660dd8004c28dc548c341e3b9e39faad2fef0ce77fbc56beed9c016689cb9468',
        x: 'dc96522329ccd49233ade48a29fdbfe8dd46f23974d9b5ee5ec41ddf9f9ab44',
        y: '7cb80d4fc3336a3e7e7e63b18616cef9d269c580059f1842bd814b06280740d'
      },
      s: {
        x: '41ba2e23566ad6a2b41e08bb389c96aa71a470b03f0ed0a0137e91017e2cdd3b',
        y: '45b57e51719ec114cc1cb17d74aead651946293166152e90223a82b4b5b449eb'
      }
    });

    test(new curves.X448(), {
      a: {
        k: 'c17d6835ec83facd2a3fe89cc909f901a45a535c34763669a55177b956ecbf54abe19011df330c1c2498b30b8e13277453636fe4e6312fbc',
        x: 'a31700b63788e5b28616a3528c361f15abb59af9541bc66b74dd5dffaf9a0e31ccd32e032e843bd199870a255b22cdedce637b680ec68786',
        y: 'd324838811dd33d4da3065ebc2e10237cd91c24203d1e46abb722f47bb6215cec37deca49de24fd26121174e08133aa4a50882c201dff529'
      },
      b: {
        k: 'a6e3d9e47b915f758efe24b373f7d94b6802f516e7608a6389bef1c3299cd0b176f0b41a0ead25f6cd03c8dffc02d0f94eeb57eb854c63c8',
        x: 'a9989ad97dc0c1a53cd6b25c3277f51aef5b285c4aa2d9def8db83021deea334878cd056eaecbf6bf1d1b8bb9748bd95f3199c707bd24874',
        y: 'a6d629678478133e2685ab426064dd49681afd10000036059275365fe14c88dfc2b9e7467f059b12baa9d6fcdecaacd94052f93a15b6c9d2'
      },
      s: {
        x: 'd46033d9447dd8beb58504e511b007e09050e6009f605e55ee923ce61dca73a204d20cd0bb02209f9c67ba95dac759108d62299981d46e91',
        y: '6c7c3b108999e690258bc1415b634302bbef170ed4099dbe0c911e41f0ef45e3cb25bdfa8aa0fc7e933325691d047b7fe31483cc3cd213ac'
      }
    });

    test(new curves.ED448(), {
      a: {
        k: 'c17d6835ec83facd2a3fe89cc909f901a45a535c34763669a55177b956ecbf54abe19011df330c1c2498b30b8e13277453636fe4e6312fbc',
        x: '5a261d8379f0a2eba1f937c1be72cd54459c42f0510488f12828f2e455cd774d3ac17a7fa5a774403b9f3109c6035b9212e0923add16bcf4',
        y: '7765689f859de84d0feb418644db17e1ac2c3040a294d904a21930e23114d14db8c60f07e65ff133e56fd2295e5b215d4d4034a52ec6e1c6'
      },
      b: {
        k: 'a6e3d9e47b915f758efe24b373f7d94b6802f516e7608a6389bef1c3299cd0b176f0b41a0ead25f6cd03c8dffc02d0f94eeb57eb854c63c8',
        x: 'f9034affb5ae198a8a50934f86dfdabe74ea4a0b9379c1d71d1539c99c60d353a3b85185f45e6a53106346a7b1e2f01099e39587a50e968',
        y: 'd17800e9860f2eeaa7d2f9955969b981304351841eff8390a398d0af9b0219b6accd974ef729c31cf88bb723cb9b218096a9632106a8c64d'
      },
      s: {
        x: 'f99f4dbebd341334940a4215151a69d5ebb0412343a07efe4ba205c534713ca5110ea9683d734d05e3b706d92466311d0e99c3284dc6dab2',
        y: '9ff6d9d30735cf9f8cd25042ba28f40c9ab34da9aec2ff743601be24a32cb36d8d19184a75f20b9dad183be6791ec2a17dac7433232581d4'
      }
    });

    // https://github.com/indutny/elliptic/pull/144
    // https://tools.ietf.org/html/rfc7027
    test(new curves.BRAINPOOLP256(), {
      a: {
        k: '81db1ee100150ff2ea338d708271be38300cb54241d79950f77b063039804f1d',
        x: '44106e913f92bc02a1705d9953a8414db95e1aaa49e81d9e85f929a8e3100be5',
        y: '8ab4846f11caccb73ce49cbdd120f5a900a69fd32c272223f789ef10eb089bdc'
      },
      b: {
        k: '55e40bc41e37e3e2ad25c3c6654511ffa8474a91a0032087593852d3e7d76bd3',
        x: '8d2d688c6cf93e1160ad04cc4429117dc2c41825e1e9fca0addd34e6f1b39f7b',
        y: '990c57520812be512641e47034832106bc7d3e8dd0e4c7f1136d7006547cec6a'
      },
      s: {
        x: '89afc39d41d3b327814b80940b042590f96556ec91e6ae7939bce31f3a18bf2b',
        y: '49c27868f4eca2179bfd7d59b1e3bf34c1dbde61ae12931648f43e59632504de'
      }
    });

    test(new curves.BRAINPOOLP384(), {
      a: {
        k: '1e20f5e048a5886f1f157c74e91bde2b98c8b52d58e5003d57053fc4b0bd65d6f15eb5d1ee1610df870795143627d042',
        x: '68b665dd91c195800650cdd363c625f4e742e8134667b767b1b476793588f885ab698c852d4a6e77a252d6380fcaf068',
        y: '55bc91a39c9ec01dee36017b7d673a931236d2f1f5c83942d049e3fa20607493e0d038ff2fd30c2ab67d15c85f7faa59'
      },
      b: {
        k: '032640bc6003c59260f7250c3db58ce647f98e1260acce4acda3dd869f74e01f8ba5e0324309db6a9831497abac96670',
        x: '4d44326f269a597a5b58bba565da5556ed7fd9a8a9eb76c25f46db69d19dc8ce6ad18e404b15738b2086df37e71d1eb4',
        y: '62d692136de56cbe93bf5fa3188ef58bc8a3a0ec6c1e151a21038a42e9185329b5b275903d192f8d4e1f32fe9cc78c48'
      },
      s: {
        x: 'bd9d3a7ea0b3d519d09d8e48d0785fb744a6b355e6304bc51c229fbbce239bbadf6403715c35d4fb2a5444f575d4f42',
        y: 'df213417ebe4d8e40a5f76f66c56470c489a3478d146decf6df0d94bae9e598157290f8756066975f1db34b2324b7bd'
      }
    });

    test(new curves.BRAINPOOLP512(), {
      a: {
        k: '16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422',
        x: 'a420517e406aac0acdce90fcd71487718d3b953efd7fbec5f7f27e28c6149999397e91e029e06457db2d3e640668b392c2a7e737a7f0bf04436d11640fd09fd',
        y: '72e6882e8db28aad36237cd25d580db23783961c8dc52dfa2ec138ad472a0fcef3887cf62b623b2a87de5c588301ea3e5fc269b373b60724f5e82a6ad147fde7'
      },
      b: {
        k: '230e18e1bcc88a362fa54e4ea3902009292f7f8033624fd471b5d8ace49d12cfabbc19963dab8e2f1eba00bffb29e4d72d13f2224562f405cb80503666b25429',
        x: '9d45f66de5d67e2e6db6e93a59ce0bb48106097ff78a081de781cdb31fce8ccbaaea8dd4320c4119f1e9cd437a2eab3731fa9668ab268d871deda55a5473199f',
        y: '2fdc313095bcdd5fb3a91636f07a959c8e86b5636a1e930e8396049cb481961d365cc11453a06c719835475b12cb52fc3c383bce35e27ef194512b71876285fa'
      },
      s: {
        x: 'a7927098655f1f9976fa50a9d566865dc530331846381c87256baf3226244b76d36403c024d7bbf0aa0803eaff405d3d24f11a9b5c0bef679fe1454b21c4cd1f',
        y: '7db71c3def63212841c463e881bdcf055523bd368240e6c3143bd8def8b3b3223b95e0f53082ff5e412f4222537a43df1c6d25729ddb51620a832be6a26680a2'
      }
    });
  });

  describe('Precomputation', () => {
    it('should have precomputed curves', () => {
      const p256 = new curves.P256();
      p256.precompute(rng);

      const secp256k1 = new curves.SECP256K1();
      secp256k1.precompute(rng);

      const ed25519 = new curves.ED25519();
      ed25519.precompute(rng);

      const x25519 = new curves.X25519();
      x25519.precompute(rng);

      const ed448 = new curves.ED448();
      ed448.precompute(rng);

      const x448 = new curves.X448();
      x448.precompute(rng);

      assert(p256.g.pre);
      assert(secp256k1.g.pre);
      assert(ed25519.g.pre);
      assert(x25519.g.pre);
      assert(ed448.g.pre);
      assert(x448.g.pre);
    });
  });

  describe('Curve', () => {
    it('should work with example curve', () => {
      const curve = new ShortCurve({
        p: '1d',
        a: '4',
        b: '14',
        n: '25',
        h: '1',
        z: '-8', // Icart
        g: [
          '0',
          '7'
        ]
      });

      sanityCheck(curve);

      const p = curve.pointFromJSON(['18', '16']);

      assert(p.validate());
      assert(p.dbl().validate());
      assert(p.dbl().add(p).validate());
      assert(p.dbl().add(p.dbl()).validate());
      assert(p.dbl().add(p.dbl()).eq(p.add(p).add(p).add(p)));

      const q = curve.randomPoint(rng);

      assert(q.validate());
    });

    it('should verify all curves', () => {
      const p192 = new curves.P192();
      const p224 = new curves.P224();
      const p256 = new curves.P256();
      const p384 = new curves.P384();
      const p521 = new curves.P521();
      const secp192k1 = new extra.SECP192K1();
      const secp224k1 = new extra.SECP224K1();
      const secp256k1 = new curves.SECP256K1();
      const x25519 = new curves.X25519();
      const x448 = new curves.X448();
      const frp256v1 = new extra.FRP256V1();
      const anomalous = new extra.ANOMALOUS();
      const bn2254 = new extra.BN2254();
      const wei25519 = new extra.WEI25519();
      const ed1174 = new extra.ED1174();
      const mont1174 = new extra.MONT1174();
      const ed41417 = new extra.ED41417();
      const curve383187 = new extra.CURVE383187();
      const m221 = new extra.M221();
      const e222 = new extra.E222();
      const m383 = new extra.M383();
      const e382 = new extra.E382();
      const m511 = new extra.M511();
      const e521 = new extra.E521();
      const mdc = new extra.MDC();
      const ed25519 = new curves.ED25519();
      const ed448 = new curves.ED448();
      const iso448 = new curves.ISO448();
      const mont448 = new curves.MONT448();
      const jubjub = new extra.JUBJUB();
      const iso256k1 = new extra.ISO256K1();
      const curve13318 = new extra.CURVE13318();

      for (const curve of [p192,
                           p224,
                           p256,
                           p384,
                           p521,
                           secp192k1,
                           secp224k1,
                           secp256k1,
                           x25519,
                           x448,
                           frp256v1,
                           anomalous,
                           bn2254,
                           wei25519,
                           ed1174,
                           mont1174,
                           ed41417,
                           curve383187,
                           m221,
                           e222,
                           m383,
                           e382,
                           m511,
                           e521,
                           mdc,
                           x25519,
                           ed25519,
                           x448,
                           ed448,
                           iso448,
                           mont448,
                           jubjub,
                           iso256k1,
                           curve13318]) {
        sanityCheck(curve);
      }
    });

    it('should dbl points on edwards curve using proj coordinates', () => {
      const curve = new EdwardsCurve({
        p: ['3fffffffffffffffffffffffffffffffffffffffffffffff',
            'ffffffffffffffffffffffffffffffffffffffffffffff97'],
        a: '1',
        // -67254 mod p
        d: ['3fffffffffffffffffffffffffffffffffffffffffffffff',
            'fffffffffffffffffffffffffffffffffffffffffffef8e1'],
        n: ['0fffffffffffffffffffffffffffffffffffffffffffffff',
            'd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719'],
        h: '4',
        z: '-1',
        g: [
          ['196f8dd0eab20391e5f05be96e8d20ae68f840032b0b6435',
           '2923bab85364841193517dbce8105398ebc0cc9470f79603'],
          '11'
        ]
      });

      const point = [
        ['21fd21b36cbdbe0d77ad8692c25d918774f5d3bc179c4cb0',
         'ae3c364bf1bea981d02e9f97cc62f20acacf0c553887e5fb'],
        ['29f994329799dba72aa12ceb06312300167b6e18fbed607c',
         '63709826c57292cf29f5bab4f5c99c739cf107a3833bb553']
      ];

      const double = [
        ['0561c8722cf82b2f0d7c36bc72e34539dcbf181e8d98f524',
         '4480e79f5b51a4a541457016c9c0509d49078eb5909a1121'],
        ['05b7812fae9d164ee9249c56a16e29a1ad2cdc6353227074',
         'dd96d59df363a0bcb5bc67d50b44843ea833156bdc0ac6a2']
      ];

      const p = curve.pointFromJSON(point);
      const d = curve.pointFromJSON(double);

      assert(p.add(p).eq(d));
      assert(p.dbl().eq(d));
    });

    it('should be able to find a point given y coordinate (edwards)', () => {
      const curve = new EdwardsCurve({
        p: '07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7',
        a: '1',
        // -1174 mod p
        d: '07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb61',
        n: '01fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971',
        h: '4',
        z: '-1'
      });

      const target = curve.pointFromJSON([
        ['05d040ddaa645bf27d2d2f302c569723',
         '1425185fd9a410f220ac5c5c7fbeb8a1'],
        ['02f8ca771306cd23e929775177f2c213',
         '843a017a6487b2ec5f9b2a3808108ef2']
      ]);

      const y = curve.field('02f8ca771306cd23e929775177f2c213'
                          + '843a017a6487b2ec5f9b2a3808108ef2', 16);

      const point = curve.pointFromY(y, true);

      assert(point.eq(target));
      assert(point.randomize(rng).eq(target));
    });

    it('should calculate j-invariant', () => {
      const expect = '39240375672115510010799456308813573486'
                   + '606784421612167109713554819120306934551';

      const j1 = new curves.SECP256K1().jinv();
      const j2 = new extra.WEI25519().jinv();
      const j3 = new curves.X25519().jinv();
      const j4 = new curves.ED25519().jinv();

      assert.strictEqual(j1.toString(10), '0');
      assert.strictEqual(j2.toString(10), expect);
      assert.strictEqual(j3.toString(10), expect);
      assert.strictEqual(j4.toString(10), expect);
    });

    it('should find an odd point given a y coordinate', () => {
      const curve = new EdwardsCurve({
        id: 'ED25519',
        // 2^255 - 19
        p: ['7fffffffffffffff ffffffffffffffff',
            'ffffffffffffffff ffffffffffffffed'],
        a: '-1',
        // (-121665 * 121666^-1) mod p
        d: ['52036cee2b6ffe73 8cc740797779e898',
            '00700a4d4141d8ab 75eb4dca135978a3'],
        n: ['1000000000000000 0000000000000000',
            '14def9dea2f79cd6 5812631a5cf5d3ed'],
        h: '8',
        z: '2',
        g: [
          '216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a',
          // 4/5
          '6666666666666666666666666666666666666666666666666666666666666658'
        ]
      });

      const y = curve.field(
        '4627191eb12f51005d2a7f3ef570376a3403801aae928c8ffd13feabadf84505',
        16);

      const p = curve.pointFromY(y, true);

      assert.deepStrictEqual(p.getX().toString(16),
        '2cd591ae3789fd62dc420a152002f79973a387eacecadc6a9a00c1a89488c15d');
    });

    it('should work with secp112r1', () => {
      const curve = new ShortCurve({
        id: 'SECP112R1',
        // (2^128 - 3) / 76439
        p: 'db7c 2abf62e3 5e668076 bead208b',
        a: 'db7c 2abf62e3 5e668076 bead2088',
        b: '659e f8ba0439 16eede89 11702b22',
        n: 'db7c 2abf62e3 5e7628df ac6561c5',
        h: '1',
        z: 'e', // Icart
        g: [
          '0948 7239995a 5ee76b55 f9c2f098',
          'a89c e5af8724 c0a23e0e 0ff77500'
        ]
      });

      const p = curve.pointFromJSON(['0948 7239995a 5ee76b55 f9c2f098',
                                     'a89c e5af8724 c0a23e0e 0ff77500']);

      assert(p.validate());
      assert(p.dbl().validate());

      const raw = Buffer.from('0209487239995a5ee76b55f9c2f098', 'hex');
      const p2 = curve.decodePoint(raw);

      assert(p2.eq(curve.g));
      assert(p2.randomize(rng).eq(curve.g.toJ()));
    });

    it('should work with secp192k1', () => {
      const curve = new ShortCurve({
        id: 'SECP192K1',
        // 2^192 − 2^32 − 2^12 − 2^8 − 2^7 − 2^6 − 2^3 − 1
        p: 'ffffffff ffffffff ffffffff ffffffff fffffffe ffffee37',
        a: '0',
        b: '3',
        n: 'ffffffff ffffffff fffffffe 26f2fc17 0f69466a 74defd8d',
        h: '1',
        z: '1',
        g: [
          'db4ff10e c057e9ae 26b07d02 80b7f434 1da5d1b1 eae06c7d',
          '9b2f2f6d 9c5628a7 844163d0 15be8634 4082aa88 d95e2f9d'
        ]
      });

      assert(curve.endo);

      assert.deepStrictEqual(curve.endo.toJSON(), {
        beta: '447a96e6c647963e2f7809feaab46947f34b0aa3ca0bba74',
        lambda: 'c27b0d93eddc7284b0c2ae9813318686dbb7a0ea73692cdb',
        basis: [
          {
            a: 'b3fb3400dec5c4adceb8655c',
            b: '-71169be7330b3038edb025f1'
          },
          {
            a: '71169be7330b3038edb025f1',
            b: '012511cfe811d0f4e6bc688b4d'
          }
        ],
        pre: [
          256,
          '012511cfe811d0f4e6bc688b4f1d8ccf8538b55e6f',
          '-71169be7330b3038edb025f1d0f885ee42a60a2e'
        ]
      });

      const p = curve.pointFromJSON([
        'f091cf6331b1747684f5d2549cd1d4b3a8bed93b94f93cb6',
        'fd7af42e1e7565a02e6268661c5e42e603da2d98a18f2ed5'
      ]);

      assert(p.validate());
      assert(p.dbl().validate());
    });

    it('should work with secp224k1', () => {
      const curve = new ShortCurve({
        id: 'SECP224K1',
        // 2^224 − 2^32 − 2^12 − 2^11 − 2^9 − 2^7 − 2^4 − 2 − 1
        p: 'ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffe56d',
        a: '0',
        b: '5',
        n: '01 00000000 00000000 00000000 0001dce8 d2ec6184 caf0a971 769fb1f7',
        h: '1',
        z: '-1',
        g: [
          'a1455b33 4df099df 30fc28a1 69a467e9 e47075a9 0f7e650e b6b7a45c',
          '7e089fed 7fba3442 82cafbd6 f7e319f7 c0b0bd59 e2ca4bdb 556d61a5'
        ]
      });

      assert(curve.endo);

      assert.deepStrictEqual(curve.endo.toJSON(), {
        beta: '01f178ffa4b17c89e6f73aece2aad57af4c0a748b63c830947b27e04',
        lambda: '9f232defb3b343f41911103d422bcc75342913534b55766d0a016a6e',
        basis: [
          {
            a: 'b8adf1378a6eb73409fa6c9c637d',
            b: '-6b8cf07d4ca75c88957d9d670591'
          },
          {
            a: '6b8cf07d4ca75c88957d9d670591',
            b: '01243ae1b4d71613bc9f780a03690e'
          }
        ],
        pre: [
          320,
          '01243ae1b4d71613bc9f780a03690bdf98be31116fb699ea8a6760',
          '-6b8cf07d4ca75c88957d9d67059037a4208027beaad46e56a2d5'
        ]
      });

      const p = curve.pointFromJSON([
        '86c0deb56aeb9712390999a0232b9bf596b9639fa1ce8cf426749e60',
        '8f598c954e1085555b474a79906b855c539ed633dbf4a9fa9f06b69a'
      ]);

      assert(p.validate());
      assert(p.dbl().validate());
    });

    it('should get correct endomorphism', () => {
      // See: Guide to Elliptic Curve Cryptography,
      // Example 3.73, Page 125, Section 3.5.
      const curve = new ShortCurve({
        id: 'P160', // NID_wap_wsg_idm_ecid_wtls9
        p: 'fffffffffffffffffffffffffffffffffffc808f',
        a: '0', // Above document incorrectly says a=3.
        b: '3',
        n: '100000000000000000001cdc98ae0e2de574abf33',
        h: '1',
        z: '1',
        g: [
          '1',
          '2'
        ]
      });

      const vector = {
        beta: new BN('771473166210819779552257112796337671037538143582', 10),
        lambda: new BN('903860042511079968555273866340564498116022318806', 10),
        a1: new BN('788919430192407951782190', 10),
        b1: new BN('-602889891024722752429129', 10),
        a2: new BN('602889891024722752429129', 10),
        b2: new BN('1391809321217130704211319', 10),
        shift: 192,
        g1: new BN('5977775516895535289545055658493944', 10),
        g2: new BN('-2589392365040188149150209749093577', 10),

        // Example 3.75, Page 127, Section 3.5.
        rl: new BN('2180728751409538655993509', 10),
        tl: new BN('-186029539167685199353061', 10),
        rl1: new BN('788919430192407951782190', 10),
        tl1: new BN('602889891024722752429129', 10),
        rl2: new BN('602889891024722752429129', 10),
        tl2: new BN('-1391809321217130704211319', 10),

        k: new BN('965486288327218559097909069724275579360008398257', 10),
        c1: new BN('919446671339517233512759', 10),
        c2: new BN('398276613783683332374156', 10),
        k1: new BN('-98093723971803846754077', 10),
        k2: new BN('381880690058693066485147', 10),

        x: new BN('1313336216859441506280637003930462525814923264244', 10),
        y: new BN('935492494656886138804488857832238799944592224261', 10)
      };

      curve.endo = null;
      curve.endo = curve._getEndomorphism(1);

      assert(curve.endo.beta.fromRed().eq(vector.beta));
      assert(curve.endo.lambda.eq(vector.lambda));
      assert(curve.endo.basis[0].a.eq(vector.a1));
      assert(curve.endo.basis[0].b.eq(vector.b1));
      assert(curve.endo.basis[1].a.eq(vector.a2));
      assert(curve.endo.basis[1].b.eq(vector.b2));
      assert(curve.endo.pre[0] === vector.shift);
      assert(curve.endo.pre[1].eq(vector.g1));
      assert(curve.endo.pre[2].eq(vector.g2));

      {
        const [, beta] = curve._getEndoRoots(curve.p);
        const [, lambda] = curve._getEndoRoots(curve.n);

        assert(beta.eq(vector.beta));
        assert(lambda.eq(vector.lambda));

        // Should be cube roots of unity.
        assert(beta.powmn(3, curve.p).cmpn(1) === 0);
        assert(lambda.powmn(3, curve.n).cmpn(1) === 0);
      }

      {
        const {lambda} = vector;
        const [rl, tl, rl1, tl1, rl2, tl2] = curve._egcdSqrt(lambda);

        assert(rl.eq(vector.rl));
        assert(tl.eq(vector.tl));
        assert(rl1.eq(vector.rl1));
        assert(tl1.eq(vector.tl1));
        assert(rl2.eq(vector.rl2));
        assert(tl2.eq(vector.tl2));
      }

      {
        const {lambda} = vector;
        const [v1, v2] = curve._getEndoBasis(lambda);

        assert(v1.a.eq(vector.a1));
        assert(v1.b.eq(vector.b1));
        assert(v2.a.eq(vector.a2));
        assert(v2.b.eq(vector.b2));
      }

      {
        const {basis} = curve.endo;
        const [shift, g1, g2] = curve._getEndoPrecomp(basis);

        assert(shift === vector.shift);
        assert(g1.eq(vector.g1));
        assert(g2.eq(vector.g2));
      }

      {
        const {b1, b2, k} = vector;
        const c1 = b2.mul(k).divRound(curve.n);
        const c2 = b1.neg().mul(k).divRound(curve.n);

        assert(c1.eq(vector.c1));
        assert(c2.eq(vector.c2));
      }

      {
        const {shift, g1, g2, k} = vector;
        const c1 = k.mulShift(g1, shift);
        const c2 = k.mulShift(g2, shift).ineg();

        assert(c1.eq(vector.c1));
        assert(c2.eq(vector.c2));
      }

      {
        const {k} = vector;
        const [k1, k2] = curve._endoSplit(k);

        assert(k1.eq(vector.k1));
        assert(k2.eq(vector.k2));
      }

      {
        const {k} = vector;

        curve.precompute(rng);

        const p = curve.g.mul(k);

        assert(!p.isInfinity());
        assert(p.x.fromRed().eq(vector.x));
        assert(p.y.fromRed().eq(vector.y));
      }
    });

    it('should work with secp256k1', () => {
      const curve = new ShortCurve({
        id: 'SECP256K1',
        p: ['ffffffff ffffffff ffffffff ffffffff',
            'ffffffff ffffffff fffffffe fffffc2f'],
        a: '0',
        b: '7',
        n: ['ffffffff ffffffff ffffffff fffffffe',
            'baaedce6 af48a03b bfd25e8c d0364141'],
        h: '1',
        z: '1',
        g: [
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
        ]
      });

      const p = curve.pointFromJSON([
        ['79be667e f9dcbbac 55a06295 ce870b07',
         '029bfcdb 2dce28d9 59f2815b 16f81798'],
        ['483ada77 26a3c465 5da4fbfc 0e1108a8',
         'fd17b448 a6855419 9c47d08f fb10d4b8']
      ]);

      const s = new BN('79be667e f9dcbbac 55a06295 ce870b07', 16);

      assert(p.validate());
      assert(p.dbl().validate());
      assert(p.toJ().dbl().toP().validate());
      assert(p.mul(s).validate());

      // Endomorphism test
      assert(curve.endo);

      assert.strictEqual(
        curve.endo.beta.fromRed().toString(16),
        '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee');

      assert.strictEqual(
        curve.endo.lambda.toString(16),
        '5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72');

      assert.strictEqual(curve.endo.basis[0].a.toString(16),
                         '3086d221a7d46bcde86c90e49284eb15');
      assert.strictEqual(curve.endo.basis[0].b.toString(16),
                         '-e4437ed6010e88286f547fa90abfe4c3');
      assert.strictEqual(curve.endo.basis[1].a.toString(16),
                         '114ca50f7a8e2f3f657c1108d9d44cfd8');
      assert.strictEqual(curve.endo.basis[1].b.toString(16),
                         '3086d221a7d46bcde86c90e49284eb15');

      assert.strictEqual(curve.endo.pre[0], 384);
      assert.strictEqual(curve.endo.pre[1].toString(16),
                         '3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031');
      assert.strictEqual(curve.endo.pre[2].toString(16),
                         '-e4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71');

      for (let i = 0; i < 10; i++) {
        const k = curve.randomScalar(rng);

        if (i & 1)
          k.ineg();

        if (i & 2)
          k.imul(curve.randomScalar(rng));

        const [k1, k2] = curve._endoSplit(k);
        const r = k1.add(k2.mul(curve.endo.lambda)).mod(curve.n);

        assert.strictEqual(r.toString(16), k.mod(curve.n).toString(16));
      }

      const endoSplit2 = (k) => {
        const [v1, v2] = curve.endo.basis;
        const [shift, g1, g2] = curve.endo.pre;

        const c1 = k.mulShift(g1, shift);
        const c2 = k.mulShift(g2, shift).ineg();

        const p1 = c1.mul(v1.a);
        const p2 = c2.mul(v2.a);
        const q1 = c1.ineg().mul(v1.b);
        const q2 = c2.mul(v2.b);

        const k1 = k.sub(p1).isub(p2);
        const k2 = q1.isub(q2);

        return [k1, k2];
      };

      for (let i = 0; i < 10; i++) {
        const k = curve.randomScalar(rng);

        if (i & 1)
          k.ineg();

        if (i & 2)
          k.imul(curve.randomScalar(rng));

        const [k1, k2] = endoSplit2(k);
        const r = k1.add(k2.mul(curve.endo.lambda)).mod(curve.n);

        assert.strictEqual(r.toString(16), k.mod(curve.n).toString(16));
      }

      const endoSplit3 = (k) => {
        const {lambda} = curve.endo;
        const [v1, v2] = curve.endo.basis;
        const [shift, g1, g2] = curve.endo.pre;

        k = k.mod(curve.n);

        // c1 = ((k * g1) >> t) * -b1
        // c2 = ((k * -g2) >> t) * -b2
        // k2 = c1 + c2
        // k1 = k2 * -lambda + k
        const c1 = k.mulShift(g1, shift).mul(v1.b.neg());
        const c2 = k.mulShift(g2.neg(), shift).mul(v2.b.neg());
        const k2 = c1.add(c2).mod(curve.n);
        const k1 = k2.mul(lambda.neg()).iadd(k).mod(curve.n);

        if (k1.cmp(curve.nh) > 0)
          k1.ineg().imod(curve.n).ineg();

        if (k2.cmp(curve.nh) > 0)
          k2.ineg().imod(curve.n).ineg();

        return [k1, k2];
      };

      for (let i = 0; i < 10; i++) {
        const k = curve.randomScalar(rng);

        if (i & 1)
          k.ineg();

        if (i & 2)
          k.imul(curve.randomScalar(rng));

        const [k1, k2] = endoSplit3(k);
        const r = k1.add(k2.mul(curve.endo.lambda)).mod(curve.n);

        assert.strictEqual(r.toString(16), k.mod(curve.n).toString(16));
      }
    });

    it('should verify scalar decomposition bounds', () => {
      // See: https://github.com/bitcoin-core/secp256k1/pull/822
      const curve = new curves.SECP256K1();
      const {lambda, basis} = curve.endo;
      const a1 = basis[0].a;
      const b1 = basis[0].b;
      const a2 = basis[1].a;
      const b2 = basis[1].b;
      const {n} = curve;
      const scalars = [];

      // Generate scalar decomposition bounds.
      //
      //   k1_bound = (a1 + a2 - 1) / 2
      //   k2_bound = (-b1 + b2) / 2
      const k1Bound = a1.add(a2).isubn(1).iushrn(1).imod(n);
      const k2Bound = b1.neg().iadd(b2).iushrn(1).imod(n);

      assert(k1Bound.toString(16) === 'a2a8918ca85bafe22016d0b917e4dd76');
      assert(k2Bound.toString(16) === '8a65287bd47179fb2be08846cea267ec');

      assert(k1Bound.bitLength() <= 128);
      assert(k2Bound.bitLength() <= 128);

      // Check random scalars.
      for (let i = 0; i < 100; i++) {
        const k = curve.randomScalar(rng);
        const [k1, k2] = curve._endoSplit(k);
        const s = lambda.mul(k2).iadd(k1).imod(n);

        assert(s.cmp(k) === 0);
        assert(k1.ucmp(k1Bound) <= 0);
        assert(k2.ucmp(k2Bound) <= 0);
      }

      // Generate scalars that split near bounds.
      //
      //   k = (a * lambda + (n + b) / 2) mod n
      //
      // Where a = (-2, -1, 0, 1, 2)
      //       b = (-3, -1, 1, 3)
      for (const a of [-2, -1, 0, 1, 2]) {
        for (const b of [-3, -1, 1, 3]) {
          const k = lambda.muln(a).iadd(n.addn(b).iushrn(1)).imod(n);
          const [k1, k2] = curve._endoSplit(k);
          const s = lambda.mul(k2).iadd(k1).imod(n);

          assert(s.cmp(k) === 0);
          assert(k1.ucmp(k1Bound) <= 0);
          assert(k2.ucmp(k2Bound) <= 0);

          scalars.push(k);
        }
      }

      // Verify P * k + P * r + P * -(k + r) = O.
      // Where r is a random integer in [1,n-1].
      for (const k of scalars) {
        const k1 = curve.randomScalar(rng);
        const k2 = k.add(k1).ineg().imod(n);
        const g = curve.randomPoint(rng);
        const p0 = g.mul(k);
        const p1 = g.mul(k1);
        const p2 = g.mul(k2);

        assert(k1.add(k2).imod(n).cmp(k.neg().imod(n)) === 0);
        assert(p0.add(p1).add(p2).isInfinity());
      }
    });

    it('should compute this problematic secp256k1 multiplication', () => {
      const curve = new curves.SECP256K1();
      const g1 = curve.g;
      const g2 = curve.g.clone();

      curve.precompute(rng);

      assert(g1.pre);
      assert(!g2.pre);

      const a = new BN(
        '6d1229a6b24c2e775c062870ad26bc261051e0198c67203167273c7c62538846',
        16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not use fixed NAF when k is too large', () => {
      const curve = new curves.SECP256K1();
      const g1 = curve.g;
      const g2 = curve.g.clone();

      curve.precompute(rng);

      assert(g1.pre);
      assert(!g2.pre);

      const a = new BN('6d1229a6b24c2e775c062870ad26bc26105'
                     + '1e0198c67203167273c7c6253884612345678', 16);

      const p1 = g1.mul(a);
      const p2 = g2.mul(a);

      assert(p1.eq(p2));
    });

    it('should not fail on secp256k1 regression', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const k1 = new BN(
        '32efeba414cd0c830aed727749e816a01c471831536fd2fce28c56b54f5a3bb1',
        16);

      const k2 = new BN(
        '5f2e49b5d64e53f9811545434706cde4de528af97bfd49fde1f6cf792ee37a8c',
        16);

      const p1 = curve.g.mul(k1);
      const p2 = curve.g.mul(k2);

      // 2 + 2 + 1 = 2 + 1 + 2
      const two = p2.dbl();
      const five = two.dbl().add(p2);
      const three = two.add(p2);
      const maybeFive = three.add(two);

      assert(maybeFive.eq(five));

      const p3 = p1.mul(k2);
      const p4 = p2.mul(k1);

      assert(p3.validate());
      assert(p4.validate());
      assert(p3.eq(p4));
    });

    it('should correctly double the affine point on secp256k1', () => {
      const curve = new curves.SECP256K1();

      const bad = [
        curve.field(
          '026a2073b1ef6fab47ace18e60e728a05180a82755bbcec9a0abc08ad9f7a3d4',
          16),
        curve.field(
          '9cd8cb48c3281596139f147c1364a3ede88d3f310fdb0eb98c924e599ca1b3c9',
          16),
        curve.field(
          'd78587ad45e4102f48b54b5d85598296e069ce6085002e169c6bad78ddc6d9bd',
          16)
      ];

      const good = [
        curve.field(
          'e7789226739ac2eb3c7ccb2a9a910066beeed86cdb4e0f8a7fee8eeb29dc7016',
          16),
        curve.field(
          '4b76b191fd6d47d07828ea965e275b76d0e3e0196cd5056d38384fbb819f9fcb',
          16),
        curve.field(
          'cbf8d99056618ba132d6145b904eee1ce566e0feedb9595139c45f84e90cfa7d',
          16)
      ];

      const pbad = curve.jpoint(...bad);
      const pgood = curve.jpoint(...good);

      // They are the same points
      assert(pbad.add(pgood.neg()).isInfinity());

      // But doubling borks them out
      assert(pbad.dbl().add(pgood.dbl().neg()).isInfinity());
    });

    it('should multiply with blinding', () => {
      const curve = new curves.SECP256K1();

      curve.precompute(rng);

      const {blind} = curve.g.pre.blinding;
      const neg = blind.neg().imod(curve.n);
      const point1 = curve.g.mulBlind(neg);
      const point2 = curve.g.mul(neg);
      const point3 = curve.g.mulBlind(blind);
      const point4 = curve.g.mul(blind);

      assert(point1.eq(point2));
      assert(point3.eq(point4));
      assert(point3.neg().eq(point1));
    });

    it('should convert mont to twisted', () => {
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();
      const [a, d] = x25519._edwards(x25519.one.redNeg(), false);

      assert(a.eq(ed25519.a));
      assert(d.eq(ed25519.d));

      assert(x25519.jinv().eq(ed25519.jinv()));
      assert(x25519.isIsomorphic(ed25519));
      assert(ed25519.isIsomorphic(x25519));
      assert(!x25519.isIsomorphic(ed25519, true));
      assert(!ed25519.isIsomorphic(x25519, true));
    });

    it('should convert mont to edwards', () => {
      const x448 = new curves.X448();
      const ed448 = new curves.ISO448();
      const [a, d] = x448._edwards(x448.one, true);

      assert(a.eq(ed448.a));
      assert(d.eq(ed448.d));

      assert(x448.jinv().eq(ed448.jinv()));
      assert(!x448.isIsomorphic(ed448));
      assert(!ed448.isIsomorphic(x448));
      assert(x448.isIsomorphic(ed448, true));
      assert(ed448.isIsomorphic(x448, true));
    });

    it('should convert twisted to mont', () => {
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();
      const [a, b] = ed25519._mont(ed25519.one, false);

      assert(a.eq(x25519.a));
      assert(b.eq(x25519.b));
    });

    it('should convert edwards to mont', () => {
      const x448 = new curves.X448();
      const iso448 = new curves.ISO448();
      const [a, b] = iso448._mont(iso448.one, true);

      assert(x448.jinv().eq(iso448.jinv()));
      assert(a.eq(x448.a));
      assert(b.eq(x448.b));
    });

    it('should convert mont to short', () => {
      const wei25519 = new curves.WEI25519();
      const x25519 = new curves.X25519();
      const [a, b] = x25519._short();

      assert(a.eq(wei25519.a));
      assert(b.eq(wei25519.b));

      assert(wei25519.jinv().eq(x25519.jinv()));
      assert(wei25519.isIsomorphic(x25519));
      assert(x25519.isIsomorphic(wei25519));
    });

    it('should convert short to mont (twisted)', () => {
      const x25519 = new curves.X25519();
      const wei25519 = new curves.WEI25519();
      const [a, b] = wei25519._mont();

      assert(wei25519.jinv().eq(x25519.jinv()));
      assert(a.eq(x25519.a));
      assert(b.eq(x25519.b));
    });

    it('should convert short to mont (twisted, native)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = ed25519.toMont();
      const wei25519 = x25519.toShort();
      const [a, b] = wei25519._mont(null, false);

      assert(wei25519.jinv().eq(x25519.jinv()));
      assert(a.eq(x25519.a));
      assert(b.eq(x25519.b));
    });

    it('should convert short to mont (twist448)', () => {
      const ed448 = new curves.TWIST448();
      const x448 = ed448.toMont(ed448.one);
      const wei448 = x448.toShort();
      const [a, b] = wei448._mont();

      assert(a.eq(x448.a));
      assert(b.eq(x448.b));

      assert(ed448.jinv().eq(x448.jinv()));
      assert(wei448.jinv().eq(x448.jinv()));
      assert(ed448.isIsomorphic(x448));
      assert(x448.isIsomorphic(ed448));
      assert(!ed448.isIsomorphic(x448, true));
      assert(!x448.isIsomorphic(ed448, true));
      assert(wei448.isIsomorphic(x448));
      assert(x448.isIsomorphic(wei448));
    });

    it('should convert short to mont (edwards)', () => {
      const x448 = new curves.X448();
      const wei448 = x448.toShort();
      const [a, b] = wei448._mont();

      assert(a.eq(x448.a));
      assert(b.eq(x448.b));

      assert(wei448.jinv().eq(x448.jinv()));
      assert(wei448.isIsomorphic(x448));
      assert(x448.isIsomorphic(wei448));
    });

    it('should convert short to mont (edwards, native)', () => {
      const ed448 = new curves.ED448();
      const x448 = ed448.toMont();
      const wei448 = x448.toShort();
      const [a, b] = wei448._mont(null, false);

      assert(a.eq(x448.a));
      assert(b.eq(x448.b));

      assert(wei448.jinv().eq(x448.jinv()));
      assert(wei448.isIsomorphic(x448));
      assert(x448.isIsomorphic(wei448));
    });

    it('should convert short to mont (edwards, native, inverted)', () => {
      const ed448 = new curves.ED448();
      const x448 = ed448.toMont(null, true);
      const wei448 = x448.toShort();
      const [a, b] = wei448._mont();

      assert(a.eq(x448.a));
      assert(b.eq(x448.b));

      assert(wei448.jinv().eq(x448.jinv()));
      assert(wei448.isIsomorphic(x448, true));
      assert(x448.isIsomorphic(wei448, true));
    });

    it('should convert short to edwards', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = ed25519.toMont();
      const wei25519 = x25519.toShort();
      const [a, d] = wei25519._edwards(null, false);

      assert(a.eq(ed25519.a));
      assert(d.eq(ed25519.d));
    });

    it('should convert edwards to short', () => {
      const ed25519 = new curves.ED25519();
      const [a0, b0] = ed25519.toMont()._short();
      const [a, b] = ed25519._short();

      assert(a.eq(a0));
      assert(b.eq(b0));
    });

    it('should match multiplications', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, x25519, ed25519]) {
        for (let i = 0; i < 2; i++) {
          const k0 = curve.randomScalar(rng);
          const k1 = k0.divn(3).mul(k0);

          const p1 = curve.g.mul(k0);
          const p2 = curve.g.mul(k0);

          assert(p1.eq(p2));

          const j1 = curve.g.jmul(k0);
          const j2 = curve.g.jmul(k0);

          assert(j1.eq(j2));

          const j3 = curve.g.toJ().mul(k0);
          const j4 = curve.g.toJ().mul(k0);

          assert(j3.eq(j4));

          const p3 = curve.g.mul(k1);
          const p4 = curve.g.mul(k1.mod(curve.n));
          const p5 = curve.g.mul(k1);

          assert(p3.eq(p4));
          assert(p4.eq(p5));

          const p6 = curve.g.mul(k1.neg());
          const p7 = curve.g.mul(k1.neg().imod(curve.n));
          const p8 = curve.g.mul(k1.neg());

          assert(p6.eq(p3.neg()));
          assert(p6.eq(p7));
          assert(p7.eq(p8));

          curve.precompute(rng);
        }
      }
    });

    it('should match multiplications (ladder)', () => {
      const curve = new curves.SECP256K1();

      const k0 = curve.randomScalar(rng);
      const k1 = k0.muln(17);

      const p1 = curve.g.mulBlind(k0);
      const p2 = curve.g.mul(k0);

      assert(p1.eq(p2));

      const p3 = curve.g.mulBlind(k0.neg());
      const p4 = curve.g.mul(k0.neg().imod(curve.n));

      assert(p3.eq(p1.neg()));
      assert(p3.eq(p4));

      const j1 = curve.g.jmulBlind(k0);
      const j2 = curve.g.jmul(k0);

      assert(j1.eq(j2));

      const j3 = curve.g.jmulBlind(k0.neg());
      const j4 = curve.g.jmul(k0.neg().imod(curve.n));

      assert(j3.eq(j1.neg()));
      assert(j3.eq(j4));

      const j5 = curve.g.jmulBlind(k1);
      const j6 = curve.g.jmul(k1);

      assert(j5.eq(j6));

      const j7 = curve.g.jmulBlind(k1.neg());
      const j8 = curve.g.jmul(k1.neg().imod(curve.n));

      assert(j7.eq(j5.neg()));
      assert(j7.eq(j8));

      assert(curve.g.mulBlind(new BN(0)).isInfinity());
      assert(curve.g.mulBlind(new BN(-1)).eq(curve.g.neg()));
      assert(curve.g.mulBlind(new BN(-2)).eq(curve.g.dbl().neg()));
      assert(curve.g.mulBlind(new BN(-3)).eq(curve.g.dbl().add(curve.g).neg()));
      assert(curve.g.mulBlind(new BN(-4)).eq(curve.g.dbl().dbl().neg()));
      assert(curve.g.mulBlind(new BN(1)).eq(curve.g));
      assert(curve.g.mulBlind(new BN(2)).eq(curve.g.dbl()));
      assert(curve.g.mulBlind(new BN(3)).eq(curve.g.dbl().add(curve.g)));
      assert(curve.g.mulBlind(new BN(4)).eq(curve.g.dbl().dbl()));
      assert(curve.g.mulBlind(curve.n).isInfinity());
      assert(curve.g.mulBlind(curve.n.add(curve.n)).isInfinity());
      assert(curve.g.mulBlind(curve.n.addn(1)).eq(curve.g));
      assert(curve.g.mulBlind(curve.n.addn(1).add(curve.n)).eq(curve.g));
      assert(curve.g.mulBlind(curve.n.addn(2)).eq(curve.g.dbl()));
      assert(curve.g.mulBlind(curve.n.addn(2).add(curve.n)).eq(curve.g.dbl()));
      assert(curve.g.mulBlind(curve.n.addn(3)).eq(curve.g.dbl().add(curve.g)));
      assert(curve.g.mulBlind(curve.n.addn(4)).eq(curve.g.dbl().dbl()));
      assert(curve.g.mulBlind(curve.n.subn(1)).eq(curve.g.neg()));
      assert(curve.g.mulBlind(curve.n.subn(1).add(curve.n)).eq(curve.g.neg()));
      assert(curve.g.mulBlind(curve.n.subn(2)).eq(curve.g.dbl().neg()));
      assert(curve.g.mulBlind(curve.n.subn(2).add(curve.n)).eq(curve.g.dbl().neg()));
      assert(curve.g.mulBlind(curve.n.subn(3)).eq(curve.g.dbl().add(curve.g).neg()));
      assert(curve.g.mulBlind(curve.n.subn(4)).eq(curve.g.dbl().dbl().neg()));
      assert(curve.g.mulBlind(curve.n.muln(2)).isInfinity());
      assert(curve.g.mulBlind(curve.n.neg()).isInfinity());
      assert(curve.g.mulBlind(curve.n.muln(2).neg()).isInfinity());
    });

    it('should match multiplications (ladder+rng)', () => {
      const curve = new curves.SECP256K1();

      const k0 = curve.randomScalar(rng);
      const k1 = k0.muln(17);

      const p1 = curve.g.mulBlind(k0, rng);
      const p2 = curve.g.mul(k0);

      assert(p1.eq(p2));

      const p3 = curve.g.mulBlind(k0.neg(), rng);
      const p4 = curve.g.mul(k0.neg().imod(curve.n));

      assert(p3.eq(p1.neg()));
      assert(p3.eq(p4));

      const j1 = curve.g.jmulBlind(k0, rng);
      const j2 = curve.g.jmul(k0);

      assert(j1.eq(j2));

      const j3 = curve.g.jmulBlind(k0.neg(), rng);
      const j4 = curve.g.jmul(k0.neg().imod(curve.n));

      assert(j3.eq(j1.neg()));
      assert(j3.eq(j4));

      const j5 = curve.g.jmulBlind(k1, rng);
      const j6 = curve.g.jmul(k1);

      assert(j5.eq(j6));

      const j7 = curve.g.jmulBlind(k1.neg(), rng);
      const j8 = curve.g.jmul(k1.neg().imod(curve.n));

      assert(j7.eq(j5.neg()));
      assert(j7.eq(j8));

      assert(curve.g.mulBlind(new BN(0), rng).isInfinity());
      assert(curve.g.mulBlind(new BN(-1), rng).eq(curve.g.neg()));
      assert(curve.g.mulBlind(new BN(-2)).eq(curve.g.dbl().neg()));
      assert(curve.g.mulBlind(new BN(-3)).eq(curve.g.dbl().add(curve.g).neg()));
      assert(curve.g.mulBlind(new BN(-4)).eq(curve.g.dbl().dbl().neg()));
      assert(curve.g.mulBlind(new BN(1), rng).eq(curve.g));
      assert(curve.g.mulBlind(new BN(2), rng).eq(curve.g.dbl()));
      assert(curve.g.mulBlind(new BN(3), rng).eq(curve.g.dbl().add(curve.g)));
      assert(curve.g.mulBlind(new BN(4), rng).eq(curve.g.dbl().dbl()));
      assert(curve.g.mulBlind(curve.n, rng).isInfinity());
      assert(curve.g.mulBlind(curve.n.add(curve.n), rng).isInfinity());
      assert(curve.g.mulBlind(curve.n.addn(1), rng).eq(curve.g));
      assert(curve.g.mulBlind(curve.n.addn(1).add(curve.n), rng).eq(curve.g));
      assert(curve.g.mulBlind(curve.n.addn(2), rng).eq(curve.g.dbl()));
      assert(curve.g.mulBlind(curve.n.addn(2).add(curve.n), rng).eq(curve.g.dbl()));
      assert(curve.g.mulBlind(curve.n.addn(3), rng).eq(curve.g.dbl().add(curve.g)));
      assert(curve.g.mulBlind(curve.n.addn(4), rng).eq(curve.g.dbl().dbl()));
      assert(curve.g.mulBlind(curve.n.subn(1), rng).eq(curve.g.neg()));
      assert(curve.g.mulBlind(curve.n.subn(1).add(curve.n), rng).eq(curve.g.neg()));
      assert(curve.g.mulBlind(curve.n.subn(2), rng).eq(curve.g.dbl().neg()));
      assert(curve.g.mulBlind(curve.n.subn(2).add(curve.n), rng).eq(curve.g.dbl().neg()));
      assert(curve.g.mulBlind(curve.n.subn(3), rng).eq(curve.g.dbl().add(curve.g).neg()));
      assert(curve.g.mulBlind(curve.n.subn(4), rng).eq(curve.g.dbl().dbl().neg()));
      assert(curve.g.mulBlind(curve.n.muln(2), rng).isInfinity());
      assert(curve.g.mulBlind(curve.n.neg(), rng).isInfinity());
      assert(curve.g.mulBlind(curve.n.muln(2).neg(), rng).isInfinity());
    });

    it('should match multiplications (fixed)', () => {
      const curve = new curves.SECP256K1();
      const mul = (p, k) => curve._fixedNafMul(p, k).toP();
      const jmul = (p, k) => curve._fixedNafMul(p, k);

      const k1 = curve.randomScalar(rng);
      const k2 = BN.mask(256);

      curve.precompute(rng);

      assert(curve.g._hasDoubles(k1));
      assert(curve.g._hasDoubles(k1.neg()));

      assert(k2.bitLength() === 256);
      assert(curve.g._hasDoubles(k2));
      assert(curve.g._hasDoubles(k2.neg()));

      const p1 = mul(curve.g, k1);
      const p2 = curve.g.mul(k1);

      assert(p1.eq(p2));

      const p3 = mul(curve.g, k1.neg());
      const p4 = curve.g.mul(k1.neg().imod(curve.n));

      assert(p3.eq(p1.neg()));
      assert(p3.eq(p4));

      const j1 = jmul(curve.g, k1);
      const j2 = curve.g.jmul(k1);

      assert(j1.eq(j2));

      const j3 = jmul(curve.g, k1.neg());
      const j4 = curve.g.jmul(k1.neg().imod(curve.n));

      assert(j3.eq(j1.neg()));
      assert(j3.eq(j4));
    });

    it('should match multiplications (wnaf)', () => {
      const curve = new curves.SECP256K1();
      const mul = (p, k) => curve._wnafMul(5, p, k).toP();
      const jmul = (p, k) => curve._wnafMul(5, p, k);

      for (const g of [curve.g, curve.g, curve.randomPoint(rng)]) {
        const k0 = curve.randomScalar(rng);
        const k1 = k0.divn(3).mul(k0);

        const p1 = mul(g, k0);
        const p2 = g.mul(k0);

        assert(p1.eq(p2));

        const j1 = jmul(g, k0);
        const j2 = g.jmul(k0);

        assert(j1.eq(j2));

        const p3 = mul(g, k1);
        const p4 = g.mul(k1.mod(curve.n));

        assert(p3.eq(p4));

        const p5 = mul(g, k1.neg());
        const p6 = g.mul(k1.neg().imod(curve.n));

        assert(p5.eq(p3.neg()));
        assert(p5.eq(p6));

        curve.precompute(rng);
      }
    });

    it('should match multiplications (muladd)', () => {
      const curve = new curves.SECP256K1();
      const mul = (p, k) => curve._wnafMulAdd(2, [p], [k]).toP();
      const jmul = (p, k) => curve._wnafMulAdd(2, [p], [k]);

      for (const g of [curve.g, curve.g, curve.randomPoint(rng)]) {
        const k0 = curve.randomScalar(rng);
        const k1 = k0.divn(3).mul(k0);

        const p1 = mul(g, k0);
        const p2 = g.mul(k0);

        assert(p1.eq(p2));

        const j1 = jmul(g, k0);
        const j2 = g.jmul(k0);

        assert(j1.eq(j2));

        const p3 = mul(g, k1);
        const p4 = g.mul(k1.mod(curve.n));

        assert(p3.eq(p4));

        const p5 = mul(g, k1.neg());
        const p6 = g.mul(k1.neg().imod(curve.n));

        assert(p5.eq(p3.neg()));
        assert(p5.eq(p6));

        curve.precompute(rng);
      }
    });

    it('should match multiplications (endo)', () => {
      const curve = new curves.SECP256K1();
      const mul = (p, k) => curve._endoWnafMulAdd([p], [k]).toP();
      const jmul = (p, k) => curve._endoWnafMulAdd([p], [k]);

      for (const g of [curve.g, curve.g, curve.randomPoint(rng)]) {
        const k0 = curve.randomScalar(rng);
        const k1 = k0.divn(3).mul(k0);

        const p1 = mul(g, k0);
        const p2 = g.mul(k0);

        assert(p1.eq(p2));

        const j1 = jmul(g, k0);
        const j2 = g.jmul(k0);

        assert(j1.eq(j2));

        const p3 = mul(g, k1);
        const p4 = g.mul(k1.mod(curve.n));

        assert(p3.eq(p4));

        const p5 = mul(g, k1.neg());
        const p6 = g.mul(k1.neg().imod(curve.n));

        assert(p5.eq(p3.neg()));
        assert(p5.eq(p6));

        curve.precompute(rng);
      }
    });

    it('should match multiplications (blind)', () => {
      const curve = new curves.SECP256K1();
      const mul = (p, k) => p.mulBlind(k, rng);
      const jmul = (p, k) => p.jmulBlind(k, rng);

      for (const g of [curve.g, curve.g, curve.randomPoint(rng)]) {
        const k0 = curve.randomScalar(rng);
        const k1 = k0.divn(3).mul(k0);

        const p1 = mul(g, k0);
        const p2 = g.mul(k0);

        assert(p1.eq(p2));

        const j1 = jmul(g, k0);
        const j2 = g.jmul(k0);

        assert(j1.eq(j2));

        const p3 = mul(g, k1);
        const p4 = g.mul(k1.mod(curve.n));

        assert(p3.eq(p4));

        const p5 = mul(g, k1.neg());
        const p6 = g.mul(k1.neg().imod(curve.n));

        assert(p5.eq(p3.neg()));
        assert(p5.eq(p6));

        curve.precompute(rng);
      }
    });

    it('should match multiply+add', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, x25519, ed25519]) {
        for (let i = 0; i < 2; i++) {
          const k0 = curve.randomScalar(rng);
          const k1 = curve.randomScalar(rng);
          const k2 = k0.divn(3).mul(k0);
          const A = curve.randomPoint(rng);
          const J = A.randomize(rng);

          const p1 = curve.g.mulAdd(k0, A, k1);
          const p2 = curve.g.mulAdd(k0, A, k1);

          assert(p1.eq(p2));

          const j1 = curve.g.jmulAdd(k0, A, k1);
          const j2 = curve.g.jmulAdd(k0, A, k1);

          assert(j1.eq(j2));

          const j3 = curve.g.toJ().mulAdd(k0, J, k1);
          const j4 = curve.g.toJ().mulAdd(k0, J, k1);

          assert(j3.eq(j4));

          const p3 = curve.g.mulAdd(k2, A, k1);
          const p4 = curve.g.mulAdd(k2.mod(curve.n), A, k1);
          const p5 = curve.g.mulAdd(k2, A, k1);

          assert(p3.eq(p4));
          assert(p5.eq(p4));

          const p6 = curve.g.mulAdd(k2.neg(), A, k1);
          const p7 = curve.g.mulAdd(k2.neg().imod(curve.n), A, k1);
          const p8 = curve.g.mulAdd(k2.neg(), A, k1);

          assert(p6.eq(p7));
          assert(p8.eq(p7));

          curve.precompute(rng);
        }
      }
    });

    it('should multiply negative scalar', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, x25519, ed25519]) {
        for (let i = 0; i < 2; i++) {
          const k1 = curve.randomScalar(rng);
          const k2 = k1.sqr();
          const k3 = k2.divn(17);
          const k4 = k3.mod(curve.n);

          {
            const p1 = curve.g.mul(k1);
            const p2 = curve.g.mul(k1.neg());

            assert(!p2.isInfinity());
            assert(p2.eq(p1.neg()));

            const p3 = curve.g.mul(k2);
            const p4 = curve.g.mul(k2.neg());

            assert(!p4.isInfinity());
            assert(p4.eq(p3.neg()));

            const p5 = p1.mul(k3);
            const p6 = p1.mul(k3.neg());

            assert(!p6.isInfinity());
            assert(p6.eq(p5.neg()));

            const p7 = p2.mul(k4);
            const p8 = p2.mul(k4.neg());

            assert(!p8.isInfinity());
            assert(p8.eq(p7.neg()));
          }

          {
            const p1 = curve.g.jmul(k1);
            const p2 = curve.g.jmul(k1.neg());

            assert(!p2.isInfinity());
            assert(p2.eq(p1.neg()));

            const p3 = curve.g.jmul(k2);
            const p4 = curve.g.jmul(k2.neg());

            assert(!p4.isInfinity());
            assert(p4.eq(p3.neg()));

            const p5 = p1.jmul(k3);
            const p6 = p1.jmul(k3.neg());

            assert(!p6.isInfinity());
            assert(p6.eq(p5.neg()));

            const p7 = p2.jmul(k4);
            const p8 = p2.jmul(k4.neg());

            assert(!p8.isInfinity());
            assert(p8.eq(p7.neg()));
          }

          {
            const p1 = curve.g.mulBlind(k1, rng);
            const p2 = curve.g.mulBlind(k1.neg(), rng);

            assert(!p2.isInfinity());
            assert(p2.eq(p1.neg()));

            const p3 = curve.g.mulBlind(k2, rng);
            const p4 = curve.g.mulBlind(k2.neg(), rng);

            assert(!p4.isInfinity());
            assert(p4.eq(p3.neg()));

            const p5 = p1.mulBlind(k3, rng);
            const p6 = p1.mulBlind(k3.neg(), rng);

            assert(!p6.isInfinity());
            assert(p6.eq(p5.neg()));

            const p7 = p2.mulBlind(k4, rng);
            const p8 = p2.mulBlind(k4.neg(), rng);

            assert(!p8.isInfinity());
            assert(p8.eq(p7.neg()));
          }

          curve.precompute(rng);
        }
      }
    });

    it('should multiply+add negative scalar', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();

      for (const curve of [p256, secp256k1, x25519, ed25519]) {
        for (let i = 0; i < 2; i++) {
          const A0 = curve.randomPoint(rng);
          const J0 = A0.randomize(rng);
          const k0 = curve.randomScalar(rng);
          const A1 = A0.mul(k0);
          const J1 = A1.randomize(rng);
          const k1 = curve.randomScalar(rng);
          const k2 = k1.sqr();
          const k3 = k2.divn(17);
          const k4 = k3.mod(curve.n);

          {
            const p1 = curve.g.mul(k1).neg().add(A1);
            const p2 = curve.g.mulAdd(k1.neg(), A0, k0);

            assert(!p2.isInfinity());
            assert(p2.eq(p1));

            const p3 = curve.g.mul(k2).neg().add(A1);
            const p4 = curve.g.mulAdd(k2.neg(), A0, k0);

            assert(!p4.isInfinity());
            assert(p4.eq(p3));

            const p5 = p1.mul(k3).neg().add(A1);
            const p6 = p1.mulAdd(k3.neg(), A0, k0);

            assert(!p6.isInfinity());
            assert(p6.eq(p5));

            const p7 = p2.mul(k4).neg().add(A1);
            const p8 = p2.mulAdd(k4.neg(), A0, k0);

            assert(!p8.isInfinity());
            assert(p8.eq(p7));
          }

          {
            const p1 = curve.g.jmul(k1).neg().add(J1);
            const p2 = curve.g.jmulAdd(k1.neg(), A0, k0);

            assert(!p2.isInfinity());
            assert(p2.eq(p1));

            const p3 = curve.g.jmul(k2).neg().add(J1);
            const p4 = curve.g.jmulAdd(k2.neg(), A0, k0);

            assert(!p4.isInfinity());
            assert(p4.eq(p3));

            const p5 = p1.jmul(k3).neg().add(J1);
            const p6 = p1.jmulAdd(k3.neg(), J0, k0);

            assert(!p6.isInfinity());
            assert(p6.eq(p5));

            const p7 = p2.jmul(k4).neg().add(J1);
            const p8 = p2.jmulAdd(k4.neg(), J0, k0);

            assert(!p8.isInfinity());
            assert(p8.eq(p7));
          }

          curve.precompute(rng);
        }
      }
    });

    it('should correctly recover X (edwards)', () => {
      const ed25519 = new curves.ED25519();
      const ed448 = new curves.ED448();

      for (const curve of [ed25519, ed448]) {
        const y = curve.g.getY();
        const s = curve.g.x.redIsOdd();
        const g = curve.pointFromY(y, s);

        assert(curve.g.eq(g));
      }
    });

    it('should correctly recover Y (edwards)', () => {
      const ed25519 = new curves.ED25519();
      const ed448 = new curves.ED448();

      for (const curve of [ed25519, ed448]) {
        const x = curve.g.getX();
        const s = curve.g.y.redIsOdd();
        const g = curve.pointFromX(x, s);

        assert(curve.g.eq(g));
      }

      for (const curve of [ed25519, ed448]) {
        for (let i = 0; i < 4; i++) {
          const p = curve.randomPoint(rng);
          const x = p.getX();
          const s = p.y.redIsOdd();
          const q = curve.pointFromX(x, s);

          assert(p.eq(q));
        }
      }
    });

    it('should have basepoint for x25519', () => {
      // https://tools.ietf.org/html/rfc7748#section-4.1
      const x25519 = new curves.X25519();
      const v = x25519.g.toX().getY(true);

      const e = new BN('20ae19a1 b8a086b4 e01edd2c 7748d14c'
                     + '923d4d7e 6d7c61b2 29e9c5a2 7eced3d9', 16);

      assert(v.cmp(e) === 0);
      assert(x25519.g.validate());
    });

    it('should have basepoint for x448', () => {
      // https://tools.ietf.org/html/rfc7748#section-4.2
      const x448 = new curves.X448();
      const v = x448.g.toX().getY(false);

      const e = new BN('7d235d12 95f5b1f6 6c98ab6e 58326fce'
                     + 'cbae5d34 f55545d0 60f75dc2 8df3f6ed'
                     + 'b8027e23 46430d21 1312c4b1 50677af7'
                     + '6fd7223d 457b5b1a', 16);

      assert(v.cmp(e) === 0);
      assert(x448.g.validate());
    });

    it('should test birational equivalence (curve25519)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const edwardsG = ed25519.pointFromMont(x25519.g);
      const montG = x25519.pointFromEdwards(ed25519.g.randomize(rng));

      assert(x25519.isIsomorphic(ed25519));
      assert(edwardsG.eq(ed25519.g));
      assert(montG.eq(x25519.g));
    });

    it('should test 4-isogeny equivalence (curve448)', () => {
      const ed448 = new curves.ED448();
      const x448 = new curves.X448();
      const edwardsG = ed448.pointFromMont(x448.g);
      const montG = x448.pointFromEdwards(ed448.g.randomize(rng));

      assert(!x448.jinv().eq(ed448.jinv()));
      assert(x448.isIsogenous(ed448));
      assert(ed448.isIsogenous(x448));
      assert(edwardsG.eq(ed448.g));
      assert(montG.eq(x448.g));
    });

    it('should test birational equivalence (x1174)', () => {
      const ed1174 = new extra.ED1174();

      const params = [
        [null, false],
        [ed1174.one, true]
      ];

      for (const [b, invert] of params) {
        const x1174 = ed1174.toMont(b, invert);
        const edwardsG = ed1174.pointFromMont(x1174.g);
        const montG = x1174.pointFromEdwards(ed1174.g.randomize(rng));

        assert(x1174.jinv().eq(ed1174.jinv()));
        assert(x1174.isIsomorphic(ed1174, invert));
        assert(!ed1174.g.hasTorsion());
        assert(edwardsG.eq(ed1174.g));
        assert(montG.eq(x1174.g));

        sanityCheck(x1174);

        const k = ed1174.randomScalar(rng);
        const p0 = ed1174.g.mul(k);
        const p1 = x1174.g.mul(k);
        const r0 = ed1174.pointFromMont(p1);
        const r1 = x1174.pointFromEdwards(p0);

        assert(r0.eq(p0));
        assert(r1.eq(p1));
      }
    });

    it('should test birational equivalence (mont448)', () => {
      const ed448 = new curves.ED448();
      const mont448 = ed448.toMont(ed448.one, true);
      const edwardsG = ed448.pointFromMont(mont448.g);
      const montG = mont448.pointFromEdwards(ed448.g.randomize(rng));

      assert(mont448.jinv().eq(ed448.jinv()));
      assert(mont448.isIsomorphic(ed448, true));
      assert(!ed448.g.hasTorsion());
      assert(edwardsG.eq(ed448.g));
      assert(montG.eq(mont448.g));

      sanityCheck(mont448);

      const k = ed448.randomScalar(rng);
      const p0 = ed448.g.mul(k);
      const p1 = mont448.g.mul(k);
      const r0 = ed448.pointFromMont(p1);
      const r1 = mont448.pointFromEdwards(p0);

      assert(r0.eq(p0));
      assert(r1.eq(p1));

      const m = new curves.MONT448();

      assert(m.a.eq(mont448.a));
      assert(m.b.eq(mont448.b));
      assert(m.g.eq(mont448.g));
      assert(m._scale(ed448, true).eq(mont448._scale(ed448, true)));
    });

    it('should test birational equivalence (iso448)', () => {
      const ed448 = new curves.ISO448();
      const x448 = new curves.X448();
      const edwardsG = ed448.pointFromMont(x448.g);
      const montG = x448.pointFromEdwards(ed448.g.randomize(rng));

      assert(x448.jinv().eq(ed448.jinv()));
      assert(x448.isIsomorphic(ed448, true));
      assert(!ed448.g.hasTorsion());
      assert(edwardsG.eq(ed448.g));
      assert(montG.eq(x448.g));

      const k = ed448.randomScalar(rng);
      const p0 = ed448.g.mul(k);
      const p1 = x448.g.mul(k);
      const r0 = ed448.pointFromMont(p1);
      const r1 = x448.pointFromEdwards(p0);

      assert(r0.eq(p0));
      assert(r1.eq(p1));
    });

    it('should test 4-isogeny equivalence (twist448)', () => {
      const twist448 = new extra.TWIST448();

      // Sanity check.
      {
        const p1 = twist448.g;
        const p2 = p1.randomize(rng);

        for (const p of [p1, p2]) {
          assert(p.add(p).eq(p.dbl()));
          assert(p.dbl().validate());
        }

        sanityCheck(twist448);
      }

      const ed448 = new curves.ED448();
      const twistedG = twist448.pointFromEdwards(ed448.g.randomize(rng));
      const untwistedG = ed448.pointFromEdwards(twist448.g.randomize(rng));

      assert(!ed448.jinv().eq(twist448.jinv()));
      assert(twist448.isIsogenous(ed448));
      assert(ed448.isIsogenous(twist448));
      assert(!twist448.g.hasTorsion());
      assert(twistedG.eq(twist448.g));
      assert(untwistedG.eq(ed448.g));

      const k = twist448.randomScalar(rng);
      const p = twist448.g.mul(k);
      const q = ed448.g.mul(k);
      const r0 = twist448.pointFromEdwards(q);
      const r1 = ed448.pointFromEdwards(p);

      assert(r0.eq(p));
      assert(r1.eq(q));
    });

    it('should test birational equivalence (raw25519)', () => {
      const x25519 = new curves.X25519();
      const raw25519 = x25519.toEdwards();

      // Sanity check.
      {
        const p1 = raw25519.g;
        const p2 = p1.randomize(rng);

        for (const p of [p1, p2]) {
          assert(p.add(p).eq(p.dbl()));
          assert(p.dbl().validate());
        }

        sanityCheck(raw25519);
      }

      const edwardsG = raw25519.pointFromMont(x25519.g);
      const montG = x25519.pointFromEdwards(raw25519.g.randomize(rng));

      assert(x25519.jinv().eq(raw25519.jinv()));
      assert(x25519.isIsomorphic(raw25519));
      assert(!raw25519.g.hasTorsion());
      assert(edwardsG.eq(raw25519.g));
      assert(montG.eq(x25519.g));

      const k = raw25519.randomScalar(rng);
      const p0 = raw25519.g.mul(k);
      const p1 = x25519.g.mul(k);
      const r0 = raw25519.pointFromMont(p1);
      const r1 = x25519.pointFromEdwards(p0);

      assert(r0.eq(p0));
      assert(r1.eq(p1));
    });

    it('should hot potato a point across 4 curves', () => {
      const iso448 = new curves.ISO448();
      const x448 = new curves.X448();
      const ed448 = new curves.ED448();
      const twist448 = new curves.TWIST448();

      // Start at iso448.
      const g0 = iso448.g.randomize(rng);

      // Pass to curve448.
      const g1 = x448.pointFromEdwards(g0);

      // Pass to ed448.
      const g2 = ed448.pointFromMont(g1);

      // Pass to twist448.
      const g3 = twist448.pointFromEdwards(g2);

      // Should be the base point.
      assert(g0.eq(iso448.g));
      assert(g1.eq(x448.g));
      assert(g2.eq(ed448.g));
      assert(g3.eq(twist448.g));
    });

    it('should test wei25519 equivalence (1)', () => {
      const wei25519 = new extra.WEI25519();
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();

      assert(wei25519.jinv().eq(ed25519.jinv()));
      assert(x25519.jinv().eq(ed25519.jinv()));
      assert(x25519.isIsomorphic(wei25519));
      assert(x25519.isIsomorphic(ed25519));

      for (let i = 0; i < 10; i++) {
        const we = wei25519.g.mul(new BN(i));
        const mo = x25519.g.toX().mul(new BN(i));
        const ma = x25519.g.mul(new BN(i));
        const ed = ed25519.g.mul(new BN(i));
        const sign = ma.isOdd();

        assert(wei25519.pointFromShort(we).eq(we));
        assert(wei25519.pointFromMont(mo.toP(sign)).eq(we));
        assert(wei25519.pointFromMont(ma).eq(we));
        assert(wei25519.pointFromEdwards(ed).eq(we));

        assert(x25519.pointFromShort(we).toX().eq(mo));
        assert(x25519.pointFromMont(mo.toP(sign)).toX().eq(mo));
        assert(x25519.pointFromMont(ma).eq(ma));
        assert(x25519.pointFromEdwards(ed).toX().eq(mo));

        assert(ed25519.pointFromShort(we).eq(ed));
        assert(ed25519.pointFromMont(mo.toP(sign)).eq(ed));
        assert(ed25519.pointFromMont(ma).eq(ed));
        assert(ed25519.pointFromEdwards(ed).eq(ed));
      }
    });

    it('should test wei25519 equivalence (2)', () => {
      const ed25519 = new curves.ED25519();
      const ed = new curves.ED25519();
      const wei25519 = ed.toShort(ed.field(2));
      const x25519 = new curves.X25519();

      assert(wei25519.jinv().eq(ed25519.jinv()));
      assert(x25519.jinv().eq(ed25519.jinv()));
      assert(x25519.isIsomorphic(wei25519));
      assert(x25519.isIsomorphic(ed25519));

      for (let i = 0; i < 10; i++) {
        const we = wei25519.g.mul(new BN(i));
        const mo = x25519.g.toX().mul(new BN(i));
        const ma = x25519.g.mul(new BN(i));
        const ed = ed25519.g.mul(new BN(i));
        const sign = ma.isOdd();

        assert(wei25519.pointFromShort(we).eq(we));
        assert(wei25519.pointFromMont(mo.toP(sign)).eq(we));
        assert(wei25519.pointFromMont(ma).eq(we));
        assert(wei25519.pointFromEdwards(ed).eq(we));

        assert(x25519.pointFromShort(we).toX().eq(mo));
        assert(x25519.pointFromMont(mo.toP(sign)).toX().eq(mo));
        assert(x25519.pointFromMont(ma).eq(ma));
        assert(x25519.pointFromEdwards(ed).toX().eq(mo));

        assert(ed25519.pointFromShort(we).eq(ed));
        assert(ed25519.pointFromMont(mo.toP(sign)).eq(ed));
        assert(ed25519.pointFromMont(ma).eq(ed));
        assert(ed25519.pointFromEdwards(ed).eq(ed));
      }
    });

    it('should test wei25519 creation', () => {
      const wei25519 = new extra.WEI25519();
      const ed25519 = new curves.ED25519();
      const mont = ed25519.toMont(ed25519.one, false, true);
      const wei = mont.toShort();

      assert(wei.a.eq(wei25519.a));
      assert(wei.b.eq(wei25519.b));
      assert(wei.g.eq(wei25519.g));
      assert(wei.pointFromMont(mont.g).eq(wei.g));
      assert(mont.pointFromShort(wei.g).eq(mont.g));

      assert(wei25519.jinv().eq(ed25519.jinv()));
      assert(mont.jinv().eq(ed25519.jinv()));
      assert(wei.jinv().eq(ed25519.jinv()));
      assert(mont.isIsomorphic(wei));
      assert(mont.isIsomorphic(ed25519));
    });

    it('should test iso448 creation', () => {
      const x448 = new curves.X448();
      const iso448 = x448.toEdwards(x448.one, true, false);
      const expect = new curves.ISO448();

      assert(iso448.a.eq(expect.a));
      assert(iso448.d.eq(expect.d));
      assert(iso448.g.eq(expect.g));
      assert(iso448.pointFromMont(x448.g).eq(iso448.g));
      assert(x448.pointFromEdwards(iso448.g).eq(x448.g));
      assert(x448.isIsomorphic(iso448, true));
      assert(iso448.isIsomorphic(x448, true));
    });

    it('should test x25519 creation (1)', () => {
      const x25519 = new curves.X25519();
      const wei25519 = new extra.WEI25519();
      const mont = wei25519.toMont(null, null, false);

      assert(mont.a.eq(x25519.a));
      assert(mont.b.eq(x25519.b));
      assert(mont.g.eq(x25519.g));
      assert(mont.pointFromShort(wei25519.g).eq(mont.g));
      assert(wei25519.pointFromMont(mont.g).eq(wei25519.g));

      assert(wei25519.jinv().eq(x25519.jinv()));
      assert(mont.jinv().eq(x25519.jinv()));
      assert(mont.isIsomorphic(wei25519));
    });

    it('should test x25519 creation (2)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = ed25519.toMont();
      const wei25519 = x25519.toShort();
      const mont = wei25519.toMont(null, false);

      assert(mont.a.eq(x25519.a));
      assert(mont.b.eq(x25519.b));
      assert(mont.g.eq(x25519.g));
      assert(mont.pointFromShort(wei25519.g).eq(mont.g));
      assert(wei25519.pointFromMont(mont.g).eq(wei25519.g));

      assert(wei25519.jinv().eq(x25519.jinv()));
      assert(mont.jinv().eq(x25519.jinv()));
      assert(mont.isIsomorphic(wei25519));
    });

    it('should test x25519 creation (3)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = ed25519.toMont();
      const wei25519 = x25519.toShort();
      const mont = wei25519.toMont(null, false);

      assert(mont.a.eq(x25519.a));
      assert(mont.b.eq(x25519.b));
      assert(mont.g.eq(x25519.g));
      assert(mont.pointFromShort(wei25519.g).eq(mont.g));
      assert(wei25519.pointFromMont(mont.g).eq(wei25519.g));

      assert(wei25519.jinv().eq(x25519.jinv()));
      assert(mont.jinv().eq(x25519.jinv()));
      assert(mont.isIsomorphic(wei25519));
    });

    it('should test x25519 creation (4)', () => {
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();
      const mont = ed25519.toMont(ed25519.one, false, false);

      assert(mont.a.eq(x25519.a));
      assert(mont.b.eq(x25519.b));
      assert(mont.g.eq(x25519.g));
      assert(mont.pointFromEdwards(ed25519.g).eq(mont.g));
      assert(mont.pointFromEdwards(ed25519.g.randomize(rng)).eq(mont.g));
      assert(ed25519.pointFromMont(mont.g).eq(ed25519.g));

      assert(ed25519.jinv().eq(x25519.jinv()));
      assert(x25519.isIsomorphic(ed25519));
      assert(mont.isIsomorphic(ed25519));
    });

    it('should test ed25519 creation', () => {
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();
      const ed = x25519.toEdwards(x25519.one.redNeg(), false, false);

      assert(ed.a.eq(ed25519.a));
      assert(ed.d.eq(ed25519.d));
      assert(ed.g.eq(ed25519.g));
      assert(x25519.pointFromEdwards(ed.g).eq(x25519.g));
      assert(x25519.pointFromEdwards(ed.g.randomize(rng)).eq(x25519.g));
      assert(ed.pointFromMont(x25519.g).eq(ed.g));

      assert(ed25519.jinv().eq(x25519.jinv()));
      assert(ed.jinv().eq(x25519.jinv()));
      assert(x25519.isIsomorphic(ed25519));
      assert(x25519.isIsomorphic(ed));
    });

    it('should test short->edwards creation', () => {
      const expect = new curves.ED25519();
      const short = expect.toMont().toShort();
      const edwards = short.toEdwards(null, false);

      assert(edwards.a.eq(expect.a));
      assert(edwards.d.eq(expect.d));
      assert(edwards.g.eq(expect.g));
      assert(edwards.isIsomorphic(short));
      assert(short.isIsomorphic(edwards));
      assert(edwards.jinv().eq(short.jinv()));

      assert(edwards.pointFromShort(short.g).eq(edwards.g));
      assert(short.pointFromEdwards(edwards.g).eq(short.g));
      assert(short.pointFromEdwards(edwards.g.randomize(rng)).eq(short.g));
    });

    it('should test edwards->short creation', () => {
      const edwards = new curves.ED25519();
      const expect = edwards.toMont().toShort();
      const short = edwards.toShort();

      assert(short.a.eq(expect.a));
      assert(short.b.eq(expect.b));
      assert(short.g.eq(expect.g));
      assert(short.isIsomorphic(edwards));
      assert(edwards.isIsomorphic(short));
      assert(short.jinv().eq(edwards.jinv()));

      assert(edwards.pointFromShort(short.g).eq(edwards.g));
      assert(short.pointFromEdwards(edwards.g).eq(short.g));
      assert(short.pointFromEdwards(edwards.g.randomize(rng)).eq(short.g));

      const k = short.randomScalar(rng);
      const p0 = expect.g.mul(k);
      const p1 = edwards.g.mul(k);

      assert(edwards.pointFromShort(p0).eq(p1));
      assert(short.pointFromEdwards(p1).eq(p0));
    });

    it('should test wei25519 equivalence when B != 1', () => {
      const ed = new curves.ED25519();
      const mont = ed.toMont();
      const wei = mont.toShort();

      assert(wei.g.validate());
      assert(mont.b.cmp(mont.one) !== 0);

      assert(wei.jinv().eq(mont.jinv()));
      assert(ed.jinv().eq(mont.jinv()));
      assert(mont.isIsomorphic(wei));
      assert(mont.isIsomorphic(ed));

      const k = ed.randomScalar(rng);
      const p1 = ed.g.mul(k);
      const p2 = mont.g.mul(k);
      const p3 = wei.g.mul(k);

      // Edwards.
      assert(ed.pointFromMont(p2).eq(p1));

      // Mont.
      assert(mont.pointFromEdwards(p1).eq(p2));
      assert(mont.pointFromShort(p3).eq(p2));

      // Short.
      assert(wei.pointFromMont(p2).eq(p3));
    });

    it('should test elligator (exceptional case, r=1)', () => {
      const x448 = new curves.X448();
      const p = x448.pointFromUniform(x448.one);
      const r = x448.pointToUniform(p, 1);
      const q = x448.pointFromUniform(r);

      assert(p.validate());
      assert(p.eq(q));
    });

    it('should test elligator (exceptional case, denominator=0)', () => {
      const curve = new curves.X25519();
      const lhs = curve.a.redNeg();
      const rhs = curve.one;
      const i2 = curve.two.redInvert();
      const v = lhs.redMul(rhs.redFermat());
      const v2 = v.redSqr();
      const v3 = v2.redMul(v);
      const f = v3.redAdd(curve.a.redMul(v2)).redIAdd(curve.b.redMul(v));
      const e = f.redPow(curve.p.subn(1).iushrn(1));
      const l = curve.one.redSub(e).redMul(curve.a).redMul(i2);
      const x = e.redMul(v).redISub(l);

      const p = curve.pointFromX(x, false);
      const r = curve.pointToUniform(p, 1);
      const q = curve.pointFromUniform(r);

      assert(p.validate());
      assert(p.eq(q));
    });

    it('should test elligator against DJB\'s formula', () => {
      // Map:
      //
      //   f(a) = a^((q - 1) / 2)
      //   v = -A / (1 + u * r^2)
      //   e = f(v^3 + A * v^2 + B * v)
      //   x = e * v - (1 - e) * A / 2
      //   y = -e * sqrt(x^3 + A * x^2 + B * x)
      const curve = new curves.X25519();
      const i2 = curve.two.redInvert();
      const u = curve.randomField(rng);
      const lhs = curve.a.redNeg();
      const rhs = curve.one.redAdd(curve.z.redMul(u.redSqr()));
      const v = lhs.redMul(rhs.redFermat());
      const f = curve.solveY2(v);
      const e = f.redPow(curve.p.subn(1).iushrn(1));
      const l = curve.one.redSub(e).redMul(curve.a).redMul(i2);
      const x = e.redMul(v).redISub(l);
      const y0 = curve.solveY(x);

      if (y0.redIsHigh())
        y0.redINeg();

      const y = e.redNeg().redMul(y0);
      const p = curve.point(x, y);
      const q = curve.pointFromUniform(u);

      assert(p.validate());
      assert(p.eq(q) || p.eq(q.neg()));

      const r = curve.pointToUniform(p, y.redIsLow() | 0);

      assert(r.eq(u) || r.eq(u.redNeg()));
    });

    it('should test elligator (mont)', () => {
      const x25519 = new curves.X25519();
      const x448 = new curves.X448();

      for (const curve of [x25519, x448]) {
        const u1 = curve.randomField(rng);
        const p1 = curve.pointFromUniform(u1);
        const u2 = curve.pointToUniform(p1, 0);
        const p2 = curve.pointFromUniform(u2);
        const u3 = curve.pointToUniform(p2, 1);
        const p3 = curve.pointFromUniform(u3);

        assert(p1.validate());
        assert(p1.eq(p2));
        assert(p2.eq(p3));
      }
    });

    it('should test elligator', () => {
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();
      const x448 = new curves.X448();
      const iso448 = new curves.ISO448();
      const mont448 = new curves.MONT448();
      const ed448 = new curves.ED448();

      for (const [x, curve] of [[x25519, ed25519],
                                [x448, iso448],
                                [mont448, ed448]]) {
        const u1 = curve.randomField(rng);
        const p1 = curve.pointFromUniform(u1, x);
        const u2 = curve.pointToUniform(p1, 0, x);
        const p2 = curve.pointFromUniform(u2, x);
        const u3 = curve.pointToUniform(p2, 1, x);
        const p3 = curve.pointFromUniform(u3, x);

        assert(p1.validate());
        assert(p1.eq(p2));
        assert(p2.eq(p3));
      }
    });

    it('should test elligator (ed448)', () => {
      const x = new curves.X448();
      const curve = new curves.ED448();

      // 4-isogeny map can't handle torsion points.
      let u, p;
      do {
        u = x.randomField(rng);
        p = x.pointFromUniform(u);
      } while (p.toX().hasTorsion());

      const u1 = u.forceRed(curve.red);
      const p1 = curve.pointFromUniform(u1, x);
      const u2 = curve.pointToUniform(p1, 0, x);
      const p2 = curve.pointFromUniform(u2, x);
      const u3 = curve.pointToUniform(p2, 1, x);
      const p3 = curve.pointFromUniform(u3, x);

      assert(p1.validate());
      assert(p1.eq(p2));
      assert(p2.eq(p3));
    });

    it('should test elligator key generation', () => {
      const x = new curves.X25519();
      const curve = new curves.ED25519();

      // Censorship-resistant key sharing.
      let k, p, bytes;

      for (;;) {
        k = curve.randomScalar(rng);
        p = curve.g.mul(k);

        // Fails on about half the keys.
        let u;
        try {
          u = curve.pointToUniform(p, rng.randomInt() & 3, x);
        } catch (e) {
          continue;
        }

        // Encode uniform bytes.
        bytes = curve.encodeUniform(u, rng.randomInt());

        break;
      }

      // Run elligator on the other side.
      const u = curve.decodeUniform(bytes);
      const q = curve.pointFromUniform(u, x);

      assert(p.eq(q));
    });

    it('should test elligator 1', () => {
      const curve = new extra.ED1174();

      {
        // c = 2 / s^2
        // r = c + 1 / c
        const {s, si, i2, two} = curve;
        const c = two.redDiv(s.redSqr());
        const ci = c.redInvert();
        const r = c.redAdd(c.redInvert());
        const ci2 = c.redSqr().redInvert();

        // c = 2 / s^2 = 2 * (1 / s)^2
        // 1 / c = s^2 / 2
        // 1 / c^2 = (1 / c)^2
        const c_ = si.redSqr().redIMuln(2);
        const ci_ = s.redSqr().redMul(i2);
        const r_ = c_.redAdd(ci_);
        const ci2_ = ci_.redSqr();

        assert(c_.eq(c));
        assert(ci_.eq(ci));
        assert(r_.eq(r));
        assert(ci2_.eq(ci2));
      }

      const r1 = curve.field(1337);
      const p1 = curve._elligator1(r1);

      assert(p1.validate());

      assert.deepStrictEqual(p1.toJSON(), [
        '0751dcb3ac43e56dd98495eb18dd99d601652d6303006f53d1629f3422cf9c55',
        '029122c5febb9231a42535ff7dc960d33cc0845ca61864fa657ae4587f0c4f87'
      ]);

      const r2 = curve._invert1(p1.randomize(rng), 1);

      assert.strictEqual(r2.fromRed().toNumber(), 1337);

      const p3 = curve.pointFromJSON([
        '02b407fb3fdae072411ca31ec7baa1278be5fd5d2300a52fdcd212d7712d2a27',
        '02aadd80383c1a4c807dac923e0e0f3f17680513b1c4cde2fadc21480dcb2785'
      ]);

      assert(p3.validate());

      assert.throws(() => curve._invert1(p3, 0), {
        message: 'X is not a square mod P.'
      });

      // If x = 2 * s * (c - 1) * f(c) / r
      // then ((y - 1) / 2 * (y + 1)) * r = -2.
      // Has 2-torsion.
      const p4 = curve.pointFromJSON([
        '05e19eca85e361b2b0cfb2903df32a222a8f1ed6404d1355f3db39ea2b68874e',
        '073d2571a3f4137c416f9acad9f974d6ebb700a7841ba0e655a5fd3cb5c43c2b'
      ]);

      const u4 = curve._invert1(p4.randomize(rng), 0);

      assert(u4.eq(curve.zero));
      assert(curve._elligator1(u4).eq(p4));

      // y + 1 = 0
      const p5 = curve.point(curve.zero, curve.one.redNeg());
      const u5 = curve._invert1(p5.randomize(rng), 0);

      assert(curve._elligator1(u5).eq(p5));

      // solve(r * ((1 - t) / (1 + t)) == -(1 + ((1 - t) / (1 + t)))^2, t)
      // solve(r * ((1 - t) / (1 + t)) + (1 + ((1 - t) / (1 + t)))^2 == 0, t)
      // t = +-sqrt(4 / r + 1)

      // +sqrt(4 / r + 1)
      const u6 = curve.field(
        'db45a143a82731b3f79da0767a2ad5795d14ca751205e86477dc24f45539a8',
        16);

      // -sqrt(4 / r + 1)
      const u7 = curve.field(
        '0724ba5ebc57d8ce4c08625f8985d52a86a2eb358aedfa179b8823db0baac64f',
        16);

      assert(curve._elligator1(u6).validate());
      assert(curve._elligator1(u7).validate());

      for (let i = 0; i < 100; i++) {
        const r1 = curve.field(i);
        const p1 = curve._elligator1(r1);
        const r2 = curve._invert1(p1.randomize(rng), i);
        const p2 = curve._elligator1(r2);

        assert(curve._elligator1(r1.redNeg()).eq(p1));
        assert(curve._elligator1(r2.redNeg()).eq(p2));

        assert(!p1.isInfinity());
        assert(p1.validate());
        assert(p1.eq(p2));
      }
    });

    it('should test elligator 2 (api)', () => {
      const eddsa = new EDDSA('ED1174', null, null, SHA512);

      const u1 = Buffer.from(
        '3905000000000000000000000000000000000000000000000000000000000000',
        'hex');

      const pub1 = eddsa.publicKeyFromUniform(u1);
      const u2 = eddsa.publicKeyToUniform(pub1, rng.randomInt() & 3);
      const pub2 = eddsa.publicKeyFromUniform(u2);

      assert.bufferEqual(pub1,
        '70b0f380a71b859a059be759a37b3fc32c9f368200cada5bce6d44013add6e85');
      assert.bufferEqual(pub2, pub1);

      const pub3 = eddsa.publicKeyFromHash(rng.randomBytes(64), true);

      assert(!eddsa.publicKeyHasTorsion(pub3));
      assert(eddsa.publicKeyVerify(pub3));
    });

    it('should test elligator hash', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const ed448 = new curves.ED448();
      const x448 = new curves.X448();

      for (const [edwards, mont] of [[ed25519, x25519], [ed448, x448]]) {
        const size = mont.fieldSize * 2;

        for (let i = 0; i < 10; i++) {
          const u = rng.randomBytes(size);
          const p0 = edwards.pointFromHash(u, true, mont);
          const p1 = mont.pointFromEdwards(p0);
          const p2 = mont.pointFromHash(u, true);

          assert(p1.validate());
          assert(p2.validate());
          assert(p1.eq(p2));
        }
      }
    });

    it('should test elligator hash (api)', () => {
      const ecdh = new ECDH('M511');
      const pub = ecdh.publicKeyFromHash(rng.randomBytes(128), true);

      assert(!ecdh.publicKeyHasTorsion(pub));
      assert(ecdh.publicKeyVerify(pub));
    });

    it('should do elligator 2 with B != 1 (mont)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const native = ed25519.toMont();

      // Some sanity checks.
      const x0 = native.g.x.redMul(native.bi);
      const y0 = native.g.y.redMul(native.bi);

      assert(native.b0.eq(native.b.redSqr().redInvert()));
      assert(native._solveY0(x0).eq(y0.redSqr()));

      const u0 = native.randomField(rng);
      const p0 = native.pointFromUniform(u0);
      const p1 = x25519.pointFromUniform(u0.forceRed(x25519.red));

      assert(p0.validate());
      assert(p1.validate());
      assert(p0.getX().eq(p1.getX()));

      const u1 = native.pointToUniform(p0, 0);
      const p2 = native.pointFromUniform(u1);

      assert(p2.validate());
      assert(p2.eq(p0));
    });

    it('should do elligator 2 with B != 1 (edwards)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const native = ed25519.toMont();

      const u0 = ed25519.randomField(rng);
      const p0 = ed25519.pointFromUniform(u0, native);
      const p1 = ed25519.pointFromUniform(u0, x25519);

      assert(p0.validate());
      assert(p1.validate());
      assert(p0.eq(p1) || p0.eq(p1.neg()));

      const u1 = ed25519.pointToUniform(p0, 0, native);
      const p2 = ed25519.pointFromUniform(u1, native);

      assert(p2.validate());
      assert(p2.eq(p0));
    });

    it('should do elligator 2 on fabricated twisted edwards curve', () => {
      const mont = new extra.M383();
      const twisted = mont.toEdwards(mont.one.redNeg());

      checkCurve(twisted);

      const u0 = twisted.randomField(rng);
      const p0 = twisted.pointFromUniform(u0, mont);
      const u1 = twisted.pointToUniform(p0, 0, mont);
      const p1 = twisted.pointFromUniform(u1, mont);

      assert(p1.eq(p0));
    });

    it('should test simple shallue-woestijne-ulas algorithm', () => {
      const curve = new curves.P256();
      const u = curve.randomField(rng);
      const p = curve.pointFromUniform(u);

      assert(p.validate());

      {
        // -b * (1 / a) == -b / a
        const a = curve.b.redNeg().redMul(curve.ai);
        const b = curve.b.redNeg().redDiv(curve.a);

        assert(a.eq(b));
      }

      {
        // b * (1 / z) * (1 / a) == b / (z * a)
        const a = curve.b.redMul(curve.zi).redMul(curve.ai);
        const b = curve.b.redDiv(curve.z.redMul(curve.a));

        assert(a.eq(b));
      }
    });

    it('should test shallue-van de woestijne encoding', () => {
      const curve = new curves.SECP256K1();
      const u = curve.randomField(rng);
      const p = curve.pointFromUniform(u);

      const mod = (x, y) => {
        let r = x % y;

        if (r < 0)
          r += y;

        return r;
      };

      const svdw = (t) => {
        // f(a) = a^((q - 1) / 2)
        // w = sqrt(-3) * t / (1 + b + t^2)
        // x1 = (-1 + sqrt(-3)) / 2 - t * w
        // x2 = -1 - x1
        // x3 = 1 + 1 / w^2
        // alpha = f(r1^2 * (x1^3 + b))
        // beta = f(r2^2 * (x2^3 + b))
        // i = [(alpha - 1) * beta mod 3] + 1
        // P = (xi, f(r3^2 * t) * sqrt(xi^3 + b))
        const e = curve.p.subn(2);
        const u = curve.three.redNeg().redSqrt();
        const v = curve.one.redAdd(curve.b).redIAdd(t.redSqr());
        const w = u.redMul(t).redMul(v.redPow(e));
        const tw = t.redMul(w);
        const x1 = curve.one.redNeg().redIAdd(u).redMul(curve.i2).redISub(tw);
        const x2 = curve.one.redNeg().redISub(x1);
        const x3 = curve.one.redAdd(w.redSqr().redPow(e));
        const alpha = curve.solveY2(x1).redLegendre() | 1;
        const beta = curve.solveY2(x2).redLegendre() | 1;
        const i = mod((alpha - 1) * beta, 3);
        const x = [x1, x2, x3][i];
        const y = curve.solveY(x);

        if (y.redIsOdd() !== t.redIsOdd())
          y.redINeg();

        return curve.point(x, y);
      };

      assert(p.validate());

      const q = svdw(u);

      assert(p.eq(q));

      {
        // sqrt(-3 * z^2)
        const c = curve.z.redSqr().redIMuln(-3).redSqrt();

        assert(curve.c.eq(c));
      }

      {
        // (1 / 3) * (1 / z)^2 == 1 / (3 * z^2)
        const a = curve.i3.redMul(curve.zi.redSqr());
        const b = curve.z.redSqr().redIMuln(3).redInvert();

        assert(a.eq(b));
      }

      {
        // (1 / 3) * (1 / z)^2 == 1 / (3 * z^2)
        const z = curve.randomField(rng);
        const zi = z.redInvert();
        const a = curve.i3.redMul(zi.redSqr());
        const b = z.redSqr().redIMuln(3).redInvert();

        assert(a.eq(b));
      }
    });

    it('should invert shallue-van de woestijne', () => {
      const curve = new curves.SECP256K1();
      const p = curve._svdw(curve.zero);

      assert(p.validate());

      for (let i = 0; i < 3; i++) {
        let p, u;

        for (;;) {
          p = curve.randomPoint(rng);

          try {
            u = curve._svdwi(p, rng.randomInt());
          } catch (e) {
            continue;
          }

          break;
        }

        const q = curve._svdw(u);

        assert(p.eq(q));
      }
    });

    it('should invert sswu', () => {
      const curve = new curves.P256();
      const p = curve._sswu(curve.zero);

      assert(p.validate());

      for (let i = 0; i < 3; i++) {
        let p, u;

        for (;;) {
          p = curve.randomPoint(rng);

          try {
            u = curve._sswui(p, rng.randomInt());
          } catch (e) {
            continue;
          }

          break;
        }

        const q = curve._sswu(u);

        assert(p.eq(q));
      }
    });

    it('should invert elligator for weierstrass', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();

      for (const curve of [p256, secp256k1]) {
        let p, u;

        for (;;) {
          p = curve.randomPoint(rng);

          try {
            u = curve.pointToUniform(p, rng.randomInt() & 3);
          } catch (e) {
            assert(e.message === 'Invalid point.');
            continue;
          }

          break;
        }

        const q = curve.pointFromUniform(u);

        assert(p.eq(q));
      }
    });

    it('should invert elligator squared', () => {
      const p192 = new curves.P192();
      const p224 = new curves.P224();
      const p256 = new curves.P256();
      const p384 = new curves.P384();
      const p521 = new curves.P521();
      const secp192k1 = new extra.SECP192K1();
      const secp224k1 = new extra.SECP224K1();
      const secp256k1 = new curves.SECP256K1();
      const x25519 = new curves.X25519();
      const x448 = new curves.X448();
      const frp256v1 = new extra.FRP256V1();
      const anomalous = new extra.ANOMALOUS();
      const bn2254 = new extra.BN2254();
      const wei25519 = new extra.WEI25519();
      const ed1174 = new extra.ED1174();
      const ed41417 = new extra.ED41417();
      const curve383187 = new extra.CURVE383187();
      const m221 = new extra.M221();
      const e222 = new extra.E222();
      const m383 = new extra.M383();
      const e382 = new extra.E382();
      const m511 = new extra.M511();
      const e521 = new extra.E521();
      const mdc = new extra.MDC();
      const iso256k1 = new extra.ISO256K1();
      const curve13318 = new extra.CURVE13318();

      for (const curve of [p192,
                           p224,
                           p256,
                           p384,
                           p521,
                           secp192k1,
                           secp224k1,
                           secp256k1,
                           x25519,
                           x448,
                           frp256v1,
                           anomalous,
                           bn2254,
                           wei25519,
                           ed1174,
                           ed41417,
                           curve383187,
                           m221,
                           e222,
                           m383,
                           e382,
                           m511,
                           e521,
                           mdc,
                           iso256k1,
                           curve13318]) {
        const p = curve.randomPoint(rng);
        const u = curve.pointToHash(p, 0, rng);
        const q = curve.pointFromHash(u);

        assert(p.eq(q));
      }
    });

    it('should invert elligator squared (elligator 2)', () => {
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();
      const x448 = new curves.X448();
      const ed448 = new curves.ED448();
      const iso448 = new curves.ISO448();
      const mont448 = new curves.MONT448();
      const jubjub = new extra.JUBJUB();
      const mubmub = jubjub.toMont(jubjub.one);

      for (const [x, curve] of [[x25519, ed25519],
                                [x448, ed448],
                                [x448, iso448],
                                [mont448, ed448],
                                [mubmub, jubjub]]) {
        const p = curve.randomPoint(rng);
        const u = curve.pointToHash(p, 0, rng, x);
        const q = curve.pointFromHash(u, false, x);

        assert(p.eq(q));
      }
    });

    it('should invert SSWU elligator squared on Ed448', () => {
      const edwards = new curves.ED448();
      const mont = edwards.toMont(edwards.one, true);
      const wei = mont.toShort();
      const zai = wei.a.redMuln(-3).redInvert();

      // Satisfies jacobi(z) == -1
      // and jacobi(g(b / (z * a))) == 1.
      wei.z = wei.field(-3);
      wei.zi = wei.z.redInvert();

      assert(!wei.z.redIsSquare());
      assert(wei.solveY2(wei.b.redMul(zai)).redIsSquare());

      // Insane trick.
      const u = rng.randomBytes(112);
      const p = wei.pointFromHash(u, false);
      const v = wei.pointToHash(p, 0, rng);
      const q = wei.pointFromHash(v, false);

      const p0 = mont.pointFromShort(p);
      const p1 = edwards.pointFromMont(p0);

      const q0 = mont.pointFromShort(q);
      const q1 = edwards.pointFromMont(q0);

      assert(p.eq(q));
      assert(p0.eq(q0));
      assert(p1.eq(q1));
    });

    it('should test unified addition (secp256k1)', () => {
      // Cases:
      //
      //   M == 0, R == 0: X1 != X2, Y1 == -Y2
      //   M == 0, R != 0: X1 == X2, Y1 == -Y2
      //   M != 0, R == 0: X1 != X2, Y1 == Y2
      const curve = new curves.SECP256K1();

      const vectors = [
        // G + R
        [
          [
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ],
          [
            '9474d13ad9314a46210de4b7e846bc2324fc0638cc77f88a84ebf6c283c704f4 ',
            '161e854a5015fd39b45c32c1897b1cd423ffdd4a4dbad2b09fb56351cf7e2c4e'
          ]
        ],
        // R + R
        [
          [
            'c7f5c3fe72dd8e0c7c71efc5ce1611115419e5a6cf5d645ee30f3603fca08a29',
            '58fb0e0348a4bee8b4e8cd253f6429135fc7c556a0c5af87d6ca6194166a6790'
          ],
          [
            'd63f7ed3c5ef0f3caeae2d2baf3d3636a12a993e0a72fe81d1beb0589dcc7687',
            '383d0b172413048a5deff4ffca1b183645fc6f2c82e881c790fdb2fb178834d6'
          ]
        ],
        // M = 0, R = 0
        [
          [
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ],
          [
            'bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb',
            'b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777'
          ]
        ],
        [
          [
            'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
            'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
          ],
          [
            '3ba398aa59edee676a580508b285c92cbad4d45f9bd24c9b0e635ac1b7ec5dbb',
            '30798050e8b0bdd98c5eb9413f03be1f2ef7d1b591d8eefed3cf12b5305838cf'
          ]
        ],
        [
          [
            'eef57567a6beda8b2307bdb2e2d64649ca3da5e99b0e6e600b258ed7fc5c6432',
            '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
          ],
          [
            'ff429d7bb1932077e2f99ebfc8da744fcace96ed151e77f6935836a51584c204',
            '89322a0eac42d6d43a3f55bae08f2b523bc0f0496bb338a2157af40688fef615'
          ]
        ],
        // M = 0, R != 0
        [
          [
            '89cef607c2cfe639107741129288f9508df3537abe429af16fc42a86b684b0d2',
            'aa2ecd65992c94e9cc8e4013ac0f3d08b588d7a4b3b25e8612642c5498e9ab2b'
          ],
          [
            '89cef607c2cfe639107741129288f9508df3537abe429af16fc42a86b684b0d2',
            '55d1329a66d36b163371bfec53f0c2f74a77285b4c4da179ed9bd3aa67165104'
          ]
        ],
        [
          [
            '2a6603cea614a0034057d7bfc56949743a2e3c15d1a4cfb7920cb9652d0bfbe8',
            'cc36607d45f9aed4bbe93d212456ffdd481337da39c141c8d82a5db283679c40'
          ],
          [
            '2a6603cea614a0034057d7bfc56949743a2e3c15d1a4cfb7920cb9652d0bfbe8',
            '33c99f82ba06512b4416c2dedba90022b7ecc825c63ebe3727d5a24c7c985fef'
          ]
        ],
        // M != 0, R = 0
        [
          [
            'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
            'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
          ],
          [
            '3ba398aa59edee676a580508b285c92cbad4d45f9bd24c9b0e635ac1b7ec5dbb',
            'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
          ]
        ],
        [
          [
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ],
          [
            'bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ]
        ],
        [
          [
            'eef57567a6beda8b2307bdb2e2d64649ca3da5e99b0e6e600b258ed7fc5c6432',
            '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
          ],
          [
            'ff429d7bb1932077e2f99ebfc8da744fcace96ed151e77f6935836a51584c204',
            '76cdd5f153bd292bc5c0aa451f70d4adc43f0fb6944cc75dea850bf87701061a'
          ]
        ]
      ];

      for (const [json1, json2] of vectors) {
        const o = curve.point();
        const p = curve.pointFromJSON(json1);
        const q = curve.pointFromJSON(json2);
        const r = p.add(q);

        const oj = curve.jpoint();
        const pj = p.toJ().randomize(rng);
        const qj = q.toJ().scale(pj.z);
        const rj = pj.add(qj);

        // Sanity check for affine.
        assert(r.toJ().eq(rj));

        assert(p.add(o).eq(p));
        assert(o.add(p).eq(p));
        assert(o.add(o).eq(o));

        // Sanity check for jacobian.
        assert(rj.toP().eq(r));

        assert(pj.add(oj).eq(pj));
        assert(oj.add(pj).eq(pj));
        assert(oj.add(oj).eq(oj));

        // Sanity check for jacobian (mixed).
        assert(pj.add(o).eq(pj));
        assert(oj.add(p).eq(pj));
        assert(oj.add(o).eq(oj));

        // Affine.
        assert(p.add(q).eq(r));
        assert(p.add(p).eq(p.dbl()));
        assert(q.add(q).eq(q.dbl()));
        assert(p.dbl().eq(p.dbl()));
        assert(q.dbl().eq(q.dbl()));

        assert(p.add(o).eq(p));
        assert(o.add(p).eq(p));
        assert(o.add(o).eq(o));

        // Jacobian.
        assert(pj.add(qj).eq(rj));
        assert(pj.add(pj).eq(pj.dbl()));
        assert(qj.add(qj).eq(qj.dbl()));
        assert(pj.dbl().eq(pj.dbl()));
        assert(qj.dbl().eq(qj.dbl()));

        assert(pj.add(oj).eq(pj));
        assert(oj.add(pj).eq(pj));
        assert(oj.add(oj).eq(oj));

        // Jacobian (mixed).
        assert(pj.add(q).eq(rj));
        assert(pj.add(p).eq(pj.dbl()));
        assert(qj.add(q).eq(qj.dbl()));

        assert(pj.add(o).eq(pj));
        assert(oj.add(p).eq(pj));
        assert(oj.add(o).eq(oj));
      }
    });

    it('should test doubling when infinity (dbl)', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const bp256 = new curves.BRAINPOOLP256();
      const ed25519 = new curves.ED25519();
      const ed448 = new curves.ED448();

      for (const curve of [p256, secp256k1, bp256, ed25519, ed448]) {
        const p = curve.jpoint().clone();
        const q = p.dbl();

        assert(q.isInfinity());
        assert(q.eq(p));

        if (curve.type === 'edwards') {
          assert(q.x.eq(curve.zero));
          assert(q.y.eq(q.z));
        } else {
          assert(q.x.eq(curve.one));
          assert(q.y.eq(curve.one));
          assert(q.z.eq(curve.zero));
        }
      }
    });

    it('should test doubling when infinity (dbl)', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const bp256 = new curves.BRAINPOOLP256();

      for (const curve of [p256, secp256k1, bp256]) {
        const x = curve.randomField(rng);
        const y = curve.randomField(rng);
        const z = curve.zero.clone();
        const p = curve.jpoint(x, y, z);
        const q = p.dbl();

        assert(q.isInfinity());
        assert(q.eq(curve.jpoint()));
        assert(q.z.eq(curve.zero));
      }
    });

    it('should test doubling when y=0 (dbl)', () => {
      const p256 = new curves.P256();
      const secp256k1 = new curves.SECP256K1();
      const bp256 = new curves.BRAINPOOLP256();

      for (const curve of [p256, secp256k1, bp256]) {
        const x = curve.randomField(rng);
        const y = curve.zero.clone();
        const z = curve.randomField(rng);
        const p = curve.jpoint(x, y, z);
        const q = p.dbl();

        assert(q.isInfinity());
        assert(q.eq(curve.jpoint()));
        assert(q.z.eq(curve.zero));
      }
    });

    it('should test doubling when y=0 (dbl, valid 2-torsion)', () => {
      // Pick a curve with 2-torsion.
      const curve = new curves.WEI25519();
      const i3 = curve.three.redInvert();
      const x = curve.field(486662).redMul(i3);
      const y = curve.zero.clone();
      const z = curve.one.clone();
      const p = curve.jpoint(x, y, z).randomize(rng);
      const q = p.dbl();

      assert(p.validate());
      assert(q.isInfinity());
      assert(q.eq(curve.jpoint()));
      assert(q.x.eq(curve.one));
      assert(q.y.eq(curve.one));
      assert(q.z.eq(curve.zero));
    });

    it('should test adding when lambda=0', () => {
      const curve = new curves.SECP256K1();

      const p = curve.pointFromJSON([
        'f96e09c5f26fa15c38fd52282087c96a53411a75d4a65a9faed9c1113955b28f',
        'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
      ]);

      const q = curve.pointFromJSON([
        '3ba398aa59edee676a580508b285c92cbad4d45f9bd24c9b0e635ac1b7ec5dbb',
        'cf867faf174f422673a146bec0fc41e0d1082e4a6e2711012c30ed49cfa7c360'
      ]);

      const r = p.toJ().add(q).toP();

      assert(p.add(q).eq(r));
    });

    it('should test doubling when lambda=0', () => {
      const curve = new curves.P521();
      const p = curve.pointFromX(curve.field(1), false);
      const q = p.toJ().dbl().toP();

      assert(p.dbl().eq(q));
    });

    it('should test edwards addition', () => {
      const ed25519 = new curves.ED25519();
      const ed448 = new curves.ED448();

      for (const curve of [ed25519, ed448]) {
        const p = curve.randomPoint(rng);
        const q = curve.randomPoint(rng);

        // Z1 != 1, Z2 != 1
        const r = p.randomize(rng).add(q.randomize(rng)).normalize();

        // Z1 = 1, Z2 != 1
        assert(p.add(q.randomize(rng)).eq(r));

        // Z1 != 1, Z2 = 1
        assert(p.randomize(rng).add(q).eq(r));

        // Z1 = 1, Z2 = 1
        assert(p.add(q).eq(r));
      }
    });

    it('should test unified addition', () => {
      const p256 = new curves.P256();
      const bp256 = new curves.BRAINPOOLP256();
      const secp256k1 = new curves.SECP256K1();
      const wei25519 = new extra.WEI25519();
      const x25519 = new curves.X25519();
      const ed25519 = new curves.ED25519();
      const ed448 = new curves.ED448();

      for (const curve of [p256,
                           bp256,
                           secp256k1,
                           wei25519,
                           x25519,
                           ed25519,
                           ed448]) {
        const p = curve.randomPoint(rng);
        const q = curve.randomPoint(rng);
        const o = curve.point();
        const pj = p.randomize(rng);
        const qj = q.randomize(rng);
        const oj = o.randomize(rng);

        assert(p.add(q).eq(p.add(q)));
        assert(q.add(p).eq(p.add(q)));
        assert(p.add(p).eq(p.dbl()));
        assert(q.add(q).eq(q.dbl()));
        assert(p.dbl().eq(p.dbl()));
        assert(q.dbl().eq(q.dbl()));
        assert(p.add(p.neg()).eq(o));
        assert(q.add(q.neg()).eq(o));
        assert(p.add(o).eq(p));
        assert(o.add(p).eq(p));
        assert(q.add(o).eq(q));
        assert(o.add(q).eq(q));
        assert(o.add(o).eq(o));

        assert(pj.add(qj).eq(pj.add(qj)));
        assert(qj.add(pj).eq(pj.add(qj)));
        assert(pj.add(pj).eq(pj.dbl()));
        assert(qj.add(qj).eq(qj.dbl()));
        assert(pj.dbl().eq(pj.dbl()));
        assert(qj.dbl().eq(qj.dbl()));
        assert(pj.add(pj.neg()).eq(oj));
        assert(qj.add(qj.neg()).eq(oj));
        assert(pj.add(oj).eq(pj));
        assert(oj.add(pj).eq(pj));
        assert(qj.add(oj).eq(qj));
        assert(oj.add(qj).eq(qj));
        assert(oj.add(oj).eq(oj));
      }

      {
        const [x] = wei25519._findRS();
        const p = wei25519.pointFromX(x);
        const j = p.randomize(rng);

        assert(p.add(p).isInfinity());
        assert(p.dbl().isInfinity());
        assert(j.add(j).isInfinity());
        assert(j.dbl().isInfinity());
      }

      {
        const p = x25519.pointFromX(x25519.zero);

        assert(p.add(p).isInfinity());
        assert(p.dbl().isInfinity());
      }
    });

    it('should match multiplications (mont-affine)', () => {
      const curve = new curves.X25519();

      for (let i = 0; i < 2; i++) {
        const k = curve.randomScalar(rng);
        const g = curve.g;
        const p = g.mul(k);
        const q = curve.g.mul(k);

        assert(q.eq(p));
        assert(g.mul(k).eq(p));
        assert(g.mulBlind(k).eq(p));
        assert(g.mulBlind(k).eq(p));
        assert(g.mulBlind(k, rng).eq(p));
        assert(g.mulBlind(k, rng).eq(p));

        {
          const m = curve.n.muln(17);
          const p1 = g.mul(k.mul(m));
          const p2 = g.mul(k.mul(m));
          const p3 = g.mulBlind(k.mul(m));
          const p4 = g.mul(k.mul(m).imod(curve.n));
          const p5 = g.mul(k.mul(m).imod(curve.n));
          const p6 = g.mulBlind(k.mul(m).imod(curve.n));
          const p7 = g.mulBlind(k.mul(m).imod(curve.n), rng);
          const p8 = g.mulBlind(k.mul(m).imod(curve.n));
          const p9 = g.mulBlind(k.mul(m).imod(curve.n), rng);

          assert(p1.eq(p2));
          assert(p2.eq(p3));
          assert(p3.eq(p4));
          assert(p4.eq(p5));
          assert(p5.eq(p6));
          assert(p6.eq(p7));
          assert(p8.eq(p9));
        }

        {
          const p1 = g.mul(k.neg());
          const p2 = g.mul(k.neg());
          const p3 = g.mulBlind(k.neg());
          const p4 = g.mul(k.neg().imod(curve.n));
          const p5 = g.mul(k.neg().imod(curve.n));
          const p6 = g.mulBlind(k.neg().imod(curve.n));
          const p7 = g.mulBlind(k.neg().imod(curve.n), rng);
          const p8 = g.mulBlind(k.neg().imod(curve.n));
          const p9 = g.mulBlind(k.neg().imod(curve.n), rng);

          assert(p1.eq(p2));
          assert(p2.eq(p3));
          assert(p3.eq(p4));
          assert(p4.eq(p5));
          assert(p5.eq(p6));
          assert(p6.eq(p7));
          assert(p8.eq(p9));
        }

        curve.precompute(rng);
      }
    });

    it('should match multiplications (mont-x)', () => {
      const curve = new curves.X25519();
      const k = curve.randomScalar(rng);
      const g = curve.g.toX();
      const p = g.mul(k);
      const q = curve.g.mul(k);

      assert(q.toX().eq(p));
      assert(g.mul(k).eq(p));
      assert(g.mulBlind(k).eq(p));
      assert(g.mulBlind(k).eq(p));
      assert(g.mulBlind(k, rng).eq(p));
      assert(g.mulBlind(k, rng).eq(p));

      {
        const m = curve.n.muln(17);
        const p1 = g.mul(k.mul(m));
        const p2 = g.mul(k.mul(m));
        const p3 = g.mulBlind(k.mul(m));
        const p4 = g.mul(k.mul(m).imod(curve.n));
        const p5 = g.mul(k.mul(m).imod(curve.n));
        const p6 = g.mulBlind(k.mul(m).imod(curve.n));
        const p7 = g.mulBlind(k.mul(m).imod(curve.n), rng);
        const p8 = g.mulBlind(k.mul(m).imod(curve.n));
        const p9 = g.mulBlind(k.mul(m).imod(curve.n), rng);

        assert(p1.eq(p2));
        assert(p2.eq(p3));
        assert(p3.eq(p4));
        assert(p4.eq(p5));
        assert(p5.eq(p6));
        assert(p6.eq(p7));
        assert(p8.eq(p9));
      }

      {
        const p1 = g.mul(k.neg());
        const p2 = g.mul(k.neg());
        const p3 = g.mulBlind(k.neg());
        const p4 = g.mul(k.neg().imod(curve.n));
        const p5 = g.mul(k.neg().imod(curve.n));
        const p6 = g.mulBlind(k.neg().imod(curve.n));
        const p7 = g.mulBlind(k.neg().imod(curve.n), rng);
        const p8 = g.mulBlind(k.neg().imod(curve.n));
        const p9 = g.mulBlind(k.neg().imod(curve.n), rng);

        assert(p1.eq(p2));
        assert(p2.eq(p3));
        assert(p3.eq(p4));
        assert(p4.eq(p5));
        assert(p5.eq(p6));
        assert(p6.eq(p7));
        assert(p8.eq(p9));
      }
    });

    it('should test montgomery multiplication and conversion (1)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const g = x25519.randomPoint(rng).toX();
      const k = x25519.decodeClamped(rng.randomBytes(x25519.scalarSize));
      const p = g.mul(k);
      const eg = ed25519.pointFromMont(g.toP());
      const ep = ed25519.pointFromMont(p.toP());
      const r = eg.mul(k);

      assert(ep.eq(r) || ep.eq(r.neg()));
    });

    it('should test montgomery multiplication and conversion (2)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const g = x25519.randomPoint(rng);
      const k = x25519.randomScalar(rng);
      const p = g.mul(k);
      const eg = ed25519.pointFromMont(g);
      const ep = ed25519.pointFromMont(p);
      const r = eg.mul(k);

      assert(ep.eq(r));
    });

    it('should test montgomery multiplication and conversion (3)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const k = x25519.decodeClamped(rng.randomBytes(x25519.scalarSize));
      const p = x25519.g.toX().mul(k);
      const q = ed25519.pointFromMont(p.toP());
      const r = ed25519.g.mul(k);

      assert(q.eq(r) || q.eq(r.neg()));
    });

    it('should test montgomery multiplication and conversion (4)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const k = x25519.randomScalar(rng);
      const p = x25519.g.mul(k);
      const q = ed25519.pointFromMont(p);
      const r = ed25519.g.mul(k);

      assert(q.eq(r));
    });

    it('should test mont torsion multiplication with blinding', () => {
      const curve = new curves.X25519();
      const torsion = [curve.point()];

      curve.precompute(rng);

      const small = [
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0000000000000000000000000000000000000000000000000000000000000001',
        '00b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebe0',
        '57119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c5f'
      ];

      for (const json of small) {
        const x = curve.field(json, 16);
        const p = curve.pointFromX(x, false);
        const q = p.neg();

        torsion.push(p);

        if (!q.eq(p))
          torsion.push(q);
      }

      for (const g of torsion) {
        const k = curve.randomScalar(rng);
        const p1 = g.mul(k);
        const p2 = g.mulBlind(k, rng);

        assert(p1.eq(p2));
      }

      for (const t of torsion) {
        const k = curve.randomScalar(rng);
        const g = curve.randomPoint(rng).add(t);
        const p1 = g.mul(k);
        const p2 = g.mulBlind(k, rng);

        assert(p1.eq(p2));
      }
    });

    it('should test edwards torsion multiplication with blinding', () => {
      const curve = new curves.ED25519();
      const torsion = [];

      curve.precompute(rng);

      const small = [
        [
          '0000000000000000000000000000000000000000000000000000000000000000',
          '0000000000000000000000000000000000000000000000000000000000000001'
        ],
        [
          '0000000000000000000000000000000000000000000000000000000000000000',
          '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec'
        ],
        [
          '547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d',
          '0000000000000000000000000000000000000000000000000000000000000000'
        ],
        [
          '2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0',
          '0000000000000000000000000000000000000000000000000000000000000000'
        ],
        [
          '602a465ff9c6b5d716cc66cdc721b544a3e6c38fec1a1dc7215eb9b93aba2ea3',
          '7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'
        ],
        [
          '1fd5b9a006394a28e933993238de4abb5c193c7013e5e238dea14646c545d14a',
          '7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'
        ],
        [
          '602a465ff9c6b5d716cc66cdc721b544a3e6c38fec1a1dc7215eb9b93aba2ea3',
          '05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826'
        ],
        [
          '1fd5b9a006394a28e933993238de4abb5c193c7013e5e238dea14646c545d14a',
          '05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826'
        ]
      ];

      for (const json of small)
        torsion.push(curve.pointFromJSON(json));

      for (const g of torsion) {
        const k = curve.randomScalar(rng);
        const p1 = g.mul(k);
        const p2 = g.mulBlind(k, rng);

        assert(p1.eq(p2));
      }

      for (const t of torsion) {
        const k = curve.randomScalar(rng);
        const g = curve.randomPoint(rng).add(t);
        const p1 = g.mul(k);
        const p2 = g.mulBlind(k, rng);

        assert(p1.eq(p2));
      }
    });

    it('should hit exceptional case when a is not square (twisted)', () => {
      const x448 = new curves.X448();
      const curve = x448.toEdwards();
      const {zero, one} = curve;

      assert(!curve.a.redIsSquare());
      assert(curve.d.redIsSquare());

      // P*h = -Q*h.
      // P has 2-torsion (0, -1).
      const p = curve.pointFromJSON([
        ['25dd1f9d4f2450ed175c9a39ea7d9165698a1d4b97fc449f6bbc8a63',
         'eafb0a2d2438ed7a248d441072f07aca20cb6d0730676f81c5617a5e'],
        ['bdbfe8f1c1721151df0f46d228f3657390b320db1fdce2b05cf66c1a',
         '0eee98f5732b591475e7ffeb0b0779f47ca7d2fdb96939b18cae56cd']
      ]);

      // Q has 4-torsion.
      //
      // On "normal" twisted curves, the 4-torsion point is:
      //
      //   (+-sqrt(1 / a), 0)
      //
      // Because `a` is non-square, our 4-torsion point is:
      //
      //   (+-sqrt(1 / d), oo)
      //
      // So, our 4-torsion point is _not_ representable.
      //
      // This causes exceptional cases in the addition formula.
      const q = curve.pointFromJSON([
        ['12fd957ff7b992df9b1c1bbba80a5d8861290cc1d8949972c507bdb8',
         '7d31da593ff5f3ea6434eabeab8c48df8ac17fb695aaa325bda51407'],
        ['5ad639725654d8853c543ab6d0831ac0e6483f8c81a308665167acc9',
         '4e3236f24d5f1c36afc64fff5ad5ddf5cc1ff3ca1d6ddb15d3d79a4f']
      ]);

      assert(p.validate());
      assert(q.validate());

      // Affine twisted addition formula:
      //
      //   x3 = (x1 * y2 + y1 * x2) / (1 + d * x1 * x2 * y1 * y2)
      //   y3 = (y1 * y2 - a * x1 * x2) / (1 - d * x1 * x2 * y1 * y2)
      const x1x2 = p.x.redMul(q.x);
      const y1y2 = p.y.redMul(q.y);
      const x1y2 = p.x.redMul(q.y);
      const y1x2 = p.y.redMul(q.x);
      const dx1x2y1y2 = curve._mulD(x1x2).redMul(y1y2);

      const xn = x1y2.redIAdd(y1x2);
      const xd = one.redAdd(dx1x2y1y2);
      const yn = y1y2.redISub(curve._mulA(x1x2));
      const yd = one.redSub(dx1x2y1y2);
      const d = xd.redMul(yd);

      let x = null;
      let y = null;

      if (!d.isZero()) {
        const l = d.redInvert();

        x = xn.redMul(l.redMul(yd));
        y = yn.redMul(l.redMul(xd));
      }

      assert(x == null);
      assert(y == null);
      assert(yd.isZero());

      // Cannot add, as the result would
      // be our unrepresentable 4-torsion
      // point.
      assert.throws(() => p.add(q), {
        message: 'Invalid point.'
      });

      // Likewise.
      assert.throws(() => q.mul(curve.n), {
        message: 'Invalid point.'
      });

      // Should be 2-torsion.
      const t2 = curve.point(zero, one.redNeg());
      assert(p.mul(curve.n).eq(t2));

      // P + -P = O
      assert(p.mulH().add(q.mulH()).isInfinity());
    });

    it('should test x equality', () => {
      const secp256k1 = new curves.SECP256K1();
      const p256 = new curves.P256();

      for (const curve of [secp256k1, p256]) {
        const p = curve.randomPoint(rng);
        const x = p.getX();
        const r = p.randomize(rng);

        assert(p.eqX(x));
        assert(p.eqR(x));
        assert(r.eqX(x));
        assert(r.eqR(x));

        x.iaddn(1);

        assert(!p.eqX(x));
        assert(!p.eqR(x));
        assert(!r.eqX(x));
        assert(!r.eqR(x));
      }
    });

    it('should test fuzzy x equality', () => {
      const secp256k1 = new curves.SECP256K1();
      const p256 = new curves.P256();

      for (const curve of [secp256k1, p256]) {
        let p;

        for (;;) {
          const x = BN.random(rng, curve.n, curve.p);
          const s = BN.random(rng, 0, 2);

          try {
            p = curve.pointFromX(x, s.isOdd());
          } catch (e) {
            continue;
          }

          break;
        }

        const x = p.getX().imod(curve.n);

        assert(x.cmp(p.getX()) < 0);

        assert(p.eqR(x));
        assert(!p.eqR(x.subn(1)));
        assert(!p.eqR(x.addn(1)));

        const r = p.randomize(rng);

        assert(r.eqR(x));
        assert(!r.eqR(x.subn(1)));
        assert(!r.eqR(x.addn(1)));
      }
    });

    it('should test jacobian equality', () => {
      const curve = new curves.SECP256K1();
      const p1 = curve.randomPoint(rng).randomize(rng);
      const p2 = p1.clone();
      const p3 = curve.randomPoint(rng).scale(p1.z);
      const p4 = p1.clone().normalize().randomize(rng);

      assert(p1 !== p2);
      assert(p1.z.eq(p2.z));
      assert(p1.eq(p2));

      assert(p1 !== p3);
      assert(p1.z.eq(p3.z));
      assert(!p1.eq(p3));

      assert(p1 !== p4);
      assert(!p1.z.eq(p4.z));
      assert(p1.eq(p4));
    });

    it('should test quad y', () => {
      const curve = new curves.SECP256K1();

      for (let i = 0; i < 100; i++) {
        const p = curve.randomPoint(rng);
        const q = p.normalize().y.redJacobi() === 1;
        const r = p.randomize(rng);

        assert.strictEqual(p.isSquare(), q);
        assert.strictEqual(r.isSquare(), q);
      }
    });

    it('should test validation', () => {
      const p256 = new curves.P256();
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const ed448 = new curves.ED448();

      for (const curve of [p256, ed25519, x25519, ed448]) {
        const p = curve.randomPoint(rng);

        assert(p.validate());
        assert(p.toJ().validate());
        assert(p.randomize(rng).validate());
      }
    });

    it('should test equality', () => {
      const p256 = new curves.P256();
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const ed448 = new curves.ED448();

      for (const curve of [p256, ed25519, x25519, ed448]) {
        const p = curve.randomPoint(rng).randomize(rng);
        const q = p.randomize(rng);
        const o = curve.jpoint();

        assert(p.eq(q));
        assert(!p.eq(o));
      }
    });

    it('should test repeated doubling', () => {
      const curve = new curves.BRAINPOOLP256();
      const p = curve.randomPoint(rng);
      const j = p.randomize(rng);

      assert(j.dblp(0).eq(j));
      assert(j.dblp(1).eq(j.dbl()));
      assert(j.dblp(2).eq(j.dbl().dbl()));
      assert(j.dblp(3).eq(j.dbl().dbl().dbl()));

      assert(j.dblp(0).toP().eq(p.dblp(0)));
      assert(j.dblp(1).toP().eq(p.dblp(1)));
      assert(j.dblp(2).toP().eq(p.dblp(2)));
      assert(j.dblp(3).toP().eq(p.dblp(3)));
    });

    it('should test projective validation (mont)', () => {
      const curve = new curves.X25519();

      for (let i = 0; i < 100; i++) {
        const x = curve.randomField(rng);
        const valid = curve.solveY2(x).redJacobi() >= 0;
        const p = curve.xpoint(x).randomize(rng);

        assert.strictEqual(p.validate(), valid);
      }
    });

    it('should mul by cofactor (1)', () => {
      const curve = new curves.ED25519();
      const t = curve.pointFromY(curve.one.redNeg());
      const p0 = curve.randomPoint(rng);
      const p1 = p0.add(t);
      const p2 = p1.mul(curve.h);
      const p3 = p1.mul(curve.h);
      const p4 = p1.mulBlind(curve.h);
      const p5 = p1.mulH();

      assert(p2.eq(p3));
      assert(p3.eq(p4));
      assert(p4.eq(p5));
      assert(p1.mulH().divH().eq(p0));
    });

    it('should mul by cofactor (2)', () => {
      const curve = new curves.X25519();
      const t = curve.pointFromX(curve.zero);
      const p0 = curve.randomPoint(rng);
      const p1 = p0.add(t);
      const p2 = p1.mul(curve.h);
      const p3 = p1.mul(curve.h);
      const p4 = p1.mulBlind(curve.h);
      const p5 = p1.mulH();

      assert(p2.eq(p3));
      assert(p3.eq(p4));
      assert(p4.eq(p5));
      assert(p1.mulH().divH().eq(p0));
    });

    it('should mul by cofactor (3)', () => {
      const curve = new curves.ED25519();
      const k = curve.randomScalar(rng);
      const e = k.mul(curve.h).mod(curve.n);

      assert(curve.mulH(k).eq(e));
    });

    it('should check for small order points (ed25519)', () => {
      const curve = new curves.ED25519();

      // Note about order 8:
      // `x` must satisfy: a * d * x^4 - 2 * a * x^2 + 1 = 0
      const small = [
        // (0, 1) (order 1)
        [
          '0000000000000000000000000000000000000000000000000000000000000000',
          '0000000000000000000000000000000000000000000000000000000000000001'
        ],
        // (0, -1) (order 2)
        [
          '0000000000000000000000000000000000000000000000000000000000000000',
          '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec'
        ],
        // (-sqrt(1 / a), 0) (order 4)
        [
          '547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d',
          '0000000000000000000000000000000000000000000000000000000000000000'
        ],
        // (sqrt(1 / a), 0) (order 4)
        [
          '2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0',
          '0000000000000000000000000000000000000000000000000000000000000000'
        ],
        // (-sqrt((1 / d) - sqrt(a^2 - a * d) / (a * d)), sqrt(a) * x) (order 8)
        [
          '602a465ff9c6b5d716cc66cdc721b544a3e6c38fec1a1dc7215eb9b93aba2ea3',
          '7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'
        ],
        // (sqrt((1 / d) - sqrt(a^2 - a * d) / (a * d)), sqrt(a) * x) (order 8)
        [
          '1fd5b9a006394a28e933993238de4abb5c193c7013e5e238dea14646c545d14a',
          '7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'
        ],
        // (-sqrt((1 / d) - sqrt(a^2 - a * d) / (a * d)), -sqrt(a) * x) (order 8)
        [
          '602a465ff9c6b5d716cc66cdc721b544a3e6c38fec1a1dc7215eb9b93aba2ea3',
          '05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826'
        ],
        // (sqrt((1 / d) - sqrt(a^2 - a * d) / (a * d)), -sqrt(a) * x) (order 8)
        [
          '1fd5b9a006394a28e933993238de4abb5c193c7013e5e238dea14646c545d14a',
          '05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826'
        ]
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasTorsion());

      // This is why edwards curves suck.
      for (let i = 1; i < small.length; i++) {
        // P = point of small order
        const p = curve.pointFromJSON(small[i]);

        // Q = G + P
        const q = curve.g.add(p);

        assert(p.validate());
        assert(!p.isInfinity());
        assert(q.validate());
        assert(!q.isInfinity());

        // P * H == O
        assert(p.isSmall());

        // P * N != O
        assert(p.hasTorsion());

        // Q * H != O
        assert(!q.isSmall());

        // Q * N != O
        assert(q.hasTorsion());

        // Q * H == G * H
        assert(q.mulH().eq(curve.g.mulH()));

        // Check multiples.
        assert(p.mul(new BN(2 * 8)).eq(curve.point()));
        assert(q.mul(new BN(2 * 8)).eq(curve.g.mul(new BN(2 * 8))));
        assert(q.mul(new BN(2 * 8)).eq(q.mul(new BN(2)).mul(new BN(8))));

        // Test batching logic.
        const e = curve.randomScalar(rng);
        const a = curve.randomScalar(rng);
        const ea = e.mul(a).imod(curve.n);
        const eah = ea.mul(curve.h);

        assert(q.mul(eah).eq(curve.g.mul(eah)));
        assert(q.mul(eah).eq(curve.g.mul(ea).mulH()));
        assert(q.mul(eah).eq(curve.g.mulH().mul(ea)));
        assert(q.mul(eah).eq(q.mulH().mul(ea)));

        // Test any order-related computations.
        assert(p.mulBlind(curve.h).isInfinity());
        assert(!p.mulBlind(curve.n).isInfinity());
        assert(!q.mulBlind(curve.h).isInfinity());
        assert(!q.mulBlind(curve.n).isInfinity());
        assert(q.mulBlind(curve.h).eq(curve.g.mulH()));
      }
    });

    it('should check for small order points (x25519)', () => {
      const curve = new curves.X25519();

      // Full list from: https://cr.yp.to/ecdh.html
      //
      // See also:
      // https://github.com/jedisct1/libsodium/blob/cec56d8/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L17
      // https://eprint.iacr.org/2017/806.pdf
      const small = [
        // 0 (order 1 & 2)
        '0000000000000000000000000000000000000000000000000000000000000000',
        // 1 (order 4)
        '0000000000000000000000000000000000000000000000000000000000000001',
        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        '00b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebe0',
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        '57119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c5f',
        // p - 1 (invalid)
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec',
        // p (order 1 & 2)
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
        // p + 1 (order 4)
        '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee',
        // p + 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        '80b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebcd',
        // p + 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        'd7119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c4c',
        // 2 * p - 1 (invalid)
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd9',
        // 2 * p (order 1 & 2)
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda',
        // 2 * p + 1 (order 4)
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdb'
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasTorsion());

      for (let i = 0; i < small.length; i++) {
        const x = curve.field(small[i], 16);
        const p = curve.xpoint(x);

        if (i === 4 || i === 9) {
          // Note that `p - 1`, and `2 * p - 1`
          // do not satisfy the curve equation.
          // `a - 2` is not a quadratic residue.
          assert(p.x.cmp(curve.one.redNeg()) === 0);
        } else {
          assert(p.validate());
        }

        assert(!p.isInfinity());
        assert(p.isSmall());
        assert(p.hasTorsion());
      }
    });

    it('should check for small order points (ed448)', () => {
      const curve = new curves.ED448();

      // https://hyperelliptic.org/EFD/g1p/auto-edwards.html
      // - The neutral element of the curve is the point (0, c).
      // - The point (0, -c) has order 2.
      // - The points (c, 0) and (-c, 0) have order 4.
      const small = [
        // 0, c (order 1)
        [
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000'],
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000001']
        ],
        // 0, -c (order 2, rejected)
        [
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000'],
          ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
           'fffffffffffffffffffffffffffffffffffffffffffffffffffffffe']
        ],
        // c, 0 (order 4)
        [
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000001'],
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000']
        ],
        // -c, 0 (order 4)
        [
          ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
           'fffffffffffffffffffffffffffffffffffffffffffffffffffffffe'],
          ['00000000000000000000000000000000000000000000000000000000',
           '00000000000000000000000000000000000000000000000000000000']
        ]
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasTorsion());

      // This is why edwards curves suck.
      for (let i = 1; i < small.length; i++) {
        // P = point of small order
        const p = curve.pointFromJSON(small[i]);

        // Q = G + P
        const q = curve.g.add(p);

        assert(p.validate());
        assert(!p.isInfinity());
        assert(q.validate());
        assert(!q.isInfinity());

        // P * H == O
        assert(p.isSmall());

        // P * N != O
        assert(p.hasTorsion());

        // Q * H != O
        assert(!q.isSmall());

        // Q * N != O
        assert(q.hasTorsion());

        // Q * H == G * H
        assert(q.mulH().eq(curve.g.mulH()));

        // Check multiples.
        assert(p.mul(new BN(2 * 4)).eq(curve.point()));
        assert(q.mul(new BN(2 * 4)).eq(curve.g.mul(new BN(2 * 4))));
        assert(q.mul(new BN(2 * 4)).eq(q.mul(new BN(2)).mul(new BN(4))));

        // Test batching logic.
        const e = curve.randomScalar(rng);
        const a = curve.randomScalar(rng);
        const ea = e.mul(a).imod(curve.n);
        const eah = ea.mul(curve.h);

        assert(q.mul(eah).eq(curve.g.mul(eah)));
        assert(q.mul(eah).eq(curve.g.mul(ea).mulH()));
        assert(q.mul(eah).eq(curve.g.mulH().mul(ea)));
        assert(q.mul(eah).eq(q.mulH().mul(ea)));

        // Test any order-related computations.
        assert(p.mulBlind(curve.h).isInfinity());
        assert(!p.mulBlind(curve.n).isInfinity());
        assert(!q.mulBlind(curve.h).isInfinity());
        assert(!q.mulBlind(curve.n).isInfinity());
        assert(q.mulBlind(curve.h).eq(curve.g.mulH()));
      }
    });

    it('should check for small order points (x448)', () => {
      const curve = new curves.X448();

      const small = [
        // 0 (order 1)
        ['00000000000000000000000000000000000000000000000000000000',
         '00000000000000000000000000000000000000000000000000000000'],
        // 1 (order 2, invalid, rejected)
        ['00000000000000000000000000000000000000000000000000000000',
         '00000000000000000000000000000000000000000000000000000001'],
        // p - 1 (order 4)
        ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
         'fffffffffffffffffffffffffffffffffffffffffffffffffffffffe'],
        // p (order 1)
        ['fffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
         'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
        // p + 1 (order, invalid, rejected)
        ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
         '00000000000000000000000000000000000000000000000000000000']
      ];

      assert(!curve.g.isSmall());
      assert(!curve.g.hasTorsion());

      for (let i = 0; i < small.length; i++) {
        const x = curve.field(small[i].join(''), 16);
        const p = curve.xpoint(x);

        if (i === 1 || i === 4) {
          // Note that `1`, and `p + 1`
          // do not satisfy the curve equation.
          // `a + 2` is not a quadratic residue.
          assert(p.x.cmp(curve.one) === 0);
        } else {
          assert(p.validate());
        }

        assert(!p.isInfinity());
        assert(p.isSmall());
        assert(p.hasTorsion());
      }
    });

    it('should compute inverse sqrt properly', () => {
      const ed25519 = new curves.ED25519();
      const ed448 = new curves.ED448();
      const e521 = new extra.E521();
      const ed1174 = new extra.ED1174();

      for (const curve of [ed25519, ed448, e521, ed1174]) {
        for (let i = 0; i < 10; i++) {
          const k = curve.randomScalar(rng);
          const p = curve.g.mul(k).normalize();
          const x1 = curve.solveX2(p.y).redSqrt();
          const x2 = curve.solveX(p.y);
          const y1 = curve.solveY2(p.x).redSqrt();
          const y2 = curve.solveY(p.x);

          if (x1.redIsOdd() !== p.x.redIsOdd())
            x1.redINeg();

          if (x2.redIsOdd() !== p.x.redIsOdd())
            x2.redINeg();

          if (y1.redIsOdd() !== p.y.redIsOdd())
            y1.redINeg();

          if (y2.redIsOdd() !== p.y.redIsOdd())
            y2.redINeg();

          assert(x1.eq(p.x));
          assert(x2.eq(p.x));
          assert(y1.eq(p.y));
          assert(y2.eq(p.y));
        }
      }
    });

    it('should handle x25519<->ed25519 edge cases', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const {a, bi, two} = x25519;
      const c = ed25519._scale(x25519, false);

      // Should be +sqrt(-(A + 2) / B).
      const e = a.redAdd(two).redINeg().redMul(bi).redSqrt();

      if (e.redIsOdd())
        e.redINeg();

      assert(c.eq(e));

      // (0, 1) -> O
      {
        const p = ed25519.point(ed25519.zero, ed25519.one);
        const q = x25519.point();

        assert(p.validate() && q.validate());
        assert(x25519.pointFromEdwards(p).eq(q));
        assert(ed25519.pointFromMont(q).eq(p));
      }

      // (0, -1) -> (0, 0)
      {
        const p = ed25519.point(ed25519.zero, ed25519.one.redNeg());
        const q = x25519.point(x25519.zero, x25519.zero);

        assert(p.validate() && q.validate());
        assert(x25519.pointFromEdwards(p).eq(q));
        assert(ed25519.pointFromMont(q).eq(p));
      }

      // (1 / +-sqrt(a), 0) -> (1, +-sqrt((A + 2) / B))
      {
        const x = ed25519.a.redSqrt().redInvert();
        const y = ed25519.zero;

        const u = x25519.one;
        const v = a.redAdd(two).redMul(bi).redSqrt().redINeg();

        const p = ed25519.point(x, y);
        const q = x25519.point(u, v);

        assert(p.validate() && q.validate());
        assert(x25519.pointFromEdwards(p).eq(q));
        assert(ed25519.pointFromMont(q).eq(p));
        assert(x25519.pointFromEdwards(p.neg()).eq(q.neg()));
        assert(ed25519.pointFromMont(q.neg()).eq(p.neg()));
      }
    });

    it('should handle x448<->iso448 edge cases', () => {
      const ed448 = new curves.ISO448();
      const x448 = new curves.X448();
      const {a, bi, two} = x448;
      const c = ed448._scale(x448, true);

      // Should be +sqrt((A - 2) / B).
      const e = a.redSub(two).redMul(bi).redSqrt();

      if (e.redIsOdd())
        e.redINeg();

      assert(c.eq(e));

      // (0, 1) -> O
      {
        const p = ed448.point(ed448.zero, ed448.one);
        const q = x448.point();

        assert(p.validate() && q.validate());
        assert(x448.pointFromEdwards(p).eq(q));
        assert(ed448.pointFromMont(q).eq(p));
      }

      // (0, -1) -> (0, 0)
      {
        const p = ed448.point(ed448.zero, ed448.one.redNeg());
        const q = x448.point(x448.zero, x448.zero);

        assert(p.validate() && q.validate());
        assert(x448.pointFromEdwards(p).eq(q));
        assert(ed448.pointFromMont(q).eq(p));
      }

      // (+-1, 0) -> (-1, +-sqrt((A - 2) / B))
      {
        const p = ed448.point(ed448.one, ed448.zero);
        const q = x448.point(x448.one.redNeg(), e.redNeg());

        assert(p.validate() && q.validate());
        assert(x448.pointFromEdwards(p).eq(q));
        assert(ed448.pointFromMont(q).eq(p));
        assert(x448.pointFromEdwards(p.neg()).eq(q.neg()));
        assert(ed448.pointFromMont(q.neg()).eq(p.neg()));
      }

      // (-1, +-sqrt((A - 2) / B)) -> (+-sqrt(1 / d), oo)
      // c = 2 / +-sqrt(B * (a - d))
      // x = c * u / v
      //   = c * -1 / +-sqrt((A - 2) / B)
      //   = +-sqrt(1 / d)
      {
        const ed448 = x448.toEdwards();
        const a = x448.field(ed448.a);
        const d = x448.field(ed448.d);
        const p = x448.pointFromX(x448.one.redNeg(), false);
        const c = x448._scale(ed448, false);
        const ce = x448.two.redDiv(x448.b.redMul(a.redSub(d)).redSqrt());
        const x = c.redMul(p.x).redDiv(p.y);
        const xe = ed448.d.redInvert().redSqrt();

        assert(ed448.d.redIsSquare());
        assert(p.y.eq(e));
        assert(c.eq(ce));
        assert(x.eq(xe));
      }
    });

    it('should handle x448<->ed448 edge cases', () => {
      const ed448 = new curves.ED448();
      const x448 = new curves.X448();

      // (0, 1) -> O
      {
        const p = ed448.point(ed448.zero, ed448.one);
        const q = x448.point();

        assert(p.validate() && q.validate());
        assert(x448.pointFromEdwards(p).eq(q));
      }

      // (0, -1) -> (0, 0)
      {
        const p = ed448.point(ed448.zero, ed448.one.redNeg());
        const q = x448.point(x448.zero, x448.zero);

        assert(p.validate() && q.validate());
        assert(x448.pointFromEdwards(p).eq(q));
      }

      // (+-1, 0) -> (0, 0)
      {
        const p = ed448.point(ed448.one, ed448.zero);
        const q = x448.point(x448.zero, x448.zero);

        assert(p.validate() && q.validate());
        assert(x448.pointFromEdwards(p).eq(q));
        assert(x448.pointFromEdwards(p.neg()).eq(q.neg()));
      }

      // Other way:
      // O -> (0, 1)
      {
        const p = x448.point();
        const q = ed448.point(ed448.zero, ed448.one);

        assert(p.validate() && q.validate());
        assert(ed448.pointFromMont(p).eq(q));
      }

      // (0, 0) -> (0, -1) -> (0, 1)
      {
        const p = x448.point(x448.zero, x448.zero);
        const q = ed448.point(ed448.zero, ed448.one);

        assert(p.validate() && q.validate());
        assert(ed448.pointFromMont(p).eq(q));
      }

      // (-1, +-sqrt((A - 2) / B)) -> (+-1, 0) -> (0, 1)
      {
        const {a, bi, two} = x448;
        const v = a.redSub(two).redMul(bi).redSqrt();
        const p = x448.point(x448.one.redNeg(), v);
        const q = ed448.point(ed448.zero, ed448.one);

        assert(p.validate() && q.validate());
        assert(ed448.pointFromMont(p).eq(q));
        assert(ed448.pointFromMont(p.neg()).eq(q));
      }
    });

    it('should handle short->edwards edge case (1)', () => {
      // ((5 * d - a) / 12, y) -> ((d - a) / (4 * y), oo)
      // ((5 * d - a) / 12, y) -> (+-sqrt(1 / d), oo)
      // y = (d - a) / 4 * +-sqrt(d)
      const edwards = new extra.TWIST448();
      const short = edwards.toShort();
      const {a, d} = edwards;
      const x0 = d.redMuln(5).redISub(a).redDivn(12);
      const y0 = d.redSub(a).redDivn(4).redMul(d.redSqrt().redINeg());
      const p = short.pointFromX(short.field(x0));
      const px = edwards.field(p.x);
      const py = edwards.field(p.y);

      assert(px.eq(x0));
      assert(py.eq(y0));

      const ex = d.redSub(a).redDiv(py.redMuln(4));

      assert.throws(() => edwards.pointFromX(ex), {
        message: 'X is not a square mod P.'
      });

      const d5 = d.redMuln(5);
      const x6 = px.redMuln(6);
      const x12 = px.redMuln(12);
      const xx = x6.redSub(a).redISub(d);
      const xz = py.redMuln(6);
      const yz = x12.redAdd(a).redISub(d5);

      assert(xx.redDiv(xz).eq(ex));
      assert(yz.isZero());
    });

    it('should handle short->edwards edge case (2)', () => {
      // ((5 * a - d) / 12, (a - d) / 4 * +-sqrt(a)) -> (+-sqrt(1 / a), 0)
      const edwards = new curves.ED25519();
      const short = edwards.toShort();
      const {a, d} = edwards;
      const x0 = a.redMuln(5).redISub(d).redDivn(12);
      const y0 = a.redSub(d).redDivn(4).redMul(a.redSqrt().redINeg());
      const p = short.pointFromX(short.field(x0));

      assert(p.x.eq(x0));
      assert(p.y.eq(y0));

      const ex = a.redInvert().redSqrt();
      const q = edwards.pointFromShort(p).normalize();

      assert(q.x.eq(ex));
      assert(q.y.isZero());
    });

    it('should find r and s values', () => {
      const edwards = new curves.ED25519();
      const mont = edwards.toMont();
      const short = mont.toShort();
      const [r] = short._findRS();

      assert(!mont.b.eq(mont.one));
      assert(r.eq(edwards.ad6));
      assert(r.eq(mont.a3.redMul(mont.bi)));
    });

    it('should test short isomorphism (1)', () => {
      const e = new curves.ED25519();
      const m = e.toMont(e.one);
      const w1 = m.toShort();
      const w2 = w1.toShort(w1.field(2), true);

      // https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html#further-dom-parms
      assert(w2.a.fromRed().toJSON(), '02');
      assert(w2.b.fromRed().toJSON(),
        '1ac1da05b55bc14633bd39e47f94302ef19843dcf669916f6a5dfd0165538cd1');
      assert(w2.g.x.fromRed().toJSON(),
        '17cfeac378aed661318e8634582275b6d9ad4def072ea1935ee3c4e87a940ffa');
      assert(w2.g.y.fromRed().toJSON(),
        '0c08a952c55dfad62c4f13f1a8f68dcadc5c331d297a37b6f0d7fdcc51e16b4d');

      assert(w1.isIsomorphic(w2));
      assert(w2.isIsomorphic(w1));
      assert(w1.pointFromShort(w2.g).eq(w1.g));
      assert(w2.pointFromShort(w1.g).eq(w2.g));
    });

    it('should test short isomorphism (2)', () => {
      const e = new curves.ED25519();
      const w1 = e.toShort();
      const w2 = w1.toShort(w1.field(2), true);

      // https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html#further-dom-parms
      assert(w2.a.fromRed().toJSON(), '02');
      assert(w2.b.fromRed().toJSON(),
        '1ac1da05b55bc14633bd39e47f94302ef19843dcf669916f6a5dfd0165538cd1');
      assert(w2.g.x.fromRed().toJSON(),
        '17cfeac378aed661318e8634582275b6d9ad4def072ea1935ee3c4e87a940ffa');
      assert(w2.g.y.fromRed().toJSON(),
        '0c08a952c55dfad62c4f13f1a8f68dcadc5c331d297a37b6f0d7fdcc51e16b4d');

      assert(w1.isIsomorphic(w2));
      assert(w2.isIsomorphic(w1));
      assert(w1.pointFromShort(w2.g).eq(w1.g));
      assert(w2.pointFromShort(w1.g).eq(w2.g));
    });

    it('should test short isomorphism (3)', () => {
      const ed25519 = new curves.ED25519();
      const x25519 = new curves.X25519();
      const fresh = new curves.ED25519();
      const short = ed25519.toShort(ed25519.field(2));
      const edwards = short.toEdwards(short.field(-1), true);
      const mont = short.toMont(short.field(1), true, true);
      const inv = x25519.toEdwards(null, true);

      // https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html#further-dom-parms
      assert(short.a.fromRed().toJSON(), '02');
      assert(short.b.fromRed().toJSON(),
        '1ac1da05b55bc14633bd39e47f94302ef19843dcf669916f6a5dfd0165538cd1');
      assert(short.g.x.fromRed().toJSON(),
        '17cfeac378aed661318e8634582275b6d9ad4def072ea1935ee3c4e87a940ffa');
      assert(short.g.y.fromRed().toJSON(),
        '0c08a952c55dfad62c4f13f1a8f68dcadc5c331d297a37b6f0d7fdcc51e16b4d');

      assert(edwards.a.eq(ed25519.a));
      assert(edwards.d.eq(ed25519.d));
      assert(edwards.g.eq(ed25519.g));

      assert(mont.a.eq(x25519.a));
      assert(mont.b.eq(x25519.b));
      assert(mont.g.eq(x25519.g));

      assert(ed25519.isIsomorphic(short));
      assert(short.isIsomorphic(ed25519));
      assert(ed25519.pointFromShort(short.g).eq(ed25519.g));
      assert(short.pointFromEdwards(ed25519.g).eq(short.g));

      assert(mont.isIsomorphic(short));
      assert(short.isIsomorphic(mont));
      assert(mont.pointFromShort(short.g).eq(mont.g));
      assert(short.pointFromMont(mont.g).eq(short.g));

      assert(fresh.pointFromShort(short.g).eq(fresh.g));
      assert(short.pointFromEdwards(fresh.g).eq(short.g));

      assert(x25519.pointFromShort(short.g).eq(x25519.g));
      assert(short.pointFromMont(x25519.g).eq(short.g));

      assert(short.pointFromEdwards(inv.g).eq(short.g));
      assert(inv.pointFromShort(short.g).eq(inv.g));

      const short2 = x25519.toShort(x25519.field(2), true, true);

      assert(short2.a.eq(short.a));
      assert(short2.b.eq(short.b));
      assert(short2.g.eq(short.g));

      assert(short2.isIsomorphic(x25519));
      assert(x25519.isIsomorphic(short2));
      assert(short2.pointFromMont(x25519.g).eq(short2.g));
      assert(x25519.pointFromShort(short2.g).eq(x25519.g));

      const short3 = x25519.toShort();

      assert(short2.isIsomorphic(short3));
      assert(short3.isIsomorphic(short2));
      assert(short2.pointFromShort(short3.g).eq(short2.g));
      assert(short3.pointFromShort(short2.g).eq(short3.g));

      assert(ed25519.isIsomorphic(short3));
      assert(short3.isIsomorphic(ed25519));
      assert(ed25519.pointFromShort(short3.g).eq(ed25519.g));
      assert(short3.pointFromEdwards(ed25519.g).eq(short3.g));

      const p = ed25519.point(ed25519.zero, ed25519.one.redNeg());
      const q = short.pointFromEdwards(p);

      assert(!q.x.eq(ed25519.ad6));
      assert(q.y.isZero());
      assert(q.validate());
    });

    it('should test short isomorphism with j-invariant 0', () => {
      const curve = new curves.SECP256K1();
      const other = curve.toShort(curve.field(1337));

      assert(curve.isIsomorphic(other));

      {
        const g = curve.pointFromShort(other.g);

        assert(g.eq(curve.g));

        const g2 = curve.pointFromShort(other.g.dbl());

        assert(g2.eq(curve.g.dbl()));
      }

      {
        const g = other.pointFromShort(curve.g);

        assert(g.eq(other.g));

        const g2 = other.pointFromShort(curve.g.dbl());

        assert(g2.eq(other.g.dbl()));
      }

      const k = curve.randomScalar(rng);
      const p1 = curve.g.mul(k);
      const p2 = other.g.mul(k);

      assert(curve.pointFromShort(p2).eq(p1));
      assert(other.pointFromShort(p1).eq(p2));
    });

    it('should create short point from y coordinate', () => {
      const curve = new curves.SECP256K1();
      const {y} = curve.g;

      assert(curve.pointFromY(y, 2).eq(curve.g));

      for (const x of curve.solveX(y))
        assert(curve.point(x, y).validate());
    });

    it('should test mont isomorphism (1)', () => {
      const e = new curves.ED25519();
      const m1 = e.toMont(e.field(3), false, false);
      const m2 = new curves.X25519();
      const m3 = m2.toMont(m2.field(3), false, true);

      assert(m1.a.eq(m3.a));
      assert(m1.b.eq(m3.b));
      assert(m1.g.eq(m3.g));

      assert(m2.isIsomorphic(m3));
      assert(m3.isIsomorphic(m2));
      assert(m2.pointFromMont(m3.g).eq(m2.g));
      assert(m3.pointFromMont(m2.g).eq(m3.g));
    });

    it('should test mont isomorphism (2)', () => {
      const m0 = new curves.X25519();
      const m1 = new curves.ED25519().toMont(null, false, false);
      const m2 = m1.toMont(m1.field(1), true);

      assert(!m1.b.eq(m0.b));
      assert(!m1.g.eq(m0.g));

      assert(m2.a.eq(m0.a));
      assert(m2.b.eq(m0.b));
      assert(m2.g.eq(m0.g));

      assert(m1.isIsomorphic(m2));
      assert(m2.isIsomorphic(m1));
      assert(m1.pointFromMont(m2.g).eq(m1.g));
      assert(m2.pointFromMont(m1.g).eq(m2.g));
    });

    it('should test edwards isomorphism', () => {
      const e0 = new curves.ED25519();
      const m0 = e0.toMont();
      const e1 = m0.toEdwards(m0.field(3), false, false);
      const e2 = e0.toEdwards(e0.field(3), false);

      assert(e1.g.validate());
      assert(e2.g.validate());
      assert(e1.a.eq(e2.a));
      assert(e1.d.eq(e2.d));
      assert(e1.g.eq(e2.g));

      assert(e1.isIsomorphic(e2));
      assert(e2.isIsomorphic(e1));
      assert(e1.pointFromEdwards(e2.g.randomize(rng)).eq(e1.g));
      assert(e2.pointFromEdwards(e1.g.randomize(rng)).eq(e2.g));
      assert(e1.pointFromEdwards(e2.g.randomize(rng)).validate());
      assert(e2.pointFromEdwards(e1.g.randomize(rng)).validate());
    });

    it('should do division (1)', () => {
      const curve = new curves.ED25519();
      const g = curve.g;
      const p = g.muln(3);
      const q = p.divn(3);

      assert(p.eq(g.dbl().add(g)));
      assert(q.eq(g));
    });

    it('should do division (2)', () => {
      const curve = new curves.ED25519();
      const g = curve.g;
      const p = g.muln(-3);
      const q = p.divn(-3);

      assert(p.eq(g.dbl().add(g).neg()));
      assert(q.eq(g));
    });

    it('should do subtraction', () => {
      const curve = new curves.ED25519();
      const p = curve.randomPoint(rng);
      const q = curve.randomPoint(rng);
      const r = p.add(q.neg());

      assert(p.sub(q).eq(r));
    });

    it('should test svdw inversion edge case (x = -(c + z) / 2)', () => {
      const curve = new extra.SECP192K1();
      const {z} = curve;
      const z2 = z.redSqr();
      const c = z2.redMuln(-3).redSqrt();
      const x = c.redAdd(z).redINeg().redMul(curve.i2);
      const p = curve.pointFromX(x);
      const x2z = x.redMuln(2).redIAdd(z);

      assert(x2z.eq(c.redNeg()));

      // c1 = 0
      // (2 * x + z) = -sqrt(-3 * z^2)
      assert.throws(() => curve.pointToUniform(p, 0), {
        message: 'Invalid point.'
      });

      // svdw(u) != x
      assert.throws(() => curve.pointToUniform(p, 1), {
        message: 'Invalid point.'
      });

      assert.strictEqual(curve.pointToUniform(p, 2).fromRed().toString(16),
        '7925331b18c739cad09ed978d1fd2e9a2a937420e83d306a');

      assert.strictEqual(curve.pointToUniform(p, 3).fromRed().toString(16),
        '73c71fbc1ad4911630d2696473c3356c9df9d97a36d22626');
    });

    it('should test svdw inversion edge case (x = (c - z) / 2)', () => {
      const curve = new curves.SECP256K1();
      const {z} = curve;
      const z2 = z.redSqr();
      const c = z2.redMuln(-3).redSqrt();
      const x = c.redSub(z).redMul(curve.i2);
      const p = curve.pointFromX(x);
      const x2z = x.redMuln(2).redIAdd(z);

      assert(x2z.eq(c));

      assert(curve.pointToUniform(p, 0).eq(curve.zero));

      // c0 = 0
      // (2 * x + z) = +sqrt(-3 * z^2)
      assert.throws(() => curve.pointToUniform(p, 1), {
        message: 'Invalid point.'
      });

      assert.throws(() => curve.pointToUniform(p, 2), {
        message: 'Invalid point.'
      });

      assert.throws(() => curve.pointToUniform(p, 3), {
        message: 'Invalid point.'
      });
    });

    it('should test sswu inversion edge case (x = -b / a)', () => {
      const curve = new curves.P192();
      const x = curve.b.redNeg().redDiv(curve.a);
      const p = curve.pointFromX(x);

      // a * x + b = 0
      assert.throws(() => curve.pointToUniform(p, 0), {
        message: 'Invalid point.'
      });

      // a * x + b = 0
      assert.throws(() => curve.pointToUniform(p, 1), {
        message: 'Invalid point.'
      });

      assert(curve.pointToUniform(p, 2).eq(curve.zero));
      assert(curve.pointToUniform(p, 3).eq(curve.zero));
    });

    it('should test curve13318', () => {
      const curve = new extra.CURVE13318();

      sanityCheck(curve);
    });
  });

  describe('Point codec', () => {
    it('should throw when trying to decode random bytes', () => {
      const secp256k1 = new curves.SECP256K1();

      assert.throws(() => {
        secp256k1.decodePoint(Buffer.from(
          '0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          'hex'));
      });
    });

    it('should be able to encode/decode a short curve point', () => {
      const curve = new curves.SECP256K1();

      const vectors = [
        {
          coords: [
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
          ],
          compact: '02'
            + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          encoded: '04'
            + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
            + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
          hybrid: '06'
            + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
            + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
        },
        {
          coords: [
            'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
            'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
          ],
          compact: '03'
            + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
          encoded: '04'
            + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
            + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297',
          hybrid: '07'
            + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556'
            + 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
        }
      ];

      for (const vector of vectors) {
        const p = curve.pointFromJSON(vector.coords);

        // Encodes as expected
        assert.bufferEqual(p.encode(false), vector.encoded);
        assert.bufferEqual(p.encode(true), vector.compact);

        // Decodes as expected
        assert(curve.decodePoint(Buffer.from(vector.encoded, 'hex')).eq(p));
        assert(curve.decodePoint(Buffer.from(vector.compact, 'hex')).eq(p));
        assert(curve.decodePoint(Buffer.from(vector.hybrid, 'hex')).eq(p));
      }
    });

    it('should be able to encode/decode a mont curve point', () => {
      const curve = new curves.X25519();

      const vector = {
        scalar: '6',
        coords: [
          '26954ccdc99ebf34f8f1dde5e6bb080685fec73640494c28f9fe0bfa8c794531'
        ],
        encoded:
          '3145798cfa0bfef9284c494036c7fe850608bbe6e5ddf1f834bf9ec9cd4c9526'
      };

      const p = curve.xpoint(curve.field(vector.coords[0], 16));
      const g = curve.g.toX();
      const scalar = new BN(vector.scalar, 16);
      const encoded = p.encode();
      const decoded = curve.decodeX(encoded);

      assert(decoded.eq(p));

      assert.bufferEqual(encoded, vector.encoded);
      assert.bufferEqual(g.mul(scalar).encode(), encoded);
      assert.bufferEqual(g.mulBlind(scalar).encode(), encoded);
      assert.bufferEqual(g.mulBlind(scalar).encode(), encoded);
      assert.bufferEqual(g.mulBlind(scalar, rng).encode(), encoded);
      assert.bufferEqual(g.mulBlind(scalar, rng).encode(), encoded);
    });
  });

  describe('E521', () => {
    it('should have E521', () => {
      const e521 = new extra.E521();
      const inf = e521.point();

      assert(e521.g.validate());
      assert(e521.g.dbl().validate());
      assert(e521.g.dbl().dbl().validate());
      assert(e521.g.mul(e521.n).eq(inf));
      assert(!e521.g.mul(e521.n.subn(1)).eq(inf));
      assert(e521.g.mul(e521.n.addn(1)).eq(e521.g));
      assert(e521.g.mul(new BN(1)).eq(e521.g));
      assert(e521.g.mul(new BN(2)).eq(e521.g.dbl()));
      assert(e521.g.mul(new BN(3)).eq(e521.g.dbl().add(e521.g)));

      sanityCheck(e521);
    });

    it('should clamp properly', () => {
      const e521 = new extra.E521();
      const scalar = rng.randomBytes(e521.n.byteLength());

      e521.clamp(scalar);
    });

    it('should handle difference in scalar/field bytes', () => {
      const e521 = new EDDSA('E521', null, null, SHAKE256);

      const msg = rng.randomBytes(e521.size);
      const secret = e521.privateKeyGenerate();
      const pub = e521.publicKeyCreate(secret);

      assert(e521.publicKeyVerify(pub));

      const sig = e521.sign(msg, secret);

      assert(e521.verify(msg, sig, pub));

      sig[0] ^= 1;

      assert(!e521.verify(msg, sig, pub));
    });

    it('should do diffie hellman', () => {
      const e521 = new EDDSA('E521', null, null, SHAKE256);

      const alicePriv = e521.privateKeyGenerate();
      const alicePub = e521.publicKeyCreate(alicePriv);

      const bobPriv = e521.privateKeyGenerate();
      const bobPub = e521.publicKeyCreate(bobPriv);

      const aliceSecret = e521.derive(bobPub, alicePriv);
      const bobSecret = e521.derive(alicePub, bobPriv);

      assert.bufferEqual(aliceSecret, bobSecret);
    });
  });
});
