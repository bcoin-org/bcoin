/*!
 * curves.js - curve definitions for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const elliptic = require('../../lib/js/elliptic');

const {
  ShortCurve,
  MontCurve,
  EdwardsCurve
} = elliptic;

/**
 * SECP192K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 12, section 2.5.1)
 * https://www.secg.org/sec2-v2.pdf (page 6, section 2.2.1)
 */

class SECP192K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP192K1',
      ossl: 'secp192k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // 2^192 − 2^32 − 4553 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'fffffffe ffffee37'],
      a: '0',
      b: '3',
      n: ['ffffffff ffffffff fffffffe 26f2fc17',
          '0f69466a 74defd8d'],
      h: '1',
      // SVDW
      z: '1',
      // sqrt(-3)
      c: ['88f52dcd 8c8f2c7c 5ef013fd 5568d28f',
          'e6961547 941774e9'],
      g: [
        ['db4ff10e c057e9ae 26b07d02 80b7f434',
         '1da5d1b1 eae06c7d'],
        ['9b2f2f6d 9c5628a7 844163d0 15be8634',
         '4082aa88 d95e2f9d'],
        pre
      ]
    });
  }
}

/**
 * SECP224K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 13, section 2.6.1)
 * https://www.secg.org/sec2-v2.pdf (page 7, section 2.3.1)
 */

class SECP224K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP224K1',
      ossl: 'secp224k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // 2^224 − 2^32 − 6803 (= 5 mod 8)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff fffffffe ffffe56d'],
      a: '0',
      b: '5',
      n: ['01',
          '00000000 00000000 00000000 0001dce8',
          'd2ec6184 caf0a971 769fb1f7'],
      h: '1',
      // SVDW
      z: '-1',
      // sqrt(-3)
      c: ['03e2f1ff 4962f913 cdee75d9 c555aaf5',
          'e9814e91 6c790612 8f64fc09'],
      g: [
        ['a1455b33 4df099df 30fc28a1 69a467e9',
         'e47075a9 0f7e650e b6b7a45c'],
        ['7e089fed 7fba3442 82cafbd6 f7e319f7',
         'c0b0bd59 e2ca4bdb 556d61a5'],
        pre
      ]
    });
  }
}

/**
 * ANSSI FRP256V1
 */

class FRP256V1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'FRP256V1',
      ossl: null,
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // (= 3 mod 4)
      p: ['f1fd178c 0b3ad58f 10126de8 ce42435b',
          '3961adbc abc8ca6d e8fcf353 d86e9c03'],
      // -3 mod p
      a: ['f1fd178c 0b3ad58f 10126de8 ce42435b',
          '3961adbc abc8ca6d e8fcf353 d86e9c00'],
      b: ['ee353fca 5428a930 0d4aba75 4a44c00f',
          'dfec0c9a e4b1a180 3075ed96 7b7bb73f'],
      n: ['f1fd178c 0b3ad58f 10126de8 ce42435b',
          '53dc67e1 40d2bf94 1ffdd459 c6d655e1'],
      h: '1',
      // Icart
      z: '-5',
      g: [
        ['b6b3d4c3 56c139eb 31183d47 49d42395',
         '8c27d2dc af98b701 64c97a2d d98f5cff'],
        ['6142e0f7 c8b20491 1f9271f0 f3ecef8c',
         '2701c307 e8e4c9e1 83115a15 54062cfb'],
        pre
      ]
    });
  }
}

/**
 * ANOMALOUS
 * https://safecurves.cr.yp.to/index.html
 */

class ANOMALOUS extends ShortCurve {
  constructor(pre) {
    super({
      id: 'ANOMALOUS',
      ossl: null,
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // (= 3 mod 4)
      p: ['00000b00 00000000 00000000 00009530',
          '00000000 00000000 0001f9d7'],
      a: ['0000098d 0fac687d 6343eb1a 1f595283',
          'eb1a1f58 d0fac687 d635f5e4'],
      b: ['000004a1 f58d0fac 687d6343 eb1a5e2d',
          '6343eb1a 1f58d0fa c688ab3f'],
      n: ['00000b00 00000000 00000000 00009530',
          '00000000 00000000 0001f9d7'],
      h: '1',
      // SSWU
      z: 'e',
      g: [
        ['00000101 efb35fd1 963c4871 a2d17eda',
         'afa7e249 807f58f8 705126c6'],
        ['00000223 89a39543 75834304 ba1d509a',
         '97de6c07 148ea7f5 951b20e7'],
        pre
      ]
    });
  }
}

/**
 * BN(2,254)
 * https://eprint.iacr.org/2010/429
 */

class BN2254 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BN2254',
      ossl: null,
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // (= 3 mod 4)
      p: ['25236482 40000001 ba344d80 00000008',
          '61210000 00000013 a7000000 00000013'],
      a: '0',
      b: '2',
      n: ['25236482 40000001 ba344d80 00000007',
          'ff9f8000 00000010 a1000000 0000000d'],
      h: '1',
      // SVDW
      z: '-1',
      // sqrt(-3)
      c: ['25236482 40000001 26cd8900 00000003',
          'cf0f0000 00000006 0c000000 00000004'],
      g: [
        // (-1, 1)
        ['25236482 40000001 ba344d80 00000008',
         '61210000 00000013 a7000000 00000012'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000001'],
        pre
      ]
    });
  }
}

/**
 * WEI25519
 * https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html#rfc.appendix.E.3
 */

class WEI25519 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'WEI25519',
      ossl: null,
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'p25519',
      // 2^255 - 19 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffed'],
      a: ['2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa',
          'aaaaaaaa aaaaaaaa aaaaaa98 4914a144'],
      b: ['7b425ed0 97b425ed 097b425e d097b425',
          'ed097b42 5ed097b4 260b5e9c 7710c864'],
      n: ['10000000 00000000 00000000 00000000',
          '14def9de a2f79cd6 5812631a 5cf5d3ed'],
      h: '8',
      // SSWU
      z: '8',
      g: [
        ['2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa',
         'aaaaaaaa aaaaaaaa aaaaaaaa aaad245a'],
        ['20ae19a1 b8a086b4 e01edd2c 7748d14c',
         '923d4d7e 6d7c61b2 29e9c5a2 7eced3d9'],
        pre
      ],
      torsion: [
        [],
        [
          ['2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa',
           'aaaaaaaa aaaaaaaa aaaaaaaa aaad2451'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa',
           'aaaaaaaa aaaaaaaa aaaaaaaa aaad2452'],
          ['141b0b68 06563d50 3de05885 280b5910',
           '9ca5ee38 d7b56c9c 165db710 6377bbd8']
        ],
        [
          ['2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa',
           'aaaaaaaa aaaaaaaa aaaaaaaa aaad2452'],
          ['6be4f497 f9a9c2af c21fa77a d7f4a6ef',
           '635a11c7 284a9363 e9a248ef 9c884415']
        ],
        [
          ['01bc4a7b 87f8cd83 3138c703 6f06eeaf',
           '069a2e47 005c7b5b cf36fb4e 6742c0c3'],
          ['173a6c76 c2ba719b ce3935ff ba04afea',
           'df5bbcb9 71559722 f0efc7bd fb7f9a36']
        ],
        [
          ['01bc4a7b 87f8cd83 3138c703 6f06eeaf',
           '069a2e47 005c7b5b cf36fb4e 6742c0c3'],
          ['68c59389 3d458e64 31c6ca00 45fb5015',
           '20a44346 8eaa68dd 0f103842 048065b7']
        ],
        [
          ['2b62f409 c0b00d31 a85bdd47 9637b485',
           '156f4a9c a58e00c1 5962ebe6 27281031'],
          ['46ce3ed6 a9617c5a d6b7d3eb 19d74ba8',
           '6cc403d6 127fe4b2 9778eb7c 6daf84d3']
        ],
        [
          ['2b62f409 c0b00d31 a85bdd47 9637b485',
           '156f4a9c a58e00c1 5962ebe6 27281031'],
          ['3931c129 569e83a5 29482c14 e628b457',
           '933bfc29 ed801b4d 68871483 92507b1a']
        ]
      ]
    });
  }
}

/**
 * TWIST448
 * https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n675
 */

class TWIST448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'TWIST448',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      a: '-1',
      // -39082 mod p
      d: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffff6755'],
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['7fffffff ffffffff ffffffff ffffffff',
         'ffffffff ffffffff fffffffe 80000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000'],
        ['8508de14 f04286d4 8d06c130 78ca2408',
         '05264370 504c74c3 93d5242c 50452714',
         '14181844 d73f48e5 199b0c1e 3ab470a1',
         'c86079b4 dfdd4a64'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe']
        ],
        [],
        []
      ]
    });
  }
}

/**
 * ED1174
 * http://elligator.cr.yp.to/elligator-20130828.pdf
 */

class ED1174 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED1174',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigEd1174',
      context: false,
      prime: 'p251',
      // 2^251 - 9 (= 3 mod 4)
      p: ['07ffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffff7'],
      a: '1',
      // -1174 mod p
      d: ['07ffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffb61'],
      n: ['01ffffff ffffffff ffffffff ffffffff',
          'f77965c4 dfd30734 8944d45f d166c971'],
      h: '4',
      // Elligator 1
      s: ['03fe707f 0d7004fd 334ee813 a5f1a74a',
          'b2449139 c82c39d8 4a09ae74 cc78c615'],
      // Elligator 2
      z: '-1',
      g: [
        ['037fbb0c ea308c47 9343aee 7c029a190',
         'c021d96a 492ecd65 16123f2 7bce29eda'],
        ['06b72f82 d47fb7cc 66568411 69840e0c',
         '4fe2dee2 af3f976b a4ccb1bf 9b46360e'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['07ffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff fffffff6']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['07ffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff fffffff6'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ]
      ]
    });
  }
}

/**
 * MONT1174
 * Isomorphic to Ed1174.
 */

class MONT1174 extends MontCurve {
  constructor() {
    super({
      id: 'MONT1174',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHA512',
      prime: 'p251',
      // 2^251 - 9 (= 3 mod 4)
      p: ['07ffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffff7'],
      // -2346 / -1175 mod p
      a: ['00c1787b c0619b57 cd74203e bf4abaef',
          '394ce8b0 0a75371f 27dee226 c801be35'],
      b: '1',
      n: ['01ffffff ffffffff ffffffff ffffffff',
          'f77965c4 dfd30734 8944d45f d166c971'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['025ce209 06ce32bf bcb056eb 1c23bc02',
         '6203486a ba85a5a5 ff17e62d 1052d2e5'],
        ['048dfca1 329feb9d bc9625dd aff063cc',
         '30dfc71d 09fbefe9 1e1bafa2 42de55c5']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['07ffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff fffffff6'],
          ['07a585fc 04fd08e6 a1bbe32d 1c08f706',
           '90700417 ca6ab745 7d895319 44182025']
        ],
        [
          ['07ffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff fffffff6'],
          ['005a7a03 fb02f719 5e441cd2 e3f708f9',
           '6f8ffbe8 359548ba 8276ace6 bbe7dfd2']
        ]
      ]
    });
  }
}

/**
 * ED41417 (also known as Curve3617)
 * https://cr.yp.to/ecdh/curve41417-20140706.pdf
 * https://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class ED41417 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED41417',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd41417',
      context: false,
      prime: null,
      // 2^414 - 17 (= 3 mod 4)
      p: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffef'],
      a: '1',
      // 3617
      d: ['00000000 00000000 00000000 00000000',
          '00000000 00000000 00000000 00000000',
          '00000000 00000000 00000000 00000000',
          '00000e21'],
      n: ['07ffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffeb3c c92414cf',
          '706022b3 6f1c0338 ad63cf18 1b0e71a5',
          'e106af79'],
      h: '8',
      // Elligator 1
      s: ['09d97112 36cb615f 21a3ee8b 56f69ebb',
          '592d05eb 9401dbd3 de60e7d4 b0bdbb03',
          'f1ecba9b 5ce72822 e95ef209 e638bb96',
          'dda55cef'],
      // Elligator 2
      z: '-1',
      g: [
        ['1a334905 14144330 0218c063 1c326e5f',
         'cd46369f 44c03ec7 f57ff354 98a4ab4d',
         '6d6ba111 301a73fa a8537c64 c4fd3812',
         'f3cbc595'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000022'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000'],
          ['3fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffee']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000']
        ],
        [
          ['3fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffee'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000']
        ],
        [
          ['1bb00090 7ec3b857 bc73b6bb 4fc2f677',
           '4eb90596 794501a9 8da231c9 38af8e03',
           'd8da6119 77140345 795a9f22 305d477d',
           'bf2d6e21'],
          ['1bb00090 7ec3b857 bc73b6bb 4fc2f677',
           '4eb90596 794501a9 8da231c9 38af8e03',
           'd8da6119 77140345 795a9f22 305d477d',
           'bf2d6e21']
        ],
        [
          ['244fff6f 813c47a8 438c4944 b03d0988',
           'b146fa69 86bafe56 725dce36 c75071fc',
           '27259ee6 88ebfcba 86a560dd cfa2b882',
           '40d291ce'],
          ['1bb00090 7ec3b857 bc73b6bb 4fc2f677',
           '4eb90596 794501a9 8da231c9 38af8e03',
           'd8da6119 77140345 795a9f22 305d477d',
           'bf2d6e21']
        ],
        [
          ['1bb00090 7ec3b857 bc73b6bb 4fc2f677',
           '4eb90596 794501a9 8da231c9 38af8e03',
           'd8da6119 77140345 795a9f22 305d477d',
           'bf2d6e21'],
          ['244fff6f 813c47a8 438c4944 b03d0988',
           'b146fa69 86bafe56 725dce36 c75071fc',
           '27259ee6 88ebfcba 86a560dd cfa2b882',
           '40d291ce']
        ],
        [
          ['244fff6f 813c47a8 438c4944 b03d0988',
           'b146fa69 86bafe56 725dce36 c75071fc',
           '27259ee6 88ebfcba 86a560dd cfa2b882',
           '40d291ce'],
          ['244fff6f 813c47a8 438c4944 b03d0988',
           'b146fa69 86bafe56 725dce36 c75071fc',
           '27259ee6 88ebfcba 86a560dd cfa2b882',
           '40d291ce']
        ]
      ]
    });
  }
}

/**
 * CURVE383187
 * https://eprint.iacr.org/2013/647
 */

class CURVE383187 extends MontCurve {
  constructor() {
    super({
      id: 'CURVE383187',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: null,
      // 2^383 - 187 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffff45'],
      // 229969
      a: '38251',
      b: '1',
      n: ['10000000 00000000 00000000 00000000',
          '00000000 00000000 0e85a852 87a1488a',
          'cd41ae84 b2b70304 46f72088 b00a0e21'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000005'],
        ['1eebe07d c1871896 732b12d5 504a3237',
         '0471965c 7a11f2c8 9865f855 ab3cbd7c',
         '224e3620 c31af337 0788457d d5ce46df']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['1de721ff 03b0822b 2d6c91dd 343c7d22',
           '3e0e9f24 e38843b8 a259a3c1 fdec077b',
           'e01b6a29 9eb01e56 6c058cb9 52a64a5e']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['6218de00 fc4f7dd4 d2936e22 cbc382dd',
           'c1f160db 1c77bc47 5da65c3e 0213f884',
           '1fe495d6 614fe1a9 93fa7346 ad59b4e7']
        ],
        [
          ['1dd1a7c5 57a62ba3 f8df23e2 cfab1e5d',
           '62d175d3 0036f347 7c01fa1f b61e35cc',
           '5bc1e1a3 4dea3f52 259246a7 0bfade69'],
          ['09487d51 20bb08d7 e551f77b 1d9eb1c0',
           '596ecb44 edc4d46b c457ad89 851724d2',
           '71f7665e 874c6664 9e30de40 6eab3b7e']
        ],
        [
          ['1dd1a7c5 57a62ba3 f8df23e2 cfab1e5d',
           '62d175d3 0036f347 7c01fa1f b61e35cc',
           '5bc1e1a3 4dea3f52 259246a7 0bfade69'],
          ['76b782ae df44f728 1aae0884 e2614e3f',
           'a69134bb 123b2b94 3ba85276 7ae8db2d',
           '8e0899a1 78b3999b 61cf21bf 9154c3c7']
        ],
        [
          ['2660143c a0f8d005 ac47b862 c7dbe75e',
           '21114be3 38b88547 3f4abe5c 4e09bb3b',
           'e4074a09 74b58401 02629fe6 4eb88c22'],
          ['00e5054d 2f7d1184 9b043eef ee90a649',
           '51a947d8 7be5e34e 4dbe3c91 7cc742c1',
           'f2650f05 020cdfbe 4e471125 b93d610b']
        ],
        [
          ['2660143c a0f8d005 ac47b862 c7dbe75e',
           '21114be3 38b88547 3f4abe5c 4e09bb3b',
           'e4074a09 74b58401 02629fe6 4eb88c22'],
          ['7f1afab2 d082ee7b 64fbc110 116f59b6',
           'ae56b827 841a1cb1 b241c36e 8338bd3e',
           '0d9af0fa fdf32041 b1b8eeda 46c29e3a']
        ]
      ]
    });
  }
}

/**
 * M221
 * http://eprint.iacr.org/2013/647.pdf
 */

class M221 extends MontCurve {
  constructor() {
    super({
      id: 'M221',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHA256',
      prime: null,
      // 2^221 - 3 (= 5 mod 8)
      p: ['1fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffd'],
      // 117050
      a: '1c93a',
      b: '1',
      n: ['04000000 00000000 00000000 000015a0',
          '8ed730e8 a2f77f00 5042605b'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000004'],
        ['0f7acdd2 a4939571 d1cef14e ca37c228',
         'e61dbff1 0707dc6c 08c5056d']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000001'],
          ['01213189 89fc7223 0c9f4a09 cb9f2bdb',
           'bb625858 97db3dff bc589d39']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000001'],
          ['1edece76 76038ddc f360b5f6 3460d424',
           '449da7a7 6824c200 43a762c4']
        ],
        [
          ['0d167a72 d31965d9 8a8f0552 df6670c5',
           'cb4c0b27 d222e992 ad992862'],
          ['0f1d26bc 4672d626 59381cb8 7806c6ed',
           '41b9322b 5702c794 652c5bc5']
        ],
        [
          ['0d167a72 d31965d9 8a8f0552 df6670c5',
           'cb4c0b27 d222e992 ad992862'],
          ['10e2d943 b98d29d9 a6c7e347 87f93912',
           'be46cdd4 a8fd386b 9ad3a438']
        ],
        [
          ['152be8a0 40df7e6c 8eaf8ec0 b7d7e6f1',
           'ab78a589 5d93926c cb18120f'],
          ['0c5e131d 919b614d 744abb20 597c89a3',
           'd0bd6c72 4990406c a96d9cdc']
        ],
        [
          ['152be8a0 40df7e6c 8eaf8ec0 b7d7e6f1',
           'ab78a589 5d93926c cb18120f'],
          ['13a1ece2 6e649eb2 8bb544df a683765c',
           '2f42938d b66fbf93 56926321']
        ]
      ]
    });
  }
}

/**
 * E222
 * http://eprint.iacr.org/2013/647.pdf
 */

class E222 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E222',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigE222',
      context: false,
      prime: null,
      // 2^222 - 117 (= 3 mod 4)
      p: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffff8b'],
      a: '1',
      // 160102
      d: ['00000000 00000000 00000000 00000000',
          '00000000 00000000 00027166'],
      n: ['0fffffff ffffffff ffffffff fffff70c',
          'bc95e932 f802f314 23598cbf'],
      h: '4',
      // Elligator 1
      s: ['108bd829 b2739d6a 89a0d065 61849d96',
          '8cd2cf7d 01ea0846 5368b19b'],
      // Elligator 2
      z: '-1',
      g: [
        ['19b12bb1 56a389e5 5c9768c3 03316d07',
         'c23adab3 736eb2bc 3eb54e51'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 0000001c'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000'],
          ['3fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffff8a']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000']
        ],
        [
          ['3fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffff8a'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000']
        ]
      ]
    });
  }
}

/**
 * M383
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class M383 extends MontCurve {
  constructor() {
    super({
      id: 'M383',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: null,
      // 2^383 - 187 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffff45'],
      // 2065150
      a: '1f82fe',
      b: '1',
      n: ['10000000 00000000 00000000 00000000',
          '00000000 00000000 06c79673 ac36ba6e',
          '7a32576f 7b1b249e 46bbc225 be9071d7'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 0000000c'],
        ['1ec7ed04 aaf834af 310e304b 2da0f328',
         'e7c165f0 e8988abd 39928612 90f617aa',
         '1f1b2e7d 0b6e332e 969991b6 2555e77e']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['1b54b299 32ed4911 ecd6a451 b7e6bb16',
           'f6eddedb a06bee23 1ff166df d795bbb6',
           '4d21acf9 01dda11f a0274135 c4272299']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['64ab4d66 cd12b6ee 13295bae 481944e9',
           '09122124 5f9411dc e00e9920 286a4449',
           'b2de5306 fe225ee0 5fd8beca 3bd8dcac']
        ],
        [
          ['521344d4 c6725bec faa5867c 168cc8ca',
           '23841a29 e6481d3b 21450507 5e5bc5fd',
           '7445895c 24fc6f4a 3ff37b58 a1753dbf'],
          ['15868aad c2f806bc 46a30775 26394ab5',
           '733663d2 07e723ff ad1a483f cbc53ba3',
           'b31eca93 fbcf0520 2fe47699 53a828a5']
        ],
        [
          ['521344d4 c6725bec faa5867c 168cc8ca',
           '23841a29 e6481d3b 21450507 5e5bc5fd',
           '7445895c 24fc6f4a 3ff37b58 a1753dbf'],
          ['6a797552 3d07f943 b95cf88a d9c6b54a',
           '8cc99c2d f818dc00 52e5b7c0 343ac45c',
           '4ce1356c 0430fadf d01b8966 ac57d6a0']
        ],
        [
          ['6496205d 9f683636 df07c227 5940ad63',
           'ca57a38d 5a8fbf0b 1e9dc8b8 50cfb16f',
           '25fdd095 debed2f5 005b0712 e6d906ba'],
          ['02d95512 8ead2b03 f9fd98bc 05d43711',
           '4eeddf40 8996dc8c 2cdfe3bf 2a1c2a7c',
           'e7a57e78 0345899e b0817b70 6483b9c4']
        ],
        [
          ['6496205d 9f683636 df07c227 5940ad63',
           'ca57a38d 5a8fbf0b 1e9dc8b8 50cfb16f',
           '25fdd095 debed2f5 005b0712 e6d906ba'],
          ['7d26aaed 7152d4fc 06026743 fa2bc8ee',
           'b11220bf 76692373 d3201c40 d5e3d583',
           '185a8187 fcba7661 4f7e848f 9b7c4581']
        ]
      ]
    });
  }
}

/**
 * E382
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class E382 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E382',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigE382',
      context: false,
      prime: null,
      // 2^382 - 105 (= 3 mod 4)
      p: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffff97'],
      a: '1',
      // -67254 mod p
      d: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffef8e1'],
      n: ['0fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff d5fb21f2 1e95eee1',
          '7c5e6928 1b102d27 73e27e13 fd3c9719'],
      h: '4',
      // Elligator 1
      s: ['11e24c2d 89fc3662 81997e95 e0d98705',
          '3c450018 7834351f 34055452 39ac8ad5',
          '19dae89c e8c7a39a 131cc679 c00ffffc'],
      // Elligator 2
      z: '-1',
      g: [
        ['196f8dd0 eab20391 e5f05be9 6e8d20ae',
         '68f84003 2b0b6435 2923bab8 53648411',
         '93517dbc e8105398 ebc0cc94 70f79603'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000011'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['3fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffff96']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['3fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffff96'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ]
      ]
    });
  }
}

/**
 * M511
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class M511 extends MontCurve {
  constructor() {
    super({
      id: 'M511',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: null,
      // 2^511 - 187 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffff45'],
      // 530438
      a: '81806',
      b: '1',
      n: ['10000000 00000000 00000000 00000000',
          '00000000 00000000 00000000 00000000',
          '17b5feff 30c7f567 7ab2aeeb d13779a2',
          'ac125042 a6aa10bf a54c15ba b76baf1b'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000005'],
        ['2fbdc0ad 8530803d 28fdbad3 54bb488d',
         '32399ac1 cf8f6e01 ee3f9638 9b90c809',
         '422b9429 e8a43dbf 49308ac4 455940ab',
         'e9f1dbca 542093a8 95e30a64 af056fa5']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['0f93957c 44c32e34 5f2ac0fb b097179e',
           'fbc18c4e 90318733 91b3ab48 7639025c',
           'd5597e9e 919cab04 fc0786ee aacc702e',
           '6f8de417 06a1b5c0 22abddd5 2a6d884b']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['706c6a83 bb3cd1cb a0d53f04 4f68e861',
           '043e73b1 6fce78cc 6e4c54b7 89c6fda3',
           '2aa68161 6e6354fb 03f87911 55338fd1',
           '90721be8 f95e4a3f dd54222a d59276fa']
        ],
        [
          ['2831fcd0 9d739314 4bb7fb81 3caefa31',
           'be5f1697 6c63b32e 446d49f5 d93d9851',
           '609fea13 b8b54a7f 9fb4704f 86666dc7',
           '2afdb86c 7fc2ccb1 8a2d7217 bc417ac7'],
          ['08356807 bb9cc085 9f07a2c8 b1e7ed47',
           '7d65d374 ef442bce 44bda0b7 e47390ee',
           '19b15418 adc69bad bd1ce594 784a7dea',
           '415e0cf7 0d8fbe94 255e2089 3bbae2f4']
        ],
        [
          ['2831fcd0 9d739314 4bb7fb81 3caefa31',
           'be5f1697 6c63b32e 446d49f5 d93d9851',
           '609fea13 b8b54a7f 9fb4704f 86666dc7',
           '2afdb86c 7fc2ccb1 8a2d7217 bc417ac7'],
          ['77ca97f8 44633f7a 60f85d37 4e1812b8',
           '829a2c8b 10bbd431 bb425f48 1b8c6f11',
           'e64eabe7 52396452 42e31a6b 87b58215',
           'bea1f308 f270416b daa1df76 c4451c51']
        ],
        [
          ['38a6d836 d9061082 f5f28287 6222d690',
           '4a1dd0cb 73393e6a 982b5f79 3a5062f4',
           'f4ad18af 24115f76 683c81d3 2400b1db',
           'f5e67f65 72f9c7ce 307ad23d eee373ea'],
          ['3618ede9 576ff84b dda36126 10747134',
           '71a05dc5 5181f100 02110c69 f4707885',
           '3bb4a661 98ac1066 33013626 32e742cf',
           '7cd98365 0cf7186c 655156cb 6deb0e28']
        ],
        [
          ['38a6d836 d9061082 f5f28287 6222d690',
           '4a1dd0cb 73393e6a 982b5f79 3a5062f4',
           'f4ad18af 24115f76 683c81d3 2400b1db',
           'f5e67f65 72f9c7ce 307ad23d eee373ea'],
          ['49e71216 a89007b4 225c9ed9 ef8b8ecb',
           '8e5fa23a ae7e0eff fdeef396 0b8f877a',
           'c44b599e 6753ef99 ccfec9d9 cd18bd30',
           '83267c9a f308e793 9aaea934 9214f11d']
        ]
      ]
    });
  }
}

/**
 * E521
 * http://eprint.iacr.org/2013/647.pdf
 * http://tools.ietf.org/html/draft-ladd-safecurves-02
 */

class E521 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'E521',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigE521',
      context: false,
      prime: 'p521',
      // 2^521 - 1 (= 3 mod 4)
      p: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff'],
      a: '1',
      // -376014 mod p
      d: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffa4331'],
      n: ['0000007f ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffffffd 15b6c647 46fc85f7 36b8af5e',
          '7ec53f04 fbd8c456 9a8f1f45 40ea2435',
          'f5180d6b'],
      h: '4',
      // Elligator 1
      s: ['000000cd c45eed49 413d0fb4 56e2e7c4',
          '003c943e 8030aae7 5e6c0702 c871f054',
          '2fc3b693 70d50b2e 0dc92250 9eb0e675',
          '812bf1b2 f7ea84ad 2db62f78 aa8c789c',
          '85796224'],
      // Elligator 2
      z: '-1',
      g: [
        ['00000075 2cb45c48 648b189d f90cb229',
         '6b2878a3 bfd9f42f c6c818ec 8bf3c9c0',
         'c6203913 f6ecc5cc c72434b1 ae949d56',
         '8fc99c60 59d0fb13 364838aa 302a940a',
         '2f19ba6c'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '0000000c'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000'],
          ['000001ff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'fffffffe']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000']
        ],
        [
          ['000001ff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'fffffffe'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000']
        ]
      ]
    });
  }
}

/**
 * MDC
 * https://cryptoexperts.github.io/million-dollar-curve/
 */

class MDC extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'MDC',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigMDC',
      context: false,
      prime: null,
      // (= 3 mod 4)
      p: ['f13b68b9 d456afb4 532f92fd d7a5fd4f',
          '086a9037 ef07af9e c1371040 5779ec13'],
      a: '1',
      d: ['57130452 1965b68a 7cdfbfcc fb0cb962',
          '5f1270f6 3f21f041 ee930925 0300cf89'],
      n: ['3c4eda2e 7515abed 14cbe4bf 75e97f53',
          '4fb38975 faf974bb 588552f4 21b0f7fb'],
      h: '4',
      // Elligator 1
      s: ['2bfcf45c fbcc3086 fb60bbeb fc611e28',
          'f70e33ab 41de2ecb 42225097 817038e2'],
      // Elligator 2
      z: '-1',
      g: [
        ['b681886a 7f903b83 d85b421 e03cbcf63',
         '50d72abb 8d2713e2 232c25b fee68363b'],
        ['ca6734e1 b59c0b03 59814dcf 6563da42',
         '1da8bc3d 81a93a3a 7e73c355 bd2864b5'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['f13b68b9 d456afb4 532f92fd d7a5fd4f',
           '086a9037 ef07af9e c1371040 5779ec12']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['f13b68b9 d456afb4 532f92fd d7a5fd4f',
           '086a9037 ef07af9e c1371040 5779ec12'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ]
      ]
    });
  }
}

/**
 * Jubjub
 * https://z.cash/technology/jubjub/
 * https://github.com/zkcrypto/jubjub
 */

class JUBJUB extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'JUBJUB',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigJubjub',
      context: false,
      prime: null,
      // (= 1 mod 16)
      p: ['73eda753 299d7d48 3339d808 09a1d805',
          '53bda402 fffe5bfe ffffffff 00000001'],
      a: '-1',
      // -(10240 / 10241) mod p
      d: ['2a9318e7 4bfa2b48 f5fd9207 e6bd7fd4',
          '292d7f6d 37579d26 01065fd6 d6343eb1'],
      n: ['0e7db4ea 6533afa9 06673b01 01343b00',
          'a6682093 ccc81082 d0970e5e d6f72cb7'],
      h: '8',
      // Elligator 2
      z: '5',
      g: [
        ['11dafe5d 23e12180 86a365b9 9fbf3d3b',
         'e72f6afd 7d1f7262 3e6b0714 92d1122b'],
        ['1d523cf1 ddab1a17 93132e78 c866c0c3',
         '3e26ba5c c220fed7 cc3f870e 59d292aa'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['73eda753 299d7d48 3339d808 09a1d805',
           '53bda402 fffe5bfe ffffffff 00000000']
        ],
        [
          ['00000000 00000000 8d51ccce 760304d0',
           'ec030002 76030000 00010000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['73eda753 299d7d47 a5e80b39 939ed334',
           '67baa400 89fb5bfe fffeffff 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['0218c81a 6eff03d4 488ef781 683bbf33',
           'd919893e c24fd67c 26d19585 d8dff2be'],
          ['2a94e9a1 1036e51a 1c98a7d2 5c54659e',
           'c2b6b572 0c79b75d 00f2df96 100b6924']
        ],
        [
          ['71d4df38 ba9e7973 eaaae086 a16618d1',
           '7aa41ac4 3dae8582 d92e6a79 27200d43'],
          ['2a94e9a1 1036e51a 1c98a7d2 5c54659e',
           'c2b6b572 0c79b75d 00f2df96 100b6924']
        ],
        [
          ['0218c81a 6eff03d4 488ef781 683bbf33',
           'd919893e c24fd67c 26d19585 d8dff2be'],
          ['4958bdb2 1966982e 16a13035 ad4d7266',
           '9106ee90 f384a4a1 ff0d2068 eff496dd']
        ],
        [
          ['71d4df38 ba9e7973 eaaae086 a16618d1',
           '7aa41ac4 3dae8582 d92e6a79 27200d43'],
          ['4958bdb2 1966982e 16a13035 ad4d7266',
           '9106ee90 f384a4a1 ff0d2068 eff496dd']
        ]
      ]
    });
  }
}

/**
 * ISO256K1 (3-isogenous to secp256k1)
 * https://gist.github.com/chjj/09c447047d5d0b63afcbbbc484d2c882
 */

class ISO256K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'ISO256K1',
      ossl: null,
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'k256',
      // 2^256 - 2^32 - 977 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe fffffc2f'],
      a: ['3f8731ab dd661adc a08a5558 f0f5d272',
          'e953d363 cb6f0e5d 405447c0 1a444533'],
      // 1771
      b: '6eb',
      n: ['ffffffff ffffffff ffffffff fffffffe',
          'baaedce6 af48a03b bfd25e8c d0364141'],
      h: '1',
      // SSWU
      z: '-b',
      g: [
        ['4010e1cb b86ab7f3 a40248e9 21dc5e7f',
         '4d4384af d9d43b09 2fef88a7 4062e495'],
        ['8e133b20 6fb54a5d 7c567df8 ecae8f71',
         'e5018676 5ed9fa20 1e7cc15d 68368ca7'],
        pre
      ]
    });
  }
}

/**
 * Curve13318
 * https://eprint.iacr.org/2019/1166
 * https://twitter.com/pbarreto/status/869103226276134912
 */

class CURVE13318 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'CURVE13318',
      ossl: null,
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'p25519',
      // 2^255 - 19 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffed'],
      // -3 mod p
      a: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffea'],
      // 13318
      b: '3406',
      n: ['80000000 00000000 00000000 00000000',
          'f4f654f8 3deb8d16 eb7d12dc 4dc2cbe3'],
      h: '1',
      // SSWU
      z: '2',
      g: [
        // (-7, 114)
        ['7fffffff ffffffff ffffffff ffffffff',
         'ffffffff ffffffff ffffffff ffffffe6'],
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000072'],
        pre
      ]
    });
  }
}

/*
 * Register
 */

elliptic.register('SECP192K1', SECP192K1);
elliptic.register('SECP224K1', SECP224K1);
elliptic.register('FRP256V1', FRP256V1);
elliptic.register('ANOMALOUS', ANOMALOUS);
elliptic.register('BN2254', BN2254);
elliptic.register('WEI25519', WEI25519);
elliptic.register('TWIST448', TWIST448);
elliptic.register('ED1174', ED1174);
elliptic.register('MONT1174', MONT1174);
elliptic.register('ED41417', ED41417);
elliptic.register('CURVE383187', CURVE383187);
elliptic.register('M221', M221);
elliptic.register('E222', E222);
elliptic.register('M383', M383);
elliptic.register('E382', E382);
elliptic.register('M511', M511);
elliptic.register('E521', E521);
elliptic.register('MDC', MDC);
elliptic.register('JUBJUB', JUBJUB);
elliptic.register('ISO256K1', ISO256K1);
elliptic.register('CURVE13318', CURVE13318);

/*
 * Expose
 */

module.exports = {
  SECP192K1,
  SECP224K1,
  FRP256V1,
  ANOMALOUS,
  BN2254,
  WEI25519,
  TWIST448,
  ED1174,
  MONT1174,
  ED41417,
  CURVE383187,
  M221,
  E222,
  M383,
  E382,
  M511,
  E521,
  MDC,
  JUBJUB,
  ISO256K1,
  CURVE13318
};
