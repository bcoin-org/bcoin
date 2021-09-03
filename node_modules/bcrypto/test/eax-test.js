'use strict';

const assert = require('bsert');
const cipher = require('../lib/cipher');
const AES = require('../lib/js/ciphers/aes');
const {CMAC} = require('../lib/js/ciphers/modes');

// https://tools.ietf.org/html/rfc4493#section-4
const mvectors = [
  [
    '',
    'bb1d6929e95937287fa37d129b756746'
  ],
  [
    '6bc1bee22e409f96e93d7e117393172a',
    '070a16b46b4d4144f79bdd9dd04a287c'
  ],
  [
    ['6bc1bee22e409f96e93d7e117393172a',
     'ae2d8a571e03ac9c9eb76fac45af8e51',
     '30c81c46a35ce411'].join(''),
    'dfa66747de9ae63030ca32611497c827'
  ],
  [
    ['6bc1bee22e409f96e93d7e117393172a',
     'ae2d8a571e03ac9c9eb76fac45af8e51',
     '30c81c46a35ce411e5fbc1191a0a52ef',
     'f69f2445df4f9b17ad2b417be66c3710'].join(''),
    '51f0bebf7e3b9d92fc49741779363cfe'
  ]
];

// https://github.com/gnutls/nettle/blob/master/testsuite/eax-test.c
// http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
const vectors = [
  // key, auth data, plaintext, ciphertext, nonce, tag
  [
    'AES-128-EAX',
    '233952dee4d5ed5f9b9c6d6ff80ff478',
    '6bfb914fd07eae6b',
    '',
    '',
    '62ec67f9c3a4a407fcb2a8c49031a8b3',
    'e037830e8389f27b025a2d6527e79d01'
  ],
  [
    'AES-128-EAX',
    '91945d3f4dcbee0bf45ef52255f095a4',
    'fa3bfd4806eb53fa',
    'f7fb',
    '19dd',
    'becaf043b0a23d843194ba972c66debd',
    '5c4c9331049d0bdab0277408f67967e5'
  ],
  [
    'AES-128-EAX',
    '01f74ad64077f2e704c0f60ada3dd523',
    '234a3463c1264ac6',
    '1a47cb4933',
    'd851d5bae0',
    '70c3db4f0d26368400a10ed05d2bff5e',
    '3a59f238a23e39199dc9266626c40f80'
  ],
  [
    'AES-128-EAX',
    'd07cf6cbb7f313bdde66b727afd3c5e8',
    '33cce2eabff5a79d',
    '481c9e39b1',
    '632a9d131a',
    '8408dfff3c1a2b1292dc199e46b7d617',
    'd4c168a4225d8e1ff755939974a7bede'
  ],
  [
    'AES-128-EAX',
    '35b6d0580005bbc12b0587124557d2c2',
    'aeb96eaebe2970e9',
    '40d0c07da5e4',
    '071dfe16c675',
    'fdb6b06676eedc5c61d74276e1f8e816',
    'cb0677e536f73afe6a14b74ee49844dd'
  ],
  [
    'AES-128-EAX',
    'bd8e6e11475e60b268784c38c62feb22',
    'd4482d1ca78dce0f',
    '4de3b35c3fc039245bd1fb7d',
    '835bb4f15d743e350e728414',
    '6eac5c93072d8e8513f750935e46da1b',
    'abb8644fd6ccb86947c5e10590210a4f'
  ],
  [
    'AES-128-EAX',
    '7c77d6e813bed5ac98baa417477a2e7d',
    '65d2017990d62528',
    '8b0a79306c9ce7ed99dae4f87f8dd61636',
    '02083e3979da014812f59f11d52630da30',
    '1a8c98dcd73d38393b2bf1569deefc19',
    '137327d10649b0aa6e1c181db617d7f2'
  ],
  [
    'AES-128-EAX',
    '5fff20cafab119ca2fc73549e20f5b0d',
    '54b9f04e6a09189a',
    '1bda122bce8a8dbaf1877d962b8592dd2d56',
    '2ec47b2c4954a489afc7ba4897edcdae8cc3',
    'dde59b97d722156d4d9aff2bc7559826',
    '3b60450599bd02c96382902aef7f832a'
  ],
  [
    'AES-128-EAX',
    'a4a4782bcffd3ec5e7ef6d8c34a56123',
    '899a175897561d7e',
    '6cf36720872b8513f6eab1a8a44438d5ef11',
    '0de18fd0fdd91e7af19f1d8ee8733938b1e8',
    'b781fcf2f75fa5a8de97a9ca48e522ec',
    'e7f6d2231618102fdb7fe55ff1991700'
  ],
  [
    'AES-128-EAX',
    '8395fcf1e95bebd697bd010bc766aac3',
    '126735fcc320d25a',
    'ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7',
    'cb8920f87a6c75cff39627b56e3ed197c552d295a7',
    '22e7add93cfc6393c57ec0b3c17d6b44',
    'cfc46afc253b4652b1af3795b124ab6e'
  ]
];

describe('EAX', function() {
  for (const [i, item] of mvectors.entries()) {
    const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
    const msg = Buffer.from(item[0], 'hex');
    const tag = Buffer.from(item[1], 'hex');

    it(`should pass cmac vector #${i + 1}`, () => {
      const cmac = new CMAC(new AES(128).init(key));

      cmac.init();
      cmac.update(msg);

      assert.bufferEqual(cmac.final(), tag);
    });
  }

  for (const [i, item] of vectors.entries()) {
    const alg = item[0];
    const key = Buffer.from(item[1], 'hex');
    const aad = Buffer.from(item[2], 'hex');
    const pt1 = Buffer.from(item[3], 'hex');
    const ct1 = Buffer.from(item[4], 'hex');
    const nonce = Buffer.from(item[5], 'hex');
    const tag = Buffer.from(item[6], 'hex');

    it(`should pass eax vector #${i + 1}`, () => {
      const c = new cipher.Cipher(alg);
      const d = new cipher.Decipher(alg);

      c.init(key, nonce);
      c.setAAD(aad);

      d.init(key, nonce);
      d.setAAD(aad);
      d.setAuthTag(tag);

      const ct2 = c.update(pt1);

      c.final();

      const mac = c.getAuthTag();

      assert.bufferEqual(mac, tag);
      assert.bufferEqual(ct2, ct1);

      const pt2 = d.update(ct1);

      d.final();

      assert.bufferEqual(pt2, pt1);
    });
  }
});
