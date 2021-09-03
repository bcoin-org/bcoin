'use strict';

const assert = require('bsert');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const HmacDRBG = require('../lib/hmac-drbg');
const HashDRBG = require('../lib/hash-drbg');
const CtrDRBG = require('../lib/ctr-drbg');
const vectors = require('./data/drbg-nist.json');
const getNIST = require('./util/drbg-vectors');

const engines = [
  ['hash', HashDRBG],
  ['hmac', HmacDRBG]
];

const hashes = [
  ['SHA-1', SHA1],
  ['SHA-224', SHA224],
  ['SHA-256', SHA256],
  ['SHA-384', SHA384],
  ['SHA-512', SHA512]
];

describe('DRBG', function() {
  it('should support hmac-drbg-sha256', () => {
    function doDrbg(opt) {
      const entropy = Buffer.from(opt.entropy || '', 'utf8');
      const nonce = Buffer.from(opt.nonce || '', 'utf8');
      const pers = Buffer.from(opt.pers || '', 'utf8');
      const size = opt.size;
      const expect = Buffer.from(opt.res, 'hex');
      const drbg = new HmacDRBG(SHA256, entropy, nonce, pers);

      assert.bufferEqual(drbg.generate(size), expect);
    }

    const tests = [
      {
        entropy: 'totally random0123456789',
        nonce: 'secret nonce',
        pers: 'my drbg',
        size: 32,
        res: '018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a157'
      },
      {
        entropy: 'totally random0123456789',
        nonce: 'secret nonce',
        pers: null,
        size: 32,
        res: 'ed5d61ecf0ef38258e62f03bbb49f19f2cd07ba5145a840d83b134d5963b3633'
      }
    ];

    for (const test of tests)
      doDrbg(test);
  });

  describe('NIST vector', function() {
    for (const opt of vectors) {
      const entropy = Buffer.from(opt.entropy || '', 'hex');
      const nonce = Buffer.from(opt.nonce || '', 'hex');
      const pers = Buffer.from(opt.pers || '', 'hex');
      const expected = Buffer.from(opt.expected, 'hex');

      it(`should not fail at ${opt.name}`, () => {
        const drbg = new HmacDRBG(SHA256, entropy, nonce, pers);

        let last = null;

        for (let i = 0; i < opt.add.length; i++) {
          let add = opt.add[i];

          if (add)
            add = Buffer.from(add, 'hex');

          last = drbg.generate(expected.length, add);
        }

        assert(last);
        assert.bufferEqual(last, expected);
      });
    }
  });

  describe('reseeding', function() {
    it('should reseed', () => {
      const entropy = 'totally random string with'
        + ' many chars that I typed in agony';
      const nonce = 'nonce';
      const pers = 'pers';

      const original = new HmacDRBG(
        SHA256,
        Buffer.from(entropy, 'utf8'),
        Buffer.from(nonce, 'utf8'),
        Buffer.from(pers, 'utf8')
      );

      const reseeded = new HmacDRBG(
        SHA256,
        Buffer.from(entropy, 'utf8'),
        Buffer.from(nonce, 'utf8'),
        Buffer.from(pers, 'utf8')
      );

      assert.bufferEqual(original.generate(32), reseeded.generate(32));

      reseeded.reseed(Buffer.from('another absolutely random string', 'utf8'));

      assert.notBufferEqual(original.generate(32), reseeded.generate(32));
    });
  });

  for (const [type, DRBG] of engines) {
    describe(DRBG.name, function() {
      for (const [name, alg] of hashes) {
        const vectors = getNIST(type, name);

        for (const [i, vector] of vectors.entries()) {
          it(`should pass ${name} NIST vector #${i + 1} (${type})`, () => {
            const drbg = new DRBG(alg);

            drbg.init(vector.EntropyInput, vector.Nonce,
                      vector.PersonalizationString);

            drbg.reseed(vector.EntropyInputReseed,
                        vector.AdditionalInputReseed);

            drbg.generate(vector.ReturnedBits.length,
                          vector.AdditionalInput[0]);

            const result = drbg.generate(vector.ReturnedBits.length,
                                         vector.AdditionalInput[1]);

            assert.bufferEqual(result, vector.ReturnedBits);
          });
        }
      }
    });
  }

  describe('CtrDRBG', function() {
    for (const df of [false, true]) {
      for (const id of ['AES-128', 'AES-192', 'AES-256']) {
        const name = id + (df ? ' use df' : ' no df');
        const vectors = getNIST('ctr', name);
        const bits = id.slice(-3) | 0;

        for (const [i, vector] of vectors.entries()) {
          it(`should pass ${name} NIST vector #${i + 1} (ctr,df=${df})`, () => {
            const drbg = new CtrDRBG(bits, df);

            drbg.init(vector.EntropyInput, vector.Nonce,
                      vector.PersonalizationString);

            drbg.reseed(vector.EntropyInputReseed,
                        vector.AdditionalInputReseed);

            drbg.generate(vector.ReturnedBits.length,
                          vector.AdditionalInput[0]);

            const result = drbg.generate(vector.ReturnedBits.length,
                                         vector.AdditionalInput[1]);

            assert.bufferEqual(result, vector.ReturnedBits);
          });
        }
      }
    }
  });
});
