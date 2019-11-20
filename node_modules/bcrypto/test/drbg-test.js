/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

// See:
// https://github.com/indutny/hmac-drbg/blob/master/test/drbg-test.js

'use strict';

const assert = require('bsert');
const DRBG = require('../lib/drbg');
const SHA256 = require('../lib/sha256');
const vectors = require('./data/drbg-nist.json');

describe('DRBG', function() {
  it('should support hmac-drbg-sha256', () => {
    function doDrbg(opt) {
      const entropy = Buffer.from(opt.entropy || '', 'utf8');
      const nonce = Buffer.from(opt.nonce || '', 'utf8');
      const pers = Buffer.from(opt.pers || '', 'utf8');
      const size = opt.size;
      const expect = Buffer.from(opt.res, 'hex');
      const drbg = new DRBG(SHA256, entropy, nonce, pers);

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
        const drbg = new DRBG(SHA256, entropy, nonce, pers);

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

      const original = new DRBG(
        SHA256,
        Buffer.from(entropy, 'utf8'),
        Buffer.from(nonce, 'utf8'),
        Buffer.from(pers, 'utf8')
      );

      const reseeded = new DRBG(
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
});
