'use strict';

const assert = require('bsert');
const bech32m = require('../lib/encoding/bech32m');
const bech32 = require('../lib/encoding/bech32');

// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#test-vectors
const validStrings = [
  'A1LQFN3A',
  'a1lqfn3a',
  'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
  'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
  '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
  'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
  '?1v759aa'
];

const invalidStrings = [
  '\x201xj0phk',
  '\x7F1g6xzxy',
  '\x801vctc34',
  'an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4',
  'qyrz8wqd2c9m',
  '1qyrz8wqd2c9m',
  'y1b0jsk6g',
  'lt1igcx5c0',
  'in1muywd',
  'mm1crxm3i',
  'au1s5cgom',
  'M1VUXWEZ',
  '16plkw9',
  '1p2gdwpf'
];

// bech32 and bech32m
const validAddresses = [
  ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
  ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
  ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'],
  ['BC1SW50QGDZ25J', '6002751e'],
  ['bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', '5210751e76e8199196d454941c45d1b3a323'],
  ['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
  ['tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c', '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798']
];

const invalidAddresses = [
  'tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut',
  'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
  'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf',
  'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
  'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47',
  'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
  'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
  'bc1pw5dgrnzv',
  'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
  'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
  'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq',
  'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
  'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j',
  'bc1gmk9yu'
];

describe('Bech32m', function() {
  for (const str of validStrings) {
    const text = str.slice(0, 32) + '...';

    it(`should have valid string for ${text}`, () => {
      const [hrp, data] = bech32m.deserialize(str);
      assert(hrp);
      assert(data);
      assert(bech32m.is(str));
    });
  }

  for (const str of invalidStrings) {
    const text = str.slice(0, 32).replace(/[^\w]/g, '') + '...';

    it(`should have invalid string for ${text}`, () => {
      assert.throws(() => bech32m.deserialize(str));
      assert(!bech32m.is(str));
    });
  }

  for (const [addr, expected] of validAddresses) {
    const text = addr.slice(0, 32) + '...';

    it(`should have valid address for ${text}`, () => {
        const program = (version, script) => {
          const data = Buffer.alloc(2 + script.length);
          // Bitcoin PUSH opcodes > 0 start at 0x50
          data[0] = version ? version + 0x50 : 0;
          data[1] = script.length;
          script.copy(data, 2);
          return data.toString('hex');
        };

      if (bech32m.test(addr)) {
        const [hrp, version, script] = bech32m.decode(addr);

        assert(hrp !== null);
        assert(version !== 0);
        assert.strictEqual(program(version, script), expected);
      } else {
        assert(bech32.test(addr));
        const [hrp, version, script] = bech32.decode(addr);

        assert(hrp !== null);
        assert(version === 0);
        assert.strictEqual(program(version, script), expected);
      }
    });
  }

  for (const addr of invalidAddresses) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => {
        if (bech32.is(addr)) {
          const [hrp, version, script] = bech32.decode(addr);
          assert(hrp === 'bc' || hrp === 'tb');
          assert(version === 0);
          assert(script.length === 20 || script.length === 32);
        }

        if (bech32m.is(addr)) {
          const [hrp, version, script] = bech32m.decode(addr);
          assert(hrp === 'bc' || hrp === 'tb');
          assert(version !== 0);
          assert(script.length >= 2 || script.length <= 40);
        }

        assert(false);
      });
    });
  }
});
