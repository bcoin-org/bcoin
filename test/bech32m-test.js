'use strict';

const assert = require('bsert');
const Address = require('../lib/primitives/address');

// see https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
// for test vectors, they include both the valid and invalid addresses

const validAddresses = [
    [
        'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y',
        Buffer.from([
          0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
          0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
          0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
          0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        ])
    ],
    [
        'BC1SW50QGDZ25J',
        Buffer.from([
          0x60, 0x02, 0x75, 0x1e
        ])
    ],
    [
        'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs',
        Buffer.from([
          0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
          0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
        ])
    ],
    [
        'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c',
        Buffer.from([
          0x51, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
          0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
          0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
          0x33
        ])
    ],
    [
        'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
        Buffer.from([
          0x51, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55,
          0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb,
          0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
          0x98
        ])
    ]
];

const invalidAddresses = [
  // invalid hrp
  'tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut',
  // invalid checksum (Bech32 instead of Bech32m)
  'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
  // invalid checksum (Bech32 instead of Bech32m)
  'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf',
  // invalid checksum (Bech32 instead of Bech32m)
  'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
  // invalid checksum (Bech32m instead of Bech32)
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
  // invalid checksum (Bech32m instead of Bech32)
  'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47',
  // invalid character in checksum
  'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
  // invalid witness version
  'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
  // invalid program length (1 byte)
  'bc1pw5dgrnzv',
  // invalid program length (41 bytes)
  'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
  // invalid program length for witness version 0
  'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
  // mixed case
  'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq',
  // zero padding of more than 4 bits
  'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf',
  // non-zero padding in 8-to-5 conversion
  'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j',
  // empty data section
  'bc1gmk9yu'
];

function createProgram(version, program) {
  const data = Buffer.allocUnsafe(2 + program.length);
  data[0] = version ? version + 0x50 : 0;
  data[1] = program.length;
  program.copy(data, 2);
  return data;
}

describe('Bech32m', function() {
  for (const [addr, script] of validAddresses) {
    it(`should have valid address for ${addr}`, () => {
      let ret = null;
      let network = null;

      try {
        network = 'main';
        ret = Address.fromBech32m(addr, network);
      } catch (e) {
        ret = null;
      }

      if (ret === null) {
        try {
          network = 'testnet';
          ret = Address.fromBech32m(addr, network);
        } catch (e) {
          ret = null;
        }
      }

      assert(ret !== null);

      const output = createProgram(ret.version, ret.hash);
      assert.bufferEqual(output, script);

      const recreate = ret.toBech32m(network);
      assert.strictEqual(recreate, addr.toLowerCase());
    });
  }

  for (const addr of invalidAddresses) {
    it(`should have invalid address for ${addr}`, () => {
      assert.throws(() => Address.fromBech32m(addr, 'main'));
      assert.throws(() => Address.fromBech32m(addr, 'testnet'));
    });
  }
});
