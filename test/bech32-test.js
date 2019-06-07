// Parts of this software are based on "bech32".
// https://github.com/sipa/bech32
//
// Copyright (c) 2017 Pieter Wuille
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Address = require('../lib/primitives/address');

// see https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
// for test vectors, they include both the valid and invalid addresses

const validAddresses = [
  [
    'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
    Buffer.from([
      0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
      0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
    ])
  ],
  [
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
    Buffer.from([
      0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
      0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
      0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
      0x62
    ])
  ],
  [
    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw50'
    + '8d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
    Buffer.from([
      0x81, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
      0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
      0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
      0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
    ])
  ],
  [
    'BC1SW50QA3JX3S',
    Buffer.from([
      0x90, 0x02, 0x75, 0x1e
    ])
  ],
  [
    'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
    Buffer.from([
      0x82, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
      0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
    ])
  ],
  [
    'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
    Buffer.from([
      0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
      0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
      0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
      0x33
    ])
  ]
];

const invalidAddresses = [
  // invalid hrp
  'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty',
  // invalid checksum
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
  // invalid witness version
  'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2',
  // invalid program length
  'bc1rw5uspcuh',
  // invalid program length
  'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d'
  + '6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
  // invalid program length for witness version 0
  'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
  // mixed case
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
  // zero padding of more than 4 bits
  'tb1pw508d6qejxtdg4y5r3zarqfsj6c3',
  // non zero padding in 8 to 5 conversion
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv',
  // empty data section
  'bc1gmk9yu'
];

function createProgram(version, program) {
  const data = Buffer.allocUnsafe(2 + program.length);
  data[0] = version ? version + 0x80 : 0;
  data[1] = program.length;
  program.copy(data, 2);
  return data;
}

describe('Bech32', function() {
  for (const [addr, script] of validAddresses) {
    it(`should have valid address for ${addr}`, () => {
      let ret = null;
      let network = null;

      try {
        network = 'main';
        ret = Address.fromBech32(addr, network);
      } catch (e) {
        ret = null;
      }

      if (ret === null) {
        try {
          network = 'testnet';
          ret = Address.fromBech32(addr, network);
        } catch (e) {
          ret = null;
        }
      }

      assert(ret !== null);

      const output = createProgram(ret.version, ret.hash);
      assert.bufferEqual(output, script);

      const recreate = ret.toBech32(network);
      assert.strictEqual(recreate, addr.toLowerCase());
    });
  }

  for (const addr of invalidAddresses) {
    it(`should have invalid address for ${addr}`, () => {
      assert.throws(() => Address.fromBech32(addr, 'main'));
      assert.throws(() => Address.fromBech32(addr, 'testnet'));
    });
  }
});
