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

'use strict';

var assert = require('assert');
var bech32 = require('../lib/utils/bech32');
var Address = require('../lib/primitives/address');

describe('Bech32', function() {
  var VALID_CHECKSUM = [
    'A12UEL5L',
    'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
    'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
    '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
    'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w'
  ];

  var VALID_ADDRESS = [
    [
      'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
      new Buffer([
        0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
        0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
      ])
    ],
    [
      'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
      new Buffer([
        0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
        0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
        0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
        0x62
      ])
    ],
    [
      'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
      new Buffer([
        0x81, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
        0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
        0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
      ])
    ],
    [
      'BC1SW50QA3JX3S',
      new Buffer([
        0x90, 0x02, 0x75, 0x1e
      ])
    ],
    [
      'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
      new Buffer([
        0x82, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
        0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
      ])
    ],
    [
      'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
      new Buffer([
        0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
        0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
        0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
        0x33
      ])
    ]
  ];

  var INVALID_ADDRESS = [
    'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
    'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2',
    'bc1rw5uspcuh',
    'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
    'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
    'tb1pw508d6qejxtdg4y5r3zarqfsj6c3',
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv',
  ];

  function fromAddress(hrp, addr) {
    var dec = bech32.decode(addr);
    var data;

    if (dec.hrp !== hrp || dec.data.length < 1 || dec.data[0] > 16)
      throw new Error('Invalid bech32 prefix or data length.');

    data = bech32.bitsify(dec.data, 84, 5, 8, -1, 1);

    if (data.length < 2 || data.length > 40)
      throw new Error('Invalid witness program size.');

    if (dec.data[0] === 0 && data.length !== 20 && data.length !== 32)
      throw new Error('Malformed witness program.');

    return {
      version: dec.data[0],
      program: data
    };
  }

  function toAddress(hrp, version, program) {
    var data = bech32.bitsify(program, 65, 8, 5, version, 0);
    var ret = bech32.encode(hrp, data);

    fromAddress(hrp, ret);

    return ret;
  }

  function createProgram(version, program) {
    var ver = new Buffer([version ? version + 0x80 : 0, program.length]);
    return Buffer.concat([ver, program]);
  }

  VALID_CHECKSUM.forEach(function(test) {
    it('should have valid checksum for ' + test, function() {
      var ret = bech32.decode(test);
      assert(ret);
    });
  });

  VALID_ADDRESS.forEach(function(test) {
    var address = test[0];
    var scriptpubkey = test[1];
    it('should have valid address for ' + address, function() {
      var hrp = 'bc';
      var ret, ok, output, recreate;

      try {
        ret = fromAddress(hrp, address);
      } catch (e) {
        ret = null;
      }

      if (ret === null) {
        hrp = 'tb';
        try {
          ret = fromAddress(hrp, address);
        } catch (e) {
          ret = null;
        }
      }

      ok = ret !== null;

      if (ok) {
        output = createProgram(ret.version, ret.program);
        ok = output.compare(scriptpubkey) === 0;
      }

      if (ok) {
        recreate = toAddress(hrp, ret.version, ret.program);
        ok = (recreate === address.toLowerCase());
      }

      assert(ok);
    });
  });

  INVALID_ADDRESS.forEach(function(test) {
    it('should have invalid address for ' + test, function() {
      var ok1, ok2, ok;

      try {
        ok1 = fromAddress('bc', test);
      } catch (e) {
        ok1 = null;
      }

      try {
        ok2 = fromAddress('tb', test);
      } catch (e) {
        ok2 = null;
      }

      ok = ok1 === null && ok2 === null;
      assert(ok);
    });
  });

  VALID_ADDRESS.forEach(function(test, i) {
    var address = test[0];
    var scriptpubkey = test[1];

    // TODO: Fix. (wrong length for program)
    // Need to drop old segwit addrs.
    if (i >= 2 && i <= 4)
      return;

    it('should have valid address for ' + address, function() {
      var ret, ok, output, recreate;

      try {
        ret = Address.fromBech32(address, 'main');
      } catch (e) {
        ret = null;
      }

      if (ret === null) {
        try {
          ret = Address.fromBech32(address, 'testnet');
        } catch (e) {
          ret = null;
        }
      }

      ok = ret !== null;

      if (ok) {
        output = createProgram(ret.version, ret.hash);
        ok = output.compare(scriptpubkey) === 0;
      }

      if (ok) {
        recreate = ret.toBech32();
        ok = (recreate === address.toLowerCase());
      }

      assert(ok);
    });
  });

  INVALID_ADDRESS.forEach(function(test) {
    it('should have invalid address for ' + test, function() {
      var ok1, ok2, ok;

      try {
        ok1 = Address.fromBech32(test, 'main');
      } catch (e) {
        ok1 = null;
      }

      try {
        ok2 = Address.fromBech32(test, 'testnet');
      } catch (e) {
        ok2 = null;
      }

      assert(!ok2);
    });
  });
});
