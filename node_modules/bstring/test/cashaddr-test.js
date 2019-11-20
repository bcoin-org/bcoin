// Copyright (c) 2018 the bcoin developers
//
// Parts of this software are based on "CashAddr".
// https://github.com/Bitcoin-ABC/bitcoin-abc
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
const base58 = require('../lib/base58');

const cashaddrc = require('../lib/cashaddr');
const cashaddrjs = require('../lib/cashaddr-browser');

const {
  p2pkh: addressTranslationP2PKH,
  p2sh: addressTranslationP2SH
} = require('./data/cashaddrlegacy.json');
const testSizeVectors = require('./data/cashaddrsizes.json');
const invalidDecodeVectors = require('./data/cashaddrinvaliddecode.json');
const invalidEncodeVectors = require('./data/cashaddrinvalidencode.json');
const validEdgeVectors = require('./data/cashaddredge.json');

function testCashAddr(cashaddr) {
  describe('encoding', function() {
    for (const test of testSizeVectors) {
      it(`should encode address ${test.addr} (${test.bytes} bytes)`, () => {
        const addr = cashaddr.encode(
          test.prefix, test.type, Buffer.from(test.hash, 'hex'));
        assert.strictEqual(addr, test.addr);
      });

      it(`should decode address ${test.addr} (${test.bytes} bytes)`, () => {
        const { type, prefix, hash } = cashaddr.decode(test.addr, test.prefix);
        assert.strictEqual(type, test.type);
        assert.strictEqual(prefix, test.prefix);
        assert.bufferEqual(hash, Buffer.from(test.hash, 'hex'));
      });
    }
  });

  describe('translation', function() {
    for (const translation of addressTranslationP2PKH) {
      it(`should translate base58 P2PKH for ${translation.legacy}`, () => {
        const hash = base58.decode(translation.legacy).slice(1, -4);

        const prefix = 'bitcoincash';
        const type = 0;
        const addr = cashaddr.encode(prefix, type, hash);

        assert.strictEqual(addr, translation.cashaddr);
      });
    }

    for (const translation of addressTranslationP2SH) {
      it(`should translate base58 P2SH for ${translation.legacy}`, () => {
        const hash = base58.decode(translation.legacy).slice(1, -4);

        const prefix = 'bitcoincash';
        const type = 1;
        const addr = cashaddr.encode(prefix, type, hash);

        assert.strictEqual(addr, translation.cashaddr);
      });
    }

    for (const addrinfo of addressTranslationP2PKH) {
      it(`should decode P2PKH for ${addrinfo.cashaddr}`, () => {
        const addr = addrinfo.cashaddr;
        const results = cashaddr.decode(addr);

        assert.strictEqual(results.prefix, 'bitcoincash');
        assert.strictEqual(results.type, 0);
        assert.bufferEqual(results.hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should encode P2PKH for ${addrinfo.cashaddr}`, () => {
        const addr = cashaddr.encode(
          'bitcoincash', 0, Buffer.from(addrinfo.hash, 'hex'));

        assert.strictEqual(addr, addrinfo.cashaddr);
      });
    }

    for (const addrinfo of addressTranslationP2SH) {
      it(`should decode P2SH for ${addrinfo.cashaddr}`, () => {
        const addr = addrinfo.cashaddr;
        const results = cashaddr.decode(addr);

        assert.strictEqual(results.prefix, 'bitcoincash');
        assert.strictEqual(results.type, 1);
        assert.bufferEqual(results.hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should encode P2SH for ${addrinfo.cashaddr}`, () => {
        const addr = cashaddr.encode(
          'bitcoincash', 1, Buffer.from(addrinfo.hash, 'hex'));

        assert.strictEqual(addr, addrinfo.cashaddr);
      });
    }

    for (const addrinfo of addressTranslationP2PKH) {
      it(`should decode P2PKH with prefix ${addrinfo.cashaddr}`, () => {
        const defaultPrefix = 'bitcoincash';
        const addr = addrinfo.cashaddr.split(':')[1];
        const results = cashaddr.decode(addr, defaultPrefix);

        assert.strictEqual(results.prefix, 'bitcoincash');
        assert.strictEqual(results.type, 0);
        assert.bufferEqual(results.hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should decode P2PKH with default prefix ${addrinfo.cashaddr}`, () => {
        const addr = addrinfo.cashaddr.split(':')[1];
        const results = cashaddr.decode(addr);

        assert.strictEqual(results.prefix, 'bitcoincash');
        assert.strictEqual(results.type, 0);
        assert.bufferEqual(results.hash, Buffer.from(addrinfo.hash, 'hex'));
      });
    }

    for (const addrinfo of addressTranslationP2SH) {
      it(`should decode P2Sh with prefix ${addrinfo.cashaddr}`, () => {
        const defaultPrefix = 'bitcoincash';
        const addr = addrinfo.cashaddr.split(':')[1];
        const results = cashaddr.decode(addr, defaultPrefix);

        assert.strictEqual(results.prefix, 'bitcoincash');
        assert.strictEqual(results.type, 1);
        assert.bufferEqual(results.hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should decode P2Sh with default prefix ${addrinfo.cashaddr}`, () => {
        const addr = addrinfo.cashaddr.split(':')[1];
        const results = cashaddr.decode(addr);

        assert.strictEqual(results.prefix, 'bitcoincash');
        assert.strictEqual(results.type, 1);
        assert.bufferEqual(results.hash, Buffer.from(addrinfo.hash, 'hex'));
      });
    }
  });

  describe('invalid decoding', function() {
    for (const addrinfo of invalidDecodeVectors) {
      it(`"${addrinfo.reason}" w/ invalid address ${addrinfo.addr}`, () => {
        let err;

        try {
          cashaddr.decode(addrinfo.addr, addrinfo.prefix);
        } catch(e) {
          err = e;
        }
        assert(err, 'Exception error missing.');
        assert.strictEqual(err.message, addrinfo.reason);
      });
    }
  });

  describe('invalid encoding', function() {
    for (const test of invalidEncodeVectors) {
      it(`"${test.reason}" (${test.note})`, () => {
        let err;
        try {
          cashaddr.encode(
            test.prefix, test.type, Buffer.from(test.hash, 'hex'));
        } catch(e) {
          err = e;
        }
        assert(err, 'Exception error missing.');
        assert.strictEqual(err.message, test.reason);
      });
    }
  });

  describe('valid edge cases', function() {
    for (const test of validEdgeVectors) {
      it(`encode ${test.note} with address: ${test.addr}`, () => {
        const addr = cashaddr.encode(
          test.prefix, test.type, Buffer.from(test.hash, 'hex'));
        assert.strictEqual(addr, test.addr.toLowerCase());
      });

      it(`decode ${test.note} with address: ${test.addr}`, () => {
        const { type, prefix, hash } = cashaddr.decode(
          test.addr, test.prefix.toLowerCase());
        assert.strictEqual(type, test.type);
        assert.strictEqual(prefix.toLowerCase(), test.prefix.toLowerCase());
        assert.bufferEqual(hash, Buffer.from(test.hash, 'hex'));
      });

      it(`roundtrip ${test.note} with address: ${test.addr}`, () => {
        const addr = cashaddr.encode(
          test.prefix, test.type, Buffer.from(test.hash, 'hex'));
        assert.strictEqual(addr, test.addr.toLowerCase());
        const { type, prefix, hash } = cashaddr.decode(
          test.addr, test.prefix.toLowerCase());
        assert.strictEqual(type, test.type);
        assert.strictEqual(prefix.toLowerCase(), test.prefix.toLowerCase());
        assert.bufferEqual(hash, Buffer.from(test.hash, 'hex'));
      });
    }
  });
}

describe('cashaddr', function() {
  describe('native', function() {
    testCashAddr(cashaddrc);
  });

  describe('browser', function() {
    testCashAddr(cashaddrjs);
  });
});
