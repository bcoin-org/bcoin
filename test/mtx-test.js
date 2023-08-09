/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const CoinView = require('../lib/coins/coinview');
const WalletCoinView = require('../lib/wallet/walletcoinview');
const MTX = require('../lib/primitives/mtx');
const Path = require('../lib/wallet/path');
const Address = require('../lib/primitives/address');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');

const mtx1json = require('./data/mtx1.json');
const mtx2json = require('./data/mtx2.json');
const mtx1 = MTX.fromJSON(mtx1json);
const mtx2 = MTX.fromJSON(mtx2json);

describe('MTX', function () {
  it('should serialize wallet coin view', () => {
    const json = mtx1.getJSON('regtest');
    const got = json.inputs[0].path;
    const want = {
      name: 'default',
      account: 0,
      change: false,
      derivation: 'm/44\'/1\'/0\'/0/0'
    };

    assert.deepStrictEqual(got, want);
  });

  it('should deserialize wallet coin view', () => {
    const view = mtx1.view;
    const input = mtx1.inputs[0];
    const got = view.getPathFor(input);
    const want = new Path();
    want.name = 'default';
    want.account = 0;
    want.branch = 0;
    want.index = 0;

    assert.ok(view instanceof WalletCoinView);
    assert.deepStrictEqual(got, want);
  });

  it('should serialize coin view', () => {
    const json = mtx2.getJSON('regtest');
    const got = json.inputs[0].path;
    const want = undefined;

    assert.deepStrictEqual(got, want);
  });

  it('should deserialize coin view', () => {
    const view = mtx2.view;
    const input = mtx2.inputs[0];
    const got = view.getPathFor(input);
    const want = null;

    assert.ok(view instanceof CoinView);
    assert.deepStrictEqual(got, want);
  });

  it('should en/decode mtx with 1 in, 1 out', () => {
    const input = new Input({
      prevout: {
        hash: Buffer.alloc(32),
        index: 0
      }
    });
    const output = new Output({
      value: 1e8,
      address: new Address()
    });
    const mtx1 = new MTX({
      inputs: [input],
      outputs: [output]
    });
    const mtx2 = MTX.fromRaw(mtx1.toRaw());
    assert.deepStrictEqual(mtx1, mtx2);
  });

  it('should en/decode mtx with 0 in, 1 out', () => {
    const output = new Output({
      value: 1e8,
      address: new Address()
    });
    const mtx1 = new MTX({
      outputs: [output]
    });
    const mtx2 = MTX.fromRaw(mtx1.toRaw());
    assert.deepStrictEqual(mtx1, mtx2);
  });
});
