/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const Coin = require('../lib/primitives/coin');
const assert = require('bsert');
const common = require('../test/util/common');
const nodejsUtil = require('util');

const tx1 = common.readTX('tx1');
const coin1 = common.readFile('coin1.raw');

describe('Coin', function() {
  it('should instantiate from tx', () => {
    const [tx] = tx1.getTX();
    const coin = Coin.fromTX(tx, 0, 0);

    assert.strictEqual(coin.getAddress().toString(),
      '3KUER9kZ693d5FQgvmr5qNDKnSpP9nXv9v');
    assert.strictEqual(coin.value, 5000000);
    assert.strictEqual(coin.getType(), 'multisig');
    assert.strictEqual(coin.version, 1);
    assert.strictEqual(coin.height, 0);
    assert.strictEqual(coin.coinbase, false);
    assert.strictEqual(coin.txid(),
      'ff80fe4937e2de16411c3a2bc534d661dc8b4f8aad75e6fbc4b1ec6060d9ef1c');
    assert.strictEqual(coin.index, 0);
  });

  it('should instantiate from raw', () => {
    const coin = Coin.fromRaw(coin1);

    assert.strictEqual(coin.getAddress().toString(),
      '3KUER9kZ693d5FQgvmr5qNDKnSpP9nXv9v');
    assert.strictEqual(coin.value, 5000000);
    assert.strictEqual(coin.getType(), 'multisig');
    assert.strictEqual(coin.version, 1);
    assert.strictEqual(coin.height, 0);
    assert.strictEqual(coin.coinbase, false);
    assert.strictEqual(coin.index, 0);
  });

  it('should inspect Coin', () => {
    const coin = new Coin();
    const fmt = nodejsUtil.format(coin);
    assert(typeof fmt === 'string');
    assert(fmt.includes('coinbase'));
    assert(fmt.includes('script'));
  });
});
