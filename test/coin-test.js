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

  it('should validate input types', function() {
    assert.throws(() => new Coin().fromOptions({ version: '1' }));
    assert.throws(() => new Coin().fromOptions({ height: -2 }));
    assert.throws(() => new Coin().fromOptions({ value: -1 }));
    assert.throws(() => new Coin().fromOptions({ coinbase: 'true' }));
    assert.throws(() => new Coin().fromOptions({ hash: 'abc' }));
    assert.throws(() => new Coin().fromOptions({ index: -1 }));
  });

  it('should correctly calculate depth', () => {
    const coin = new Coin({
      version: 1,
      height: 100,
      value: 5000000000,
      script: Buffer.from('76a91476a04053bda0a88bda5177b86a15c3b29f5598788ac', 'hex'),
      coinbase: false,
      hash: Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
      index: 0
    });

    assert.strictEqual(coin.getDepth(99), 0);
    assert.strictEqual(coin.getDepth(100), 1);
    assert.strictEqual(coin.getDepth(101), 2);
  });

  it('should correctly serialize and deserialize to/from JSON', () => {
    const coin = new Coin({
      version: 1,
      height: 100,
      value: 5000000000,
      script: Buffer.from('76a91476a04053bda0a88bda5177b86a15c3b29f5598788ac', 'hex'),
      coinbase: false,
      hash: Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
      index: 0
    });

    const json = coin.toJSON();
    const coin2 = Coin.fromJSON(json);

    assert.deepStrictEqual(coin.toRaw(), coin2.toRaw());
  });


  it('should create a coin from options', function() {
    const options = {
      version: 1,
      height: 42,
      value: 1000000,
      script: Buffer.from('a914d7f6d1c6e2d6eeb2ae2f88a52f032cbbf5e5b5c987', 'hex'),
      coinbase: false,
      hash: Buffer.from('0'.repeat(64), 'hex'),
      index: 0
    };

    const coin = Coin.fromOptions(options);

    assert.strictEqual(coin.version, options.version);
    assert.strictEqual(coin.height, options.height);
    assert.strictEqual(coin.value, options.value);
    assert.deepStrictEqual(coin.script.toRaw(), options.script);
    assert.strictEqual(coin.coinbase, options.coinbase);
    assert.deepStrictEqual(coin.hash, options.hash);
    assert.strictEqual(coin.index, options.index);
  });
});
