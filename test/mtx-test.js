/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';
const assert = require('assert');

const { Outpoint, Coin } = require('../lib/primitives');
const { WalletKey } = require('../lib/wallet');
const Script = require('../lib/script/script');
const { MTX, Selector } = require('../lib/primitives/mtx');
const { policy } = require('../lib/protocol');

const compressed = true;
const network = 'main';

const alice = WalletKey.generate(compressed, network);

function dummyCoins(num = 500, value = 500) {
  let count = 0;
  const coins = [];

  while(count < num) {
    const cb = new MTX();
    cb.addInput({
      prevout: new Outpoint(),
      Script: new Script(),
      sequence: 0xffffffff
    });
    // dust output to alice
    cb.addOutput({
      address: alice.getAddress('string', network),
      value
    });
    coins.push(Coin.fromTX(cb, 0, 0));
    count++;
  }
  return coins;
}

describe('CoinSelector', () => {
  it('should select fill coins', async () => {
    const mtx = new MTX();

    mtx.addOutput({ value: 0, address: alice.getAddress('string', network)});

    let coins = dummyCoins();
    const selector = new Selector(mtx, {
      fill: true,
      select: 'value',
      rate: 500
    });

    let selected = await selector.select(coins);
    assert(selected.chosen.length, 'No coins were selected');

    // try and provide number of coins that would
    // push the weight over the limit
    while (selected.chosen.length === coins.length) {
      const newCoins = dummyCoins();
      coins = coins.concat(newCoins);
      selected = await selector.select(coins);
    }

    assert(
      selected.chosen.length !== coins.length,
      `Selector should stop selecting once coins cause weight
       to surpass policy limit`
    );
    const size = await selector.tx.estimateSize();
    assert(
      size > policy.MAX_TX_SIZE,
      `Selector's tx size should have exceeded size limit
       as indication that tx is filled`
    );
  });

  it('should only select fill coins up to value threshold', async () => {
    const threshold = 5000;
    const coinsAtThreshold = 5;

    const mtx = new MTX();
    mtx.addOutput({ value: 0, address: alice.getAddress('string', network)});

    let coins = dummyCoins();
    // add some coins at the threshold
    coins = coins.concat(dummyCoins(coinsAtThreshold, threshold));

    const selector = new Selector(mtx, {
      fill: true,
      rate: 500,
      threshold
    });

    const selected = await selector.select(coins);
    assert(
      coins.length - selected.chosen.length === coinsAtThreshold,
      'Coins w/ value at threshold should not be selected'
    );
  });

  it('should throw if threshold option but not reverseValue set', async () => {
    let coins = dummyCoins();
    const mtx = new MTX();
    mtx.addOutput({ value: 0, address: alice.getAddress('string', network)});

    let error;
    try {
      const selector = new Selector(mtx, { fill: true, threshold: 1000 });
      await selector.select(coins);
    } catch(e) {
      error = e;
    }

    assert(error instanceof Error, 'Expected it to throw an error');
  });
});

describe('MTX', () => {
  it('should fill with coins', async () => {
    const mtx = new MTX();

    mtx.addOutput({ value: 5000, address: alice.getAddress('string', network)});

    const smallCoin = { count: 500, value: 500 };
    const largeCoin = { count: 2000, value: 1000 };

    let coins = dummyCoins(smallCoin.count, smallCoin.value);
    const largerCoins = dummyCoins(largeCoin.count, largeCoin.value);
    // use coins with larger value to test prioritization
    coins = coins.concat(largerCoins);
    await mtx.fill(coins, {
      rate: 500,
      changeAddress: alice.getAddress('string', network)
    });

    assert(mtx.inputs.length, 'mtx did not fill with coins');
    assert(
      coins.length > mtx.inputs.length,
      'MTX filled with too many coins'
    );

    const weight = await mtx.getWeight();
    assert(
      weight <= policy.MAX_TX_WEIGHT,
      'Filled mtx should not exceed policy weight'
    );

    assert(
      mtx.inputs.length > smallCoin.count,
      'mtx didn\'t fill with all the smaller value coins'
    );
    let counter = 0;

    while (counter < smallCoin.count) {
      const prevout = mtx.view.getOutput(mtx.inputs[counter].prevout);
      assert(
        prevout.value === smallCoin.value,
        'fill should prioritize small coins'
      );
      counter++;
    }
  });
});

