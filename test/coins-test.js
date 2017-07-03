'use strict';

const assert = require('assert');
const Output = require('../lib/primitives/output');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');
const CoinView = require('../lib/coins/coinview');
const CoinEntry = require('../lib/coins/coinentry');
const StaticWriter = require('../lib/utils/staticwriter');
const BufferReader = require('../lib/utils/reader');
const parseTX = require('./util/common').parseTX;

const data = parseTX('data/tx1.hex');
const tx1 = data.tx;

function reserialize(coin) {
  let raw = coin.toRaw();
  let entry = CoinEntry.fromRaw(raw);
  entry.raw = null;
  return CoinEntry.fromRaw(entry.toRaw());
}

function deepCoinsEqual(a, b) {
  assert.strictEqual(a.version, b.version);
  assert.strictEqual(a.height, b.height);
  assert.strictEqual(a.coinbase, b.coinbase);
  assert.deepStrictEqual(a.raw, b.raw);
}

describe('Coins', function() {
  it('should instantiate coinview from tx', () => {
    let hash = tx1.hash('hex');
    let view = new CoinView();
    let prevout = new Outpoint(hash, 0);
    let input = Input.fromOutpoint(prevout);
    let coins, entry, output;

    view.addTX(tx1, 1);

    coins = view.get(hash);
    assert.equal(coins.outputs.length, tx1.outputs.length);

    entry = coins.get(0);
    assert(entry);
    assert(!entry.spent);

    assert.equal(entry.version, 1);
    assert.equal(entry.height, 1);
    assert.equal(entry.coinbase, false);
    assert.equal(entry.raw, null);
    assert(entry.output instanceof Output);
    assert.equal(entry.spent, false);

    output = view.getOutput(input);
    assert(output);

    deepCoinsEqual(entry, reserialize(entry));
  });

  it('should spend an output', () => {
    let hash = tx1.hash('hex');
    let view = new CoinView();
    let coins, entry, length;

    view.addTX(tx1, 1);

    coins = view.get(hash);
    assert(coins);
    length = coins.length();

    view.spendOutput(new Outpoint(hash, 0));

    coins = view.get(hash);
    assert(coins);

    entry = coins.get(0);
    assert(entry);
    assert(entry.spent);

    deepCoinsEqual(entry, reserialize(entry));
    assert.strictEqual(coins.length(), length);

    assert.equal(view.undo.items.length, 1);
  });

  it('should handle coin view', () => {
    let view = new CoinView();
    let i, tx, size, bw, br;
    let raw, res, prev, coins;

    for (i = 1; i < data.txs.length; i++) {
      tx = data.txs[i];
      view.addTX(tx, 1);
    }

    size = view.getSize(tx1);
    bw = new StaticWriter(size);
    raw = view.toWriter(bw, tx1).render();
    br = new BufferReader(raw);
    res = CoinView.fromReader(br, tx1);

    prev = tx1.inputs[0].prevout;
    coins = res.get(prev.hash);

    assert.strictEqual(coins.length(), 2);
    assert.strictEqual(coins.get(0), null);
    deepCoinsEqual(coins.get(1), reserialize(coins.get(1)));
  });
});
