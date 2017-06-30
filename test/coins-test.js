'use strict';

const assert = require('assert');
const Output = require('../lib/primitives/output');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');
const CoinView = require('../lib/coins/coinview');
const Coins = require('../lib/coins/coins');
const StaticWriter = require('../lib/utils/staticwriter');
const BufferReader = require('../lib/utils/reader');
const parseTX = require('./util/common').parseTX;

let data = parseTX('data/tx1.hex');
let tx1 = data.tx;

function collect(coins) {
  let outputs = [];
  let i;

  for (i = 0; i < coins.outputs.length; i++) {
    if (!coins.isUnspent(i))
      continue;
    outputs.push(coins.getOutput(i));
  }

  return outputs;
}

function reserialize(coins) {
  let raw = coins.toRaw();
  return Coins.fromRaw(raw);
}

function deepCoinsEqual(a, b) {
  assert(a.outputs.length > 0);
  assert(b.outputs.length > 0);

  assert.strictEqual(a.version, b.version);
  assert.strictEqual(a.height, b.height);
  assert.strictEqual(a.coinbase, b.coinbase);
  assert.strictEqual(a.length(), b.length());
  assert.deepStrictEqual(collect(a), collect(b));
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

    assert.equal(coins.version, 1);
    assert.equal(coins.height, 1);
    assert.equal(coins.coinbase, false);
    assert.equal(coins.outputs.length, tx1.outputs.length);

    entry = coins.get(0);
    assert(entry);
    assert(!entry.spent);

    assert.equal(entry.offset, 0);
    assert.equal(entry.size, 0);
    assert.equal(entry.raw, null);
    assert(entry.output instanceof Output);
    assert.equal(entry.spent, false);

    output = view.getOutput(input);
    assert(output);

    deepCoinsEqual(coins, reserialize(coins));
  });

  it('should spend an output', () => {
    let hash = tx1.hash('hex');
    let view = new CoinView();
    let coins, entry, length;

    view.addTX(tx1, 1);

    coins = view.get(hash);
    assert(coins);
    length = coins.length();

    view.spendOutput(hash, 0);

    coins = view.get(hash);
    assert(coins);

    entry = coins.get(0);
    assert(entry);
    assert(entry.spent);

    deepCoinsEqual(coins, reserialize(coins));
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

    size = view.getFastSize(tx1);
    bw = new StaticWriter(size);
    raw = view.toFast(bw, tx1).render();
    br = new BufferReader(raw);
    res = CoinView.fromFast(br, tx1);

    prev = tx1.inputs[0].prevout;
    coins = res.get(prev.hash);

    assert.deepStrictEqual(coins.get(0), reserialize(coins).get(0));
  });
});
