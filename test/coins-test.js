/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Output = require('../lib/primitives/output');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');
const CoinView = require('../lib/coins/coinview');
const CoinEntry = require('../lib/coins/coinentry');
const StaticWriter = require('../lib/utils/staticwriter');
const BufferReader = require('../lib/utils/reader');
const common = require('./util/common');

const tx1 = common.readTX('tx1');

function reserialize(coin) {
  const raw = coin.toRaw();
  const entry = CoinEntry.fromRaw(raw);
  entry.raw = null;
  return CoinEntry.fromRaw(entry.toRaw());
}

function deepCoinsEqual(a, b) {
  assert.strictEqual(a.version, b.version);
  assert.strictEqual(a.height, b.height);
  assert.strictEqual(a.coinbase, b.coinbase);
  assert.bufferEqual(a.raw, b.raw);
}

describe('Coins', function() {
  it('should instantiate coinview from tx', () => {
    const [tx] = tx1.getTX();
    const hash = tx.hash('hex');
    const view = new CoinView();
    const prevout = new Outpoint(hash, 0);
    const input = Input.fromOutpoint(prevout);

    view.addTX(tx, 1);

    const coins = view.get(hash);
    assert.strictEqual(coins.outputs.size, tx.outputs.length);

    const entry = coins.get(0);
    assert(entry);

    assert.strictEqual(entry.version, 1);
    assert.strictEqual(entry.height, 1);
    assert.strictEqual(entry.coinbase, false);
    assert.strictEqual(entry.raw, null);
    assert.instanceOf(entry.output, Output);
    assert.strictEqual(entry.spent, false);

    const output = view.getOutputFor(input);
    assert(output);

    deepCoinsEqual(entry, reserialize(entry));
  });

  it('should spend an output', () => {
    const [tx] = tx1.getTX();
    const hash = tx.hash('hex');
    const view = new CoinView();

    view.addTX(tx, 1);

    const coins = view.get(hash);
    assert(coins);

    const length = coins.outputs.size;

    view.spendEntry(new Outpoint(hash, 0));

    assert.strictEqual(view.get(hash), coins);

    const entry = coins.get(0);
    assert(entry);
    assert(entry.spent);

    deepCoinsEqual(entry, reserialize(entry));
    assert.strictEqual(coins.outputs.size, length);

    assert.strictEqual(view.undo.items.length, 1);
  });

  it('should handle coin view', () => {
    const [tx, view] = tx1.getTX();

    const size = view.getSize(tx);
    const bw = new StaticWriter(size);
    const raw = view.toWriter(bw, tx).render();
    const br = new BufferReader(raw);
    const res = CoinView.fromReader(br, tx);

    const prev = tx.inputs[0].prevout;
    const coins = res.get(prev.hash);

    assert.strictEqual(coins.outputs.size, 1);
    assert.strictEqual(coins.get(0), null);
    deepCoinsEqual(coins.get(1), reserialize(coins.get(1)));
  });
});
