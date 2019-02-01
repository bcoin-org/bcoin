'use strict';

const CoinView = require('../lib/coins/coinview');
const BufferReader = require('bufio').BufferReader;
const StaticWriter = require('bufio').StaticWriter;
const common = require('../test/util/common');
const bench = require('./bench');

const [tx, view] = common.readTX('tx3').getTX();

{
  const end = bench('serialize');

  for (let i = 0; i < 10000000; i++) {
    const bw = new StaticWriter(view.getSize(tx));
    view.toWriter(bw, tx).render();
  }

  end(10000000);
}

{
  const bw = new StaticWriter(view.getSize(tx));
  const raw = view.toWriter(bw, tx).render();

  const end = bench('parse');

  for (let i = 0; i < 10000000; i++) {
    const br = new BufferReader(raw);
    CoinView.fromReader(br, tx);
  }

  end(10000000);
}
