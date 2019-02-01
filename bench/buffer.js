'use strict';

const BufferWriter = require('bufio').BufferWriter;
const StaticWriter = require('bufio').StaticWriter;
const common = require('../test/util/common');
const bench = require('./bench');

const tx5 = common.readTX('tx5');

{
  const [tx] = tx5.getTX();
  const end = bench('serialize (static-writer)');
  for (let i = 0; i < 10000; i++) {
    tx.refresh();
    const {size} = tx.getWitnessSizes();
    const bw = new StaticWriter(size);
    tx.toWriter(bw);
    bw.render();
  }
  end(10000);
}

{
  const [tx] = tx5.getTX();
  const end = bench('serialize (buffer-writer)');
  for (let i = 0; i < 10000; i++) {
    tx.refresh();
    const bw = new BufferWriter();
    tx.toWriter(bw);
    bw.render();
  }
  end(10000);
}
