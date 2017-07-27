'use strict';

const fs = require('fs');
const TX = require('../lib/primitives/tx');
const BufferWriter = require('../lib/utils/writer');
const StaticWriter = require('../lib/utils/staticwriter');
const bench = require('./bench');

const hex = fs.readFileSync(`${__dirname}/../test/data/wtx.hex`, 'utf8');
const raw = Buffer.from(hex.trim(), 'hex');
const tx = TX.fromRaw(raw);

{
  const end = bench('serialize (static-writer)');
  for (let i = 0; i < 10000; i++) {
    tx.refresh();
    const {size} = tx.getWitnessSizes();
    const bw = new StaticWriter(size);
    tx.toWitnessWriter(bw).render();
  }
  end(10000);
}

{
  const end = bench('serialize (buffer-writer)');
  for (let i = 0; i < 10000; i++) {
    tx.refresh();
    const bw = new BufferWriter();
    tx.toWitnessWriter(bw).render();
  }
  end(10000);
}
