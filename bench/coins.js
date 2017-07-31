'use strict';

const fs = require('fs');
const Coins = require('../lib/coins/coins');
const TX = require('../lib/primitives/tx');
const bench = require('./bench');

const hex = fs.readFileSync(`${__dirname}/../test/data/wtx.hex`, 'utf8');
const wtx = TX.fromRaw(hex.trim(), 'hex');
const coins = Coins.fromTX(wtx, 1);
const raw = coins.toRaw();

{
  const end = bench('serialize');

  for (let i = 0; i < 10000; i++)
    coins.toRaw();

  end(10000);
}

{
  const end = bench('parse');

  for (let i = 0; i < 10000; i++)
    Coins.fromRaw(raw);

  end(10000);
}

{
  const end = bench('get');

  for (let i = 0; i < 10000; i++) {
    for (let j = 0; j < coins.outputs.length; j++)
      coins.get(j);
  }

  end(10000 * coins.outputs.length);
}
