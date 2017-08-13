'use strict';

const Coins = require('../lib/coins/coins');
const common = require('../test/util/common');
const bench = require('./bench');

const [tx] = common.readTX('tx5').getTX();
const coins = Coins.fromTX(tx, 1);
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
