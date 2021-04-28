'use strict';

const random = require('bcrypto/lib/random');
const util = require('../lib/utils/util');
const bench = require('./bench');

const hashes = [];

for (let i = 0; i < 100000; i++)
  hashes.push(random.randomBytes(32));

{
  const end = bench('hexstring');
  for (let i = 0; i < hashes.length; i++)
    util.fromRev(util.revHex(hashes[i]));
  end(100000);
}
