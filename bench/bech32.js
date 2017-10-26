'use strict';

const Address = require('../lib/primitives/address');
const random = require('bcrypto/lib/random');
const bench = require('./bench');
const addrs = [];

{
  const end = bench('serialize');
  for (let i = 0; i < 100000; i++) {
    const addr = Address.fromProgram(0, random.randomBytes(20));
    addrs.push(addr.toBech32());
  }
  end(100000);
}

{
  const end = bench('parse');
  for (let i = 0; i < 100000; i++) {
    const b32 = addrs[i];
    const addr = Address.fromBech32(b32);
    addrs[i] = addr;
  }
  end(100000);
}

console.error(addrs[0][0]);
