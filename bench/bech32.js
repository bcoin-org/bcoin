'use strict';

const Address = require('../lib/primitives/address');
const random = require('../lib/crypto/random');
const bench = require('./bench');

let i, end, addr;

let addrs = [];

end = bench('serialize');
for (i = 0; i < 100000; i++) {
  addr = Address.fromProgram(0, random.randomBytes(20));
  addrs.push(addr.toBech32());
}
end(i);

end = bench('parse');
for (i = 0; i < 100000; i++) {
  addr = addrs[i];
  addr = Address.fromBech32(addr);
  addrs[i] = addr;
}
end(i);

console.error(addrs);
