'use strict';

const bench = require('./bench');
const base58 = require('../lib/encoding/base58');

const rounds = 1000;
const data = Buffer.alloc(1000, 0xaa);
const str = base58.encode(data);

bench('base58 encode', rounds, () => {
  base58.encode(data);
});

bench('base58 decode', rounds, () => {
  base58.decode(str);
});
