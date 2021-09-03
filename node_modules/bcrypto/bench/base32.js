'use strict';

const bench = require('./bench');
const base32 = require('../lib/encoding/base32');

const rounds = 200000;
const data = Buffer.alloc(1000, 0xaa);
const str = base32.encode(data);

bench('base32 encode', rounds, () => {
  base32.encode(data);
});

bench('base32 decode', rounds, () => {
  base32.decode(str);
});
