'use strict';

const bench = require('./bench');
const cash32 = require('../lib/encoding/cash32');

const rounds = 1000000;
const data = Buffer.alloc(20, 0xaa);
const str = cash32.encode('bitcoincash', 0, data);

bench('cash32 encode', rounds, () => {
  cash32.encode('bitcoincash', 0, data);
});

bench('cash32 decode', rounds, () => {
  cash32.decode(str);
});
