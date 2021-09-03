'use strict';

const bench = require('./bench');
const bech32 = require('../lib/encoding/bech32');

const rounds = 1000000;
const data = Buffer.alloc(20, 0xaa);
const str = bech32.encode('bc', 0, data);

bench('bech32 encode', rounds, () => {
  bech32.encode('bc', 0, data);
});

bench('bech32 decode', rounds, () => {
  bech32.decode(str);
});
