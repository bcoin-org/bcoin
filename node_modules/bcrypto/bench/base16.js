'use strict';

const bench = require('./bench');
const base16 = require('../lib/encoding/base16');

const rounds = 200000;
const data = Buffer.alloc(1000, 0xaa);
const str = base16.encode(data);

bench('base16 encode', rounds, () => {
  base16.encode(data);
});

bench('base16 decode', rounds, () => {
  base16.decode(str);
});

bench('base16 encode (node)', rounds, () => {
  data.toString('hex');
});

bench('base16 decode (node)', rounds, () => {
  const buf = Buffer.allocUnsafeSlow(1000);

  buf.write(str, 'hex');
});
