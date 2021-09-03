'use strict';

const bench = require('./bench');
const base64 = require('../lib/encoding/base64');

const rounds = 100000;
const data = Buffer.alloc(1000, 0xaa);
const str = base64.encode(data);

bench('base64 encode', rounds, () => {
  base64.encode(data);
});

bench('base64 decode', rounds, () => {
  base64.decode(str);
});

bench('base64 encode (node)', rounds, () => {
  data.toString('base64');
});

bench('base64 decode (node)', rounds, () => {
  const buf = Buffer.allocUnsafeSlow(1000);

  buf.write(str, 'base64');
});
