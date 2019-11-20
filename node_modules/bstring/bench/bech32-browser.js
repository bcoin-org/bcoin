'use strict';

const bench = require('./bench');
const bech32 = require('../lib/bech32-browser');
const crypto = require('crypto');

const addrs = [];

{
  const end = bench('encode');
  for (let i = 0; i < 100000; i++) {
    const hash = crypto.randomBytes(20);
    const prefix = 'bc';
    const version = 0;

    const addr = bech32.encode(prefix, version, hash);
    addrs.push(addr);
  }
  end(addrs.length);
}

{
  const end = bench('decode');

  for (let i = 0; i < addrs.length; i++) {
    bech32.decode(addrs[i]);
  }
  end(addrs.length);
}
