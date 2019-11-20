'use strict';

const bench = require('./bench');
const cashaddr = require('../lib/cashaddr');
const crypto = require('crypto');

const addrs = [];

{
  const end = bench('serialize');
  for (let i = 0; i < 100000; i++) {
    const hash = crypto.randomBytes(20);
    const prefix = 'bitcoincash';
    const type = 0;

    const addr = cashaddr.encode(prefix, type, hash);
    addrs.push(addr);
  }
  end(addrs.length);
}

{
  const end = bench('deserialize');

  for (let i = 0; i < addrs.length; i++)
    cashaddr.decode(addrs[i]);

  end(addrs.length);
}
