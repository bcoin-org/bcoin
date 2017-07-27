'use strict';

const ChaCha20 = require('../lib/crypto/chacha20');
const Poly1305 = require('../lib/crypto/poly1305');
const digest = require('../lib/crypto/digest');
const bench = require('./bench');

console.log('note: rate measured in kb/s');

const chacha = new ChaCha20();
const poly = new Poly1305();
const key = Buffer.alloc(32, 0x02);
const iv = Buffer.from('0102030405060708', 'hex');
const chunk = Buffer.allocUnsafe(32);
const data = Buffer.allocUnsafe(32);

for (let i = 0; i < 32; i++)
  chunk[i] = i;

for (let i = 0; i < 32; i++)
  data[i] = i & 0xff;

chacha.init(key, iv, 0);
poly.init(key);

{
  const end = bench('encrypt');
  for (let i = 0; i < 1000000; i++)
    chacha.encrypt(chunk);
  end(1000000 * 32 / 1024);
}

{
  const end = bench('update');
  for (let i = 0; i < 1000000; i++)
    poly.update(data);
  end(1000000 * 32 / 1024);
}

{
  const end = bench('finish');
  for (let i = 0; i < 1000000; i++) {
    poly.init(key);
    poly.update(data);
    poly.finish();
  }
  end(1000000 * 32 / 1024);
}

// For reference:
{
  const end = bench('sha256');
  for (let i = 0; i < 1000000; i++)
    digest.hash256(data);
  end(1000000 * 32 / 1024);
}
