'use strict';

const bench = require('./bench');
const cipher = require('../lib/cipher');

{
  const rounds = 100000;
  const data = Buffer.alloc(1024, 0xaa);
  const key = Buffer.alloc(32, 0x01);
  const iv = Buffer.alloc(16, 0x02);
  const chunks = [];

  for (let i = 0; i < 1024; i += 63)
    chunks.push(data.slice(i, i + 63));

  bench('aes-256-cbc encrypt', rounds, () => {
    cipher.encrypt('AES-256-CBC', key, iv, data);
  });

  bench('aes-256-cbc context', rounds, () => {
    const ctx = new cipher.Cipher('AES-256-CBC');

    ctx.init(key, iv);

    for (const chunk of chunks)
      ctx.update(chunk);

    ctx.final();
  });
}
