'use strict';

const crypto = require('crypto');

function toString1(buf) {
  return buf.toString('binary');
}

function toString2(buf) {
  let str = '';

  for (let i = 0; i < buf.length; i++)
    str += String.fromCharCode(buf[i]);

  return str;
}

const arr = [];

for (let i = 0; i < 256; i++)
  arr.push(String.fromCharCode(i));

function toString3(buf) {
  let str = '';

  for (let i = 0; i < buf.length; i++)
    str += arr[buf[i]];

  return str;
}

function fromString1(str) {
  return Buffer.from(str, 'binary');
}

function fromString2(str) {
  const buf = Buffer.allocUnsafe(str.length);

  for (let i = 0; i < str.length; i++)
    buf[i] = str.charCodeAt(i) & 0xff;

  return buf;
}

{
  const bufs = [];

  for (let i = 0; i < 1000000; i++) {
    const key = crypto.randomBytes(32);
    bufs.push(key);
  }

  const now = Date.now();
  const out = [];

  for (const buf of bufs)
    toString1(buf);

  console.log(Date.now() - now);
}

for (;;) {
  const key = crypto.randomBytes(32);
  const str = toString1(key);
  const buf = fromString1(str);

  if (!buf.equals(key))
    throw new Error('Invalid buffer.');

  const map = new Map();
  map.set(str, true);

  if (map.get(str) !== true)
    throw new Error('Invalid map.');
}
