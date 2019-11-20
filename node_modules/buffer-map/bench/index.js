'use strict';

const {BufferMap} = require('../lib/buffer-map');
const crypto = require('crypto');
const items = [];

function memory() {
  if (typeof gc === 'function')
    gc();

  const mem = process.memoryUsage();

  console.log({
    total: mb(mem.rss),
    jsHeap: mb(mem.heapUsed),
    jsHeapTotal: mb(mem.heapTotal),
    nativeHeap: mb(mem.rss - mem.heapTotal),
    external: mb(mem.external)
  });
}

function mb(num) {
  return num / 1024 / 1024;
}

for (let i = 0; i < 2000000; i++) {
  const key = crypto.randomBytes(32);
  const value = crypto.randomBytes(32);
  items.push([key, key.toString('hex'), value]);
}

function bench(name, cb) {
  const now = Date.now();

  for (const [key, , value] of items)
    cb(key, value);

  console.log('%s: %d', name, Date.now() - now);
}

function benchHex(name, cb) {
  const now = Date.now();

  for (const [, key, value] of items)
    cb(key, value);

  console.log('%s: %d', name, Date.now() - now);
}

{
  const map = new BufferMap();
  bench('warmup', (key, value) => {
    map.set(key, value);
  });
}

{
  const map = new Map();
  benchHex('warmup-hex', (key, value) => {
    map.set(key, value);
  });
}

{
  const map = new BufferMap();

  let i = 0;
  let now;

  bench('set', (key, value) => {
    map.set(key, value);
  });

  bench('get', (key, value) => {
    if (map.get(key))
      i += 1;
  });

  now = Date.now();
  for (const value of map.values())
    i += value.length;
  console.log(i);
  console.log('%s: %d', 'values', Date.now() - now);

  now = Date.now();
  for (const [key, value] of map.entries())
    i += key.length + value.length;
  console.log(i);
  console.log('%s: %d', 'entries', Date.now() - now);

  memory();

  bench('delete', (key, value) => {
    map.delete(key);
  });

  console.log(i);
}

{
  const map = new Map();

  let i = 0;
  let now;

  benchHex('set-hex', (key, value) => {
    map.set(key, value);
  });

  benchHex('get-hex', (key, value) => {
    if (map.get(key))
      i += 1;
  });

  now = Date.now();
  for (const value of map.values())
    i += value.length;
  console.log(i);
  console.log('%s: %d', 'values-hex', Date.now() - now);

  now = Date.now();
  for (const [key, value] of map.entries())
    i += key.length + value.length;
  console.log(i);
  console.log('%s: %d', 'entries-hex', Date.now() - now);

  memory();

  benchHex('delete-hex', (key, value) => {
    map.delete(key);
  });

  console.log(i);
}
