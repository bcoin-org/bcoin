'use strict';

const f = process.argv.indexOf('-f');
const g = process.argv.indexOf('-g');
const b = process.argv.indexOf('-B');
const i = f !== -1 ? f : g;
const grep = i !== -1 && i + 1 < process.argv.length
  ? new RegExp(process.argv[i + 1])
  : /^/;

if (b !== -1 && b + 1 < process.argv.length)
  process.env.NODE_BACKEND = process.argv[b + 1];

module.exports = function bench(name, ops, cb) {
  if (!grep.test(name))
    return;

  const start = process.hrtime();

  for (let i = 0; i < ops; i++)
    cb();

  const elapsed = process.hrtime(start);
  const time = elapsed[0] + elapsed[1] / 1e9;
  const rate = ops / time;

  console.log('%s: ops=%d, time=%d, rate=%s',
    name, ops, time, rate.toFixed(5));
};
