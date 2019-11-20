'use strict';

module.exports = function bench(name, ops, cb) {
  const start = process.hrtime();

  for (let i = 0; i < ops; i++)
    cb();

  const elapsed = process.hrtime(start);
  const time = elapsed[0] + elapsed[1] / 1e9;
  const rate = ops / time;

  console.log('%s: ops=%d, time=%d, rate=%s',
    name, ops, time, rate.toFixed(5));
};
