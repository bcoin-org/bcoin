'use strict';

module.exports = function bench(name) {
  const start = process.hrtime();
  return function end(ops) {
    const elapsed = process.hrtime(start);
    const time = elapsed[0] + elapsed[1] / 1e9;
    const rate = ops / time;

    console.log('%s: ops=%d, time=%d, rate=%s',
      name, ops, time, rate.toFixed(5));
  };
};
