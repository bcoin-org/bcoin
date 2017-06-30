'use strict';

module.exports = function bench(name) {
  let start = process.hrtime();
  return function end(ops) {
    let elapsed = process.hrtime(start);
    let time = elapsed[0] + elapsed[1] / 1e9;
    let rate = ops / time;

    console.log('%s: ops=%d, time=%d, rate=%s',
      name, ops, time, rate.toFixed(5));
  };
};
