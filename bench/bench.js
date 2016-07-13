'use strict';

module.exports = function bench(name) {
  var start = process.hrtime();
  return function end(ops) {
    var elapsed = process.hrtime(start);
    var time = elapsed[0] + elapsed[1] / 1e9;
    var rate = ops / time;

    console.log('%s: ops=%d, time=%d, rate=%s',
      name, ops, time, rate.toFixed(5));
  };
};
