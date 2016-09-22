'use strict';

function exec(gen) {
  return new Promise(function(resolve, reject) {
    function step(value, rejection) {
      var next;

      try {
        if (rejection)
          next = gen.throw(value);
        else
          next = gen.next(value);
      } catch (e) {
        reject(e);
        return;
      }

      if (next.done) {
        resolve(next.value);
        return;
      }

      if (!(next.value instanceof Promise)) {
        step(next.value);
        return;
      }

      next.value.then(step, function(e) {
        step(e, true);
      });
    }

    step(undefined);
  });
}

function spawn(generator, self) {
  var gen = generator.call(self);
  return exec(gen);
}

function co(generator) {
  return function() {
    var gen = generator.apply(this, arguments);
    return exec(gen);
  };
}

spawn.co = co;

module.exports = spawn;
