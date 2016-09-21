'use strict';

// See: https://github.com/yoursnetwork/asink

function spawn(generator, self) {
  return new Promise(function(resolve, reject) {
    var gen = generator.call(self);

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

module.exports = spawn;
