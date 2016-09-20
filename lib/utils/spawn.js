'use strict';

// See: https://github.com/yoursnetwork/asink

function spawn(genF, self) {
  return new Promise(function(resolve, reject) {
    var gen = genF.call(self);

    function step(nextF) {
      var next;

      try {
        next = nextF();
      } catch (e) {
        // finished with failure, reject the promise
        reject(e);
        return;
      }

      if (next.done) {
        // finished with success, resolve the promise
        resolve(next.value);
        return;
      }

      // not finished, chain off the yielded promise and `step` again
      Promise.resolve(next.value).then(function(v) {
        step(function() {
          return gen.next(v);
        });
      }, function (e) {
        step(function() {
          return gen.throw(e);
        });
      });
    }

    step(function() {
      return gen.next(undefined);
    });
  });
}

module.exports = spawn;
