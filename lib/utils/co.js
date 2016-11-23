/*!
 * co.js - promise and generator control flow for bcoin
 * Originally based on yoursnetwork's "asink" module.
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var nextTick = require('./nexttick');
var every;

/**
 * Execute an instantiated generator.
 * @param {Generator} gen
 * @returns {Promise}
 */

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

      if (!isPromise(next.value)) {
        step(next.value, false);
        return;
      }

      next.value.then(succeed, fail);
    }

    function succeed(value) {
      step(value, false);
    }

    function fail(value) {
      step(value, true);
    }

    step(undefined, false);
  });
}

/**
 * Execute generator function
 * with a context and execute.
 * @param {GeneratorFunction} generator
 * @param {Object} ctx
 * @returns {Promise}
 */

function spawn(generator, ctx) {
  var gen = generator.call(ctx);
  return exec(gen);
}

/**
 * Wrap a generator function to be
 * executed into a function that
 * returns a promise.
 * @param {GeneratorFunction}
 * @returns {Function}
 */

function co(generator) {
  return function() {
    var gen = generator.apply(this, arguments);
    return exec(gen);
  };
}

/**
 * Test whether an object is a promise.
 * @param {Object} obj
 * @returns {Boolean}
 */

function isPromise(obj) {
  return obj && typeof obj.then === 'function';
}

/**
 * Wrap a generator function to be
 * executed into a function that
 * accepts a node.js style callback.
 * @param {GeneratorFunction}
 * @returns {Function}
 */

function cob(generator) {
  return function(_) {
    var i, args, callback, gen;

    if (arguments.length === 0
        || typeof arguments[arguments.length - 1] !== 'function') {
      throw new Error((generator.name || 'Function') + ' requires a callback.');
    }

    args = new Array(arguments.length - 1);
    callback = arguments[arguments.length - 1];

    for (i = 0; i < args.length; i++)
      args[i] = arguments[i];

    gen = generator.apply(this, args);

    return cb(exec(gen), callback);
  };
}

/**
 * Wrap a generator function to be
 * executed into a function that
 * accepts a node.js style callback.
 * Only executes callback on error.
 * @param {GeneratorFunction}
 * @returns {Function}
 */

function con(generator) {
  return function() {
    var i, args, callback, gen;

    if (arguments.length === 0
        || typeof arguments[arguments.length - 1] !== 'function') {
      throw new Error((generator.name || 'Function') + ' requires a callback.');
    }

    args = new Array(arguments.length);
    callback = arguments[arguments.length - 1];

    for (i = 0; i < args.length; i++)
      args[i] = arguments[i];

    gen = generator.apply(this, args);

    return exec(gen).catch(function(err) {
      // Escape the promise's scope:
      nextTick(function() {
        callback(err);
      });
    });
  };
}

/**
 * Wait for promise to resolve and
 * execute a node.js style callback.
 * @param {Promise} promise
 * @returns {Promise}
 */

function cb(promise, callback) {
  promise.then(function(value) {
    nextTick(function() {
      callback(null, value);
    });
  }, function(err) {
    nextTick(function() {
      callback(err);
    });
  });
}

/**
 * Wait for a nextTick with a promise.
 * @returns {Promise}
 */

function wait() {
  return new Promise(function(resolve, reject) {
    nextTick(resolve);
  });
};

/**
 * Wait for a timeout with a promise.
 * @param {Number} time
 * @returns {Promise}
 */

function timeout(time) {
  return new Promise(function(resolve, reject) {
    setTimeout(resolve, time);
  });
}

/**
 * Wrap `resolve` and `reject` into
 * a node.js style callback.
 * @param {Function} resolve
 * @param {Function} reject
 * @returns {Function}
 */

function wrap(resolve, reject) {
  return function(err, result) {
    if (err) {
      reject(err);
      return;
    }
    resolve(result);
  };
}

/**
 * Call a function that accepts node.js
 * style callbacks, wrap with a promise.
 * @private
 * @param {Object} ctx
 * @param {Function} func
 * @param {Array} args
 * @returns {Promise}
 */

function _call(ctx, func, args) {
  return new Promise(function(resolve, reject) {
    args.push(wrap(resolve, reject));
    func.apply(ctx, args);
  });
}

/**
 * Call a function that accepts node.js
 * style callbacks, wrap with a promise.
 * @param {Function} func
 * @returns {Promise}
 */

function call(func) {
  var args = new Array(Math.max(0, arguments.length - 1));
  var i;

  for (i = 1; i < arguments.length; i++)
    args[i - 1] = arguments[i];

  /* jshint validthis:true */
  return _call(this, func, args);
}

/**
 * Wrap a function that accepts node.js
 * style callbacks into a function that
 * returns a promise.
 * @param {Function} func
 * @param {Object?} ctx
 * @returns {Function}
 */

function promisify(func, ctx) {
  return function() {
    var args = new Array(arguments.length);
    var i;

    for (i = 0; i < arguments.length; i++)
      args[i] = arguments[i];

    return _call(ctx || this, func, args);
  };
}

/**
 * Execute each promise and
 * have them pass a truth test.
 * @param {Promise[]} jobs
 * @returns {Promise}
 */

every = co(function* every(jobs) {
  var result = yield Promise.all(jobs);
  var i;

  for (i = 0; i < result.length; i++) {
    if (!result[i])
      return false;
  }

  return true;
});

/*
 * This drives me nuts.
 */

if (typeof window !== 'undefined') {
  window.onunhandledrejection = function(event) {
    throw event.reason;
  };
} else {
 process.on('unhandledRejection', function(err, promise) {
    throw err;
  });
}

/*
 * Expose
 */

exports = co;
exports.exec = exec;
exports.spawn = spawn;
exports.co = co;
exports.cob = cob;
exports.con = con;
exports.cb = cb;
exports.wait = wait;
exports.timeout = timeout;
exports.wrap = wrap;
exports.call = call;
exports.promisify = promisify;
exports.every = every;

module.exports = exports;
