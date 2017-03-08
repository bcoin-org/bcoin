/*!
 * co.js - promise and generator control flow for bcoin
 * Originally based on yoursnetwork's "asink" module.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module utils/co
 */

var assert = require('assert');
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

    exec(gen).then(function(value) {
      nextTick(function() {
        callback(null, value);
      });
    }, function(err) {
      nextTick(function() {
        callback(err);
      });
    });
  };
}

/**
 * Wait for a nextTick with a promise.
 * @returns {Promise}
 */

function wait() {
  return new Promise(tick);
};

/**
 * Wait for a nextTick.
 * @private
 * @param {Function} resolve
 * @param {Function} reject
 */

function tick(resolve, reject) {
  nextTick(resolve);
}

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
 * Wrap a function that accepts node.js
 * style callbacks into a function that
 * returns a promise.
 * @param {Function} func
 * @param {Object?} ctx
 * @returns {Function}
 */

function promisify(func, ctx) {
  return function() {
    var self = this;
    var args = new Array(arguments.length);
    var i;

    for (i = 0; i < arguments.length; i++)
      args[i] = arguments[i];

    return new Promise(function(resolve, reject) {
      args.push(wrap(resolve, reject));
      func.apply(ctx || self, args);
    });
  };
}

/**
 * Execute each promise and
 * have them pass a truth test.
 * @method
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

/**
 * Start an interval. Wait for promise
 * to resolve on each iteration.
 * @param {Function} func
 * @param {Number?} time
 * @param {Object?} self
 * @returns {Object}
 */

function startInterval(func, time, self) {
  var cb, ctx;

  ctx = {
    timer: null,
    stopped: false
  };

  cb = co(function* () {
    assert(ctx.timer != null);
    ctx.timer = null;

    try {
      yield func.call(self);
    } finally {
      if (!ctx.stopped)
        ctx.timer = setTimeout(cb, time);
    }
  });

  ctx.timer = setTimeout(cb, time);

  return ctx;
}

/**
 * Clear an interval.
 * @param {Object} ctx
 */

function stopInterval(ctx) {
  assert(ctx);
  if (ctx.timer != null) {
    clearTimeout(ctx.timer);
    ctx.timer = null;
  }
  ctx.stopped = true;
}

/**
 * Start a timeout.
 * @param {Function} func
 * @param {Number?} time
 * @param {Object?} self
 * @returns {Object}
 */

function startTimeout(func, time, self) {
  return {
    timer: setTimeout(func.bind(self), time),
    stopped: false
  };
}

/**
 * Clear a timeout.
 * @param {Object} ctx
 */

function stopTimeout(ctx) {
  assert(ctx);
  if (ctx.timer != null) {
    clearTimeout(ctx.timer);
    ctx.timer = null;
  }
  ctx.stopped = true;
}

/**
 * Create a job object.
 * @returns {Job}
 */

function job(resolve, reject) {
  return new Job(resolve, reject);
}

/**
 * Job
 * @constructor
 * @ignore
 * @param {Function} resolve
 * @param {Function} reject
 * @property {Function} resolve
 * @property {Function} reject
 */

function Job(resolve, reject) {
  this.resolve = resolve;
  this.reject = reject;
}

/*
 * This drives me nuts.
 */

if (typeof window !== 'undefined' && window) {
  window.onunhandledrejection = function(event) {
    throw event.reason;
  };
} else if (typeof process !== 'undefined' && process) {
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
exports.wait = wait;
exports.timeout = timeout;
exports.wrap = wrap;
exports.promisify = promisify;
exports.every = every;
exports.setInterval = startInterval;
exports.clearInterval = stopInterval;
exports.setTimeout = startTimeout;
exports.clearTimeout = stopTimeout;
exports.job = job;

module.exports = exports;
