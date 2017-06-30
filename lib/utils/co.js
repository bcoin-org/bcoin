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

const assert = require('assert');

/**
 * Execute an instantiated generator.
 * @param {Generator} gen
 * @returns {Promise}
 */

function exec(gen) {
  return new Promise((resolve, reject) => {
    let step = (value, rejection) => {
      let next;

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
    };

    let succeed = (value) => {
      step(value, false);
    };

    let fail = (value) => {
      step(value, true);
    };

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
  let gen = generator.call(ctx);
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
    let gen = generator.apply(this, arguments);
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
 * Wrap an async function to be
 * executed into a function that
 * accepts a node.js style callback.
 * @param {AsyncFunction}
 * @returns {Function}
 */

function cob(func) {
  return function(_) {
    let args, callback;

    if (arguments.length === 0
        || typeof arguments[arguments.length - 1] !== 'function') {
      throw new Error((func.name || 'Function') + ' requires a callback.');
    }

    args = new Array(arguments.length - 1);
    callback = arguments[arguments.length - 1];

    for (let i = 0; i < args.length; i++)
      args[i] = arguments[i];

    func.apply(this, args).then((value) => {
      setImmediate(() => callback(null, value));
    }, (err) => {
      setImmediate(() => callback(err));
    });
  };
}

/**
 * Wait for a nextTick with a promise.
 * @returns {Promise}
 */

function wait() {
  return new Promise((resolve) => setImmediate(resolve));
};

/**
 * Wait for a timeout with a promise.
 * @param {Number} time
 * @returns {Promise}
 */

function timeout(time) {
  return new Promise((resolve) => setTimeout(resolve, time));
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
    let args = new Array(arguments.length);

    for (let i = 0; i < arguments.length; i++)
      args[i] = arguments[i];

    return new Promise((resolve, reject) => {
      args.push(wrap(resolve, reject));
      func.apply(ctx || this, args);
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

async function every(jobs) {
  let result = await Promise.all(jobs);

  for (let item of result) {
    if (!item)
      return false;
  }

  return true;
}

/**
 * Start an interval. Wait for promise
 * to resolve on each iteration.
 * @param {Function} func
 * @param {Number?} time
 * @param {Object?} self
 * @returns {Object}
 */

function startInterval(func, time, self) {
  let ctx = {
    timer: null,
    stopped: false
  };

  let cb = async () => {
    assert(ctx.timer != null);
    ctx.timer = null;

    try {
      await func.call(self);
    } finally {
      if (!ctx.stopped)
        ctx.timer = setTimeout(cb, time);
    }
  };

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
