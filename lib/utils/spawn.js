/*!
 * spawn.js - promise and generator control flow for bcoin
 * Originally based on yoursnetwork's "asink" module.
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('./utils');

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

/**
 * Execute generator function
 * with a context and execute.
 * @param {GeneratorFunction} generator
 * @param {Object} self
 * @returns {Promise}
 */

function spawn(generator, self) {
  var gen = generator.call(self);
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
 * Wrap a generator function to be
 * executed into a function that
 * accepts a node.js style callback.
 * @param {GeneratorFunction}
 * @returns {Function}
 */

function cob(generator) {
  return function() {
    var i, args, callback, gen;

    if (arguments.length === 0
        || typeof arguments[arguments.length - 1] !== 'function') {
      throw new Error('Function must accept a callback.');
    }

    args = new Array(arguments.length - 1);
    callback = arguments[arguments.length - 1];

    for (i = 0; i < args.length; i++)
      args[i] = arguments[i];

    gen = generator.apply(this, args);

    return cb(exec(gen), function(err, result) {
      // Escape the promise's scope:
      utils.nextTick(function() {
        callback(err, result);
      });
    });
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
      throw new Error('Function must accept a callback.');
    }

    args = new Array(arguments.length);
    callback = arguments[arguments.length - 1];

    for (i = 0; i < args.length; i++)
      args[i] = arguments[i];

    gen = generator.apply(this, args);

    return exec(gen).catch(function(err) {
      // Escape the promise's scope:
      utils.nextTick(function() {
        callback(err);
      });
    });
  };
}

/**
 * Wait for promise to resolve and
 * execute a node.js style callback.
 * @param {Promise} promise
 * @param {Function} callback
 */

function cb(promise, callback) {
  promise.then(function(value) {
    callback(null, value);
  }, function(err) {
    callback(err);
  });
}

/**
 * Wait for a nextTick with a promise.
 * @returns {Promise}
 */

function wait() {
  return new Promise(function(resolve, reject) {
    utils.nextTick(resolve);
  });
};

/**
 * Wait for a timeout with a promise.
 * @param {Number} time
 * @returns {Promise}
 */

function timeout(time) {
  return new Promise(function(resolve, reject) {
    setTimeout(function() {
      resolve();
    }, time);
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
    if (err)
      return reject(err);
    resolve(result);
  };
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
    args[i] = arguments[i];

  return new Promise(function(resolve, reject) {
    args.push(function(err, result) {
      if (err)
        return reject(err);
      resolve(result);
    });
    func.apply(self, args);
  });
}

/**
 * Wrap a function that accepts node.js
 * style callbacks into a function that
 * returns a promise.
 * @param {Function} func
 * @param {Object?} self
 * @returns {Function}
 */

function promisify(func, self) {
  return function() {
    var args = new Array(arguments.length);
    var i;

    for (i = 0; i < args.length; i++)
      args[i] = arguments[i];

    return new Promise(function(resolve, reject) {
      args.push(function(err, result) {
        if (err)
          return reject(err);
        resolve(result);
      });
      func.apply(self, args);
    });
  };
}

/*
 * Expose
 */

exports = spawn;
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

module.exports = spawn;
