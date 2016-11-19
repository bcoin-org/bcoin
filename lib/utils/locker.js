/*!
 * locker.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var util = require('../utils/util');
var assert = require('assert');

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * @exports Locker
 * @constructor
 * @param {Function?} add - `add` method (whichever method is queuing data).
 */

function Locker(add) {
  if (!(this instanceof Locker))
    return Locker.create(add);

  EventEmitter.call(this);

  this.add = add === true;

  this.jobs = [];
  this.busy = false;
  this.destroyed = false;

  this.pending = [];
  this.pendingMap = {};

  this.unlocker = this.unlock.bind(this);
}

util.inherits(Locker, EventEmitter);

/**
 * Create a closure scoped locker.
 * @param {Function?} add
 * @returns {Function} Lock method.
 */

Locker.create = function create(add) {
  var locker = new Locker(add);
  return function lock(arg1, arg2) {
    return locker.lock(arg1, arg2);
  };
};

/**
 * Test whether the locker has a pending
 * object by key (usually a {@link Hash}).
 * @param {Hash|String} key
 * @returns {Boolean}
 */

Locker.prototype.hasPending = function hasPending(key) {
  return this.pendingMap[key] === true;
};

/**
 * Lock the parent object and all its methods
 * which use the locker. Begin to queue calls.
 * @param {Boolean?} force - Bypass the lock.
 * @returns {Promise} Returns {Function}, must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

Locker.prototype.lock = function lock(arg1, arg2) {
  var self = this;
  var force, item;

  if (this.add) {
    item = arg1;
    force = arg2;
  } else {
    force = arg1;
  }

  if (this.destroyed)
    return Promise.reject(new Error('Locker is destroyed.'));

  if (force) {
    assert(this.busy);
    return Promise.resolve(util.nop);
  }

  if (this.busy) {
    if (item) {
      this.pending.push(item);
      this.pendingMap[item.hash('hex')] = true;
    }

    return new Promise(function(resolve, reject) {
      self.jobs.push(new Job(resolve, reject, item));
    });
  }

  this.busy = true;

  return Promise.resolve(this.unlocker);
};

/**
 * The actual unlock callback.
 * @private
 */

Locker.prototype.unlock = function unlock() {
  var job;

  this.busy = false;

  if (this.pending.length === 0)
    this.emit('drain');

  if (this.jobs.length === 0)
    return;

  job = this.jobs.shift();

  if (this.destroyed) {
    job.reject(new Error('Locker was destroyed.'));
    return;
  }

  if (job.item) {
    assert(job.item === this.pending.shift());
    delete this.pendingMap[job.item.hash('hex')];
  }

  this.busy = true;

  job.resolve(this.unlocker);
};

/**
 * Destroy the locker. Purge all pending calls.
 */

Locker.prototype.destroy = function destroy() {
  this.destroyed = true;
};

/**
 * Wait for a drain (empty queue).
 * @returns {Promise}
 */

Locker.prototype.onDrain = function onDrain() {
  var self = this;

  assert(this.add, 'Cannot wait for drain without add method.');

  if (this.pending.length === 0)
    return Promise.resolve();

  return new Promise(function(resolve, reject) {
    self.once('drain', resolve);
  });
};

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * Locks methods according to passed-in key.
 * @exports MappedLock
 * @constructor
 */

function MappedLock() {
  if (!(this instanceof MappedLock))
    return MappedLock.create();

  this.jobs = {};
  this.busy = {};
  this.destroyed = false;
}

/**
 * Create a closure scoped locker.
 * @returns {Function} Lock method.
 */

MappedLock.create = function create() {
  var locker = new MappedLock();
  return function lock(key, force) {
    return locker.lock(key, force);
  };
};

/**
 * Lock the parent object and all its methods
 * which use the locker with a specified key.
 * Begin to queue calls.
 * @param {String|Number} key
 * @param {Function} func - The method being called.
 * @param {Array} args - Arguments passed to the method.
 * @param {Boolean?} force - Force a call.
 * @returns {Function} Unlocker - must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

MappedLock.prototype.lock = function lock(key, force) {
  var self = this;

  if (this.destroyed)
    return Promise.reject(new Error('Locker is destroyed.'));

  if (key == null)
    return Promise.resolve(util.nop);

  if (force) {
    assert(this.busy[key]);
    return Promise.resolve(util.nop);
  }

  if (this.busy[key]) {
    return new Promise(function(resolve, reject) {
      if (!self.jobs[key])
        self.jobs[key] = [];
      self.jobs[key].push(new Job(resolve, reject));
    });
  }

  this.busy[key] = true;

  return Promise.resolve(this.unlock(key));
};

/**
 * Create an unlock callback.
 * @private
 * @param {String} key
 * @returns {Function} Unlocker.
 */

MappedLock.prototype.unlock = function unlock(key) {
  var self = this;
  return function unlocker() {
    var jobs = self.jobs[key];
    var job;

    delete self.busy[key];

    if (!jobs)
      return;

    job = jobs.shift();
    assert(job);

    if (jobs.length === 0)
      delete self.jobs[key];

    if (self.destroyed) {
      job.reject(new Error('Locker was destroyed.'));
      return;
    }

    self.busy[key] = true;

    job.resolve(unlocker);
  };
};

/**
 * Destroy the locker. Purge all pending calls.
 */

MappedLock.prototype.destroy = function destroy() {
  this.destroyed = true;
};

/**
 * Locker Job
 * @exports Job
 * @constructor
 * @param {Function} resolve
 * @param {Function} reject
 * @param {Object?} item
 */

function Job(resolve, reject, item) {
  this.resolve = resolve;
  this.reject = reject;
  this.item = item || null;
}

/*
 * Expose
 */

exports = Locker;
exports.Mapped = MappedLock;

module.exports = exports;
