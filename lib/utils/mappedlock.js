/*!
 * mappedlock.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * Locks methods according to passed-in key.
 * @alias module:utils.MappedLock
 * @constructor
 */

function MappedLock() {
  if (!(this instanceof MappedLock))
    return MappedLock.create();

  this.jobs = new Map();
  this.busy = new Set();
  this.destroyed = false;
}

/**
 * Create a closure scoped lock.
 * @returns {Function} Lock method.
 */

MappedLock.create = function create() {
  var lock = new MappedLock();
  return function _lock(key, force) {
    return lock.lock(key, force);
  };
};

/**
 * Test whether the lock has a pending
 * job or a job in progress (by name).
 * @param {String} name
 * @returns {Boolean}
 */

MappedLock.prototype.has = function has(name) {
  return this.busy.has(name);
};

/**
 * Test whether the lock has
 * a pending job by name.
 * @param {String} name
 * @returns {Boolean}
 */

MappedLock.prototype.hasPending = function hasPending(name) {
  return this.jobs.has(name);
};

/**
 * Lock the parent object and all its methods
 * which use the lock with a specified key.
 * Begin to queue calls.
 * @param {String|Number} key
 * @param {Boolean?} force - Force a call.
 * @returns {Promise} - Returns {Function}, must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

MappedLock.prototype.lock = function lock(key, force) {
  var self = this;

  if (this.destroyed)
    return Promise.reject(new Error('Lock is destroyed.'));

  if (key == null)
    return Promise.resolve(nop);

  if (force) {
    assert(this.busy.has(key));
    return Promise.resolve(nop);
  }

  if (this.busy.has(key)) {
    return new Promise(function(resolve, reject) {
      if (!self.jobs.has(key))
        self.jobs.set(key, []);
      self.jobs.get(key).push(new Job(resolve, reject));
    });
  }

  this.busy.add(key);

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
    var jobs = self.jobs.get(key);
    var job;

    assert(self.destroyed || self.busy.has(key));
    self.busy.delete(key);

    if (!jobs)
      return;

    assert(!self.destroyed);

    job = jobs.shift();
    assert(job);

    if (jobs.length === 0)
      self.jobs.delete(key);

    self.busy.add(key);

    job.resolve(unlocker);
  };
};

/**
 * Destroy the lock. Purge all pending calls.
 */

MappedLock.prototype.destroy = function destroy() {
  var err = new Error('Lock was destroyed.');
  var map = this.jobs;
  var jobs, job;

  assert(!this.destroyed, 'Lock is already destroyed.');

  this.destroyed = true;

  this.jobs = new Map();
  this.busy = new Map();

  for (jobs of map.values()) {
    for (job of jobs)
      job.reject(err);
  }
};

/**
 * Lock Job
 * @constructor
 * @ignore
 * @param {Function} resolve
 * @param {Function} reject
 */

function Job(resolve, reject) {
  this.resolve = resolve;
  this.reject = reject;
}

/*
 * Helpers
 */

function nop() {}

/*
 * Expose
 */

module.exports = MappedLock;
