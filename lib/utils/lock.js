/*!
 * lock.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * @alias module:utils.Lock
 * @constructor
 * @param {Boolean?} named - Whether to
 * maintain a map of queued jobs by job name.
 */

function Lock(named) {
  if (!(this instanceof Lock))
    return Lock.create(named);

  this.named = named === true;

  this.jobs = [];
  this.busy = false;
  this.destroyed = false;

  this.map = Object.create(null);
  this.current = null;

  this.unlocker = this.unlock.bind(this);
}

/**
 * Create a closure scoped lock.
 * @param {Boolean?} named
 * @returns {Function} Lock method.
 */

Lock.create = function create(named) {
  var lock = new Lock(named);
  return function _lock(arg1, arg2) {
    return lock.lock(arg1, arg2);
  };
};

/**
 * Test whether the lock has a pending
 * job or a job in progress (by name).
 * @param {String} name
 * @returns {Boolean}
 */

Lock.prototype.has = function has(name) {
  assert(this.named, 'Must use named jobs.');

  if (this.current === name)
    return true;

  return this.map[name] > 0;
};

/**
 * Test whether the lock has
 * a pending job by name.
 * @param {String} name
 * @returns {Boolean}
 */

Lock.prototype.hasPending = function hasPending(name) {
  assert(this.named, 'Must use named jobs.');
  return this.map[name] > 0;
};

/**
 * Lock the parent object and all its methods
 * which use the lock. Begin to queue calls.
 * @param {String?} name - Job name.
 * @param {Boolean?} force - Bypass the lock.
 * @returns {Promise} - Returns {Function}, must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

Lock.prototype.lock = function lock(arg1, arg2) {
  var self = this;
  var name, force;

  if (this.named) {
    name = arg1 || null;
    force = arg2;
  } else {
    name = null;
    force = arg1;
  }

  if (this.destroyed)
    return Promise.reject(new Error('Lock is destroyed.'));

  if (force) {
    assert(this.busy);
    return Promise.resolve(nop);
  }

  if (this.busy) {
    if (name) {
      if (!this.map[name])
        this.map[name] = 0;
      this.map[name]++;
    }
    return new Promise(function(resolve, reject) {
      self.jobs.push(new Job(resolve, reject, name));
    });
  }

  this.busy = true;
  this.current = name;

  return Promise.resolve(this.unlocker);
};

/**
 * The actual unlock callback.
 * @private
 */

Lock.prototype.unlock = function unlock() {
  var job;

  assert(this.destroyed || this.busy);

  this.busy = false;
  this.current = null;

  if (this.jobs.length === 0)
    return;

  assert(!this.destroyed);

  job = this.jobs.shift();

  if (job.name) {
    assert(this.map[job.name] > 0);
    if (--this.map[job.name] === 0)
      delete this.map[job.name];
  }

  this.busy = true;
  this.current = job.name;

  job.resolve(this.unlocker);
};

/**
 * Destroy the lock. Purge all pending calls.
 */

Lock.prototype.destroy = function destroy() {
  var err = new Error('Lock was destroyed.');
  var i, jobs, job;

  assert(!this.destroyed, 'Lock is already destroyed.');

  this.destroyed = true;

  jobs = this.jobs.slice();

  this.busy = false;
  this.jobs.length = 0;
  this.map = Object.create(null);
  this.current = null;

  for (i = 0; i < jobs.length; i++) {
    job = jobs[i];
    job.reject(err);
  }
};

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * Locks methods according to passed-in key.
 * @alias module:utils.MappedLock
 * @constructor
 */

function MappedLock() {
  if (!(this instanceof MappedLock))
    return MappedLock.create();

  this.jobs = Object.create(null);
  this.busy = Object.create(null);
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
  return this.busy[name] === true;
};

/**
 * Test whether the lock has
 * a pending job by name.
 * @param {String} name
 * @returns {Boolean}
 */

MappedLock.prototype.hasPending = function hasPending(name) {
  return this.jobs[name] != null;
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
    assert(this.busy[key]);
    return Promise.resolve(nop);
  }

  if (this.busy[key]) {
    return new Promise(function(resolve, reject) {
      if (!self.jobs[key])
        self.jobs[key] = [];
      self.jobs[key].push(new Job(resolve, reject, null));
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

    assert(self.destroyed || self.busy[key]);
    delete self.busy[key];

    if (!jobs)
      return;

    assert(!self.destroyed);

    job = jobs.shift();
    assert(job);

    if (jobs.length === 0)
      delete self.jobs[key];

    self.busy[key] = true;

    job.resolve(unlocker);
  };
};

/**
 * Destroy the lock. Purge all pending calls.
 */

MappedLock.prototype.destroy = function destroy() {
  var err = new Error('Lock was destroyed.');
  var map = this.jobs;
  var keys = Object.keys(map);
  var i, j, key, jobs, job;

  assert(!this.destroyed, 'Lock is already destroyed.');

  this.destroyed = true;

  this.jobs = Object.create(null);
  this.busy = Object.create(null);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    jobs = map[key];
    for (j = 0; j < jobs.length; j++) {
      job = jobs[j];
      job.reject(err);
    }
  }
};

/**
 * Lock Job
 * @constructor
 * @ignore
 * @param {Function} resolve
 * @param {Function} reject
 * @param {String?} name
 */

function Job(resolve, reject, name) {
  this.resolve = resolve;
  this.reject = reject;
  this.name = name || null;
}

/*
 * Helpers
 */

function nop() {}

/*
 * Expose
 */

exports = Lock;
exports.Mapped = MappedLock;

module.exports = exports;
