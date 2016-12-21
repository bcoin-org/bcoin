/*!
 * locker.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * @exports Locker
 * @constructor
 * @param {Boolean?} named - Whether to
 * maintain a map of queued jobs by job name.
 */

function Locker(named) {
  if (!(this instanceof Locker))
    return Locker.create(named);

  this.named = named === true;

  this.jobs = [];
  this.waiting = [];
  this.busy = false;
  this.destroyed = false;

  this.map = {};
  this.pending = 0;
  this.current = null;

  this.unlocker = this.unlock.bind(this);
}

/**
 * Create a closure scoped locker.
 * @param {Boolean?} named
 * @returns {Function} Lock method.
 */

Locker.create = function create(named) {
  var locker = new Locker(named);
  return function lock(arg1, arg2) {
    return locker.lock(arg1, arg2);
  };
};

/**
 * Test whether the locker has a pending
 * job or a job in progress (by name).
 * @param {String} name
 * @returns {Boolean}
 */

Locker.prototype.has = function has(name) {
  assert(this.named, 'Must use named jobs.');

  if (this.current === name)
    return true;

  return this.map[name] > 0;
};

/**
 * Test whether the locker has
 * a pending job by name.
 * @param {String} name
 * @returns {Boolean}
 */

Locker.prototype.hasPending = function hasPending(name) {
  assert(this.named, 'Must use named jobs.');
  return this.map[name] > 0;
};

/**
 * Test whether the locker is
 * busy with a named job.
 * @returns {Boolean}
 */

Locker.prototype.isBusy = function isBusy() {
  assert(this.named, 'Must use named jobs.');
  if (this.current)
    return true;
  return this.pending > 0;
};

/**
 * Lock the parent object and all its methods
 * which use the locker. Begin to queue calls.
 * @param {String?} name - Job name.
 * @param {Boolean?} force - Bypass the lock.
 * @returns {Promise} - Returns {Function}, must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

Locker.prototype.lock = function lock(arg1, arg2) {
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
    return Promise.reject(new Error('Locker is destroyed.'));

  if (force) {
    assert(this.busy);
    return Promise.resolve(nop);
  }

  if (this.busy) {
    if (name) {
      if (!this.map[name])
        this.map[name] = 0;
      this.map[name]++;
      this.pending++;
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

Locker.prototype.unlock = function unlock() {
  var job;

  assert(this.destroyed || this.busy);

  this.busy = false;
  this.current = null;

  if (this.jobs.length === 0) {
    assert(this.pending === 0);
    this.drain();
    return;
  }

  assert(!this.destroyed);

  job = this.jobs.shift();

  if (job.name) {
    assert(this.map[job.name] > 0);
    if (--this.map[job.name] === 0)
      delete this.map[job.name];
    this.pending--;
  } else {
    if (this.pending === 0)
      this.drain();
  }

  this.busy = true;
  this.current = job.name;

  job.resolve(this.unlocker);
};

/**
 * Wait for a drain (empty queue).
 * @returns {Promise}
 */

Locker.prototype.wait = function wait() {
  var self = this;

  assert(this.named, 'Must use named jobs.');

  if (this.destroyed)
    return Promise.reject(new Error('Locker is destroyed.'));

  if (!this.isBusy()) {
    assert(this.waiting.length === 0);
    return Promise.resolve();
  }

  return new Promise(function(resolve, reject) {
    self.waiting.push(new Job(resolve, reject, null));
  });
};

/**
 * Notify drainers that the queue has emptied.
 * @private
 */

Locker.prototype.drain = function drain() {
  var i, jobs, job;

  if (this.waiting.length === 0)
    return;

  jobs = this.waiting.slice();

  this.waiting.length = 0;

  for (i = 0; i < jobs.length; i++) {
    job = jobs[i];
    job.resolve();
  }
};

/**
 * Destroy the locker. Purge all pending calls.
 */

Locker.prototype.destroy = function destroy() {
  var err = new Error('Locker was destroyed.');
  var i, jobs, job;

  assert(!this.destroyed, 'Locker is already destroyed.');

  this.destroyed = true;

  jobs = this.jobs.slice();

  this.busy = false;
  this.jobs.length = 0;
  this.map = {};
  this.pending = 0;
  this.current = null;

  for (i = 0; i < jobs.length; i++) {
    job = jobs[i];
    job.reject(err);
  }

  jobs = this.waiting.slice();

  this.waiting.length = 0;

  for (i = 0; i < jobs.length; i++) {
    job = jobs[i];
    job.reject(err);
  }
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
 * Test whether the locker has a pending job by name.
 * @param {String} name
 * @returns {Boolean}
 */

MappedLock.prototype.has = function has(name) {
  return this.busy[name] === true;
};

/**
 * Test whether the locker is busy .
 * @returns {Boolean}
 */

MappedLock.prototype.isBusy = function isBusy() {
  return this.busy;
};

/**
 * Lock the parent object and all its methods
 * which use the locker with a specified key.
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
    return Promise.reject(new Error('Locker is destroyed.'));

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
 * Destroy the locker. Purge all pending calls.
 */

MappedLock.prototype.destroy = function destroy() {
  var err = new Error('Locker was destroyed.');
  var map = this.jobs;
  var keys = Object.keys(map);
  var i, j, key, jobs, job;

  assert(!this.destroyed, 'Locker is already destroyed.');

  this.destroyed = true;

  this.jobs = {};
  this.busy = {};

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
 * Locker Job
 * @exports Job
 * @constructor
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

exports = Locker;
exports.Mapped = MappedLock;

module.exports = exports;
