/*!
 * mappedlock.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * Mapped Lock
 * @alias module:utils.MappedLock
 */

class MappedLock {
  /**
   * Create a mapped lock.
   * @constructor
   */

  constructor() {
    this.jobs = new Map();
    this.busy = new Set();
    this.destroyed = false;
  }

  /**
   * Create a closure scoped lock.
   * @returns {Function} Lock method.
   */

  static create() {
    const lock = new MappedLock();
    return function _lock(key, force) {
      return lock.lock(key, force);
    };
  }

  /**
   * Test whether the lock has a pending
   * job or a job in progress (by name).
   * @param {String} name
   * @returns {Boolean}
   */

  has(name) {
    return this.busy.has(name);
  }

  /**
   * Test whether the lock has
   * a pending job by name.
   * @param {String} name
   * @returns {Boolean}
   */

  pending(name) {
    return this.jobs.has(name);
  }

  /**
   * Lock the parent object and all its methods
   * which use the lock with a specified key.
   * Begin to queue calls.
   * @param {String|Number} key
   * @param {Boolean} [force=false] - Force a call.
   * @returns {Promise} - Returns {Function}, must be
   * called once the method finishes executing in order
   * to resolve the queue.
   */

  lock(key, force = false) {
    if (this.destroyed)
      return Promise.reject(new Error('Lock is destroyed.'));

    if (key == null)
      return Promise.resolve(nop);

    if (force) {
      assert(this.busy.has(key));
      return Promise.resolve(nop);
    }

    if (this.busy.has(key)) {
      return new Promise((resolve, reject) => {
        if (!this.jobs.has(key))
          this.jobs.set(key, []);
        this.jobs.get(key).push(new Job(resolve, reject));
      });
    }

    this.busy.add(key);

    return Promise.resolve(this.unlock(key));
  }

  /**
   * Create an unlock callback.
   * @private
   * @param {String} key
   * @returns {Function} Unlocker.
   */

  unlock(key) {
    const self = this;
    return function unlocker() {
      const jobs = self.jobs.get(key);

      assert(self.destroyed || self.busy.has(key));
      self.busy.delete(key);

      if (!jobs)
        return;

      assert(!self.destroyed);

      const job = jobs.shift();
      assert(job);

      if (jobs.length === 0)
        self.jobs.delete(key);

      self.busy.add(key);

      job.resolve(unlocker);
    };
  }

  /**
   * Destroy the lock. Purge all pending calls.
   */

  destroy() {
    assert(!this.destroyed, 'Lock is already destroyed.');

    const map = this.jobs;

    this.destroyed = true;

    this.jobs = new Map();
    this.busy = new Map();

    for (const jobs of map.values()) {
      for (const job of jobs)
        job.reject(new Error('Lock was destroyed.'));
    }
  }
}

/**
 * Lock Job
 * @ignore
 */

class Job {
  /**
   * Create a lock job.
   * @constructor
   * @param {Function} resolve
   * @param {Function} reject
   */

  constructor(resolve, reject) {
    this.resolve = resolve;
    this.reject = reject;
  }
}

/*
 * Helpers
 */

function nop() {}

/*
 * Expose
 */

module.exports = MappedLock;
