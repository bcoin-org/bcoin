/*!
 * lock.js - lock and queue for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/**
 * Mutex Lock
 */

class Lock {
  /**
   * Create a lock.
   * @constructor
   * @param {Boolean?} named - Whether to
   * maintain a map of queued jobs by job name.
   * @param {Function?} CustomMap
   */

  constructor(named = false, CustomMap) {
    assert(typeof named === 'boolean');
    assert(!CustomMap || typeof CustomMap === 'function');

    this.named = named;
    this.jobs = [];
    this.busy = false;
    this.destroyed = false;

    this.map = CustomMap ? new CustomMap() : new Map();
    this.current = null;

    this.unlocker = this.unlock.bind(this);
  }

  /**
   * Create a closure scoped lock.
   * @param {Boolean?} named
   * @param {Function?} CustomMap
   * @returns {Function} Lock method.
   */

  static create(named, CustomMap) {
    const lock = new Lock(named, CustomMap);
    return function _lock(arg1, arg2) {
      return lock.lock(arg1, arg2);
    };
  }

  /**
   * Test whether the lock has a pending
   * job or a job in progress (by name).
   * @param {String} name
   * @returns {Boolean}
   */

  has(name) {
    assert(this.named, 'Must use named jobs.');

    if (this.current) {
      if (Buffer.isBuffer(name)) {
        if (this.current.equals(name))
          return true;
      } else {
        if (this.current === name)
          return true;
      }
    }

    return this.pending(name);
  }

  /**
   * Test whether the lock has
   * a pending job by name.
   * @param {String} name
   * @returns {Boolean}
   */

  pending(name) {
    assert(this.named, 'Must use named jobs.');

    const count = this.map.get(name);

    if (count == null)
      return false;

    return count > 0;
  }

  /**
   * Lock the parent object and all its methods
   * which use the lock. Begin to queue calls.
   * @param {String?} name - Job name.
   * @param {Boolean?} force - Bypass the lock.
   * @returns {Promise} - Returns {Function}, must be
   * called once the method finishes executing in order
   * to resolve the queue.
   */

  lock(arg1, arg2) {
    let name, force;

    if (this.named) {
      name = arg1 || null;
      force = arg2 || false;
    } else {
      name = null;
      force = arg1 || false;
    }

    if (this.destroyed)
      return Promise.reject(new Error('Lock is destroyed.'));

    if (force) {
      assert(this.busy);
      return Promise.resolve(nop);
    }

    if (this.busy) {
      if (name) {
        const count = this.map.get(name) || 0;
        this.map.set(name, count + 1);
      }
      return new Promise((resolve, reject) => {
        this.jobs.push(new Job(resolve, reject, name));
      });
    }

    this.busy = true;
    this.current = name;

    return Promise.resolve(this.unlocker);
  }

  /**
   * The actual unlock callback.
   * @private
   */

  unlock() {
    assert(this.destroyed || this.busy);

    this.busy = false;
    this.current = null;

    if (this.jobs.length === 0)
      return;

    assert(!this.destroyed);

    const job = this.jobs.shift();

    if (job.name) {
      let count = this.map.get(job.name);
      assert(count > 0);
      if (--count === 0)
        this.map.delete(job.name);
      else
        this.map.set(job.name, count);
    }

    this.busy = true;
    this.current = job.name;

    job.resolve(this.unlocker);
  }

  /**
   * Destroy the lock. Purge all pending calls.
   */

  destroy() {
    assert(!this.destroyed, 'Lock is already destroyed.');

    this.destroyed = true;

    const jobs = this.jobs;

    this.busy = false;
    this.jobs = [];
    this.map.clear();
    this.current = null;

    for (const job of jobs)
      job.reject(new Error('Lock was destroyed.'));
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
   * @param {String?} name
   */

  constructor(resolve, reject, name) {
    this.resolve = resolve;
    this.reject = reject;
    this.name = name || null;
  }
}

/*
 * Helpers
 */

function nop() {}

/*
 * Expose
 */

module.exports = Lock;
