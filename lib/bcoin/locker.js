/*!
 * locker.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * @exports Locker
 * @constructor
 * @param {Function} parent - Parent constructor.
 * @param {Function?} add - `add` method (whichever method is queuing data).
 * @param {Number?} limit - Limit in bytes of data that can be queued.
 */

function Locker(parent, add, limit) {
  if (!(this instanceof Locker))
    return Locker(parent, add, limit);

  this.parent = parent;
  this.jobs = [];
  this.busy = false;

  this.pending = [];
  this.pendingMap = {};
  this.pendingSize = 0;
  this.pendingLimit = limit || (20 << 20);
  this.add = add;
}

utils.inherits(Locker, EventEmitter);

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
 * @param {Function} func - The method being called.
 * @param {Array} args - Arguments passed to the method.
 * @param {Boolean?} force - Force a call.
 * @returns {Function} unlock - Unlocker - must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

Locker.prototype.lock = function lock(func, args, force) {
  var self = this;
  var obj, called;

  if (force) {
    assert(this.busy);
    return function unlock() {
      assert(!called);
      called = true;
    };
  }

  if (this.busy) {
    if (this.add && func === this.add) {
      obj = args[0];
      this.pending.push(obj);
      this.pendingMap[obj.hash('hex')] = true;
      this.pendingSize += obj.getSize();
      if (this.pendingSize > this.pendingLimit) {
        this.purgePending();
        return;
      }
    }
    this.jobs.push([func, args]);
    return;
  }

  this.busy = true;

  return function unlock() {
    var item, obj;

    assert(!called);
    called = true;

    self.busy = false;

    if (self.add && func === self.add) {
      if (self.pending.length === 0)
        self.emit('flush');
    }

    if (self.jobs.length === 0)
      return;

    item = self.jobs.shift();

    if (self.add && item[0] === self.add) {
      obj = item[1][0];
      assert(obj === self.pending.shift());
      delete self.pendingMap[obj.hash('hex')];
      self.pendingSize -= obj.getSize();
    }

    item[0].apply(self.parent, item[1]);
  };
};

/**
 * Destroy the locker. Purge all pending calls.
 */

Locker.prototype.destroy = function destroy() {
  if (this.add)
    this.purgePending();
  this.jobs.length = 0;
};

/**
 * Purge all pending calls (called once `add` has hit `limit`).
 */

Locker.prototype.purgePending = function purgePending() {
  var self = this;
  var total = this.pending.length;

  assert(this.add);

  this.emit('purge', total, this.pendingSize);

  this.pending.forEach(function(obj) {
    delete self.pendingMap[obj.hash('hex')];
  });

  this.pending.length = 0;
  this.pendingSize = 0;

  this.jobs = this.jobs.filter(function(item) {
    return item[0] !== self.add;
  });

  if (total !== 0)
    this.emit('flush');
};

/**
 * Wait for a flush (empty queue).
 * @param {Function} callback
 */

Locker.prototype.onFlush = function onFlush(callback) {
  if (this.pending.length === 0)
    return callback();

  this.once('flush', callback);
};

module.exports = Locker;
