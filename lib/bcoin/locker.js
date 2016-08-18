/*!
 * locker.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * @exports Locker
 * @constructor
 * @param {Function} parent - Parent object.
 * @param {Function?} add - `add` method (whichever method is queuing data).
 */

function Locker(parent, add) {
  if (!(this instanceof Locker))
    return Locker.create(parent, add);

  EventEmitter.call(this);

  this.parent = parent;
  this.jobs = [];
  this.busy = false;

  this.pending = [];
  this.pendingMap = {};
  this.add = add;
}

utils.inherits(Locker, EventEmitter);

/**
 * Create a closure scoped locker.
 * @param {Function} parent - Parent object.
 * @param {Function?} add
 * @returns {Function} Lock method.
 */

Locker.create = function create(parent, add) {
  var locker = new Locker(parent, add);
  return function lock(func, args, force) {
    return locker.lock(func, args, force);
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
 * @param {Function} func - The method being called.
 * @param {Array} args - Arguments passed to the method.
 * @param {Boolean?} force - Force a call.
 * @returns {Function} Unlocker - must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

Locker.prototype.lock = function lock(func, args, force) {
  var self = this;
  var callback = args[args.length - 1];
  var obj, called, arg;

  if (typeof callback !== 'function')
    throw new Error(func.name + ' requires a callback.');

  if (force) {
    assert(this.busy);
    return function unlock(err, res1, res2) {
      assert(!called, 'Locked callback executed twice.');
      called = true;
      callback(err, res1, res2);
    };
  }

  if (this.busy) {
    if (this.add && func === this.add) {
      obj = args[0];
      this.pending.push(obj);
      this.pendingMap[obj.hash('hex')] = true;
    }
    this.jobs.push([func, args]);
    return;
  }

  this.busy = true;

  return function unlock(err, res1, res2) {
    var item, obj;

    assert(!called, 'Locked callback executed twice.');
    called = true;

    self.busy = false;

    if (self.add && func === self.add) {
      if (self.pending.length === 0)
        self.emit('drain');
    }

    if (self.jobs.length === 0) {
      callback(err, res1, res2);
      return;
    }

    item = self.jobs.shift();

    if (self.add && item[0] === self.add) {
      obj = item[1][0];
      assert(obj === self.pending.shift());
      delete self.pendingMap[obj.hash('hex')];
    }

    item[0].apply(self.parent, item[1]);

    callback(err, res1, res2);
  };
};

/**
 * Destroy the locker. Purge all pending calls.
 */

Locker.prototype.destroy = function destroy() {
  if (this.add) {
    this.pending.length = 0;
    this.pendingMap = {};
  }
  this.jobs.length = 0;
};

/**
 * Wait for a drain (empty queue).
 * @param {Function} callback
 */

Locker.prototype.onDrain = function onDrain(callback) {
  assert(this.add, 'Cannot wait for drain without add method.');

  if (this.pending.length === 0)
    return callback();

  this.once('drain', callback);
};

/**
 * Represents a mutex lock for locking asynchronous object methods.
 * Locks methods according to passed-in key.
 * @exports MappedLock
 * @constructor
 * @param {Function} parent - Parent object.
 */

function MappedLock(parent) {
  if (!(this instanceof MappedLock))
    return MappedLock.create(parent);

  this.parent = parent;
  this.jobs = [];
  this.busy = {};
}

/**
 * Create a closure scoped locker.
 * @param {Function} parent - Parent object.
 * @returns {Function} Lock method.
 */

MappedLock.create = function create(parent) {
  var locker = new MappedLock(parent);
  return function lock(key, func, args, force) {
    return locker.lock(key, func, args, force);
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

MappedLock.prototype.lock = function lock(key, func, args, force) {
  var self = this;
  var callback = args[args.length - 1];
  var called;

  if (typeof callback !== 'function')
    throw new Error(func.name + ' requires a callback.');

  if (force || key == null) {
    assert(key == null || this.busy[key]);
    return function unlock(err, res1, res2) {
      assert(!called, 'Locked callback executed twice.');
      called = true;
      callback(err, res1, res2);
    };
  }

  if (this.busy[key]) {
    this.jobs.push([func, args]);
    return;
  }

  this.busy[key] = true;

  return function unlock(err, res1, res2) {
    var item;

    assert(!called, 'Locked callback executed twice.');
    called = true;

    delete self.busy[key];

    if (self.jobs.length === 0) {
      callback(err, res1, res2);
      return;
    }

    item = self.jobs.shift();

    item[0].apply(self.parent, item[1]);

    callback(err, res1, res2);
  };
};

/*
 * Expose
 */

exports = Locker;
exports.mapped = MappedLock;
module.exports = exports;
