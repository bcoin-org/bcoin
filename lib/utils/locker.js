/*!
 * locker.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var utils = require('../utils/utils');
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
 * @param {Boolean?} force - Bypass the lock.
 * @returns {Promise->Function} Unlocker - must be
 * called once the method finishes executing in order
 * to resolve the queue.
 */

Locker.prototype.lock = function lock(arg1, arg2) {
  var self = this;
  var force, obj;

  if (this.add) {
    obj = arg1;
    force = arg2;
  } else {
    force = arg1;
  }

  if (force) {
    assert(this.busy);
    return new Promise(function(resolve, reject) {
      resolve(function unlock() {});
    });
  }

  if (this.busy) {
    return new Promise(function(resolve, reject) {
      if (obj) {
        self.pending.push(obj);
        self.pendingMap[obj.hash('hex')] = true;
      }
      self.jobs.push([resolve, obj]);
    });
  }

  this.busy = true;

  return new Promise(function(resolve, reject) {
    resolve(function unlock() {
      var item, res, obj;

      self.busy = false;

      if (self.pending.length === 0)
        self.emit('drain');

      if (self.jobs.length === 0)
        return;

      item = self.jobs.shift();
      res = item[0];
      obj = item[1];

      if (obj) {
        assert(obj === self.pending.shift());
        delete self.pendingMap[obj.hash('hex')];
      }

      self.busy = true;
      res(unlock);
    });
  });
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
 * @returns {Promise}
 */

Locker.prototype.onDrain = function onDrain() {
  var self = this;

  assert(this.add, 'Cannot wait for drain without add method.');

  return new Promise(function(resolve, reject) {
    if (self.pending.length === 0)
      return resolve();

    self.once('drain', resolve);
  });
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

MappedLock.prototype.lock = function lock(key, force) {
  var self = this;

  if (force || key == null) {
    assert(key == null || this.busy[key]);
    return new Promise(function(resolve, reject) {
      resolve(function unlock() {});
    });
  }

  if (this.busy[key]) {
    return new Promise(function(resolve, reject) {
      self.jobs.push([resolve, key]);
    });
  }

  this.busy[key] = true;

  return new Promise(function(resolve, reject) {
    resolve(self._unlock(key));
  });
};

/**
 * Create an unlock callback.
 * @private
 * @param {String} key
 * @returns {Function} Unlocker.
 */

MappedLock.prototype._unlock = function _unlock(key) {
  var self = this;
  return function unlock() {
    var item;

    delete self.busy[key];

    if (self.jobs.length === 0)
      return;

    item = self.jobs.shift();

    self.busy = true;
    item[0](self._unlock(item[1]));
  };
};

/*
 * Expose
 */

exports = Locker;
exports.mapped = MappedLock;
module.exports = exports;
