/**
 * locker.js - lock and queue for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;

/**
 * Locker
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

Locker.prototype.hasPending = function hasPending(key) {
  return this.pendingMap[key] === true;
};

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

Locker.prototype.purgePending = function purgePending() {
  var self = this;

  assert(this.add);

  utils.debug('Warning: %dmb of pending objects. Purging.',
    utils.mb(this.pendingSize));

  this.pending.forEach(function(obj) {
    delete self.pendingMap[obj.hash('hex')];
  });

  this.pending.length = 0;
  this.pendingSize = 0;

  this.jobs = this.jobs.filter(function(item) {
    return item[0] !== self.add;
  });
};

Locker.prototype.onFlush = function onFlush(callback) {
  if (this.pending.length === 0)
    return callback();

  this.once('flush', callback);
};

/**
 * Expose
 */

module.exports = Locker;
