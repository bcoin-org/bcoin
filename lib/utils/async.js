/*!
 * async.js - async object class for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('./util');
var co = require('./co');
var Locker = require('./locker');
var assert = require('assert');
var EventEmitter = require('events').EventEmitter;

/**
 * An abstract object that handles state and
 * provides recallable open and close methods.
 * @constructor
 * @property {Boolean} loading
 * @property {Boolean} closing
 * @property {Boolean} loaded
 */

function AsyncObject() {
  assert(this instanceof AsyncObject);

  EventEmitter.call(this);

  this._asyncLock = new Locker();

  this.loading = false;
  this.closing = false;
  this.loaded = false;
}

util.inherits(AsyncObject, EventEmitter);

/**
 * Open the object (recallable).
 * @returns {Promise}
 */

AsyncObject.prototype.open = co(function* open() {
  var unlock = yield this._asyncLock.lock();
  try {
    return yield this.__open();
  } finally {
    unlock();
  }
});

/**
 * Open the object (without a lock).
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype.__open = co(function* open() {
  if (this.loaded)
    return;

  this.emit('preopen');

  this.loading = true;

  try {
    yield this._open();
  } catch (e) {
    this.loading = false;
    this.emit('error', e);
    throw e;
  }

  this.loading = false;
  this.loaded = true;

  this.emit('open');
});

/**
 * Close the object (recallable).
 * @returns {Promise}
 */

AsyncObject.prototype.close = co(function* close() {
  var unlock = yield this._asyncLock.lock();
  try {
    return yield this.__close();
  } finally {
    unlock();
  }
});

/**
 * Close the object (without a lock).
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype.__close = co(function* close() {
  if (!this.loaded)
    return;

  this.emit('preclose');

  this.closing = true;

  try {
    yield this._close();
  } catch (e) {
    this.closing = false;
    this.emit('error', e);
    throw e;
  }

  this.closing = false;
  this.loaded = false;

  this.emit('close');
});

/**
 * Close the object (recallable).
 * @method
 * @returns {Promise}
 */

AsyncObject.prototype.destroy = AsyncObject.prototype.close;

/**
 * Initialize the object.
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype._open = function _open(callback) {
  throw new Error('Abstract method.');
};

/**
 * Close the object.
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype._close = function _close(callback) {
  throw new Error('Abstract method.');
};

/*
 * Expose
 */

module.exports = AsyncObject;
