/*!
 * async.js - async object class for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var util = require('./util');
var co = require('./co');
var Lock = require('./lock');

/**
 * An abstract object that handles state and
 * provides recallable open and close methods.
 * @alias module:utils.AsyncObject
 * @constructor
 * @property {Boolean} loading
 * @property {Boolean} closing
 * @property {Boolean} loaded
 */

function AsyncObject() {
  assert(this instanceof AsyncObject);

  EventEmitter.call(this);

  this._asyncLock = new Lock();
  this._hooks = Object.create(null);

  this.loading = false;
  this.closing = false;
  this.loaded = false;
}

util.inherits(AsyncObject, EventEmitter);

/**
 * Open the object (recallable).
 * @method
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
 * @method
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype.__open = co(function* open() {
  if (this.loaded)
    return;

  yield this.fire('preopen');

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

  yield this.fire('open');
});

/**
 * Close the object (recallable).
 * @method
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
 * @method
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype.__close = co(function* close() {
  if (!this.loaded)
    return;

  yield this.fire('preclose');

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

  yield this.fire('close');
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

/**
 * Add a hook listener.
 * @param {String} type
 * @param {Function} handler
 */

AsyncObject.prototype.hook = function hook(type, handler) {
  assert(typeof type === 'string', '`type` must be a string.');

  if (!this._hooks[type])
    this._hooks[type] = [];

  this._hooks[type].push(handler);
};

/**
 * Emit events and hooks for type.
 * @method
 * @param {String} type
 * @param {...Object} args
 * @returns {Promise}
 */

AsyncObject.prototype.fire = co(function* fire() {
  yield this.fireHook.apply(this, arguments);
  this.emit.apply(this, arguments);
});

/**
 * Emit an asynchronous event (hook).
 * Wait for promises to resolve.
 * @method
 * @param {String} type
 * @param {...Object} args
 * @returns {Promise}
 */

AsyncObject.prototype.fireHook = co(function* fireHook(type) {
  var i, j, listeners, args, handler;

  assert(typeof type === 'string', '`type` must be a string.');

  listeners = this._hooks[type];

  if (!listeners || listeners.length === 0)
    return;

  for (i = 0; i < listeners.length; i++) {
    handler = listeners[i];

    switch (arguments.length) {
      case 1:
        yield handler();
        break;
      case 2:
        yield handler(arguments[1]);
        break;
      case 3:
        yield handler(arguments[1], arguments[2]);
        break;
      case 4:
        yield handler(arguments[1], arguments[2], arguments[3]);
        break;
      default:
        if (!args) {
          args = new Array(arguments.length - 1);
          for (j = 1; j < arguments.length; j++)
            args[j - 1] = arguments[j];
        }
        yield handler.apply(null, args);
        break;
    }
  }
});

/*
 * Expose
 */

module.exports = AsyncObject;
