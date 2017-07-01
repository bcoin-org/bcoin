/*!
 * asyncemitter.js - event emitter which resolves promises.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * Represents a promise-resolving event emitter.
 * @alias module:utils.AsyncEmitter
 * @see EventEmitter
 * @constructor
 */

function AsyncEmitter() {
  if (!(this instanceof AsyncEmitter))
    return new AsyncEmitter();

  this._events = Object.create(null);
}

/**
 * Add a listener.
 * @param {String} type
 * @param {Function} handler
 */

AsyncEmitter.prototype.addListener = function addListener(type, handler) {
  return this._push(type, handler, false);
};

/**
 * Add a listener.
 * @param {String} type
 * @param {Function} handler
 */

AsyncEmitter.prototype.on = function on(type, handler) {
  return this.addListener(type, handler);
};

/**
 * Add a listener to execute once.
 * @param {String} type
 * @param {Function} handler
 */

AsyncEmitter.prototype.once = function once(type, handler) {
  return this._push(type, handler, true);
};

/**
 * Prepend a listener.
 * @param {String} type
 * @param {Function} handler
 */

AsyncEmitter.prototype.prependListener = function prependListener(type, handler) {
  return this._unshift(type, handler, false);
};

/**
 * Prepend a listener to execute once.
 * @param {String} type
 * @param {Function} handler
 */

AsyncEmitter.prototype.prependOnceListener = function prependOnceListener(type, handler) {
  return this._unshift(type, handler, true);
};

/**
 * Push a listener.
 * @private
 * @param {String} type
 * @param {Function} handler
 * @param {Boolean} once
 */

AsyncEmitter.prototype._push = function _push(type, handler, once) {
  assert(typeof type === 'string', '`type` must be a string.');

  if (!this._events[type])
    this._events[type] = [];

  this._events[type].push(new Listener(handler, once));

  this.emit('newListener', type, handler);
};

/**
 * Unshift a listener.
 * @param {String} type
 * @param {Function} handler
 * @param {Boolean} once
 */

AsyncEmitter.prototype._unshift = function _unshift(type, handler, once) {
  assert(typeof type === 'string', '`type` must be a string.');

  if (!this._events[type])
    this._events[type] = [];

  this._events[type].unshift(new Listener(handler, once));

  this.emit('newListener', type, handler);
};

/**
 * Remove a listener.
 * @param {String} type
 * @param {Function} handler
 */

AsyncEmitter.prototype.removeListener = function removeListener(type, handler) {
  let i, listeners, listener;
  let index = -1;

  assert(typeof type === 'string', '`type` must be a string.');

  listeners = this._events[type];

  if (!listeners)
    return;

  for (i = 0; i < listeners.length; i++) {
    listener = listeners[i];
    if (listener.handler === handler) {
      index = i;
      break;
    }
  }

  if (index === -1)
    return;

  listeners.splice(index, 1);

  if (listeners.length === 0)
    delete this._events[type];

  this.emit('removeListener', type, handler);
};

/**
 * Set max listeners.
 * @param {Number} max
 */

AsyncEmitter.prototype.setMaxListeners = function setMaxListeners(max) {
  assert(typeof max === 'number', '`max` must be a number.');
  assert(max >= 0, '`max` must be non-negative.');
  assert(max % 1 === 0, '`max` must be an integer.');
};

/**
 * Remove all listeners.
 * @param {String?} type
 */

AsyncEmitter.prototype.removeAllListeners = function removeAllListeners(type) {
  if (arguments.length === 0) {
    this._events = Object.create(null);
    return;
  }

  assert(typeof type === 'string', '`type` must be a string.');

  delete this._events[type];
};

/**
 * Get listeners array.
 * @param {String} type
 * @returns {Function[]}
 */

AsyncEmitter.prototype.listeners = function listeners(type) {
  let listeners, listener;
  let result = [];

  assert(typeof type === 'string', '`type` must be a string.');

  listeners = this._events[type];

  if (!listeners)
    return result;

  for (listener of listeners)
    result.push(listener.handler);

  return result;
};

/**
 * Get listener count for an event.
 * @param {String} type
 */

AsyncEmitter.prototype.listenerCount = function listenerCount(type) {
  let listeners;

  assert(typeof type === 'string', '`type` must be a string.');

  listeners = this._events[type];

  if (!listeners)
    return 0;

  return listeners.length;
};

/**
 * Emit an event synchronously.
 * @method
 * @param {String} type
 * @param {...Object} args
 * @returns {Promise}
 */

AsyncEmitter.prototype.emit = function emit(type) {
  let i, j, listeners, error, err, args, listener, handler;

  assert(typeof type === 'string', '`type` must be a string.');

  listeners = this._events[type];

  if (!listeners || listeners.length === 0) {
    if (type === 'error') {
      error = arguments[1];

      if (error instanceof Error)
        throw error;

      err = new Error(`Uncaught, unspecified "error" event. (${error})`);
      err.context = error;
      throw err;
    }
    return;
  }

  for (i = 0; i < listeners.length; i++) {
    listener = listeners[i];
    handler = listener.handler;

    if (listener.once) {
      listeners.splice(i, 1);
      i--;
    }

    switch (arguments.length) {
      case 1:
        handler();
        break;
      case 2:
        handler(arguments[1]);
        break;
      case 3:
        handler(arguments[1], arguments[2]);
        break;
      case 4:
        handler(arguments[1], arguments[2], arguments[3]);
        break;
      default:
        if (!args) {
          args = new Array(arguments.length - 1);
          for (j = 1; j < arguments.length; j++)
            args[j - 1] = arguments[j];
        }
        handler.apply(null, args);
        break;
    }
  }
};

/**
 * Emit an event. Wait for promises to resolve.
 * @method
 * @param {String} type
 * @param {...Object} args
 * @returns {Promise}
 */

AsyncEmitter.prototype.fire = async function fire(type) {
  let i, j, listeners, error, err, args, listener, handler;

  assert(typeof type === 'string', '`type` must be a string.');

  listeners = this._events[type];

  if (!listeners || listeners.length === 0) {
    if (type === 'error') {
      error = arguments[1];

      if (error instanceof Error)
        throw error;

      err = new Error(`Uncaught, unspecified "error" event. (${error})`);
      err.context = error;
      throw err;
    }
    return;
  }

  for (i = 0; i < listeners.length; i++) {
    listener = listeners[i];
    handler = listener.handler;

    if (listener.once) {
      listeners.splice(i, 1);
      i--;
    }

    switch (arguments.length) {
      case 1:
        await handler();
        break;
      case 2:
        await handler(arguments[1]);
        break;
      case 3:
        await handler(arguments[1], arguments[2]);
        break;
      case 4:
        await handler(arguments[1], arguments[2], arguments[3]);
        break;
      default:
        if (!args) {
          args = new Array(arguments.length - 1);
          for (j = 1; j < arguments.length; j++)
            args[j - 1] = arguments[j];
        }
        await handler.apply(null, args);
        break;
    }
  }
};

/**
 * Emit an event. Ignore rejections.
 * @method
 * @param {String} type
 * @param {...Object} args
 * @returns {Promise}
 */

AsyncEmitter.prototype.tryFire = async function tryFire(type) {
  try {
    await this.emit.apply(this, arguments);
  } catch (e) {
    if (type === 'error')
      return;

    try {
      await this.emit('error', e);
    } catch (e) {
      ;
    }
  }
};

/**
 * Event Listener
 * @constructor
 * @ignore
 * @param {Function} handler
 * @param {Boolean} once
 * @property {Function} handler
 * @property {Boolean} once
 */

function Listener(handler, once) {
  assert(typeof handler === 'function', '`handler` must be a function.');
  assert(typeof once === 'boolean', '`once` must be a function.');
  this.handler = handler;
  this.once = once;
}

/*
 * Expose
 */

module.exports = AsyncEmitter;
