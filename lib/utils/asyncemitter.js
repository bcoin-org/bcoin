/*!
 * asyncemitter.js - event emitter which resolves promises.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/**
 * Async Emitter
 * @alias module:utils.AsyncEmitter
 * @see EventEmitter
 */

class AsyncEmitter {
  /**
   * Create an async emitter.
   * @constructor
   */

  constructor() {
    this._events = Object.create(null);
  }

  /**
   * Add a listener.
   * @param {String} type
   * @param {Function} handler
   */

  addListener(type, handler) {
    return this._push(type, handler, false);
  }

  /**
   * Add a listener.
   * @param {String} type
   * @param {Function} handler
   */

  on(type, handler) {
    return this.addListener(type, handler);
  }

  /**
   * Add a listener to execute once.
   * @param {String} type
   * @param {Function} handler
   */

  once(type, handler) {
    return this._push(type, handler, true);
  }

  /**
   * Prepend a listener.
   * @param {String} type
   * @param {Function} handler
   */

  prependListener(type, handler) {
    return this._unshift(type, handler, false);
  }

  /**
   * Prepend a listener to execute once.
   * @param {String} type
   * @param {Function} handler
   */

  prependOnceListener(type, handler) {
    return this._unshift(type, handler, true);
  }

  /**
   * Push a listener.
   * @private
   * @param {String} type
   * @param {Function} handler
   * @param {Boolean} once
   */

  _push(type, handler, once) {
    assert(typeof type === 'string', '`type` must be a string.');

    if (!this._events[type])
      this._events[type] = [];

    this.emit('newListener', type, handler);

    this._events[type].push(new Listener(handler, once));
  }

  /**
   * Unshift a listener.
   * @param {String} type
   * @param {Function} handler
   * @param {Boolean} once
   */

  _unshift(type, handler, once) {
    assert(typeof type === 'string', '`type` must be a string.');

    if (!this._events[type])
      this._events[type] = [];

    this.emit('newListener', type, handler);

    this._events[type].unshift(new Listener(handler, once));
  }

  /**
   * Remove a listener.
   * @param {String} type
   * @param {Function} handler
   */

  removeListener(type, handler) {
    assert(typeof type === 'string', '`type` must be a string.');

    const listeners = this._events[type];

    if (!listeners)
      return;

    let index = -1;

    for (let i = 0; i < listeners.length; i++) {
      const listener = listeners[i];
      if (listener.handler === handler) {
        index = i;
        break;
      }
    }

    if (index === -1)
      return;

    splice(listeners, index);

    if (listeners.length === 0)
      delete this._events[type];

    this.emit('removeListener', type, handler);
  }

  /**
   * Set max listeners.
   * @param {Number} max
   */

  setMaxListeners(max) {
    assert(typeof max === 'number', '`max` must be a number.');
    assert(max >= 0, '`max` must be non-negative.');
    assert(Number.isSafeInteger(max), '`max` must be an integer.');
  }

  /**
   * Remove all listeners.
   * @param {String?} type
   */

  removeAllListeners(type) {
    if (arguments.length === 0) {
      this._events = Object.create(null);
      return;
    }

    assert(typeof type === 'string', '`type` must be a string.');

    delete this._events[type];
  }

  /**
   * Get listeners array.
   * @param {String} type
   * @returns {Function[]}
   */

  listeners(type) {
    assert(typeof type === 'string', '`type` must be a string.');

    const listeners = this._events[type];

    if (!listeners)
      return [];

    const result = [];

    for (const {handler} of listeners)
      result.push(handler);

    return result;
  }

  /**
   * Get listener count for an event.
   * @param {String} type
   */

  listenerCount(type) {
    assert(typeof type === 'string', '`type` must be a string.');

    const listeners = this._events[type];

    if (!listeners)
      return 0;

    return listeners.length;
  }

  /**
   * Get event names.
   * @returns {String[]}
   */

  eventNames() {
    return Object.keys(this._events);
  }

  /**
   * Emit an event synchronously.
   * @param {String} type
   * @param {...Object} args
   * @returns {Promise}
   */

  emit(type) {
    try {
      this._emit.apply(this, arguments);
    } catch (e) {
      if (type === 'error')
        throw e;

      this._emit('error', e);
    }
  }

  /**
   * Emit an event synchronously.
   * @private
   * @param {String} type
   * @param {...Object} args
   * @returns {Promise}
   */

  _emit(type) {
    assert(typeof type === 'string', '`type` must be a string.');

    const listeners = this._events[type];

    if (!listeners) {
      if (type === 'error') {
        const msg = arguments[1];

        if (msg instanceof Error)
          throw msg;

        const err = new Error(`Uncaught, unspecified "error" event. (${msg})`);
        err.context = msg;
        throw err;
      }
      return;
    }

    assert(listeners.length > 0);

    let args = null;

    for (let i = 0; i < listeners.length; i++) {
      const listener = listeners[i];
      const handler = listener.handler;

      if (listener.once) {
        splice(listeners, i);
        if (listeners.length === 0)
          delete this._events[type];
        i -= 1;
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
            for (let j = 1; j < arguments.length; j++)
              args[j - 1] = arguments[j];
          }
          handler.apply(null, args);
          break;
      }
    }
  }

  /**
   * Emit an event. Wait for promises to resolve.
   * @method
   * @param {String} type
   * @param {...Object} args
   * @returns {Promise}
   */

  async emitAsync(type) {
    try {
      await this._emitAsync.apply(this, arguments);
    } catch (e) {
      if (type === 'error')
        throw e;

      await this._emitAsync('error', e);
    }
  }

  /**
   * Emit an event. Wait for promises to resolve.
   * @private
   * @param {String} type
   * @param {...Object} args
   * @returns {Promise}
   */

  async _emitAsync(type) {
    assert(typeof type === 'string', '`type` must be a string.');

    const listeners = this._events[type];

    if (!listeners) {
      if (type === 'error') {
        const msg = arguments[1];

        if (msg instanceof Error)
          throw msg;

        const err = new Error(`Uncaught, unspecified "error" event. (${msg})`);
        err.context = msg;
        throw err;
      }
      return;
    }

    assert(listeners.length > 0);

    let args = null;

    for (let i = 0; i < listeners.length; i++) {
      const listener = listeners[i];
      const handler = listener.handler;

      if (listener.once) {
        splice(listeners, i);
        if (listeners.length === 0)
          delete this._events[type];
        i -= 1;
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
            for (let j = 1; j < arguments.length; j++)
              args[j - 1] = arguments[j];
          }
          await handler.apply(null, args);
          break;
      }
    }
  }
}

/**
 * Event Listener
 * @ignore
 * @property {Function} handler
 * @property {Boolean} once
 */

class Listener {
  /**
   * Create an event listener.
   * @constructor
   * @param {Function} handler
   * @param {Boolean} once
   */

  constructor(handler, once) {
    assert(typeof handler === 'function', '`handler` must be a function.');
    assert(typeof once === 'boolean', '`once` must be a function.');
    this.handler = handler;
    this.once = once;
  }
}

/*
 * Helpers
 */

function splice(list, i) {
  if (i === 0) {
    list.shift();
    return;
  }

  let k = i + 1;

  while (k < list.length)
    list[i++] = list[k++];

  list.pop();
}

/*
 * Expose
 */

module.exports = AsyncEmitter;
