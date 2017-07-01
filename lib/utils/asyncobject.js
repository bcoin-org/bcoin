/*!
 * async.js - async object class for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const util = require('./util');
const Lock = require('./lock');

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

AsyncObject.prototype.open = async function open() {
  let unlock = await this._asyncLock.lock();
  try {
    return await this.__open();
  } finally {
    unlock();
  }
};

/**
 * Open the object (without a lock).
 * @method
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype.__open = async function open() {
  if (this.loaded)
    return;

  await this.fire('preopen');

  this.loading = true;

  try {
    await this._open();
  } catch (e) {
    this.loading = false;
    this.emit('error', e);
    throw e;
  }

  this.loading = false;
  this.loaded = true;

  await this.fire('open');
};

/**
 * Close the object (recallable).
 * @method
 * @returns {Promise}
 */

AsyncObject.prototype.close = async function close() {
  let unlock = await this._asyncLock.lock();
  try {
    return await this.__close();
  } finally {
    unlock();
  }
};

/**
 * Close the object (without a lock).
 * @method
 * @private
 * @returns {Promise}
 */

AsyncObject.prototype.__close = async function close() {
  if (!this.loaded)
    return;

  await this.fire('preclose');

  this.closing = true;

  try {
    await this._close();
  } catch (e) {
    this.closing = false;
    this.emit('error', e);
    throw e;
  }

  this.closing = false;
  this.loaded = false;

  await this.fire('close');
};

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

AsyncObject.prototype.fire = async function fire() {
  await this.fireHook.apply(this, arguments);
  this.emit.apply(this, arguments);
};

/**
 * Emit an asynchronous event (hook).
 * Wait for promises to resolve.
 * @method
 * @param {String} type
 * @param {...Object} args
 * @returns {Promise}
 */

AsyncObject.prototype.fireHook = async function fireHook(type) {
  let listeners, args;

  assert(typeof type === 'string', '`type` must be a string.');

  listeners = this._hooks[type];

  if (!listeners || listeners.length === 0)
    return;

  for (let handler of listeners) {
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
          for (let i = 1; i < arguments.length; i++)
            args[i - 1] = arguments[i];
        }
        await handler.apply(null, args);
        break;
    }
  }
};

/*
 * Expose
 */

module.exports = AsyncObject;
