/*!
 * async.js - async object class for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var assert = utils.assert;
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

  this.loading = false;
  this.closing = false;
  this.loaded = false;
  this.locker = null;
}

utils.inherits(AsyncObject, EventEmitter);

/**
 * Open the object (recallable).
 * @param {Function} callback
 */

AsyncObject.prototype.open = function open(callback) {
  var self = this;

  callback = utils.ensure(callback);

  assert(!this.closing, 'Cannot open while closing.');

  if (this.loaded)
    return utils.nextTick(callback);

  if (this.loading)
    return this.once('open', callback);

  if (this.locker) {
    callback = this.locker.lock(open, [callback]);
    assert(callback, 'Cannot call methods before load.');
  }

  this.emit('preopen');

  this.loading = true;

  this._open(function(err) {
    utils.nextTick(function() {
      if (err) {
        self.loading = false;
        self._error('open', err);
        return callback(err);
      }

      self.loading = false;
      self.loaded = true;
      self.emit('open');

      callback();
    });
  });
};

/**
 * Close the object (recallable).
 * @param {Function} callback
 */

AsyncObject.prototype.close = function close(callback) {
  var self = this;

  callback = utils.ensure(callback);

  assert(!this.loading, 'Cannot close while loading.');

  if (!this.loaded)
    return utils.nextTick(callback);

  if (this.closing)
    return this.on('close', callback);

  if (this.locker) {
    callback = this.locker.lock(close, [callback]);
    if (!callback)
      return;
  }

  this.emit('preclose');

  this.closing = true;
  this.loaded = false;

  this._close(function(err) {
    utils.nextTick(function() {
      if (err) {
        self.closing = false;
        self._error('close', err);
        return callback(err);
      }

      self.closing = false;
      self.emit('close');

      callback();
    });
  });
};

/**
 * Close the object (recallable).
 * @method
 * @param {Function} callback
 */

AsyncObject.prototype.destroy = AsyncObject.prototype.close;

/**
 * Emit an error for `open` or `close` listeners.
 * @private
 * @param {String} event
 * @param {Error} err
 */

AsyncObject.prototype._error = function _error(event, err) {
  var listeners = this.listeners(event);
  var i;

  this.removeAllListeners(event);

  for (i = 0; i < listeners.length; i++)
    listeners[i](err);

  this.emit('error', err);
};

/**
 * Initialize the object.
 * @private
 * @param {Function} callback
 */

AsyncObject.prototype._open = function _open(callback) {
  throw new Error('Abstract method.');
};

/**
 * Close the object.
 * @private
 * @param {Function} callback
 */

AsyncObject.prototype._close = function _close(callback) {
  throw new Error('Abstract method.');
};

/*
 * Expose
 */

module.exports = AsyncObject;
