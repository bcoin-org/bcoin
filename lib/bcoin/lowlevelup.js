/*!
 * lowlevelup.js - low level levelup
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var utils = require('./utils');
var EventEmitter = require('events').EventEmitter;

/**
 * Extremely low-level version of levelup.
 * The only levelup feature it provides is
 * error-wrapping. It gives a nice recallable
 * `open()` method and event. It assumes ascii
 * keys and binary values.
 *
 * This avoids pulling in extra deps and
 * lowers memory usage.
 *
 * @expose LowlevelUp
 * @constructor
 * @param {String} file - Location.
 * @param {Object} options - Leveldown options.
 */

function LowlevelUp(file, options) {
  var self = this;

  if (!(this instanceof LowlevelUp))
    return new LowlevelUp(file, options);

  EventEmitter.call(this);

  this.loaded = false;

  this.db = new options.db(file);

  // Stay as close to the metal as possible.
  // We want to make calls to C++ directly.
  while (this.db.db && this.db.db.put && this.db.db !== this.db)
    this.db = this.db.db;

  this.binding = this.db;

  if (this.db.binding)
    this.binding = this.db.binding;

  this.binding.open(options, function(err) {
    if (err)
      return self.emit('error', err);

    self.loaded = true;
    self.emit('open');
  });
}

utils.inherits(LowlevelUp, EventEmitter);

/**
 * Open the database (recallable).
 * @param {Function} callback
 */

LowlevelUp.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Retrieve a record from the database.
 * @param {String} key
 * @param {Object?} options
 * @param {Function} callback - Returns [Error, Buffer].
 */

LowlevelUp.prototype.get = function get(key, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  return this.binding.get(key, options, function(err, result) {
    if (err) {
      if (err.notFound || /not\s*found/i.test(err.message)) {
        err.notFound = true;
        err.type = 'NotFoundError';
      }
      return callback(err);
    }
    return callback(null, result);
  });
};

/**
 * Close the database (not recallable).
 * @param {Function} callback
 */

LowlevelUp.prototype.close = function close(callback) {
  return this.binding.close(callback);
};

/**
 * Store a record in the database.
 * @param {String} key
 * @param {Buffer} value
 * @param {Object?} options
 * @param {Function} callback
 */

LowlevelUp.prototype.put = function put(key, value, options, callback) {
  return this.binding.put(key, value, options, callback);
};

/**
 * Remove a record from the database.
 * @param {String} key
 * @param {Object?} options
 * @param {Function} callback
 */

LowlevelUp.prototype.del = function del(key, options, callback) {
  return this.binding.del(key, options, callback);
};

/**
 * Create an atomic batch.
 * @param {Array?} ops
 * @param {Object?} options
 * @param {Function} callback
 * @returns {Leveldown.Batch}
 */

LowlevelUp.prototype.batch = function batch(ops, options, callback) {
  if (!ops)
    return this.binding.batch();
  return this.binding.batch(ops, options, callback);
};

/**
 * Create an iterator.
 * @param {Object} options
 * @returns {Leveldown.Iterator}
 */

LowlevelUp.prototype.iterator = function iterator(options) {
  return this.db.iterator(options);
};

/**
 * Get a database property.
 * @param {String} name - Property name.
 * @returns {String?}
 */

LowlevelUp.prototype.getProperty = function getProperty(name) {
  if (!this.binding.getProperty)
    return null;

  return this.binding.getProperty(name);
};

/**
 * Calculate approximate database size.
 * @param {String} start - Start key.
 * @param {String} end - End key.
 * @param {Function} callback - Returns [Error, Number].
 */

LowlevelUp.prototype.approximateSize = function approximateSize(start, end, callback) {
  return this.binding.approximateSize(start, end, callback);
};

module.exports = LowlevelUp;
