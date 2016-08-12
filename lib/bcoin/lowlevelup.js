/*!
 * lowlevelup.js - low level levelup
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('./utils');
var assert = utils.assert;
var AsyncObject = require('./async');
var VERSION_ERROR;

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
  if (!(this instanceof LowlevelUp))
    return new LowlevelUp(file, options);

  AsyncObject.call(this);

  this.options = options;
  this.backend = options.db;
  this.location = file;

  this.db = new options.db(file);

  // Stay as close to the metal as possible.
  // We want to make calls to C++ directly.
  while (this.db.db && this.db.db.put && this.db.db !== this.db)
    this.db = this.db.db;

  this.binding = this.db;

  if (this.db.binding)
    this.binding = this.db.binding;
}

utils.inherits(LowlevelUp, AsyncObject);

/**
 * Open the database (recallable).
 * @alias LowlevelUp#open
 * @param {Function} callback
 */

LowlevelUp.prototype._open = function open(callback) {
  this.binding.open(this.options, callback);
};

/**
 * Close the database (recallable).
 * @alias LowlevelUp#close
 * @param {Function} callback
 */

LowlevelUp.prototype._close = function close(callback) {
  this.binding.close(callback);
};

/**
 * Destroy the database.
 * @param {Function} callback
 */

LowlevelUp.prototype.destroy = function destroy(callback) {
  assert(!this.loading);
  assert(!this.closing);
  assert(!this.loaded);

  if (!this.backend.destroy)
    return utils.nextTick(callback);

  this.backend.destroy(this.location, callback);
};

/**
 * Repair the database.
 * @param {Function} callback
 */

LowlevelUp.prototype.repair = function repair(callback) {
  assert(!this.loading);
  assert(!this.closing);
  assert(!this.loaded);

  if (!this.backend.repair)
    return utils.asyncify(callback)(new Error('Cannot repair.'));

  this.backend.repair(this.location, callback);
};

/**
 * Retrieve a record from the database.
 * @param {String} key
 * @param {Object?} options
 * @param {Function} callback - Returns [Error, Buffer].
 */

LowlevelUp.prototype.get = function get(key, options, callback) {
  assert(this.loaded, 'Cannot use database before it is loaded.');

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  return this.binding.get(key, options, function(err, result) {
    if (err) {
      if (isNotFound(err))
        return callback();
      return callback(err);
    }
    return callback(null, result);
  });
};

/**
 * Store a record in the database.
 * @param {String} key
 * @param {Buffer} value
 * @param {Object?} options
 * @param {Function} callback
 */

LowlevelUp.prototype.put = function put(key, value, options, callback) {
  assert(this.loaded, 'Cannot use database before it is loaded.');
  return this.binding.put(key, value, options, callback);
};

/**
 * Remove a record from the database.
 * @param {String} key
 * @param {Object?} options
 * @param {Function} callback
 */

LowlevelUp.prototype.del = function del(key, options, callback) {
  assert(this.loaded, 'Cannot use database before it is loaded.');
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
  assert(this.loaded, 'Cannot use database before it is loaded.');

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
  assert(this.loaded, 'Cannot use database before it is loaded.');
  return this.db.iterator(options);
};

/**
 * Get a database property.
 * @param {String} name - Property name.
 * @returns {String}
 */

LowlevelUp.prototype.getProperty = function getProperty(name) {
  assert(this.loaded, 'Cannot use database before it is loaded.');

  if (!this.binding.getProperty)
    return '';

  return this.binding.getProperty(name);
};

/**
 * Calculate approximate database size.
 * @param {String} start - Start key.
 * @param {String} end - End key.
 * @param {Function} callback - Returns [Error, Number].
 */

LowlevelUp.prototype.approximateSize = function approximateSize(start, end, callback) {
  assert(this.loaded, 'Cannot use database before it is loaded.');
  return this.binding.approximateSize(start, end, callback);
};

/**
 * Test whether a key exists.
 * @param {String} key
 * @param {Function} callback - Returns [Error, Boolean].
 */

LowlevelUp.prototype.has = function has(key, callback) {
  return this.get(key, function(err, value) {
    if (err)
      return callback(err);

    return callback(null, value != null);
  });
};

/**
 * Get and deserialize a record with a callback.
 * @param {String} key
 * @param {Function} parse - Accepts [Buffer(data), String(key)].
 * Return value should be the parsed object.
 * @param {Function} callback - Returns [Error, Object].
 */

LowlevelUp.prototype.fetch = function fetch(key, parse, callback) {
  return this.get(key, function(err, value) {
    if (err)
      return callback(err);

    if (!value)
      return callback();

    try {
      value = parse(value, key);
    } catch (e) {
      return callback(e);
    }

    return callback(null, value);
  });
};

LowlevelUp.prototype.each = function each(options, handler, callback) {
  var opt, iter;

  opt = {
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: options.values || false,
    fillCache: options.fillCache || false,
    keyAsBuffer: options.keyAsBuffer || false,
    valueAsBuffer: true,
    reverse: options.reverse || false
  };

  if (options.limit != null)
    opt.limit = options.limit;

  iter = this.iterator(opt);

  (function next(stop) {
    if (stop === true)
      return iter.end(callback);

    iter.next(function(err, key, value) {
      if (err) {
        return iter.end(function() {
          callback(err);
        });
      }

      if (key === undefined)
        return iter.end(callback);

      handler(key, value, next);
    });
  })();
};

/**
 * Collect all keys from iterator options.
 * @param {Object} options - Iterator options.
 * @param {Function} callback - Returns [Error, Array].
 */

LowlevelUp.prototype.iterate = function iterate(options, callback) {
  var items = [];
  var iter, opt;

  opt = {
    gte: options.gte,
    lte: options.lte,
    keys: true,
    values: options.values || false,
    fillCache: options.fillCache || false,
    keyAsBuffer: options.keyAsBuffer || false,
    valueAsBuffer: true,
    reverse: options.reverse || false
  };

  // Work around a bug in leveldown that
  // I haven't fixed yet, where iterator
  // treats limit=undefined as limit=0.
  if (options.limit != null)
    opt.limit = options.limit;

  iter = this.iterator(opt);

  (function next() {
    iter.next(function(err, key, value) {
      if (err) {
        return iter.end(function() {
          callback(err);
        });
      }

      if (key === undefined) {
        return iter.end(function(err) {
          if (err)
            return callback(err);
          return callback(null, items);
        });
      }

      if (options.values) {
        if (options.parse) {
          try {
            value = options.parse(value, key);
          } catch (e) {
            return iter.end(function() {
              return callback(e);
            });
          }
        }
        if (value)
          items.push(value);
        return next();
      }

      if (options.transform)
        key = options.transform(key);

      if (key)
        items.push(key);

      next();
    });
  })();
};

/**
 * Collect all keys from iterator options.
 * Proxy the keys to further lookups.
 * @param {Object} options - Iterator options.
 * @param {Function} callback - Returns [Error, Array].
 */

LowlevelUp.prototype.lookup = function lookup(options, callback) {
  var self = this;
  var items = [];

  assert(!options.values, 'Cannot pass `values` into lookup.');

  return this.iterate(options, function(err, keys) {
    if (err)
      return callback(err);

    utils.forEachSerial(keys, function(key, next) {
      self.get(key, function(err, value) {
        if (err)
          return callback(err);

        if (!value)
          return next();

        if (options.parse) {
          try {
            value = options.parse(value, key);
          } catch (e) {
            return callback(e);
          }
        }

        if (value)
          items.push(value);

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      return callback(null, items);
    });
  });
};

/**
 * Write and assert a version number for the database.
 * @param {Number} version
 * @param {Function} callback
 */

LowlevelUp.prototype.checkVersion = function checkVersion(key, version, callback) {
  var self = this;
  this.get(key, function(err, data) {
    if (err)
      return callback(err);

    if (!data) {
      data = new Buffer(4);
      data.writeUInt32LE(version, 0, true);
      return self.put(key, data, callback);
    }

    data = data.readUInt32LE(0, true);

    if (data !== version)
      return callback(new Error(VERSION_ERROR));

    return callback();
  });
};

/*
 * Helpers
 */

function isNotFound(err) {
  if (!err)
    return false;

  return err.notFound
    || err.type === 'NotFoundError'
    || /not\s*found/i.test(err.message);
}

VERSION_ERROR = 'Warning:'
  + ' Your database does not match the current database version.'
  + ' This is likely because the database layout or serialization'
  + ' format has changed drastically. If you want to dump your'
  + ' data, downgrade to your previous version first. If you do'
  + ' not think you should be seeing this error, post an issue on'
  + ' the repo.';

/*
 * Expose
 */

module.exports = LowlevelUp;
