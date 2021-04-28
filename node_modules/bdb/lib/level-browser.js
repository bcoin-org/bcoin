/*!
 * level-browser.js - IDB wrapper for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on IDBWrapper.
 * @license IDBWrapper - A cross-browser wrapper for IndexedDB
 * Version 1.7.2
 * Copyright (c) 2011 - 2017 Jens Arps
 * http://jensarps.de/
 *
 * Licensed under the MIT license
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const IDB = global.indexedDB
  || global.webkitIndexedDB
  || global.mozIndexedDB
  || global.shimIndexedDB;

const KeyRange = global.IDBKeyRange
  || global.webkitIDBKeyRange
  || global.mozIDBKeyRange;

const flags = {
  READ_ONLY: 'readonly',
  READ_WRITE: 'readwrite',
  VERSION_CHANGE: 'versionchange',
  NEXT: 'next',
  NEXT_UNIQUE: 'nextunique',
  PREV: 'prev',
  PREV_UNIQUE: 'prevunique'
};

/**
 * Level
 */

class Level {
  constructor(location) {
    assert(typeof location === 'string');
    this.options = {};
    this.version = 1;
    this.name = `bdb-${location}`;
    this.location = location;
    this.db = null;
    this.store = null;
  }

  transaction(flag) {
    return this.db.transaction([this.location], flag);
  }

  open(options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    if (!options)
      options = {};

    this.options = options;

    const req = IDB.open(this.name, this.version);

    req.onerror = createErrback(callback);

    req.onsuccess = (event) => {
      if (this.db) {
        callback();
        return;
      }

      this.db = event.target.result;

      if (typeof this.db.version === 'string') {
        callback(new Error('IndexedDB is out of date.'));
        return;
      }

      if (!this.db.objectStoreNames.contains(this.location)) {
        callback(new Error('Could not create object store.'));
        return;
      }

      const tx = this.transaction(flags.READ_ONLY);

      this.store = tx.objectStore(this.location);

      callback();
    };

    req.onupgradeneeded = (event) => {
      this.db = event.target.result;

      if (this.db.objectStoreNames.contains(this.location)) {
        this.store = event.target.transaction.objectStore(this.location);
        return;
      }

      this.store = this.db.createObjectStore(this.location, {
        autoIncrement: false
      });
    };

    return this;
  }

  close(callback) {
    this.db.close();
    callback();
    return this;
  }

  put(key, value, callback) {
    const errback = createErrback(callback);
    const tx = this.transaction(flags.READ_WRITE);

    let success = false;

    tx.oncomplete = () => {
      if (!success) {
        callback(new Error('Operation failed.'));
        return;
      }
      callback();
    };

    tx.onabort = errback;
    tx.onerror = errback;

    const req = tx.objectStore(this.location).put(value, toHex(key));

    req.onsuccess = (event) => {
      success = true;
    };

    req.onerror = errback;

    return this;
  }

  get(key, options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    if (!options)
      options = {};

    const errback = createErrback(callback);
    const tx = this.transaction(flags.READ_ONLY);

    let success = false;
    let result = null;

    tx.oncomplete = () => {
      if (!success) {
        callback(new Error('Operation failed.'));
        return;
      }

      if (result === undefined) {
        const err = new Error('IDB_NOTFOUND: Key not found.');
        err.notFound = true;
        err.type = 'NotFoundError';
        callback(err);
        return;
      }

      if (result && !Buffer.isBuffer(result) && result.buffer)
        result = Buffer.from(result.buffer);

      if (options.asBuffer === false)
        result = result.toString('utf8');

      callback(null, result);
    };

    tx.onabort = errback;
    tx.onerror = errback;

    const req = tx.objectStore(this.location).get(toHex(key));

    req.onsuccess = function(event) {
      success = true;
      result = event.target.result;
    };

    req.onerror = errback;

    return this;
  }

  del(key, callback) {
    const errback = createErrback(callback);
    const tx = this.transaction(flags.READ_WRITE);

    let success = false;

    tx.oncomplete = () => {
      if (!success) {
        callback(new Error('Operation failed.'));
        return;
      }
      callback();
    };

    tx.onabort = errback;
    tx.onerror = errback;

    const req = tx.objectStore(this.location).delete(toHex(key));

    req.onsuccess = (event) => {
      success = true;
    };

    req.onerror = errback;

    return this;
  }

  batch(ops, options, callback) {
    if (!callback) {
      callback = options;
      options = null;
    }

    const b = new Batch(this, options);

    if (ops) {
      b.ops = ops;
      b.write(callback);
      return undefined;
    }

    return b;
  }

  iterator(options) {
    return new Iterator(this, options);
  }

  static destroy(location, callback) {
    if (!IDB.deleteDatabase) {
      callback(new Error('Destroy not supported.'));
      return;
    }

    const req = IDB.deleteDatabase(`bdb-${location}`);
    req.onsuccess = () => callback();
    req.onerror = createErrback(callback);
  }
}

/**
 * Batch
 */

class Batch {
  /**
   * Create a batch.
   * @constructor
   * @ignore
   * @param {Level} db
   * @param {Object?} options
   */

  constructor(db, options) {
    this.db = db;
    this.options = options || {};
    this.ops = [];
    this.written = false;
  }

  /**
   * Insert a record.
   * @param {Buffer|String} key
   * @param {Buffer} value
   */

  put(key, value) {
    assert(!this.written, 'Already written.');
    this.ops.push(new BatchOp('put', key, value));
    return this;
  }

  /**
   * Remove a record.
   * @param {Buffer|String} key
   */

  del(key) {
    assert(!this.written, 'Already written.');
    this.ops.push(new BatchOp('del', key));
    return this;
  }

  /**
   * Commit the batch.
   * @param {Function} callback
   */

  write(callback) {
    if (this.written) {
      callback(new Error('Already written.'));
      return this;
    }

    const errback = createErrback(callback);
    const tx = this.db.transaction(flags.READ_WRITE);

    let count = this.ops.length;
    let called = false;
    let success = false;

    tx.oncomplete = () => {
      if (!success) {
        callback(new Error('Operation failed.'));
        return;
      }
      callback();
    };

    tx.onabort = errback;
    tx.onerror = errback;

    const onSuccess = () => {
      count -= 1;
      if (count === 0 && !called) {
        called = true;
        success = true;
      }
    };

    const onError = (event) => {
      tx.abort();
      if (!called) {
        called = true;
        errback(event);
      }
    };

    for (const {type, key, value} of this.ops) {
      const store = tx.objectStore(this.db.location);
      switch (type) {
        case 'put': {
          const req = store.put(value, toHex(key));
          req.onsuccess = onSuccess;
          req.onerror = onError;
          break;
        }
        case 'del': {
          const req = store.delete(toHex(key));
          req.onsuccess = onSuccess;
          req.onerror = onError;
          break;
        }
        default: {
          callback(new Error('Bad op type.'));
          return this;
        }
      }
    }

    return this;
  }

  /**
   * Clear batch of all ops.
   */

  clear() {
    assert(!this.written, 'Already written.');
    this.ops = [];
    return this;
  }
}

/**
 * Batch Op
 */

class BatchOp {
  /**
   * Create a batch op.
   * @constructor
   * @ignore
   * @param {String} type
   * @param {Buffer} key
   * @param {Buffer|null} value
   */

  constructor(type, key, value) {
    this.type = type;
    this.key = key;
    this.value = value;
  }
}

/**
 * Iterator
 */

class Iterator {
  constructor(db, options) {
    this.db = db;
    this.options = new IteratorOptions(options);
    this.cursor = null;
    this.error = null;
    this.started = false;
    this.ended = false;
    this.callback = null;
  }

  seek(key) {
    throw new Error('Not implemented.');
  }

  next(callback) {
    if (this.ended) {
      callback(new Error('Iterator already ended.'));
      return;
    }

    if (this.callback) {
      callback(new Error('Callback already pending.'));
      return;
    }

    if (this.error) {
      callback(this.error);
      return;
    }

    if (!this.started) {
      this.callback = callback;
      this.start();
      return;
    }

    assert(this.cursor);
    this.callback = callback;
    this.cursor.continue();
    this.cursor = null;
  }

  end(callback) {
    if (this.ended) {
      callback(new Error('Iterator already ended.'));
      return;
    }
    this.ended = true;
    callback();
  }

  start() {
    if (this.started)
      return;

    const options = this.options;
    const tx = this.db.transaction(flags.READ_ONLY);
    const store = tx.objectStore(this.db.location);

    let success = false;
    let total = 0;

    tx.oncomplete = () => {
      if (!success && !this.error)
        this.error = new Error('Iterator ended early.');

      if (this.error) {
        this.respond(this.error);
        return;
      }

      this.respond(null, undefined, undefined);
    };

    const onError = (event) => {
      this.error = wrapError(event);
      this.respond(this.error);
    };

    tx.onabort = onError;
    tx.onerror = onError;

    const start = toHex(options.start);
    const end = toHex(options.end);

    let range = null;

    if (start && end)
      range = KeyRange.bound(start, end, options.gt, options.lt);
    else if (start)
      range = KeyRange.lowerBound(start, options.gt);
    else if (end)
      range = KeyRange.upperBound(end, options.lt);
    else
      range = KeyRange.lowerBound('\0', true);

    const direction = options.reverse ? flags.PREV : flags.NEXT;
    const req = store.openCursor(range, direction);

    req.onerror = onError;

    req.onsuccess = (event) => {
      const cursor = event.target.result;

      if (this.error) {
        this.respond(this.error);
        return;
      }

      if (!cursor) {
        success = true;
        return;
      }

      if (options.limit !== -1) {
        if (total >= options.limit) {
          success = true;
          return;
        }
        total += 1;
      }

      let key = Buffer.from(cursor.key, 'hex');
      let value = cursor.value;

      if (value && !Buffer.isBuffer(value) && value.buffer)
        value = Buffer.from(value.buffer);

      if (!options.keyAsBuffer)
        key = key.toString('utf8');

      if (!options.valueAsBuffer)
        value = value.toString('utf8');

      this.cursor = cursor;
      this.respond(null, key, value);
    };

    this.started = true;
  }

  respond(err, key, value) {
    if (!this.callback)
      return;
    const cb = this.callback;
    this.callback = null;
    cb(err, key, value);
  }
}

/**
 * Iterator Options
 */

class IteratorOptions {
  /**
   * Create iterator options.
   * @constructor
   * @ignore
   * @param {Object} options
   */

  constructor(options) {
    this.keys = true;
    this.values = true;
    this.start = null;
    this.end = null;
    this.gt = false;
    this.lt = false;
    this.keyAsBuffer = true;
    this.valueAsBuffer = true;
    this.reverse = false;
    this.limit = -1;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options.
   * @private
   * @param {Object} options
   * @returns {IteratorOptions}
   */

  fromOptions(options) {
    if (options.keys != null) {
      assert(typeof options.keys === 'boolean');
      this.keys = options.keys;
    }

    if (options.values != null) {
      assert(typeof options.values === 'boolean');
      this.values = options.values;
    }

    if (options.start != null)
      this.start = options.start;

    if (options.end != null)
      this.end = options.end;

    if (options.gte != null)
      this.start = options.gte;

    if (options.lte != null)
      this.end = options.lte;

    if (options.gt != null) {
      this.gt = true;
      this.start = options.gt;
    }

    if (options.lt != null) {
      this.lt = true;
      this.end = options.lt;
    }

    if (this.start != null) {
      if (typeof this.start === 'string')
        this.start = Buffer.from(this.start, 'utf8');
      assert(Buffer.isBuffer(this.start), '`start` must be a Buffer.');
    }

    if (this.end != null) {
      if (typeof this.end === 'string')
        this.end = Buffer.from(this.end, 'utf8');
      assert(Buffer.isBuffer(this.end), '`end` must be a Buffer.');
    }

    if (options.keyAsBuffer != null) {
      assert(typeof options.keyAsBuffer === 'boolean');
      this.keyAsBuffer = options.keyAsBuffer;
    }

    if (options.valueAsBuffer != null) {
      assert(typeof options.valueAsBuffer === 'boolean');
      this.valueAsBuffer = options.valueAsBuffer;
    }

    if (options.reverse != null) {
      assert(typeof options.reverse === 'boolean');
      this.reverse = options.reverse;
    }

    if (options.limit != null) {
      assert(typeof options.limit === 'number');
      this.limit = options.limit;
    }

    return this;
  }
}

/*
 * Helpers
 */

function toHex(key) {
  if (key == null)
    return key;

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  assert(Buffer.isBuffer(key));

  return key.toString('hex');
}

function wrapError(event) {
  if (!event)
    return new Error('Unknown IndexedDB error (no event).');

  if (event instanceof Error)
    return event;

  const {target} = event;

  if (!target)
    return new Error('Unknown IndexedDB error (no target).');

  if (target.error) {
    const {error} = target;

    if (error instanceof Error)
      return error;

    if (error.name === 'VersionError')
      return new Error('IndexedDB version error.');

    return new Error(String(error));
  }

  if (target.errorCode != null) {
    if (target.errorCode === 12)
      return new Error('IndexedDB version error.');
    return new Error(`IndexedDB error: ${target.errorCode}.`);
  }

  return new Error('Unknown IndexedDB error (no error).');
}

function createErrback(callback) {
  return (event) => {
    return callback(wrapError(event));
  };
}

/*
 * Expose
 */

module.exports = Level;
