/**
 * datastore.js - storage
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../bcoin');
var levelup = require('levelup');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;
var pad32 = utils.pad32;

var MAX_FILE_SIZE = 128 * 1024 * 1024;
// var MAX_FILE_SIZE = 10 * 1024 * 1024;
var NULL_CHUNK = new Buffer([0xff, 0xff, 0xff, 0xff]);

/**
 * DataStore
 */

function DataStore(db, options) {
  if (!(this instanceof DataStore))
    return new DataStore(db, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.dir = options.name;

  bcoin.ensurePrefix();

  if (!this.dir)
    this.dir = bcoin.prefix + '/store-' + network.type + '.db';

  this._db = db;
  this.db = this;

  this.busy = false;
  this.jobs = [];

  this.fileIndex = -1;

  // Keep a pool of FDs open for disk cache benefits
  this.pool = new bcoin.lru(50, 1, function(key, value) {
    fs.close(value.fd, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  this._init();
}

utils.inherits(DataStore, EventEmitter);

DataStore.prototype._lock = function _lock(func, args, force) {
  var self = this;
  var called;

  if (force) {
    assert(this.busy);
    return function unlock() {
      assert(!called);
      called = true;
    };
  }

  if (this.busy) {
    this.jobs.push([func, args]);
    return;
  }

  this.busy = true;

  return function unlock() {
    var item;

    assert(!called);
    called = true;

    self.busy = false;

    if (self.jobs.length === 0) {
      self.emit('flush');
      return;
    }

    item = self.jobs.shift();
    item[0].apply(self, item[1]);
  };
};

DataStore.prototype._exists = function _exists(callback) {
  fs.stat(this.dir, function(err) {
    if (err && err.code !== 'ENOENT')
      return callback(err);
    return callback(null, err == null);
  });
};

DataStore.prototype._ensure = function _ensure(callback) {
  var self = this;
  this._exists(function(err, result) {
    if (err)
      return callback(err);

    if (result)
      return callback();

    return fs.mkdir(self.dir, 0750, callback);
  });
};

DataStore.prototype._init = function _init(callback) {
  var self = this;
  callback = utils.ensure(callback);
  return this._ensure(function(err) {
    if (err)
      return callback(err);

    self.getLastIndex(function(err, index) {
      if (err)
        return callback(err);

      self.fileIndex = index;

      return callback();
    });
  });
};

DataStore.prototype.allocatePage = function allocatePage(callback) {
  var self = this;
  var index = this.fileIndex + 1;
  fs.writeFile(this.dir + '/f' + pad32(index), new Buffer([]), function(err) {
    if (err)
      return callback(err);
    self.openFile(index, function(err, fd, size, index) {
      if (err)
        return callback(err);

      self.fileIndex = index;
      return callback(null, fd, size, index);
    });
  });
};

DataStore.prototype.openFile = function openFile(index, callback) {
  var self = this;
  var entry = this.pool.get(index);
  if (entry)
    return callback(null, entry.fd, entry.size, index);
  fs.open(this.dir + '/f' + pad32(index), 'r+', function(err, fd) {
    if (err)
      return callback(err);
    fs.fstat(fd, function(err, stat) {
      if (err)
        return callback(err);
      self.pool.set(index, { fd: fd, size: stat.size });
      return callback(null, fd, stat.size, index);
    });
  });
};

DataStore.prototype.currentFile = function currentFile(callback) {
  if (this.fileIndex === -1)
    return this.allocatePage(callback);
  return this.openFile(this.fileIndex, callback);
};

DataStore.prototype.getLastIndex = function getLastIndex(callback) {
  var i, max, index;

  fs.readdir(this.dir, function(err, list) {
    if (err)
      return callback(err);

    max = -1;
    for (i = 0; i < list.length; i++) {
      if (!/^f\d{10}$/.test(list[i]))
        continue;
      index = +list[i].substring(1);
      if (index > max)
        max = index;
    }

    return callback(null, max);
  });
};

DataStore.prototype.close = function close(callback) {
  var self = this;
  return callback();
};

DataStore.prototype.getData = function get(off, callback) {
  var self = this;

  callback = utils.ensure(callback);

  off = this.parseOffset(off);

  this.openFile(off.fileIndex, function(err, fd, fsize) {
    if (err)
      return callback(err);
    return self.read(fd, off.offset, off.size, function(err, data) {
      if (err)
        return callback(err);
      return callback(null, data);
    });
  });
};

DataStore.prototype.get = function get(key, callback) {
  var self = this;
  return this._db.get(key, function(err, offset) {
    if (err)
      return callback(err);
    if (isDirect(key))
      return callback(null, offset);
    return self.getData(offset, callback);
  });
};

DataStore.prototype.batch = function batch(ops, options, callback) {
  var batch;

  if (!callback) {
    callback = options;
    options = null;
  }

  if (!options)
    options = {};

  batch = new Batch(this, options);

  if (ops) {
    batch.ops = ops;
    return batch.write(callback);
  }

  return batch;
};

function Batch(store, options) {
  this.options = options;
  this.ops = [];
  this.store = store;
  this._db = store._db;
}

Batch.prototype.put = function(key, value) {
  this.ops.push({ type: 'put', key: key, value: value });
};

Batch.prototype.del = function del(key) {
  this.ops.push({ type: 'del', key: key });
};

Batch.prototype.write = function write(callback) {
  var self = this;
  var batch;

  if (!this._db)
    return callback(new Error('Already written.'));

  batch = this.options.sync
    ? utils.syncBatch(this._db)
    : this._db.batch();

  if (this.options.sync)
    this._db.fsync = true;

  utils.forEachSerial(this.ops, function(op, next) {
    if (op.type === 'put') {
      if (isDirect(op.key)) {
        batch.put(op.key, op.value);
        return next();
      }
      return self.store.putData(op.value, function(err, offset) {
        if (err)
          return callback(err);
        batch.put(op.key, offset);
        next();
      });
    }

    if (op.type === 'del') {
      if (isDirect(op.key)) {
        batch.del(op.key);
        return next();
      }
      return self._db.get(op.key, function(err, offset) {
        if (err && err.type !== 'NotFoundError')
          return callback(err);
        if (!offset)
          return next();
        batch.del(op.key);
        self.store.delData(offset, next);
      });
    }

    return callback(new Error('Bad op type.'));
  }, function(err) {
    self.ops.length = 0;

    delete self.ops;
    delete self._db;
    delete self.store;

    if (err)
      return callback(err);

    return batch.write(callback);
  });
};

DataStore.prototype.iterator = function iterator(options) {
  return new Iterator(this, options);
};

function Iterator(store, options) {
  this.store = store;
  this._db = store._db;
  if (options && options.keys === false)
    options.keys = true;
  this.iterator = this._db.db.iterator(options);
}

Iterator.prototype.seek = function seek(key) {
  return this.iterator.seek(key);
};

// Store coins, chain entries, dummies, lookup
// hashes directly in the db (unless they're
// the same length as offset).
function isDirect(key) {
  return !/^(b\/b\/|t\/t\/)/.test(key);
}

Iterator.prototype.next = function next(callback) {
  return this.iterator.next(function(err, key, value) {
    if (err)
      return callback(err);

    if (value) {
      if (isDirect(key))
        return callback(null, key, value);
      return self.getData(value, function(err, data) {
        if (err)
          return callback(err);
        return callback(null, key, data);
      });
    }

    return callback(null, key, value);
  });
};

Iterator.prototype.end = function end(callback) {
  var ret = this.iterator.end(callback);
  delete this.iterator;
  delete this.store;
  delete this._db;
  return ret;
};

utils.wrap = function wrap(callback, unlock) {
  return function(err, result) {
    unlock();
    if (callback)
      callback(err, result);
  };
};

DataStore.prototype.putData = function putData(data, callback, force) {
  var self = this;
  var offset;

  var unlock = this._lock(putData, [data, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  this.currentFile(function(err, fd, fsize, index) {
    if (err)
      return callback(err);

    return self.write(fd, fsize, data, function(err, written) {
      if (err)
        return callback(err);

      offset = self.createOffset(index, fsize, written);

      fsize += written;

      // tx1 -> tx1-start/undo -> tx2 -> tx2-start/undo
      return self.write(fd, fsize, offset, function(err, written) {
        if (err)
          return callback(err);

        fsize += written;

        if (self.pool.has(index))
          self.pool.get(index).size = fsize;

        if (fsize > MAX_FILE_SIZE) {
          return self.allocatePage(function(err) {
            if (err)
              return callback(err);
            return callback(null, offset);
          });
        }

        return callback(null, offset);
      });
    });
  });
};

DataStore.prototype.put = function put(key, value, callback) {
  var self = this;

  var unlock = this._lock(put, [key, value, callback]);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (isDirect(key))
    return this._db.put(key, value, callback);

  return this.putData(value, function(err, offset) {
    if (err)
      return callback(err);

    return self._db.put(key, offset, callback);
  }, true);
};

DataStore.prototype.readUndo = function readUndo(index, offset, callback) {
  var self = this;

  return this.openFile(index, function(err, fd, fsize) {
    if (err)
      return callback(err);

    return self.read(fd, offset - 12, 12, function(err, data) {
      if (err)
        return callback(err);

      return callback(null, self.parseOffset(data));
    });
  });
};

DataStore.prototype.delData = function delData(off, callback, force) {
  var self = this;
  var index, offset, size;

  var unlock = this._lock(delData, [off, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  off = this.parseOffset(off);
  index = off.fileIndex;
  offset = off.offset;
  size = off.size;

  return this.openFile(index, function(err, fd, fsize) {
    if (err)
      return callback(err);

    // Overwrite the "fileIndex" in the undo chunk
    return self.write(fd, offset + size, NULL_CHUNK, function(err) {
      if (err)
        return callback(err);

      if (offset + size + 12 !== fsize)
        return callback();

      // If we're deleting the last record, traverse
      // through the reverse linked list of undo offsets
      // until we hit a record that isn't deleted.
      // Truncate to the last deleted record's offset.
      (function next() {
        if (offset === 0)
          return done();
        self.readUndo(index, offset, function(err, undo) {
          if (err)
            return callback(err);
          if (undo.fileIndex !== 0xffffffff)
            return done();
          offset = undo.offset;
          if (offset === 0)
            return done();
          return next();
        });
      })();

      function done() {
        // Delete the file if nothing is in it.
        if (offset === 0) {
          self.pool.remove(index);
          return fs.unlink(self.dir + '/f' + pad32(index), callback);
        }
        self.truncate(index, offset + 12, callback);
      }
    });
  });
};

DataStore.prototype.del = function del(key, callback, force) {
  var self = this;

  var unlock = this._lock(del, [key, callback], force);
  if (!unlock)
    return;

  callback = utils.wrap(callback, unlock);

  if (isDirect(key))
    return this._db.del(key, callback);

  this._db.get(key, function(err, off) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);
    if (!off)
      return callback();
    self.delData(off, function(err) {
      if (err)
        return callback(err);
      self._db.del(key, callback);
    }, true);
  });
};

DataStore.prototype.createOffset = function createOffset(fileIndex, offset, size) {
  var buf = new Buffer(12);
  utils.writeU32(buf, fileIndex, 0);
  utils.writeU32(buf, offset, 4);
  utils.writeU32(buf, size, 8);
  return buf;
};

DataStore.prototype.parseOffset = function parseOffset(data) {
  return {
    fileIndex: utils.readU32(data, 0),
    offset: utils.readU32(data, 4),
    size: utils.readU32(data, 8)
  };
};

DataStore.prototype.truncate = function truncate(index, size, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.openFile(index, function(err, fd, fsize) {
    if (err)
      return callback(err);

    fs.ftruncate(fd, size, function(err) {
      if (err)
        return callback(err);

      if (self.pool.has(index))
        self.pool.get(index).size = size;

      return callback();
    });
  });
};

DataStore.prototype._ioError = function _ioError(name, size, offset) {
  return new Error(name
    + '() failed at offset '
    + offset
    + ' with '
    + size
    + ' bytes left.');
};

DataStore.prototype.read = function read(fd, offset, size, callback) {
  var self = this;
  var index = 0;
  var data;

  callback = utils.ensure(callback);

  assert(!(offset < 0 || offset == null))

  data = new Buffer(size);

  (function next() {
    fs.read(fd, data, index, size, offset, function(err, bytes) {
      if (err)
        return callback(err);

      if (!bytes)
        return callback(self._ioError('read', size, offset));

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length)
        return callback(null, data);

      next();
    });
  })();
};

DataStore.prototype.write = function write(fd, offset, data, callback) {
  var self = this;
  var size = data.length;
  var index = 0;

  callback = utils.ensure(callback);

  assert(!(offset < 0 || offset == null));

  (function next() {
    fs.write(fd, data, index, size, offset, function(err, bytes) {
      if (err) {
        return callback(err, index);
      }

      if (!bytes)
        return callback(self._ioError('write', size, offset));

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length) {
        if (!self.fsync)
          return callback(null, index);
        return fs.fsync(fd, function(err) {
          if (err)
            return callback(err);
          return callback(null, index);
        });
      }

      next();
    });
  })();
};

module.exports = DataStore;
