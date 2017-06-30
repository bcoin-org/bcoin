'use strict';

const Level = require('level-js');

function DB(location) {
  this.level = new Level(location);
  this.bufferKeys = false;
}

DB.prototype.open = function open(options, callback) {
  this.bufferKeys = options.bufferKeys === true;
  this.level.open(options, callback);
};

DB.prototype.close = function close(callback) {
  this.level.close(callback);
};

DB.prototype.get = function get(key, options, callback) {
  if (this.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.level.get(key, options, callback);
};

DB.prototype.put = function get(key, value, options, callback) {
  if (this.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.level.put(key, value, options, callback);
};

DB.prototype.del = function del(key, options, callback) {
  if (this.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.level.del(key, options, callback);
};

DB.prototype.batch = function batch(ops, options, callback) {
  if (!ops)
    return new Batch(this);

  if (this.bufferKeys) {
    for (let op of ops) {
      if (Buffer.isBuffer(op.key))
        op.key = op.key.toString('hex');
    }
  }

  this.level.batch(ops, options, callback);
};

DB.prototype.iterator = function iterator(options) {
  return new Iterator(this, options);
};

DB.destroy = function destroy(db, callback) {
  Level.destroy(db, callback);
};

function Batch(db) {
  this.db = db;
  this.batch = db.level.batch();
  this.hasOps = false;
}

Batch.prototype.put = function put(key, value) {
  if (this.db.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.batch.put(key, value);
  this.hasOps = true;
  return this;
};

Batch.prototype.del = function del(key) {
  if (this.db.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.batch.del(key);
  this.hasOps = true;
  return this;
};

Batch.prototype.write = function write(callback) {
  if (!this.hasOps)
    return callback();
  this.batch.write(callback);
  return this;
};

Batch.prototype.clear = function clear() {
  this.batch.clear();
  return this;
};

function Iterator(db, options) {
  if (db.bufferKeys) {
    if (Buffer.isBuffer(options.gt))
      options.gt = options.gt.toString('hex');
    if (Buffer.isBuffer(options.gte))
      options.gte = options.gte.toString('hex');
    if (Buffer.isBuffer(options.lt))
      options.lt = options.lt.toString('hex');
    if (Buffer.isBuffer(options.lte))
      options.lte = options.lte.toString('hex');
  }
  options.keyAsBuffer = false;
  this.db = db;
  this.iter = db.level.iterator(options);
  this._end = false;
}

Iterator.prototype.next = function next(callback) {
  this.iter.next((err, key, value) => {
    // Hack for level-js: it doesn't actually
    // end iterators -- it keeps streaming keys
    // and values.
    if (this._end)
      return;

    if (err) {
      callback(err);
      return;
    }

    if (key === undefined && value === undefined) {
      callback(err, key, value);
      return;
    }

    if (key && this.db.bufferKeys)
      key = Buffer.from(key, 'hex');

    if (value && !Buffer.isBuffer(value) && value.buffer)
      value = Buffer.from(value.buffer);

    callback(err, key, value);
  });
};

Iterator.prototype.seek = function seek(key) {
  if (this.db.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.iter.seek(key);
};

Iterator.prototype.end = function end(callback) {
  if (this._end)
    return callback(new Error('end() already called on iterator.'));
  this._end = true;
  this.iter.end(callback);
};

module.exports = DB;
