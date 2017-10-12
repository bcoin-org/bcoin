'use strict';

const Level = require('level-js');

function DB(location) {
  this.level = new Level(location);
}

DB.prototype.open = function open(options, callback) {
  this.level.open(options, callback);
};

DB.prototype.close = function close(callback) {
  this.level.close(callback);
};

DB.prototype.get = function get(key, options, callback) {
  this.level.get(toHex(key), options, callback);
};

DB.prototype.put = function put(key, value, options, callback) {
  this.level.put(toHex(key), value, options, callback);
};

DB.prototype.del = function del(key, options, callback) {
  this.level.del(toHex(key), options, callback);
};

DB.prototype.batch = function batch(ops, options, callback) {
  if (!ops)
    return new Batch(this);

  for (const op of ops)
    op.key = toHex(op.key);

  this.level.batch(ops, options, callback);

  return undefined;
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
  this.batch.put(toHex(key), value);
  this.hasOps = true;
  return this;
};

Batch.prototype.del = function del(key) {
  this.batch.del(toHex(key));
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
  const opt = {
    gt: toHex(options.gt),
    gte: toHex(options.gte),
    lt: toHex(options.lt),
    lte: toHex(options.lte),
    limit: options.limit,
    reverse: options.reverse,
    keys: options.keys,
    values: options.values,
    keyAsBuffer: false,
    valueAsBuffer: true
  };
  this.db = db;
  this.iter = db.level.iterator(opt);
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

    if (key)
      key = Buffer.from(key, 'hex');

    if (value && !Buffer.isBuffer(value) && value.buffer)
      value = Buffer.from(value.buffer);

    callback(err, key, value);
  });
};

Iterator.prototype.seek = function seek(key) {
  this.iter.seek(toHex(key));
};

Iterator.prototype.end = function end(callback) {
  if (this._end) {
    callback(new Error('end() already called on iterator.'));
    return;
  }
  this._end = true;
  this.iter.end(callback);
};

function toHex(key) {
  if (Buffer.isBuffer(key))
    return key.toString('hex');
  return key;
}

module.exports = DB;
