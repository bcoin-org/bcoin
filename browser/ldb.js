var level = require('level-js');

function DB(file) {
  this.level = new level(file);
  this.bufferKeys = false;
}

DB.prototype.open = function open(options, callback) {
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
  return this.level.batch(ops, options, callback);
};

DB.prototype.iterator = function iterator(options) {
  options.keyAsBuffer = false;
  return new Iterator(this, options);
};

DB.prototype.approximateSize = function approximateSize(start, end, callback) {
  return this.level.approximateSize(start, end, callback);
};

DB.prototype.getProperty = function getProperty(name) {
  return this.level.getProperty(name);
};

function Batch(db) {
  this.db = db;
  this.batch = db.level.batch();
}

Batch.prototype.put = function(key, value) {
  if (this.db.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.batch.put(key, value);
  return this;
};

Batch.prototype.del = function del(key) {
  if (this.db.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.batch.del(key);
  return this;
};

Batch.prototype.write = function write(callback) {
  this.batch.write(callback);
  return this;
};

Batch.prototype.clear = function clear() {
  this.batch.clear();
  return this;
};

function Iterator(db, options) {
  this.db = db;
  this.iter = db.level.iterator(options);
}

Iterator.prototype.next = function(callback) {
  var self = this;
  this.iter.next(function(err, key, value) {
    if (err) {
      callback(err);
      return;
    }

    if (key === undefined) {
      callback(err, key, value);
      return;
    }

    if (self.db.bufferKeys)
      key = new Buffer(key, 'hex');

    if (!Buffer.isBuffer(value))
      value = new Buffer(value.buffer);

    callback(err, key, value);
  });
};

Iterator.prototype.seek = function seek(key) {
  if (this.db.bufferKeys && Buffer.isBuffer(key))
    key = key.toString('hex');
  this.iter.seek(key);
};

Iterator.prototype.end = function end(callback) {
  this.iter.end(callback);
};

module.exports = DB;
