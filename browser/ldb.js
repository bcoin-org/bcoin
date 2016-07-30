var level = require('level-js');

function DB(location) {
  this.level = new level(location);
  this.bufferKeys = false;
}

DB.prototype.open = function open(options, callback) {
  this.bufferKeys = options.bufferKeys;
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
  return new Iterator(this, options);
};

DB.destroy = function destroy(db, callback) {
  level.destroy(db, callback);
};

function Batch(db) {
  this.db = db;
  this.batch = db.level.batch();
  this.hasOps = false;
}

Batch.prototype.put = function(key, value) {
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
