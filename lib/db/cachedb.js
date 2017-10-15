'use strict';

const assert = require('assert');
const RBT = require('../utils/rbt');
const co = require('../utils/co');
const DUMMY = Buffer.from([0x00]);

/**
 * CacheDB
 * @constructor
 */

function CacheDB(ldb) {
  this.ldb = ldb;
  this.rbt = new RBT(compare, true);
  this.pendingKeys = new Set();
  this.pendingRemove = new Set();
  this.current = null;
  this.size = 0;
  this.lastFlush = 0;
  this.interval = null;
  this.debug = () => {};
}

CacheDB.prototype.open = async function open(key) {
  assert(!this.current);

  await this.ldb.open();

  this.current = this.ldb.batch();
  this.size = 0;
  this.lastFlush = Math.floor(Date.now() / 1000);
  this.interval = co.setInterval(this.maybeFlush, 10000, this);
};

CacheDB.prototype.close = async function close(key) {
  assert(this.current);

  this.rbt.reset();
  this.pendingKeys.clear();
  this.pendingRemove.clear();
  this.current = null;
  this.size = 0;
  this.lastFlush = 0;
  await co.clearInterval(this.interval);
  this.interval = null;

  await this.ldb.close();
};

CacheDB.prototype.destroy = function destroy() {
  return this.ldb.destroy();
};

CacheDB.prototype.repair = function repair() {
  return this.ldb.repair();
};

CacheDB.prototype.backup = async function backup(path) {
  await this.write();
  return await this.ldb.backup(path);
};

CacheDB.prototype.getProperty = function getProperty(name) {
  return this.ldb.getProperty(name);
};

CacheDB.prototype.approximateSize = function approximateSize(start, end) {
  return this.ldb.approximateSize(start, end);
};

CacheDB.prototype.compactRange = function compactRange(start, end) {
  return this.ldb.compactRange(start, end);
};

CacheDB.prototype.range = function range(options) {
  return this.ldb.range.call(this, options);
};

CacheDB.prototype.keys = function keys(options) {
  return this.ldb.keys.call(this, options);
};

CacheDB.prototype.values = function values(options) {
  return this.ldb.values.call(this, options);
};

CacheDB.prototype.dump = function dump() {
  return this.ldb.dump();
};

CacheDB.prototype.checkVersion = function checkVersion(key, version) {
  return this.ldb.checkVersion(key, version);
};

CacheDB.prototype.clone = async function clone(path) {
  await this.write();
  return await this.ldb.clone(path);
};

CacheDB.prototype.has = async function has(key) {
  assert(this.current);
  const value = await this.get(key);
  return value != null;
};

CacheDB.prototype.get = async function get(key) {
  assert(this.current);

  const node = this.rbt.search(key);

  if (node)
    return node.value;

  const hex = key.toString('hex');

  if (this.pendingRemove.has(hex))
    return null;

  return this.ldb.get(key);
};

CacheDB.prototype.put = function put(key, value) {
  assert(this.current);

  if (!value)
    value = DUMMY;

  this.size += key.length * 3 + 80;
  this.size += value.length + 80;

  this.rbt.insert(key, value);
  this.current.put(key, value);

  const hex = key.toString('hex');

  this.pendingKeys.add(hex);
  this.pendingRemove.delete(hex);
};

CacheDB.prototype.del = function del(key) {
  assert(this.current);

  this.size += key.length * 3 + 80;

  if (!this.rbt.remove(key))
    this.current.del(key);

  const hex = key.toString('hex');

  this.pendingKeys.delete(hex);
  this.pendingRemove.add(hex);
};

CacheDB.prototype.batch = function batch() {
  assert(this.current);
  return new Batch(this);
};

CacheDB.prototype.iterator = function iterator(options) {
  assert(this.current);
  return new Iterator(this, options);
};

CacheDB.prototype.clear = function clear() {
  assert(this.current);
  this.rbt.reset();
  this.pendingKeys.clear();
  this.pendingRemove.clear();
  this.current.clear();
};

CacheDB.prototype.needsFlush = function needsFlush() {
  if (this.size > 100000000)
    return true;

  const now = Math.floor(Date.now() / 1000);

  if (now > this.lastFlush + 30)
    return true;

  return false;
};

CacheDB.prototype.maybeFlush = async function maybeFlush() {
  if (this.needsFlush())
    await this.flush();
};

CacheDB.prototype.flush = async function flush() {
  const batch = this.current;

  this.debug('Flushing database: %dmb.', this.size / 1024 / 1024);

  assert(batch);

  this.rbt.reset();
  this.pendingKeys.clear();
  this.pendingRemove.clear();
  this.current = this.ldb.batch();
  this.size = 0;
  this.lastFlush = Math.floor(Date.now() / 1000);

  await batch.write();
};

CacheDB.prototype.hasKey = function hasKey(key) {
  const hex = key.toString('hex');

  if (this.pendingKeys.has(hex))
    return true;

  return this.pendingRemove.has(hex);
};

/**
 * Batch
 * @constructor
 * @ignore
 */

function Batch(db) {
  this.db = db;
  this.items = [];
}

Batch.prototype.put = function put(key, value) {
  if (!value)
    value = DUMMY;
  this.items.push(new BatchItem(key, value));
};

Batch.prototype.del = function del(key) {
  this.items.push(new BatchItem(key, null));
};

Batch.prototype.clear = function clear() {
  this.items.length = 0;
};

Batch.prototype.write = function write() {
  for (const {key, value} of this.items) {
    if (value) {
      this.db.put(key, value);
      continue;
    }
    this.db.del(key);
  }
  this.items.length = 0;
};

/**
 * BatchItem
 * @constructor
 * @ignore
 */

function BatchItem(key, value) {
  this.key = key;
  this.value = value;
}

/**
 * Iterator
 * @constructor
 * @ignore
 */

function Iterator(db, options) {
  options.limit = null;
  const iter = db.ldb.iterator(options);
  const opt = iter.options;

  this.db = db;
  this.reverse = opt.reverse;
  this.limit = opt.limit;

  this.ldb = iter;
  this.rbt = new RBTIterator(db.rbt, opt);

  this.key = null;
  this.value = null;

  this.opened = false;
  this.valid = true;
  this.total = 0;
}

Iterator.prototype.next = async function next() {
  if (!this.opened) {
    await this.ldb.next();
    this.rbt.next();
    this.opened = true;
  }

  if (this.limit !== -1) {
    if (this.total >= this.limit) {
      await this.end();
      return false;
    }
    this.total += 1;
  }

  const iter = await this.pick();

  if (!iter) {
    this.key = null;
    this.value = null;
    this.valid = false;
    return false;
  }

  this.key = iter.key;
  this.value = iter.value;

  await iter.next();

  return true;
};

Iterator.prototype.seek = function seek(key) {
  this.ldb.seek(key);
  this.rbt.seek(key);
};

Iterator.prototype.end = async function end() {
  assert(this.valid);

  await this.ldb.end();

  this.rbt.end();

  this.key = null;
  this.value = null;
  this.valid = false;
};

Iterator.prototype.skip = async function skip() {
  while (this.ldb.valid) {
    const {key} = this.ldb;

    if (!this.db.hasKey(key))
      break;

    await this.ldb.next();
  }
};

Iterator.prototype.pick = async function pick() {
  await this.skip();

  if (!this.ldb.valid && !this.rbt.valid)
    return null;

  if (!this.rbt.valid)
    return this.ldb;

  if (!this.ldb.valid)
    return this.rbt;

  let cmp = 0;

  if (this.reverse)
    cmp = this.rbt.key.compare(this.ldb.key);
  else
    cmp = this.ldb.key.compare(this.rbt.key);

  if (cmp > 0)
    return this.rbt;

  return this.ldb;
};

/**
 * RBTIterator
 * @constructor
 * @ignore
 */

function RBTIterator(rbt, options) {
  this.rbt = rbt;
  this.options = options;
  this.iter = null;
  this.key = null;
  this.value = null;
  this.valid = true;
  this.init();
}

RBTIterator.prototype.init = function init() {
  const options = this.options;
  const iter = this.rbt.iterator(null);

  if (options.reverse) {
    const end = options.lt || options.lte;
    if (end) {
      iter.seekMax(end);
      if (options.lt && iter.valid()) {
        if (iter.compare(end) === 0)
          iter.prev();
      }
    } else {
      iter.seekLast();
    }
  } else {
    const start = options.gt || options.gte;
    if (start) {
      iter.seekMin(start);
      if (options.gt && iter.valid()) {
        if (iter.compare(start) === 0)
          iter.next();
      }
    } else {
      iter.seekFirst();
    }
  }

  this.iter = iter;
};

RBTIterator.prototype.next = function next() {
  const options = this.options;
  const iter = this.iter;

  if (!this.iter)
    throw new Error('Cannot call next.');

  let result;
  if (options.reverse) {
    result = iter.prev();

    // Stop once we hit a key below our gte key.
    const start = options.gt || options.gte;
    if (result && start) {
      if (options.gt) {
        if (iter.compare(start) <= 0)
          result = false;
      } else {
        if (iter.compare(start) < 0)
          result = false;
      }
    }
  } else {
    result = iter.next();

    // Stop once we hit a key above our lte key.
    const end = options.lt || options.lte;
    if (result && end) {
      if (options.lt) {
        if (iter.compare(end) >= 0)
          result = false;
      } else {
        if (iter.compare(end) > 0)
          result = false;
      }
    }
  }

  if (!result) {
    this.iter = null;
    this.key = null;
    this.value = null;
    this.valid = false;
    return false;
  }

  this.key = iter.key;
  this.value = iter.value;

  return true;
};

RBTIterator.prototype.seek = function seek(key) {
  assert(this.iter, 'Already ended.');
  assert(Buffer.isBuffer(key), 'Key must be a Buffer.');

  if (this.options.reverse)
    this.iter.seekMax(key);
  else
    this.iter.seekMin(key);
};

RBTIterator.prototype.end = function end() {
  if (!this.iter)
    throw new Error('Already ended.');

  this.iter = null;
  this.key = null;
  this.value = null;
  this.valid = false;
};

/*
 * Helpers
 */

function compare(a, b) {
  return a.compare(b);
}

/*
 * Expose
 */

module.exports = CacheDB;
