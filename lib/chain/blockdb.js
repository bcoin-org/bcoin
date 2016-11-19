/*!
 * blockdb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var co = require('../utils/co');
var Flat = require('../db/flat');
var LRU = require('../utils/lru');
var FileEntry = Flat.FileEntry;

/**
 * BlockDB
 * @constructor
 */

function BlockDB(chaindb) {
  this.chaindb = chaindb;
  this.db = chaindb.db;
  this.layout = chaindb.layout;
  this.flat = new Flat(this.db);
  this.cache = new LRU(8192);
}

BlockDB.prototype.open = function open() {
  return this.flat.open();
};

BlockDB.prototype.close = function close() {
  return this.flat.close();
};

BlockDB.prototype.sync = co(function* sync() {
  var entry = yield this.chaindb.getTip();
  var block, rollback;

  assert(entry);

  for (;;) {
    try {
      block = yield this.readBlock(entry.hash);
    } catch (e) {
      if (e.type !== 'ChecksumMismatch')
        throw e;
      block = null;
    }

    if (block)
      break;

    this.cache.remove(entry.hash);

    entry = yield entry.getPrevious();
    assert(entry);

    rollback = true;
  }

  if (!rollback)
    return;

  yield this.chaindb.reset(entry.hash, true);
});

BlockDB.prototype.getEntry = co(function* getEntry(hash) {
  var key = hash;
  var entry, data;

  if (typeof key !== 'string')
    key = key.toString('hex');

  entry = this.cache.get(key);

  if (entry)
    return entry;

  data = yield this.db.get(this.layout.b(hash));

  if (!data)
    return;

  entry = FileEntry.fromRaw(data);

  this.cache.set(key, entry);

  return entry;
});

BlockDB.prototype.saveBlock = co(function* saveBlock(block) {
  var hash = block.hash();
  var hex = block.hash('hex');
  var entry = yield this.flat.write(block.toRaw());

  if (block.height === 0)
    yield this.flat.sync();

  this.cache.set(hex, entry);

  this.chaindb.put(this.layout.b(hash), entry.toRaw());
});

BlockDB.prototype.readBlock = co(function* readBlock(hash) {
  var entry = yield this.getEntry(hash);

  if (!entry)
    return;

  return yield this.readBlockEntry(entry);
});

BlockDB.prototype.readBlockEntry = function readBlockEntry(entry) {
  return this.flat.read(entry.index, entry.pos);
};

BlockDB.prototype.removeBlock = co(function* removeBlock(hash) {
  var entry = yield this.getEntry(hash);

  if (!entry)
    return;

  this.chaindb.del(this.layout.b(hash));

  if (entry.pos === 0)
    yield this.flat.remove(entry.index);
});

BlockDB.prototype.pruneBlock = co(function* pruneBlock(hash) {
  var entry = yield this.getEntry(hash);
  if (!entry)
    return;
  return yield this.pruneBlockEntry(hash, entry);
});

BlockDB.prototype.pruneBlockEntry = function pruneBlockEntry(hash, entry) {
  var index = entry.index;
  if (index === this.current.index)
    index -= 1;
  this.chaindb.del(this.layout.b(hash));
  return this.flat.remove(index);
};

/**
 * Batch
 * @constructor
 */

function Batch(ffdb) {
  this.ffdb = ffdb;
  this.ops = [];
}

Batch.prototype.put = function put(block) {
  this.ops.push(new BatchOp(0, block));
};

Batch.prototype.del = function del(hash) {
  this.ops.push(new BatchOp(1, hash));
};

Batch.prototype.write = co(function* write() {
  var i, op;

  for (i = 0; i < this.ops.length; i++) {
    op = this.ops[i];
    switch (op.type) {
      case 0:
        yield this.ffdb.saveBlock(op.data);
        break;
      case 1:
        yield this.ffdb.removeBlock(op.data);
        break;
      default:
        assert(false);
    }
  }
});

/**
 * BatchOp
 * @constructor
 */

function BatchOp(type, data) {
  this.type = type;
  this.data = data;
}

/*
 * Expose
 */

module.exports = BlockDB;
