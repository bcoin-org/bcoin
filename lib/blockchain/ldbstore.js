'use strict';

const path = require('path');
const LDB = require('../db/ldb');
const layout = require('./layout');

/**
 * LDBStore
 * @constructor
 */

function LDBStore(db, options) {
  if (!(this instanceof LDBStore))
    return new LDBStore(db, options);

  let location = options.location;
  if (location)
    location = path.resolve(location, '..', 'blocks');

  this.db = LDB({
    db: options.db,
    location: location,
    maxFiles: 64,
    cacheSize: 32 << 20,
    compression: true
  });
};

LDBStore.prototype.open = async function open() {
  await this.db.open();
};

LDBStore.prototype.close = async function close() {
  await this.db.close();
};

LDBStore.prototype.writeBlock = async function writeBlock(hash, block) {
  const batch = this.db.batch();
  batch.put(layout.b(hash), block);
  return batch.write();
};

LDBStore.prototype.readBlock = async function readBlock(hash) {
  return this.db.get(layout.b(hash));
};

LDBStore.prototype.writeUndo = async function writeUndo(hash, undo) {
  const batch = this.db.batch();
  batch.put(layout.u(hash), undo);
  return batch.write();
};

LDBStore.prototype.readUndo = async function readUndo(hash) {
  return this.db.get(layout.u(hash));
};

LDBStore.prototype.pruneBlock = async function pruneBlock(hash) {
  const batch = this.db.batch();
  batch.del(layout.b(hash));
  batch.del(layout.u(hash));
  return batch.write();
};

LDBStore.prototype.removeBlock = async function removeBlock(hash) {
  const batch = this.db.batch();
  batch.del(layout.b(hash));
  batch.del(layout.u(hash));
  return batch.write();
};

/*
 * Expose
 */

module.exports = LDBStore;
