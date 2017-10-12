'use strict';

const layout = require('./layout');

/**
 * LocalStore
 * @constructor
 */

function LocalStore(db, options) {
  if (!(this instanceof LocalStore))
    return new LocalStore(db, options);

  this.db = db;
};

LocalStore.prototype.open = async function open() {
};

LocalStore.prototype.close = async function close() {
};

LocalStore.prototype.writeBlock = async function writeBlock(hash, block, batch) {
  batch.put(layout.b(hash), block);
};

LocalStore.prototype.readBlock = async function readBlock(hash) {
  return this.db.get(layout.b(hash));
};

LocalStore.prototype.writeUndo = async function writeUndo(hash, undo, batch) {
  batch.put(layout.u(hash), undo);
};

LocalStore.prototype.readUndo = async function readUndo(hash) {
  return this.db.get(layout.u(hash));
};

LocalStore.prototype.pruneBlock = async function pruneBlock(hash, batch) {
  batch.del(layout.b(hash));
  batch.del(layout.u(hash));
};

LocalStore.prototype.removeBlock = async function removeBlock(hash, batch) {
  batch.del(layout.b(hash));
  batch.del(layout.u(hash));
};

/*
 * Expose
 */

module.exports = LocalStore;
