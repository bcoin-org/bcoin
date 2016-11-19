/*!
 * blockdb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * BlockDB
 * @constructor
 */

function BlockDB(chaindb) {
  this.chaindb = chaindb;
  this.db = chaindb.db;
  this.layout = chaindb.layout;
}

BlockDB.prototype.open = function open() {
  return Promise.resolve();
};

BlockDB.prototype.close = function close() {
  return Promise.resolve();
};

BlockDB.prototype.sync = function sync() {
  return Promise.resolve();
};

BlockDB.prototype.saveBlock = function saveBlock(block) {
  this.chaindb.put(this.layout.b(block.hash()), block.toRaw());
  return Promise.resolve();
};

BlockDB.prototype.readBlock = function readBlock(hash) {
  return this.db.get(this.layout.b(hash));
};

BlockDB.prototype.readBlockEntry = function readBlockEntry(entry) {
  return this.readBlock(entry.hash);
};

BlockDB.prototype.removeBlock = function removeBlock(hash) {
  this.chaindb.del(this.layout.b(hash));
  return Promise.resolve();
};

BlockDB.prototype.pruneBlock = function pruneBlock(hash) {
  this.chaindb.del(this.layout.b(hash));
  return Promise.resolve();
};

BlockDB.prototype.pruneBlockEntry = function pruneBlockEntry(entry) {
  return this.pruneBlock(entry.hash);
};

/*
 * Expose
 */

module.exports = BlockDB;
