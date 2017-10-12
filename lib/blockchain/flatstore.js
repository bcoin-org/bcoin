'use strict';

const path = require('path');
const encoding = require('../utils/encoding');
const {Flat, FileEntry} = require('./flat');
const layout = require('./layout');

/**
 * FlatStore
 * @constructor
 * @param {Object} db
 * @param {Object} network
 */

function FlatStore(db, options) {
  const {location, network} = options;
  const dir = path.resolve(location, '..', 'blocks');

  this.db = db;
  this.keepBlocks = network.block.keepBlocks;

  this.blocks = new Flat(dir, 'b', network.magic, 64);
  this.undo = new Flat(dir, 'u', network.magic, 1);

  this.blockFiles = new Map();
  this.undoFiles = new Map();
}

FlatStore.prototype.open = async function open() {
  await this.blocks.open();
  await this.undo.open();
};

FlatStore.prototype.close = async function close() {
  await this.undo.close();
  await this.blocks.close();
};

FlatStore.prototype.getEntry = async function getEntry(key) {
  const raw = await this.db.get(key);

  if (!raw)
    return null;

  return FileEntry.fromRaw(raw);
};

FlatStore.prototype.writeBlock = async function writeBlock(hash, block, batch) {
  const entry = await this.blocks.write(block);
  batch.put(layout.b(hash), entry.toRaw());
};

FlatStore.prototype.readBlock = async function readBlock(hash) {
  const entry = await this.getEntry(layout.b(hash));

  if (!entry)
    return null;

  return await this.blocks.read(entry);
};

FlatStore.prototype.writeUndo = async function writeUndo(hash, undo, batch) {
  const entry = await this.undo.write(undo);
  batch.put(layout.u(hash), entry.toRaw());
};

FlatStore.prototype.readUndo = async function readUndo(hash) {
  const entry = await this.getEntry(layout.u(hash));

  if (!entry)
    return null;

  return await this.undo.read(entry);
};

FlatStore.prototype.pruneBlock = async function pruneBlock(hash, batch) {
  const block = await this.getEntry(layout.b(hash));
  const undo = await this.getEntry(layout.u(hash));

  if (block)
    await this.prune(block, 4000000, this.blocks);

  if (undo)
    await this.prune(undo, 150000, this.undo);

  batch.del(layout.b(hash));
  batch.del(layout.u(hash));
};

FlatStore.prototype.removeBlock = async function removeBlock(hash, batch) {
};

FlatStore.prototype.prune = async function prune(entry, size, store) {
  const horizon = this.keepBlocks * 2 * (size + 12);

  let index = entry.index;

  if (index === 0)
    return;

  let total = 0;

  total += entry.offset;

  while (index--) {
    const file = store.files[index];

    if (!file)
      continue;

    if (total > horizon)
      await store.remove(index);

    total += file.pos;
  }
};

FlatStore.prototype.indexTX = function indexTX(block, entry, batch) {
  let {offset, index} = entry;

  offset += 80;
  offset += encoding.sizeVarint(block.txs.length);

  for (const tx of block.txs) {
    const hash = tx.hash();
    const size = tx.getSize();
    const entry = new FileEntry(index, offset, size);
    offset += size;
    batch.put(layout.t(hash), concat(entry.toRaw(), block.hash()));
    // Spent by
    // for (const {prevout} of tx.inputs) {
    //   const {hash, index} = prevout;
    //   batch.put(layout.S(hash, index), hash);
    // }
  }
};

FlatStore.prototype.readTX = async function readTX(hash) {
  const raw = await this.db.get(layout.t(hash));

  if (!raw)
    return null;

  const entry = raw.slice(0, 12);
  const block = raw.toString('hex', 12, 44);

  return [block, await this.blocks.read(entry)];
};

/*
 * Helpers
 */

function concat(a, b) {
  return Buffer.concat([a, b]);
}

/*
 * Expose
 */

module.exports = FlatStore;
