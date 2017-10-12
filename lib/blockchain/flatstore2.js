'use strict';

const assert = require('assert');
const path = require('path');
const {U32} = require('../utils/encoding');
const {Flat} = require('./flat');
const layout = require('./layout');

function FlatStore(options, db) {
  const {location, network} = options;
  const dir = path.resolve(location, '..', 'blocks');
  this.keepBlocks = network.block.keepBlocks;
  this.db = db;
  this.blocks = new Flat(dir, 'b', network.magic, 64);
  this.undo = new Flat(dir, 'u', network.magic, 1);
  this.blockFiles = new Map();
  this.undoFiles = new Map();
}

FlatStore.prototype.open = async function open() {
  const items = await this.db.range({
    gte: layout.f('a', 0),
    lte: layout.f('z', 0xffffffff)
  });

  for (const {key, value} of items) {
    const [ch, index] = layout.ff(key);
    const height = value.readUInt32LE(0, true);

    switch (ch) {
      case 'b':
        this.blockFiles.set(index, height);
        break;
      case 'u':
        this.undoFiles.set(index, height);
        break;
      default:
        assert(false);
        break;
    }
  }

  await this.blocks.open();
  await this.undo.open();
};

FlatStore.prototype.close = async function close() {
  await this.undo.close();
  await this.blocks.close();
};

FlatStore.prototype.writeBlock = async function writeBlock(batch, hash, block, height) {
  const entry = await this.blocks.save(block.toRaw());

  batch.put(layout.b(hash), entry.toRaw());

  const cache = this.blockFiles.get(entry.index);

  if (cache == null || cache < height) {
    this.blockFiles.set(entry.index, height);
    batch.put(layout.f('b', entry.index), U32(height));
  }
};

FlatStore.prototype.getBlock = async function getBlock(hash) {
  const raw = await this.db.get(layout.b(hash));

  if (!raw)
    return null;

  return await this.blocks.resolve(raw);
};

FlatStore.prototype.writeUndo = async function writeUndo(batch, hash, undo, height) {
  const entry = await this.undo.save(undo.commit());

  batch.put(layout.u(hash), entry.toRaw());

  const cache = this.undoFiles.get(entry.index);

  if (cache == null || cache < height) {
    this.undoFiles.set(entry.index, height);
    batch.put(layout.f('u', entry.index), U32(height));
  }
};

FlatStore.prototype.getUndo = async function getUndo(hash) {
  const raw = await this.db.get(layout.u(hash));

  if (!raw)
    return null;

  return await this.undo.resolve(raw);
};

FlatStore.prototype.prune = async function prune(batch, tipHeight) {
  const target = tipHeight - this.keepBlocks;

  const blocks = [];

  for (const [index, height] of this.blockFiles) {
    if (height <= target && index < this.blocks.last) {
      this.blockFiles.delete(index);
      blocks.push(index);
    }
  }

  const undo = [];

  for (const [index, height] of this.undoFiles) {
    if (height <= target && index < this.undo.last) {
      this.undoFiles.delete(index);
      undo.push(index);
    }
  }

  for (const index of blocks)
    await this.blocks.remove(index);

  for (const index of undo)
    await this.undo.remove(index);
};
