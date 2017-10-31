/*!
 * records.js - walletdb records
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module wallet/records
 */

const assert = require('assert');
const util = require('../utils/util');
const encoding = require('../utils/encoding');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const TX = require('../primitives/tx');

/**
 * Chain State
 * @constructor
 */

function ChainState() {
  if (!(this instanceof ChainState))
    return new ChainState();

  this.startHeight = 0;
  this.startHash = encoding.NULL_HASH;
  this.height = 0;
  this.marked = false;
}

/**
 * Clone the state.
 * @returns {ChainState}
 */

ChainState.prototype.clone = function clone() {
  const state = new ChainState();
  state.startHeight = this.startHeight;
  state.startHash = this.startHash;
  state.height = this.height;
  state.marked = this.marked;
  return state;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

ChainState.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);

  this.startHeight = br.readU32();
  this.startHash = br.readHash('hex');
  this.height = br.readU32();
  this.marked = br.readU8() === 1;

  return this;
};

/**
 * Instantiate chain state from serialized data.
 * @param {Hash} hash
 * @param {Buffer} data
 * @returns {ChainState}
 */

ChainState.fromRaw = function fromRaw(data) {
  return new ChainState().fromRaw(data);
};

/**
 * Serialize the chain state.
 * @returns {Buffer}
 */

ChainState.prototype.toRaw = function toRaw() {
  const bw = new StaticWriter(41);

  bw.writeU32(this.startHeight);
  bw.writeHash(this.startHash);
  bw.writeU32(this.height);
  bw.writeU8(this.marked ? 1 : 0);

  return bw.render();
};

/**
 * Block Meta
 * @constructor
 * @param {Hash} hash
 * @param {Number} height
 * @param {Number} time
 */

function BlockMeta(hash, height, time) {
  if (!(this instanceof BlockMeta))
    return new BlockMeta(hash, height, time);

  this.hash = hash || encoding.NULL_HASH;
  this.height = height != null ? height : -1;
  this.time = time || 0;
}

/**
 * Clone the block.
 * @returns {BlockMeta}
 */

BlockMeta.prototype.clone = function clone() {
  return new BlockMeta(this.hash, this.height, this.time);
};

/**
 * Get block meta hash as a buffer.
 * @returns {Buffer}
 */

BlockMeta.prototype.toHash = function toHash() {
  return Buffer.from(this.hash, 'hex');
};

/**
 * Instantiate block meta from chain entry.
 * @private
 * @param {ChainEntry} entry
 */

BlockMeta.prototype.fromEntry = function fromEntry(entry) {
  this.hash = entry.hash;
  this.height = entry.height;
  this.time = entry.time;
  return this;
};

/**
 * Instantiate block meta from json object.
 * @private
 * @param {Object} json
 */

BlockMeta.prototype.fromJSON = function fromJSON(json) {
  this.hash = encoding.revHex(json.hash);
  this.height = json.height;
  this.time = json.time;
  return this;
};

/**
 * Instantiate block meta from serialized tip data.
 * @private
 * @param {Buffer} data
 */

BlockMeta.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);
  this.hash = br.readHash('hex');
  this.height = br.readU32();
  this.time = br.readU32();
  return this;
};

/**
 * Instantiate block meta from chain entry.
 * @param {ChainEntry} entry
 * @returns {BlockMeta}
 */

BlockMeta.fromEntry = function fromEntry(entry) {
  return new BlockMeta().fromEntry(entry);
};

/**
 * Instantiate block meta from json object.
 * @param {Object} json
 * @returns {BlockMeta}
 */

BlockMeta.fromJSON = function fromJSON(json) {
  return new BlockMeta().fromJSON(json);
};

/**
 * Instantiate block meta from serialized data.
 * @param {Hash} hash
 * @param {Buffer} data
 * @returns {BlockMeta}
 */

BlockMeta.fromRaw = function fromRaw(data) {
  return new BlockMeta().fromRaw(data);
};

/**
 * Serialize the block meta.
 * @returns {Buffer}
 */

BlockMeta.prototype.toRaw = function toRaw() {
  const bw = new StaticWriter(42);
  bw.writeHash(this.hash);
  bw.writeU32(this.height);
  bw.writeU32(this.time);
  return bw.render();
};

/**
 * Convert the block meta to a more json-friendly object.
 * @returns {Object}
 */

BlockMeta.prototype.toJSON = function toJSON() {
  return {
    hash: encoding.revHex(this.hash),
    height: this.height,
    time: this.time
  };
};

/**
 * TXRecord
 * @constructor
 * @param {TX} tx
 * @param {BlockMeta?} block
 */

function TXRecord(tx, block) {
  if (!(this instanceof TXRecord))
    return new TXRecord(tx, block);

  this.tx = null;
  this.hash = null;
  this.mtime = util.now();
  this.height = -1;
  this.block = null;
  this.index = -1;
  this.time = 0;

  if (tx)
    this.fromTX(tx, block);
}

/**
 * Inject properties from tx and block.
 * @private
 * @param {TX} tx
 * @param {Block?} block
 * @returns {TXRecord}
 */

TXRecord.prototype.fromTX = function fromTX(tx, block) {
  this.tx = tx;
  this.hash = tx.hash('hex');

  if (block)
    this.setBlock(block);

  return this;
};

/**
 * Instantiate tx record from tx and block.
 * @param {TX} tx
 * @param {Block?} block
 * @returns {TXRecord}
 */

TXRecord.fromTX = function fromTX(tx, block) {
  return new TXRecord().fromTX(tx, block);
};

/**
 * Set block data (confirm).
 * @param {BlockMeta} block
 */

TXRecord.prototype.setBlock = function setBlock(block) {
  this.height = block.height;
  this.block = block.hash;
  this.time = block.time;
};

/**
 * Unset block (unconfirm).
 */

TXRecord.prototype.unsetBlock = function unsetBlock() {
  this.height = -1;
  this.block = null;
  this.time = 0;
};

/**
 * Convert tx record to a block meta.
 * @returns {BlockMeta}
 */

TXRecord.prototype.getBlock = function getBlock() {
  if (this.height === -1)
    return null;

  return new BlockMeta(this.block, this.height, this.time);
};

/**
 * Calculate current number of transaction confirmations.
 * @param {Number} height - Current chain height.
 * @returns {Number} confirmations
 */

TXRecord.prototype.getDepth = function getDepth(height) {
  assert(typeof height === 'number', 'Must pass in height.');

  if (this.height === -1)
    return 0;

  if (height < this.height)
    return 0;

  return height - this.height + 1;
};

/**
 * Get serialization size.
 * @returns {Number}
 */

TXRecord.prototype.getSize = function getSize() {
  let size = 0;

  size += this.tx.getSize();
  size += 4;

  if (this.block) {
    size += 1;
    size += 32;
    size += 4 * 3;
  } else {
    size += 1;
  }

  return size;
};

/**
 * Serialize a transaction to "extended format".
 * @returns {Buffer}
 */

TXRecord.prototype.toRaw = function toRaw() {
  const size = this.getSize();
  const bw = new StaticWriter(size);

  let index = this.index;

  this.tx.toWriter(bw);

  bw.writeU32(this.mtime);

  if (this.block) {
    if (index === -1)
      index = 0x7fffffff;

    bw.writeU8(1);
    bw.writeHash(this.block);
    bw.writeU32(this.height);
    bw.writeU32(this.time);
    bw.writeU32(index);
  } else {
    bw.writeU8(0);
  }

  return bw.render();
};

/**
 * Inject properties from "extended" format.
 * @private
 * @param {Buffer} data
 */

TXRecord.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data);

  this.tx = new TX();
  this.tx.fromReader(br);

  this.hash = this.tx.hash('hex');
  this.mtime = br.readU32();

  if (br.readU8() === 1) {
    this.block = br.readHash('hex');
    this.height = br.readU32();
    this.time = br.readU32();
    this.index = br.readU32();
    if (this.index === 0x7fffffff)
      this.index = -1;
  }

  return this;
};

/**
 * Instantiate a transaction from a buffer
 * in "extended" serialization format.
 * @param {Buffer} data
 * @returns {TX}
 */

TXRecord.fromRaw = function fromRaw(data) {
  return new TXRecord().fromRaw(data);
};

/**
 * Map Record
 * @constructor
 */

function MapRecord() {
  this.wids = new Set();
}

MapRecord.prototype.add = function add(wid) {
  if (this.wids.has(wid))
    return false;

  this.wids.add(wid);

  return true;
};

MapRecord.prototype.remove = function remove(wid) {
  return this.wids.delete(wid);
};

MapRecord.prototype.toWriter = function toWriter(bw) {
  bw.writeU32(this.wids.size);

  for (const wid of this.wids)
    bw.writeU32(wid);

  return bw;
};

MapRecord.prototype.getSize = function getSize() {
  return 4 + this.wids.size * 4;
};

MapRecord.prototype.toRaw = function toRaw() {
  const size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

MapRecord.prototype.fromReader = function fromReader(br) {
  const count = br.readU32();

  for (let i = 0; i < count; i++)
    this.wids.add(br.readU32());

  return this;
};

MapRecord.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

MapRecord.fromReader = function fromReader(br) {
  return new MapRecord().fromReader(br);
};

MapRecord.fromRaw = function fromRaw(data) {
  return new MapRecord().fromRaw(data);
};

/*
 * Expose
 */

exports.ChainState = ChainState;
exports.BlockMeta = BlockMeta;
exports.TXRecord = TXRecord;
exports.MapRecord = MapRecord;

module.exports = exports;
