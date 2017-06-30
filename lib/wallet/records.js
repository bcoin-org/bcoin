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

  this.startHeight = -1;
  this.startHash = encoding.NULL_HASH;
  this.height = -1;
  this.marked = false;
}

/**
 * Clone the state.
 * @returns {ChainState}
 */

ChainState.prototype.clone = function clone() {
  let state = new ChainState();
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
  let br = new BufferReader(data);

  this.startHeight = br.readU32();
  this.startHash = br.readHash('hex');
  this.height = br.readU32();
  this.marked = true;

  if (br.left() > 0)
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
  let bw = new StaticWriter(41);

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
 * @param {Number} ts
 */

function BlockMeta(hash, height, ts) {
  if (!(this instanceof BlockMeta))
    return new BlockMeta(hash, height, ts);

  this.hash = hash || encoding.NULL_HASH;
  this.height = height != null ? height : -1;
  this.ts = ts || 0;
}

/**
 * Clone the block.
 * @returns {BlockMeta}
 */

BlockMeta.prototype.clone = function clone() {
  return new BlockMeta(this.hash, this.height, this.ts);
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
  this.ts = entry.ts;
  return this;
};

/**
 * Instantiate block meta from json object.
 * @private
 * @param {Object} json
 */

BlockMeta.prototype.fromJSON = function fromJSON(json) {
  this.hash = util.revHex(json.hash);
  this.height = json.height;
  this.ts = json.ts;
  return this;
};

/**
 * Instantiate block meta from serialized tip data.
 * @private
 * @param {Buffer} data
 */

BlockMeta.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  this.hash = br.readHash('hex');
  this.height = br.readU32();
  this.ts = br.readU32();
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
  let bw = new StaticWriter(42);
  bw.writeHash(this.hash);
  bw.writeU32(this.height);
  bw.writeU32(this.ts);
  return bw.render();
};

/**
 * Convert the block meta to a more json-friendly object.
 * @returns {Object}
 */

BlockMeta.prototype.toJSON = function toJSON() {
  return {
    hash: util.revHex(this.hash),
    height: this.height,
    ts: this.ts
  };
};

/**
 * Wallet Block
 * @constructor
 * @param {Hash} hash
 * @param {Number} height
 */

function BlockMapRecord(height) {
  if (!(this instanceof BlockMapRecord))
    return new BlockMapRecord(height);

  this.height = height != null ? height : -1;
  this.txs = [];
  this.index = {};
}

/**
 * Instantiate wallet block from serialized data.
 * @private
 * @param {Hash} hash
 * @param {Buffer} data
 */

BlockMapRecord.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  let count = br.readU32();

  for (let i = 0; i < count; i++) {
    let hash = br.readHash('hex');
    let tx = TXMapRecord.fromReader(hash, br);
    this.txs.push(tx);
    this.index[tx.hash] = tx;
  }

  return this;
};

/**
 * Instantiate wallet block from serialized data.
 * @param {Hash} hash
 * @param {Buffer} data
 * @returns {BlockMapRecord}
 */

BlockMapRecord.fromRaw = function fromRaw(height, data) {
  return new BlockMapRecord(height).fromRaw(data);
};

/**
 * Calculate serialization size.
 * @returns {Number}
 */

BlockMapRecord.prototype.getSize = function getSize() {
  let size = 0;

  size += 4;

  for (let tx of this.txs) {
    size += 32;
    size += tx.getSize();
  }

  return size;
};

/**
 * Serialize the wallet block as a block.
 * Contains matching transaction hashes.
 * @returns {Buffer}
 */

BlockMapRecord.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  let bw = new StaticWriter(size);

  bw.writeU32(this.txs.length);

  for (let tx of this.txs) {
    bw.writeHash(tx.hash);
    tx.toWriter(bw);
  }

  return bw.render();
};

/**
 * Add a hash and wid pair to the block.
 * @param {Hash} hash
 * @param {WalletID} wid
 * @returns {Boolean}
 */

BlockMapRecord.prototype.add = function add(hash, wid) {
  let tx = this.index[hash];

  if (!tx) {
    tx = new TXMapRecord(hash);
    tx.wids.push(wid);
    this.txs.push(tx);
    this.index[tx.hash] = tx;
    return true;
  }

  return tx.add(wid);
};

/**
 * Remove a hash and wid pair from the block.
 * @param {Hash} hash
 * @param {WalletID} wid
 * @returns {Boolean}
 */

BlockMapRecord.prototype.remove = function remove(hash, wid) {
  let tx = this.index[hash];

  if (!tx)
    return false;

  if (!tx.remove(wid))
    return false;

  if (tx.wids.length === 0) {
    let result = util.binaryRemove(this.txs, tx, cmpid);
    assert(result);
    delete this.index[tx.hash];
  }

  return true;
};

/**
 * TX Hash
 * @constructor
 */

function TXMapRecord(hash, wids) {
  this.hash = hash || encoding.NULL_HASH;
  this.wids = wids || [];
  this.id = TXMapRecord.id++;
}

TXMapRecord.id = 0;

TXMapRecord.prototype.add = function add(wid) {
  return util.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

TXMapRecord.prototype.remove = function remove(wid) {
  return util.binaryRemove(this.wids, wid, cmp);
};

TXMapRecord.prototype.toWriter = function toWriter(bw) {
  return serializeWallets(bw, this.wids);
};

TXMapRecord.prototype.getSize = function getSize() {
  return sizeWallets(this.wids);
};

TXMapRecord.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

TXMapRecord.prototype.fromReader = function fromReader(br) {
  this.wids = parseWallets(br);
  return this;
};

TXMapRecord.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

TXMapRecord.fromReader = function fromReader(hash, br) {
  return new TXMapRecord(hash).fromReader(br);
};

TXMapRecord.fromRaw = function fromRaw(hash, data) {
  return new TXMapRecord(hash).fromRaw(data);
};

/**
 * Outpoint Map
 * @constructor
 */

function OutpointMapRecord(hash, index, wids) {
  this.hash = hash || encoding.NULL_HASH;
  this.index = index != null ? index : -1;
  this.wids = wids || [];
}

OutpointMapRecord.prototype.add = function add(wid) {
  return util.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

OutpointMapRecord.prototype.remove = function remove(wid) {
  return util.binaryRemove(this.wids, wid, cmp);
};

OutpointMapRecord.prototype.toWriter = function toWriter(bw) {
  return serializeWallets(bw, this.wids);
};

OutpointMapRecord.prototype.getSize = function getSize() {
  return sizeWallets(this.wids);
};

OutpointMapRecord.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

OutpointMapRecord.prototype.fromReader = function fromReader(br) {
  this.wids = parseWallets(br);
  return this;
};

OutpointMapRecord.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

OutpointMapRecord.fromReader = function fromReader(hash, index, br) {
  return new OutpointMapRecord(hash, index).fromReader(br);
};

OutpointMapRecord.fromRaw = function fromRaw(hash, index, data) {
  return new OutpointMapRecord(hash, index).fromRaw(data);
};

/**
 * Path Record
 * @constructor
 */

function PathMapRecord(hash, wids) {
  this.hash = hash || encoding.NULL_HASH;
  this.wids = wids || [];
}

PathMapRecord.prototype.add = function add(wid) {
  return util.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

PathMapRecord.prototype.remove = function remove(wid) {
  return util.binaryRemove(this.wids, wid, cmp);
};

PathMapRecord.prototype.toWriter = function toWriter(bw) {
  return serializeWallets(bw, this.wids);
};

PathMapRecord.prototype.getSize = function getSize() {
  return sizeWallets(this.wids);
};

PathMapRecord.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

PathMapRecord.prototype.fromReader = function fromReader(br) {
  this.wids = parseWallets(br);
  return this;
};

PathMapRecord.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

PathMapRecord.fromReader = function fromReader(hash, br) {
  return new PathMapRecord(hash).fromReader(br);
};

PathMapRecord.fromRaw = function fromRaw(hash, data) {
  return new PathMapRecord(hash).fromRaw(data);
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
  this.ps = util.now();
  this.height = -1;
  this.block = null;
  this.index = -1;
  this.ts = 0;

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
  this.ts = block.ts;
};

/**
 * Unset block (unconfirm).
 */

TXRecord.prototype.unsetBlock = function unsetBlock() {
  this.height = -1;
  this.block = null;
  this.ts = 0;
};

/**
 * Convert tx record to a block meta.
 * @returns {BlockMeta}
 */

TXRecord.prototype.getBlock = function getBlock() {
  if (this.height === -1)
    return;
  return new BlockMeta(this.block, this.height, this.ts);
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
  let size = this.getSize();
  let bw = new StaticWriter(size);
  let index = this.index;

  this.tx.toWriter(bw);

  bw.writeU32(this.ps);

  if (this.block) {
    if (index === -1)
      index = 0x7fffffff;

    bw.writeU8(1);
    bw.writeHash(this.block);
    bw.writeU32(this.height);
    bw.writeU32(this.ts);
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
  let br = new BufferReader(data);

  this.tx = new TX();
  this.tx.fromReader(br);

  this.hash = this.tx.hash('hex');
  this.ps = br.readU32();

  if (br.readU8() === 1) {
    this.block = br.readHash('hex');
    this.height = br.readU32();
    this.ts = br.readU32();
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

/*
 * Helpers
 */

function cmp(a, b) {
  return a - b;
}

function cmpid(a, b) {
  return a.id - b.id;
}

function parseWallets(br) {
  let count = br.readU32();
  let wids = [];

  for (let i = 0; i < count; i++)
    wids.push(br.readU32());

  return wids;
}

function sizeWallets(wids) {
  return 4 + wids.length * 4;
}

function serializeWallets(bw, wids) {
  bw.writeU32(wids.length);

  for (let wid of wids)
    bw.writeU32(wid);

  return bw;
}

/*
 * Expose
 */

exports.ChainState = ChainState;
exports.BlockMeta = BlockMeta;
exports.BlockMapRecord = BlockMapRecord;
exports.TXMapRecord = TXMapRecord;
exports.OutpointMapRecord = OutpointMapRecord;
exports.PathMapRecord = PathMapRecord;
exports.TXRecord = TXRecord;

module.exports = exports;
