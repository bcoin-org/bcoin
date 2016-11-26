/*!
 * records.js - walletdb records
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var assert = require('assert');
var constants = require('../protocol/constants');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

/**
 * Chain State
 * @constructor
 */

function ChainState() {
  if (!(this instanceof ChainState))
    return new ChainState();

  this.startHeight = -1;
  this.startHash = constants.NULL_HASH;
  this.height = -1;
  this.marked = false;
}

/**
 * Clone the state.
 * @returns {ChainState}
 */

ChainState.prototype.clone = function clone() {
  var state = new ChainState();
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
  var br = new BufferReader(data);

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

ChainState.prototype.toRaw = function toRaw(writer) {
  var bw = new BufferWriter(writer);

  bw.writeU32(this.startHeight);
  bw.writeHash(this.startHash);
  bw.writeU32(this.height);
  bw.writeU8(this.marked ? 1 : 0);

  if (!writer)
    bw = bw.render();

  return bw;
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

  this.hash = hash || constants.NULL_HASH;
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
  return new Buffer(this.hash, 'hex');
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
  var br = new BufferReader(data);
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

BlockMeta.prototype.toRaw = function toRaw(writer) {
  var bw = new BufferWriter(writer);

  bw.writeHash(this.hash);
  bw.writeU32(this.height);
  bw.writeU32(this.ts);

  if (!writer)
    bw = bw.render();

  return bw;
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
  var br = new BufferReader(data);
  var count = br.readU32();
  var i, hash, tx;

  for (i = 0; i < count; i++) {
    hash = br.readHash('hex');
    tx = TXMapRecord.fromRaw(hash, br);
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
 * Serialize the wallet block as a block.
 * Contains matching transaction hashes.
 * @returns {Buffer}
 */

BlockMapRecord.prototype.toRaw = function toRaw(writer) {
  var bw = new BufferWriter(writer);
  var i, tx;

  bw.writeU32(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    bw.writeHash(tx.hash);
    tx.toRaw(bw);
  }

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Add a hash and wid pair to the block.
 * @param {Hash} hash
 * @param {WalletID} wid
 * @returns {Boolean}
 */

BlockMapRecord.prototype.add = function add(hash, wid) {
  var tx = this.index[hash];

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
  var tx = this.index[hash];
  var result;

  if (!tx)
    return false;

  if (!tx.remove(wid))
    return false;

  if (tx.wids.length === 0) {
    result = util.binaryRemove(this.txs, tx, cmpid);
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
  this.hash = hash || constants.NULL_HASH;
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

TXMapRecord.prototype.toRaw = function toRaw(writer) {
  return serializeWallets(this.wids, writer);
};

TXMapRecord.prototype.fromRaw = function fromRaw(data) {
  this.wids = parseWallets(data);
  return this;
};

TXMapRecord.fromRaw = function fromRaw(hash, data) {
  return new TXMapRecord(hash).fromRaw(data);
};

/**
 * Outpoint Map
 * @constructor
 */

function OutpointMapRecord(hash, index, wids) {
  this.hash = hash || constants.NULL_HASH;
  this.index = index != null ? index : -1;
  this.wids = wids || [];
}

OutpointMapRecord.prototype.add = function add(wid) {
  return util.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

OutpointMapRecord.prototype.remove = function remove(wid) {
  return util.binaryRemove(this.wids, wid, cmp);
};

OutpointMapRecord.prototype.toRaw = function toRaw(writer) {
  return serializeWallets(this.wids, writer);
};

OutpointMapRecord.prototype.fromRaw = function fromRaw(data) {
  this.wids = parseWallets(data);
  return this;
};

OutpointMapRecord.fromRaw = function fromRaw(hash, index, data) {
  return new OutpointMapRecord(hash, index).fromRaw(data);
};

/**
 * Path Record
 * @constructor
 */

function PathMapRecord(hash, wids) {
  this.hash = hash || constants.NULL_HASH;
  this.wids = wids || [];
}

PathMapRecord.prototype.add = function add(wid) {
  return util.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

PathMapRecord.prototype.remove = function remove(wid) {
  return util.binaryRemove(this.wids, wid, cmp);
};

PathMapRecord.prototype.toRaw = function toRaw(writer) {
  return serializeWallets(this.wids, writer);
};

PathMapRecord.prototype.fromRaw = function fromRaw(data) {
  this.wids = parseWallets(data);
  return this;
};

PathMapRecord.fromRaw = function fromRaw(hash, data) {
  return new PathMapRecord(hash).fromRaw(data);
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

function parseWallets(data) {
  var br = new BufferReader(data);
  var count = br.readU32();
  var wids = [];
  var i;

  for (i = 0; i < count; i++)
    wids.push(br.readU32());

  return wids;
}

function serializeWallets(wids, writer) {
  var bw = new BufferWriter(writer);
  var i, wid;

  bw.writeU32(wids.length);

  for (i = 0; i < wids.length; i++) {
    wid = wids[i];
    bw.writeU32(wid);
  }

  if (!writer)
    bw = bw.render();

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

module.exports = exports;
