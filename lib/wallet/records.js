/*!
 * records.js - walletdb records
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var assert = require('assert');
var constants = require('../protocol/constants');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');

/**
 * Wallet Tip
 * @constructor
 * @param {Hash} hash
 * @param {Number} height
 */

function ChainState() {
  if (!(this instanceof ChainState))
    return new ChainState();

  this.start = new HeaderRecord();
  this.tip = new HeaderRecord();
}

/**
 * Clone the block.
 * @returns {ChainState}
 */

ChainState.prototype.clone = function clone() {
  var state = new ChainState();
  state.start = this.start;
  state.tip = this.tip;
  return state;
};

/**
 * Instantiate wallet block from serialized tip data.
 * @private
 * @param {Buffer} data
 */

ChainState.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  this.start.fromRaw(p);
  this.tip.fromRaw(p);
  return this;
};

/**
 * Instantiate wallet block from serialized data.
 * @param {Hash} hash
 * @param {Buffer} data
 * @returns {ChainState}
 */

ChainState.fromRaw = function fromRaw(data) {
  return new ChainState().fromRaw(data);
};

/**
 * Serialize the wallet block as a tip (hash and height).
 * @returns {Buffer}
 */

ChainState.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  this.start.toRaw(p);
  this.tip.toRaw(p);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Wallet Tip
 * @constructor
 * @param {Hash} hash
 * @param {Number} height
 */

function HeaderRecord(hash, height, ts) {
  if (!(this instanceof HeaderRecord))
    return new HeaderRecord(hash, height, ts);

  this.hash = hash || constants.NULL_HASH;
  this.height = height != null ? height : -1;
  this.ts = ts || 0;
}

/**
 * Clone the block.
 * @returns {HeaderRecord}
 */

HeaderRecord.prototype.clone = function clone() {
  return new HeaderRecord(this.hash, this.height, this.ts);
};

/**
 * Instantiate wallet block from chain entry.
 * @private
 * @param {ChainEntry} entry
 */

HeaderRecord.prototype.fromEntry = function fromEntry(entry) {
  this.hash = entry.hash;
  this.height = entry.height;
  this.ts = entry.ts;
  return this;
};

/**
 * Instantiate wallet block from json object.
 * @private
 * @param {Object} json
 */

HeaderRecord.prototype.fromJSON = function fromJSON(json) {
  this.hash = utils.revHex(json.hash);
  this.height = json.height;
  this.ts = json.ts;
  return this;
};

/**
 * Instantiate wallet block from serialized tip data.
 * @private
 * @param {Buffer} data
 */

HeaderRecord.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  this.hash = p.readHash('hex');
  this.height = p.readU32();
  this.ts = p.readU32();
  return this;
};

/**
 * Instantiate wallet block from chain entry.
 * @param {ChainEntry} entry
 * @returns {HeaderRecord}
 */

HeaderRecord.fromEntry = function fromEntry(entry) {
  return new HeaderRecord().fromEntry(entry);
};

/**
 * Instantiate wallet block from json object.
 * @param {Object} json
 * @returns {HeaderRecord}
 */

HeaderRecord.fromJSON = function fromJSON(json) {
  return new HeaderRecord().fromJSON(json);
};

/**
 * Instantiate wallet block from serialized data.
 * @param {Hash} hash
 * @param {Buffer} data
 * @returns {HeaderRecord}
 */

HeaderRecord.fromRaw = function fromRaw(data) {
  return new HeaderRecord().fromRaw(data);
};

/**
 * Serialize the wallet block as a tip (hash and height).
 * @returns {Buffer}
 */

HeaderRecord.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeHash(this.hash);
  p.writeU32(this.height);
  p.writeU32(this.ts);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Convert the block to a more json-friendly object.
 * @returns {Object}
 */

HeaderRecord.prototype.toJSON = function toJSON() {
  return {
    hash: utils.revHex(this.hash),
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
  var p = new BufferReader(data);
  var i, hash, tx, count;

  while (p.left()) {
    hash = p.readHash('hex');
    tx = new TXMapRecord(hash);
    count = p.readVarint();
    for (i = 0; i < count; i++)
      tx.wids.push(p.readU32());
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
  var p = new BufferWriter(writer);
  var i, j, tx;

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    p.writeHash(tx.hash);
    p.writeVarint(tx.wids.length);
    for (j = 0; j < tx.wids.length; j++)
      p.writeU32(tx.wids[j]);
  }

  if (!writer)
    p = p.render();

  return p;
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
    result = utils.binaryRemove(this.txs, tx, cmpid);
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
  return utils.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

TXMapRecord.prototype.remove = function remove(wid) {
  return utils.binaryRemove(this.wids, wid, cmp);
};

TXMapRecord.prototype.toRaw = function toRaw() {
  return serializeWallets(this.wids);
};

TXMapRecord.prototype.fromRaw = function fromRaw(data) {
  this.wids = parseWallets(data);
  return this;
};

TXMapRecord.fromRaw = function fromRaw(hash, data) {
  return new TXMapRecord(hash).fromRaw(data);
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
  return utils.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

PathMapRecord.prototype.remove = function remove(wid) {
  return utils.binaryRemove(this.wids, wid, cmp);
};

PathMapRecord.prototype.toRaw = function toRaw() {
  return serializeWallets(this.wids);
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
  var p = new BufferReader(data);
  var wids = [];

  while (p.left())
    wids.push(p.readU32());

  return wids;
}

function serializeWallets(wids) {
  var p = new BufferWriter();
  var i, wid;

  for (i = 0; i < wids.length; i++) {
    wid = wids[i];
    p.writeU32(wid);
  }

  return p.render();
}

/*
 * Expose
 */

exports.ChainState = ChainState;
exports.HeaderRecord = HeaderRecord;
exports.BlockMapRecord = BlockMapRecord;
exports.TXMapRecord = TXMapRecord;
exports.PathMapRecord = PathMapRecord;

module.exports = exports;
