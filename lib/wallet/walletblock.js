/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
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
 * Wallet Block
 * @constructor
 * @param {Hash} hash
 * @param {Number} height
 */

function WalletBlock(hash, height, ts) {
  if (!(this instanceof WalletBlock))
    return new WalletBlock(hash, height, ts);

  this.hash = hash || constants.NULL_HASH;
  this.height = height != null ? height : -1;
  this.ts = ts || 0;
  this.txs = [];
  this.index = {};
}

/**
 * Clone the block.
 * @returns {WalletBlock}
 */

WalletBlock.prototype.clone = function clone() {
  return new WalletBlock(this.hash, this.height, this.ts);
};

/**
 * Instantiate wallet block from chain entry.
 * @private
 * @param {ChainEntry} entry
 */

WalletBlock.prototype.fromEntry = function fromEntry(entry) {
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

WalletBlock.prototype.fromJSON = function fromJSON(json) {
  this.hash = utils.revHex(json.hash);
  this.height = json.height;
  this.ts = json.ts;
  return this;
};

/**
 * Instantiate wallet block from serialized data.
 * @private
 * @param {Hash} hash
 * @param {Buffer} data
 */

WalletBlock.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  var i, hash, tx, count;

  this.hash = p.readHash('hex');
  this.height = p.readU32();
  this.ts = p.readU32();

  while (p.left()) {
    hash = p.readHash('hex');
    tx = new TXHash(hash);
    count = p.readVarint();
    for (i = 0; i < count; i++)
      tx.wids.push(p.readU32());
    this.txs.push(tx);
    this.index[tx.hash] = tx;
  }

  return this;
};

/**
 * Instantiate wallet block from serialized tip data.
 * @private
 * @param {Buffer} data
 */

WalletBlock.prototype.fromTip = function fromTip(data) {
  var p = new BufferReader(data);
  this.hash = p.readHash('hex');
  this.height = p.readU32();
  this.ts = p.readU32();
  return this;
};

/**
 * Instantiate wallet block from chain entry.
 * @param {ChainEntry} entry
 * @returns {WalletBlock}
 */

WalletBlock.fromEntry = function fromEntry(entry) {
  return new WalletBlock().fromEntry(entry);
};

/**
 * Instantiate wallet block from json object.
 * @param {Object} json
 * @returns {WalletBlock}
 */

WalletBlock.fromJSON = function fromJSON(json) {
  return new WalletBlock().fromJSON(json);
};

/**
 * Instantiate wallet block from serialized data.
 * @param {Hash} hash
 * @param {Buffer} data
 * @returns {WalletBlock}
 */

WalletBlock.fromRaw = function fromRaw(data) {
  return new WalletBlock().fromRaw(data);
};

/**
 * Instantiate wallet block from serialized tip data.
 * @private
 * @param {Buffer} data
 */

WalletBlock.fromTip = function fromTip(data) {
  return new WalletBlock().fromTip(data);
};

/**
 * Serialize the wallet block as a tip (hash and height).
 * @returns {Buffer}
 */

WalletBlock.prototype.toTip = function toTip(writer) {
  var p = new BufferWriter(writer);

  p.writeHash(this.hash);
  p.writeU32(this.height);
  p.writeU32(this.ts);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize the wallet block as a block.
 * Contains matching transaction hashes.
 * @returns {Buffer}
 */

WalletBlock.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);
  var i, j, tx;

  p.writeHash(this.hash);
  p.writeU32(this.height);
  p.writeU32(this.ts);

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

WalletBlock.prototype.add = function add(hash, wid) {
  var tx = this.index[hash];

  if (!tx) {
    tx = new TXHash(hash);
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

WalletBlock.prototype.remove = function remove(hash, wid) {
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
 * Convert the block to a more json-friendly object.
 * @returns {Object}
 */

WalletBlock.prototype.toJSON = function toJSON() {
  return {
    hash: utils.revHex(this.hash),
    height: this.height
  };
};

/**
 * TX Hash
 * @constructor
 */

function TXHash(hash, wids) {
  this.hash = hash || constants.NULL_HASH;
  this.wids = wids || [];
  this.id = TXHash.id++;
}

TXHash.id = 0;

TXHash.prototype.add = function add(wid) {
  return utils.binaryInsert(this.wids, wid, cmp, true) !== -1;
};

TXHash.prototype.remove = function remove(wid) {
  return utils.binaryRemove(this.wids, wid, cmp);
};

TXHash.prototype.toRaw = function toRaw(writer) {
  return serializeWallets(this.wids, writer);
};

TXHash.prototype.fromRaw = function fromRaw(data) {
  return parseWallets(data);
};

TXHash.fromRaw = function fromRaw(hash, data) {
  return new TXHash(hash).fromRaw(data);
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

/*
 * Expose
 */

exports = WalletBlock;
exports.WalletBlock = WalletBlock;
exports.TXHash = TXHash;

module.exports = exports;
