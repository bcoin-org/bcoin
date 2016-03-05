/**
 * chainblock.js - chainblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

/**
 * ChainBlock
 */

function ChainBlock(chain, data, prev) {
  if (!(this instanceof ChainBlock))
    return new ChainBlock(chain, data);

  this.chain = chain;
  this.hash = data.hash;
  this.version = data.version;
  this.prevBlock = data.prevBlock;
  this.merkleRoot = data.merkleRoot;
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.height = data.height;
  this.chainwork = data.chainwork || this.getChainwork(prev);

  assert(this.chainwork);

  this.previous = [];
}

ChainBlock.BLOCK_SIZE = 116;

ChainBlock.prototype.getProof = function getProof() {
  var target = utils.fromCompact(this.bits);
  if (target.isNeg() || target.cmpn(0) === 0)
    return new bn(0);
  return new bn(1).ushln(256).div(target.addn(1));
};

ChainBlock.prototype.getChainwork = function getChainwork(prev) {
  return (prev ? prev.chainwork : new bn(0)).add(this.getProof());
};

ChainBlock.prototype.isGenesis = function isGenesis() {
  return this.hash === network.genesis.hash;
};

ChainBlock.prototype.toJSON = function toJSON() {
  return {
    hash: this.hash,
    version: this.version,
    prevBlock: this.prevBlock,
    merkleRoot: this.merkleRoot,
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    height: this.height
  };
};

ChainBlock.fromJSON = function fromJSON(chain, json) {
  return new ChainBlock(chain, json);
};

ChainBlock.prototype.toRaw = function toRaw() {
  var res = new Buffer(ChainBlock.BLOCK_SIZE);

  utils.write32(res, this.version, 0);
  utils.copy(new Buffer(this.prevBlock, 'hex'), res, 4);
  utils.copy(new Buffer(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);
  utils.writeU32(res, this.height, 80);
  utils.copy(new Buffer(this.chainwork.toArray('be', 32)), res, 84);

  return res;
};

ChainBlock.fromRaw = function fromRaw(chain, p) {
  return new ChainBlock(chain, {
    hash: utils.toHex(utils.dsha256(p.slice(0, 80))),
    version: utils.read32(p, 0),
    prevBlock: utils.toHex(p.slice(4, 36)),
    merkleRoot: utils.toHex(p.slice(36, 68)),
    ts: utils.readU32(p, 68),
    bits: utils.readU32(p, 72),
    nonce: utils.readU32(p, 76),
    height: utils.readU32(p, 80),
    chainwork: new bn(p.slice(84, 116), 'be')
  });
};

ChainBlock.prototype.getMedianTimeAsync = function getMedianTime(callback) {
  var self = this;
  var median = [];
  var timeSpan = constants.block.medianTimespan;
  var i = 0;

  (function next(err, entry) {
    if (err)
      return callback(err);

    if (!entry || i >= timeSpan) {
      median = median.sort();
      return callback(null, median[median.length / 2 | 0]);
    }

    median[i] = entry.ts;
    i++;

    self.chain.db.get(entry.prevBlock, next);
  })(null, this);
};

ChainBlock.prototype.isOutdatedAsync = function isOutdated(version, callback) {
  return this.isSuperMajority(version, network.block.majorityRejectOutdated, callback);
};

ChainBlock.prototype.isUpgradedAsync = function isUpgraded(version, callback) {
  return this.isSuperMajority(version, network.block.majorityEnforceUpgrade, callback);
};

ChainBlock.prototype.isSuperMajorityAsync = function isSuperMajority(version, required, callback) {
  var self = this;
  var found = 0;
  var majorityWindow = network.block.majorityWindow;
  var i = 0;

  (function next(err, entry) {
    if (err)
      return callback(err);

    if (!entry || i >= majorityWindow || found >= required)
      return callback(null, found >= required);

    if (entry.version >= version)
      found++;

    i++;

    self.chain.db.get(entry.prevBlock, next);
  })(null, this);
};

ChainBlock.prototype.alloc = function alloc(callback) {
  var majorityWindow = network.block.majorityWindow;
  var medianTimespan = constants.block.medianTimespan;
  var powDiffInterval = network.powDiffInterval;
  var allowMinDiff = network.powAllowMinDifficultyBlocks;
  var max = Math.max(majorityWindow, medianTimespan);
  if ((this.height + 1) % powDiffInterval === 0 || allowMinDiff)
    max = Math.max(max, powDiffInterval);
  return this._alloc(max, callback);
};

ChainBlock.prototype._alloc = function _alloc(max, callback) {
  var self = this;
  var entry = this;

  assert(this.previous.length === 0);

  // Try to do this iteratively and synchronously
  // so we don't have to wait on nextTicks.
  for (;;) {
    this.previous.push(entry);

    if (this.previous.length >= max)
      return callback();

    if (!this.chain.db.hasCache(entry.prevBlock))
      break;

    entry = this.chain.db.getCache(entry.prevBlock);
  }

  (function next(err, entry) {
    if (err) {
      self.free();
      return callback(err);
    }

    if (!entry)
      return callback();

    self.previous.push(entry);

    if (self.previous.length >= max)
      return callback();

    self.chain.db.get(entry.prevBlock, next);
  })(null, entry);
};

ChainBlock.prototype.free = function free() {
  this.previous.length = 0;
};

ChainBlock.prototype.getMedianTime = function getMedianTime() {
  var entry = this;
  var median = [];
  var timeSpan = constants.block.medianTimespan;
  var i;

  for (i = 0; i < timeSpan && entry; i++, entry = this.previous[i])
    median.push(entry.ts);

  median = median.sort();

  return median[median.length / 2 | 0];
};

ChainBlock.prototype.isOutdated = function isOutdated(version) {
  return this.isSuperMajority(version, network.block.majorityRejectOutdated);
};

ChainBlock.prototype.isUpgraded = function isUpgraded(version) {
  return this.isSuperMajority(version, network.block.majorityEnforceUpgrade);
};

ChainBlock.prototype.isSuperMajority = function isSuperMajority(version, required) {
  var entry = this;
  var found = 0;
  var majorityWindow = network.block.majorityWindow;
  var i;

  for (i = 0; i < majorityWindow && found < required && entry; i++) {
    if (entry.version >= version)
      found++;
    entry = this.previous[i + 1];
  }

  return found >= required;
};

/**
 * Expose
 */

module.exports = ChainBlock;
