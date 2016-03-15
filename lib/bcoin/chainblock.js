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
  this.ancestors = [];
}

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

ChainBlock.prototype.ensureAncestors = function ensureAncestors(callback) {
  var majorityWindow = network.block.majorityWindow;
  var medianTimespan = constants.block.medianTimespan;
  var powDiffInterval = network.powDiffInterval;
  var allowMinDiff = network.powAllowMinDifficultyBlocks;
  var max = Math.max(majorityWindow, medianTimespan);
  if ((this.height + 1) % powDiffInterval === 0 || allowMinDiff)
    max = Math.max(max, powDiffInterval);
  assert(this.ancestors.length === 0);
  return this.alloc(max, callback);
};

ChainBlock.prototype.alloc = function alloc(max, callback) {
  var self = this;
  var i;

  return this.getAncestors(max, function(err, ancestors) {
    if (err)
      return callback(err);

    assert(ancestors);

    self.ancestors.length = 0;

    for (i = 0; i < ancestors.length; i++)
      self.ancestors.push(ancestors[i]);

    return callback();
  });
};

ChainBlock.prototype.getAncestors = function getAncestors(max, callback) {
  var entry = this;
  var ancestors = this.ancestors.slice();

  if (max === 0)
    return callback(null, []);

  if (ancestors.length)
    entry = ancestors.pop();

  assert(utils.isFinite(max));

  // Try to do this iteratively and synchronously
  // so we don't have to wait on nextTicks.
  for (;;) {
    ancestors.push(entry);

    if (ancestors.length >= max)
      return callback(null, ancestors);

    if (!this.chain.db.hasCache(entry.prevBlock)) {
      ancestors.pop();
      break;
    }

    entry = this.chain.db.getCache(entry.prevBlock);
  }

  (function next(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(null, ancestors);

    ancestors.push(entry);

    if (ancestors.length >= max)
      return callback(null, ancestors);

    entry.getPrevious(next);
  })(null, entry);
};

ChainBlock.prototype.free = function free() {
  this.ancestors.length = 0;
};

ChainBlock.prototype.isMainChain = function isMainChain(callback) {
  var self = this;
  return this.chain.db.getHash(this.height, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback(null, false);

    return callback(null, self.hash === hash);
  });
};

ChainBlock.prototype.getAncestorByHeight = function getAncestorByHeight(height, callback) {
  assert(height >= 0);
  assert(height <= this.height);
  return this.getAncestor(this.height - height, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    assert(entry.height === height);

    return callback(null, entry);
  });
};

ChainBlock.prototype.getAncestor = function getAncestor(index, callback) {
  assert(index >= 0);
  return this.getAncestors(index + 1, function(err, ancestors) {
    if (err)
      return callback(err);

    if (ancestors.length !== index + 1)
      return callback();

    return callback(null, ancestors[ancestors.length - 1]);
  });
};

ChainBlock.prototype.getPrevious = function getPrevious(callback) {
  return this.chain.db.get(this.prevBlock, callback);
};

ChainBlock.prototype.getNext = function getNext(callback) {
  var self = this;
  return this.chain.db.getNextHash(this.hash, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    return self.chain.db.get(hash, callback);
  });
};

ChainBlock.prototype.getMedianTime = function getMedianTime(ancestors) {
  var entry = this;
  var median = [];
  var timeSpan = constants.block.medianTimespan;
  var i;

  if (!ancestors)
    ancestors = this.ancestors;

  for (i = 0; i < timeSpan && entry; i++, entry = ancestors[i])
    median.push(entry.ts);

  median = median.sort();

  return median[median.length / 2 | 0];
};

ChainBlock.prototype.isOutdated = function isOutdated(version, ancestors) {
  return this.isSuperMajority(version, network.block.majorityRejectOutdated, ancestors);
};

ChainBlock.prototype.isUpgraded = function isUpgraded(version, ancestors) {
  return this.isSuperMajority(version, network.block.majorityEnforceUpgrade, ancestors);
};

ChainBlock.prototype.isSuperMajority = function isSuperMajority(version, required, ancestors) {
  var entry = this;
  var found = 0;
  var majorityWindow = network.block.majorityWindow;
  var i;

  if (!ancestors)
    ancestors = this.ancestors;

  for (i = 0; i < majorityWindow && found < required && entry; i++) {
    if (entry.version >= version)
      found++;
    entry = ancestors[i + 1];
  }

  return found >= required;
};

ChainBlock.prototype.getMedianTimeAsync = function getMedianTimeAsync(callback) {
  var self = this;

  return this.getAncestors(constants.block.medianTimespan, function(err, ancestors) {
    if (err)
      return callback(err);

    return callback(null, self.getMedianTime(ancestors));
  });
};

ChainBlock.prototype.toRaw = function toRaw() {
  var res = new Buffer(116);

  utils.write32(res, this.version, 0);
  utils.copy(new Buffer(this.prevBlock, 'hex'), res, 4);
  utils.copy(new Buffer(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);
  utils.writeU32(res, this.height, 80);
  utils.copy(new Buffer(this.chainwork.toArray('le', 32)), res, 84);

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
    chainwork: new bn(p.slice(84, 116), 'le')
  });
};

ChainBlock.prototype.toJSON = function toJSON() {
  return {
    version: this.version,
    hash: utils.revHex(this.hash),
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    height: this.height,
    chainwork: this.chainwork.toString('hex')
  };
};

ChainBlock.fromJSON = function fromJSON(chain, json) {
  json.hash = utils.revHex(json.hash);
  json.prevBlock = utils.revHex(json.prevBlock);
  json.merkleRoot = utils.revHex(json.merkleRoot);
  json.chainwork = new bn(json.chainwork, 'hex');
  return new ChainBlock(chain, json);
};

ChainBlock.prototype.inspect = function inspect() {
  var json = this.toJSON();
  json.ancestors = this.ancestors.length;
  return json;
};

/**
 * Expose
 */

module.exports = ChainBlock;
