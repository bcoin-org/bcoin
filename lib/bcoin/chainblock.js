/**
 * chainblock.js - chainblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
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

function ChainBlock(chain, data) {
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
  this.chainwork = data.chainwork || this.getChainwork();
}

ChainBlock.BLOCK_SIZE = 112;

ChainBlock.prototype.__defineGetter__('prev', function() {
  return this.chain.db.get(this.height - 1);
});

ChainBlock.prototype.__defineGetter__('next', function() {
  return this.chain.db.get(this.height + 1);
});

ChainBlock.prototype.getProof = function getProof() {
  var target = utils.fromCompact(this.bits);
  if (target.isNeg() || target.cmpn(0) === 0)
    return new bn(0);
  return new bn(1).ushln(256).div(target.addn(1));
};

ChainBlock.prototype.getChainwork = function getChainwork() {
  var prev = this.prev;
  return (prev ? prev.chainwork : new bn(0)).add(this.getProof());
};

ChainBlock.prototype.isGenesis = function isGenesis(version) {
  return this.hash === network.genesis.hash;
};

ChainBlock.prototype.getMedianTime = function getMedianTime() {
  var entry = this;
  var median = [];
  var timeSpan = constants.block.medianTimespan;
  var i;

  for (i = 0; i < timeSpan && entry; i++, entry = entry.prev)
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
    entry = entry.prev;
  }

  return found >= required;
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
  utils.copy(utils.toArray(this.prevBlock, 'hex'), res, 4);
  utils.copy(utils.toArray(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);
  utils.copy(this.chainwork.toArray('be', 32), res, 80);

  return res;
};

ChainBlock.fromRaw = function fromRaw(chain, height, p) {
  return new ChainBlock(chain, {
    height: height,
    hash: utils.toHex(utils.dsha256(p.slice(0, 80))),
    version: utils.read32(p, 0),
    prevBlock: utils.toHex(p.slice(4, 36)),
    merkleRoot: utils.toHex(p.slice(36, 68)),
    ts: utils.readU32(p, 68),
    bits: utils.readU32(p, 72),
    nonce: utils.readU32(p, 76),
    chainwork: new bn(p.slice(80, 112), 'be')
  });
};

/**
 * Expose
 */

module.exports = ChainBlock;
