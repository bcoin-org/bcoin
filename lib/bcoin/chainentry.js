/*!
 * chainentry.js - chainentry object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var InvItem = bcoin.packets.InvItem;

/**
 * Represents an entry in the chain. Unlike
 * other bitcoin fullnodes, we store the
 * chainwork _with_ the entry in order to
 * avoid reading the entire chain index on
 * boot and recalculating the chainworks.
 * @exports ChainEntry
 * @constructor
 * @param {Chain} chain
 * @param {Object} options
 * @param {ChainEntry} prev
 * @property {Hash} hash
 * @property {Number} version - Transaction version. Note that BCoin reads
 * versions as unsigned even though they are signed at the protocol level.
 * This value will never be negative.
 * @property {Hash} prevBlock
 * @property {Hash} merkleRoot
 * @property {Number} ts
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} height
 * @property {BN} chainwork
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function ChainEntry(chain, options, prev) {
  if (!(this instanceof ChainEntry))
    return new ChainEntry(chain, options, prev);

  this.chain = chain;
  this.network = chain ? chain.network : bcoin.network.get();

  this.hash = constants.NULL_HASH;
  this.version = 1;
  this.prevBlock = constants.NULL_HASH;
  this.merkleRoot = constants.NULL_HASH;
  this.ts = 0;
  this.bits = 0;
  this.nonce = 0;
  this.height = -1;
  this.chainwork = null;

  if (options)
    this.fromOptions(options, prev);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @param {ChainEntry} prev - Previous entry.
 */

ChainEntry.prototype.fromOptions = function fromOptions(options, prev) {
  assert(options, 'Block data is required.');
  assert(typeof options.hash === 'string');
  assert(utils.isNumber(options.version));
  assert(typeof options.prevBlock === 'string');
  assert(typeof options.merkleRoot === 'string');
  assert(utils.isNumber(options.ts));
  assert(utils.isNumber(options.bits));
  assert(utils.isNumber(options.nonce));
  assert(!options.chainwork || bn.isBN(options.chainwork));

  this.hash = options.hash;
  this.version = options.version;
  this.prevBlock = options.prevBlock;
  this.merkleRoot = options.merkleRoot;
  this.ts = options.ts;
  this.bits = options.bits;
  this.nonce = options.nonce;
  this.height = options.height;
  this.chainwork = options.chainwork;

  if (!this.chainwork)
    this.chainwork = this.getChainwork(prev);

  return this;
};

/**
 * Instantiate chainentry from options.
 * @param {Chain} chain
 * @param {Object} options
 * @param {ChainEntry} prev - Previous entry.
 * @returns {ChainEntry}
 */

ChainEntry.fromOptions = function fromOptions(chain, options, prev) {
  return new ChainEntry(chain).fromOptions(options, prev);
};

/**
 * The max chainwork (1 << 256).
 * @const {BN}
 */

ChainEntry.MAX_CHAINWORK = new bn(1).ushln(256);

/**
 * Calculate the proof: (1 << 256) / (target + 1)
 * @returns {BN} proof
 */

ChainEntry.prototype.getProof = function getProof() {
  var target = utils.fromCompact(this.bits);
  if (target.isNeg() || target.cmpn(0) === 0)
    return new bn(0);
  return ChainEntry.MAX_CHAINWORK.div(target.iaddn(1));
};

/**
 * Calculate the chainwork by
 * adding proof to previous chainwork.
 * @returns {BN} chainwork
 */

ChainEntry.prototype.getChainwork = function getChainwork(prev) {
  var proof = this.getProof();

  if (!prev)
    return proof;

  return proof.iadd(prev.chainwork);
};

/**
 * Test against the genesis block.
 * @returns {Boolean}
 */

ChainEntry.prototype.isGenesis = function isGenesis() {
  return this.hash === this.network.genesis.hash;
};

/**
 * Allocate ancestors based on retarget interval and
 * majority window. These ancestors will be stored
 * in the `ancestors` array and enable use of synchronous
 * ChainEntry methods.
 * @param {Function} callback
 */

ChainEntry.prototype.getRetargetAncestors = function getRetargetAncestors(callback) {
  var majorityWindow = this.network.block.majorityWindow;
  var medianTimespan = constants.block.MEDIAN_TIMESPAN;
  var powDiffInterval = this.network.pow.retargetInterval;
  var allowMinDiff = this.network.pow.allowMinDifficultyBlocks;
  var max = Math.max(majorityWindow, medianTimespan);
  if ((this.height + 1) % powDiffInterval === 0 || allowMinDiff)
    max = Math.max(max, powDiffInterval);
  return this.getAncestors(max, callback);
};

/**
 * Collect ancestors.
 * @param {Number} max - Number of ancestors.
 * @param {Function} callback - Returns [Error, ChainEntry[]].
 */

ChainEntry.prototype.getAncestors = function getAncestors(max, callback) {
  var entry = this;
  var ancestors = [];
  var cached;

  if (max === 0)
    return callback(null, []);

  assert(utils.isNumber(max));

  // Try to do this iteratively and synchronously
  // so we don't have to wait on nextTicks.
  for (;;) {
    ancestors.push(entry);

    if (ancestors.length >= max)
      return callback(null, ancestors);

    cached = this.chain.db.getCache(entry.prevBlock);

    if (!cached) {
      ancestors.pop();
      break;
    }

    entry = cached;
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

/**
 * Test whether the entry is in the main chain.
 * @param {Function} callback - Return [Error, Boolean].
 */

ChainEntry.prototype.isMainChain = function isMainChain(callback) {
  return this.chain.db.isMainChain(this, callback);
};

/**
 * Collect ancestors up to `height`.
 * @param {Number} height
 * @param {Function} callback - Returns [Error, ChainEntry[]].
 */

ChainEntry.prototype.getAncestorByHeight = function getAncestorByHeight(height, callback) {
  var self = this;

  if (height < 0)
    return utils.nextTick(callback);

  assert(height >= 0);
  assert(height <= this.height);

  this.isMainChain(function(err, main) {
    if (err)
      return callback(err);

    if (main)
      return self.chain.db.get(height, callback);

    return self.getAncestor(self.height - height, function(err, entry) {
      if (err)
        return callback(err);

      if (!entry)
        return callback();

      assert(entry.height === height);

      return callback(null, entry);
    });
  });
};

/**
 * Get a single ancestor by index. Note that index-0 is
 * the same entry. This is done for sane porting of
 * bitcoind functions to BCoin.
 * @param {Number} index
 * @returns {Function} callback - Returns [Error, ChainEntry].
 */

ChainEntry.prototype.getAncestor = function getAncestor(index, callback) {
  assert(index >= 0);
  return this.getAncestors(index + 1, function(err, ancestors) {
    if (err)
      return callback(err);

    if (ancestors.length < index + 1)
      return callback();

    return callback(null, ancestors[index]);
  });
};

/**
 * Get previous entry.
 * @param {Function} callback - Returns [Error, ChainEntry].
 */

ChainEntry.prototype.getPrevious = function getPrevious(callback) {
  return this.chain.db.get(this.prevBlock, callback);
};

/**
 * Get next entry.
 * @param {Function} callback - Returns [Error, ChainEntry].
 */

ChainEntry.prototype.getNext = function getNext(callback) {
  var self = this;
  return this.chain.db.getNextHash(this.hash, function(err, hash) {
    if (err)
      return callback(err);

    if (!hash)
      return callback();

    return self.chain.db.get(hash, callback);
  });
};

/**
 * Get median time past.
 * @see GetMedianTimePast().
 * @param {ChainEntry[]} ancestors - Note that index 0 is the same entry.
 * @returns {Number} Median time past.
 */

ChainEntry.prototype.getMedianTime = function getMedianTime(ancestors) {
  var entry = this;
  var median = [];
  var timeSpan = constants.block.MEDIAN_TIMESPAN;
  var i;

  for (i = 0; i < timeSpan && entry; i++, entry = ancestors[i])
    median.push(entry.ts);

  median = median.sort();

  return median[median.length / 2 | 0];
};

/**
 * Get median time past asynchronously (see {@link ChainEntry#getMedianTime}).
 * @param {Function} callback - Returns [Error, Number].
 */

ChainEntry.prototype.getMedianTimeAsync = function getMedianTimeAsync(callback) {
  var self = this;
  var MEDIAN_TIMESPAN = constants.block.MEDIAN_TIMESPAN;

  return this.getAncestors(MEDIAN_TIMESPAN, function(err, ancestors) {
    if (err)
      return callback(err);

    return callback(null, self.getMedianTime(ancestors));
  });
};

/**
 * Check isSuperMajority against majorityRejectOutdated.
 * @param {Number} version
 * @param {ChainEntry[]} ancestors
 * @returns {Boolean}
 */

ChainEntry.prototype.isOutdated = function isOutdated(version, ancestors) {
  return this.isSuperMajority(version,
    this.network.block.majorityRejectOutdated,
    ancestors);
};

/**
 * Check {@link ChainEntry#isUpgraded asynchronously}.
 * @param {Number} version
 * @param {Function} callback - Returns [Error, Boolean].
 * @returns {Boolean}
 */

ChainEntry.prototype.isOutdatedAsync = function isOutdatedAsync(version, callback) {
  return this.isSuperMajorityAsync(version,
    this.network.block.majorityRejectOutdated,
    callback);
};

/**
 * Check isSuperMajority against majorityEnforceUpgrade.
 * @param {Number} version
 * @param {ChainEntry[]} ancestors
 * @returns {Boolean}
 */

ChainEntry.prototype.isUpgraded = function isUpgraded(version, ancestors) {
  return this.isSuperMajority(version,
    this.network.block.majorityEnforceUpgrade,
    ancestors);
};

/**
 * Check {@link ChainEntry#isUpgraded} asynchronously.
 * @param {Number} version
 * @param {Function} callback
 * @returns {Boolean}
 */

ChainEntry.prototype.isUpgradedAsync = function isUpgradedAsync(version, callback) {
  return this.isSuperMajorityAsync(version,
    this.network.block.majorityEnforceUpgrade,
    callback);
};

/**
 * Calculate found number of block versions within the majority window.
 * @param {Number} version
 * @param {Number} required
 * @param {ChainEntry[]} ancestors
 * @returns {Boolean}
 */

ChainEntry.prototype.isSuperMajority = function isSuperMajority(version, required, ancestors) {
  var entry = this;
  var found = 0;
  var majorityWindow = this.network.block.majorityWindow;
  var i;

  for (i = 0; i < majorityWindow && found < required && entry; i++) {
    if (entry.version >= version)
      found++;
    entry = ancestors[i + 1];
  }

  return found >= required;
};

/**
 * Calculate {@link ChainEntry#isSuperMajority asynchronously}.
 * @param {Number} version
 * @param {Number} required
 * @param {Function} callback - Returns [Error, Boolean].
 * @returns {Boolean}
 */

ChainEntry.prototype.isSuperMajorityAsync = function isSuperMajorityAsync(version, required, callback) {
  var self = this;
  var majorityWindow = this.network.block.majorityWindow;

  return this.getAncestors(majorityWindow, function(err, ancestors) {
    if (err)
      return callback(err);

    return callback(null, self.isSuperMajority(version, required, ancestors));
  });
};

ChainEntry.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash);
});

/**
 * Inject properties from block.
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev - Previous entry.
 */

ChainEntry.prototype.fromBlock = function fromBlock(block, prev) {
  assert(block.height !== -1);

  this.hash = block.hash('hex');
  this.version = block.version;
  this.prevBlock = block.prevBlock;
  this.merkleRoot = block.merkleRoot;
  this.ts = block.ts;
  this.bits = block.bits;
  this.nonce = block.nonce;
  this.height = block.height;
  this.chainwork = this.getChainwork(prev);

  return this;
};

/**
 * Instantiate chainentry from block.
 * @param {Chain} chain
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev - Previous entry.
 * @returns {ChainEntry}
 */

ChainEntry.fromBlock = function fromBlock(chain, block, prev) {
  return new ChainEntry(chain).fromBlock(block, prev);
};

/**
 * Serialize the entry to internal database format.
 * @returns {Buffer}
 */

ChainEntry.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.write32(this.version);
  p.writeHash(this.prevBlock);
  p.writeHash(this.merkleRoot);
  p.writeU32(this.ts);
  p.writeU32(this.bits);
  p.writeU32(this.nonce);
  p.writeU32(this.height);
  p.writeBytes(this.chainwork.toArrayLike(Buffer, 'le', 32));

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

ChainEntry.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data, true);
  var hash = utils.hash256(p.readBytes(80));

  p.seek(-80);

  this.hash = hash.toString('hex');
  this.version = p.readU32(); // Technically signed
  this.prevBlock = p.readHash('hex');
  this.merkleRoot = p.readHash('hex');
  this.ts = p.readU32();
  this.bits = p.readU32();
  this.nonce = p.readU32();
  this.height = p.readU32();
  this.chainwork = new bn(p.readBytes(32), 'le');

  return this;
};

/**
 * Deserialize the entry.
 * @param {Chain} chain
 * @param {Buffer} data
 * @returns {ChainEntry}
 */

ChainEntry.fromRaw = function fromRaw(chain, data) {
  return new ChainEntry(chain).fromRaw(data);
};

/**
 * Serialize the entry to an object more
 * suitable for JSON serialization.
 * @returns {Object}
 */

ChainEntry.prototype.toJSON = function toJSON() {
  return {
    hash: utils.revHex(this.hash),
    version: this.version,
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    height: this.height,
    chainwork: this.chainwork.toString(10)
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

ChainEntry.prototype.fromJSON = function fromJSON(json) {
  assert(json, 'Block data is required.');
  assert(typeof json.hash === 'string');
  assert(utils.isNumber(json.version));
  assert(typeof json.prevBlock === 'string');
  assert(typeof json.merkleRoot === 'string');
  assert(utils.isNumber(json.ts));
  assert(utils.isNumber(json.bits));
  assert(utils.isNumber(json.nonce));
  assert(typeof json.chainwork === 'string');

  this.hash = utils.revHex(json.hash);
  this.version = json.version;
  this.prevBlock = utils.revHex(json.prevBlock);
  this.merkleRoot = utils.revHex(json.merkleRoot);
  this.ts = json.ts;
  this.bits = json.bits;
  this.nonce = json.nonce;
  this.height = json.height;
  this.chainwork = new bn(json.chainwork, 10);

  return this;
};

/**
 * Instantiate block from jsonified object.
 * @param {Chain} chain
 * @param {Object} json
 * @returns {ChainEntry}
 */

ChainEntry.fromJSON = function fromJSON(chain, json) {
  return new ChainEntry(chain).fromJSON(json);
};

/**
 * Convert the entry to a headers object.
 * @returns {Headers}
 */

ChainEntry.prototype.toHeaders = function toHeaders() {
  return bcoin.headers.fromEntry(this);
};

/**
 * Convert the entry to an inv item.
 * @returns {InvItem}
 */

ChainEntry.prototype.toInv = function toInv() {
  return new InvItem(constants.inv.BLOCK, this.hash);
};

/**
 * Return a more user-friendly object.
 * @returns {Object}
 */

ChainEntry.prototype.inspect = function inspect() {
  return this.toJSON();
};

/**
 * Test whether an object is a {@link ChainEntry}.
 * @param {Object} obj
 * @returns {Boolean}
 */

ChainEntry.isChainEntry = function isChainEntry(obj) {
  return obj
    && obj.chainwork !== undefined
    && typeof obj.getMedianTime === 'function';
};

/*
 * Expose
 */

module.exports = ChainEntry;
