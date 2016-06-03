/*!
 * chainentry.js - chainentry object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * Represents an entry in the chain. Unlike
 * other bitcoin fullnodes, we store the
 * chainwork _with_ the entry in order to
 * avoid reading the entire chain index on
 * boot and recalculating the chainworks.
 * @exports ChainEntry
 * @constructor
 * @param {Chain} chain
 * @param {Object} data
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

function ChainEntry(chain, data, prev) {
  if (!(this instanceof ChainEntry))
    return new ChainEntry(chain, data);

  this.chain = chain;

  this.network = this.chain
    ? this.chain.network
    : bcoin.network.get();

  this.hash = data.hash;
  this.version = data.version;
  this.prevBlock = data.prevBlock;
  this.merkleRoot = data.merkleRoot;
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.height = data.height;
  this.chainwork = data.chainwork || this.getChainwork(prev);
}

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

  if (max === 0)
    return callback(null, []);

  assert(utils.isNumber(max));

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

  return this.getAncestors(constants.block.MEDIAN_TIMESPAN, function(err, ancestors) {
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
  return this.isSuperMajority(version, this.network.block.majorityRejectOutdated, ancestors);
};

/**
 * Check {@link ChainEntry#isUpgraded asynchronously}.
 * @param {Number} version
 * @param {Function} callback - Returns [Error, Boolean].
 * @returns {Boolean}
 */

ChainEntry.prototype.isOutdatedAsync = function isOutdatedAsync(version, callback) {
  return this.isSuperMajorityAsync(
    version,
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
  return this.isSuperMajority(version, this.network.block.majorityEnforceUpgrade, ancestors);
};

/**
 * Check {@link ChainEntry#isUpgraded} asynchronously.
 * @param {Number} version
 * @param {Function} callback
 * @returns {Boolean}
 */

ChainEntry.prototype.isUpgradedAsync = function isUpgradedAsync(version, callback) {
  return this.isSuperMajorityAsync(
    version,
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

  return this.getAncestors(this.network.block.majorityWindow, function(err, ancestors) {
    if (err)
      return callback(err);

    return callback(null, self.isSuperMajority(version, required, ancestors));
  });
};

ChainEntry.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash);
});

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
  p.writeBytes(this.chainwork.toBuffer('le', 32));

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Deserialize the entry.
 * @param {Chain} chain
 * @param {Buffer} buf
 * @returns {ChainEntry}
 */

ChainEntry.fromRaw = function fromRaw(chain, buf) {
  var p = new BufferReader(buf, true);
  var hash = utils.dsha256(p.readBytes(80));

  p.seek(-80);

  return new ChainEntry(chain, {
    hash: hash.toString('hex'),
    version: p.readU32(), // Technically signed
    prevBlock: p.readHash('hex'),
    merkleRoot: p.readHash('hex'),
    ts: p.readU32(),
    bits: p.readU32(),
    nonce: p.readU32(),
    height: p.readU32(),
    chainwork: new bn(p.readBytes(32), 'le')
  });
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
 * Instantiate block from jsonified object.
 * @param {Chain} chain
 * @param {Object} json
 * @returns {ChainEntry}
 */

ChainEntry.fromJSON = function fromJSON(chain, json) {
  return new ChainEntry(chain, {
    hash: utils.revHex(json.hash),
    version: json.version,
    prevBlock: utils.revHex(json.prevBlock),
    merkleRoot: utils.revHex(json.merkleRoot),
    ts: json.ts,
    bits: json.bits,
    nonce: json.nonce,
    height: json.height,
    chainwork: new bn(json.chainwork, 10)
  });
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
    && bn.isBN(obj.chainwork)
    && typeof obj.getMedianTime === 'function';
};

/*
 * Expose
 */

module.exports = ChainEntry;
