/*!
 * chainblock.js - chainblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
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
 * @exports ChainBlock
 * @constructor
 * @param {Chain} chain
 * @param {Object} data
 * @param {ChainBlock} prev
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
 * @property {ChainBlock[]} ancestors - Ancestors are temporarily
 * advocate for IsSuperMajority and retargeting.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
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

/**
 * Calculate the proof: (1 << 256) / (target + 1)
 * @returns {BN} proof
 */

ChainBlock.prototype.getProof = function getProof() {
  var target = utils.fromCompact(this.bits);
  if (target.isNeg() || target.cmpn(0) === 0)
    return new bn(0);
  return new bn(1).ushln(256).div(target.addn(1));
};

/**
 * Calculate the chainwork by
 * adding proof to previous chainwork.
 * @returns {BN} chainwork
 */

ChainBlock.prototype.getChainwork = function getChainwork(prev) {
  return (prev ? prev.chainwork : new bn(0)).add(this.getProof());
};

/**
 * Test against the genesis block.
 * @returns {Boolean}
 */

ChainBlock.prototype.isGenesis = function isGenesis() {
  return this.hash === network.genesis.hash;
};

/**
 * Allocate ancestors based on retarget interval and
 * majority window. These ancestors will be stored
 * in the `ancestors` array and enable use of synchronous
 * ChainBlock methods.
 * @param {Function} callback
 */

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

/**
 * Allocate ancestors.
 * @param {Number} max - Number of ancestors.
 * @param {Function} callback
 */

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

/**
 * Collect ancestors.
 * @param {Number} max - Number of ancestors.
 * @param {Function} callback - Returns [Error, ChainBlock[]].
 */

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

/**
 * Free up ancestors. This is very important because
 * chain entries are cached in the ChainDB's LRU cache.
 */

ChainBlock.prototype.free = function free() {
  this.ancestors.length = 0;
};

/**
 * Test whether the entry is in the main chain.
 * @param {Function} callback - Return [Error, Boolean].
 */

ChainBlock.prototype.isMainChain = function isMainChain(callback) {
  return this.chain.db.isMainChain(this, callback);
};

/**
 * Collect ancestors up to `height`.
 * @param {Number} height
 * @param {Function} callback - Returns [Error, ChainBlock[]].
 */

ChainBlock.prototype.getAncestorByHeight = function getAncestorByHeight(height, callback) {
  if (height < 0)
    return utils.nextTick(callback);

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

/**
 * Get a single ancestor by index. Note that index-0 is
 * the same entry. This is done for sane porting of
 * bitcoind functions to BCoin.
 * @param {Number} index
 * @returns {Function} callback - Returns [Error, ChainBlock].
 */

ChainBlock.prototype.getAncestor = function getAncestor(index, callback) {
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
 * @param {Function} callback - Returns [Error, ChainBlock].
 */

ChainBlock.prototype.getPrevious = function getPrevious(callback) {
  return this.chain.db.get(this.prevBlock, callback);
};

/**
 * Get next entry.
 * @param {Function} callback - Returns [Error, ChainBlock].
 */

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

/**
 * Get median time past.
 * @see GetMedianTimePast().
 * @param {ChainBlock[]} ancestors - Note that index 0 is the same entry.
 * @returns {Number} Median time past.
 */

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

/**
 * Check isSuperMajority against majorityRejectOutdated.
 * @param {Number} version
 * @param {ChainBlock[]} ancestors
 * @returns {Boolean}
 */

ChainBlock.prototype.isOutdated = function isOutdated(version, ancestors) {
  return this.isSuperMajority(version, network.block.majorityRejectOutdated, ancestors);
};

/**
 * Check isSuperMajority against majorityEnforceUpgrade.
 * @param {Number} version
 * @param {ChainBlock[]} ancestors
 * @returns {Boolean}
 */

ChainBlock.prototype.isUpgraded = function isUpgraded(version, ancestors) {
  return this.isSuperMajority(version, network.block.majorityEnforceUpgrade, ancestors);
};

/**
 * Calculate found number of block versions within the majority window.
 * @param {Number} version
 * @param {Number} required
 * @param {ChainBlock[]} ancestors
 * @returns {Boolean}
 */

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

/**
 * Get median time past asynchronously.
 * @param {Function} callback - Returns [Error, Number].
 */

ChainBlock.prototype.getMedianTimeAsync = function getMedianTimeAsync(callback) {
  var self = this;

  return this.getAncestors(constants.block.medianTimespan, function(err, ancestors) {
    if (err)
      return callback(err);

    return callback(null, self.getMedianTime(ancestors));
  });
};

ChainBlock.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash);
});

/**
 * Serialize the entry to internal database format.
 * @returns {Buffer}
 */

ChainBlock.prototype.toRaw = function toRaw() {
  var p = new BufferWriter();

  p.write32(this.version);
  p.writeHash(this.prevBlock);
  p.writeHash(this.merkleRoot);
  p.writeU32(this.ts);
  p.writeU32(this.bits);
  p.writeU32(this.nonce);
  p.writeU32(this.height);
  p.writeBytes(this.chainwork.toBuffer('le', 32));

  return p.render();
};

/**
 * Deserialize the entry.
 * @param {Chain} chain
 * @param {Buffer} buf
 * @returns {ChainBlock}
 */

ChainBlock.fromRaw = function fromRaw(chain, buf) {
  var p = new BufferReader(buf);
  var hash = utils.dsha256(buf.slice(0, 80));

  return new ChainBlock(chain, {
    hash: utils.toHex(hash),
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

/**
 * Instantiate block from jsonified object.
 * @param {Chain} chain
 * @param {Object} json
 * @returns {ChainBlock}
 */

ChainBlock.fromJSON = function fromJSON(chain, json) {
  json.hash = utils.revHex(json.hash);
  json.prevBlock = utils.revHex(json.prevBlock);
  json.merkleRoot = utils.revHex(json.merkleRoot);
  json.chainwork = new bn(json.chainwork, 'hex');
  return new ChainBlock(chain, json);
};

/**
 * Return a more user-friendly object.
 * @returns {Object}
 */

ChainBlock.prototype.inspect = function inspect() {
  var json = this.toJSON();
  json.ancestors = this.ancestors.length;
  return json;
};

/**
 * Test whether an object is a {@link ChainBlock}.
 * @returns {Boolean}
 */

ChainBlock.isChainBlock = function isChainBlock(obj) {
  return obj
    && bn.isBN(obj.chainwork)
    && typeof obj.getMedianTime === 'function';
};

/**
 * Expose
 */

return ChainBlock;
};
