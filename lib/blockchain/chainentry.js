/*!
 * chainentry.js - chainentry object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var BN = require('bn.js');
var Network = require('../protocol/network');
var constants = require('../protocol/constants');
var util = require('../utils/util');
var btcutils = require('../btc/utils');
var crypto = require('../crypto/crypto');
var assert = require('assert');
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');
var Headers = require('../primitives/headers');
var InvItem = require('../primitives/invitem');
var co = require('../utils/co');

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
  this.network = chain ? chain.network : Network.primary;

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
  assert(util.isNumber(options.version));
  assert(typeof options.prevBlock === 'string');
  assert(typeof options.merkleRoot === 'string');
  assert(util.isNumber(options.ts));
  assert(util.isNumber(options.bits));
  assert(util.isNumber(options.nonce));
  assert(!options.chainwork || BN.isBN(options.chainwork));

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

ChainEntry.MAX_CHAINWORK = new BN(1).ushln(256);

/**
 * Calculate the proof: (1 << 256) / (target + 1)
 * @returns {BN} proof
 */

ChainEntry.prototype.getProof = function getProof() {
  var target = btcutils.fromCompact(this.bits);
  if (target.isNeg() || target.cmpn(0) === 0)
    return new BN(0);
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
 * @returns {Promise}
 */

ChainEntry.prototype.getRetargetAncestors = function getRetargetAncestors() {
  var timespan = constants.block.MEDIAN_TIMESPAN;
  var interval = this.network.pow.retargetInterval;
  var reset = this.network.pow.difficultyReset;
  var max = timespan;

  if ((this.height + 1) % interval === 0 || reset)
    max = Math.max(max, interval);

  return this.getAncestors(max);
};

/**
 * Collect ancestors.
 * @param {Number} max - Number of ancestors.
 * @returns {Promise} - Returns ChainEntry[].
 */

ChainEntry.prototype.getAncestors = co(function* getAncestors(max) {
  var entry = this;
  var ancestors = [];
  var cached;

  if (max === 0)
    return ancestors;

  assert(util.isNumber(max));

  for (;;) {
    ancestors.push(entry);

    if (ancestors.length >= max)
      return ancestors;

    cached = this.chain.db.getCache(entry.prevBlock);

    if (!cached) {
      ancestors.pop();
      break;
    }

    entry = cached;
  }

  while (entry) {
    ancestors.push(entry);
    if (ancestors.length >= max)
      break;
    entry = yield entry.getPrevious();
  }

  return ancestors;
});

/**
 * Test whether the entry is in the main chain.
 * @returns {Promise} - Return Boolean.
 */

ChainEntry.prototype.isMainChain = co(function* isMainChain() {
  var entry;

  if (this.hash === this.chain.tip.hash
      || this.hash === this.network.genesis.hash) {
    return true;
  }

  entry = this.chain.db.getCache(this.height);

  if (entry) {
    if (entry.hash === this.hash)
      return true;
    return false;
  }

  if (yield this.chain.db.getNextHash(this.hash))
    return true;

  return false;
});

/**
 * Get ancestor by `height`.
 * @param {Number} height
 * @returns {Promise} - Returns ChainEntry[].
 */

ChainEntry.prototype.getAncestor = co(function* getAncestor(height) {
  var entry = this;

  if (height < 0)
    return;

  assert(height >= 0);
  assert(height <= this.height);

  if (yield this.isMainChain())
    return yield this.chain.db.getEntry(height);

  while (entry.height !== height) {
    entry = yield entry.getPrevious();
    assert(entry);
  }

  return entry;
});

/**
 * Get previous entry.
 * @returns {Promise} - Returns ChainEntry.
 */

ChainEntry.prototype.getPrevious = function getPrevious() {
  return this.chain.db.getEntry(this.prevBlock);
};

/**
 * Get next entry.
 * @returns {Promise} - Returns ChainEntry.
 */

ChainEntry.prototype.getNext = co(function* getNext() {
  var hash = yield this.chain.db.getNextHash(this.hash);
  if (!hash)
    return;
  return yield this.chain.db.getEntry(hash);
});

/**
 * Get next entry.
 * @returns {Promise} - Returns ChainEntry.
 */

ChainEntry.prototype.getNextEntry = co(function* getNextEntry() {
  var entry = yield this.chain.db.getEntry(this.height + 1);

  if (!entry)
    return;

  // Not on main chain.
  if (entry.prevBlock !== this.hash)
    return;

  return entry;
});

/**
 * Get median time past.
 * @see GetMedianTimePast().
 * @param {ChainEntry[]} ancestors - Note that index 0 is the same entry.
 * @returns {Number} Median time past.
 */

ChainEntry.prototype.getMedianTime = function getMedianTime(ancestors) {
  var timespan = constants.block.MEDIAN_TIMESPAN;
  var entry = this;
  var median = [];
  var i;

  for (i = 0; i < timespan && entry; i++, entry = ancestors[i])
    median.push(entry.ts);

  median = median.sort();

  return median[median.length / 2 | 0];
};

/**
 * Get median time past asynchronously (see {@link ChainEntry#getMedianTime}).
 * @returns {Promise} - Returns Number.
 */

ChainEntry.prototype.getMedianTimeAsync = co(function* getMedianTimeAsync() {
  var timespan = constants.block.MEDIAN_TIMESPAN;
  var ancestors = yield this.getAncestors(timespan);
  return this.getMedianTime(ancestors);
});

/**
 * Test whether the entry is potentially
 * an ancestor of a checkpoint.
 * @returns {Boolean}
 */

ChainEntry.prototype.isHistorical = function isHistorical() {
  if (this.chain.options.useCheckpoints) {
    if (this.height + 1 <= this.network.checkpoints.lastHeight)
      return true;
  }
  return false;
};

/**
 * Test whether the entry contains an unknown version bit.
 * @returns {Boolean}
 */

ChainEntry.prototype.hasUnknown = function hasUnknown() {
  var bits = this.version & constants.versionbits.TOP_MASK;
  var topBits = constants.versionbits.TOP_BITS;

  if ((bits >>> 0) !== topBits)
    return false;

  return (this.version & this.network.unknownBits) !== 0;
};

/**
 * Test whether the entry contains a version bit.
 * @param {Object} deployment
 * @returns {Boolean}
 */

ChainEntry.prototype.hasBit = function hasBit(bit) {
  var bits = this.version & constants.versionbits.TOP_MASK;
  var topBits = constants.versionbits.TOP_BITS;
  var mask = 1 << bit;
  return (bits >>> 0) === topBits && (this.version & mask) !== 0;
};

ChainEntry.prototype.__defineGetter__('rhash', function() {
  return util.revHex(this.hash);
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
  var bw = new BufferWriter(writer);

  bw.writeU32(this.version);
  bw.writeHash(this.prevBlock);
  bw.writeHash(this.merkleRoot);
  bw.writeU32(this.ts);
  bw.writeU32(this.bits);
  bw.writeU32(this.nonce);
  bw.writeU32(this.height);
  bw.writeBytes(this.chainwork.toArrayLike(Buffer, 'le', 32));

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

ChainEntry.prototype.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data, true);
  var hash = crypto.hash256(br.readBytes(80));

  br.seek(-80);

  this.hash = hash.toString('hex');
  this.version = br.readU32(); // Technically signed
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.ts = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();
  this.height = br.readU32();
  this.chainwork = new BN(br.readBytes(32), 'le');

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
    hash: util.revHex(this.hash),
    version: this.version,
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
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
  assert(util.isNumber(json.version));
  assert(typeof json.prevBlock === 'string');
  assert(typeof json.merkleRoot === 'string');
  assert(util.isNumber(json.ts));
  assert(util.isNumber(json.bits));
  assert(util.isNumber(json.nonce));
  assert(typeof json.chainwork === 'string');

  this.hash = util.revHex(json.hash);
  this.version = json.version;
  this.prevBlock = util.revHex(json.prevBlock);
  this.merkleRoot = util.revHex(json.merkleRoot);
  this.ts = json.ts;
  this.bits = json.bits;
  this.nonce = json.nonce;
  this.height = json.height;
  this.chainwork = new BN(json.chainwork, 10);

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
  return Headers.fromEntry(this);
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
  var json = this.toJSON();
  json.version = util.hex32(json.version);
  return json;
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
