/*!
 * chainentry.js - chainentry object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const BN = require('../crypto/bn');
const consensus = require('../protocol/consensus');
const util = require('../utils/util');
const digest = require('../crypto/digest');
const encoding = require('../utils/encoding');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const Headers = require('../primitives/headers');
const InvItem = require('../primitives/invitem');
const ZERO = new BN(0);

/**
 * Represents an entry in the chain. Unlike
 * other bitcoin fullnodes, we store the
 * chainwork _with_ the entry in order to
 * avoid reading the entire chain index on
 * boot and recalculating the chainworks.
 * @alias module:blockchain.ChainEntry
 * @constructor
 * @param {Object?} options
 * @property {Hash} hash
 * @property {Number} version - Transaction version. Note that Bcoin reads
 * versions as unsigned even though they are signed at the protocol level.
 * This value will never be negative.
 * @property {Hash} prevBlock
 * @property {Hash} merkleRoot
 * @property {Number} time
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} height
 * @property {BN} chainwork
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function ChainEntry(options) {
  if (!(this instanceof ChainEntry))
    return new ChainEntry(options);

  this.hash = encoding.NULL_HASH;
  this.version = 1;
  this.prevBlock = encoding.NULL_HASH;
  this.merkleRoot = encoding.NULL_HASH;
  this.time = 0;
  this.bits = 0;
  this.nonce = 0;
  this.height = 0;
  this.chainwork = ZERO;

  if (options)
    this.fromOptions(options);
}

/**
 * The max chainwork (1 << 256).
 * @const {BN}
 */

ChainEntry.MAX_CHAINWORK = new BN(1).ushln(256);

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 */

ChainEntry.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Block data is required.');
  assert(typeof options.hash === 'string');
  assert(util.isU32(options.version));
  assert(typeof options.prevBlock === 'string');
  assert(typeof options.merkleRoot === 'string');
  assert(util.isU32(options.time));
  assert(util.isU32(options.bits));
  assert(util.isU32(options.nonce));
  assert(util.isU32(options.height));
  assert(!options.chainwork || BN.isBN(options.chainwork));

  this.hash = options.hash;
  this.version = options.version;
  this.prevBlock = options.prevBlock;
  this.merkleRoot = options.merkleRoot;
  this.time = options.time;
  this.bits = options.bits;
  this.nonce = options.nonce;
  this.height = options.height;
  this.chainwork = options.chainwork || ZERO;

  return this;
};

/**
 * Instantiate chainentry from options.
 * @param {Object} options
 * @param {ChainEntry} prev - Previous entry.
 * @returns {ChainEntry}
 */

ChainEntry.fromOptions = function fromOptions(options, prev) {
  return new ChainEntry().fromOptions(options, prev);
};

/**
 * Calculate the proof: (1 << 256) / (target + 1)
 * @returns {BN} proof
 */

ChainEntry.prototype.getProof = function getProof() {
  const target = consensus.fromCompact(this.bits);

  if (target.isNeg() || target.isZero())
    return new BN(0);

  return ChainEntry.MAX_CHAINWORK.div(target.iaddn(1));
};

/**
 * Calculate the chainwork by
 * adding proof to previous chainwork.
 * @returns {BN} chainwork
 */

ChainEntry.prototype.getChainwork = function getChainwork(prev) {
  const proof = this.getProof();

  if (!prev)
    return proof;

  return proof.iadd(prev.chainwork);
};

/**
 * Test against the genesis block.
 * @returns {Boolean}
 */

ChainEntry.prototype.isGenesis = function isGenesis() {
  return this.height === 0;
};

/**
 * Test whether the entry contains an unknown version bit.
 * @param {Network} network
 * @returns {Boolean}
 */

ChainEntry.prototype.hasUnknown = function hasUnknown(network) {
  const TOP_MASK = consensus.VERSION_TOP_MASK;
  const TOP_BITS = consensus.VERSION_TOP_BITS;
  const bits = (this.version & TOP_MASK) >>> 0;

  if (bits !== TOP_BITS)
    return false;

  return (this.version & network.unknownBits) !== 0;
};

/**
 * Test whether the entry contains a version bit.
 * @param {Number} bit
 * @returns {Boolean}
 */

ChainEntry.prototype.hasBit = function hasBit(bit) {
  return consensus.hasBit(this.version, bit);
};

/**
 * Get little-endian block hash.
 * @returns {Hash}
 */

ChainEntry.prototype.rhash = function rhash() {
  return util.revHex(this.hash);
};

/**
 * Inject properties from block.
 * @private
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev - Previous entry.
 */

ChainEntry.prototype.fromBlock = function fromBlock(block, prev) {
  this.hash = block.hash('hex');
  this.version = block.version;
  this.prevBlock = block.prevBlock;
  this.merkleRoot = block.merkleRoot;
  this.time = block.time;
  this.bits = block.bits;
  this.nonce = block.nonce;
  this.height = prev ? prev.height + 1: 0;
  this.chainwork = this.getChainwork(prev);
  return this;
};

/**
 * Instantiate chainentry from block.
 * @param {Block|MerkleBlock} block
 * @param {ChainEntry} prev - Previous entry.
 * @returns {ChainEntry}
 */

ChainEntry.fromBlock = function fromBlock(block, prev) {
  return new ChainEntry().fromBlock(block, prev);
};

/**
 * Serialize the entry to internal database format.
 * @returns {Buffer}
 */

ChainEntry.prototype.toRaw = function toRaw() {
  const bw = new StaticWriter(116);

  bw.writeU32(this.version);
  bw.writeHash(this.prevBlock);
  bw.writeHash(this.merkleRoot);
  bw.writeU32(this.time);
  bw.writeU32(this.bits);
  bw.writeU32(this.nonce);
  bw.writeU32(this.height);
  bw.writeBytes(this.chainwork.toArrayLike(Buffer, 'le', 32));

  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

ChainEntry.prototype.fromRaw = function fromRaw(data) {
  const br = new BufferReader(data, true);
  const hash = digest.hash256(br.readBytes(80));

  br.seek(-80);

  this.hash = hash.toString('hex');
  this.version = br.readU32();
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.time = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();
  this.height = br.readU32();
  this.chainwork = new BN(br.readBytes(32), 'le');

  return this;
};

/**
 * Deserialize the entry.
 * @param {Buffer} data
 * @returns {ChainEntry}
 */

ChainEntry.fromRaw = function fromRaw(data) {
  return new ChainEntry().fromRaw(data);
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
    time: this.time,
    bits: this.bits,
    nonce: this.nonce,
    height: this.height,
    chainwork: this.chainwork.toString('hex', 64)
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
  assert(util.isU32(json.version));
  assert(typeof json.prevBlock === 'string');
  assert(typeof json.merkleRoot === 'string');
  assert(util.isU32(json.time));
  assert(util.isU32(json.bits));
  assert(util.isU32(json.nonce));
  assert(typeof json.chainwork === 'string');

  this.hash = util.revHex(json.hash);
  this.version = json.version;
  this.prevBlock = util.revHex(json.prevBlock);
  this.merkleRoot = util.revHex(json.merkleRoot);
  this.time = json.time;
  this.bits = json.bits;
  this.nonce = json.nonce;
  this.height = json.height;
  this.chainwork = new BN(json.chainwork, 'hex');

  return this;
};

/**
 * Instantiate block from jsonified object.
 * @param {Object} json
 * @returns {ChainEntry}
 */

ChainEntry.fromJSON = function fromJSON(json) {
  return new ChainEntry().fromJSON(json);
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
  return new InvItem(InvItem.types.BLOCK, this.hash);
};

/**
 * Return a more user-friendly object.
 * @returns {Object}
 */

ChainEntry.prototype.inspect = function inspect() {
  const json = this.toJSON();
  json.version = util.hex32(json.version);
  return json;
};

/**
 * Test whether an object is a {@link ChainEntry}.
 * @param {Object} obj
 * @returns {Boolean}
 */

ChainEntry.isChainEntry = function isChainEntry(obj) {
  return obj instanceof ChainEntry;
};

/*
 * Expose
 */

module.exports = ChainEntry;
