/*!
 * chainentry.js - chainentry object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const BN = require('bn.js');
const consensus = require('../protocol/consensus');
const hash256 = require('bcrypto/lib/hash256');
const util = require('../utils/util');
const Headers = require('../primitives/headers');
const InvItem = require('../primitives/invitem');

/*
 * Constants
 */

const ZERO = new BN(0);

/**
 * Chain Entry
 * Represents an entry in the chain. Unlike
 * other bitcoin fullnodes, we store the
 * chainwork _with_ the entry in order to
 * avoid reading the entire chain index on
 * boot and recalculating the chainworks.
 * @alias module:blockchain.ChainEntry
 * @property {Hash} hash
 * @property {Number} version
 * @property {Hash} prevBlock
 * @property {Hash} merkleRoot
 * @property {Number} time
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} height
 * @property {BN} chainwork
 * @property {Hash} rhash
 */

class ChainEntry {
  /**
   * Create a chain entry.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    this.hash = consensus.NULL_HASH;
    this.version = 1;
    this.prevBlock = consensus.NULL_HASH;
    this.merkleRoot = consensus.NULL_HASH;
    this.time = 0;
    this.bits = 0;
    this.nonce = 0;
    this.height = 0;
    this.chainwork = ZERO;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Block data is required.');
    assert(typeof options.hash === 'string');
    assert((options.version >>> 0) === options.version);
    assert(typeof options.prevBlock === 'string');
    assert(typeof options.merkleRoot === 'string');
    assert((options.time >>> 0) === options.time);
    assert((options.bits >>> 0) === options.bits);
    assert((options.nonce >>> 0) === options.nonce);
    assert((options.height >>> 0) === options.height);
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
  }

  /**
   * Instantiate chainentry from options.
   * @param {Object} options
   * @param {ChainEntry} prev - Previous entry.
   * @returns {ChainEntry}
   */

  static fromOptions(options, prev) {
    return new this().fromOptions(options, prev);
  }

  /**
   * Calculate the proof: (1 << 256) / (target + 1)
   * @returns {BN} proof
   */

  getProof() {
    const target = consensus.fromCompact(this.bits);

    if (target.isNeg() || target.isZero())
      return new BN(0);

    return ChainEntry.MAX_CHAINWORK.div(target.iaddn(1));
  }

  /**
   * Calculate the chainwork by
   * adding proof to previous chainwork.
   * @returns {BN} chainwork
   */

  getChainwork(prev) {
    const proof = this.getProof();

    if (!prev)
      return proof;

    return proof.iadd(prev.chainwork);
  }

  /**
   * Test against the genesis block.
   * @returns {Boolean}
   */

  isGenesis() {
    return this.height === 0;
  }

  /**
   * Test whether the entry contains an unknown version bit.
   * @param {Network} network
   * @returns {Boolean}
   */

  hasUnknown(network) {
    const TOP_MASK = consensus.VERSION_TOP_MASK;
    const TOP_BITS = consensus.VERSION_TOP_BITS;
    const bits = (this.version & TOP_MASK) >>> 0;

    if (bits !== TOP_BITS)
      return false;

    return (this.version & network.unknownBits) !== 0;
  }

  /**
   * Test whether the entry contains a version bit.
   * @param {Number} bit
   * @returns {Boolean}
   */

  hasBit(bit) {
    return consensus.hasBit(this.version, bit);
  }

  /**
   * Get little-endian block hash.
   * @returns {Hash}
   */

  rhash() {
    return util.revHex(this.hash);
  }

  /**
   * Inject properties from block.
   * @private
   * @param {Block|MerkleBlock} block
   * @param {ChainEntry} prev - Previous entry.
   */

  fromBlock(block, prev) {
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
  }

  /**
   * Instantiate chainentry from block.
   * @param {Block|MerkleBlock} block
   * @param {ChainEntry} prev - Previous entry.
   * @returns {ChainEntry}
   */

  static fromBlock(block, prev) {
    return new this().fromBlock(block, prev);
  }

  /**
   * Serialize the entry to internal database format.
   * @returns {Buffer}
   */

  toRaw() {
    const bw = bio.write(116);

    bw.writeU32(this.version);
    bw.writeHash(this.prevBlock);
    bw.writeHash(this.merkleRoot);
    bw.writeU32(this.time);
    bw.writeU32(this.bits);
    bw.writeU32(this.nonce);
    bw.writeU32(this.height);
    bw.writeBytes(this.chainwork.toArrayLike(Buffer, 'le', 32));

    return bw.render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data, true);
    const hash = hash256.digest(br.readBytes(80));

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
  }

  /**
   * Deserialize the entry.
   * @param {Buffer} data
   * @returns {ChainEntry}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Serialize the entry to an object more
   * suitable for JSON serialization.
   * @returns {Object}
   */

  toJSON() {
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
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    assert(json, 'Block data is required.');
    assert(typeof json.hash === 'string');
    assert((json.version >>> 0) === json.version);
    assert(typeof json.prevBlock === 'string');
    assert(typeof json.merkleRoot === 'string');
    assert((json.time >>> 0) === json.time);
    assert((json.bits >>> 0) === json.bits);
    assert((json.nonce >>> 0) === json.nonce);
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
  }

  /**
   * Instantiate block from jsonified object.
   * @param {Object} json
   * @returns {ChainEntry}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Convert the entry to a headers object.
   * @returns {Headers}
   */

  toHeaders() {
    return Headers.fromEntry(this);
  }

  /**
   * Convert the entry to an inv item.
   * @returns {InvItem}
   */

  toInv() {
    return new InvItem(InvItem.types.BLOCK, this.hash);
  }

  /**
   * Return a more user-friendly object.
   * @returns {Object}
   */

  inspect() {
    const json = this.toJSON();
    json.version = json.version.toString(16);
    return json;
  }

  /**
   * Test whether an object is a {@link ChainEntry}.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isChainEntry(obj) {
    return obj instanceof ChainEntry;
  }
}

/**
 * The max chainwork (1 << 256).
 * @const {BN}
 */

ChainEntry.MAX_CHAINWORK = new BN(1).ushln(256);

/*
 * Expose
 */

module.exports = ChainEntry;
