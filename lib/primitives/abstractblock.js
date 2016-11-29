/*!
 * abstractblock.js - abstract block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var constants = require('../protocol/constants');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var btcutils = require('../btc/utils');
var VerifyResult = require('../btc/errors').VerifyResult;
var BufferWriter = require('../utils/writer');
var InvItem = require('./invitem');

/**
 * The class which all block-like objects inherit from.
 * @exports AbstractBlock
 * @constructor
 * @abstract
 * @param {NakedBlock} options
 * @property {Number} version - Block version. Note
 * that BCoin reads versions as unsigned despite
 * them being signed on the protocol level. This
 * number will never be negative.
 * @property {Hash} prevBlock - Previous block hash.
 * @property {Hash} merkleRoot - Merkle root hash.
 * @property {Number} ts - Timestamp.
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} totalTX - Transaction count.
 * @property {Number} height - Block height (-1 if not present).
 * @property {TX[]} txs - Transaction vector.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function AbstractBlock(options) {
  if (!(this instanceof AbstractBlock))
    return new AbstractBlock(options);

  this.version = 1;
  this.prevBlock = constants.NULL_HASH;
  this.merkleRoot = constants.NULL_HASH;
  this.ts = 0;
  this.bits = 0;
  this.nonce = 0;
  this.totalTX = 0;
  this.height = -1;

  this.txs = null;
  this.mutable = false;

  this._valid = null;
  this._hash = null;
  this._hhash = null;
  this._size = null;
  this._witnessSize = null;

  if (options)
    this.parseOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {NakedBlock} options
 */

AbstractBlock.prototype.parseOptions = function parseOptions(options) {
  assert(options, 'Block data is required.');
  assert(util.isNumber(options.version));
  assert(typeof options.prevBlock === 'string');
  assert(typeof options.merkleRoot === 'string');
  assert(util.isNumber(options.ts));
  assert(util.isNumber(options.bits));
  assert(util.isNumber(options.nonce));

  this.version = options.version;
  this.prevBlock = options.prevBlock;
  this.merkleRoot = options.merkleRoot;
  this.ts = options.ts;
  this.bits = options.bits;
  this.nonce = options.nonce;

  if (options.totalTX != null) {
    assert(util.isNumber(options.totalTX));
    this.totalTX = options.totalTX;
  }

  if (options.height != null) {
    assert(util.isNumber(options.height));
    this.height = options.height;
  }

  if (options.mutable != null)
    this.mutable = !!options.mutable;

  return this;
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

AbstractBlock.prototype.parseJSON = function parseJSON(json) {
  assert(json, 'Block data is required.');
  assert(util.isNumber(json.version));
  assert(typeof json.prevBlock === 'string');
  assert(typeof json.merkleRoot === 'string');
  assert(util.isNumber(json.ts));
  assert(util.isNumber(json.bits));
  assert(util.isNumber(json.nonce));
  assert(util.isNumber(json.totalTX));
  assert(util.isNumber(json.height));

  this.version = json.version;
  this.prevBlock = util.revHex(json.prevBlock);
  this.merkleRoot = util.revHex(json.merkleRoot);
  this.ts = json.ts;
  this.bits = json.bits;
  this.nonce = json.nonce;
  this.totalTX = json.totalTX;
  this.height = json.height;

  return this;
};

/**
 * Hash the block headers.
 * @param {String?} enc - Can be `'hex'` or `null`.
 * @returns {Hash|Buffer} hash
 */

AbstractBlock.prototype.hash = function hash(enc) {
  var hash = this._hash;
  var hex;

  if (!hash) {
    hash = crypto.hash256(this.abbr());
    if (!this.mutable)
      this._hash = hash;
  }

  if (enc === 'hex') {
    hex = this._hhash;
    if (!hex) {
      hex = hash.toString('hex');
      if (!this.mutable)
        this._hhash = hex;
    }
    hash = hex;
  }

  return hash;
};

/**
 * Serialize the block headers.
 * @returns {Buffer}
 */

AbstractBlock.prototype.abbr = function abbr(writer) {
  var bw = BufferWriter(writer);

  bw.writeU32(this.version);
  bw.writeHash(this.prevBlock);
  bw.writeHash(this.merkleRoot);
  bw.writeU32(this.ts);
  bw.writeU32(this.bits);
  bw.writeU32(this.nonce);

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Verify the block.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verify = function verify(now, ret) {
  var valid = this._valid;

  if (valid == null) {
    valid = this._verify(now, ret);
    if (!this.mutable)
      this._valid = valid;
  }

  return valid;
};

/**
 * Verify the block headers (called by `verify()` in
 * all objects which inherit from AbstractBlock).
 * @param {Number|null} - Adjusted time.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verifyHeaders = function verifyHeaders(now, ret) {
  if (!now)
    now = util.now();

  if (!ret)
    ret = new VerifyResult();

  // Check proof of work.
  if (!this.verifyPOW()) {
    ret.reason = 'high-hash';
    ret.score = 50;
    return false;
  }

  // Check timestamp against adjusted-time + 2 hours.
  if (this.ts > now + 2 * 60 * 60) {
    ret.reason = 'time-too-new';
    ret.score = 0;
    return false;
  }

  return true;
};

/**
 * Verify proof-of-work.
 * @returns {Boolean}
 */

AbstractBlock.prototype.verifyPOW = function verifyPOW() {
  return btcutils.verifyPOW(this.hash(), this.bits);
};

/**
 * Set the `height` property and the `height`
 * property of all transactions within the block.
 * @param {Number} height
 */

AbstractBlock.prototype.setHeight = function setHeight(height) {
  var i;

  this.height = height;

  if (!this.txs)
    return;

  for (i = 0; i < this.txs.length; i++)
    this.txs[i].height = height;
};

AbstractBlock.prototype.__defineGetter__('rhash', function() {
  return util.revHex(this.hash('hex'));
});

/**
 * Convert the block to an inv item.
 * @returns {InvItem}
 */

AbstractBlock.prototype.toInv = function toInv() {
  return new InvItem(constants.inv.BLOCK, this.hash('hex'));
};

/*
 * Expose
 */

module.exports = AbstractBlock;
