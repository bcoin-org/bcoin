/**
 * abstractblock.js - abstract block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * AbstractBlock
 */

function AbstractBlock(data) {
  var self = this;

  if (!(this instanceof AbstractBlock))
    return new AbstractBlock(data);

  this.type = 'block';
  this.subtype = null;
  this.version = data.version;
  this.prevBlock = utils.toHex(data.prevBlock);
  this.merkleRoot = utils.toHex(data.merkleRoot);
  this.ts = data.ts;
  this.bits = data.bits;
  this.nonce = data.nonce;
  this.totalTX = data.totalTX;
  this.height = data.height != null ? data.height : -1;

  this._raw = data._raw || null;
  this._size = data._size || 0;

  this.relayedBy = data.relayedBy || '0.0.0.0';

  this._chain = data.chain;

  this.valid = null;
  this._hash = null;

  // https://gist.github.com/sipa/bf69659f43e763540550
  // http://lists.linuxfoundation.org/pipermail/bitcoin-dev/2015-August/010396.html
  this.versionBits = (this.version >>> 29) & 7;
  this.realVersion = this.version & 0x1fffffff;
  this.highVersion = this.version & 0x1ffffff8;
  this.lowVersion = this.version & 7;
}

AbstractBlock.prototype.hash = function hash(enc) {
  if (!this._hash)
    this._hash = utils.dsha256(this.abbr());

  return enc === 'hex' ? utils.toHex(this._hash) : this._hash;
};

AbstractBlock.prototype.abbr = function abbr() {
  var res;

  if (this._raw)
    return this._raw.slice(0, 80);

  res = new Buffer(80);
  utils.write32(res, this.version, 0);
  utils.copy(new Buffer(this.prevBlock, 'hex'), res, 4);
  utils.copy(new Buffer(this.merkleRoot, 'hex'), res, 36);
  utils.writeU32(res, this.ts, 68);
  utils.writeU32(res, this.bits, 72);
  utils.writeU32(res, this.nonce, 76);

  return res;
};

AbstractBlock.prototype.getSize = function getSize() {
  return this._size || this.render().length;
};

AbstractBlock.prototype.verify = function verify() {
  if (this.valid == null)
    this.valid = this._verify();
  return this.valid;
};

AbstractBlock.prototype.verifyHeaders = function verifyHeaders() {
  // Check proof of work
  if (!utils.testTarget(this.bits, this.hash())) {
    utils.debug('Block failed POW test: %s', this.rhash);
    return false;
  }

  // Check timestamp against now + 2 hours
  if (this.ts > utils.now() + 2 * 60 * 60) {
    utils.debug('Block timestamp is too high: %s', this.rhash);
    return false;
  }

  return true;
};

AbstractBlock.prototype.isGenesis = function isGenesis() {
  return this.hash('hex') === network.genesis.hash;
};

AbstractBlock.prototype.__defineGetter__('chain', function() {
  return this._chain || bcoin.chain.global;
});

AbstractBlock.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

/**
 * Expose
 */

module.exports = AbstractBlock;
