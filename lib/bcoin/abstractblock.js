/**
 * abstractblock.js - abstract block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');
var network = bcoin.protocol.network;
var BufferWriter = require('./writer');

/**
 * AbstractBlock
 */

function AbstractBlock(data) {
  if (!(this instanceof AbstractBlock))
    return new AbstractBlock(data);

  this.type = null;
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

  this.valid = null;
  this._hash = null;
}

AbstractBlock.prototype.hash = function hash(enc) {
  if (!this._hash)
    this._hash = utils.dsha256(this.abbr());

  return enc === 'hex' ? utils.toHex(this._hash) : this._hash;
};

AbstractBlock.prototype.abbr = function abbr() {
  var p;

  if (this._raw)
    return this._raw.slice(0, 80);

  p = new BufferWriter();

  p.write32(this.version);
  p.writeHash(this.prevBlock);
  p.writeHash(this.merkleRoot);
  p.writeU32(this.ts);
  p.writeU32(this.bits);
  p.writeU32(this.nonce);

  return p.render();
};

AbstractBlock.prototype.getSize = function getSize() {
  return this._size || this.render().length;
};

AbstractBlock.prototype.verify = function verify(ret) {
  if (this.valid == null)
    this.valid = this._verify(ret);
  return this.valid;
};

AbstractBlock.prototype.verifyHeaders = function verifyHeaders(ret) {
  if (!ret)
    ret = {};

  // Check proof of work
  if (!utils.testTarget(this.bits, this.hash())) {
    ret.reason = 'high-hash';
    ret.score = 50;
    return false;
  }

  // Check timestamp against now + 2 hours
  if (this.ts > utils.now() + 2 * 60 * 60) {
    ret.reason = 'time-too-new';
    ret.score = 0;
    return false;
  }

  return true;
};

AbstractBlock.prototype.isGenesis = function isGenesis() {
  return this.hash('hex') === network.genesis.hash;
};

AbstractBlock.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

/**
 * Expose
 */

module.exports = AbstractBlock;
