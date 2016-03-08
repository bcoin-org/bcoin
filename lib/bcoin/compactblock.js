/**
 * compactblock.js - compact block object for bcoin
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
 * CompactBlock
 */

function CompactBlock(data) {
  var self = this;

  if (!(this instanceof CompactBlock))
    return new CompactBlock(data);

  bcoin.abstractblock.call(this, data);

  this.type = 'compactblock';
  this.coinbaseHeight = data.coinbaseHeight;
}

utils.inherits(CompactBlock, bcoin.abstractblock);

CompactBlock.prototype._verify = function _verify() {
  return this.verifyHeaders();
};

CompactBlock.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  return this.coinbaseHeight;
};

CompactBlock.prototype.toBlock = function toBlock() {
  var block = bcoin.protocol.parser.parseBlock(this._raw);
  delete this._raw;
  assert(!block._raw);
  block = new bcoin.block(block);
  if (this.valid != null)
    block.valid = this.valid;
  return block;
};

/**
 * Expose
 */

module.exports = CompactBlock;
