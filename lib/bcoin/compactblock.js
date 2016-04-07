/**
 * compactblock.js - compact block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var bn = require('bn.js');
var utils = require('./utils');
var assert = utils.assert;

/**
 * CompactBlock
 */

function CompactBlock(data) {
  if (!(this instanceof CompactBlock))
    return new CompactBlock(data);

  bcoin.abstractblock.call(this, data);

  this.type = 'compactblock';
  this.coinbaseHeight = -1;

  if (this.version >= 2) {
    if (Buffer.isBuffer(data.coinbaseHeight) && data.coinbaseHeight.length <= 6)
      this.coinbaseHeight = new bn(data.coinbaseHeight, 'le').toNumber();
  }
}

utils.inherits(CompactBlock, bcoin.abstractblock);

CompactBlock.prototype._verify = function _verify(ret) {
  return this.verifyHeaders(ret);
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

CompactBlock.isCompactBlock = function isCompactBlock(block) {
  return block
    && block.type === 'compactblock'
    && typeof block.toBlock === 'function';
};

/**
 * Expose
 */

return CompactBlock;
};
