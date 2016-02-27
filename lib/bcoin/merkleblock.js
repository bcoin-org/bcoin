/**
 * merkleblock.js - merkleblock object for bcoin
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
 * MerkleBlock
 */

function MerkleBlock(data) {
  if (!(this instanceof MerkleBlock))
    return new MerkleBlock(data);

  bcoin.abstractblock.call(this, data);

  this.type = 'merkleblock'

  this.hashes = (data.hashes || []).map(function(hash) {
    return utils.toHex(hash);
  });

  this.flags = data.flags || [];

  // List of matched TXs
  this.tx = [];

  // TXs that will be pushed on
  this.txs = [];
}

utils.inherits(MerkleBlock, bcoin.abstractblock);

MerkleBlock.prototype.render = function render() {
  if (this._raw)
    return this._raw;
  return bcoin.protocol.framer.merkleBlock(this);
};

MerkleBlock.prototype.hasTX = function hasTX(hash) {
  return this.tx.indexOf(hash) !== -1;
};

MerkleBlock.prototype._verifyPartial = function _verifyPartial() {
  var height = 0;
  var tx = [];
  var i = 0;
  var j = 0;
  var hashes = this.hashes;
  var flags = this.flags;
  var i, root;

  // Count leaves
  for (i = this.totalTX; i > 0; i >>= 1)
    height++;

  if (this.totalTX > (1 << (height - 1)))
    height++;

  function visit(depth) {
    var flag, left, right;

    if (i === flags.length * 8 || j === hashes.length)
      return null;

    flag = (flags[i >> 3] >>> (i & 7)) & 1;
    i++;

    if (flag === 0 || depth === height) {
      if (depth === height)
        tx.push(hashes[j]);
      return hashes[j++];
    }

    // Go deeper
    left = visit(depth + 1);
    if (!left)
      return null;

    right = visit(depth + 1);
    if (right === left)
      return null;

    if (!right)
      right = left;

    return utils.toHex(utils.dsha256(left + right, 'hex'));
  }

  root = visit(1);

  if (!root || root !== this.merkleRoot)
    return false;

  this.tx = tx;

  return true;
};

MerkleBlock.prototype._verify = function _verify() {
  if (!this.verifyHeaders())
    return false;

  // Verify the partial merkle tree if we are a merkleblock.
  if (!this._verifyPartial()) {
    utils.debug('Block failed merkle test: %s', this.rhash);
    return false;
  }

  return true;
};

MerkleBlock.prototype.inspect = function inspect() {
  var copy = bcoin.merkleblock(this);
  copy.__proto__ = null;
  delete copy._raw;
  delete copy._chain;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.date = new Date((copy.ts || 0) * 1000).toISOString();
  return copy;
};

MerkleBlock.prototype.toRaw = function toRaw(enc) {
  var data;

  data = this.render();

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

MerkleBlock._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseMerkleBlock(data);
};

MerkleBlock.fromRaw = function fromRaw(data, enc) {
  return new MerkleBlock(MerkleBlock._fromRaw(data, enc));
};

/**
 * Expose
 */

module.exports = MerkleBlock;
