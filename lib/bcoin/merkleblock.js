/**
 * merkleblock.js - merkleblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');

/**
 * MerkleBlock
 */

function MerkleBlock(data) {
  if (!(this instanceof MerkleBlock))
    return new MerkleBlock(data);

  bcoin.abstractblock.call(this, data);

  this.type = 'merkleblock';

  this.hashes = (data.hashes || []).map(function(hash) {
    return utils.toBuffer(hash, 'hex');
  });

  this.flags = data.flags || [];

  // List of matched TXs
  this.txMap = {};
  this.tx = [];

  // TXs that will be pushed on
  this.txs = [];
}

utils.inherits(MerkleBlock, bcoin.abstractblock);

MerkleBlock.prototype.render = function render() {
  return this.getRaw();
};

MerkleBlock.prototype.renderNormal = function renderNormal() {
  return this.getRaw();
};

MerkleBlock.prototype.renderWitness = function renderWitness() {
  return this.getRaw();
};

MerkleBlock.prototype.getSize = function getSize() {
  if (this._size == null)
    this.getRaw();
  return this._size;
};

MerkleBlock.prototype.getRaw = function getRaw() {
  if (!this._raw) {
    this._raw = bcoin.protocol.framer.merkleBlock(this);
    this._size = this._raw.length;
  }
  return this._raw;
};

MerkleBlock.prototype.hasTX = function hasTX(hash) {
  return this.txMap[hash] === true;
};

MerkleBlock.prototype._verifyPartial = function _verifyPartial() {
  var height = 0;
  var tx = [];
  var txMap = {};
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
      if (depth === height) {
        tx.push(utils.toHex(hashes[j]));
        txMap[tx[tx.length - 1]] = true;
      }
      return hashes[j++];
    }

    // Go deeper
    left = visit(depth + 1);
    if (!left)
      return null;

    right = visit(depth + 1);
    if (right && utils.isEqual(right, left))
      return null;

    if (!right)
      right = left;

    return utils.dsha256(Buffer.concat([left, right]));
  }

  root = utils.toHex(visit(1));

  if (!root || root !== this.merkleRoot)
    return false;

  this.tx = tx;
  this.txMap = txMap;

  return true;
};

MerkleBlock.prototype._verify = function _verify(ret) {
  if (!ret)
    ret = {};

  if (!this.verifyHeaders(ret))
    return false;

  // Verify the partial merkle tree if we are a merkleblock.
  if (!this._verifyPartial()) {
    ret.reason = 'bad-txnmrklroot';
    ret.score = 100;
    return false;
  }

  return true;
};

MerkleBlock.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  return -1;
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

MerkleBlock.isMerkleBlock = function isMerkleBlock(obj) {
  return obj
    && Array.isArray(obj.flags)
    && typeof obj._verifyPartial === 'function';
};

/**
 * Expose
 */

module.exports = MerkleBlock;
