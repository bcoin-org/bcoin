/*!
 * merkleblock.js - merkleblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');

/**
 * Represents a merkle (filtered) block.
 * @exports MerkleBlock
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} data
 * @property {String} type - "merkleblock" (getdata type).
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
 * @property {Number} height - Block height (-1 if not in the chain).
 * @property {Buffer[]} hashes
 * @property {Buffer} flags
 * @property {TX[]} txs - Transaction vector.
 * @property {Hash[]} tx - List of matched tx hashes.
 * @property {Object} txMap - Map of matched tx hashes.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function MerkleBlock(data) {
  if (!(this instanceof MerkleBlock))
    return new MerkleBlock(data);

  bcoin.abstractblock.call(this, data);

  this.hashes = (data.hashes || []).map(function(hash) {
    if (typeof hash === 'string')
      hash = new Buffer(hash, 'hex');
    return hash;
  });

  this.flags = data.flags || [];

  // List of matched TXs
  this.txMap = {};
  this.tx = [];
  this._partialVerified = null;

  // TXs that will be pushed on
  this.txs = [];
}

utils.inherits(MerkleBlock, bcoin.abstractblock);

/**
 * Serialize the merkleblock.
 * @returns {Buffer}
 */

MerkleBlock.prototype.render = function render() {
  return this.getRaw();
};

/**
 * Serialize the merkleblock.
 * @returns {Buffer}
 */

MerkleBlock.prototype.renderNormal = function renderNormal() {
  return this.getRaw();
};

/**
 * Serialize the merkleblock.
 * @returns {Buffer}
 */

MerkleBlock.prototype.renderWitness = function renderWitness() {
  return this.getRaw();
};

/**
 * Get merkleblock size.
 * @returns {Number} Size.
 */

MerkleBlock.prototype.getSize = function getSize() {
  if (this._size == null)
    this.getRaw();
  return this._size;
};

/**
 * Get the raw merkleblock serialization.
 * @returns {Buffer}
 */

MerkleBlock.prototype.getRaw = function getRaw() {
  if (!this._raw) {
    this._raw = bcoin.protocol.framer.merkleBlock(this);
    this._size = this._raw.length;
  }
  return this._raw;
};

/**
 * Test the block's _matched_ transaction vector against a hash.
 * @param {Hash|TX} hash
 * @returns {Boolean}
 */

MerkleBlock.prototype.hasTX = function hasTX(hash) {
  if (hash instanceof bcoin.tx)
    hash = hash.hash('hex');

  this.verifyPartial();

  return this.txMap[hash] === true;
};

/**
 * Verify the partial merkletree. Push leaves onto
 * {@link MerkleBlock#tx} and into {@link MerkleBlock#txMap}.
 * @private
 * @returns {Boolean}
 */

MerkleBlock.prototype.verifyPartial = function verifyPartial() {
  var height = 0;
  var tx = [];
  var txMap = {};
  var j = 0;
  var hashes = this.hashes;
  var flags = this.flags;
  var i, root;

  if (this._partialVerified != null)
    return this._partialVerified;

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
        tx.push(hashes[j].toString('hex'));
        txMap[tx[tx.length - 1]] = true;
      }
      return hashes[j++];
    }

    // Go deeper
    left = visit(depth + 1);
    if (!left)
      return null;

    right = visit(depth + 1);
    if (right && utils.equal(right, left))
      return null;

    if (!right)
      right = left;

    return utils.dsha256(Buffer.concat([left, right]));
  }

  root = visit(1);

  if (!root || root.toString('hex') !== this.merkleRoot) {
    this._partialVerified = false;
    return false;
  }

  this.tx = tx;
  this.txMap = txMap;
  this._partialVerified = true;

  return true;
};

/**
 * Do non-contextual verification on the block.
 * Verify the headers and the partial merkle tree.
 * @alias verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

MerkleBlock.prototype._verify = function _verify(ret) {
  if (!ret)
    ret = {};

  if (!this.verifyHeaders(ret))
    return false;

  // Verify the partial merkle tree if we are a merkleblock.
  if (!this.verifyPartial()) {
    ret.reason = 'bad-txnmrklroot';
    ret.score = 100;
    return false;
  }

  return true;
};

/**
 * Extract the coinbase height (always -1).
 * @returns {Number}
 */

MerkleBlock.prototype.getCoinbaseHeight = function getCoinbaseHeight() {
  return -1;
};

/**
 * Inspect the block and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

MerkleBlock.prototype.inspect = function inspect() {
  var copy = bcoin.merkleblock(this);
  copy.__proto__ = null;
  delete copy._raw;
  delete copy._chain;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.date = utils.date(copy.ts);
  return copy;
};

/**
 * Serialize the merkleblock.
 * @see {MerkleBlock#render}
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

MerkleBlock.prototype.toRaw = function toRaw(enc) {
  var data;

  data = this.render();

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse a serialized merkleblock.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedBlock} A "naked" headers object.
 */

MerkleBlock.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseMerkleBlock(data);
};

/**
 * Instantiate a merkleblock from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Headers}
 */

MerkleBlock.fromRaw = function fromRaw(data, enc) {
  return new MerkleBlock(MerkleBlock.parseRaw(data, enc));
};

/**
 * Create a merkleblock from a {@link Block} object, passing
 * it through a filter first. This will build the partial
 * merkle tree.
 * @param {Block} block
 * @param {Bloom} bloom
 * @returns {MerkleBlock}
 */

MerkleBlock.fromBlock = function fromBlock(block, bloom) {
  var matches = [];
  var txs = [];
  var leaves = [];
  var bits = [];
  var hashes = [];
  var i, tx, totalTX, height, flags, p;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    if (tx.isWatched(bloom)) {
      matches.push(1);
      txs.push(tx);
    } else {
      matches.push(0);
    }
    leaves.push(tx.hash());
  }

  totalTX = leaves.length;

  function width(height) {
    return (totalTX + (1 << height) - 1) >> height;
  }

  function hash(height, pos, leaves) {
    var left, right;

    if (height === 0)
      return leaves[0];

    left = hash(height - 1, pos * 2, leaves);

    if (pos * 2 + 1 < width(height - 1, pos * 2 + 1, leaves))
      right = hash(height - 1, pos * 2 + 1, leaves);
    else
      right = left;

    return utils.dsha256(Buffer.concat([left, right]));
  }

  function traverse(height, pos, leaves, matches) {
    var parent = 0;
    var p;

    for (p = (pos << height); p < ((pos + 1) << height) && p < totalTX; p++)
      parent |= matches[p];

    bits.push(parent);

    if (height === 0 || !parent) {
      hashes.push(hash(height, pos, leaves));
      return;
    }

    traverse(height - 1, pos * 2, leaves, matches);

    if (pos * 2 + 1 < width(height - 1))
      traverse(height - 1, pos * 2 + 1, leaves, matches);
  }

  height = 0;
  while (width(height) > 1)
    height++;

  traverse(height, 0, leaves, matches);

  flags = new Buffer((bits.length + 7) / 8 | 0);
  for (p = 0; p < bits.length; p++)
    flags[p / 8 | 0] |= bits[p] << (p % 8);

  block = new MerkleBlock({
    version: block.version,
    prevBlock: block.prevBlock,
    merkleRoot: block.merkleRoot,
    ts: block.ts,
    bits: block.bits,
    nonce: block.nonce,
    totalTX: totalTX,
    height: block.height,
    hashes: hashes,
    flags: flags
  });

  block.txs = txs;

  return block;
};

/**
 * Test an object to see if it is a MerkleBlock object.
 * @param {Object} obj
 * @returns {Boolean}
 */

MerkleBlock.isMerkleBlock = function isMerkleBlock(obj) {
  return obj
    && Array.isArray(obj.flags)
    && typeof obj.verifyPartial === 'function';
};

module.exports = MerkleBlock;
