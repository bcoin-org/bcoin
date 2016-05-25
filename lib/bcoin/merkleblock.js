/*!
 * merkleblock.js - merkleblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;

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
 * @property {Hash[]} matches - List of matched tx hashes.
 * @property {Object} map - Map of matched tx hashes.
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function MerkleBlock(data) {
  if (!(this instanceof MerkleBlock))
    return new MerkleBlock(data);

  bcoin.abstractblock.call(this, data);

  assert(Array.isArray(data.hashes));
  assert(Buffer.isBuffer(data.flags));

  this.hashes = data.hashes;
  this.flags = data.flags;

  // List of matched TXs
  this.map = {};
  this.matches = [];
  this._validPartial = null;

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
 * Add a transaction to the block's tx vector.
 * @param {TX|NakedTX} tx
 * @returns {TX}
 */

MerkleBlock.prototype.addTX = function addTX(tx) {
  var index, hash;

  if (!(tx instanceof bcoin.tx))
    tx = new bcoin.tx(tx);

  hash = tx.hash('hex');
  index = this.map[hash];

  this.txs.push(tx);

  tx.setBlock(this, index);

  return tx;
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

  return this.map[hash] != null;
};

/**
 * Verify the partial merkletree. Push leaves onto
 * {@link MerkleBlock#tx} and into {@link MerkleBlock#map}.
 * @private
 * @returns {Boolean}
 */

MerkleBlock.prototype.verifyPartial = function verifyPartial() {
  var tree;

  if (this._validPartial != null)
    return this._validPartial;

  tree = this.extractTree();

  if (!tree || tree.root !== this.merkleRoot) {
    this._validPartial = false;
    return false;
  }

  this.matches = tree.matches;
  this.map = tree.map;
  this._validPartial = true;

  return true;
};

/**
 * Extract the matches from partial merkle
 * tree and calculate merkle root.
 * @private
 * @returns {Object}
 */

MerkleBlock.prototype.extractTree = function extractTree() {
  var bitsUsed = 0;
  var hashUsed = 0;
  var matches = [];
  var indexes = [];
  var map = {};
  var failed = false;
  var hashes = new Array(this.hashes.length);
  var bits = new Array(this.flags.length * 8);
  var totalTX = this.totalTX;
  var height = 0;
  var root, p;

  function width(height) {
    return (totalTX + (1 << height) - 1) >>> height;
  }

  function traverse(height, pos) {
    var parent, hash, left, right, txid;

    if (bitsUsed >= bits.length) {
      failed = true;
      return constants.ZERO_HASH;
    }

    parent = bits[bitsUsed++];

    if (height === 0 || !parent) {
      if (hashUsed >= hashes.length) {
        failed = true;
        return constants.ZERO_HASH;
      }
      hash = hashes[hashUsed++];
      if (height === 0 && parent) {
        txid = hash.toString('hex');
        matches.push(txid);
        indexes.push(pos);
        map[txid] = pos;
      }
      return hash;
    }

    left = traverse(height - 1, pos * 2);
    if (pos * 2 + 1 < width(height - 1)) {
      right = traverse(height - 1, pos * 2 + 1);
      if (utils.equal(right, left))
        failed = true;
    } else {
      right = left;
    }

    return utils.dsha256(Buffer.concat([left, right]));
  }

  for (p = 0; p < hashes.length; p++)
    hashes[p] = new Buffer(this.hashes[p], 'hex');

  for (p = 0; p < bits.length; p++)
    bits[p] = +((this.flags[p / 8 | 0] & (1 << (p % 8))) !== 0);

  if (totalTX === 0)
    return;

  if (totalTX > constants.block.MAX_SIZE / 60)
    return;

  if (hashes.length > totalTX)
    return;

  if (bits.length < hashes.length)
    return;

  height = 0;
  while (width(height) > 1)
    height++;

  root = traverse(height, 0);

  if (failed)
    return;

  if (((bitsUsed + 7) / 8 | 0) !== ((bits.length + 7) / 8 | 0))
    return;

  if (hashUsed !== hashes.length)
    return;

  return {
    root: root.toString('hex'),
    matches: matches,
    indexes: indexes,
    map: map
  };
};

/**
 * Do non-contextual verification on the block.
 * Verify the headers and the partial merkle tree.
 * @alias MerkleBlock#verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

MerkleBlock.prototype._verify = function _verify(ret) {
  if (!ret)
    ret = {};

  if (!this.verifyHeaders(ret))
    return false;

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
  return {
    type: 'merkleblock',
    hash: this.rhash,
    height: this.height,
    date: utils.date(this.ts),
    version: this.version,
    prevBlock: utils.revHex(this.prevBlock),
    merkleRoot: utils.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    totalTX: this.totalTX,
    hashes: this.hashes,
    flags: this.flags,
    map: this.map
  };
};

/**
 * Serialize the merkleblock.
 * @see {MerkleBlock#render}
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

MerkleBlock.prototype.toRaw = function toRaw(enc) {
  var data = this.render();

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
    return (totalTX + (1 << height) - 1) >>> height;
  }

  function hash(height, pos, leaves) {
    var left, right;

    if (height === 0)
      return leaves[pos];

    left = hash(height - 1, pos * 2, leaves);

    if (pos * 2 + 1 < width(height - 1))
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
      hashes.push(hash(height, pos, leaves).toString('hex'));
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
  flags.fill(0);

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
 * Test whether an object is a MerkleBlock.
 * @param {Object} obj
 * @returns {Boolean}
 */

MerkleBlock.isMerkleBlock = function isMerkleBlock(obj) {
  return obj
    && Buffer.isBuffer(obj.flags)
    && typeof obj.verifyPartial === 'function';
};

/*
 * Expose
 */

module.exports = MerkleBlock;
