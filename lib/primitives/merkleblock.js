/*!
 * merkleblock.js - merkleblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var AbstractBlock = require('./abstractblock');
var VerifyResult = require('../protocol/errors').VerifyResult;
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');
var encoding = require('../utils/encoding');
var consensus = require('../protocol/consensus');
var Headers = require('./headers');
var DUMMY = new Buffer([0]);

/**
 * Represents a merkle (filtered) block.
 * @alias module:primitives.MerkleBlock
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} options
 */

function MerkleBlock(options) {
  if (!(this instanceof MerkleBlock))
    return new MerkleBlock(options);

  AbstractBlock.call(this);

  this.hashes = [];
  this.flags = DUMMY;

  this.totalTX = 0;
  this.tree = null;
  this.txs = [];

  if (options)
    this.fromOptions(options);
}

util.inherits(MerkleBlock, AbstractBlock);

/**
 * Inject properties from options object.
 * @private
 * @param {NakedBlock} options
 */

MerkleBlock.prototype.fromOptions = function fromOptions(options) {
  var i, hash;

  this.parseOptions(options);

  assert(options, 'MerkleBlock data is required.');
  assert(Array.isArray(options.hashes));
  assert(Buffer.isBuffer(options.flags));
  assert(util.isUInt32(options.totalTX));

  if (options.hashes) {
    for (i = 0; i < options.hashes.length; i++) {
      hash = options.hashes[i];
      if (typeof hash === 'string')
        hash = new Buffer(hash, 'hex');
      this.hashes.push(hash);
    }
  }

  if (options.flags)
    this.flags = options.flags;

  if (options.totalTX != null)
    this.totalTX = options.totalTX;

  return this;
};

/**
 * Instantiate merkle block from options object.
 * @param {NakedBlock} options
 * @returns {MerkleBlock}
 */

MerkleBlock.fromOptions = function fromOptions(data) {
  return new MerkleBlock().fromOptions(data);
};

/**
 * Clear any cached values.
 * @param {Boolean?} all - Clear transactions.
 */

MerkleBlock.prototype.refresh = function refresh(all) {
  this.tree = null;
  this._refresh(all);
};

/**
 * Add a transaction to the block's tx vector.
 * @param {TX} tx
 * @returns {Number}
 */

MerkleBlock.prototype.addTX = function addTX(tx) {
  var tree = this.getTree();
  var hash = tx.hash('hex');
  var index = tree.map[hash];

  this.txs.push(tx);

  return index != null ? index : -1;
};

/**
 * Test the block's _matched_ transaction vector against a hash.
 * @param {Hash} hash
 * @returns {Boolean}
 */

MerkleBlock.prototype.hasTX = function hasTX(hash) {
  return this.indexOf(hash) !== -1;
};

/**
 * Test the block's _matched_ transaction vector against a hash.
 * @param {Hash} hash
 * @returns {Number} Index.
 */

MerkleBlock.prototype.indexOf = function indexOf(hash) {
  var tree = this.getTree();
  var index = tree.map[hash];

  if (index == null)
    return -1;

  return index;
};

/**
 * Do non-contextual verification on the block.
 * Verify the headers and the partial merkle tree.
 * @alias MerkleBlock#verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

MerkleBlock.prototype.verify = function verify(ret) {
  if (!this.verifyPOW())
    return false;

  if (!this.verifyBody())
    return false;

  return true;
};

/**
 * Verify the partial merkletree. Push leaves onto
 * {@link MerkleBlock#tx} and into {@link MerkleBlock#map}.
 * @private
 * @returns {Boolean}
 */

MerkleBlock.prototype.verifyBody = function verifyBody(ret) {
  var tree = this.getTree();

  if (!ret)
    ret = new VerifyResult();

  if (tree.root !== this.merkleRoot) {
    ret.reason = 'bad-txnmrklroot';
    ret.score = 100;
    return false;
  }

  return true;
};

/**
 * Extract the matches from partial merkle
 * tree and calculate merkle root.
 * @returns {Object}
 */

MerkleBlock.prototype.getTree = function getTree() {
  if (!this.tree) {
    try {
      this.tree = this.extractTree();
    } catch (e) {
      this.tree = new PartialTree();
    }
  }
  return this.tree;
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
  var hashes = this.hashes;
  var flags = this.flags;
  var totalTX = this.totalTX;
  var height = 0;
  var root, buf;

  function width(height) {
    return (totalTX + (1 << height) - 1) >>> height;
  }

  function traverse(height, pos) {
    var parent, hash, left, right, txid;

    if (bitsUsed >= flags.length * 8) {
      failed = true;
      return encoding.ZERO_HASH;
    }

    parent = (flags[bitsUsed / 8 | 0] >>> (bitsUsed % 8)) & 1;
    bitsUsed++;

    if (height === 0 || !parent) {
      if (hashUsed >= hashes.length) {
        failed = true;
        return encoding.ZERO_HASH;
      }
      hash = hashes[hashUsed++];
      if (height === 0 && parent) {
        txid = hash.toString('hex');
        matches.push(hash);
        indexes.push(pos);
        map[txid] = pos;
      }
      return hash;
    }

    left = traverse(height - 1, pos * 2);
    if (pos * 2 + 1 < width(height - 1)) {
      right = traverse(height - 1, pos * 2 + 1);
      if (util.equal(right, left))
        failed = true;
    } else {
      right = left;
    }

    left.copy(buf, 0);
    right.copy(buf, 32);

    return crypto.hash256(buf);
  }

  if (totalTX === 0)
    throw new Error('Zero transactions.');

  if (totalTX > consensus.MAX_BLOCK_SIZE / 60)
    throw new Error('Too many transactions.');

  if (hashes.length > totalTX)
    throw new Error('Too many hashes.');

  if (flags.length * 8 < hashes.length)
    throw new Error('Flags too small.');

  while (width(height) > 1)
    height++;

  if (height > 0)
    buf = new Buffer(64);

  root = traverse(height, 0);

  if (failed)
    throw new Error('Mutated merkle tree.');

  if (((bitsUsed + 7) / 8 | 0) !== flags.length)
    throw new Error('Too many flag bits.');

  if (hashUsed !== hashes.length)
    throw new Error('Incorrect number of hashes.');

  return new PartialTree(root, matches, indexes, map);
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
  return this.format();
};

/**
 * Inspect the block and return a more
 * user-friendly representation of the data.
 * @param {CoinView} view
 * @param {Number} height
 * @returns {Object}
 */

MerkleBlock.prototype.format = function format(view, height) {
  return {
    hash: this.rhash(),
    height: height != null ? height : -1,
    date: util.date(this.ts),
    version: util.hex32(this.version),
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    totalTX: this.totalTX,
    hashes: this.hashes.map(function(hash) {
      return hash.toString('hex');
    }),
    flags: this.flags,
    map: this.getTree().map,
    txs: this.txs.length
  };
};

/**
 * Get merkleblock size.
 * @returns {Number} Size.
 */

MerkleBlock.prototype.getSize = function getSize() {
  var size = 0;
  size += 80;
  size += 4;
  size += encoding.sizeVarint(this.hashes.length);
  size += this.hashes.length * 32;
  size += encoding.sizeVarint(this.flags.length);
  size += this.flags.length;
  return size;
};

/**
 * Write the merkleblock to a buffer writer.
 * @param {BufferWriter} bw
 */

MerkleBlock.prototype.toWriter = function toWriter(bw) {
  var i;

  this.writeAbbr(bw);

  bw.writeU32(this.totalTX);

  bw.writeVarint(this.hashes.length);

  for (i = 0; i < this.hashes.length; i++)
    bw.writeHash(this.hashes[i]);

  bw.writeVarBytes(this.flags);

  return bw;
};

/**
 * Serialize the merkleblock.
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

MerkleBlock.prototype.toRaw = function toRaw() {
  var size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

MerkleBlock.prototype.fromReader = function fromReader(br) {
  var i, count;

  this.parseAbbr(br);

  this.totalTX = br.readU32();

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.hashes.push(br.readHash());

  this.flags = br.readVarBytes();

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

MerkleBlock.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate a merkleblock from a buffer reader.
 * @param {BufferReader} br
 * @returns {MerkleBlock}
 */

MerkleBlock.fromReader = function fromReader(br) {
  return new MerkleBlock().fromReader(br);
};

/**
 * Instantiate a merkleblock from a serialized data.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {MerkleBlock}
 */

MerkleBlock.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new MerkleBlock().fromRaw(data);
};

/**
 * Convert the block to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

MerkleBlock.prototype.toJSON = function toJSON() {
  return this.getJSON();
};

/**
 * Convert the block to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @param {Network} network
 * @param {CoinView} view
 * @param {Number} height
 * @returns {Object}
 */

MerkleBlock.prototype.getJSON = function getJSON(network, view, height) {
  return {
    hash: this.rhash(),
    height: height,
    version: this.version,
    prevBlock: util.revHex(this.prevBlock),
    merkleRoot: util.revHex(this.merkleRoot),
    ts: this.ts,
    bits: this.bits,
    nonce: this.nonce,
    totalTX: this.totalTX,
    hashes: this.hashes.map(function(hash) {
      return util.revHex(hash.toString('hex'));
    }),
    flags: this.flags.toString('hex')
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

MerkleBlock.prototype.fromJSON = function fromJSON(json) {
  var i, hash;

  assert(json, 'MerkleBlock data is required.');
  assert(Array.isArray(json.hashes));
  assert(typeof json.flags === 'string');
  assert(util.isUInt32(json.totalTX));

  this.parseJSON(json);

  for (i = 0; i < json.hashes.length; i++) {
    hash = util.revHex(json.hashes[i]);
    this.hashes.push(new Buffer(hash, 'hex'));
  }

  this.flags = new Buffer(json.flags, 'hex');

  this.totalTX = json.totalTX;

  return this;
};

/**
 * Instantiate a merkle block from a jsonified block object.
 * @param {Object} json - The jsonified block object.
 * @returns {MerkleBlock}
 */

MerkleBlock.fromJSON = function fromJSON(json) {
  return new MerkleBlock().fromJSON(json);
};

/**
 * Create a merkleblock from a {@link Block} object, passing
 * it through a filter first. This will build the partial
 * merkle tree.
 * @param {Block} block
 * @param {Bloom} filter
 * @returns {MerkleBlock}
 */

MerkleBlock.fromBlock = function fromBlock(block, filter) {
  var matches = [];
  var i, tx;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    matches.push(tx.isWatched(filter) ? 1 : 0);
  }

  return MerkleBlock.fromMatches(block, matches);
};

/**
 * Create a merkleblock from an array of txids.
 * This will build the partial merkle tree.
 * @param {Block} block
 * @param {Hash[]} hashes
 * @returns {MerkleBlock}
 */

MerkleBlock.fromHashes = function fromHashes(block, hashes) {
  var filter = {};
  var matches = [];
  var i, tx, hash;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    if (Buffer.isBuffer(hash))
      hash = hash.toString('hex');
    filter[hash] = true;
  }

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    hash = tx.hash('hex');
    matches.push(filter[hash] ? 1 : 0);
  }

  return MerkleBlock.fromMatches(block, matches);
};

/**
 * Create a merkleblock from an array of matches.
 * This will build the partial merkle tree.
 * @param {Block} block
 * @param {Number[]} matches
 * @returns {MerkleBlock}
 */

MerkleBlock.fromMatches = function fromMatches(block, matches) {
  var txs = [];
  var leaves = [];
  var bits = [];
  var hashes = [];
  var totalTX = block.txs.length;
  var height = 0;
  var i, p, tx, flags, merkle, buf;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i];
    if (matches[i])
      txs.push(tx);
    leaves.push(tx.hash());
  }

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

    left.copy(buf, 0);
    right.copy(buf, 32);

    return crypto.hash256(buf);
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

  while (width(height) > 1)
    height++;

  if (height > 0)
    buf = new Buffer(64);

  traverse(height, 0, leaves, matches);

  flags = new Buffer((bits.length + 7) / 8 | 0);
  flags.fill(0);

  for (p = 0; p < bits.length; p++)
    flags[p / 8 | 0] |= bits[p] << (p % 8);

  merkle = new MerkleBlock();
  merkle._hash = block._hash;
  merkle._hhash = block._hhash;
  merkle.version = block.version;
  merkle.prevBlock = block.prevBlock;
  merkle.merkleRoot = block.merkleRoot;
  merkle.ts = block.ts;
  merkle.bits = block.bits;
  merkle.nonce = block.nonce;
  merkle.totalTX = totalTX;
  merkle.hashes = hashes;
  merkle.flags = flags;
  merkle.txs = txs;

  return merkle;
};

/**
 * Test whether an object is a MerkleBlock.
 * @param {Object} obj
 * @returns {Boolean}
 */

MerkleBlock.isMerkleBlock = function isMerkleBlock(obj) {
  return obj
    && Buffer.isBuffer(obj.flags)
    && typeof obj.verifyBody === 'function';
};

/**
 * Convert the block to a headers object.
 * @returns {Headers}
 */

MerkleBlock.prototype.toHeaders = function toHeaders() {
  return Headers.fromBlock(this);
};

/*
 * Helpers
 */

function PartialTree(root, matches, indexes, map) {
  this.root = root ? root.toString('hex') : encoding.NULL_HASH;
  this.matches = matches || [];
  this.indexes = indexes || [];
  this.map = map || {};
}

/*
 * Expose
 */

module.exports = MerkleBlock;
