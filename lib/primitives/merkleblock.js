/*!
 * merkleblock.js - merkleblock object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const bio = require('bufio');
const util = require('../utils/util');
const hash256 = require('bcrypto/lib/hash256');
const consensus = require('../protocol/consensus');
const AbstractBlock = require('./abstractblock');
const Headers = require('./headers');
const DUMMY = Buffer.from([0]);
const {encoding} = bio;

/**
 * Merkle Block
 * Represents a merkle (filtered) block.
 * @alias module:primitives.MerkleBlock
 * @extends AbstractBlock
 */

class MerkleBlock extends AbstractBlock {
  /**
   * Create a merkle block.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.txs = [];
    this.hashes = [];
    this.flags = DUMMY;

    this.totalTX = 0;
    this._tree = null;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    this.parseOptions(options);

    assert(options, 'MerkleBlock data is required.');
    assert(Array.isArray(options.hashes));
    assert(Buffer.isBuffer(options.flags));
    assert((options.totalTX >>> 0) === options.totalTX);

    if (options.hashes) {
      for (let hash of options.hashes) {
        if (typeof hash === 'string')
          hash = Buffer.from(hash, 'hex');
        assert(Buffer.isBuffer(hash));
        this.hashes.push(hash);
      }
    }

    if (options.flags) {
      assert(Buffer.isBuffer(options.flags));
      this.flags = options.flags;
    }

    if (options.totalTX != null) {
      assert((options.totalTX >>> 0) === options.totalTX);
      this.totalTX = options.totalTX;
    }

    return this;
  }

  /**
   * Instantiate merkle block from options object.
   * @param {Object} options
   * @returns {MerkleBlock}
   */

  static fromOptions(data) {
    return new this().fromOptions(data);
  }

  /**
   * Clear any cached values.
   * @param {Boolean?} all - Clear transactions.
   */

  refresh(all) {
    this._refresh();
    this._tree = null;

    if (!all)
      return;

    for (const tx of this.txs)
      tx.refresh();
  }

  /**
   * Test the block's _matched_ transaction vector against a hash.
   * @param {Hash} hash
   * @returns {Boolean}
   */

  hasTX(hash) {
    return this.indexOf(hash) !== -1;
  }

  /**
   * Test the block's _matched_ transaction vector against a hash.
   * @param {Hash} hash
   * @returns {Number} Index.
   */

  indexOf(hash) {
    const tree = this.getTree();
    const index = tree.map.get(hash);

    if (index == null)
      return -1;

    return index;
  }

  /**
   * Verify the partial merkletree.
   * @private
   * @returns {Boolean}
   */

  verifyBody() {
    const [valid] = this.checkBody();
    return valid;
  }

  /**
   * Verify the partial merkletree.
   * @private
   * @returns {Array} [valid, reason, score]
   */

  checkBody() {
    const tree = this.getTree();

    if (tree.root !== this.merkleRoot)
      return [false, 'bad-txnmrklroot', 100];

    return [true, 'valid', 0];
  }

  /**
   * Extract the matches from partial merkle
   * tree and calculate merkle root.
   * @returns {Object}
   */

  getTree() {
    if (!this._tree) {
      try {
        this._tree = this.extractTree();
      } catch (e) {
        this._tree = new PartialTree();
      }
    }
    return this._tree;
  }

  /**
   * Extract the matches from partial merkle
   * tree and calculate merkle root.
   * @private
   * @returns {Object}
   */

  extractTree() {
    const matches = [];
    const indexes = [];
    const map = new Map();
    const hashes = this.hashes;
    const flags = this.flags;
    const totalTX = this.totalTX;

    let bitsUsed = 0;
    let hashUsed = 0;
    let failed = false;
    let height = 0;

    const width = (height) => {
      return (totalTX + (1 << height) - 1) >>> height;
    };

    const traverse = (height, pos) => {
      if (bitsUsed >= flags.length * 8) {
        failed = true;
        return consensus.ZERO_HASH;
      }

      const parent = (flags[bitsUsed / 8 | 0] >>> (bitsUsed % 8)) & 1;

      bitsUsed += 1;

      if (height === 0 || !parent) {
        if (hashUsed >= hashes.length) {
          failed = true;
          return consensus.ZERO_HASH;
        }

        const hash = hashes[hashUsed];

        hashUsed += 1;

        if (height === 0 && parent) {
          const txid = hash.toString('hex');
          matches.push(hash);
          indexes.push(pos);
          map.set(txid, pos);
        }

        return hash;
      }

      const left = traverse(height - 1, pos * 2);
      let right;

      if (pos * 2 + 1 < width(height - 1)) {
        right = traverse(height - 1, pos * 2 + 1);
        if (right.equals(left))
          failed = true;
      } else {
        right = left;
      }

      return hash256.root(left, right);
    };

    if (totalTX === 0)
      throw new Error('Zero transactions.');

    if (totalTX > consensus.MAX_BLOCK_SIZE / 60)
      throw new Error('Too many transactions.');

    if (hashes.length > totalTX)
      throw new Error('Too many hashes.');

    if (flags.length * 8 < hashes.length)
      throw new Error('Flags too small.');

    while (width(height) > 1)
      height += 1;

    const root = traverse(height, 0);

    if (failed)
      throw new Error('Mutated merkle tree.');

    if (((bitsUsed + 7) / 8 | 0) !== flags.length)
      throw new Error('Too many flag bits.');

    if (hashUsed !== hashes.length)
      throw new Error('Incorrect number of hashes.');

    return new PartialTree(root, matches, indexes, map);
  }

  /**
   * Extract the coinbase height (always -1).
   * @returns {Number}
   */

  getCoinbaseHeight() {
    return -1;
  }

  /**
   * Inspect the block and return a more
   * user-friendly representation of the data.
   * @returns {Object}
   */

  inspect() {
    return this.format();
  }

  /**
   * Inspect the block and return a more
   * user-friendly representation of the data.
   * @param {CoinView} view
   * @param {Number} height
   * @returns {Object}
   */

  format(view, height) {
    return {
      hash: this.rhash(),
      height: height != null ? height : -1,
      date: util.date(this.time),
      version: this.version.toString(16),
      prevBlock: util.revHex(this.prevBlock),
      merkleRoot: util.revHex(this.merkleRoot),
      time: this.time,
      bits: this.bits,
      nonce: this.nonce,
      totalTX: this.totalTX,
      hashes: this.hashes.map((hash) => {
        return hash.toString('hex');
      }),
      flags: this.flags,
      map: this.getTree().map,
      txs: this.txs.length
    };
  }

  /**
   * Get merkleblock size.
   * @returns {Number} Size.
   */

  getSize() {
    let size = 0;
    size += 80;
    size += 4;
    size += encoding.sizeVarint(this.hashes.length);
    size += this.hashes.length * 32;
    size += encoding.sizeVarint(this.flags.length);
    size += this.flags.length;
    return size;
  }

  /**
   * Write the merkleblock to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    this.writeHead(bw);

    bw.writeU32(this.totalTX);

    bw.writeVarint(this.hashes.length);

    for (const hash of this.hashes)
      bw.writeHash(hash);

    bw.writeVarBytes(this.flags);

    return bw;
  }

  /**
   * Serialize the merkleblock.
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {Buffer|String}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.readHead(br);

    this.totalTX = br.readU32();

    const count = br.readVarint();

    for (let i = 0; i < count; i++)
      this.hashes.push(br.readHash());

    this.flags = br.readVarBytes();

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate a merkleblock from a buffer reader.
   * @param {BufferReader} br
   * @returns {MerkleBlock}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate a merkleblock from a serialized data.
   * @param {Buffer} data
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {MerkleBlock}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Convert the block to an object suitable
   * for JSON serialization.
   * @returns {Object}
   */

  toJSON() {
    return this.getJSON();
  }

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

  getJSON(network, view, height) {
    return {
      hash: this.rhash(),
      height: height,
      version: this.version,
      prevBlock: util.revHex(this.prevBlock),
      merkleRoot: util.revHex(this.merkleRoot),
      time: this.time,
      bits: this.bits,
      nonce: this.nonce,
      totalTX: this.totalTX,
      hashes: this.hashes.map((hash) => {
        return util.revHex(hash.toString('hex'));
      }),
      flags: this.flags.toString('hex')
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  fromJSON(json) {
    assert(json, 'MerkleBlock data is required.');
    assert(Array.isArray(json.hashes));
    assert(typeof json.flags === 'string');
    assert((json.totalTX >>> 0) === json.totalTX);

    this.parseJSON(json);

    for (let hash of json.hashes) {
      hash = util.revHex(hash);
      this.hashes.push(Buffer.from(hash, 'hex'));
    }

    this.flags = Buffer.from(json.flags, 'hex');

    this.totalTX = json.totalTX;

    return this;
  }

  /**
   * Instantiate a merkle block from a jsonified block object.
   * @param {Object} json - The jsonified block object.
   * @returns {MerkleBlock}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Create a merkleblock from a {@link Block} object, passing
   * it through a filter first. This will build the partial
   * merkle tree.
   * @param {Block} block
   * @param {Bloom} filter
   * @returns {MerkleBlock}
   */

  static fromBlock(block, filter) {
    const matches = [];

    for (const tx of block.txs)
      matches.push(tx.isWatched(filter) ? 1 : 0);

    return this.fromMatches(block, matches);
  }

  /**
   * Create a merkleblock from an array of txids.
   * This will build the partial merkle tree.
   * @param {Block} block
   * @param {Hash[]} hashes
   * @returns {MerkleBlock}
   */

  static fromHashes(block, hashes) {
    const filter = new Set();

    for (let hash of hashes) {
      if (Buffer.isBuffer(hash))
        hash = hash.toString('hex');
      filter.add(hash);
    }

    const matches = [];

    for (const tx of block.txs) {
      const hash = tx.hash('hex');
      matches.push(filter.has(hash) ? 1 : 0);
    }

    return this.fromMatches(block, matches);
  }

  /**
   * Create a merkleblock from an array of matches.
   * This will build the partial merkle tree.
   * @param {Block} block
   * @param {Number[]} matches
   * @returns {MerkleBlock}
   */

  static fromMatches(block, matches) {
    const txs = [];
    const leaves = [];
    const bits = [];
    const hashes = [];
    const totalTX = block.txs.length;
    let height = 0;

    const width = (height) => {
      return (totalTX + (1 << height) - 1) >>> height;
    };

    const hash = (height, pos, leaves) => {
      if (height === 0)
        return leaves[pos];

      const left = hash(height - 1, pos * 2, leaves);
      let right;

      if (pos * 2 + 1 < width(height - 1))
        right = hash(height - 1, pos * 2 + 1, leaves);
      else
        right = left;

      return hash256.root(left, right);
    };

    const traverse = (height, pos, leaves, matches) => {
      let parent = 0;

      for (let p = pos << height; p < ((pos + 1) << height) && p < totalTX; p++)
        parent |= matches[p];

      bits.push(parent);

      if (height === 0 || !parent) {
        hashes.push(hash(height, pos, leaves));
        return;
      }

      traverse(height - 1, pos * 2, leaves, matches);

      if (pos * 2 + 1 < width(height - 1))
        traverse(height - 1, pos * 2 + 1, leaves, matches);
    };

    for (let i = 0; i < block.txs.length; i++) {
      const tx = block.txs[i];

      if (matches[i])
        txs.push(tx);

      leaves.push(tx.hash());
    }

    while (width(height) > 1)
      height += 1;

    traverse(height, 0, leaves, matches);

    const flags = Buffer.allocUnsafe((bits.length + 7) / 8 | 0);
    flags.fill(0);

    for (let p = 0; p < bits.length; p++)
      flags[p / 8 | 0] |= bits[p] << (p % 8);

    const merkle = new this();
    merkle._hash = block._hash;
    merkle._hhash = block._hhash;
    merkle.version = block.version;
    merkle.prevBlock = block.prevBlock;
    merkle.merkleRoot = block.merkleRoot;
    merkle.time = block.time;
    merkle.bits = block.bits;
    merkle.nonce = block.nonce;
    merkle.totalTX = totalTX;
    merkle.hashes = hashes;
    merkle.flags = flags;
    merkle.txs = txs;

    return merkle;
  }

  /**
   * Test whether an object is a MerkleBlock.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isMerkleBlock(obj) {
    return obj instanceof MerkleBlock;
  }

  /**
   * Convert the block to a headers object.
   * @returns {Headers}
   */

  toHeaders() {
    return Headers.fromBlock(this);
  }
}

/*
 * Helpers
 */

class PartialTree {
  constructor(root, matches, indexes, map) {
    this.root = root ? root.toString('hex') : consensus.NULL_HASH;
    this.matches = matches || [];
    this.indexes = indexes || [];
    this.map = map || new Map();
  }
}

/*
 * Expose
 */

module.exports = MerkleBlock;
