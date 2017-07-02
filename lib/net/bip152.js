/*!
 * bip152.js - compact block object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module net/bip152
 */

const assert = require('assert');
const util = require('../utils/util');
const BufferReader = require('../utils/reader');
const BufferWriter = require('../utils/writer');
const StaticWriter = require('../utils/staticwriter');
const encoding = require('../utils/encoding');
const consensus = require('../protocol/consensus');
const digest = require('../crypto/digest');
const siphash256 = require('../crypto/siphash').siphash256;
const AbstractBlock = require('../primitives/abstractblock');
const TX = require('../primitives/tx');
const Headers = require('../primitives/headers');
const Block = require('../primitives/block');

/**
 * Represents a compact block (bip152): `cmpctblock` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 * @extends AbstractBlock
 * @param {Object} options
 * @property {Buffer|null} keyNonce - Nonce for siphash key.
 * @property {Number[]} ids - Short IDs.
 * @property {Object[]} ptx - Prefilled transactions.
 * @property {TX[]} available - Available transaction vector.
 * @property {Object} idMap - Map of short ids to indexes.
 * @property {Number} count - Transactions resolved.
 * @property {Buffer|null} sipKey - Siphash key.
 */

function CompactBlock(options) {
  if (!(this instanceof CompactBlock))
    return new CompactBlock(options);

  AbstractBlock.call(this);

  this.keyNonce = null;
  this.ids = [];
  this.ptx = [];

  this.available = [];
  this.idMap = new Map();
  this.count = 0;
  this.sipKey = null;
  this.totalTX = 0;
  this.now = 0;

  if (options)
    this.fromOptions(options);
}

util.inherits(CompactBlock, AbstractBlock);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

CompactBlock.prototype.fromOptions = function fromOptions(options) {
  this.parseOptions(options);

  assert(Buffer.isBuffer(options.keyNonce));
  assert(Array.isArray(options.ids));
  assert(Array.isArray(options.ptx));

  this.keyNonce = options.keyNonce;
  this.ids = options.ids;
  this.ptx = options.ptx;

  if (options.available)
    this.available = options.available;

  if (options.idMap)
    this.idMap = options.idMap;

  if (options.count)
    this.count = options.count;

  if (options.totalTX != null)
    this.totalTX = options.totalTX;

  this.sipKey = options.sipKey;

  this.initKey();

  return this;
};

/**
 * Instantiate compact block from options.
 * @param {Object} options
 * @returns {CompactBlock}
 */

CompactBlock.fromOptions = function fromOptions(options) {
  return new CompactBlock().fromOptions(options);
};

/**
 * Verify the block.
 * @returns {Boolean}
 */

CompactBlock.prototype.verifyBody = function verifyBody() {
  return true;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

CompactBlock.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  let count;

  this.version = br.readU32();
  this.prevBlock = br.readHash('hex');
  this.merkleRoot = br.readHash('hex');
  this.ts = br.readU32();
  this.bits = br.readU32();
  this.nonce = br.readU32();

  this.keyNonce = br.readBytes(8);

  this.initKey();

  count = br.readVarint();

  this.totalTX += count;

  for (let i = 0; i < count; i++)
    this.ids.push(br.readU32() + br.readU16() * 0x100000000);

  count = br.readVarint();

  this.totalTX += count;

  for (let i = 0; i < count; i++) {
    let index = br.readVarint();
    let tx;

    assert(index <= 0xffff);
    assert(index < this.totalTX);

    tx = TX.fromReader(br);

    this.ptx.push(new PrefilledTX(index, tx));
  }

  return this;
};

/**
 * Instantiate a block from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {CompactBlock}
 */

CompactBlock.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new CompactBlock().fromRaw(data);
};

/**
 * Serialize compact block with witness data.
 * @returns {Buffer}
 */

CompactBlock.prototype.toRaw = function toRaw() {
  return this.frameRaw(true);
};

/**
 * Serialize compact block without witness data.
 * @returns {Buffer}
 */

CompactBlock.prototype.toNormal = function toNormal() {
  return this.frameRaw(false);
};

/**
 * Write serialized block to a buffer
 * writer (includes witness data).
 * @param {BufferWriter} bw
 */

CompactBlock.prototype.toWriter = function toWriter(bw) {
  return this.writeRaw(bw, true);
};

/**
 * Write serialized block to a buffer
 * writer (excludes witness data).
 * @param {BufferWriter} bw
 */

CompactBlock.prototype.toNormalWriter = function toNormalWriter(bw) {
  return this.writeRaw(bw, false);
};

/**
 * Serialize compact block.
 * @private
 * @param {Boolean} witness
 * @returns {Buffer}
 */

CompactBlock.prototype.frameRaw = function frameRaw(witness) {
  let size = this.getSize(witness);
  return this.writeRaw(new StaticWriter(size), witness).render();
};

/**
 * Calculate block serialization size.
 * @param {Boolean} witness
 * @returns {Number}
 */

CompactBlock.prototype.getSize = function getSize(witness) {
  let size = 0;

  size += 80;
  size += 8;
  size += encoding.sizeVarint(this.ids.length);
  size += this.ids.length * 6;
  size += encoding.sizeVarint(this.ptx.length);

  for (let ptx of this.ptx) {
    size += encoding.sizeVarint(ptx.index);
    if (witness)
      size += ptx.tx.getSize();
    else
      size += ptx.tx.getBaseSize();
  }

  return size;
};

/**
 * Serialize block to buffer writer.
 * @private
 * @param {BufferWriter} bw
 * @param {Boolean} witness
 */

CompactBlock.prototype.writeRaw = function writeRaw(bw, witness) {
  this.writeAbbr(bw);

  bw.writeBytes(this.keyNonce);

  bw.writeVarint(this.ids.length);

  for (let id of this.ids) {
    let lo = id % 0x100000000;
    let hi = (id - lo) / 0x100000000;
    hi &= 0xffff;
    bw.writeU32(lo);
    bw.writeU16(hi);
  }

  bw.writeVarint(this.ptx.length);

  for (let ptx of this.ptx) {
    bw.writeVarint(ptx.index);
    if (witness)
      ptx.tx.toWriter(bw);
    else
      ptx.tx.toNormalWriter(bw);
  }

  return bw;
};

/**
 * Convert block to a TXRequest
 * containing missing indexes.
 * @returns {TXRequest}
 */

CompactBlock.prototype.toRequest = function toRequest() {
  return TXRequest.fromCompact(this);
};

/**
 * Attempt to fill missing transactions from mempool.
 * @param {Boolean} witness
 * @param {Mempool} mempool
 * @returns {Boolean}
 */

CompactBlock.prototype.fillMempool = function fillMempool(witness, mempool) {
  let have = {};

  if (this.count === this.totalTX)
    return true;

  for (let entry of mempool.map.values()) {
    let tx = entry.tx;
    let hash = tx.hash();
    let id, index;

    if (witness)
      hash = tx.witnessHash();

    id = this.sid(hash);
    index = this.idMap.get(id);

    if (index == null)
      continue;

    if (have[index]) {
      // Siphash collision, just request it.
      this.available[index] = null;
      this.count--;
      continue;
    }

    this.available[index] = tx;
    have[index] = true;
    this.count++;

    // We actually may have a siphash collision
    // here, but exit early anyway for perf.
    if (this.count === this.totalTX)
      return true;
  }

  return false;
};

/**
 * Attempt to fill missing transactions from TXResponse.
 * @param {TXResponse} res
 * @returns {Boolean}
 */

CompactBlock.prototype.fillMissing = function fillMissing(res) {
  let offset = 0;

  for (let i = 0; i < this.available.length; i++) {
    if (this.available[i])
      continue;

    if (offset >= res.txs.length)
      return false;

    this.available[i] = res.txs[offset++];
  }

  return offset === res.txs.length;
};

/**
 * Calculate a transaction short ID.
 * @param {Hash} hash
 * @returns {Number}
 */

CompactBlock.prototype.sid = function sid(hash) {
  let hi, lo;

  if (typeof hash === 'string')
    hash = Buffer.from(hash, 'hex');

  [hi, lo] = siphash256(hash, this.sipKey);

  return (hi & 0xffff) * 0x100000000 + (lo >>> 0);
};

/**
 * Test whether an index is available.
 * @param {Number} index
 * @returns {Boolean}
 */

CompactBlock.prototype.hasIndex = function hasIndex(index) {
  return this.available[index] != null;
};

/**
 * Initialize the siphash key.
 * @private
 */

CompactBlock.prototype.initKey = function initKey() {
  let data = util.concat(this.abbr(), this.keyNonce);
  let hash = digest.sha256(data);
  this.sipKey = hash.slice(0, 16);
};

/**
 * Initialize compact block and short id map.
 * @private
 */

CompactBlock.prototype.init = function init() {
  let last = -1;
  let offset = 0;

  if (this.totalTX === 0)
    throw new Error('Empty vectors.');

  if (this.totalTX > consensus.MAX_BLOCK_SIZE / 10)
    throw new Error('Compact block too big.');

  // No sparse arrays here, v8.
  for (let i = 0; i < this.totalTX; i++)
    this.available.push(null);

  for (let i = 0; i < this.ptx.length; i++) {
    let ptx = this.ptx[i];
    assert(ptx);
    last += ptx.index + 1;
    assert(last <= 0xffff);
    assert(last <= this.ids.length + i);
    this.available[last] = ptx.tx;
    this.count++;
  }

  for (let i = 0; i < this.ids.length; i++) {
    let id;

    while (this.available[i + offset])
      offset++;

    id = this.ids[i];

    // Fails on siphash collision
    if (this.idMap.has(id))
      return false;

    this.idMap.set(id, i + offset);

    // We're supposed to fail here if there's
    // more than 12 hash collisions, but we
    // don't have lowlevel access to our hash
    // table. Hopefully we don't get hashdos'd.
  }

  return true;
};

/**
 * Convert completely filled compact
 * block to a regular block.
 * @returns {Block}
 */

CompactBlock.prototype.toBlock = function toBlock() {
  let block = new Block();

  block.version = this.version;
  block.prevBlock = this.prevBlock;
  block.merkleRoot = this.merkleRoot;
  block.ts = this.ts;
  block.bits = this.bits;
  block.nonce = this.nonce;
  block._hash = this._hash;
  block._hhash = this._hhash;

  for (let tx of this.available) {
    assert(tx, 'Compact block is not full.');
    block.txs.push(tx);
  }

  return block;
};

/**
 * Inject properties from block.
 * @private
 * @param {Block} block
 * @param {Boolean} witness
 * @param {Buffer?} nonce
 * @returns {CompactBlock}
 */

CompactBlock.prototype.fromBlock = function fromBlock(block, witness, nonce) {
  this.version = block.version;
  this.prevBlock = block.prevBlock;
  this.merkleRoot = block.merkleRoot;
  this.ts = block.ts;
  this.bits = block.bits;
  this.nonce = block.nonce;
  this.totalTX = block.txs.length;
  this._hash = block._hash;
  this._hhash = block._hhash;

  if (!nonce)
    nonce = util.nonce();

  this.keyNonce = nonce;

  this.initKey();

  for (let i = 1; i < block.txs.length; i++) {
    let tx = block.txs[i];
    let hash = tx.hash();
    let id;

    if (witness)
      hash = tx.witnessHash();

    id = this.sid(hash);

    this.ids.push(id);
  }

  this.ptx.push(new PrefilledTX(0, block.txs[0]));

  return this;
};

/**
 * Instantiate compact block from a block.
 * @param {Block} block
 * @param {Boolean} witness
 * @param {Buffer?} nonce
 * @returns {CompactBlock}
 */

CompactBlock.fromBlock = function fromBlock(block, witness, nonce) {
  return new CompactBlock().fromBlock(block, witness, nonce);
};

/**
 * Convert block to headers.
 * @returns {Headers}
 */

CompactBlock.prototype.toHeaders = function toHeaders() {
  return Headers.fromBlock(this);
};

/**
 * Represents a BlockTransactionsRequest (bip152): `getblocktxn` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 * @param {Object} options
 * @property {Hash} hash
 * @property {Number[]} indexes
 */

function TXRequest(options) {
  if (!(this instanceof TXRequest))
    return new TXRequest(options);

  this.hash = null;
  this.indexes = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {TXRequest}
 */

TXRequest.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.indexes)
    this.indexes = options.indexes;

  return this;
};

/**
 * Instantiate request from options.
 * @param {Object} options
 * @returns {TXRequest}
 */

TXRequest.fromOptions = function fromOptions(options) {
  return new TXRequest().fromOptions(options);
};

/**
 * Inject properties from compact block.
 * @private
 * @param {CompactBlock} block
 * @returns {TXRequest}
 */

TXRequest.prototype.fromCompact = function fromCompact(block) {
  this.hash = block.hash('hex');

  for (let i = 0; i < block.available.length; i++) {
    if (!block.available[i])
      this.indexes.push(i);
  }

  return this;
};

/**
 * Instantiate request from compact block.
 * @param {CompactBlock} block
 * @returns {TXRequest}
 */

TXRequest.fromCompact = function fromCompact(block) {
  return new TXRequest().fromCompact(block);
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 * @returns {TXRequest}
 */

TXRequest.prototype.fromReader = function fromReader(br) {
  let offset = 0;
  let count;

  this.hash = br.readHash('hex');

  count = br.readVarint();

  for (let i = 0; i < count; i++) {
    let index = br.readVarint();
    assert(index <= 0xffff);
    this.indexes.push(index);
  }

  for (let i = 0; i < count; i++) {
    let index = this.indexes[i];
    index += offset;
    assert(index <= 0xffff);
    this.indexes[i] = index;
    offset = index + 1;
  }

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {TXRequest}
 */

TXRequest.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate request from buffer reader.
 * @param {BufferReader} br
 * @returns {TXRequest}
 */

TXRequest.fromReader = function fromReader(br) {
  return new TXRequest().fromReader(br);
};

/**
 * Instantiate request from serialized data.
 * @param {Buffer} data
 * @returns {TXRequest}
 */

TXRequest.fromRaw = function fromRaw(data) {
  return new TXRequest().fromRaw(data);
};

/**
 * Calculate request serialization size.
 * @returns {Number}
 */

TXRequest.prototype.getSize = function getSize() {
  let size = 0;

  size += 32;
  size += encoding.sizeVarint(this.indexes.length);

  for (let i = 0; i < this.indexes.length; i++) {
    let index = this.indexes[i] - (i === 0 ? 0 : this.indexes[i - 1] + 1);
    size += encoding.sizeVarint(index);
  }

  return size;
};

/**
 * Write serialized request to buffer writer.
 * @param {BufferWriter} bw
 */

TXRequest.prototype.toWriter = function toWriter(bw) {
  bw.writeHash(this.hash);

  bw.writeVarint(this.indexes.length);

  for (let i = 0; i < this.indexes.length; i++) {
    let index = this.indexes[i] - (i === 0 ? 0 : this.indexes[i - 1] + 1);
    bw.writeVarint(index);
  }

  return bw;
};

/**
 * Serialize request.
 * @returns {Buffer}
 */

TXRequest.prototype.toRaw = function toRaw() {
  return this.toWriter(new BufferWriter()).render();
};

/**
 * Represents BlockTransactions (bip152): `blocktxn` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 * @param {Object} options
 * @property {Hash} hash
 * @property {TX[]} txs
 */

function TXResponse(options) {
  if (!(this instanceof TXResponse))
    return new TXResponse(options);

  this.hash = null;
  this.txs = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 * @returns {TXResponse}
 */

TXResponse.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.txs)
    this.txs = options.txs;

  return this;
};

/**
 * Instantiate response from options.
 * @param {Object} options
 * @returns {TXResponse}
 */

TXResponse.fromOptions = function fromOptions(options) {
  return new TXResponse().fromOptions(options);
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 * @returns {TXResponse}
 */

TXResponse.prototype.fromReader = function fromReader(br) {
  let count;

  this.hash = br.readHash('hex');

  count = br.readVarint();

  for (let i = 0; i < count; i++)
    this.txs.push(TX.fromReader(br));

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {TXResponse}
 */

TXResponse.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate response from buffer reader.
 * @param {BufferReader} br
 * @returns {TXResponse}
 */

TXResponse.fromReader = function fromReader(br) {
  return new TXResponse().fromReader(br);
};

/**
 * Instantiate response from serialized data.
 * @param {Buffer} data
 * @returns {TXResponse}
 */

TXResponse.fromRaw = function fromRaw(data) {
  return new TXResponse().fromRaw(data);
};

/**
 * Inject properties from block.
 * @private
 * @param {Block} block
 * @returns {TXResponse}
 */

TXResponse.prototype.fromBlock = function fromBlock(block, req) {
  this.hash = req.hash;

  for (let index of req.indexes) {
    if (index >= block.txs.length)
      break;

    this.txs.push(block.txs[index]);
  }

  return this;
};

/**
 * Instantiate response from block.
 * @param {Block} block
 * @returns {TXResponse}
 */

TXResponse.fromBlock = function fromBlock(block, req) {
  return new TXResponse().fromBlock(block, req);
};

/**
 * Serialize response with witness data.
 * @returns {Buffer}
 */

TXResponse.prototype.toRaw = function toRaw() {
  return this.frameRaw(true);
};

/**
 * Serialize response without witness data.
 * @returns {Buffer}
 */

TXResponse.prototype.toNormal = function toNormal() {
  return this.frameRaw(false);
};

/**
 * Write serialized response to a buffer
 * writer (includes witness data).
 * @param {BufferWriter} bw
 */

TXResponse.prototype.toWriter = function toWriter(bw) {
  return this.writeRaw(bw, true);
};

/**
 * Write serialized response to a buffer
 * writer (excludes witness data).
 * @param {BufferWriter} bw
 */

TXResponse.prototype.toNormalWriter = function toNormalWriter(bw) {
  return this.writeRaw(bw, false);
};

/**
 * Calculate request serialization size.
 * @returns {Number}
 */

TXResponse.prototype.getSize = function getSize(witness) {
  let size = 0;

  size += 32;
  size += encoding.sizeVarint(this.txs.length);

  for (let tx of this.txs) {
    if (witness)
      size += tx.getSize();
    else
      size += tx.getBaseSize();
  }

  return size;
};

/**
 * Write serialized response to buffer writer.
 * @private
 * @param {BufferWriter} bw
 * @param {Boolean} witness
 */

TXResponse.prototype.writeRaw = function writeRaw(bw, witness) {
  bw.writeHash(this.hash);

  bw.writeVarint(this.txs.length);

  for (let tx of this.txs) {
    if (witness)
      tx.toWriter(bw);
    else
      tx.toNormalWriter(bw);
  }

  return bw;
};

/**
 * Serialize response with witness data.
 * @private
 * @param {Boolean} witness
 * @returns {Buffer}
 */

TXResponse.prototype.frameRaw = function frameRaw(witness) {
  let size = this.getSize(witness);
  return this.writeRaw(new StaticWriter(size), witness).render();
};

/**
 * Represents a prefilled TX.
 * @constructor
 * @param {Number} index
 * @param {TX} tx
 * @property {Number} index
 * @property {TX} tx
 */

function PrefilledTX(index, tx) {
  this.index = index;
  this.tx = tx;
}

/*
 * Expose
 */

exports.CompactBlock = CompactBlock;
exports.TXRequest = TXRequest;
exports.TXResponse = TXResponse;
