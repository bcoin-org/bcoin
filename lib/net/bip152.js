/*!
 * bip152.js - compact block object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var crypto = require('../crypto/crypto');
var assert = utils.assert;
var constants = bcoin.constants;
var siphash = require('../crypto/siphash');
var AbstractBlock = bcoin.abstractblock;

/**
 * Represents a compact block (bip152): `cmpctblock` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @exports CompactBlock
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} options
 * @property {TX[]} available - Available transaction vector.
 */

function CompactBlock(options) {
  if (!(this instanceof CompactBlock))
    return new CompactBlock(options);

  AbstractBlock.call(this, options);

  this.keyNonce = null;
  this.ids = [];
  this.ptx = [];

  this.available = [];
  this.idMap = {};
  this.count = 0;
  this.sipKey = null;
  this.timeout = null;

  if (options)
    this.fromOptions(options);
}

utils.inherits(CompactBlock, AbstractBlock);

CompactBlock.prototype._verify = function _verify(ret) {
  return this.verifyHeaders(ret);
};

CompactBlock.prototype.fromOptions = function fromOptions(options) {
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

  this.sipKey = options.sipKey;

  this.initKey();
  this.init();

  return this;
};

CompactBlock.fromOptions = function fromOptions(options) {
  return new CompactBlock().fromOptions(options);
};

CompactBlock.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count, index, tx;

  this.version = p.readU32(); // Technically signed
  this.prevBlock = p.readHash('hex');
  this.merkleRoot = p.readHash('hex');
  this.ts = p.readU32();
  this.bits = p.readU32();
  this.nonce = p.readU32();

  this.keyNonce = p.readBytes(8);

  this.initKey();

  count = p.readVarint();

  this.totalTX += count;

  for (i = 0; i < count; i++)
    this.ids.push(p.readU32() + p.readU16() * 0x100000000);

  count = p.readVarint();

  this.totalTX += count;

  for (i = 0; i < count; i++) {
    index = p.readVarint();
    assert(index <= 0xffff);
    assert(index < this.totalTX);
    tx = bcoin.tx.fromRaw(p);
    this.ptx.push([index, tx]);
  }

  this.init();

  return this;
};

CompactBlock.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new CompactBlock().fromRaw(data);
};

CompactBlock.prototype.toRaw = function toRaw(writer) {
  return this.frame(true, writer);
};

CompactBlock.prototype.toNormal = function toNormal(writer) {
  return this.frame(false, writer);
};

CompactBlock.prototype.frame = function frame(witness, writer) {
  var p = bcoin.writer(writer);
  var i, id, lo, hi, ptx;

  p.write32(this.version);
  p.writeHash(this.prevBlock);
  p.writeHash(this.merkleRoot);
  p.writeU32(this.ts);
  p.writeU32(this.bits);
  p.writeU32(this.nonce);

  p.writeBytes(this.keyNonce);

  p.writeVarint(this.ids.length);

  for (i = 0; i < this.ids.length; i++) {
    id = this.ids[i];
    lo = id % 0x100000000;
    hi = (id - lo) / 0x100000000;
    hi &= 0xffff;
    p.writeU32(lo);
    p.writeU16(hi);
  }

  p.writeVarint(this.ptx.length);

  for (i = 0; i < this.ptx.length; i++) {
    ptx = this.ptx[i];
    p.writeVarint(ptx[0]);
    if (witness)
      ptx[1].toRaw(p);
    else
      ptx[1].toNormal(p);
  }

  if (!writer)
    p = p.render();

  return p;
};

CompactBlock.prototype.toRequest = function toRequest() {
  return TXRequest.fromCompact(this);
};

CompactBlock.prototype.fillMempool = function fillMempool(mempool) {
  var have = {};
  var hashes = mempool.getSnapshot();
  var i, id, index, hash, tx;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    id = this.sid(hash);
    index = this.idMap[id];

    if (index == null)
      continue;

    if (have[index]) {
      // Siphash collision, just request it.
      this.available[index] = null;
      this.count--;
      continue;
    }

    tx = mempool.getTX(hash);

    if (!tx)
      continue;

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

CompactBlock.prototype.fillMissing = function fillMissing(res) {
  var offset = 0;
  var i;

  for (i = 0; i < this.available.length; i++) {
    if (this.available[i])
      continue;

    if (offset >= res.txs.length)
      return false;

    this.available[i] = res.txs[offset++];
  }

  return offset === res.txs.length;
};

CompactBlock.prototype.sid = function sid(hash) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  hash = siphash(hash, this.sipKey);

  return hash.readUInt32LE(0, true)
    + hash.readUInt16LE(4, true)
    * 0x100000000;
};

CompactBlock.prototype.hasIndex = function hasIndex(index) {
  return this.available[index] != null;
};

CompactBlock.prototype.initKey = function initKey() {
  var data = new Buffer(88);
  var hash;

  this.abbr().copy(data, 0);
  this.keyNonce.copy(data, 80);

  hash = crypto.sha256(data);

  this.sipKey = hash.slice(0, 16);
};

CompactBlock.prototype.init = function init() {
  var i, last, ptx, offset, id;

  if (this.totalTX === 0)
    throw new Error('Empty vectors.');

  if (this.totalTX > constants.block.MAX_SIZE / 10)
    throw new Error('Compact block too big.');

  // No sparse arrays here, v8.
  for (i = 0; i < this.totalTX; i++)
    this.available.push(null);

  last = -1;

  for (i = 0; i < this.ptx.length; i++) {
    ptx = this.ptx[i];
    assert(ptx);
    last += ptx[0] + 1;
    assert(last <= 0xffff);
    assert(last <= this.ids.length + i);
    this.available[last] = ptx[1];
    this.count++;
  }

  offset = 0;

  for (i = 0; i < this.ids.length; i++) {
    while (this.available[i + offset])
      offset++;

    id = this.ids[i];

    // Fails on siphash collision
    assert(!this.idMap[id], 'Siphash collision.');

    this.idMap[id] = i + offset;

    // We're supposed to fail here if there's
    // more than 12 hash collisions, but we
    // don't have lowlevel access to our hash
    // table. Hopefully we don't get hashdos'd.
  }
};

CompactBlock.prototype.toBlock = function toBlock() {
  var block = new bcoin.block();
  var i, tx;

  block.version = this.version;
  block.prevBlock = this.prevBlock;
  block.merkleRoot = this.merkleRoot;
  block.ts = this.ts;
  block.bits = this.bits;
  block.nonce = this.nonce;
  block.totalTX = this.totalTX;
  block.txs = new Array(this.ptx.length);
  block._hash = this._hash;

  for (i = 0; i < this.available.length; i++) {
    tx = this.available[i];
    assert(tx, 'Compact block is not full.');
    tx.setBlock(block, i);
    block.txs[i] = tx;
  }

  return block;
};

CompactBlock.prototype.fromBlock = function fromBlock(block, nonce) {
  var i, tx, id;

  this.version = block.version;
  this.prevBlock = block.prevBlock;
  this.merkleRoot = block.merkleRoot;
  this.ts = block.ts;
  this.bits = block.bits;
  this.nonce = block.nonce;
  this.totalTX = block.totalTX;

  if (!nonce)
    nonce = utils.nonce(true);

  this.keyNonce = nonce;

  this.initKey();

  for (i = 1; i < block.txs.length; i++) {
    tx = block.txs[i];
    id = this.sid(tx.hash());
    this.ids.push(id);
  }

  this.ptx.push([0, block.txs[0]]);

  return this;
};

CompactBlock.fromBlock = function fromBlock(block, nonce) {
  return new CompactBlock().fromBlock(block, nonce);
};

CompactBlock.prototype.startTimeout = function startTimeout(time, callback) {
  assert(this.timeout == null);
  this.timeout = setTimeout(callback, time);
};

CompactBlock.prototype.stopTimeout = function stopTimeout() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

/**
 * Represents a BlockTransactionsRequest (bip152): `getblocktxn` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 */

function TXRequest(options) {
  if (!(this instanceof TXRequest))
    return new TXRequest(options);

  this.hash = null;
  this.indexes = [];

  if (options)
    this.fromOptions(options);
}

TXRequest.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.indexes)
    this.indexes = options.indexes;

  return this;
};

TXRequest.fromOptions = function fromOptions(options) {
  return new TXRequest().fromOptions(options);
};

TXRequest.prototype.fromCompact = function fromCompact(block) {
  var i;

  this.hash = block.hash('hex');

  for (i = 0; i < block.available.length; i++) {
    if (!block.available[i])
      this.indexes.push(i);
  }

  return this;
};

TXRequest.fromCompact = function fromCompact(block) {
  return new TXRequest().fromCompact(block);
};

TXRequest.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count, index, offset;

  this.hash = p.readHash('hex');

  count = p.readVarint();

  for (i = 0; i < count; i++) {
    index = p.readVarint();
    assert(index <= 0xffff);
    this.indexes.push(index);
  }

  offset = 0;

  for (i = 0; i < count; i++) {
    index = this.indexes[i];
    index += offset;
    assert(index <= 0xffff);
    this.indexes[i] = index;
    offset = index + 1;
  }

  return this;
};

TXRequest.fromRaw = function fromRaw(data) {
  return new TXRequest().fromRaw(data);
};

TXRequest.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);
  var i, index;

  p.writeHash(this.hash);

  p.writeVarint(this.indexes.length);

  for (i = 0; i < this.indexes.length; i++) {
    index = this.indexes[i] - (i === 0 ? 0 : this.indexes[i - 1] + 1);
    p.writeVarint(index);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Represents BlockTransactions (bip152): `blocktxn` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 */

function TXResponse(options) {
  if (!(this instanceof TXResponse))
    return new TXResponse(options);

  this.hash = null;
  this.txs = [];

  if (options)
    this.fromOptions(options);
}

TXResponse.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.txs)
    this.txs = options.txs;

  return this;
};

TXResponse.fromOptions = function fromOptions(options) {
  return new TXResponse().fromOptions(options);
};

TXResponse.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count;

  this.hash = p.readHash('hex');

  count = p.readVarint();

  for (i = 0; i < count; i++)
    this.txs.push(bcoin.tx.fromRaw(p));

  return this;
};

TXResponse.fromRaw = function fromRaw(data) {
  return new TXResponse().fromRaw(data);
};

TXResponse.prototype.fromBlock = function fromBlock(block, req) {
  var i, index;

  this.hash = req.hash;

  for (i = 0; i < req.indexes.length; i++) {
    index = req.indexes[i];
    if (index >= block.txs.length)
      return this;
    this.txs.push(block.txs[index]);
  }

  return this;
};

TXResponse.fromBlock = function fromBlock(block, req) {
  return new TXResponse().fromBlock(block, req);
};

TXResponse.prototype.toRaw = function toRaw(writer) {
  return this.frame(true, writer);
};

TXResponse.prototype.toNormal = function toNormal(writer) {
  return this.frame(false, writer);
};

TXResponse.prototype.frame = function frame(witness, writer) {
  var p = bcoin.writer(writer);
  var i, tx;

  p.writeHash(this.hash);

  p.writeVarint(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    if (witness)
      tx.toRaw(p);
    else
      tx.toNormal(p);
  }

  if (!writer)
    p = p.render();

  return p;
};

/*
 * Expose
 */

exports.CompactBlock = CompactBlock;
exports.TXRequest = TXRequest;
exports.TXResponse = TXResponse;
