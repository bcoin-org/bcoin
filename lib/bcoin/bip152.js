/*!
 * bip152.js - compact block object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var siphash = require('./siphash');
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
  this.k0 = null;
  this.k1 = null;

  if (options)
    this.fromOptions(options);
}

utils.inherits(CompactBlock, AbstractBlock);

CompactBlock.prototype._verify = function _verify(ret) {
  return this.verifyHeaders(ret);
};

CompactBlock.prototype.fromOptions = function fromOptions(options) {
  assert(bn.isBN(options.keyNonce));
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

  this.k0 = options.k0;
  this.k1 = options.k1;

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

  this.keyNonce = p.readU64();

  this.initKey();

  count = p.readVarint2();

  this.totalTX += count;

  for (i = 0; i < count; i++)
    this.ids.push(p.readU32() + p.readU16() * 0x100000000);

  count = p.readVarint2();

  this.totalTX += count;

  for (i = 0; i < count; i++) {
    index = p.readVarint2();
    assert(index <= 0xffff);
    assert(index < this.totalTX);
    tx = bcoin.tx.fromRaw(p);
    this.ptx.push([index, tx]);
  }

  this.init();

  return this;
};

CompactBlock.fromRaw = function fromRaw(data) {
  return new CompactBlock().fromRaw(data);
};

CompactBlock.prototype.toRaw = function toRaw(witness, writer) {
  var p = bcoin.writer(writer);
  var i, id, lo, hi, ptx;

  p.write32(this.version);
  p.writeHash(this.prevBlock);
  p.writeHash(this.merkleRoot);
  p.writeU32(this.ts);
  p.writeU32(this.bits);
  p.writeU32(this.nonce);

  p.writeU64(this.keyNonce);

  p.writeVarint2(this.ids.length);

  for (i = 0; i < this.ids.length; i++) {
    id = this.ids[i];
    lo = id % 0x100000000;
    hi = (id - lo) / 0x100000000;
    hi &= 0xffff;
    p.writeU32(lo);
    p.writeU16(hi);
  }

  p.writeVarint2(this.ptx.length);

  for (i = 0; i < this.ptx.length; i++) {
    ptx = this.ptx[i];
    p.writeVarint2(ptx[0]);
    if (!witness)
      ptx[1].toNormal(p);
    else
      ptx[1].toRaw(p);
  }

  if (!writer)
    p = p.render();

  return p;
};

CompactBlock.prototype.toRequest = function toRequest() {
  return BlockTXRequest.fromCompact(this);
};

CompactBlock.prototype.fillMempool = function fillMempool(mempool, callback) {
  var self = this;
  var have = {};
  var id, index;

  mempool.getSnapshot(function(err, hashes) {
    if (err)
      return callback(err);

    utils.forEachSerial(hashes, function(hash, next) {
      id = self.sid(hash);
      index = self.idMap[id];

      if (index == null)
        return next();

      if (have[index]) {
        // Siphash collision, just request it.
        self.available[index] = null;
        self.count--;
        return next();
      }

      mempool.getTX(hash, function(err, tx) {
        if (err)
          return callback(err);

        // Race condition: tx
        // fell out of mempool.
        if (!tx)
          return next();

        self.available[index] = tx;
        have[index] = true;
        self.count++;

        // We actually may have a siphash collision
        // here, but exit early anyway for perf.
        if (self.count === self.totalTX)
          return callback(null, true);

        next();
      });
    }, callback);
  });
};

CompactBlock.prototype.fillMissing = function fillMissing(missing) {
  var offset = 0;
  var i;

  for (i = 0; i < this.available.length; i++) {
    if (this.available[i])
      continue;

    if (offset >= missing.length)
      return false;

    this.available = missing[offset++];
  }

  return offset === missing.length;
};

CompactBlock.prototype.sid = function sid(hash) {
  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  hash = siphash(hash, this.k0, this.k1);

  return hash.readUInt32LE(2, true)
    + hash.readUInt16LE(6, true)
    * 0x100000000;
};

CompactBlock.prototype.hasIndex = function hasIndex(index) {
  return this.available[index] != null;
};

CompactBlock.prototype.initKey = function initKey() {
  var nonce = this.keyNonce.toArrayLike(Buffer, 'be', 8);
  var data = Buffer.concat([this.abbr(), nonce]);
  var hash = utils.sha256(data);
  this.k0 = hash.slice(0, 8);
  this.k1 = hash.slice(8, 16);
};

CompactBlock.prototype.init = function init() {
  var i, last, ptx, offset;

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
    this.idMap[this.ids[i]] = i + offset;
    // We're supposed to fail here if there's
    // more than 12 hash collisions, but we
    // don't have lowlevel access to our hash
    // table. Hopefully we don't get hashdos'd.
  }

  // Fails on siphash collision
  assert(this.ids.length === Object.keys(this.idMap).length);
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
  block._valid = this._valid;

  for (i = 0; i < this.available.length; i++) {
    tx = this.available[i];
    assert(tx, 'Compact block is not full.');
    tx.setBlock(block, i);
    block.txs[i] = tx;
  }

  return block;
};

CompactBlock.prototype.fromBlock = function fromBlock(block) {
  var i, tx, id;

  this.version = block.version;
  this.prevBlock = block.prevBlock;
  this.merkleRoot = block.merkleRoot;
  this.ts = block.ts;
  this.bits = block.bits;
  this.nonce = block.nonce;
  this.totalTX = block.totalTX;

  this.keyNonce = utils.nonce();

  this.initKey();

  for (i = 1; i < block.txs.length; i++) {
    tx = block.txs[i];
    id = this.sid(tx.hash());
    this.ids.push(id);
  }

  this.ptx.push([0, block.txs[0]]);

  return this;
};

CompactBlock.fromBlock = function fromBlock(block) {
  return new CompactBlock().fromBlock(block);
};

/**
 * Represents a BlockTransactionsRequest (bip152): `getblocktxn` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 */

function BlockTXRequest(options) {
  if (!(this instanceof BlockTXRequest))
    return new BlockTXRequest(options);

  this.hash = null;
  this.indexes = [];

  if (options)
    this.fromOptions(options);
}

BlockTXRequest.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.indexes)
    this.indexes = options.indexes;

  return this;
};

BlockTXRequest.fromOptions = function fromOptions(options) {
  return new BlockTXRequest().fromOptions(options);
};

BlockTXRequest.prototype.fromCompact = function fromCompact(block) {
  var i;

  this.hash = block.hash('hex');

  for (i = 0; i < block.available.length; i++) {
    if (!block.available[i])
      this.indexes.push(i);
  }

  return this;
};

BlockTXRequest.fromCompact = function fromCompact(block) {
  return new BlockTXRequest().fromCompact(block);
};

BlockTXRequest.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count, index, offset;

  this.hash = p.readHash('hex');

  count = p.readVarint2();

  for (i = 0; i < count; i++) {
    index = p.readVarint2();
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

BlockTXRequest.fromRaw = function fromRaw(data) {
  return new BlockTXRequest().fromRaw(data);
};

BlockTXRequest.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);
  var i, index;

  p.writeHash(this.hash);

  p.writeVarint2(this.indexes.length);

  for (i = 0; i < this.indexes.length; i++) {
    index = this.indexes[i] - (i === 0 ? 0 : this.indexes[i - 1] + 1);
    p.writeVarint2(index);
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

function BlockTX(options) {
  if (!(this instanceof BlockTX))
    return new BlockTX(options);

  this.hash = null;
  this.txs = [];

  if (options)
    this.fromOptions(options);
}

BlockTX.prototype.fromOptions = function fromOptions(options) {
  this.hash = options.hash;

  if (options.txs)
    this.txs = options.txs;

  return this;
};

BlockTX.fromOptions = function fromOptions(options) {
  return new BlockTX().fromOptions(options);
};

BlockTX.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  var i, count;

  this.hash = p.readHash('hex');

  count = p.readVarint2();

  for (i = 0; i < count; i++)
    this.txs.push(bcoin.tx.fromRaw(p));

  return this;
};

BlockTX.fromRaw = function fromRaw(data) {
  return new BlockTX().fromRaw(data);
};

BlockTX.prototype.fromBlock = function fromBlock(block, request) {
  var i, index;

  this.hash = request.hash;

  for (i = 0; i < request.indexes.length; i++) {
    index = request.indexes[i];
    if (index >= block.txs.length)
      return;
    this.txs.push(block.txs[index]);
  }

  return this;
};

BlockTX.fromBlock = function fromBlock(block, request) {
  return new BlockTX().fromBlock(block, request);
};

BlockTX.prototype.toRaw = function toRaw(witness, writer) {
  var p = bcoin.writer(writer);
  var i, tx;

  p.writeHash(this.hash);

  p.writeVarint2(this.txs.length);

  for (i = 0; i < this.txs.length; i++) {
    tx = this.txs[i];
    if (!witness)
      tx.toNormal(p);
    else
      tx.toRaw(p);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Represents a SendCompact message (bip152): `sendcmpct` packet.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
 * @constructor
 */

// NOTE TO SELF: Protocol version >= 70014
function SendCompact(mode, version) {
  if (!(this instanceof SendCompact))
    return new SendCompact(mode, version);

  this.mode = mode || 0;
  this.version = version || 1;
}

SendCompact.prototype.fromRaw = function fromRaw(data) {
  var p = bcoin.reader(data);
  this.mode = p.readU8();
  this.version = p.readU53();
  return this;
};

SendCompact.fromRaw = function fromRaw(data) {
  return new SendCompact().fromRaw(data);
};

SendCompact.prototype.toRaw = function toRaw(writer) {
  var p = bcoin.writer(writer);

  p.writeU8(this.mode);
  p.writeU64(this.version);

  if (!writer)
    p = p.render();

  return p;
};

/*
 * Expose
 */

exports.CompactBlock = CompactBlock;
exports.BlockTXRequest = BlockTXRequest;
exports.BlockTX = BlockTX;
exports.SendCompact = SendCompact;
