/*!
 * gcs.js - gcs filters for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {U64} = require('./int64');
const digest = require('../crypto/digest');
const siphash = require('../crypto/siphash');
const DUMMY = Buffer.alloc(0);
const EOF = new U64(-1);

/**
 * GCSFilter
 * @alias module:utils.GCSFilter
 * @constructor
 */

function GCSFilter() {
  this.n = 0;
  this.p = 0;
  this.m = new U64(0);
  this.data = DUMMY;
}

GCSFilter.prototype.hash = function hash(enc) {
  const h = digest.hash256(this.data);
  return enc === 'hex' ? h.toString('hex') : h;
};

GCSFilter.prototype.header = function header(prev) {
  return digest.root256(this.hash(), prev);
};

GCSFilter.prototype.match = function match(key, data) {
  const br = new BitReader(this.data);
  const term = siphash24(data, key).imod(this.m);
  let last = new U64(0);

  while (last.lt(term)) {
    const value = this.readU64(br);

    if (value === EOF)
      return false;

    value.iadd(last);

    if (value.eq(term))
      return true;

    last = value;
  }

  return false;
};

GCSFilter.prototype.matchAny = function matchAny(key, items) {
  assert(items.length > 0);

  const br = new BitReader(this.data);
  const last1 = new U64(0);
  const values = [];

  for (const item of items) {
    const hash = siphash24(item, key).imod(this.m);
    values.push(hash);
  }

  values.sort(compare);

  let last2 = values[0];
  let i = 1;

  for (;;) {
    const cmp = last1.cmp(last2);

    if (cmp === 0)
      break;

    if (cmp > 0) {
      if (i < values.length) {
        last2 = values[i];
        i += 1;
        continue;
      }
      return false;
    }

    const value = this.readU64(br);

    if (value === EOF)
      return false;

    last1.iadd(value);
  }

  return true;
};

GCSFilter.prototype.readU64 = function readU64(br) {
  try {
    return this._readU64(br);
  } catch (e) {
    if (e.message === 'EOF')
      return EOF;
    throw e;
  }
};

GCSFilter.prototype._readU64 = function _readU64(br) {
  const num = new U64(0);

  // Unary
  while (br.readBit())
    num.iaddn(1);

  const rem = br.readBits64(this.p);

  return num.ishln(this.p).ior(rem);
};

GCSFilter.prototype.toBytes = function toBytes() {
  return this.data;
};

GCSFilter.prototype.toNBytes = function toNBytes() {
  const data = Buffer.allocUnsafe(4 + this.data.length);
  data.writeUInt32BE(this.n, 0, true);
  this.data.copy(data, 4);
  return data;
};

GCSFilter.prototype.toPBytes = function toPBytes() {
  const data = Buffer.allocUnsafe(1 + this.data.length);
  data.writeUInt8(this.p, 0, true);
  this.data.copy(data, 1);
  return data;
};

GCSFilter.prototype.toNPBytes = function toNPBytes() {
  const data = Buffer.allocUnsafe(5 + this.data.length);
  data.writeUInt32BE(this.n, 0, true);
  data.writeUInt8(this.p, 4, true);
  this.data.copy(data, 5);
  return data;
};

GCSFilter.prototype.toRaw = function toRaw() {
  assert(this.p === 20);
  return this.toNBytes();
};

GCSFilter.prototype.fromItems = function fromItems(P, key, items) {
  assert(typeof P === 'number' && isFinite(P));
  assert(P >= 0 && P <= 32);

  assert(Buffer.isBuffer(key));
  assert(key.length === 16);

  assert(Array.isArray(items));
  assert(items.length > 0);
  assert(items.length <= 0xffffffff);

  this.n = items.length;
  this.p = P;
  this.m = U64(this.n).ishln(this.p);

  const values = [];

  for (const item of items) {
    assert(Buffer.isBuffer(item));
    const hash = siphash24(item, key).imod(this.m);
    values.push(hash);
  }

  values.sort(compare);

  const bw = new BitWriter();
  let last = new U64(0);

  for (const hash of values) {
    const rem = hash.sub(last).imaskn(this.p);
    const value = hash.sub(last).isub(rem).ishrn(this.p);

    last = hash;

    // Unary
    while (!value.isZero()) {
      bw.writeBit(1);
      value.isubn(1);
    }
    bw.writeBit(0);

    bw.writeBits64(rem, this.p);
  }

  this.data = bw.render();

  return this;
};

GCSFilter.prototype.fromBytes = function fromBytes(N, P, data) {
  assert(typeof N === 'number' && isFinite(N));
  assert(typeof P === 'number' && isFinite(P));
  assert(P >= 0 && P <= 32);
  assert(Buffer.isBuffer(data));

  this.n = N;
  this.p = P;
  this.m = U64(this.n).ishln(this.p);
  this.data = data;

  return this;
};

GCSFilter.prototype.fromNBytes = function fromNBytes(P, data) {
  assert(typeof P === 'number' && isFinite(P));
  assert(Buffer.isBuffer(data));
  assert(data.length >= 4);

  const N = data.readUInt32BE(0, true);

  return this.fromBytes(N, P, data.slice(4));
};

GCSFilter.prototype.fromPBytes = function fromPBytes(N, data) {
  assert(typeof N === 'number' && isFinite(N));
  assert(Buffer.isBuffer(data));
  assert(data.length >= 1);

  const P = data.readUInt8(0, true);

  return this.fromBytes(N, P, data.slice(1));
};

GCSFilter.prototype.fromNPBytes = function fromNPBytes(data) {
  assert(Buffer.isBuffer(data));
  assert(data.length >= 5);

  const N = data.readUInt32BE(0, true);
  const P = data.readUInt8(4, true);

  return this.fromBytes(N, P, data.slice(5));
};

GCSFilter.prototype.fromRaw = function fromRaw(data) {
  return this.fromNBytes(20, data);
};

GCSFilter.prototype.fromBlock = function fromBlock(block) {
  const hash = block.hash();
  const key = hash.slice(0, 16);
  const items = [];

  for (let i = 0; i < block.txs.length; i++) {
    const tx = block.txs[i];

    if (i > 0) {
      for (const input of tx.inputs)
        items.push(input.prevout.toRaw());
    }

    for (const output of tx.outputs)
      getPushes(items, output.script);
  }

  return this.fromItems(20, key, items);
};

GCSFilter.prototype.fromExtended = function fromExtended(block) {
  const hash = block.hash();
  const key = hash.slice(0, 16);
  const items = [];

  for (let i = 0; i < block.txs.length; i++) {
    const tx = block.txs[i];

    items.push(tx.hash());

    if (i > 0) {
      for (const input of tx.inputs) {
        getWitness(items, input.witness);
        getPushes(items, input.script);
      }
    }
  }

  return this.fromItems(20, key, items);
};

GCSFilter.fromItems = function fromItems(P, key, items) {
  return new GCSFilter().fromItems(P, key, items);
};

GCSFilter.fromBytes = function fromBytes(N, P, data) {
  return new GCSFilter().fromBytes(N, P, data);
};

GCSFilter.fromNBytes = function fromNBytes(P, data) {
  return new GCSFilter().fromNBytes(P, data);
};

GCSFilter.fromPBytes = function fromPBytes(N, data) {
  return new GCSFilter().fromPBytes(N, data);
};

GCSFilter.fromNPBytes = function fromNPBytes(data) {
  return new GCSFilter().fromNPBytes(data);
};

GCSFilter.fromRaw = function fromRaw(data) {
  return new GCSFilter().fromRaw(data);
};

GCSFilter.fromBlock = function fromBlock(block) {
  return new GCSFilter().fromBlock(block);
};

GCSFilter.fromExtended = function fromExtended(block) {
  return new GCSFilter().fromExtended(block);
};

/**
 * BitWriter
 * @constructor
 * @ignore
 */

function BitWriter() {
  this.stream = [];
  this.remain = 0;
}

BitWriter.prototype.writeBit = function writeBit(bit) {
  if (this.remain === 0) {
    this.stream.push(0);
    this.remain = 8;
  }

  if (bit) {
    const index = this.stream.length - 1;
    this.stream[index] |= 1 << (this.remain - 1);
  }

  this.remain--;
};

BitWriter.prototype.writeByte = function writeByte(ch) {
  if (this.remain === 0) {
    this.stream.push(0);
    this.remain = 8;
  }

  const index = this.stream.length - 1;

  this.stream[index] |= (ch >> (8 - this.remain)) & 0xff;
  this.stream.push(0);
  this.stream[index + 1] = (ch << this.remain) & 0xff;
};

BitWriter.prototype.writeBits = function writeBits(num, count) {
  assert(count >= 0);
  assert(count <= 32);

  num <<= 32 - count;

  while (count >= 8) {
    const ch = num >>> 24;
    this.writeByte(ch);
    num <<= 8;
    count -= 8;
  }

  while (count > 0) {
    const bit = num >>> 31;
    this.writeBit(bit);
    num <<= 1;
    count -= 1;
  }
};

BitWriter.prototype.writeBits64 = function writeBits64(num, count) {
  assert(count >= 0);
  assert(count <= 64);

  if (count > 32) {
    this.writeBits(num.hi, count - 32);
    this.writeBits(num.lo, 32);
  } else {
    this.writeBits(num.lo, count);
  }
};

BitWriter.prototype.render = function render() {
  const data = Buffer.allocUnsafe(this.stream.length);

  for (let i = 0; i < this.stream.length; i++)
    data[i] = this.stream[i];

  return data;
};

/**
 * BitReader
 * @constructor
 * @ignore
 */

function BitReader(data) {
  this.stream = data;
  this.pos = 0;
  this.remain = 8;
}

BitReader.prototype.readBit = function readBit() {
  if (this.pos >= this.stream.length)
    throw new Error('EOF');

  if (this.remain === 0) {
    this.pos += 1;

    if (this.pos >= this.stream.length)
      throw new Error('EOF');

    this.remain = 8;
  }

  this.remain -= 1;

  return (this.stream[this.pos] >> this.remain) & 1;
};

BitReader.prototype.readByte = function readByte() {
  if (this.pos >= this.stream.length)
    throw new Error('EOF');

  if (this.remain === 0) {
    this.pos += 1;

    if (this.pos >= this.stream.length)
      throw new Error('EOF');

    this.remain = 8;
  }

  if (this.remain === 8) {
    const ch = this.stream[this.pos];
    this.pos += 1;
    return ch;
  }

  let ch = this.stream[this.pos] & ((1 << this.remain) - 1);
  ch <<= 8 - this.remain;

  this.pos += 1;

  if (this.pos >= this.stream.length)
    throw new Error('EOF');

  ch |= this.stream[this.pos] >> this.remain;

  return ch;
};

BitReader.prototype.readBits = function readBits(count) {
  assert(count >= 0);
  assert(count <= 32);

  let num = 0;

  while (count >= 8) {
    num <<= 8;
    num |= this.readByte();
    count -= 8;
  }

  while (count > 0) {
    num <<= 1;
    num |= this.readBit();
    count -= 1;
  }

  return num;
};

BitReader.prototype.readBits64 = function readBits64(count) {
  assert(count >= 0);
  assert(count <= 64);

  const num = new U64();

  if (count > 32) {
    num.hi = this.readBits(count - 32);
    num.lo = this.readBits(32);
  } else {
    num.lo = this.readBits(count);
  }

  return num;
};

/*
 * Helpers
 */

function compare(a, b) {
  return a.cmp(b) < 0 ? -1 : 1;
}

function siphash24(data, key) {
  const [hi, lo] = siphash(data, key);
  return U64.fromBits(hi, lo);
}

function getPushes(items, script) {
  for (const op of script.code) {
    if (!op.data || op.data.length === 0)
      continue;

    items.push(op.data);
  }
}

function getWitness(items, witness) {
  for (const item of witness.items) {
    if (item.length === 0)
      continue;

    items.push(item);
  }
}

/*
 * Expose
 */

module.exports = GCSFilter;
