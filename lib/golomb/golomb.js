/*!
 * golomb.js - gcs filters for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {U64} = require('n64');
const hash256 = require('bcrypto/lib/hash256');
const {sipmod} = require('bcrypto/lib/siphash');
const bio = require('bufio');
const {BufferSet} = require('buffer-map');
const BitWriter = require('./writer');
const BitReader = require('./reader');

/*
 * Constants
 */

const DUMMY = Buffer.alloc(0);
const EOF = new U64(-1);

/**
 * Golomb - BIP 158 block filters
 * @alias module:golomb.Golomb
 * @see https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
 * @property {Number} m
 * @property {Number} n
 * @property {Number} p
 * @property {Buffer} data
 */

class Golomb {
  /**
   * Create a block filter.
   * @constructor
   */

  constructor(p,m) {
    assert(p<32 && p>=0);
    assert(m instanceof U64);

    this.n = 0;
    this.p = p;
    this.m = m;
    this.M = this.m;
    this.data = DUMMY;
  }

  /**
   * Hash the block filter.
   * @param {String?} enc - Can be `'hex'` or `null`.
   * @returns {Hash|Buffer} hash
   */

  hash(enc) {
    const h = hash256.digest(this.toNBytes());
    return enc === 'hex' ? h.toString('hex') : h;
  }

  /**
   * Get the block filter header.
   * hash of block filter concatenated with previous block filter header.
   * @param {Hash} prev - previous filter header.
   * @returns {Hash|Buffer} hash
   */

  header(prev) {
    return hash256.root(this.hash(), prev);
  }

  /**
   * Get the membership of given item in the block filter.
   * @param {Buffer} key - 128-bit key.
   * @param {Buffer} data - item.
   * @returns {Boolean} match
   */

  match(key, data) {
    const br = new BitReader(this.data);
    const term = sipmod64(data, key, this.m);

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
  }

  /**
   * Get the membership of any item of given items in the block filter.
   * @param {Buffer} key - 128-bit key.
   * @param {Buffer[]} items.
   * @returns {Boolean} match
   */

  matchAny(key, items) {
    items = new BufferSet(items);
    assert(items.size > 0);

    const br = new BitReader(this.data);
    const last1 = new U64(0);
    const values = [];

    for (const item of items) {
      const hash = sipmod64(item, key, this.m);
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
  }

  /**
   * Read uint64 from a bit reader.
   * @param {BufferReader} br {@link BitReader}
   */

  readU64(br) {
    try {
      return this._readU64(br);
    } catch (e) {
      if (e.message === 'EOF')
        return EOF;
      throw e;
    }
  }

  /**
   * Read uint64 from a bit reader.
   * @param {BufferReader} br {@link BitReader}
   * @throws on EOF
   */

  _readU64(br) {
    const num = new U64(0);

    // Unary
    while (br.readBit())
      num.iaddn(1);

    const rem = br.readBits64(this.p);

    return num.ishln(this.p).ior(rem);
  }

  /**
   * Serialize the block filter as raw filter bytes.
   * @returns {Buffer} filter
   */

  toBytes() {
    return this.data;
  }

  /**
   * Serialize the block filter as N and raw filter bytes
   * @returns {Buffer} filter
   */

  toNBytes() {
    const bw = bio.write();
    bw.writeVarint(this.n);
    bw.writeBytes(this.data);
    return bw.render();
  }

  /**
   * Serialize the block filter as default filter bytes.
   * @returns {Buffer} filter
   */

  toRaw() {
    assert(this.p < 32);
    return this.toNBytes();
  }

  /**
   * Instantiate a block filter from a 128-bit key and items.
   * @param {Buffer} key - 128-bit key.
   * @param {Buffer[]} items
   * @returns {Golomb}
   */

  fromItems(key, items) {
    items = new BufferSet(items);

    assert(Buffer.isBuffer(key));
    assert(key.length === 16);

    assert(items.size >= 0);
    assert(items.size <= 0xffffffff);

    this.n = items.size;
    this.m = this.M.mul(new U64(this.n));

    const values = [];

    for (const item of items) {
      assert(Buffer.isBuffer(item));
      const hash = sipmod64(item, key, this.m);
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
  }

  /**
   * Instantiate a block filter from an N, and raw data.
   * @param {Number} N
   * @param {Buffer} data
   * @returns {Golomb}
   */

  fromBytes(N, data) {
    assert(typeof N === 'number' && isFinite(N));
    assert(Buffer.isBuffer(data));

    this.n = N;
    this.m = this.M.mul(new U64(this.n));
    this.data = data;

    return this;
  }

  /**
   * Instantiate a block filter from raw data.
   * @param {Buffer} data
   * @returns {Golomb}
   */

  fromNBytes(data) {
    const br = bio.read(data);
    const N = br.readVarint();
    return this.fromBytes(N, data.slice(bio.sizeVarint(N)));
  }

  /**
   * Instantiate a block filter from raw data.
   * @param {Buffer} data
   * @returns {Golomb}
   */

  fromRaw(data) {
    return this.fromNBytes(data);
  }
}

/*
 * Helpers
 */

function sipmod64(data, key, m) {
  const [hi, lo] = sipmod(data, key, m.hi, m.lo);
  return U64.fromBits(hi, lo);
}

function compare(a, b) {
  return a.cmp(b);
}

/*
 * Expose
 */

module.exports = Golomb;
