/*!
 * writer.js - buffer writer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const enforce = require('./enforce');
const encoding = require('./encoding');
const EncodingError = require('./error');

/*
 * Constants
 */

const SEEK = 0;
const U8 = 1;
const U16 = 2;
const U16BE = 3;
const U24 = 4;
const U24BE = 5;
const U32 = 6;
const U32BE = 7;
const U40 = 8;
const U40BE = 9;
const U48 = 10;
const U48BE = 11;
const U56 = 12;
const U56BE = 13;
const U64 = 14;
const U64BE = 15;
const I8 = 16;
const I16 = 17;
const I16BE = 18;
const I24 = 19;
const I24BE = 20;
const I32 = 21;
const I32BE = 22;
const I40 = 23;
const I40BE = 24;
const I48 = 25;
const I48BE = 26;
const I56 = 27;
const I56BE = 28;
const I64 = 29;
const I64BE = 30;
const FL = 31;
const FLBE = 32;
const DBL = 33;
const DBLBE = 34;
const VARINT = 35;
const VARINT2 = 36;
const BYTES = 37;
const STR = 38;
const CHECKSUM = 39;
const FILL = 40;

/**
 * Buffer Writer
 */

class BufferWriter {
  /**
   * Create a buffer writer.
   * @constructor
   */

  constructor() {
    this.ops = [];
    this.offset = 0;
  }

  /**
   * Allocate and render the final buffer.
   * @returns {Buffer} Rendered buffer.
   */

  render() {
    const data = Buffer.allocUnsafeSlow(this.offset);

    let off = 0;

    for (const op of this.ops) {
      switch (op.type) {
        case SEEK:
          off += op.value;
          break;
        case U8:
          off = encoding.writeU8(data, op.value, off);
          break;
        case U16:
          off = encoding.writeU16(data, op.value, off);
          break;
        case U16BE:
          off = encoding.writeU16BE(data, op.value, off);
          break;
        case U24:
          off = encoding.writeU24(data, op.value, off);
          break;
        case U24BE:
          off = encoding.writeU24BE(data, op.value, off);
          break;
        case U32:
          off = encoding.writeU32(data, op.value, off);
          break;
        case U32BE:
          off = encoding.writeU32BE(data, op.value, off);
          break;
        case U40:
          off = encoding.writeU40(data, op.value, off);
          break;
        case U40BE:
          off = encoding.writeU40BE(data, op.value, off);
          break;
        case U48:
          off = encoding.writeU48(data, op.value, off);
          break;
        case U48BE:
          off = encoding.writeU48BE(data, op.value, off);
          break;
        case U56:
          off = encoding.writeU56(data, op.value, off);
          break;
        case U56BE:
          off = encoding.writeU56BE(data, op.value, off);
          break;
        case U64:
          off = encoding.writeU64(data, op.value, off);
          break;
        case U64BE:
          off = encoding.writeU64BE(data, op.value, off);
          break;
        case I8:
          off = encoding.writeI8(data, op.value, off);
          break;
        case I16:
          off = encoding.writeI16(data, op.value, off);
          break;
        case I16BE:
          off = encoding.writeI16BE(data, op.value, off);
          break;
        case I24:
          off = encoding.writeI24(data, op.value, off);
          break;
        case I24BE:
          off = encoding.writeI24BE(data, op.value, off);
          break;
        case I32:
          off = encoding.writeI32(data, op.value, off);
          break;
        case I32BE:
          off = encoding.writeI32BE(data, op.value, off);
          break;
        case I40:
          off = encoding.writeI40(data, op.value, off);
          break;
        case I40BE:
          off = encoding.writeI40BE(data, op.value, off);
          break;
        case I48:
          off = encoding.writeI48(data, op.value, off);
          break;
        case I48BE:
          off = encoding.writeI48BE(data, op.value, off);
          break;
        case I56:
          off = encoding.writeI56(data, op.value, off);
          break;
        case I56BE:
          off = encoding.writeI56BE(data, op.value, off);
          break;
        case I64:
          off = encoding.writeI64(data, op.value, off);
          break;
        case I64BE:
          off = encoding.writeI64BE(data, op.value, off);
          break;
        case FL:
          off = encoding.writeFloat(data, op.value, off);
          break;
        case FLBE:
          off = encoding.writeFloatBE(data, op.value, off);
          break;
        case DBL:
          off = encoding.writeDouble(data, op.value, off);
          break;
        case DBLBE:
          off = encoding.writeDoubleBE(data, op.value, off);
          break;
        case VARINT:
          off = encoding.writeVarint(data, op.value, off);
          break;
        case VARINT2:
          off = encoding.writeVarint2(data, op.value, off);
          break;
        case BYTES:
          off += op.data.copy(data, off);
          break;
        case STR:
          off += data.write(op.value, off, op.enc);
          break;
        case CHECKSUM:
          off += op.func(data.slice(0, off)).copy(data, off, 0, 4);
          break;
        case FILL:
          data.fill(op.value, off, off + op.size);
          off += op.size;
          break;
        default:
          throw new Error('Invalid type.');
      }
    }

    if (off !== data.length)
      throw new EncodingError(off, 'Out of bounds write');

    this.destroy();

    return data;
  }

  /**
   * Get size of data written so far.
   * @returns {Number}
   */

  getSize() {
    return this.offset;
  }

  /**
   * Seek to relative offset.
   * @param {Number} offset
   */

  seek(off) {
    enforce(Number.isSafeInteger(off), 'off', 'integer');

    if (this.offset + off < 0)
      throw new EncodingError(this.offset, 'Out of bounds write');

    this.offset += off;
    this.ops.push(new NumberOp(SEEK, off));

    return this;
  }

  /**
   * Destroy the buffer writer. Remove references to `ops`.
   */

  destroy() {
    this.ops.length = 0;
    this.offset = 0;
    return this;
  }

  /**
   * Write uint8.
   * @param {Number} value
   */

  writeU8(value) {
    this.offset += 1;
    this.ops.push(new NumberOp(U8, value));
    return this;
  }

  /**
   * Write uint16le.
   * @param {Number} value
   */

  writeU16(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(U16, value));
    return this;
  }

  /**
   * Write uint16be.
   * @param {Number} value
   */

  writeU16BE(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(U16BE, value));
    return this;
  }

  /**
   * Write uint24le.
   * @param {Number} value
   */

  writeU24(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(U24, value));
    return this;
  }

  /**
   * Write uint24be.
   * @param {Number} value
   */

  writeU24BE(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(U24BE, value));
    return this;
  }

  /**
   * Write uint32le.
   * @param {Number} value
   */

  writeU32(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(U32, value));
    return this;
  }

  /**
   * Write uint32be.
   * @param {Number} value
   */

  writeU32BE(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(U32BE, value));
    return this;
  }

  /**
   * Write uint40le.
   * @param {Number} value
   */

  writeU40(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(U40, value));
    return this;
  }

  /**
   * Write uint40be.
   * @param {Number} value
   */

  writeU40BE(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(U40BE, value));
    return this;
  }

  /**
   * Write uint48le.
   * @param {Number} value
   */

  writeU48(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(U48, value));
    return this;
  }

  /**
   * Write uint48be.
   * @param {Number} value
   */

  writeU48BE(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(U48BE, value));
    return this;
  }

  /**
   * Write uint56le.
   * @param {Number} value
   */

  writeU56(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(U56, value));
    return this;
  }

  /**
   * Write uint56be.
   * @param {Number} value
   */

  writeU56BE(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(U56BE, value));
    return this;
  }

  /**
   * Write uint64le.
   * @param {Number} value
   */

  writeU64(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(U64, value));
    return this;
  }

  /**
   * Write uint64be.
   * @param {Number} value
   */

  writeU64BE(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(U64BE, value));
    return this;
  }

  /**
   * Write int8.
   * @param {Number} value
   */

  writeI8(value) {
    this.offset += 1;
    this.ops.push(new NumberOp(I8, value));
    return this;
  }

  /**
   * Write int16le.
   * @param {Number} value
   */

  writeI16(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(I16, value));
    return this;
  }

  /**
   * Write int16be.
   * @param {Number} value
   */

  writeI16BE(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(I16BE, value));
    return this;
  }

  /**
   * Write int24le.
   * @param {Number} value
   */

  writeI24(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(I24, value));
    return this;
  }

  /**
   * Write int24be.
   * @param {Number} value
   */

  writeI24BE(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(I24BE, value));
    return this;
  }

  /**
   * Write int32le.
   * @param {Number} value
   */

  writeI32(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(I32, value));
    return this;
  }

  /**
   * Write int32be.
   * @param {Number} value
   */

  writeI32BE(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(I32BE, value));
    return this;
  }

  /**
   * Write int40le.
   * @param {Number} value
   */

  writeI40(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(I40, value));
    return this;
  }

  /**
   * Write int40be.
   * @param {Number} value
   */

  writeI40BE(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(I40BE, value));
    return this;
  }

  /**
   * Write int48le.
   * @param {Number} value
   */

  writeI48(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(I48, value));
    return this;
  }

  /**
   * Write int48be.
   * @param {Number} value
   */

  writeI48BE(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(I48BE, value));
    return this;
  }

  /**
   * Write int56le.
   * @param {Number} value
   */

  writeI56(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(I56, value));
    return this;
  }

  /**
   * Write int56be.
   * @param {Number} value
   */

  writeI56BE(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(I56BE, value));
    return this;
  }

  /**
   * Write int64le.
   * @param {Number} value
   */

  writeI64(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(I64, value));
    return this;
  }

  /**
   * Write int64be.
   * @param {Number} value
   */

  writeI64BE(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(I64BE, value));
    return this;
  }

  /**
   * Write float le.
   * @param {Number} value
   */

  writeFloat(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(FL, value));
    return this;
  }

  /**
   * Write float be.
   * @param {Number} value
   */

  writeFloatBE(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(FLBE, value));
    return this;
  }

  /**
   * Write double le.
   * @param {Number} value
   */

  writeDouble(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(DBL, value));
    return this;
  }

  /**
   * Write double be.
   * @param {Number} value
   */

  writeDoubleBE(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(DBLBE, value));
    return this;
  }

  /**
   * Write a varint.
   * @param {Number} value
   */

  writeVarint(value) {
    this.offset += encoding.sizeVarint(value);
    this.ops.push(new NumberOp(VARINT, value));
    return this;
  }

  /**
   * Write a varint (type 2).
   * @param {Number} value
   */

  writeVarint2(value) {
    this.offset += encoding.sizeVarint2(value);
    this.ops.push(new NumberOp(VARINT2, value));
    return this;
  }

  /**
   * Write bytes.
   * @param {Buffer} value
   */

  writeBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    if (value.length === 0)
      return this;

    this.offset += value.length;
    this.ops.push(new BufferOp(BYTES, value));

    return this;
  }

  /**
   * Write bytes with a varint length before them.
   * @param {Buffer} value
   */

  writeVarBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    this.offset += encoding.sizeVarint(value.length);
    this.ops.push(new NumberOp(VARINT, value.length));

    if (value.length === 0)
      return this;

    this.offset += value.length;
    this.ops.push(new BufferOp(BYTES, value));

    return this;
  }

  /**
   * Copy bytes.
   * @param {Buffer} value
   * @param {Number} start
   * @param {Number} end
   */

  copy(value, start, end) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');
    enforce((start >>> 0) === start, 'start', 'integer');
    enforce((end >>> 0) === end, 'end', 'integer');
    enforce(end >= start, 'start', 'integer');

    const buf = value.slice(start, end);

    this.writeBytes(buf);

    return this;
  }

  /**
   * Write string to buffer.
   * @param {String} value
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0)
      return this;

    this.offset += Buffer.byteLength(value, enc);
    this.ops.push(new StringOp(STR, value, enc));

    return this;
  }

  /**
   * Write a 32 byte hash.
   * @param {Hash} value
   */

  writeHash(value) {
    if (typeof value !== 'string') {
      enforce(Buffer.isBuffer(value), 'value', 'buffer');
      enforce(value.length === 32, 'value', '32-byte hash');
      this.writeBytes(value);
      return this;
    }

    enforce(value.length === 64, 'value', '32-byte hash');

    this.writeString(value, 'hex');

    return this;
  }

  /**
   * Write a string with a varint length before it.
   * @param {String}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeVarString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0) {
      this.ops.push(new NumberOp(VARINT, 0));
      return this;
    }

    const size = Buffer.byteLength(value, enc);

    this.offset += encoding.sizeVarint(size);
    this.offset += size;

    this.ops.push(new NumberOp(VARINT, size));
    this.ops.push(new StringOp(STR, value, enc));

    return this;
  }

  /**
   * Write a null-terminated string.
   * @param {String|Buffer}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeNullString(value, enc) {
    this.writeString(value, enc);
    this.writeU8(0);
    return this;
  }

  /**
   * Calculate and write a checksum for the data written so far.
   * @param {Function} hash
   */

  writeChecksum(hash) {
    if (hash && typeof hash.digest === 'function')
      hash = hash.digest.bind(hash);

    enforce(typeof hash === 'function', 'hash', 'function');

    this.offset += 4;
    this.ops.push(new FunctionOp(CHECKSUM, hash));

    return this;
  }

  /**
   * Fill N bytes with value.
   * @param {Number} value
   * @param {Number} size
   */

  fill(value, size) {
    enforce((value & 0xff) === value, 'value', 'byte');
    enforce((size >>> 0) === size, 'size', 'integer');

    if (size === 0)
      return this;

    this.offset += size;
    this.ops.push(new FillOp(FILL, value, size));

    return this;
  }
}

/*
 * Helpers
 */

class WriteOp {
  constructor(type) {
    this.type = type;
  }
}

class NumberOp extends WriteOp {
  constructor(type, value) {
    super(type);
    this.value = value;
  }
}

class BufferOp extends WriteOp {
  constructor(type, data) {
    super(type);
    this.data = data;
  }
}

class StringOp extends WriteOp {
  constructor(type, value, enc) {
    super(type);
    this.value = value;
    this.enc = enc;
  }
}

class FunctionOp extends WriteOp {
  constructor(type, func) {
    super(type);
    this.func = func;
  }
}

class FillOp extends WriteOp {
  constructor(type, value, size) {
    super(type);
    this.value = value;
    this.size = size;
  }
}

/*
 * Expose
 */

module.exports = BufferWriter;
