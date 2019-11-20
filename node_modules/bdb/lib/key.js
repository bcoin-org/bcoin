/**
 * key.js - key compiler for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const keyCache = Object.create(null);

const BUFFER_MIN = Buffer.alloc(0);
const BUFFER_MAX = Buffer.alloc(255, 0xff);

/*
 * Key Ops
 */

const types = {
  char: {
    min: '\x00',
    max: '\xff',
    dynamic: false,
    size(v) {
      return 1;
    },
    read(k, o) {
      assertLen(o + 1 <= k.length);
      return String.fromCharCode(k[o]);
    },
    write(k, v, o) {
      assertType(typeof v === 'string');
      assertType(v.length === 1);
      assertLen(o + 1 <= k.length);
      k[o] = v.charCodeAt(0);
      return 1;
    }
  },
  uint8: {
    min: 0,
    max: 0xff,
    dynamic: false,
    size(v) {
      return 1;
    },
    read(k, o) {
      assertLen(o + 1 <= k.length);
      return k[o];
    },
    write(k, v, o) {
      assertType((v & 0xff) === v);
      assertLen(o + 1 <= k.length);
      k[o] = v;
      return 1;
    }
  },
  uint16: {
    min: 0,
    max: 0xffff,
    dynamic: false,
    size(v) {
      return 2;
    },
    read(k, o) {
      assertLen(o + 2 <= k.length);
      return readU16BE(k, o);
    },
    write(k, v, o) {
      assertType((v & 0xffff) === v);
      assertLen(o + 2 <= k.length);
      writeU16BE(k, v, o);
      return 2;
    }
  },
  uint32: {
    min: 0,
    max: 0xffffffff,
    dynamic: false,
    size(v) {
      return 4;
    },
    read(k, o) {
      assertLen(o + 4 <= k.length);
      return readU32BE(k, o);
    },
    write(k, v, o) {
      assertType((v >>> 0) === v);
      assertLen(o + 4 <= k.length);
      writeU32BE(k, v, o);
      return 4;
    }
  },
  buffer: {
    min: BUFFER_MIN,
    max: BUFFER_MAX,
    dynamic: true,
    size(v) {
      return sizeBuffer(v);
    },
    read(k, o) {
      return readBuffer(k, o);
    },
    write(k, v, o) {
      return writeBuffer(k, v, o);
    }
  },
  hex: {
    min: BUFFER_MIN.toString('hex'),
    max: BUFFER_MAX.toString('hex'),
    dynamic: true,
    size(v) {
      return sizeString(v, 'hex');
    },
    read(k, o) {
      return readString(k, o, 'hex');
    },
    write(k, v, o) {
      return writeString(k, v, o, 'hex');
    }
  },
  ascii: {
    min: BUFFER_MIN.toString('binary'),
    max: BUFFER_MAX.toString('binary'),
    dynamic: true,
    size(v) {
      return sizeString(v, 'binary');
    },
    read(k, o) {
      return readString(k, o, 'binary');
    },
    write(k, v, o) {
      return writeString(k, v, o, 'binary');
    }
  },
  utf8: {
    min: BUFFER_MIN.toString('utf8'),
    max: BUFFER_MAX.toString('utf8'),
    dynamic: true,
    size(v) {
      return sizeString(v, 'utf8');
    },
    read(k, o) {
      return readString(k, o, 'utf8');
    },
    write(k, v, o) {
      return writeString(k, v, o, 'utf8');
    }
  },
  hash160: {
    min: Buffer.alloc(20, 0x00),
    max: Buffer.alloc(20, 0xff),
    dynamic: false,
    size(v) {
      return 20;
    },
    read(k, o) {
      assertLen(o + 20 <= k.length);
      return k.slice(o, o + 20);
    },
    write(k, v, o) {
      assertType(Buffer.isBuffer(v));
      assertType(v.copy(k, o) === 20);
      return 20;
    }
  },
  hash256: {
    min: Buffer.alloc(32, 0x00),
    max: Buffer.alloc(32, 0xff),
    dynamic: false,
    size(v) {
      return 32;
    },
    read(k, o) {
      assertLen(o + 32 <= k.length);
      return k.slice(o, o + 32);
    },
    write(k, v, o) {
      assertType(Buffer.isBuffer(v));
      assertType(v.copy(k, o) === 32);
      return 32;
    }
  },
  hash: {
    min: Buffer.alloc(1, 0x00),
    max: Buffer.alloc(64, 0xff),
    dynamic: true,
    size(v) {
      assertType(Buffer.isBuffer(v));
      return 1 + v.length;
    },
    read(k, o) {
      assertLen(o + 1 <= k.length);
      assertLen(k[o] >= 1 && k[o] <= 64);
      assertLen(o + 1 + k[o] <= k.length);
      return k.slice(o + 1, o + 1 + k[o]);
    },
    write(k, v, o) {
      assertType(Buffer.isBuffer(v));
      assertType(v.length >= 1 && v.length <= 64);
      assertLen(o + 1 <= k.length);

      k[o] = v.length;

      assertType(v.copy(k, o + 1) === v.length);

      return 1 + v.length;
    }
  },
  hhash160: {
    min: Buffer.alloc(20, 0x00),
    max: Buffer.alloc(20, 0xff),
    dynamic: false,
    size(v) {
      return 20;
    },
    read(k, o) {
      assertLen(o + 20 <= k.length);
      return k.toString('hex', o, o + 20);
    },
    write(k, v, o) {
      assertType(writeHex(k, v, o) === 20);
      return 20;
    }
  },
  hhash256: {
    min: Buffer.alloc(32, 0x00),
    max: Buffer.alloc(32, 0xff),
    dynamic: false,
    size(v) {
      return 32;
    },
    read(k, o) {
      assertLen(o + 32 <= k.length);
      return k.toString('hex', o, o + 32);
    },
    write(k, v, o) {
      assertType(writeHex(k, v, o) === 32);
      return 32;
    }
  },
  hhash: {
    min: Buffer.alloc(1, 0x00),
    max: Buffer.alloc(64, 0xff),
    dynamic: true,
    size(v) {
      return 1 + sizeHex(v);
    },
    read(k, o) {
      assertLen(o + 1 <= k.length);
      assertLen(k[o] >= 1 && k[o] <= 64);
      assertLen(o + 1 + k[o] <= k.length);
      return k.toString('hex', o + 1, o + 1 + k[o]);
    },
    write(k, v, o) {
      const size = sizeHex(v);

      assertType(size >= 1 && size <= 64);
      assertLen(o + 1 <= k.length);

      k[o] = size;

      assertType(writeHex(k, v, o + 1) === size);

      return 1 + size;
    }
  }
};

/**
 * BaseKey
 * @ignore
 */

class BaseKey {
  /**
   * Create a base key.
   * @constructor
   * @param {String[]|null} ops
   */

  constructor(ops = []) {
    assert(Array.isArray(ops));

    this.ops = [];
    this.size = 0;
    this.index = -1;

    this.init(ops);
  }

  static create(ops) {
    const hash = ops ? ops.join(':') : '';
    const cache = keyCache[hash];

    if (cache)
      return cache;

    const key = new BaseKey(ops);
    keyCache[hash] = key;

    return key;
  }

  init(ops) {
    for (let i = 0; i < ops.length; i++) {
      const name = ops[i];

      assert(typeof name === 'string');

      if (!types.hasOwnProperty(name))
        throw new Error(`Invalid type name: ${name}.`);

      const op = types[name];

      if (op.dynamic) {
        if (this.index === -1)
          this.index = i;
      } else {
        this.size += op.size();
      }

      this.ops.push(op);
    }
  }

  getSize(args) {
    assert(args.length === this.ops.length);

    let size = 1 + this.size;

    if (this.index === -1)
      return size;

    for (let i = this.index; i < args.length; i++) {
      const op = this.ops[i];
      const arg = args[i];
      if (op.dynamic)
        size += op.size(arg);
    }

    return size;
  }

  encode(id, args) {
    assert(Array.isArray(args));

    if (args.length !== this.ops.length)
      throw new Error('Wrong number of arguments passed to key.');

    const size = this.getSize(args);
    const key = Buffer.allocUnsafe(size);

    key[0] = id;

    let offset = 1;

    for (let i = 0; i < this.ops.length; i++) {
      const op = this.ops[i];
      const arg = args[i];
      offset += op.write(key, arg, offset);
    }

    return key;
  }

  decode(id, key) {
    assert(Buffer.isBuffer(key));

    if (this.ops.length === 0)
      return key;

    if (key.length === 0 || key[0] !== id)
      throw new Error('Key prefix mismatch.');

    const args = [];

    let offset = 1;

    for (const op of this.ops) {
      const arg = op.read(key, offset);
      offset += op.size(arg);
      args.push(arg);
    }

    return args;
  }

  min(id, args) {
    for (let i = args.length; i < this.ops.length; i++) {
      const op = this.ops[i];
      args.push(op.min);
    }
    return this.encode(id, args);
  }

  max(id, args) {
    for (let i = args.length; i < this.ops.length; i++) {
      const op = this.ops[i];
      args.push(op.max);
    }
    return this.encode(id, args);
  }

  root(id) {
    const key = Buffer.allocUnsafe(1);
    key[0] = id;
    return key;
  }
}

/**
 * Key
 * @ignore
 */

class Key {
  /**
   * Create a key.
   * @constructor
   * @param {Number|String} id
   * @param {String[]|null} ops
   */

  constructor(id, ops = []) {
    assert(Array.isArray(ops));

    this.id = makeID(id);
    this.base = BaseKey.create(ops);
  }

  encode(...args) {
    return this.base.encode(this.id, args);
  }

  decode(key) {
    return this.base.decode(this.id, key);
  }

  min(...args) {
    return this.base.min(this.id, args);
  }

  max(...args) {
    return this.base.max(this.id, args);
  }

  root() {
    return this.base.root(this.id);
  }
}

/*
 * Helpers
 */

function makeID(id) {
  if (typeof id === 'string') {
    assert(id.length === 1);
    id = id.charCodeAt(0);
  }

  assert((id & 0xff) === id);
  assert(id !== 0xff);

  return id;
}

function sizeString(v, enc) {
  assertType(typeof v === 'string');
  return 1 + Buffer.byteLength(v, enc);
}

function readString(k, o, enc) {
  assertLen(o + 1 <= k.length);
  assertLen(o + 1 + k[o] <= k.length);
  return k.toString(enc, o + 1, o + 1 + k[o]);
}

function writeString(k, v, o, enc) {
  assertType(typeof v === 'string');

  const size = Buffer.byteLength(v, enc);

  assertType(size <= 255);
  assertLen(o + 1 <= k.length);

  k[o] = size;

  if (size > 0)
    assertType(k.write(v, o + 1, enc) === size);

  return 1 + size;
}

function sizeBuffer(v) {
  assertType(Buffer.isBuffer(v));
  return 1 + v.length;
}

function readBuffer(k, o) {
  assertLen(o + 1 <= k.length);
  assertLen(o + 1 + k[o] <= k.length);
  return k.slice(o + 1, o + 1 + k[o]);
}

function writeBuffer(k, v, o, enc) {
  assertType(Buffer.isBuffer(v));
  assertLen(v.length <= 255);
  assertLen(o + 1 <= k.length);
  k[o] = v.length;
  assertLen(v.copy(k, o + 1) === v.length);
  return 1 + v.length;
}

function sizeHex(data) {
  if (Buffer.isBuffer(data))
    return data.length;
  assertType(typeof data === 'string');
  return data.length >>> 1;
}

function writeHex(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  assertType(typeof str === 'string');
  return data.write(str, off, 'hex');
}

function assertLen(ok) {
  if (!ok) {
    const err = new RangeError('Invalid length for database key.');
    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assertLen);
    throw err;
  }
}

function assertType(ok) {
  if (!ok) {
    const err = new TypeError('Invalid type for database key.');
    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assertType);
    throw err;
  }
}

function readU32BE(data, off) {
  return (data[off++] * 0x1000000
    + data[off++] * 0x10000
    + data[off++] * 0x100
    + data[off]);
}

function readU16BE(data, off) {
  return data[off++] * 0x100 + data[off];
}

function writeU32BE(dst, num, off) {
  dst[off + 3] = num;
  num >>>= 8;
  dst[off + 2] = num;
  num >>>= 8;
  dst[off + 1] = num;
  num >>>= 8;
  dst[off] = num;
  return off + 4;
}

function writeU16BE(dst, num, off) {
  dst[off++] = num >>> 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = Key;
