/*!
 * util.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const nodeUtil = require('util');

/**
 * @exports utils/util
 */

const util = exports;

/**
 * Clone a buffer.
 * @param {Buffer} data
 * @returns {Buffer}
 */

util.copy = function copy(data) {
  let clone = Buffer.allocUnsafe(data.length);
  data.copy(clone, 0, 0, data.length);
  return clone;
};

/**
 * Concatenate two buffers.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Buffer}
 */

util.concat = function concat(a, b) {
  let data = Buffer.allocUnsafe(a.length + b.length);
  a.copy(data, 0);
  b.copy(data, a.length);
  return data;
};

/**
 * Return hrtime (shim for browser).
 * @param {Array} time
 * @returns {Array}
 */

util.hrtime = function hrtime(time) {
  if (!process.hrtime) {
    let now = util.ms();
    let ms, sec;

    if (time) {
      time = time[0] * 1000 + time[1] / 1e6;
      now -= time;
      return now;
    }

    ms = now % 1000;
    sec = (now - ms) / 1000;
    return [sec, ms * 1e6];
  }

  if (time) {
    let elapsed = process.hrtime(time);
    return elapsed[0] * 1000 + elapsed[1] / 1e6;
  }

  return process.hrtime();
};

/**
 * Test whether a string is base58 (note that you
 * may get a false positive on a hex string).
 * @param {String?} obj
 * @returns {Boolean}
 */

util.isBase58 = function isBase58(obj) {
  return typeof obj === 'string' && /^[1-9a-zA-Z]+$/.test(obj);
};

/**
 * Test whether a string is hex (length must be even).
 * Note that this _could_ await a false positive on
 * base58 strings.
 * @param {String?} obj
 * @returns {Boolean}
 */

util.isHex = function isHex(obj) {
  return typeof obj === 'string'
    && /^[0-9a-f]+$/i.test(obj)
    && obj.length % 2 === 0;
};

/**
 * Reverse a hex-string (used because of
 * bitcoind's affinity for uint256le).
 * @param {String} data - Hex string.
 * @returns {String} Reversed hex string.
 */

util.revHex = function revHex(data) {
  let out = '';

  assert(typeof data === 'string');

  for (let i = 0; i < data.length; i += 2)
    out = data.slice(i, i + 2) + out;

  return out;
};

/**
 * Test whether a number is below MAX_SAFE_INTEGER.
 * @param {Number} value
 * @returns {Boolean}
 */

util.isSafeInteger = function isSafeInteger(value) {
  return Number.isSafeInteger(value);
};

/**
 * Test whether the result of a positive
 * addition would be below MAX_SAFE_INTEGER.
 * @param {Number} value
 * @returns {Boolean}
 */

util.isSafeAddition = function isSafeAddition(a, b) {
  let hi, lo, ahi, alo, bhi, blo;
  let as, bs, s, c;

  // We only work on positive numbers.
  assert(a >= 0);
  assert(b >= 0);

  // Fast case.
  if (a <= 0xfffffffffffff && b <= 0xfffffffffffff)
    return true;

  // Do a 64 bit addition and check the top 11 bits.
  ahi = (a * (1 / 0x100000000)) | 0;
  alo = a | 0;

  bhi = (b * (1 / 0x100000000)) | 0;
  blo = b | 0;

  // Credit to @indutny for this method.
  lo = (alo + blo) | 0;

  s = lo >> 31;
  as = alo >> 31;
  bs = blo >> 31;

  c = ((as & bs) | (~s & (as ^ bs))) & 1;

  hi = (((ahi + bhi) | 0) + c) | 0;

  hi >>>= 0;
  ahi >>>= 0;
  bhi >>>= 0;

  // Overflow?
  if (hi < ahi || hi < bhi)
    return false;

  return (hi & 0xffe00000) === 0;
};

/**
 * Test whether a number is Number,
 * finite, and below MAX_SAFE_INTEGER.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isNumber = function isNumber(value) {
  return typeof value === 'number'
    && isFinite(value)
    && util.isSafeInteger(value);
};

/**
 * Test whether an object is an int.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isInt = function isInt(value) {
  return util.isNumber(value) && value % 1 === 0;
};

/**
 * Test whether an object is an int8.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isInt8 = function isInt8(value) {
  return (value | 0) === value && value >= -0x80 && value <= 0x7f;
};

/**
 * Test whether an object is a uint8.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isUInt8 = function isUInt8(value) {
  return (value >>> 0) === value && value >= 0 && value <= 0xff;
};

/**
 * Test whether an object is an int32.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isInt32 = function isInt32(value) {
  return (value | 0) === value;
};

/**
 * Test whether an object is a uint32.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isUInt32 = function isUInt32(value) {
  return (value >>> 0) === value;
};

/**
 * Test whether an object is a int53.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isInt53 = function isInt53(value) {
  return util.isInt(value);
};

/**
 * Test whether an object is a uint53.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isUInt53 = function isUInt53(value) {
  return util.isInt(value) && value >= 0;
};

/**
 * Test whether an object is a 160 bit hash (hex string).
 * @param {String?} value
 * @returns {Boolean}
 */

util.isHex160 = function isHex160(hash) {
  return util.isHex(hash) && hash.length === 40;
};

/**
 * Test whether an object is a 256 bit hash (hex string).
 * @param {String?} value
 * @returns {Boolean}
 */

util.isHex256 = function isHex256(hash) {
  return util.isHex(hash) && hash.length === 64;
};

/**
 * Test whether a string qualifies as a float.
 *
 * This is stricter than checking if the result of parseFloat() is NaN
 * as, e.g. parseFloat successfully parses the string '1.2.3' as 1.2, and
 * we also check that the value is a string.
 *
 * @param {String?} value
 * @returns {Boolean}
 */

util.isFloat = function isFloat(value) {
  return typeof value === 'string'
    && /^-?(\d+)?(?:\.\d*)?$/.test(value)
    && value.length !== 0
    && value !== '-';
};

/**
 * util.inspect() with 20 levels of depth.
 * @param {Object|String} obj
 * @param {Boolean?} color
 * @return {String}
 */

util.inspectify = function inspectify(obj, color) {
  return typeof obj !== 'string'
    ? nodeUtil.inspect(obj, null, 20, color !== false)
    : obj;
};

/**
 * Format a string.
 * @function
 * @param {...String} args
 * @returns {String}
 */

util.fmt = nodeUtil.format;

/**
 * Format a string.
 * @param {Array} args
 * @param {Boolean?} color
 * @return {String}
 */

util.format = function format(args, color) {
  if (color == null)
    color = process.stdout ? process.stdout.isTTY : false;

  return typeof args[0] === 'object'
    ? util.inspectify(args[0], color)
    : util.fmt.apply(util, args);
};

/**
 * Write a message to stdout (console in browser).
 * @param {Object|String} obj
 * @param {...String} args
 */

util.log = function log(...args) {
  let msg;

  if (!process.stdout) {
    msg = typeof args[0] !== 'object'
      ? util.format(args, false)
      : args[0];
    console.log(msg);
    return;
  }

  msg = util.format(args);
  process.stdout.write(msg + '\n');
};

/**
 * Write a message to stderr (console in browser).
 * @param {Object|String} obj
 * @param {...String} args
 */

util.error = function error(...args) {
  let msg;

  if (!process.stderr) {
    msg = typeof args[0] !== 'object'
      ? util.format(args, false)
      : args[0];
    console.error(msg);
    return;
  }

  msg = util.format(args);
  process.stderr.write(msg + '\n');
};

/**
 * Get current time in unix time (seconds).
 * @returns {Number}
 */

util.now = function now() {
  return Math.floor(util.ms() / 1000);
};

/**
 * Get current time in unix time (milliseconds).
 * @returns {Number}
 */

util.ms = function ms() {
  if (Date.now)
    return Date.now();
  return +new Date();
};

/**
 * Create a Date ISO string from time in unix time (seconds).
 * @param {Number?} ts - Seconds in unix time.
 * @returns {String}
 */

util.date = function date(ts) {
  if (ts == null)
    ts = util.now();

  return new Date(ts * 1000).toISOString().slice(0, -5) + 'Z';
};

/**
 * Get unix seconds from a Date string.
 * @param {String} date - Date ISO String.
 * @returns {Number}
 */

util.time = function time(date) {
  if (date == null)
    return util.now();

  return new Date(date) / 1000 | 0;
};

/**
 * Get random range.
 * @param {Number} min
 * @param {Number} max
 * @returns {Number}
 */

util.random = function random(min, max) {
  return Math.floor(Math.random() * (max - min)) + min;
};

/**
 * Create a 32 or 64 bit nonce.
 * @param {Number} size
 * @returns {Buffer}
 */

util.nonce = function _nonce(size) {
  let n, nonce;

  if (!size)
    size = 8;

  switch (size) {
    case 8:
      nonce = Buffer.allocUnsafe(8);
      n = util.random(0, 0x100000000);
      nonce.writeUInt32LE(n, 0, true);
      n = util.random(0, 0x100000000);
      nonce.writeUInt32LE(n, 4, true);
      break;
    case 4:
      nonce = Buffer.allocUnsafe(4);
      n = util.random(0, 0x100000000);
      nonce.writeUInt32LE(n, 0, true);
      break;
    default:
      assert(false, 'Bad nonce size.');
      break;
  }

  return nonce;
};

/**
 * String comparator (memcmp + length comparison).
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number} -1, 1, or 0.
 */

util.strcmp = function strcmp(a, b) {
  let len = Math.min(a.length, b.length);

  for (let i = 0; i < len; i++) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }

  if (a.length < b.length)
    return -1;

  if (a.length > b.length)
    return 1;

  return 0;
};

/**
 * Convert bytes to mb.
 * @param {Number} size
 * @returns {Number} mb
 */

util.mb = function mb(size) {
  return Math.floor(size / 1024 / 1024);
};

/**
 * Inheritance.
 * @param {Function} child - Constructor to inherit.
 * @param {Function} parent - Parent constructor.
 */

util.inherits = function inherits(child, parent) {
  child.super_ = parent;
  Object.setPrototypeOf(child.prototype, parent.prototype);
  Object.defineProperty(child.prototype, 'constructor', {
    value: child,
    enumerable: false
  });
};

/**
 * Find index of a buffer in an array of buffers.
 * @param {Buffer[]} items
 * @param {Buffer} data - Target buffer to find.
 * @returns {Number} Index (-1 if not found).
 */

util.indexOf = function indexOf(items, data) {
  assert(Array.isArray(items));
  assert(Buffer.isBuffer(data));

  for (let i = 0; i < items.length; i++) {
    let item = items[i];
    assert(Buffer.isBuffer(item));
    if (item.equals(data))
      return i;
  }

  return -1;
};

/**
 * Convert a number to a padded uint8
 * string (3 digits in decimal).
 * @param {Number} num
 * @returns {String} Padded number.
 */

util.pad8 = function pad8(num) {
  assert(num >= 0);
  num = num + '';
  switch (num.length) {
    case 1:
      return '00' + num;
    case 2:
      return '0' + num;
    case 3:
      return num;
  }
  assert(false);
};

/**
 * Convert a number to a padded uint32
 * string (10 digits in decimal).
 * @param {Number} num
 * @returns {String} Padded number.
 */

util.pad32 = function pad32(num) {
  assert(num >= 0);
  num = num + '';
  switch (num.length) {
    case 1:
      return '000000000' + num;
    case 2:
      return '00000000' + num;
    case 3:
      return '0000000' + num;
    case 4:
      return '000000' + num;
    case 5:
      return '00000' + num;
    case 6:
      return '0000' + num;
    case 7:
      return '000' + num;
    case 8:
      return '00' + num;
    case 9:
      return '0' + num;
    case 10:
      return num;
    default:
      assert(false);
  }
};

/**
 * Convert a number to a padded uint8
 * string (2 digits in hex).
 * @param {Number} num
 * @returns {String} Padded number.
 */

util.hex8 = function hex8(num) {
  assert(num >= 0);
  num = num.toString(16);
  switch (num.length) {
    case 1:
      return '0' + num;
    case 2:
      return num;
    default:
      assert(false);
  }
};

/**
 * Convert a number to a padded uint32
 * string (8 digits in hex).
 * @param {Number} num
 * @returns {String} Padded number.
 */

util.hex32 = function hex32(num) {
  assert(num >= 0);
  num = num.toString(16);
  switch (num.length) {
    case 1:
      return '0000000' + num;
    case 2:
      return '000000' + num;
    case 3:
      return '00000' + num;
    case 4:
      return '0000' + num;
    case 5:
      return '000' + num;
    case 6:
      return '00' + num;
    case 7:
      return '0' + num;
    case 8:
      return num;
    default:
      assert(false);
  }
};

/**
 * Convert an array to a map.
 * @param {String[]} items
 * @returns {Object} Map.
 */

util.toMap = function toMap(items) {
  let map = {};

  for (let value of items)
    map[value] = true;

  return map;
};

/**
 * Reverse a map.
 * @param {Object} map
 * @returns {Object} Reversed map.
 */

util.revMap = function revMap(map) {
  let reversed = {};
  let keys = Object.keys(map);

  for (let key of keys)
    reversed[map[key]] = key;

  return reversed;
};

/**
 * Get object values.
 * @param {Object} map
 * @returns {Array} Values.
 */

util.values = function values(map) {
  let keys = Object.keys(map);
  let out = [];

  for (let key of keys)
    out.push(map[key]);

  return out;
};

/**
 * Perform a binary search on a sorted array.
 * @param {Array} items
 * @param {Object} key
 * @param {Function} compare
 * @param {Boolean?} insert
 * @returns {Number} Index.
 */

util.binarySearch = function binarySearch(items, key, compare, insert) {
  let start = 0;
  let end = items.length - 1;

  while (start <= end) {
    let pos = (start + end) >>> 1;
    let cmp = compare(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  return start;
};

/**
 * Perform a binary insert on a sorted array.
 * @param {Array} items
 * @param {Object} item
 * @param {Function} compare
 * @returns {Number} index
 */

util.binaryInsert = function binaryInsert(items, item, compare, uniq) {
  let i = util.binarySearch(items, item, compare, true);

  if (uniq && i < items.length) {
    if (compare(items[i], item) === 0)
      return -1;
  }

  if (i === 0)
    items.unshift(item);
  else if (i === items.length)
    items.push(item);
  else
    items.splice(i, 0, item);

  return i;
};

/**
 * Perform a binary removal on a sorted array.
 * @param {Array} items
 * @param {Object} item
 * @param {Function} compare
 * @returns {Boolean}
 */

util.binaryRemove = function binaryRemove(items, item, compare) {
  let i = util.binarySearch(items, item, compare, false);

  if (i === -1)
    return false;

  items.splice(i, 1);

  return true;
};

/**
 * Ensure hidden-class mode for object.
 * @param {Object} obj
 */

util.fastProp = function fastProp(obj) {
  ({ __proto__: obj });
};

/**
 * Quick test to see if a string is uppercase.
 * @param {String} str
 * @returns {Boolean}
 */

util.isUpperCase = function isUpperCase(str) {
  if (str.length === 0)
    return false;
  return (str.charCodeAt(0) & 32) === 0;
};

/**
 * Test to see if a string starts with a prefix.
 * @param {String} str
 * @param {String} prefix
 * @returns {Boolean}
 */

util.startsWith = function startsWiths(str, prefix) {
  return str.startsWith(prefix);
};

if (!''.startsWith) {
  util.startsWith = function startsWith(str, prefix) {
    return str.indexOf(prefix) === 0;
  };
}

/**
 * Get memory usage info.
 * @returns {Object}
 */

util.memoryUsage = function memoryUsage() {
  let mem;

  if (!process.memoryUsage) {
    return {
      total: 0,
      jsHeap: 0,
      jsHeapTotal: 0,
      nativeHeap: 0,
      external: 0
    };
  }

  mem = process.memoryUsage();

  return {
    total: util.mb(mem.rss),
    jsHeap: util.mb(mem.heapUsed),
    jsHeapTotal: util.mb(mem.heapTotal),
    nativeHeap: util.mb(mem.rss - mem.heapTotal),
    external: util.mb(mem.external)
  };
};
