/*!
 * util.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/* global gc */

var assert = require('assert');
var nodeUtil = require('util');
var os = require('os');
var Number, Math, Date;

/**
 * @exports utils/util
 */

var util = exports;

/**
 * Reference to the global object.
 * @const {Object}
 */

util.global = (function() {
  /* global self */

  if (this)
    return this;

  if (typeof window !== 'undefined')
    return window;

  if (typeof self !== 'undefined')
    return self;

  if (typeof global !== 'undefined')
    return global;

  assert(false, 'No global defined.');
})();

/*
 * Globals
 */

Number = util.global.Number;
Math = util.global.Math;
Date = util.global.Date;

/**
 * Whether we're in a browser or not.
 * @const {Boolean}
 */

util.isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

/**
 * The home directory.
 * @const {String}
 */

if (os.homedir) {
  util.HOME = os.homedir();
} else {
  util.HOME = process.env.HOME
    || process.env.USERPROFILE
    || process.env.HOMEPATH
    || '/';
}

/**
 * Global NOP function.
 * @type function
 * @static
 * @method
 */

util.nop = function() {};

/**
 * Garbage collector for `--expose-gc`.
 * @type function
 * @static
 * @method
 */

util.gc = !util.isBrowser && typeof gc === 'function' ? gc : util.nop;

/**
 * Clone a buffer.
 * @param {Buffer} data
 * @returns {Buffer}
 */

util.copy = function copy(data) {
  var clone = new Buffer(data.length);
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
  var data = new Buffer(a.length + b.length);
  a.copy(data, 0);
  b.copy(data, a.length);
  return data;
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
 * Return hrtime (shim for browser).
 * @param {Array} time
 * @returns {Array}
 */

util.hrtime = function hrtime(time) {
  var now, ms, sec, elapsed;

  if (util.isBrowser) {
    now = util.ms();
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
    elapsed = process.hrtime(time);
    return elapsed[0] * 1000 + elapsed[1] / 1e6;
  }

  return process.hrtime();
};

/**
 * Test whether a string is hex (length must be even).
 * Note that this _could_ yield a false positive on
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
 * Test whether two buffers are equal.
 * @param {Buffer?} a
 * @param {Buffer?} b
 * @returns {Boolean}
 */

util.equal = function equal(a, b) {
  var i;

  if (a == null)
    return false;

  if (b == null)
    return false;

  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));

  if (a.compare)
    return a.compare(b) === 0;

  if (a.length !== b.length)
    return false;

  for (i = 0; i < a.length; i++) {
    if (a[i] !== b[i])
      return false;
  }

  return true;
};

/**
 * Call `setImmediate`, `process.nextTick`,
 * or `setInterval` depending.
 * @function
 * @returns {Promise}
 */

util.nextTick = require('./nexttick');

/**
 * Reverse a hex-string (used because of
 * bitcoind's affinity for uint256le).
 * @param {String} data - Hex string.
 * @returns {String} Reversed hex string.
 */

util.revHex = function revHex(data) {
  var out = '';
  var i;

  assert(typeof data === 'string');

  for (i = 0; i < data.length; i += 2)
    out = data.slice(i, i + 2) + out;

  return out;
};

/**
 * Shallow merge between multiple objects.
 * @param {Object} target
 * @param {...Object} args
 * @returns {Object} target
 */

util.merge = function merge(target) {
  var i, j, obj, keys, key;

  for (i = 1; i < arguments.length; i++) {
    obj = arguments[i];
    keys = Object.keys(obj);
    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      target[key] = obj[key];
    }
  }

  return target;
};

if (Object.assign)
  util.merge = Object.assign;

/**
 * Max safe integer (53 bits).
 * @const {Number}
 * @default
 */

util.MAX_SAFE_INTEGER = 0x1fffffffffffff;

/**
 * Max 52 bit integer (safe for additions).
 * `(MAX_SAFE_INTEGER - 1) / 2`
 * @const {Number}
 * @default
 */

util.MAX_SAFE_ADDITION = 0xfffffffffffff;

/**
 * Test whether a number is below MAX_SAFE_INTEGER.
 * @param {Number} value
 * @returns {Boolean}
 */

util.isSafeInteger = function isSafeInteger(value) {
  if (Number.isSafeInteger)
    return Number.isSafeInteger(value);
  return Math.abs(value) <= util.MAX_SAFE_INTEGER;
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
  return util.isInt(value) && Math.abs(value) <= 0x7f;
};

/**
 * Test whether an object is a uint8.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isUInt8 = function isUInt8(value) {
  return util.isInt(value) && value >= 0 && value <= 0xff;
};

/**
 * Test whether an object is an int32.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isInt32 = function isInt32(value) {
  return util.isInt(value) && Math.abs(value) <= 0x7fffffff;
};

/**
 * Test whether an object is a uint32.
 * @param {Number?} value
 * @returns {Boolean}
 */

util.isUInt32 = function isUInt32(value) {
  return util.isInt(value) && value >= 0 && value <= 0xffffffff;
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
    : nodeUtil.format.apply(nodeUtil, args);
};

/**
 * Write a message to stdout (console in browser).
 * @param {Object|String} obj
 * @param {...String} args
 */

util.log = function log() {
  var args = new Array(arguments.length);
  var i, msg;

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  if (util.isBrowser) {
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

util.error = function error() {
  var args = new Array(arguments.length);
  var i, msg;

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  if (util.isBrowser) {
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
 * Unique-ify an array of strings.
 * @param {String[]} obj
 * @returns {String[]}
 */

util.uniq = function uniq(obj) {
  var table = {};
  var out = [];
  var i = 0;

  for (; i < obj.length; i++) {
    if (!table[obj[i]]) {
      out.push(obj[i]);
      table[obj[i]] = true;
    }
  }

  return out;
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
  var n, nonce;

  if (!size)
    size = 8;

  switch (size) {
    case 8:
      nonce = new Buffer(8);
      n = util.random(0, 0x100000000);
      nonce.writeUInt32LE(n, 0, true);
      n = util.random(0, 0x100000000);
      nonce.writeUInt32LE(n, 4, true);
      break;
    case 4:
      nonce = new Buffer(4);
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
  var len = Math.min(a.length, b.length);
  var i;

  for (i = 0; i < len; i++) {
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
 * Buffer comparator (memcmp + length comparison).
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number} -1, 1, or 0.
 */

util.cmp = function cmp(a, b) {
  return a.compare(b);
};

// Warning: polymorphism.
if (!Buffer.prototype.compare)
  util.cmp = util.strcmp;

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
 * @param {Function} obj - Constructor to inherit.
 * @param {Function} from - Parent constructor.
 */

util.inherits = function inherits(obj, from) {
  var f;

  obj.super_ = from;

  if (Object.setPrototypeOf) {
    Object.setPrototypeOf(obj.prototype, from.prototype);
    Object.defineProperty(obj.prototype, 'constructor', {
      value: obj,
      enumerable: false
    });
    return;
  }

  if (Object.create) {
    obj.prototype = Object.create(from.prototype, {
      constructor: {
        value: obj,
        enumerable: false
      }
    });
    return;
  }

  f = function() {};
  f.prototype = from.prototype;
  obj.prototype = new f;
  obj.prototype.constructor = obj;
};

/**
 * Find index of a buffer in an array of buffers.
 * @param {Buffer[]} obj
 * @param {Buffer} data - Target buffer to find.
 * @returns {Number} Index (-1 if not found).
 */

util.indexOf = function indexOf(obj, data) {
  var i;

  assert(Array.isArray(obj));
  assert(Buffer.isBuffer(data));

  for (i = 0; i < obj.length; i++) {
    if (!Buffer.isBuffer(obj[i]))
      continue;
    if (util.equal(obj[i], data))
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
 * @param {String[]} obj
 * @returns {Object} Map.
 */

util.toMap = function toMap(obj) {
  var map = {};
  var i, value;

  for (i = 0; i < obj.length; i++) {
    value = obj[i];
    map[value] = true;
  }

  return map;
};

/**
 * Reverse a map.
 * @param {Object} map
 * @returns {Object} Reversed map.
 */

util.revMap = function revMap(map) {
  var reversed = {};
  var keys = Object.keys(map);
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    reversed[map[key]] = key;
  }

  return reversed;
};

/**
 * Get object values.
 * @param {Object} map
 * @returns {Array} Values.
 */

util.values = function values(map) {
  var keys = Object.keys(map);
  var out = [];
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    out.push(map[key]);
  }

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
  var start = 0;
  var end = items.length - 1;
  var pos, cmp;

  while (start <= end) {
    pos = (start + end) >>> 1;
    cmp = compare(items[pos], key);

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
  var i = util.binarySearch(items, item, compare, true);

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
  var i = util.binarySearch(items, item, compare, false);
  if (i === -1)
    return false;
  items.splice(i, 1);
  return true;
};

/**
 * Unique-ify and sort an array of buffers.
 * @param {Buffer[]} items
 * @returns {Buffer[]}
 */

util.uniqBuffer = function uniqBuffer(items) {
  var out = [];
  var i, j, item;

  for (i = 0; i < items.length; i++) {
    item = items[i];
    j = util.binarySearch(out, item, util.cmp, true);

    if (j < out.length && util.cmp(out[j], item) === 0)
      continue;

    if (j === 0)
      out.unshift(item);
    else if (j === out.length)
      out.push(item);
    else
      out.splice(j, 0, item);
  }

  return out;
};

/**
 * Normalize a path.
 * @param {String} path
 * @param {Boolean?} dirname
 */

util.normalize = function normalize(path, dirname) {
  var parts;

  path = path.replace(/\\/g, '/');
  path = path.replace(/(^|\/)\.\//, '$1');
  path = path.replace(/\/+\.?$/, '');
  parts = path.split(/\/+/);

  if (dirname)
    parts.pop();

  return parts.join('/');
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
 * Promisify a function.
 * @param {Function} func
 * @returns {Function}
 */

util.promisify = function promisify(func) {
  return function() {
    var result;
    try {
      result = func.apply(this, arguments);
    } catch (e) {
      return Promise.reject(e);
    }
    return Promise.resolve(result);
  };
};

/**
 * Get memory usage info.
 * @returns {Object}
 */

util.memoryUsage = function memoryUsage() {
  var mem;

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
