/**
 * utils.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var utils = exports;

var bn = require('bn.js');
var util = require('util');
var crypto, hash;

utils.isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

if (!utils.isBrowser)
  crypto = require('cry' + 'pto');
else
  hash = require('hash.js');

/**
 * Utils
 */

utils.nop = function() {};

utils.gc = !utils.isBrowser && typeof gc === 'function' ? gc : utils.nop;

if (utils.gc !== utils.nop)
  console.error('bcoin started with --expose-gc enabled.');

utils.slice = function slice(buf, start, end) {
  var clone;

  if (start != null)
    buf = buf.slice(start, end);

  clone = new Buffer(buf.length);

  buf.copy(clone, 0, 0, buf.length);

  return clone;
};

utils.toBuffer = function toBuffer(msg, enc) {
  if (Buffer.isBuffer(msg))
    return msg;

  if (Array.isArray(msg))
    return new Buffer(msg);

  if (!msg)
    return new Buffer([]);

  if (typeof msg === 'string') {
    if (!enc)
      return new Buffer(msg, 'ascii');

    if (enc === 'base58')
      return utils.fromBase58(msg);

    return new Buffer(msg, enc);
  }

  assert(false);
};

utils.toArray = function toArray(msg, enc) {
  var res = [];
  var i, c, hi, lo, slice, num;

  if (!msg)
    return res;

  if (Buffer.isBuffer(msg))
    return Array.prototype.slice.call(msg);

  if (Array.isArray(msg))
    return msg.slice();

  if (typeof msg === 'string') {
    if (!enc) {
      for (i = 0; i < msg.length; i++) {
        c = msg.charCodeAt(i);
        hi = c >> 8;
        lo = c & 0xff;
        if (hi)
          res.push(hi, lo);
        else
          res.push(lo);
      }
    } else if (enc === 'hex') {
      msg = msg.replace(/[^a-z0-9]+/ig, '');
      if (msg.length % 2 !== 0)
        msg = '0' + msg;

      for (i = 0; i < msg.length; i += 8) {
        slice = msg.slice(i, i + 8);
        num = parseInt(slice, 16);

        if (slice.length === 8)
          res.push((num >>> 24) & 0xff);
        if (slice.length >= 6)
          res.push((num >>> 16) & 0xff);
        if (slice.length >= 4)
          res.push((num >>> 8) & 0xff);
        res.push(num & 0xff);
      }
    }
  } else {
    for (i = 0; i < msg.length; i++)
      res[i] = msg[i] | 0;
  }

  return res;
};

var base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZ'
  + 'abcdefghijkmnopqrstuvwxyz';

var unbase58 = base58.split('').reduce(function(out, ch, i) {
  out[ch] = i;
  return out;
}, {});

// Ported from:
// https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
utils.toBase58 = function toBase58(buf) {
  var zeroes = 0;
  var length = 0;
  var str = '';
  var i, size, b58, carry, j, k;

  for (i = 0; i < buf.length; i++) {
    if (buf[i] !== 0)
      break;
    zeroes++;
  }

  size = ((buf.length * 138 / 100) | 0) + 1;
  b58 = new Buffer(size);
  b58.fill(0);

  for (; i < buf.length; i++) {
    carry = buf[i];
    j = 0;
    for (k = b58.length - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;
      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = carry / 58 | 0;
    }
    assert(carry === 0);
    length = j;
  }

  i = size - length;
  while (b58[i] === 0)
    i++;

  for (j = 0; j < zeroes; j++)
    str += '1';

  for (; i < b58.length; i++)
    str += base58[b58[i]];

  return str;
};

utils.fromBase58 = function fromBase58(str) {
  var zeroes = 0;
  var i = 0;
  var b256, ch, carry, j, out;

  for (i = 0; i < str.length; i++) {
    if (str[i] !== '1')
      break;
    zeroes++;
  }

  b256 = new Buffer(((str.length * 733) / 1000 | 0) + 1);
  b256.fill(0);

  for (; i < str.length; i++) {
    ch = unbase58[str[i]];
    if (ch == null)
      throw new Error('Non-base58 character.');

    carry = ch;
    for (j = b256.length - 1; j >= 0; j--) {
      carry += 58 * b256[j];
      b256[j] = carry % 256;
      carry = carry / 256 | 0;
    }

    assert(carry === 0);
  }

  i = 0;
  while (b256[i] === 0)
    i++;

  out = new Buffer(zeroes + (b256.length - i));

  for (j = 0; j < zeroes; j++)
    out[j] = 0;

  for (; i < b256.length; i++)
    out[i] = b256[i];

  return out;
};

utils.isBase58 = function isBase58(msg) {
  return typeof msg === 'string' && /^[1-9a-zA-Z]+$/.test(msg);
};

utils.ripemd160 = function ripemd160(data, enc) {
  if (!crypto)
    return new Buffer(hash.ripemd160().update(data, enc).digest());

  return crypto.createHash('ripemd160').update(data, enc).digest();
};

utils.sha1 = function sha1(data, enc) {
  if (!crypto)
    return new Buffer(hash.sha1().update(data, enc).digest());

  return crypto.createHash('sha1').update(data, enc).digest();
};

utils.ripesha = function ripesha(data, enc) {
  return utils.ripemd160(utils.sha256(data, enc));
};

utils.checksum = function checksum(data, enc) {
  return utils.dsha256(data, enc).slice(0, 4);
};

utils.sha256 = function sha256(data, enc) {
  if (!crypto)
    return new Buffer(hash.sha256().update(data, enc).digest());

  return crypto.createHash('sha256').update(data, enc).digest();
};

utils.dsha256 = function dsha256(data, enc) {
  return utils.sha256(utils.sha256(data, enc));
};

utils.sha512hmac = function sha512hmac(data, salt) {
  var hmac, result;

  if (!crypto) {
    hmac = hash.hmac(hash.sha512, salt);
    return new Buffer(hmac.update(data).digest());
  }

  hmac = crypto.createHmac('sha512', salt);
  result = hmac.update(data).digest();

  return result;
};

/**
 * PDKBF2
 * Credit to: https://github.com/stayradiated/pbkdf2-sha512
 * Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
 * Copyright (c) 2014, JP Richardson
 */

utils.pbkdf2 = function pbkdf2(key, salt, iterations, dkLen) {
  'use strict';

  if (crypto && crypto.pbkdf2Sync)
    return crypto.pbkdf2Sync(key, salt, iterations, dkLen, 'sha512');

  var hLen = 64;

  if (dkLen > (Math.pow(2, 32) - 1) * hLen)
    throw Error('Requested key length too long');

  if (typeof key !== 'string' && typeof key.length !== 'number')
    throw new TypeError('key must a string or array');

  if (typeof salt !== 'string' && typeof salt.length !== 'number')
    throw new TypeError('salt must a string or array');

  if (typeof key === 'string')
    key = new Buffer(key, 'ascii');

  if (typeof salt === 'string')
    salt = new Buffer(salt, 'ascii');

  var DK = new Buffer(dkLen);
  var U = new Buffer(hLen);
  var T = new Buffer(hLen);
  var block1 = new Buffer(salt.length + 4);

  var l = Math.ceil(dkLen / hLen);
  var r = dkLen - (l - 1) * hLen;

  var i, j, k, destPos, len;

  utils.copy(salt.slice(0, salt.length), block1, 0);

  for (i = 1; i <= l; i++) {
    block1[salt.length + 0] = i >> 24 & 0xff;
    block1[salt.length + 1] = i >> 16 & 0xff;
    block1[salt.length + 2] = i >> 8 & 0xff;
    block1[salt.length + 3] = i >> 0 & 0xff;

    U = utils.sha512hmac(block1, key);

    utils.copy(U.slice(0, hLen), T, 0);

    for (j = 1; j < iterations; j++) {
      U = utils.sha512hmac(U, key);

      for (k = 0; k < hLen; k++)
        T[k] ^= U[k];
    }

    destPos = (i - 1) * hLen;
    len = i === l ? r : hLen;
    utils.copy(T.slice(0, len), DK, 0);
  }

  return DK;
};

utils.salt = 'bcoin:';

utils.encrypt = function encrypt(data, passphrase) {
  var cipher, out;

  if (!crypto)
    return data;

  if (data[0] === ':')
    return data;

  if (!passphrase)
    throw new Error('No passphrase.');

  cipher = crypto.createCipher('aes-256-cbc', passphrase);

  out = '';
  out += cipher.update(utils.salt + data, 'utf8', 'hex');
  out += cipher.final('hex');

  return ':' + out;
};

utils.decrypt = function decrypt(data, passphrase) {
  var decipher, out;

  if (!crypto) {
    if (data[0] === ':')
      throw new Error('Cannot decrypt.');
    return data;
  }

  if (data[0] !== ':')
    return data;

  if (!passphrase)
    throw new Error('No passphrase.');

  data = data.substring(1);

  decipher = crypto.createDecipher('aes-256-cbc', passphrase);

  out = '';
  out += decipher.update(data, 'hex', 'utf8');
  out += decipher.final('utf8');

  if (out.indexOf(utils.salt) !== 0)
    throw new Error('Decrypt failed.');

  out = out.substring(utils.salt.length);

  return out;
};

utils.copy = function copy(src, dst, off) {
  return src.copy(dst, off, 0, src.length);
};

utils.toHex = function toHex(msg) {
  if (typeof msg === 'string')
    return msg;

  return msg.toString('hex');
};

utils.isHex = function isHex(msg) {
  return typeof msg === 'string' && /^[0-9a-f]+$/i.test(msg);
};

function binaryInsert(list, item, compare, search) {
  var start = 0;
  var end = list.length;
  var pos, cmp;

  while (start < end) {
    pos = (start + end) >> 1;
    cmp = compare(item, list[pos]);

    if (cmp === 0) {
      start = pos;
      end = pos;
      break;
    } else if (cmp < 0) {
      end = pos;
    } else {
      start = pos + 1;
    }
  }

  if (!search)
    list.splice(start, 0, item);

  return start;
}

utils.binaryInsert = binaryInsert;

utils.isEqual = function isEqual(a, b) {
  var i;

  if (!a || !b)
    return false;

  if (a.length !== b.length)
    return false;

  if (a.compare)
    return a.compare(b) === 0;

  for (i = 0; i < a.length; i++) {
    if (a[i] !== b[i])
      return false;
  }

  return true;
};

if (typeof setImmediate === 'function') {
  utils.nextTick = setImmediate;
} else if (!utils.isBrowser) {
  utils.nextTick = process.nextTick;
} else {
  utils.nextTick = function nextTick(fn) {
    setTimeout(fn, 1);
  };
}

function RequestCache() {
  this.map = {};
  this.count = 0;
}

RequestCache.prototype.add = function add(id, cb) {
  id = utils.toHex(id);

  if (this.map[id]) {
    this.map[id].push(cb);
    return false;
  } else {
    this.map[id] = [ cb ];
    this.count++;
    return true;
  }
};

RequestCache.prototype.fulfill = function fulfill(id, err, data) {
  var cbs;

  id = utils.toHex(id);

  cbs = this.map[id];

  if (!this.map[id])
    return;

  delete this.map[id];
  this.count--;

  cbs.forEach(function(cb) {
    cb(err, data);
  });
};

utils.RequestCache = RequestCache;

utils.asyncify = function asyncify(callback) {
  if (callback && callback._asyncified)
    return callback;

  function asyncifyFn(err, result1, result2) {
    if (!callback)
      return err || result1;
    utils.nextTick(function() {
      callback(err, result1, result2);
    });
  }

  asyncifyFn._asyncified = true;
  if (callback)
    asyncifyFn._once = callback._once;

  return asyncifyFn;
};

utils.ensure = function ensure(callback) {
  if (!callback)
    return utils.nop;
  return callback;
};

utils.revHex = function revHex(s) {
  var r = '';
  var i = 0;

  for (; i < s.length; i += 2)
    r = s.slice(i, i + 2) + r;

  return r;
};

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}

assert.equal = function assertEqual(l, r, msg) {
  if (l != r)
    throw new Error(msg || ('Assertion failed: ' + l + ' != ' + r));
};

assert.noError = function noError(err) {
  if (err)
    throw err;
};

utils.assert = assert;

utils.btc =
utils.toBTC = function toBTC(satoshi, strict) {
  var m = new bn(10000000).mul(new bn(10));
  var lo;

  if (utils.isBTC(satoshi))
    return utils.isBTC(satoshi);

  if (!strict && utils.isFinite(satoshi))
    satoshi = new bn(Math.floor(satoshi) + '', 10);

  satoshi = utils.isSatoshi(satoshi);

  if (!satoshi)
    throw new Error('Could not calculate BTC');

  lo = satoshi.mod(m);

  if (lo.cmpn(0) !== 0) {
    lo = lo.toString(10);
    while (lo.length < 8)
      lo = '0' + lo;
    lo = '.' + lo;
  } else {
    lo = '.0';
  }

  lo = lo.replace(/0+$/, '');
  if (lo === '.')
    lo += '0';

  return satoshi.div(m).toString(10) + lo;
};

utils.satoshi =
utils.toSatoshi =
utils.fromBTC = function fromBTC(btc, strict) {
  var satoshi, parts, hi, lo;

  if (utils.isSatoshi(btc))
    return utils.isSatoshi(btc);

  if (!strict && utils.isFinite(btc)) {
    btc = btc + '';
    if (utils.isInt(btc))
      btc += '.0';
  }

  btc = utils.isBTC(btc);

  if (!btc)
    throw new Error('Could not calculate satoshis');

  parts = btc.split('.');
  hi = parts[0] || '0';
  lo = parts[1] || '0';

  while (lo.length < 8)
    lo += '0';

  satoshi = (hi + lo).replace(/^0+/, '');

  return new bn(satoshi, 10);
};

utils.isInt = function isInt(val) {
  return typeof val === 'string' && /^\d+$/.test(val);
};

utils.isFloat = function isFloat(val) {
  return typeof val === 'string' && /^\d+\.\d+$/.test(val);
};

utils.isFinite = function _isFinite(val) {
  return typeof val === 'number' && isFinite(val);
};

utils.isSatoshi = function isSatoshi(val) {
  if (bn.isBN(val))
    return val;
  if (utils.isInt(val))
    return new bn(val, 10);
  if (Buffer.isBuffer(val))
    return new bn(val);
  return false;
};

utils.isBTC = function isBTC(val) {
  if (utils.isFloat(val))
    return val;
  return false;
};

utils.toFloat = function toFloat(val) {
  if (utils.isFloat(val))
    return val;
  if (utils.isInt(val))
    return val + '.0';
  throw new Error('Could not convert ' + val + ' to float');
};

utils.parseHost = function parseHost(addr) {
  var parts;

  assert(addr);

  if (typeof addr === 'object')
    return addr;

  if (addr.indexOf(']') !== -1)
    parts = addr.split(/\]:?/);
  else
    parts = addr.split(':');

  return {
    host: parts[0].replace(/[\[\]]/g, ''),
    port: +parts[1] || 0
  };
};

utils.isIP = function isIP(ip) {
  if (typeof ip !== 'string')
    return 0;

  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip))
    return 4;

  if (/:[0-9a-f]{1,4}/i.test(ip))
    return 6;

  return 0;
};

utils.ip2version = function ip2version(ip, version) {
  var b, i, j;

  assert(Buffer.isBuffer(ip));
  assert(version === 4 || version === 6);

  if (version === 4) {
    // Check to see if this an
    // ipv4-mapped ipv6 address.
    if (ip.length > 4) {
      i = 0;
      while (ip[i] === 0)
        i++;

      // Found an ipv4 address
      if (ip.length - i === 6 && ip[i] === 0xff && ip[i + 1] === 0xff)
        return utils.slice(ip, -4);

      // No ipv4 address
      return new Buffer([0, 0, 0, 0]);
    }

    // Pad to 4 bytes
    if (ip.length < 4) {
      b = new Buffer(4);
      i = ip.length;
      j = b.length;
      b.fill(0);
      while (i)
        b[--j] = ip[--i];
      ip = b;
    }

    return ip;
  }

  if (version === 6) {
    // Pad to 4 bytes
    if (ip.length < 4) {
      b = new Buffer(4);
      i = ip.length;
      j = b.length;
      b.fill(0);
      while (i)
        b[--j] = ip[--i];
      ip = b;
    }

    // Try to convert ipv4 address to
    // ipv4-mapped ipv6 address.
    if (ip.length === 4) {
      b = new Buffer(6);
      i = ip.length;
      j = b.length;
      b.fill(0xff);
      while (i)
        b[--j] = ip[--i];
      ip = b;
    }

    // Pad to 16 bytes
    if (ip.length < 16) {
      b = new Buffer(16);
      i = ip.length;
      j = b.length;
      b.fill(0);
      while (i)
        b[--j] = ip[--i];
      ip = b;
    }

    return ip;
  }
};

utils.ip2array = function ip2array(ip, version) {
  var type = utils.isIP(ip);

  assert(version === 4 || version === 6);

  if (type === 0) {
    if (!Buffer.isBuffer(ip))
      ip = new Buffer([0, 0, 0, 0]);
  } else if (type === 4) {
    ip = new Buffer(ip.split('.').map(function(n) {
      return +n;
    }));
    assert(ip.length <= 4);
  } else if (type === 6) {
    ip = new Buffer(ip.replace(/:/g, ''), 'hex');
    assert(ip.length <= 16);
  }

  return utils.ip2version(ip, version);
};

utils.array2ip = function array2ip(ip, version) {
  var out, i, hi, lo;

  if (!Buffer.isBuffer(ip)) {
    if (utils.isIP(ip))
      ip = utils.ip2array(ip, version);
    else
      ip = new Buffer([0, 0, 0, 0]);
  }

  assert(version === 4 || version === 6);
  assert(ip.length <= 16);

  ip = utils.ip2version(ip, version);

  if (version === 4)
    return ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + ip[3];

  if (version === 6) {
    out = [];

    for (i = 0; i < ip.length; i += 2) {
      hi = ip[i].toString(16);
      if (hi.length < 2)
        hi = '0' + hi;
      lo = ip[i + 1].toString(16);
      if (lo.length < 2)
        lo = '0' + lo;
      out.push(hi + lo);
    }

    return out.join(':');
  }
};

utils.isArrayLike = function isArrayLike(msg) {
  return msg
    && !Array.isArray(msg)
    && typeof msg === 'object'
    && typeof msg.length === 'number';
};

utils.isArray = function isArray(msg) {
  return Array.isArray(msg);
};

utils.isBuffer = function isBuffer(msg) {
  return Buffer.isBuffer(msg);
};

utils.ensureBuffer = function ensureBuffer(msg) {
  if (Buffer.isBuffer(msg))
    return msg;

  if (Array.isArray(msg))
    return new Buffer(msg);

  if (utils.isHex(msg))
    return new Buffer(msg, 'hex');

  if (utils.isBase58(msg))
    return utils.fromBase58(msg);

  throw new Error('Cannot ensure buffer');
};

utils._inspect = function _inspect(obj, color) {
  return typeof obj !== 'string'
    ? util.inspect(obj, null, 20, color !== false)
    : obj;
};

utils.format = function format(args, color) {
  color = color ? process.stdout.isTTY : false;
  return typeof args[0] === 'object'
    ? utils._inspect(args[0], color) + '\n'
    : util.format.apply(util, args) + '\n';
};

utils.print = function print() {
  var args = Array.prototype.slice.call(arguments);
  return process.stdout.write(utils.format(args, true));
};

utils.debug = utils.nop;
utils.ensurePrefix = utils.nop;

utils.merge = function merge(target) {
  var args = Array.prototype.slice.call(arguments, 1);
  args.forEach(function(obj) {
    Object.keys(obj).forEach(function(key) {
      target[key] = obj[key];
    });
  });
  return target;
};

utils.hidden = function hidden(obj, prop, value) {
  Object.defineProperty(obj, prop, {
    value: value,
    enumerable: false,
    configurable: true,
    writable: true
  });
  return obj;
};

utils.sortKeys = function sortKeys(keys) {
  return keys.slice().sort(function(a, b) {
    return utils.cmp(a, b);
  });
};

utils.sortHDKeys = function sortHDKeys(keys) {
  return keys.slice().sort(function(a, b) {
    return utils.cmp(a.publicKey, b.publicKey);
  });
};

utils.uniq = function uniq(obj) {
  var out = [];
  var i = 0;

  for (; i < obj.length; i++) {
    if (out.indexOf(obj[i]) === -1)
      out.push(obj[i]);
  }

  return out;
};

utils.uniqs = function uniqs(obj) {
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

utils.fromCompact = function fromCompact(compact) {
  var exponent = compact >> 24;
  var negative = (compact >> 23) & 0x01;
  var mantissa = compact & 0x007fffff;
  var num;

  if (compact === 0)
    return new bn(0);

  if (exponent <= 3) {
    mantissa >>= 8 * (3 - exponent);
    num = new bn(mantissa);
  } else {
    num = new bn(mantissa);
    num.iushln(8 * (exponent - 3));
  }

  if (negative)
    num.ineg();

  return num;
};

utils.toCompact = function toCompact(num) {
  var mantissa, exponent, compact;

  if (num.cmpn(0) === 0)
    return 0;

  exponent = num.byteLength();
  if (exponent <= 3) {
    mantissa = num.toNumber();
    mantissa <<= 8 * (3 - exponent);
  } else {
    mantissa = num.ushrn(8 * (exponent - 3)).toNumber();
  }

  if (mantissa & 0x00800000) {
    mantissa >>= 8;
    exponent++;
  }

  compact = (exponent << 24) | mantissa;

  if (num.isNeg())
    compact |= 0x00800000;

  return compact;
};

utils.testTarget = function testTarget(target, hash) {
  if (typeof target === 'number')
    target = utils.fromCompact(target);

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  return new bn(hash, 'le').cmp(target) < 0;
};

utils.now = function now() {
  return +new Date() / 1000 | 0;
};

utils.host = function host(addr) {
  return addr.split(':')[0];
};

utils.U32 = new bn(0xffffffff);
utils.U64 = new bn('ffffffffffffffff', 'hex');

utils.nonce = function nonce() {
  var nonce = utils.U64.clone();
  nonce.imuln(Math.random());
  return nonce;
};

//
// Integer Functions
//
// Non-64-bit functions originally taken from the node.js tree:
//
// Copyright Joyent, Inc. and other Node contributors. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

utils.isNegZero = function isNegZero(bytes, order) {
  var s = 0;
  var b, res;

  if (order === 'le')
    s = bytes.length - 1;

  if (bytes[s] & 0x80) {
    b = bytes[s];
    bytes[s] &= ~0x80;
    res = new bn(bytes, order).cmpn(0) === 0;
    bytes[s] = b;
    return res;
  }

  return false;
};

utils.readU8 = function readU8(arr, off) {
  off = off >>> 0;
  return arr[off];
};

utils.readU16 = function readU16(arr, off) {
  off = off >>> 0;
  return arr[off] | (arr[off + 1] << 8);
};

utils.readU16BE = function readU16BE(arr, off) {
  off = off >>> 0;
  return (arr[off] << 8) | arr[off + 1];
};

utils.readU32 = function readU32(arr, off) {
  off = off >>> 0;

  return ((arr[off])
    | (arr[off + 1] << 8)
    | (arr[off + 2] << 16))
    + (arr[off + 3] * 0x1000000);
};

utils.readU32BE = function readU32BE(arr, off) {
  off = off >>> 0;

  return (arr[off] * 0x1000000)
    + ((arr[off + 1] << 16)
    | (arr[off + 2] << 8)
    | arr[off + 3]);
};

utils.readU64 = function readU64(arr, off) {
  var num;
  off = off >>> 0;
  num = arr.slice(off, off + 8);
  return new bn(num, 'le');
};

utils.readU64BE = function readU64BE(arr, off) {
  var num;
  off = off >>> 0;
  num = arr.slice(off, off + 8);
  return new bn(num, 'be');
};

utils.read8 = function read8(arr, off) {
  var num;
  off = off >>> 0;
  num = arr[off];
  return !(num & 0x80) ? num : (0xff - num + 1) * -1;
};

utils.read16 = function read16(arr, off) {
  var num;
  off = off >>> 0;
  num = arr[off] | (arr[off + 1] << 8);
  return (num & 0x8000) ? num | 0xffff0000 : num;
};

utils.read16BE = function read16BE(arr, off) {
  var num;
  off = off >>> 0;
  num = arr[off + 1] | (arr[off] << 8);
  return (num & 0x8000) ? num | 0xffff0000 : num;
};

utils.read32 = function read32(arr, off) {
  off = off >>> 0;

  return (arr[off])
    | (arr[off + 1] << 8)
    | (arr[off + 2] << 16)
    | (arr[off + 3] << 24);
};

utils.read32BE = function read32BE(arr, off) {
  off = off >>> 0;

  return (arr[off] << 24)
    | (arr[off + 1] << 16)
    | (arr[off + 2] << 8)
    | (arr[off + 3]);
};

utils.read64 = function read64(arr, off) {
  var num;

  off = off >>> 0;

  num = arr.slice(off, off + 8);

  // If we are signed, do (~num + 1) to get
  // the positive counterpart and set bn's
  // negative flag.
  if (num[num.length - 1] & 0x80) {
    if (utils.isNegZero(num, 'le'))
      return new bn(0);
    return new bn(num, 'le').notn(64).addn(1).neg();
  }

  return new bn(num, 'le');
};

utils.read64BE = function read64BE(arr, off) {
  var num;

  off = off >>> 0;

  num = arr.slice(off, off + 8);

  // If we are signed, do (~num + 1) to get
  // the positive counterpart and set bn's
  // negative flag.
  if (num[0] & 0x80) {
    if (utils.isNegZero(num, 'be'))
      return new bn(0);
    return new bn(num, 'be').notn(64).addn(1).neg();
  }

  return new bn(num);
};

utils.writeU8 = function writeU8(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  return 1;
};

utils.writeU16 = function writeU16(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  return 2;
};

utils.writeU16BE = function write16BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 8) & 0xff;
  dst[off + 1] = num & 0xff;
  return 2;
};

utils.writeU32 = function writeU32(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off + 3] = (num >>> 24) & 0xff;
  dst[off + 2] = (num >>> 16) & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  dst[off] = num & 0xff;
  return 4;
};

utils.writeU32BE = function writeU32BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 24) & 0xff;
  dst[off + 1] = (num >>> 16) & 0xff;
  dst[off + 2] = (num >>> 8) & 0xff;
  dst[off + 3] = num & 0xff;
  return 4;
};

utils.writeU64 = function writeU64(dst, num, off) {
  return utils.write64(dst, num, off);
};

utils.writeU64BE = function writeU64BE(dst, num, off) {
  return utils.write64BE(dst, num, off);
};

utils.writeU64N = function writeU64N(dst, num, off) {
  return utils.write64N(dst, num, off);
};

utils.writeU64NBE = function writeU64NBE(dst, num, off) {
  return utils.write64NBE(dst, num, off);
};

utils.MAX_SAFE_INTEGER = 0x1fffffffffffff;
utils.MAX_SAFE_BN = new bn(utils.MAX_SAFE_INTEGER);
utils.MAX_SAFE_HI = 0x1fffff;

utils.write64N = function write64N(dst, num, off) {
  var neg, hi, lo, one, i, b;

  num = +num;
  off = off >>> 0;

  assert(num <= utils.MAX_SAFE_INTEGER, 'Number exceeds 2^53-1');

  if (num < 0)
    neg = true;

  num = num < 0 ? -num : num;

  hi = num / 0x100000000 | 0;
  lo = num % 0x100000000;

  dst[off + 0] = (lo >>> 0) & 0xff;
  dst[off + 1] = (lo >>> 8) & 0xff;
  dst[off + 2] = (lo >>> 16) & 0xff;
  dst[off + 3] = (lo >>> 24) & 0xff;
  dst[off + 4] = (hi >>> 0) & 0xff;
  dst[off + 5] = (hi >>> 8) & 0xff;
  dst[off + 6] = (hi >>> 16) & 0xff;
  dst[off + 7] = (hi >>> 24) & 0xff;

  if (neg) {
    one = 1;
    for (i = off; i < off + 8; i++) {
      b = (dst[i] ^ 0xff) + one;
      dst[i] = b & 0xff;
      one = b >>> 8;
    }
  }

  return 8;
};

utils.write64NBE = function write64NBE(dst, num, off) {
  var neg, hi, lo, one, i, b;

  num = +num;
  off = off >>> 0;

  assert(num <= utils.MAX_SAFE_INTEGER, 'Number exceeds 2^53-1');

  if (num < 0)
    neg = true;

  num = num < 0 ? -num : num;

  hi = num / 0x100000000 | 0;
  lo = num % 0x100000000;

  dst[off + 7] = (lo >>> 0) & 0xff;
  dst[off + 6] = (lo >>> 8) & 0xff;
  dst[off + 5] = (lo >>> 16) & 0xff;
  dst[off + 4] = (lo >>> 24) & 0xff;
  dst[off + 3] = (hi >>> 0) & 0xff;
  dst[off + 2] = (hi >>> 8) & 0xff;
  dst[off + 1] = (hi >>> 16) & 0xff;
  dst[off + 0] = (hi >>> 24) & 0xff;

  if (neg) {
    one = 1;
    for (i = off + 7; i >= off; i--) {
      b = (dst[i] ^ 0xff) + one;
      dst[i] = b & 0xff;
      one = b >>> 8;
    }
  }

  return 8;
};

utils.readU64N = function readU64N(dst, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32(dst, off + 4);
  var lo = utils.readU32(dst, off);
  if (force53)
    hi &= utils.MAX_SAFE_HI;
  assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
  return (hi * 0x100000000) + lo;
};

utils.readU64NBE = function readU64NBE(dst, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32BE(dst, off);
  var lo = utils.readU32BE(dst, off + 4);
  if (force53)
    hi &= utils.MAX_SAFE_HI;
  assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
  return (hi * 0x100000000) + lo;
};

utils.read64N = function read64N(dst, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32(dst, off + 4);
  var lo = utils.readU32(dst, off);
  if (hi & 0x80000000) {
    hi = ~hi + 1;
    lo = ~lo + 1;
    if (force53)
      hi &= utils.MAX_SAFE_HI;
    assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
    return -(hi * 0x100000000 + lo);
  }
  if (force53)
    hi &= utils.MAX_SAFE_HI;
  assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
  return (hi * 0x100000000) + lo;
};

utils.read64NBE = function read64NBE(dst, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32BE(dst, off);
  var lo = utils.readU32BE(dst, off + 4);
  if (hi & 0x80000000) {
    hi = ~hi + 1;
    lo = ~lo + 1;
    if (force53)
      hi &= utils.MAX_SAFE_HI;
    assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
    return -(hi * 0x100000000 + lo);
  }
  if (force53)
    hi &= utils.MAX_SAFE_HI;
  assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
  return (hi * 0x100000000) + lo;
};

utils.readU53 = function readU53(dst, off) {
  return utils.readU64N(dst, off, true);
};

utils.readU53BE = function readU53BE(dst, off) {
  return utils.readU64NBE(dst, off, true);
};

utils.read53 = function read53(dst, off) {
  return utils.read64N(dst, off, true);
};

utils.read53BE = function read53BE(dst, off) {
  return utils.read64NBE(dst, off, true);
};

utils.write8 = function write8(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  return 1;
};

utils.write16 = function write16(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  return 2;
};

utils.write16BE = function write16BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 8) & 0xff;
  dst[off + 1] = num & 0xff;
  return 2;
};

utils.write32 = function write32(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  dst[off + 2] = (num >>> 16) & 0xff;
  dst[off + 3] = (num >>> 24) & 0xff;
  return 4;
};

utils.write32BE = function write32BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 24) & 0xff;
  dst[off + 1] = (num >>> 16) & 0xff;
  dst[off + 2] = (num >>> 8) & 0xff;
  dst[off + 3] = num & 0xff;
  return 4;
};

utils.write64 = function write64(dst, num, off) {
  var i;

  // if (!bn.isBN(num))
  //   num = new bn(+num);

  if (!bn.isBN(num))
    return utils.write64N(dst, num, off);

  off = off >>> 0;

  // Convert the number to the
  // negative byte representation.
  if (num.isNeg()) {
    if (num.cmpn(0) === 0)
      num = new bn(0);
    else
      num = num.neg().notn(64).subn(1);
  }

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toArray('le', 8);

  assert.equal(num.length, 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
};

utils.write64BE = function write64BE(dst, num, off) {
  var i;

  // if (!bn.isBN(num))
  //   num = new bn(+num);

  if (!bn.isBN(num))
    return utils.write64NBE(dst, num, off);

  off = off >>> 0;

  // Convert the number to the
  // negative byte representation.
  if (num.isNeg()) {
    if (num.cmpn(0) === 0)
      num = new bn(0);
    else
      num = num.neg().notn(64).subn(1);
  }

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toArray('be', 8);

  assert.equal(num.length, 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
};

utils.readVarint = function readVarint(arr, off) {
  var r, bytes;

  off = off >>> 0;

  if (arr[off] < 0xfd) {
    r = arr[off];
    bytes = 1;
  } else if (arr[off] === 0xfd) {
    r = arr[off + 1] | (arr[off + 2] << 8);
    bytes = 3;
  } else if (arr[off] === 0xfe) {
    r = utils.readU32(arr, off + 1);
    bytes = 5;
  } else if (arr[off] === 0xff) {
    r = utils.readU64N(arr, off + 1);
    bytes = 9;
  } else {
    assert(false, 'Malformed varint.');
  }

  return { off: off + bytes, r: r };
};

utils.writeVarint = function writeVarint(dst, num, off) {
  off = off >>> 0;

  if (bn.isBN(num)) {
    if (num.cmp(utils.U32) > 0) {
      dst[off] = 0xff;
      utils.writeU64(dst, num, off + 1);
      return 9;
    }
    num = num.toNumber();
  }

  num = +num;

  if (num < 0xfd) {
    dst[off] = num & 0xff;
    return 1;
  }

  if (num <= 0xffff) {
    dst[off] = 0xfd;
    dst[off + 1] = num & 0xff;
    dst[off + 2] = (num >>> 8) & 0xff;
    return 3;
  }

  if (num <= 0xffffffff) {
    dst[off] = 0xfe;
    dst[off + 1] = num & 0xff;
    dst[off + 2] = (num >>> 8) & 0xff;
    dst[off + 3] = (num >>> 16) & 0xff;
    dst[off + 4] = (num >>> 24) & 0xff;
    return 5;
  }

  dst[off] = 0xff;
  utils.writeU64N(dst, num, off + 1);

  return 9;
};

utils.sizeVarint = function sizeVarint(num) {
  if (bn.isBN(num)) {
    if (num.cmp(utils.U32) > 0)
      return 9;
    num = num.toNumber();
  }

  if (num < 0xfd)
    return 1;

  if (num <= 0xffff)
    return 3;

  if (num <= 0xffffffff)
    return 5;

  return 9;
};

utils.sizePush = function sizePush(num) {
  if (num <= 0x4b)
    return 1;

  if (num <= 0xff)
    return 2;

  if (num <= 0xffff)
    return 3;

  return 5;
};

utils.cmp = function(a, b) {
  var len, i;

  if (a.compare)
    return a.compare(b);

  len = Math.min(a.length, b.length);

  for (i = 0; i < len; i++) {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }

  if (a.length < b.length)
    return  -1;

  if (a.length > b.length)
    return  1;

  return 0;
};

// memcmp in constant time (can only return true or false)
// https://cryptocoding.net/index.php/Coding_rules
// $ man 3 memcmp (see NetBSD's consttime_memequal)
// This protects us against timing attacks when
// comparing an input against a secret string.
utils.ccmp = function(a, b) {
  var res = 0;
  var i;

  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));

  for (i = 0; i < a.length; i++)
    res |= a[i] ^ b[i];

  return res === 0;
};

utils.forRange = function forRange(from, to, iter, callback) {
  var pending = to - from;
  var i, error;

  callback = utils.asyncify(callback);

  if (pending <= 0)
    return callback();

  function next(err) {
    assert(pending > 0);
    if (err)
      error = err;
    if (!--pending)
      callback(error);
  }

  for (i = from; i < to; i++)
    iter(i, next, i);
};

utils.forEach = function forEach(arr, iter, callback) {
  var pending = arr.length;
  var error;

  callback = utils.asyncify(callback);

  if (!pending)
    return callback();

  function next(err) {
    assert(pending > 0);
    if (err)
      error = err;
    if (!--pending)
      callback(error);
  }

  arr.forEach(function(item, i) {
    iter(item, next, i);
  });
};

utils.forRangeSerial = function forRangeSerial(from, to, iter, callback) {
  var called = false;

  callback = utils.ensure(callback);

  (function next(err) {
    assert(!called);
    if (err) {
      called = true;
      return callback(err);
    }
    if (from >= to) {
      called = true;
      return callback();
    }
    from++;
    utils.nextTick(function() {
      iter(from - 1, next, from - 1);
    });
  })();
};

utils.forEachSerial = function forEachSerial(arr, iter, callback) {
  var i = 0;
  var called = false;

  callback = utils.ensure(callback);

  (function next(err) {
    var item;
    assert(!called);
    if (err) {
      called = true;
      return callback(err);
    }
    if (i >= arr.length) {
      called = true;
      return callback();
    }
    item = arr[i];
    i++;
    utils.nextTick(function() {
      iter(item, next, i - 1);
    });
  })();
};

utils.every = function every(arr, iter, callback) {
  var pending = arr.length;
  var result = true;
  var error;

  callback = utils.asyncify(callback);

  if (!pending)
    return callback(null, result);

  function next(err, res) {
    assert(pending > 0);
    if (err)
      error = err;
    if (!res)
      result = false;
    if (!--pending) {
      if (error)
        return callback(error);
      callback(null, result);
    }
  }

  arr.forEach(function(item, i) {
    iter(item, next, i);
  });
};

utils.everySerial = function everySerial(arr, iter, callback) {
  var i = 0;
  var called = false;

  callback = utils.ensure(callback);

  (function next(err, res) {
    var item;
    assert(!called);
    if (err) {
      called = true;
      return callback(err);
    }
    if (!res) {
      called = true;
      return callback(null, false);
    }
    if (i >= arr.length) {
      called = true;
      return callback(null, true);
    }
    item = arr[i];
    i++;
    utils.nextTick(function() {
      iter(item, next, i - 1);
    });
  })(null, true);
};

utils.mb = function mb(size) {
  return size / 1024 / 1024 | 0;
};

utils.inherits = function inherits(obj, from) {
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

utils.once = function once(callback) {
  var called;

  if (callback && callback._once)
    return callback;

  function onceFn(err, result1, result2) {
    if (called)
      return;
    called = true;
    if (callback)
      callback(err, result1, result2);
  }

  onceFn._once = true;
  if (callback)
    onceFn._asyncified = callback._asyncified;

  return onceFn;
};

utils.buildMerkleTree = function buildMerkleTree(leaves) {
  var tree = leaves.slice();
  var i, j, size, i2, hash;

  j = 0;
  size = leaves.length;

  for (; size > 1; size = ((size + 1) / 2) | 0) {
    for (i = 0; i < size; i += 2) {
      i2 = Math.min(i + 1, size - 1);
      if (i2 === i + 1 && i2 + 1 === size
          && utils.isEqual(tree[j + i], tree[j + i2])) {
        return;
      }
      hash = Buffer.concat([tree[j + i], tree[j + i2]]);
      hash = utils.dsha256(hash);
      tree.push(hash);
    }
    j += size;
  }

  if (!tree.length)
    return;

  return tree;
};

utils.getMerkleRoot = function getMerkleRoot(leaves) {
  var tree = utils.buildMerkleTree(leaves);
  if (!tree)
    return;

  return tree[tree.length - 1];
};

utils.getMerkleBranch = function getMerkleBranch(index, leaves) {
  var tree = utils.buildMerkleTree(leaves);
  var size = leaves.length;
  var branch = [];
  var j = 0;
  var i;

  for (; size > 1; size = (size + 1) / 2 | 0) {
    i = Math.min(index ^ 1, size - 1);
    branch.push(tree[j + i]);
    index >>= 1;
    j += size;
  }

  return branch;
};

utils.checkMerkleBranch = function checkMerkleBranch(hash, branch, index) {
  var otherside, i;

  if (index === -1)
    return false;

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  for (i = 0; i < branch.length; i++) {
    otherside = branch[i];

    if (index & 1)
      hash = utils.dsha256(Buffer.concat([otherside, hash]));
    else
      hash = utils.dsha256(Buffer.concat([hash, otherside]));

    index >>= 1;
  }

  return hash;
};

utils.indexOf = function indexOf(arr, buf) {
  var i;

  assert(Array.isArray(arr));
  assert(Buffer.isBuffer(buf));

  for (i = 0; i < arr.length; i++) {
    if (!Buffer.isBuffer(arr[i]))
      continue;
    if (utils.isEqual(arr[i], buf))
      return i;
  }

  return -1;
};

utils.pad32 = function pad32(num) {
  assert(num >= 0, num);
  num = num + '';
  while (num.length < 10)
    num = '0' + num;
  assert(num.length === 10);
  return num;
};

utils.wrap = function wrap(callback, unlock) {
  return function(err, result) {
    unlock();
    if (callback)
      callback(err, result);
  };
};

utils.parallel = function parallel(stack, callback) {
  var pending = stack.length;
  var error;
  var i;

  callback = utils.once(callback);

  if (!pending)
    return utils.nextTick(callback);

  function next(err) {
    assert(pending > 0);
    if (err)
      error = err;
    if (!--pending)
      callback(error);
  }

  for (i = 0; i < stack.length; i++) {
    try {
      if (stack[i].length >= 2) {
        stack[i](error, next);
        error = null;
      } else {
        if (error)
          continue;
        stack[i](next);
      }
    } catch (e) {
      pending--;
      error = e;
    }
  }
};

utils.serial = function serial(stack, callback) {
  var i = 0;
  (function next(err) {
    if (i++ >= stack.length)
      return callback(err);

    if (stack[i].length >= 2) {
      try {
        return stack[i](err, next);
      } catch (e) {
        return next(e);
      }
    }

    if (err)
      return utils.nextTick(next.bind(null, err));

    try {
      return stack[i](next);
    } catch (e) {
      return next(e);
    }
  })();
};

utils.toMap = function toMap(arr) {
  var map = {};
  arr.forEach(function(value) {
    map[value] = true;
  });
  return map;
};

utils.revMap = function revMap(map) {
  var reversed = {};
  Object.keys(map).forEach(function(key) {
    reversed[map[key]] = key;
  });
  return reversed;
};

if (utils.isBrowser) {
  bn.prototype.toBuffer = function toBuffer(order, size) {
    return this.toArrayLike(Buffer, order, size);
  };
}

/**
 * VerifyError
 */

function VerifyError(object, code, reason, score) {
  Error.call(this);

  if (Error.captureStackTrace)
    Error.captureStackTrace(this, VerifyError);

  this.type = 'VerifyError';

  this.hash = object.hash();
  this.height = object.height;

  if (object.getCoinbaseHeight && this.height === -1)
    this.height = object.getCoinbaseHeight();

  this.code = code;
  this.reason = score === -1 ? null : reason;
  this.score = score;
  this.message = reason
    + ' (code=' + code
    + ', score=' + score
    + ', height=' + this.height
    + ', hash=' + utils.revHex(utils.toHex(this.hash)) + ')';
}

utils.inherits(VerifyError, Error);

utils.VerifyError = VerifyError;
