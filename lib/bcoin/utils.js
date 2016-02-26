/**
 * utils.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var utils = exports;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var util = require('util');

/**
 * Utils
 */

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
  if (Buffer.isBuffer(msg))
    return Array.prototype.slice.call(msg);

  if (Array.isArray(msg))
    return msg.slice();

  if (!msg)
    return [];

  var res = [];
  var i, c, hi, lo, slice, num;

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

utils.toBase58 = function toBase58(arr) {
  var n = new bn(arr, 16);

  // 58 ^ 4
  var mod = new bn(0xacad10);

  var res = '';

  var r, end, i, c;

  do {
    r = n.mod(mod);
    n = n.div(mod);

    end = n.cmpn(0) === 0;

    utils.assert.equal(r.length, 1);
    r = r.words[0];

    for (i = 0; i < 4; i++) {
      c = r % 58;
      r = (r - c) / 58;

      if (c === 0 && r === 0 && end)
        break;
      res = base58[c] + res;
    }
    utils.assert.equal(r, 0);
  } while (!end);

  // Add leading "zeroes"
  for (i = 0; i < arr.length; i++) {
    if (arr[i] !== 0)
      break;
    res = '1' + res;
  }

  return res;
};

utils.fromBase58 = function fromBase58(str) {
  var i, zeroes, q, w, res, c, z;

  // Count leading "zeroes"
  for (i = 0; i < str.length; i++)
    if (str[i] !== '1')
      break;
  zeroes = i;

  // Read 4-char words and add them to bignum
  q = 1;
  w = 0;
  res = new bn(0);
  for (i = zeroes; i < str.length; i++) {
    c = unbase58[str[i]];
    if (!(c >= 0 && c < 58))
      return new Buffer([]);

    q *= 58;
    w *= 58;
    w += c;
    if (i === str.length - 1 || q === 0xacad10) {
      res = res.mul(new bn(q)).add(new bn(w));
      q = 1;
      w = 0;
    }
  }

  // Add leading "zeroes"
  z = [];
  for (i = 0; i < zeroes; i++)
    z.push(0);

  return new Buffer(z.concat(res.toArray()));
};

utils.isBase58 = function isBase58(msg) {
  return typeof msg === 'string' && /^[1-9a-zA-Z]+$/.test(msg);
};

utils.ripemd160 = function ripemd160(data, enc) {
  var result;

  if (!bcoin.crypto)
    return new Buffer(bcoin.hash.ripemd160().update(data, enc).digest());

  result = bcoin.crypto.createHash('ripemd160').update(data, enc).digest();

  return result;
};

utils.sha1 = function sha1(data, enc) {
  var result;

  if (!bcoin.crypto)
    return new Buffer(bcoin.hash.sha1().update(data, enc).digest());

  result = bcoin.crypto.createHash('sha1').update(data, enc).digest();

  return result;
};

utils.ripesha = function ripesha(data, enc) {
  return utils.ripemd160(utils.sha256(data, enc));
};

utils.checksum = function checksum(data, enc) {
  return utils.dsha256(data, enc).slice(0, 4);
};

utils.sha256 = function sha256(data, enc) {
  var result;

  if (!bcoin.crypto)
    return new Buffer(bcoin.hash.sha256().update(data, enc).digest());

  result = bcoin.crypto.createHash('sha256').update(data, enc).digest();

  return result;
};

utils.dsha256 = function dsha256(data, enc) {
  return utils.sha256(utils.sha256(data, enc));
};

utils.sha512hmac = function sha512hmac(data, salt) {
  var hmac, result;

  if (!bcoin.crypto) {
    hmac = bcoin.hash.hmac(hash.sha512, salt);
    return new Buffer(hmac.update(data).digest());
  }

  hmac = bcoin.crypto.createHmac('sha512', salt);
  result = hmac.update(data).digest();

  return result;
};

utils.salt = 'bcoin:';

utils.encrypt = function encrypt(data, passphrase) {
  var cipher, out;

  if (!bcoin.crypto)
    return data;

  if (data[0] === ':')
    return data;

  if (!passphrase)
    throw new Error('No passphrase.');

  cipher = bcoin.crypto.createCipher('aes-256-cbc', passphrase);

  out = '';
  out += cipher.update(utils.salt + data, 'utf8', 'hex');
  out += cipher.final('hex');

  return ':' + out;
};

utils.decrypt = function decrypt(data, passphrase) {
  var decipher, out;

  if (!bcoin.crypto)
    return data;

  if (data[0] !== ':')
    return data;

  if (!passphrase)
    throw new Error('No passphrase.');

  data = data.substring(1);

  decipher = bcoin.crypto.createDecipher('aes-256-cbc', passphrase);

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

  return new Buffer(msg).toString('hex');
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
  var i = 0;

  if (!a || !b)
    return false;

  if (a.length !== b.length)
    return false;

  for (; i < a.length; i++)
    if (a[i] !== b[i])
      return false;

  return true;
};

utils.nextTick = function nextTick(fn) {
  if (typeof setImmediate === 'function') {
    setImmediate(fn);
    return;
  }

  if (typeof process === 'object' && process.nextTick) {
    process.nextTick(fn);
    return;
  }

  setTimeout(fn, 1);
};

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

utils.revHex = function revHex(s) {
  var r = '';
  var i = 0;

  for (; i < s.length; i += 2)
    r = s.slice(i, i + 2) + r;

  return r;
};

utils.assert = function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
};

utils.assert.equal = function assertEqual(l, r, msg) {
  if (l != r)
    throw new Error(msg || ('Assertion failed: ' + l + ' != ' + r));
};

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
  if (val instanceof bn)
    return val;
  if (utils.isInt(val))
    return new bn(val, 10);
  if (utils.isHex(val))
    return new bn(val, 'hex');
  if (Buffer.isBuffer(val))
    return new bn(val);
  if (Array.isArray(val))
    return new bn(val);
  return false;
};

utils.isBTC = function isBTC(val) {
  if (utils.isFloat(val))
    return val;
  // For user input strings. Might cause overlap
  // with isSatoshi if not used carefully.
  // if (utils.isInt(val))
  //   return val;
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

  utils.assert(addr);

  if (typeof addr === 'object')
    return addr;

  if (addr.indexOf(']') !== -1)
    parts = addr.split(/\]:?/);
  else
    parts = addr.split(':');

  return {
    host: parts[0].replace(/[\[\]]/g, ''),
    port: +parts[1] || bcoin.protocol.network.port
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

  utils.assert(Buffer.isBuffer(ip));
  utils.assert(version === 4 || version === 6);

  if (version === 4) {
    // Check to see if this an
    // ipv4-mapped ipv6 address.
    if (ip.length > 4) {
      while (ip[0] === 0)
        ip = ip.slice(1);

      // Found an ipv4 address
      if (ip.length === 6 && ip[0] === 0xff && ip[1] === 0xff)
        return ip.slice(-4);

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

  utils.assert(version === 4 || version === 6);

  if (type === 0) {
    if (!Buffer.isBuffer(ip))
      ip = new Buffer([0, 0, 0, 0]);
  } else if (type === 4) {
    ip = new Buffer(ip.split('.').map(function(n) {
      return +n;
    }));
    utils.assert(ip.length <= 4);
  } else if (type === 6) {
    ip = new Buffer(ip.replace(/:/g, ''), 'hex');
    utils.assert(ip.length <= 16);
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

  utils.assert(version === 4 || version === 6);
  utils.assert(ip.length <= 16);

  ip = utils.ip2version(ip, version);

  if (version === 4)
    return Array.prototype.slice.call(ip).join('.');

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

utils.debug = function debug() {
  var args = Array.prototype.slice.call(arguments);
  var msg;

  if (bcoin.debug) {
    msg = utils.format(args, true);
    process.stdout.write(msg);
  }

  if (bcoin.debugFile && bcoin.fs) {
    if (!bcoin._debug) {
      bcoin.ensurePrefix();
      bcoin._debug = bcoin.fs.createWriteStream(
        bcoin.prefix + '/debug.log', { flags: 'a' });
    }
    msg = utils.format(args, false);
    bcoin._debug.write(process.pid + ': ' + msg);
  }
};

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

  // var overflow = mantissa !== 0 && ((exponent > 34)
  //   || (mantissa > 0xff && exponent > 33)
  //   || (mantissa > 0xffff && exponent > 32));

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

utils.hash = function hash(obj, enc) {
  if (obj == null)
    throw new Error('Cannot get hash of null');

  if (typeof obj === 'string')
    return enc === 'hex' ? obj : new Buffer(obj, 'hex');

  if (Buffer.isBuffer(obj))
    return enc === 'hex' ? utils.toHex(obj) : obj;

  if (typeof obj.hash === 'function')
    return obj.hash(enc);

  if (obj.hash)
    return hash(obj.hash, enc);

  if (obj._hash)
    return hash(obj._hash, enc);

  throw new Error('Cannot get hash of object');
};

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
  var i;

  if (!(num instanceof bn))
    num = new bn(+num);

  off = off >>> 0;

  // We shouldn't think of
  // this as negative.
  if (num.isNeg())
    num = num.neg();

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toArray('le', 8);

  utils.assert.equal(num.length, 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
};

utils.writeU64BE = function writeU64BE(dst, num, off) {
  var i;

  if (!(num instanceof bn))
    num = new bn(+num);

  off = off >>> 0;

  // We shouldn't think of
  // this as negative.
  if (num.isNeg())
    num = num.neg();

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toArray('be', 8);

  utils.assert.equal(num.length, 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
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

  if (!(num instanceof bn))
    num = new bn(+num);

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

  utils.assert.equal(num.length, 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
};

utils.write64BE = function write64BE(dst, num, off) {
  var i;

  if (!(num instanceof bn))
    num = new bn(+num);

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

  utils.assert.equal(num.length, 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
};

utils.readIntv = function readIntv(arr, off) {
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
    try {
      r = utils.readU64(arr, off + 1).toNumber();
    } catch (e) {
      r = 0;
    }
    bytes = 9;
  } else {
    // Malformed
    r = arr[off];
    bytes = 1;
  }

  return { off: off + bytes, r: r };
};

utils.writeIntv = function writeIntv(dst, num, off) {
  off = off >>> 0;

  if (num instanceof bn) {
    if (num.cmpn(0xffffffff) > 0) {
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
  utils.writeU64(dst, num, off + 1);
  return 9;
};

utils.sizeIntv = function sizeIntv(num) {
  if (num instanceof bn) {
    if (num.cmpn(0xffffffff) > 0)
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

utils.cmp = function(a, b) {
  var len = Math.min(a.length, b.length);

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

  if (a.length !== b.length)
    return false;

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
  var i, error;

  callback = utils.asyncify(callback);

  if (!pending)
    return callback();

  function next(err) {
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
  callback = utils.asyncify(callback);

  (function next(err) {
    if (err)
      return callback(err);
    if (from >= to)
      return callback();
    from++;
    utils.nextTick(function() {
      iter(from - 1, next, from - 1);
    });
  })();
};

utils.forEachSerial = function forEachSerial(arr, iter, callback) {
  var i = 0;

  callback = utils.asyncify(callback);

  (function next(err) {
    var item;
    if (err)
      return callback(err);
    if (i >= arr.length)
      return callback();
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
  var i, error;

  callback = utils.asyncify(callback);

  if (!pending)
    return callback(null, result);

  function next(err, res) {
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

  callback = utils.asyncify(callback);

  (function next(err, res) {
    var item;
    if (err)
      return callback(err);
    if (!result)
      return callback(null, false);
    if (i >= arr.length)
      return callback(null, true);
    item = arr[i];
    i++;
    utils.nextTick(function() {
      iter(item, next, i - 1);
    });
  })();
};

utils.mb = function mb(size) {
  return size / 1024 / 1024 | 0;
};

utils.inherits = function inherits(obj, from) {
  if (Object.create) {
    obj.prototype = Object.create(from.prototype, {
      constructor: {
        value: obj,
        enumerable: false
      }
    });
    return;
  }
  var f = function() {};
  f.prototype = from.prototype;
  obj.prototype = new f;
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
  var branch = [];
  var size = this.totalTX;
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
