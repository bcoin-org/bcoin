/*!
 * utils.js - utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

/**
 * @exports utils
 */

var utils = exports;

var assert = require('assert');
var bn = require('bn.js');
var util = require('util');
var crypto, hash, aes;

/**
 * Whether we're in a browser or not.
 * @const {Boolean}
 */

utils.isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

if (!utils.isBrowser) {
  crypto = require('cry' + 'pto');
} else {
  hash = require('hash.js');
  aes = require('./aes');
}

/**
 * Global NOP function.
 * @type function
 * @static
 * @method
 */

utils.nop = function() {};

/**
 * Garbage collector for `--expose-gc`.
 * @type function
 * @static
 * @method
 */

utils.gc = !utils.isBrowser && typeof gc === 'function' ? gc : utils.nop;

/**
 * A slow buffer slice (will allocate a new buffer).
 * @param {Buffer} data
 * @param {Number?} start
 * @param {Number?} end
 * @returns {Buffer}
 */

utils.slice = function slice(data, start, end) {
  var clone;

  if (start != null)
    data = data.slice(start, end);

  clone = new Buffer(data.length);

  data.copy(clone, 0, 0, data.length);

  return clone;
};

/*
 * Base58
 */

var base58 = ''
  + '123456789'
  + 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  + 'abcdefghijkmnopqrstuvwxyz';

var unbase58 = {};

for (var i = 0; i < base58.length; i++)
  unbase58[base58[i]] = i;

/**
 * Encode a base58 string.
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 * @param {Buffer} data
 * @returns {Base58String}
 */

utils.toBase58 = function toBase58(data) {
  var zeroes = 0;
  var length = 0;
  var str = '';
  var i, b58, carry, j, k;

  for (i = 0; i < data.length; i++) {
    if (data[i] !== 0)
      break;
    zeroes++;
  }

  b58 = new Buffer(((data.length * 138 / 100) | 0) + 1);
  b58.fill(0);

  for (; i < data.length; i++) {
    carry = data[i];
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

  i = b58.length - length;
  while (i < b58.length && b58[i] === 0)
    i++;

  for (j = 0; j < zeroes; j++)
    str += '1';

  for (; i < b58.length; i++)
    str += base58[b58[i]];

  return str;
};

/**
 * Decode a base58 string.
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 * @param {Base58String} str
 * @returns {Buffer}
 * @throws on non-base58 character.
 */

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
  while (i < b256.length && b256[i] === 0)
    i++;

  out = new Buffer(zeroes + (b256.length - i));

  for (j = 0; j < zeroes; j++)
    out[j] = 0;

  while (i < b256.length)
    out[j++] = b256[i++];

  return out;
};

/**
 * Test whether a string is base58 (note that you
 * may get a false positive on a hex string).
 * @param {String?} obj
 * @returns {Boolean}
 */

utils.isBase58 = function isBase58(obj) {
  return typeof obj === 'string' && /^[1-9a-zA-Z]+$/.test(obj);
};

/**
 * Hash with chosen algorithm.
 * @param {String} alg
 * @param {Buffer|String} data
 * @param {String?} enc - Any buffer-supported encoding.
 * @returns {Buffer}
 */

utils.hash = function _hash(alg, data, enc) {
  if (!crypto)
    return new Buffer(hash[alg]().update(data, enc).digest());

  return crypto.createHash(alg).update(data, enc).digest();
};

/**
 * Hash with ripemd160.
 * @param {Buffer|String} data
 * @param {String?} enc - Any buffer-supported encoding.
 * @returns {Buffer}
 */

utils.ripemd160 = function ripemd160(data, enc) {
  return utils.hash('ripemd160', data, enc);
};

/**
 * Hash with sha1.
 * @param {Buffer|String} data
 * @param {String?} enc - Any buffer-supported encoding.
 * @returns {Buffer}
 */

utils.sha1 = function sha1(data, enc) {
  return utils.hash('sha1', data, enc);
};

/**
 * Hash with sha256.
 * @param {Buffer|String} data
 * @param {String?} enc - Any buffer-supported encoding.
 * @returns {Buffer}
 */

utils.sha256 = function sha256(data, enc) {
  return utils.hash('sha256', data, enc);
};

/**
 * Hash with sha256 and ripemd160 (OP_HASH160).
 * @param {Buffer|String} data
 * @param {String?} enc - Any buffer-supported encoding.
 * @returns {Buffer}
 */

utils.ripesha = function ripesha(data, enc) {
  return utils.ripemd160(utils.sha256(data, enc));
};

/**
 * Hash with sha256 twice (OP_HASH256).
 * @param {Buffer|String} data
 * @param {String?} enc - Any buffer-supported encoding.
 * @returns {Buffer}
 */

utils.dsha256 = function dsha256(data, enc) {
  return utils.sha256(utils.sha256(data, enc));
};

/**
 * Create a sha256 checksum (common in bitcoin).
 * @param {Buffer|String} data
 * @param {String?} enc - Any buffer-supported encoding.
 * @returns {Buffer}
 */

utils.checksum = function checksum(data, enc) {
  return utils.dsha256(data, enc).slice(0, 4);
};

/**
 * Create an HMAC.
 * @param {String} alg
 * @param {Buffer} data
 * @param {Buffer} salt
 * @returns {Buffer} HMAC
 */

utils.hmac = function hmac(alg, data, salt) {
  var hmac;

  if (!crypto) {
    hmac = hash.hmac(hash[alg], salt);
    return new Buffer(hmac.update(data).digest());
  }

  hmac = crypto.createHmac(alg, salt);
  return hmac.update(data).digest();
};

/**
 * Perform key stretching using PBKDF2.
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iterations
 * @param {Number} dkLen - Output size.
 * @param {String?} alg
 */

/*!
 * PBKDF2
 * Credit to: https://github.com/stayradiated/pbkdf2-sha512
 * Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
 * Copyright (c) 2014, JP Richardson
 */

utils.pbkdf2 = function pbkdf2(key, salt, iterations, dkLen, alg) {
  var hLen, DK, U, T, block, l, r;
  var i, j, k, destPos, len;

  if (typeof key === 'string')
    key = new Buffer(key, 'utf8');

  if (typeof salt === 'string')
    salt = new Buffer(salt, 'utf8');

  if (!alg)
    alg = 'sha512';

  if (crypto && crypto.pbkdf2Sync)
    return crypto.pbkdf2Sync(key, salt, iterations, dkLen, alg);

  if (alg === 'sha512')
    hLen = 64;
  else if (alg === 'sha256')
    hLen = 32;
  else if (alg === 'sha1' || alg === 'ripemd160')
    hLen = 20;
  else if (alg === 'md5')
    hLen = 16;

  assert(dkLen <= 0xffffffff * hLen, 'Requested key length too long');

  DK = new Buffer(dkLen);
  T = new Buffer(hLen);
  block = new Buffer(salt.length + 4);

  l = Math.ceil(dkLen / hLen);
  r = dkLen - (l - 1) * hLen;

  salt.copy(block, 0, 0, salt.length);

  for (i = 1; i <= l; i++) {
    block[salt.length + 0] = (i >>> 24) & 0xff;
    block[salt.length + 1] = (i >>> 16) & 0xff;
    block[salt.length + 2] = (i >>> 8) & 0xff;
    block[salt.length + 3] = (i >>> 0) & 0xff;

    U = utils.hmac(alg, block, key);

    U.copy(T, 0, 0, hLen);

    for (j = 1; j < iterations; j++) {
      U = utils.hmac(alg, U, key);

      for (k = 0; k < hLen; k++)
        T[k] ^= U[k];
    }

    destPos = (i - 1) * hLen;
    len = i === l ? r : hLen;
    T.copy(DK, destPos, 0, len);
  }

  return DK;
};

/**
 * Encrypt with aes-256-cbc.
 * @param {Buffer|String} data
 * @param {Buffer|String} passphrase
 * @returns {Buffer}
 */

utils.encrypt = function encrypt(data, passphrase) {
  var key, cipher;

  assert(crypto, 'No crypto module available.');
  assert(passphrase, 'No passphrase.');

  if (typeof data === 'string')
    data = new Buffer(data, 'utf8');

  if (typeof passphrase === 'string')
    passphrase = new Buffer(passphrase, 'utf8');

  key = utils.pbkdf2key(passphrase, null, 2048, 32, 16);

  if (!crypto)
    return aes.cbc.encrypt(data, key.key, key.iv);

  cipher = crypto.createCipheriv('aes-256-cbc', key.key, key.iv);

  return Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);
};

/**
 * Decrypt from aes-256-cbc.
 * @param {Buffer|String} data
 * @param {Buffer|String} passphrase
 * @returns {Buffer}
 */

utils.decrypt = function decrypt(data, passphrase) {
  var key, decipher;

  assert(crypto, 'No crypto module available.');
  assert(passphrase, 'No passphrase.');

  if (typeof data === 'string')
    data = new Buffer(data, 'hex');

  if (typeof passphrase === 'string')
    passphrase = new Buffer(passphrase, 'utf8');

  key = utils.pbkdf2key(passphrase, null, 2048, 32, 16);

  if (!crypto)
    return aes.cbc.decrypt(data, key.key, key.iv);

  decipher = crypto.createDecipheriv('aes-256-cbc', key.key, key.iv);

  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
};

/**
 * Generate a key and IV using pbkdf2.
 * @param {Buffer|String} passphrase
 * @param {(Buffer|String)?} salt
 * @param {Number} iterations
 * @param {Number} dkLen
 * @param {Number} ivLen
 * @param {String?} alg
 * @returns {Buffer}
 */

utils.pbkdf2key = function pbkdf2key(passphrase, salt, iterations, dkLen, ivLen, alg) {
  var key = utils.pbkdf2(passphrase, salt || '', iterations, dkLen + ivLen, alg);
  return {
    key: key.slice(0, dkLen),
    iv: key.slice(dkLen)
  };
};

/**
 * Test whether a string is hex. Note that this
 * may yield a false positive on base58 strings.
 * @param {String?} obj
 * @returns {Boolean}
 */

utils.isHex = function isHex(obj) {
  return typeof obj === 'string' && /^[0-9a-f]+$/i.test(obj);
};

/**
 * Test whether two buffers are equal.
 * @param {Buffer?} a
 * @param {Buffer?} b
 * @returns {Boolean}
 */

utils.equal = function equal(a, b) {
  var i;

  if (!Buffer.isBuffer(a))
    return false;

  if (!Buffer.isBuffer(b))
    return false;

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
 * @name nextTick
 * @function
 * @param {Function} callback
 */

if (typeof setImmediate === 'function') {
  utils.nextTick = setImmediate;
} else if (!utils.isBrowser) {
  utils.nextTick = process.nextTick;
} else {
  utils.nextTick = function nextTick(fn) {
    setTimeout(fn, 1);
  };
}

/**
 * Wrap a function in a `nextTick`.
 * @param {Function} callback
 * @returns {Function} Asyncified function.
 */

utils.asyncify = function asyncify(callback) {
  if (callback && callback._asyncified)
    return callback;

  function asyncifyFn(err, result1, result2) {
    if (!callback)
      return;
    utils.nextTick(function() {
      callback(err, result1, result2);
    });
  }

  asyncifyFn._asyncified = true;
  if (callback)
    asyncifyFn._once = callback._once;

  return asyncifyFn;
};

/**
 * Ensure a callback exists, return a NOP if not.
 * @param {Function} callback
 * @returns {Function}
 */

utils.ensure = function ensure(callback) {
  if (!callback)
    return utils.nop;
  return callback;
};

/**
 * Reverse a hex-string (used because of
 * bitcoind's affinity for uint256le).
 * @param {String} s - Hex string.
 * @returns {String} Reversed hex string.
 */

utils.revHex = function revHex(s) {
  var r = '';
  var i = 0;

  for (; i < s.length; i += 2)
    r = s.slice(i, i + 2) + r;

  return r;
};

/**
 * Shallow merge between multiple objects.
 * @param {Object} target
 * @param {...Object} args
 * @returns {Object} target
 */

utils.merge = function merge(target) {
  var args = Array.prototype.slice.call(arguments, 1);
  args.forEach(function(obj) {
    Object.keys(obj).forEach(function(key) {
      target[key] = obj[key];
    });
  });
  return target;
};

/**
 * Assertion.
 * @param {Boolean} value - Expression.
 * @param {String?} message - Optional error message.
 */

utils.assert = function _assert(value, message) {
  if (!value) {
    throw new assert.AssertionError({
      message: message,
      actual: value,
      expected: true,
      operator: '==',
      stackStartFunction: _assert
    });
  }
};

utils.merge(utils.assert, assert);

utils.assert.fatal = function fatal(value, message) {
  var err;

  if (!value) {
    if (!message)
      message = 'Assertion failed (fatal exception)';

    err = new assert.AssertionError({
      message: message,
      actual: value,
      expected: true,
      operator: '==',
      stackStartFunction: fatal
    });

    if (process.exit) {
      console.error(err.stack + '');
      process.exit(1);
    } else {
      throw err;
    }
  }
};

/**
 * One bitcoin in satoshis.
 * @const {BN}
 * @default
 */

utils.COIN = new bn(10000000).muln(10);

/**
 * Convert satoshis to a BTC string. Note that
 * BTC strings _always_ have a decimal point.
 * @param {BN|Number} satoshi
 * @returns {String} BTC string.
 */

utils.btc = function btc(satoshi) {
  var neg = false;
  var btc, hi, lo;

  if (utils.isBTC(satoshi))
    return satoshi;

  assert(utils.isSatoshi(satoshi), 'Non-satoshi value for conversion.');

  if (satoshi.isNeg()) {
    satoshi = satoshi.neg();
    neg = true;
  }

  hi = satoshi.div(utils.COIN).toString(10);

  lo = satoshi.mod(utils.COIN);

  lo = lo.toString(10);

  while (lo.length < 8)
    lo = '0' + lo;

  lo = '.' + lo;

  lo = lo.replace(/0+$/, '');
  if (lo === '.')
    lo += '0';

  btc = hi + lo;

  if (neg)
    btc = '-' + btc;

  return btc;
};

/**
 * Convert BTC string to satoshis.
 * @param {String|Number} btc
 * @returns {BN} Satoshis.
 */

utils.satoshi = function satoshi(btc) {
  var neg = false;
  var satoshi, parts, hi, lo;

  if (utils.isSatoshi(btc))
    return btc;

  assert(utils.isBTC(btc), 'Non-BTC value for conversion.');

  if (btc[0] === '-') {
    neg = true;
    btc = btc.substring(1);
  }

  parts = btc.split('.');
  hi = parts[0] || '0';
  lo = parts[1] || '0';

  while (lo.length < 8)
    lo += '0';

  satoshi = (hi + lo).replace(/^0+/, '');

  satoshi = new bn(satoshi, 10);

  if (neg)
    satoshi.ineg();

  return satoshi;
};

/**
 * Test whether a number is both a Number and finite.
 * @param {Number?} val
 * @returns {Boolean}
 */

utils.isNumber = function isNumber(val) {
  return typeof val === 'number' && isFinite(val);
};

/**
 * Test whether an object qualifies as satoshis.
 * @param {BN?} val
 * @returns {Boolean}
 */

utils.isSatoshi = function isSatoshi(val) {
  return bn.isBN(val);
};

/**
 * Test whether an object qualifies as a BTC string.
 * @param {String?} val
 * @returns {Boolean}
 */

utils.isBTC = function isBTC(val) {
  return typeof val === 'string' && /^-?\d+\.\d+$/.test(val);
};

/**
 * Parse a hostname.
 * @example
 * utils.parseHost('127.0.0.1:3000');
 * @param {String|Seed} addr
 * @returns {Seed}
 */

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

/**
 * Test whether a string is an IP address.
 * @param {String?} ip
 * @returns {Number} IP version (4 or 6).
 */

utils.isIP = function isIP(ip) {
  if (typeof ip !== 'string')
    return 0;

  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip))
    return 4;

  if (/:[0-9a-f]{1,4}/i.test(ip))
    return 6;

  return 0;
};

/**
 * Cast an IPv6 or IPv4 to IPv4 or IPv6 respectively
 * (if possible using ipv4-mapped ipv6 addresses).
 * @param {Buffer} ip
 * @param {Number} version - 4 or 6.
 * @returns {Buffer} IP address.
 */

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

/**
 * Convert an IP string to a buffer.
 * @param {String} ip
 * @param {Number} version - 4 or 6.
 * @returns {Buffer}
 */

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

/**
 * Convert a buffer to an ip string.
 * @param {Buffer} ip
 * @param {Number} version - 4 or 6.
 * @returns {String}
 */

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

/**
 * util.inspect() with 20 levels of depth.
 * @param {Object|String} obj
 * @param {Boolean?} color
 * @return {String}
 */

utils.inspectify = function inspectify(obj, color) {
  return typeof obj !== 'string'
    ? util.inspect(obj, null, 20, color !== false)
    : obj;
};

/**
 * Format a string.
 * @param {Array} args
 * @param {Boolean?} color
 * @return {String}
 */

utils.format = function format(args, color) {
  color = color
    ? (process.stdout ? process.stdout.isTTY : false)
    : false;

  return typeof args[0] === 'object'
    ? utils.inspectify(args[0], color)
    : util.format.apply(util, args);
};

/**
 * Write a message to stdout (console in browser).
 * @param {Object|String} obj
 * @param {...String} args
 */

utils.print = function print() {
  var args = Array.prototype.slice.call(arguments);
  var msg;

  if (utils.isBrowser) {
    msg = typeof args[0] !== 'object'
      ? utils.format(args, false)
      : args[0];
    console.log(msg);
    return;
  }

  msg = utils.format(args, true);
  process.stdout.write(msg + '\n');
};

/**
 * Write a message to stderr (console in browser).
 * @param {Object|String} obj
 * @param {...String} args
 */

utils.error = function error() {
  var args = Array.prototype.slice.call(arguments);
  var msg;

  if (utils.isBrowser) {
    msg = typeof args[0] !== 'object'
      ? utils.format(args, false)
      : args[0];
    console.error(msg);
    return;
  }

  msg = utils.format(args, true);
  process.stderr.write(msg + '\n');
};

/**
 * Sort public keys lexicographically.
 * @param {Buffer[]} keys
 * @returns {Buffer[]} Sorted keys.
 */

utils.sortKeys = function sortKeys(keys) {
  return keys.slice().sort(function(a, b) {
    return utils.cmp(a, b);
  });
};

/**
 * Sort HD public keys lexicographically.
 * @param {HDPublicKey[]} keys
 * @returns {HDPublicKey[]} Sorted keys.
 */

utils.sortHDKeys = function sortHDKeys(keys) {
  return keys.slice().sort(function(a, b) {
    return utils.cmp(a.publicKey, b.publicKey);
  });
};

/**
 * Sort transactions by timestamp.
 * @param {TX[]} txs
 * @returns {TX[]} Sorted transactions.
 */

utils.sortTX = function sortTX(txs) {
  return txs.slice().sort(function(a, b) {
    a = a.ts || a.ps;
    b = b.ts || b.ps;
    return a - b;
  });
};

/**
 * Unique-ify an array of strings.
 * @param {String[]} obj
 * @returns {String[]}
 */

utils.uniq = function uniq(obj) {
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
 * Convert a mantissa/compact number to a big number.
 * Used for `block.bits` -> `target` conversion.
 * @param {Number} compact
 * @returns {BN}
 */

utils.fromCompact = function fromCompact(compact) {
  var exponent = compact >>> 24;
  var negative = (compact >>> 23) & 1;
  var mantissa = compact & 0x7fffff;
  var num;

  if (compact === 0)
    return new bn(0);

  // Logic ported from btcd since
  // the bitcoind code is a nightmare.
  if (exponent <= 3) {
    mantissa >>>= 8 * (3 - exponent);
    num = new bn(mantissa);
  } else {
    num = new bn(mantissa);
    num.iushln(8 * (exponent - 3));
  }

  if (negative)
    num.ineg();

  return num;
};

/**
 * Convert a big number to a mantissa/compact number.
 * Used for `target` -> `block.bits` conversion.
 * @param {BN} num
 * @returns {Number}
 */

utils.toCompact = function toCompact(num) {
  var mantissa, exponent, compact;

  if (num.cmpn(0) === 0)
    return 0;

  exponent = num.byteLength();

  // Logic ported from btcd since
  // the bitcoind code is a nightmare.
  if (exponent <= 3) {
    mantissa = num.toNumber();
    mantissa <<= 8 * (3 - exponent);
  } else {
    mantissa = num.ushrn(8 * (exponent - 3)).toNumber();
  }

  if (mantissa & 0x800000) {
    mantissa >>= 8;
    exponent++;
  }

  compact = (exponent << 24) | mantissa;

  if (num.isNeg())
    compact |= 0x800000;

  if (compact < 0)
    compact += 0x100000000;

  return compact;
};

/**
 * Test hash against a target.
 * @param {BN|Number} target - Compact number or big number.
 * @param {Buffer|Hash} hash
 * @returns {Boolean} True if hash is less than target.
 */

utils.testTarget = function testTarget(target, hash) {
  if (typeof target === 'number')
    target = utils.fromCompact(target);

  if (typeof hash === 'string')
    hash = new Buffer(hash, 'hex');

  return new bn(hash, 'le').cmp(target) < 0;
};

/**
 * Get current time in unix time (seconds).
 * @returns {Number}
 */

utils.now = function now() {
  return +new Date() / 1000 | 0;
};

/**
 * Create a Date ISO string from time in unix time (seconds).
 * @param {Number?} ts - Seconds in unix time.
 * @returns {String}
 */

utils.date = function date(ts) {
  if (ts == null)
    ts = utils.now();

  return new Date(ts * 1000).toISOString().slice(0, -5) + 'Z';
};

/**
 * Get unix seconds from a Date string.
 * @param {String} date - Date ISO String.
 * @returns {Number}
 */

utils.time = function time(date) {
  if (date == null)
    return utils.now();

  return new Date(date) / 1000 | 0;
};

/**
 * UINT32_MAX
 * @type BN
 * @const
 */

utils.U32 = new bn(0xffffffff);

/**
 * UINT64_MAX
 * @type BN
 * @const
 */

utils.U64 = new bn('ffffffffffffffff', 'hex');

/**
 * Create a 64 bit nonce.
 * @returns {BN}
 */

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

/**
 * Read uint8.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.readU8 = function readU8(data, off) {
  off = off >>> 0;
  return data[off];
};

/**
 * Read uint16le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.readU16 = function readU16(data, off) {
  off = off >>> 0;
  return data[off] | (data[off + 1] << 8);
};

/**
 * Read uint16be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.readU16BE = function readU16BE(data, off) {
  off = off >>> 0;
  return (data[off] << 8) | data[off + 1];
};

/**
 * Read uint32le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.readU32 = function readU32(data, off) {
  off = off >>> 0;

  return ((data[off])
    | (data[off + 1] << 8)
    | (data[off + 2] << 16))
    + (data[off + 3] * 0x1000000);
};

/**
 * Read uint32be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.readU32BE = function readU32BE(data, off) {
  off = off >>> 0;

  return (data[off] * 0x1000000)
    + ((data[off + 1] << 16)
    | (data[off + 2] << 8)
    | data[off + 3]);
};

/**
 * Read uint64le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.readU64 = function readU64(data, off) {
  var num;
  off = off >>> 0;
  num = data.slice(off, off + 8);
  return new bn(num, 'le');
};

/**
 * Read uint64be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.readU64BE = function readU64BE(data, off) {
  var num;
  off = off >>> 0;
  num = data.slice(off, off + 8);
  return new bn(num, 'be');
};

/**
 * Read int8.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.read8 = function read8(data, off) {
  var num;
  off = off >>> 0;
  num = data[off];
  return !(num & 0x80) ? num : (0xff - num + 1) * -1;
};

/**
 * Read int16le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.read16 = function read16(data, off) {
  var num;
  off = off >>> 0;
  num = data[off] | (data[off + 1] << 8);
  return (num & 0x8000) ? num | 0xffff0000 : num;
};

/**
 * Read int16be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.read16BE = function read16BE(data, off) {
  var num;
  off = off >>> 0;
  num = data[off + 1] | (data[off] << 8);
  return (num & 0x8000) ? num | 0xffff0000 : num;
};

/**
 * Read int32le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.read32 = function read32(data, off) {
  off = off >>> 0;

  return (data[off])
    | (data[off + 1] << 8)
    | (data[off + 2] << 16)
    | (data[off + 3] << 24);
};

/**
 * Read int32be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.read32BE = function read32BE(data, off) {
  off = off >>> 0;

  return (data[off] << 24)
    | (data[off + 1] << 16)
    | (data[off + 2] << 8)
    | (data[off + 3]);
};

/**
 * Read int64le.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.read64 = function read64(data, off) {
  var num;

  off = off >>> 0;

  num = data.slice(off, off + 8);

  if (num[num.length - 1] & 0x80)
    return new bn(num, 'le').notn(64).addn(1).neg();

  return new bn(num, 'le');
};

/**
 * Read int64be.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {BN}
 */

utils.read64BE = function read64BE(data, off) {
  var num;

  off = off >>> 0;

  num = data.slice(off, off + 8);

  if (num[0] & 0x80)
    return new bn(num, 'be').notn(64).addn(1).neg();

  return new bn(num, 'be');
};

/**
 * Write uint8.
 * @param {Number} value
 */

utils.writeU8 = function writeU8(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  return 1;
};

/**
 * Write uint16le.
 * @param {Number} value
 */

utils.writeU16 = function writeU16(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  return 2;
};

/**
 * Write uint16be.
 * @param {Number} value
 */

utils.writeU16BE = function write16BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 8) & 0xff;
  dst[off + 1] = num & 0xff;
  return 2;
};

/**
 * Write uint32le.
 * @param {Number} value
 */

utils.writeU32 = function writeU32(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off + 3] = (num >>> 24) & 0xff;
  dst[off + 2] = (num >>> 16) & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  dst[off] = num & 0xff;
  return 4;
};

/**
 * Write uint32be.
 * @param {Number} value
 */

utils.writeU32BE = function writeU32BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 24) & 0xff;
  dst[off + 1] = (num >>> 16) & 0xff;
  dst[off + 2] = (num >>> 8) & 0xff;
  dst[off + 3] = num & 0xff;
  return 4;
};

/**
 * Write uint64le.
 * @param {BN|Number} value
 */

utils.writeU64 = function writeU64(dst, num, off) {
  return utils.write64(dst, num, off);
};

/**
 * Write uint64be.
 * @param {BN|Number} value
 */

utils.writeU64BE = function writeU64BE(dst, num, off) {
  return utils.write64BE(dst, num, off);
};

/**
 * Write a javascript number as a uint64le (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.writeU64N = function writeU64N(dst, num, off) {
  return utils.write64N(dst, num, off);
};

/**
 * Write a javascript number as a uint64be (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.writeU64NBE = function writeU64NBE(dst, num, off) {
  return utils.write64NBE(dst, num, off);
};

/**
 * Max safe integer (53 bits).
 * @type Number
 * @const
 */

utils.MAX_SAFE_INTEGER = 0x1fffffffffffff;

/**
 * Max safe integer as a big number (53 bits).
 * @type BN
 * @const
 */

utils.MAX_SAFE_BN = new bn(utils.MAX_SAFE_INTEGER);

/**
 * Most-significant 4 bytes of max safe integer.
 * @type Number
 * @const
 */

utils.MAX_SAFE_HI = 0x1fffff;

/**
 * Write a javascript number as an int64le (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

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

/**
 * Write a javascript number as an int64be (faster than big numbers).
 * @param {Number} value
 * @throws on num > MAX_SAFE_INTEGER
 */

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

/**
 * Read uint64le as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.readU64N = function readU64N(data, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32(data, off + 4);
  var lo = utils.readU32(data, off);
  if (force53)
    hi &= utils.MAX_SAFE_HI;
  assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
  return (hi * 0x100000000) + lo;
};

/**
 * Read uint64be as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.readU64NBE = function readU64NBE(data, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32BE(data, off);
  var lo = utils.readU32BE(data, off + 4);
  if (force53)
    hi &= utils.MAX_SAFE_HI;
  assert(hi <= utils.MAX_SAFE_HI, 'Number exceeds 2^53-1');
  return (hi * 0x100000000) + lo;
};

/**
 * Read int64le as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.read64N = function read64N(data, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32(data, off + 4);
  var lo = utils.readU32(data, off);
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

/**
 * Read int64be as a js number.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean} force53 - Read only 53 bits, but maintain the sign.
 * @returns {Number}
 * @throws on num > MAX_SAFE_INTEGER
 */

utils.read64NBE = function read64NBE(data, off, force53) {
  off = off >>> 0;
  var hi = utils.readU32BE(data, off);
  var lo = utils.readU32BE(data, off + 4);
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

/**
 * Read first least significant 53 bits of
 * a uint64le as a js number. Maintain the sign.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.readU53 = function readU53(data, off) {
  return utils.readU64N(data, off, true);
};

/**
 * Read first least significant 53 bits of
 * a uint64be as a js number. Maintain the sign.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.readU53BE = function readU53BE(data, off) {
  return utils.readU64NBE(data, off, true);
};

/**
 * Read first least significant 53 bits of
 * a uint64le as a js number. Maintain the sign.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.read53 = function read53(data, off) {
  return utils.read64N(data, off, true);
};

/**
 * Read first least significant 53 bits of
 * a int64be as a js number. Maintain the sign.
 * @param {Buffer} data
 * @param {Number} off
 * @returns {Number}
 */

utils.read53BE = function read53BE(data, off) {
  return utils.read64NBE(data, off, true);
};

/**
 * Write int8.
 * @param {Buffer} dst
 * @param {Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write8 = function write8(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  return 1;
};

/**
 * Write int16le.
 * @param {Buffer} dst
 * @param {Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write16 = function write16(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  return 2;
};

/**
 * Write int16be.
 * @param {Buffer} dst
 * @param {Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write16BE = function write16BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 8) & 0xff;
  dst[off + 1] = num & 0xff;
  return 2;
};

/**
 * Write int32le.
 * @param {Buffer} dst
 * @param {Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write32 = function write32(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  dst[off + 2] = (num >>> 16) & 0xff;
  dst[off + 3] = (num >>> 24) & 0xff;
  return 4;
};

/**
 * Write int32be.
 * @param {Buffer} dst
 * @param {Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write32BE = function write32BE(dst, num, off) {
  num = +num;
  off = off >>> 0;
  dst[off] = (num >>> 24) & 0xff;
  dst[off + 1] = (num >>> 16) & 0xff;
  dst[off + 2] = (num >>> 8) & 0xff;
  dst[off + 3] = num & 0xff;
  return 4;
};

/**
 * Write int64le.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write64 = function write64(dst, num, off) {
  var i;

  if (!bn.isBN(num))
    return utils.write64N(dst, num, off);

  off = off >>> 0;

  if (num.isNeg())
    num = num.neg().notn(64).addn(1);

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toBuffer('le', 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
};

/**
 * Write int64be.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

utils.write64BE = function write64BE(dst, num, off) {
  var i;

  if (!bn.isBN(num))
    return utils.write64NBE(dst, num, off);

  off = off >>> 0;

  if (num.isNeg())
    num = num.neg().notn(64).addn(1);

  if (num.bitLength() > 64)
    num = num.uand(utils.U64);

  num = num.toBuffer('be', 8);

  for (i = 0; i < num.length; i++)
    dst[off++] = num[i] & 0xff;

  return 8;
};

/**
 * Read a varint.
 * @param {Buffer} data
 * @param {Number} off
 * @param {Boolean?} big - Whether to read as a big number.
 * @returns {Number}
 */

utils.readVarint = function readVarint(data, off, big) {
  var r, bytes;

  off = off >>> 0;

  assert(off < data.length);

  if (data[off] < 0xfd) {
    r = data[off];
    if (big)
      r = new bn(r);
    bytes = 1;
  } else if (data[off] === 0xfd) {
    assert(off + 2 < data.length);
    r = data[off + 1] | (data[off + 2] << 8);
    if (big)
      r = new bn(r);
    bytes = 3;
  } else if (data[off] === 0xfe) {
    assert(off + 4 < data.length);
    r = utils.readU32(data, off + 1);
    if (big)
      r = new bn(r);
    bytes = 5;
  } else if (data[off] === 0xff) {
    assert(off + 8 < data.length);
    if (big)
      r = utils.readU64(data, off + 1);
    else
      r = utils.readU64N(data, off + 1);
    bytes = 9;
  } else {
    assert(false, 'Malformed varint.');
  }

  return { off: off + bytes, r: r };
};

/**
 * Write a varint.
 * @param {Buffer} dst
 * @param {BN|Number} num
 * @param {Number} off
 * @returns {Number} Number of bytes written.
 */

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

/**
 * Calculate size of varint.
 * @param {BN|Number} num
 * @returns {Number} size
 */

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

/**
 * Calculate the size (including
 * the opcode) of a pushdata.
 * @param {Number} num - Pushdata data length.
 * @returns {Number} size
 */

utils.sizePush = function sizePush(num) {
  if (num <= 0x4b)
    return 1;

  if (num <= 0xff)
    return 2;

  if (num <= 0xffff)
    return 3;

  return 5;
};

/**
 * Buffer comparator (memcmp + length comparison).
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Number} -1, 1, or 0.
 */

utils.cmp = function cmp(a, b) {
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
    return -1;

  if (a.length > b.length)
    return 1;

  return 0;
};

/**
 * Memcmp for comparing a needle to a haystack.
 * @param {Buffer} target - Haystack.
 * @param {Buffer} data - Needle.
 * @param {Number} start - Index in haystack to begin the comparison.
 * @returns {Number} -1, 1, or 0.
 */

utils.icmp = function icmp(target, data, start) {
  var i, a, b;

  if (target.length - start < data.length)
    return -1;

  for (i = 0; i < data.length; i++) {
    a = target[i + start];
    b = data[i];
    if (a < b)
      return -1;
    if (a > b)
      return 1;
  }

  return 0;
};

/**
 * memcmp in constant time (can only return true or false).
 * This protects us against timing attacks when
 * comparing an input against a secret string.
 * @see https://cryptocoding.net/index.php/Coding_rules
 * @see `$ man 3 memcmp` (NetBSD's consttime_memequal)
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Boolean}
 */

utils.ccmp = function ccmp(a, b) {
  var res = 0;
  var i;

  if (!Buffer.isBuffer(a))
    return false;

  if (!Buffer.isBuffer(b))
    return false;

  for (i = 0; i < a.length; i++)
    res |= a[i] ^ b[i];

  return res === 0;
};

/**
 * Asnchronously iterate over a range in parallel.
 * @param {Number} from
 * @param {Number} to
 * @param {Function} iter
 * @param {Function} callback
 */

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

/**
 * Asynchronously iterate over an array in parallel.
 * @param {Array} obj
 * @param {Function} iter
 * @param {Function} callback
 */

utils.forEach = function forEach(obj, iter, callback) {
  var pending = obj.length;
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

  obj.forEach(function(item, i) {
    iter(item, next, i);
  });
};

/**
 * Asnchronously iterate over a range in serial.
 * @param {Number} from
 * @param {Number} to
 * @param {Function} iter
 * @param {Function} callback
 */

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

/**
 * Asynchronously iterate over an array in serial.
 * @param {Array} obj
 * @param {Function} iter
 * @param {Function} callback
 */

utils.forEachSerial = function forEachSerial(obj, iter, callback) {
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
    if (i >= obj.length) {
      called = true;
      return callback();
    }
    item = obj[i];
    i++;
    utils.nextTick(function() {
      iter(item, next, i - 1);
    });
  })();
};

/**
 * Asynchronously apply a truth test to every
 * member of an array in parallel.
 * @param {Array} obj
 * @param {Function} iter
 * @param {Function} callback
 */

utils.every = function every(obj, iter, callback) {
  var pending = obj.length;
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

  obj.forEach(function(item, i) {
    iter(item, next, i);
  });
};

/**
 * Asynchronously apply a truth test to every
 * member of an array in serial.
 * @param {Array} obj
 * @param {Function} iter
 * @param {Function} callback
 */

utils.everySerial = function everySerial(obj, iter, callback) {
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
    if (i >= obj.length) {
      called = true;
      return callback(null, true);
    }
    item = obj[i];
    i++;
    utils.nextTick(function() {
      iter(item, next, i - 1);
    });
  })(null, true);
};

/**
 * Convert bytes to mb.
 * @param {Number} size
 * @returns {Number} mb
 */

utils.mb = function mb(size) {
  return size / 1024 / 1024 | 0;
};

/**
 * Inheritance.
 * @param {Function} obj - Constructor to inherit.
 * @param {Function} from - Parent constructor.
 */

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

/**
 * Wrap a callback to ensure it is only called once.
 * @param {Function} callback
 * @returns {Function} Wrapped callback.
 */

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

/**
 * Build a merkle tree from leaves.
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} Tree (in rare cases this may return null).
 */

utils.buildMerkleTree = function buildMerkleTree(leaves) {
  var tree = leaves.slice();
  var i, j, size, i2, hash;

  j = 0;
  size = leaves.length;

  for (; size > 1; size = ((size + 1) / 2) | 0) {
    for (i = 0; i < size; i += 2) {
      i2 = Math.min(i + 1, size - 1);
      if (i2 === i + 1 && i2 + 1 === size
          && utils.equal(tree[j + i], tree[j + i2])) {
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

/**
 * Calculate merkle root from leaves.
 * @param {Buffer[]} leaves
 * @returns {Buffer?} Merkle root.
 */

utils.getMerkleRoot = function getMerkleRoot(leaves) {
  var tree = utils.buildMerkleTree(leaves);
  if (!tree)
    return;

  return tree[tree.length - 1];
};

/**
 * Collect a merkle branch at vector index.
 * @param {Number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} branch
 */

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

/**
 * Check a merkle branch at vector index.
 * @param {Buffer} hash
 * @param {Buffer[]} branch
 * @param {Number} index
 * @returns {Buffer} Hash.
 */

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

/**
 * Find index of a buffer in an array of buffers.
 * @param {Buffer[]} obj
 * @param {Buffer} data - Target buffer to find.
 * @returns {Number} Index (-1 if not found).
 */

utils.indexOf = function indexOf(obj, data) {
  var i;

  assert(Array.isArray(obj));
  assert(Buffer.isBuffer(data));

  for (i = 0; i < obj.length; i++) {
    if (!Buffer.isBuffer(obj[i]))
      continue;
    if (utils.equal(obj[i], data))
      return i;
  }

  return -1;
};

/**
 * Convert a number to a padded uint32
 * string (10 digits in decimal).
 * @param {Number} num
 * @returns {String} Padded number.
 */

utils.pad32 = function pad32(num) {
  assert(num >= 0);
  num = num + '';
  while (num.length < 10)
    num = '0' + num;
  assert(num.length === 10);
  return num;
};

/**
 * Wrap a callback with an `unlock` callback.
 * @see Locker
 * @param {Function} callback
 * @param {Function} unlock
 * @returns {Function} Wrapped callback.
 */

utils.wrap = function wrap(callback, unlock) {
  return function(err, result) {
    unlock();
    if (callback)
      callback(err, result);
  };
};

/**
 * Execute a stack of functions in parallel.
 * @param {Function[]} stack
 * @param {Function} callback
 */

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

/**
 * Execute a stack of functions in serial.
 * @param {Function[]} stack
 * @param {Function} callback
 */

utils.serial = function serial(stack, callback) {
  var i = 0;
  (function next(err) {
    var cb = stack[i++];

    if (!cb)
      return callback(err);

    if (cb.length >= 2) {
      try {
        return cb(err, next);
      } catch (e) {
        return next(e);
      }
    }

    if (err)
      return utils.nextTick(next.bind(null, err));

    try {
      return cb(next);
    } catch (e) {
      return next(e);
    }
  })();
};

/**
 * Convert an array to a map.
 * @param {String[]} obj
 * @returns {Object} Map.
 */

utils.toMap = function toMap(obj) {
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
 * @param {Object} Reversed map.
 */

utils.revMap = function revMap(map) {
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
 * Perform a binary search on a sorted array.
 * @param {Array} items
 * @param {Object} key
 * @param {Boolean?} insert
 * @param {Function?} compare
 * @returns {Number} Index.
 */

utils.binarySearch = function binarySearch(items, key, insert, compare) {
  var start = 0;
  var end = items.length - 1;
  var pos, cmp;

  if (!compare)
    compare = utils.cmp;

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

  return start - 1;
};

/**
 * Reference to the global object.
 * @const {Object}
 */

utils.global = (function() {
  if (this)
    return this;

  if (typeof window !== 'undefined')
    return window;

  if (typeof self !== 'undefined')
    return self;

  if (typeof global !== 'undefined')
    return global;
})();
