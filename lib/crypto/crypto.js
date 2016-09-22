/*!
 * crypto.js - crypto for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var random = require('./random');
var scrypt = require('./scrypt');
var scryptAsync = require('./scrypt-async');
var utils = require('../utils/utils');
var spawn = require('../utils/spawn');
var co = spawn.co;
var wrap = spawn.wrap;
var native = require('../utils/native');
var nodeCrypto, hash, aes;

var isBrowser =
  (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

if (!isBrowser) {
  nodeCrypto = require('crypto');
} else {
  hash = require('hash.js');
  aes = require('./aes');
}

/**
 * @exports crypto
 */

var crypto = exports;

/**
 * Hash with chosen algorithm.
 * @param {String} alg
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.hash = function _hash(alg, data) {
  if (!nodeCrypto)
    return new Buffer(hash[alg]().update(data).digest());

  return nodeCrypto.createHash(alg).update(data).digest();
};

if (native)
  crypto.hash = native.hash;

/**
 * Hash with ripemd160.
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.ripemd160 = function ripemd160(data) {
  return crypto.hash('ripemd160', data);
};

/**
 * Hash with sha1.
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.sha1 = function sha1(data) {
  return crypto.hash('sha1', data);
};

/**
 * Hash with sha256.
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.sha256 = function sha256(data) {
  return crypto.hash('sha256', data);
};

if (native)
  crypto.sha256 = native.sha256;

/**
 * Hash with sha256 and ripemd160 (OP_HASH160).
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.hash160 = function hash160(data) {
  return crypto.ripemd160(crypto.sha256(data));
};

if (native)
  crypto.hash160 = native.hash160;

/**
 * Hash with sha256 twice (OP_HASH256).
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.hash256 = function hash256(data) {
  return crypto.sha256(crypto.sha256(data));
};

if (native)
  crypto.hash256 = native.hash256;

/**
 * Create a sha256 checksum (common in bitcoin).
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.checksum = function checksum(data) {
  return crypto.hash256(data).slice(0, 4);
};

/**
 * Create an HMAC.
 * @param {String} alg
 * @param {Buffer} data
 * @param {Buffer} salt
 * @returns {Buffer} HMAC
 */

crypto.hmac = function hmac(alg, data, salt) {
  var hmac;

  if (!nodeCrypto) {
    hmac = hash.hmac(hash[alg], salt);
    return new Buffer(hmac.update(data).digest());
  }

  hmac = nodeCrypto.createHmac(alg, salt);
  return hmac.update(data).digest();
};

if (native)
  crypto.hmac = native.hmac;

/**
 * Perform key derivation using PBKDF2.
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @returns {Buffer}
 */

crypto.pbkdf2 = function pbkdf2(key, salt, iter, len, alg) {
  if (typeof key === 'string')
    key = new Buffer(key, 'utf8');

  if (typeof salt === 'string')
    salt = new Buffer(salt, 'utf8');

  if (nodeCrypto && nodeCrypto.pbkdf2Sync)
    return nodeCrypto.pbkdf2Sync(key, salt, iter, len, alg);

  return crypto._pbkdf2(key, salt, iter, len, alg);
};

/**
 * Execute pbkdf2 asynchronously.
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @param {Function} callback
 */

crypto.pbkdf2Async = function pbkdf2Async(key, salt, iter, len, alg) {
  var result;

  if (typeof key === 'string')
    key = new Buffer(key, 'utf8');

  if (typeof salt === 'string')
    salt = new Buffer(salt, 'utf8');

  if (nodeCrypto && nodeCrypto.pbkdf2) {
    return new Promise(function(resolve, reject) {
      nodeCrypto.pbkdf2(key, salt, iter, len, alg, wrap(resolve, reject));
    });
  }

  try {
    result = crypto._pbkdf2(key, salt, iter, len, alg);
  } catch (e) {
    return Promise.reject(e);
  }

  return Promise.resolve(result);
};

/**
 * Perform key derivation using scrypt.
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Buffer}
 */

crypto.scrypt = function _scrypt(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = new Buffer(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = new Buffer(salt, 'utf8');

  return scrypt(passwd, salt, N, r, p, len);
};

/**
 * Execute scrypt asynchronously.
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @param {Function} callback
 */

crypto.scryptAsync = function _scrypt(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = new Buffer(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = new Buffer(salt, 'utf8');

  return new Promise(function(resolve, reject) {
    scryptAsync(passwd, salt, N, r, p, len, wrap(resolve, reject));
  });
};

/**
 * Derive a key using pbkdf2 with 50,000 iterations.
 * @param {Buffer|String} passphrase
 * @param {Function} callback
 */

crypto.derive = function derive(passphrase) {
  return crypto.pbkdf2Async(passphrase, 'bcoin', 50000, 32, 'sha256');
};

/**
 * Encrypt with aes-256-cbc. Derives key with {@link crypto.derive}.
 * @param {Buffer} data
 * @param {Buffer|String} passphrase
 * @param {Buffer} iv - 128 bit initialization vector.
 * @param {Function} callback
 */

crypto.encrypt = co(function* encrypt(data, passphrase, iv) {
  var key;

  assert(Buffer.isBuffer(data));
  assert(passphrase, 'No passphrase.');
  assert(Buffer.isBuffer(iv));

  key = yield crypto.derive(passphrase);

  try {
    data = crypto.encipher(data, key, iv);
  } catch (e) {
    key.fill(0);
    throw e;
  }

  key.fill(0);

  return data;
});

/**
 * Encrypt with aes-256-cbc.
 * @param {Buffer} data
 * @param {Buffer} key - 256 bit key.
 * @param {Buffer} iv - 128 bit initialization vector.
 * @returns {Buffer}
 */

crypto.encipher = function encipher(data, key, iv) {
  var cipher;

  if (!nodeCrypto)
    return aes.cbc.encrypt(data, key, iv);

  cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);

  return Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);
};

/**
 * Decrypt with aes-256-cbc. Derives key with {@link crypto.derive}.
 * @param {Buffer} data
 * @param {Buffer|String} passphrase
 * @param {Buffer} iv - 128 bit initialization vector.
 * @param {Function} callback
 */

crypto.decrypt = co(function* decrypt(data, passphrase, iv) {
  var key;

  assert(Buffer.isBuffer(data));
  assert(passphrase, 'No passphrase.');
  assert(Buffer.isBuffer(iv));

  key = yield crypto.derive(passphrase);

  try {
    data = crypto.decipher(data, key, iv);
  } catch (e) {
    key.fill(0);
    throw e;
  }

  key.fill(0);

  return data;
});

/**
 * Decrypt with aes-256-cbc.
 * @param {Buffer} data
 * @param {Buffer} key - 256 bit key.
 * @param {Buffer} iv - 128 bit initialization vector.
 * @returns {Buffer}
 */

crypto.decipher = function decipher(data, key, iv) {
  var decipher;

  if (!nodeCrypto)
    return aes.cbc.decrypt(data, key, iv);

  decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);

  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
};

/**
 * Perform key derivation using PBKDF2.
 * @private
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @returns {Buffer}
 */

crypto._pbkdf2 = function pbkdf2(key, salt, iter, len, alg) {
  var size = crypto.hash(alg, new Buffer(0)).length;
  var blocks = Math.ceil(len / size);
  var out = new Buffer(len);
  var buf = new Buffer(salt.length + 4);
  var block = new Buffer(size);
  var pos = 0;
  var i, j, k, mac;

  salt.copy(buf, 0);

  for (i = 0; i < blocks; i++) {
    buf.writeUInt32BE(i + 1, salt.length, true);
    mac = crypto.hmac(alg, buf, key);
    mac.copy(block, 0);
    for (j = 1; j < iter; j++) {
      mac = crypto.hmac(alg, mac, key);
      for (k = 0; k < size; k++)
        block[k] ^= mac[k];
    }
    block.copy(out, pos);
    pos += size;
  }

  return out;
};

/**
 * Perform hkdf extraction.
 * @param {Buffer} ikm
 * @param {Buffer} salt
 * @param {String} alg
 * @returns {Buffer}
 */

crypto.hkdfExtract = function hkdfExtract(ikm, salt, alg) {
  return crypto.hmac(alg, ikm, salt);
};

/**
 * Perform hkdf expansion.
 * @param {Buffer} prk
 * @param {Buffer} info
 * @param {Number} len
 * @param {String} alg
 * @returns {Buffer}
 */

crypto.hkdfExpand = function hkdfExpand(prk, info, len, alg) {
  var size = crypto.hash(alg, new Buffer(0)).length;
  var blocks = Math.ceil(len / size);
  var i, okm, buf, out;

  if (blocks > 255)
    throw new Error('Too many blocks.');

  okm = new Buffer(len);

  if (blocks === 0)
    return okm;

  buf = new Buffer(size + info.length + 1);

  // First round:
  info.copy(buf, size);
  buf[buf.length - 1] = 1;
  out = crypto.hmac(alg, buf.slice(size), prk);
  out.copy(okm, 0);

  for (i = 1; i < blocks; i++) {
    out.copy(buf, 0);
    buf[buf.length - 1]++;
    out = crypto.hmac(alg, buf, prk);
    out.copy(okm, i * size);
  }

  return okm;
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

crypto.ccmp = function ccmp(a, b) {
  var i, res;

  if (!Buffer.isBuffer(a))
    return false;

  if (!Buffer.isBuffer(b))
    return false;

  if (b.length === 0)
    return a.length === 0;

  res = a.length ^ b.length;

  for (i = 0; i < a.length; i++)
    res |= a[i] ^ b[i % b.length];

  return res === 0;
};

/**
 * Compare two bytes in constant time.
 * @param {Number} a
 * @param {Number} b
 * @returns {Boolean}
 */

crypto.ceq = function ceq(a, b) {
  var r = ~(a ^ b) & 0xff;
  r &= r >>> 4;
  r &= r >>> 2;
  r &= r >>> 1;
  return r === 1;
};

/**
 * Build a merkle tree from leaves.
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} Tree (in rare cases this may return null).
 */

crypto.buildMerkleTree = function buildMerkleTree(leaves) {
  var tree = leaves.slice();
  var size = leaves.length;
  var i, j, i2, hash, left, right, buf;

  if (size > 1)
    buf = new Buffer(64);

  for (j = 0; size > 1; size = ((size + 1) / 2) | 0) {
    for (i = 0; i < size; i += 2) {
      i2 = Math.min(i + 1, size - 1);
      left = tree[j + i];
      right = tree[j + i2];

      if (i2 === i + 1 && i2 + 1 === size
          && utils.cmp(left, right) === 0) {
        return;
      }

      left.copy(buf, 0);
      right.copy(buf, 32);
      hash = crypto.hash256(buf);

      tree.push(hash);
    }
    j += size;
  }

  if (tree.length === 0)
    return;

  return tree;
};

if (native)
  crypto.buildMerkleTree = native.buildMerkleTree;

/**
 * Calculate merkle root from leaves.
 * @param {Buffer[]} leaves
 * @returns {Buffer?} Merkle root.
 */

crypto.getMerkleRoot = function getMerkleRoot(leaves) {
  var tree = crypto.buildMerkleTree(leaves);
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

crypto.getMerkleBranch = function getMerkleBranch(index, leaves) {
  var tree = crypto.buildMerkleTree(leaves);
  var size = leaves.length;
  var branch = [];
  var j = 0;
  var i;

  for (; size > 1; size = (size + 1) / 2 | 0) {
    i = Math.min(index ^ 1, size - 1);
    branch.push(tree[j + i]);
    index >>>= 1;
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

crypto.checkMerkleBranch = function checkMerkleBranch(hash, branch, index) {
  var i, otherside, buf;

  if (branch.length === 0)
    return hash;

  buf = new Buffer(64);

  for (i = 0; i < branch.length; i++) {
    otherside = branch[i];

    if (index & 1) {
      otherside.copy(buf, 0);
      hash.copy(buf, 32);
    } else {
      hash.copy(buf, 0);
      otherside.copy(buf, 32);
    }

    hash = crypto.hash256(buf);
    index >>>= 1;
  }

  return hash;
};

if (native)
  crypto.checkMerkleBranch = native.checkMerkleBranch;

/**
 * Generate some random bytes.
 * @function
 * @param {Number} size
 * @returns {Buffer}
 */

crypto.randomBytes = random.randomBytes;

/**
 * Generate a random number within a range.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @function
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

crypto.randomRange = random.randomRange;

/**
 * Generate a random uint32.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @function
 * @returns {Number}
 */

crypto.randomInt = random.randomInt;
