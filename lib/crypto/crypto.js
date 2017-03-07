/*!
 * crypto.js - crypto for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var backend = require('./backend');
var native = require('../utils/native').binding;
var scrypt = require('./scrypt');

/**
 * @exports crypto/crypto
 * @ignore
 */

var crypto = exports;

/**
 * Hash with chosen algorithm.
 * @function
 * @param {String} alg
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.hash = backend.hash;

/**
 * Hash with ripemd160.
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.ripemd160 = backend.ripemd160;

/**
 * Hash with sha1.
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.sha1 = backend.sha1;

/**
 * Hash with sha256.
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.sha256 = backend.sha256;

/**
 * Hash with sha256 and ripemd160 (OP_HASH160).
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.hash160 = backend.hash160;

/**
 * Hash with sha256 twice (OP_HASH256).
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

crypto.hash256 = backend.hash256;

/**
 * Create an HMAC.
 * @function
 * @param {String} alg
 * @param {Buffer} data
 * @param {Buffer} key
 * @returns {Buffer} HMAC
 */

crypto.hmac = backend.hmac;

/**
 * Perform key derivation using PBKDF2.
 * @function
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @returns {Buffer}
 */

crypto.pbkdf2 = backend.pbkdf2;

/**
 * Execute pbkdf2 asynchronously.
 * @function
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @returns {Promise}
 */

crypto.pbkdf2Async = backend.pbkdf2Async;

/**
 * Perform key derivation using scrypt.
 * @function
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Buffer}
 */

crypto.scrypt = scrypt.scrypt;

/**
 * Execute scrypt asynchronously.
 * @function
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Promise}
 */

crypto.scryptAsync = scrypt.scryptAsync;

/**
 * Perform hkdf extraction.
 * @param {Buffer} ikm
 * @param {Buffer} key
 * @param {String} alg
 * @returns {Buffer}
 */

crypto.hkdfExtract = function hkdfExtract(ikm, key, alg) {
  return crypto.hmac(alg, ikm, key);
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
 * Build a merkle tree from leaves.
 * Note that this will mutate the `leaves` array!
 * @param {Buffer[]} leaves
 * @returns {MerkleTree}
 */

crypto.createMerkleTree = function createMerkleTree(leaves) {
  var nodes = leaves;
  var size = leaves.length;
  var malleated = false;
  var i, j, k, hash, left, right, lr;

  if (size === 0) {
    hash = new Buffer(32);
    hash.fill(0);
    nodes.push(hash);
    return new MerkleTree(nodes, malleated);
  }

  lr = new Buffer(64);

  for (j = 0; size > 1; size = ((size + 1) / 2) | 0) {
    for (i = 0; i < size; i += 2) {
      k = Math.min(i + 1, size - 1);
      left = nodes[j + i];
      right = nodes[j + k];

      if (k === i + 1 && k + 1 === size
          && left.compare(right) === 0) {
        malleated = true;
      }

      left.copy(lr, 0);
      right.copy(lr, 32);

      hash = crypto.hash256(lr);

      nodes.push(hash);
    }
    j += size;
  }

  return new MerkleTree(nodes, malleated);
};

if (native)
  crypto.createMerkleTree = native.createMerkleTree;

/**
 * Calculate merkle root from leaves.
 * @param {Buffer[]} leaves
 * @returns {MerkleRoot}
 */

crypto.createMerkleRoot = function createMerkleRoot(leaves) {
  var tree = crypto.createMerkleTree(leaves);
  var hash = tree.nodes[tree.nodes.length - 1];
  var malleated = tree.malleated;
  return new MerkleRoot(hash, malleated);
};

/**
 * Collect a merkle branch at vector index.
 * @param {Number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} branch
 */

crypto.createMerkleBranch = function createMerkleBranch(index, leaves) {
  var size = leaves.length;
  var tree = crypto.createMerkleTree(leaves);
  var branch = [];
  var j = 0;
  var i;

  for (; size > 1; size = (size + 1) / 2 | 0) {
    i = Math.min(index ^ 1, size - 1);
    branch.push(tree.nodes[j + i]);
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

crypto.verifyMerkleBranch = function verifyMerkleBranch(hash, branch, index) {
  var i, otherside, lr;

  if (branch.length === 0)
    return hash;

  lr = new Buffer(64);

  for (i = 0; i < branch.length; i++) {
    otherside = branch[i];

    if (index & 1) {
      otherside.copy(lr, 0);
      hash.copy(lr, 32);
    } else {
      hash.copy(lr, 0);
      otherside.copy(lr, 32);
    }

    hash = crypto.hash256(lr);
    index >>>= 1;
  }

  return hash;
};

if (native)
  crypto.verifyMerkleBranch = native.verifyMerkleBranch;

/**
 * Encrypt with aes-256-cbc.
 * @function
 * @param {Buffer} data
 * @param {Buffer} key - 256 bit key.
 * @param {Buffer} iv - 128 bit initialization vector.
 * @returns {Buffer}
 */

crypto.encipher = backend.encipher;

/**
 * Decrypt with aes-256-cbc.
 * @function
 * @param {Buffer} data
 * @param {Buffer} key - 256 bit key.
 * @param {Buffer} iv - 128 bit initialization vector.
 * @returns {Buffer}
 */

crypto.decipher = backend.decipher;

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
 * A maybe-secure memzero.
 * @param {Buffer} data
 */

crypto.cleanse = function cleanse(data) {
  var ctr = crypto._counter;
  var i;

  for (i = 0; i < data.length; i++) {
    data[i] = ctr & 0xff;
    ctr += i;
  }

  crypto._counter = ctr >>> 0;
};

crypto._counter = 0;

if (native)
  crypto.cleanse = native.cleanse;

/**
 * Generate some random bytes.
 * @function
 * @param {Number} size
 * @returns {Buffer}
 */

crypto.randomBytes = backend.randomBytes;

/**
 * Generate a random uint32.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @function
 * @returns {Number}
 */

crypto.randomInt = function randomInt() {
  return crypto.randomBytes(4).readUInt32LE(0, true);
};

/**
 * Generate a random number within a range.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @function
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

crypto.randomRange = function randomRange(min, max) {
  var num = crypto.randomInt();
  return Math.floor((num / 0x100000000) * (max - min) + min);
};

/**
 * Merkle Tree
 * @constructor
 * @ignore
 * @param {Buffer[]} nodes
 * @param {Boolean} malleated
 */

function MerkleTree(nodes, malleated) {
  this.nodes = nodes;
  this.malleated = malleated;
}

/**
 * Merkle Root
 * @constructor
 * @ignore
 * @param {Buffer} hash
 * @param {Boolean} malleated
 */

function MerkleRoot(hash, malleated) {
  this.hash = hash;
  this.malleated = malleated;
}
