'use strict';

/**
 * @module crypto
 */

var crypto = require('./crypto');

/**
 * Crypto module.
 * @ignore
 */

exports.crypto = crypto;

/**
 * Hash with chosen algorithm.
 * @function
 * @param {String} alg
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash = crypto.hash;

/**
 * Hash with ripemd160.
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.ripemd160 = crypto.ripemd160;

/**
 * Hash with sha1.
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha1 = crypto.sha1;

/**
 * Hash with sha256.
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha256 = crypto.sha256;

/**
 * Hash with sha256 and ripemd160 (OP_HASH160).
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash160 = crypto.hash160;

/**
 * Hash with sha256 twice (OP_HASH256).
 * @function
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash256 = crypto.hash256;

/**
 * Create an HMAC.
 * @function
 * @param {String} alg
 * @param {Buffer} data
 * @param {Buffer} key
 * @returns {Buffer} HMAC
 */

exports.hmac = crypto.hmac;

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

exports.pbkdf2 = crypto.pbkdf2;

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

exports.pbkdf2Async = crypto.pbkdf2Async;

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

exports.scrypt = crypto.scrypt;

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

exports.scryptAsync = crypto.scryptAsync;

/**
 * Perform hkdf extraction.
 * @function
 * @param {Buffer} ikm
 * @param {Buffer} key
 * @param {String} alg
 * @returns {Buffer}
 */

exports.hkdfExtract = crypto.hkdfExtract;

/**
 * Perform hkdf expansion.
 * @function
 * @param {Buffer} prk
 * @param {Buffer} info
 * @param {Number} len
 * @param {String} alg
 * @returns {Buffer}
 */

exports.hkdfExpand = crypto.hkdfExpand;

/**
 * Build a merkle tree from leaves.
 * Note that this will mutate the `leaves` array!
 * @function
 * @param {Buffer[]} leaves
 * @returns {MerkleTree}
 */

exports.createMerkleTree = crypto.createMerkleTree;

/**
 * Calculate merkle root from leaves.
 * @function
 * @param {Buffer[]} leaves
 * @returns {MerkleRoot}
 */

exports.createMerkleRoot = crypto.createMerkleRoot;

/**
 * Collect a merkle branch at vector index.
 * @function
 * @param {Number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} branch
 */

exports.createMerkleBranch = crypto.createMerkleBranch;

/**
 * Check a merkle branch at vector index.
 * @function
 * @param {Buffer} hash
 * @param {Buffer[]} branch
 * @param {Number} index
 * @returns {Buffer} Hash.
 */

exports.verifyMerkleBranch = crypto.verifyMerkleBranch;

/**
 * Encrypt with aes-256-cbc.
 * @function
 * @param {Buffer} data
 * @param {Buffer} key - 256 bit key.
 * @param {Buffer} iv - 128 bit initialization vector.
 * @returns {Buffer}
 */

exports.encipher = crypto.encipher;

/**
 * Decrypt with aes-256-cbc.
 * @function
 * @param {Buffer} data
 * @param {Buffer} key - 256 bit key.
 * @param {Buffer} iv - 128 bit initialization vector.
 * @returns {Buffer}
 */

exports.decipher = crypto.decipher;

/**
 * memcmp in constant time (can only return true or false).
 * This protects us against timing attacks when
 * comparing an input against a secret string.
 * @function
 * @see https://cryptocoding.net/index.php/Coding_rules
 * @see `$ man 3 memcmp` (NetBSD's consttime_memequal)
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Boolean}
 */

exports.ccmp = crypto.ccmp;

/**
 * A maybe-secure memzero.
 * @function
 * @param {Buffer} data
 */

exports.cleanse = crypto.cleanse;

/**
 * Generate some random bytes.
 * @function
 * @param {Number} size
 * @returns {Buffer}
 */

exports.randomBytes = crypto.randomBytes;

/**
 * Generate a random uint32.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @function
 * @returns {Number}
 */

exports.randomInt = crypto.randomInt;

/**
 * Generate a random number within a range.
 * Probably more cryptographically sound than
 * `Math.random()`.
 * @function
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

exports.randomRange = crypto.randomRange;

/**
 * chachapoly module
 * @see module:crypto/chachapoly
 */

exports.chachapoly = require('./chachapoly');

/**
 * ChaCha20
 * @see module:crypto/chachapoly.ChaCha20
 */

exports.ChaCha20 = exports.chachapoly.ChaCha20;

/**
 * Poly1305
 * @see module:crypto/chachapoly.Poly1305
 */

exports.Poly1305 = exports.chachapoly.Poly1305;

/**
 * AEAD
 * @see module:crypto/chachapoly.AEAD
 */

exports.AEAD = exports.chachapoly.AEAD;

/**
 * pk module
 * @see module:crypto/pk
 */

exports.pk = require('./pk');

/**
 * RSA
 * @see module:crypto/pk.rsa
 */

exports.rsa = exports.pk.rsa;

/**
 * ECDSA
 * @see module:crypto/pk.ecdsa
 */

exports.ecdsa = exports.pk.ecdsa;

/**
 * ec module
 * @see module:crypto/ec
 */

exports.ec = require('./ec');

/**
 * schnorr module
 * @see module:crypto/schnorr
 */

exports.schnorr = require('./schnorr');

/**
 * siphash module
 * @see module:crypto/siphash
 */

exports.siphash = require('./siphash');

/**
 * siphash256
 * @see module:crypto/siphash.siphash256
 */

exports.siphash256 = exports.siphash.siphash256;
