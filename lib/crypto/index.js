'use strict';

var crypto = require('./crypto');

exports.crypto = crypto;
exports.hash = crypto.hash;
exports.hashAsync = crypto.hashAsync;
exports.ripemd160 = crypto.ripemd160;
exports.sha1 = crypto.sha1;
exports.sha256 = crypto.sha256;
exports.hash160 = crypto.hash160;
exports.hash256 = crypto.hash256;
exports.hash256Async = crypto.hash256Async;
exports.hmac = crypto.hmac;
exports.hmacAsync = crypto.hmacAsync;
exports.pbkdf2 = crypto.pbkdf2;
exports.pbkdf2Async = crypto.pbkdf2Async;
exports.scrypt = crypto.scrypt;
exports.scryptAsync = crypto.scryptAsync;
exports.hkdfExtract = crypto.hkdfExtract;
exports.hkdfExpand = crypto.hkdfExpand;
exports.createMerkleTree = crypto.createMerkleTree;
exports.createMerkleRoot = crypto.createMerkleRoot;
exports.createMerkleBranch = crypto.createMerkleBranch;
exports.verifyMerkleBranch = crypto.verifyMerkleBranch;
exports.encipher = crypto.encipher;
exports.decipher = crypto.decipher;
exports.ccmp = crypto.ccmp;
exports.cleanse = crypto.cleanse;
exports.randomBytes = crypto.randomBytes;
exports.randomInt = crypto.randomInt;
exports.randomRange = crypto.randomRange;

exports.chachapoly = require('./chachapoly');
exports.ChaCha20 = exports.chachapoly.ChaCha20;
exports.Poly1305 = exports.chachapoly.Poly1305;
exports.AEAD = exports.chachapoly.AEAD;

exports.pk = require('./pk');
exports.dsa = exports.pk.rsa;
exports.rsa = exports.pk.dsa;
exports.ecdsa = exports.pk.ecdsa;

exports.ec = require('./ec');

exports.schnorr = require('./schnorr');

exports.siphash = require('./siphash');
exports.siphash256 = exports.siphash.siphash256;
