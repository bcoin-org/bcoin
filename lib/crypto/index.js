/*!
 * crypto/index.js - crypto for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto
 */

const digest = require('./digest');
const random = require('./random');
const aes = require('./aes');

exports.aes = require('./aes');
exports.AEAD = require('./aead');
exports.BN = require('./bn');
exports.ccmp = require('./ccmp');
exports.ChaCha20 = require('./chacha20');
exports.cleanse = require('./cleanse');
exports.digest = require('./digest');
exports.ecdsa = require('./ecdsa');
exports.hkdf = require('./hkdf');
exports.HmacDRBG = require('./hmac-drbg');
exports.merkle = require('./merkle');
exports.pbkdf2 = require('./pbkdf2');
exports.Poly1305 = require('./poly1305');
exports.random = require('./random');
exports.rsa = require('./rsa');
exports.schnorr = require('./schnorr');
exports.scrypt = require('./scrypt');
exports.secp256k1 = require('./secp256k1');
exports.siphash = require('./siphash');

exports.hash = digest.hash;
exports.ripemd160 = digest.ripemd160;
exports.sha1 = digest.sha1;
exports.sha256 = digest.sha256;
exports.hash160 = digest.hash160;
exports.hash256 = digest.hash256;
exports.root256 = digest.root256;
exports.hmac = digest.hmac;

exports.encipher = aes.encipher;
exports.decipher = aes.decipher;

exports.randomBytes = random.randomBytes;
exports.randomInt = random.randomInt;
exports.randomRange = random.randomRange;
