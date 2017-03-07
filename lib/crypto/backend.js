/*!
 * backend.js - crypto backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('crypto');
var native = require('../utils/native').binding;
var backend = exports;

if (!crypto.pbkdf2Sync)
  throw new Error('This modules requires node.js v0.11.0 or above.');

/*
 * Hashing
 */

backend.hash = function hash(alg, data) {
  return crypto.createHash(alg).update(data).digest();
};

backend.ripemd160 = function ripemd160(data) {
  return backend.hash('ripemd160', data);
};

backend.sha1 = function sha1(data) {
  return backend.hash('sha1', data);
};

backend.sha256 = function sha256(data) {
  return backend.hash('sha256', data);
};

backend.hash160 = function hash160(data) {
  return backend.ripemd160(backend.sha256(data));
};

backend.hash256 = function hash256(data) {
  return backend.sha256(backend.sha256(data));
};

backend.hmac = function hmac(alg, data, key) {
  var hmac = crypto.createHmac(alg, key);
  return hmac.update(data).digest();
};

if (native) {
  backend.hash = native.hash;
  backend.hmac = native.hmac;
  backend.ripemd160 = native.ripemd160;
  backend.sha1 = native.sha1;
  backend.sha256 = native.sha256;
  backend.hash160 = native.hash160;
  backend.hash256 = native.hash256;
}

/*
 * Key Derivation
 */

backend.pbkdf2 = function pbkdf2(key, salt, iter, len, alg) {
  return crypto.pbkdf2Sync(key, salt, iter, len, alg);
};

backend.pbkdf2Async = function pbkdf2Async(key, salt, iter, len, alg) {
  return new Promise(function(resolve, reject) {
    crypto.pbkdf2(key, salt, iter, len, alg, co.wrap(resolve, reject));
  });
};

/*
 * Ciphers
 */

backend.encipher = function encipher(data, key, iv) {
  var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return util.concat(cipher.update(data), cipher.final());
};

backend.decipher = function decipher(data, key, iv) {
  var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  try {
    return util.concat(decipher.update(data), decipher.final());
  } catch (e) {
    throw new Error('Bad key for decryption.');
  }
};

if (native) {
  backend.encipher = native.encipher;
  backend.decipher = native.decipher;
}

/*
 * Misc
 */

backend.randomBytes = crypto.randomBytes;
