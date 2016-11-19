/*!
 * backend.js - crypto backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var crypto = require('crypto');
var backend = exports;

backend.hash = function hash(alg, data) {
  return crypto.createHash(alg).update(data).digest();
};

backend.hmac = function hmac(alg, data, salt) {
  var hmac = crypto.createHmac(alg, salt);
  return hmac.update(data).digest();
};

backend.pbkdf2 = function pbkdf2(key, salt, iter, len, alg) {
  return crypto.pbkdf2Sync(key, salt, iter, len, alg);
};

if (!crypto.pbkdf2Sync)
  backend.pbkdf2 = null;

backend.pbkdf2Async = function pbkdf2Async(key, salt, iter, len, alg, callback) {
  return crypto.pbkdf2(key, salt, iter, len, alg, callback);
};

if (!crypto.pbkdf2)
  backend.pbkdf2Async = null;

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

backend.randomBytes = crypto.randomBytes;
