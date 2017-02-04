/*!
 * backend-browser.js - browser crypto backend for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var hashjs = require('hash.js');
var util = require('../utils/util');
var aes = require('./aes');
var sha256 = require('./sha256');
var global = util.global;
var crypto = global.crypto || global.msCrypto || {};
var subtle = crypto.subtle && crypto.subtle.importKey ? crypto.subtle : {};
var backend = exports;

/*
 * Hashing
 */

backend.hash = function hash(alg, data) {
  var hash;

  if (alg === 'sha256')
    return sha256.digest(data);

  hash = hashjs[alg];

  assert(hash != null, 'Unknown algorithm.');

  return new Buffer(hash().update(data).digest());
};

backend.ripemd160 = function ripemd160(data) {
  return backend.hash('ripemd160', data);
};

backend.sha1 = function sha1(data) {
  return backend.hash('sha1', data);
};

backend.sha256 = function _sha256(data) {
  return sha256.digest(data);
};

backend.hash160 = function hash160(data) {
  return backend.hash('ripemd160', sha256.digest(data));
};

backend.hash256 = function hash256(data) {
  return sha256.hash256(data);
};

backend.hmac = function _hmac(alg, data, key) {
  var hash = hashjs[alg];
  var hmac;

  assert(hash != null, 'Unknown algorithm.');

  hmac = hashjs.hmac(hash, key);

  return new Buffer(hmac.update(data).digest());
};

/*
 * Key Derivation
 */

backend.pbkdf2 = function pbkdf2(key, salt, iter, len, alg) {
  var size = backend.hash(alg, new Buffer(0)).length;
  var blocks = Math.ceil(len / size);
  var out = new Buffer(len);
  var buf = new Buffer(salt.length + 4);
  var block = new Buffer(size);
  var pos = 0;
  var i, j, k, mac;

  salt.copy(buf, 0);

  for (i = 0; i < blocks; i++) {
    buf.writeUInt32BE(i + 1, salt.length, true);
    mac = backend.hmac(alg, buf, key);
    mac.copy(block, 0);
    for (j = 1; j < iter; j++) {
      mac = backend.hmac(alg, mac, key);
      for (k = 0; k < size; k++)
        block[k] ^= mac[k];
    }
    block.copy(out, pos);
    pos += size;
  }

  return out;
};

backend.pbkdf2Async = function pbkdf2Async(key, salt, iter, len, alg) {
  var algo = { name: 'PBKDF2' };
  var use = ['deriveBits'];
  var name = backend.getHash(alg);
  var length = len * 8;
  var options, promise;

  options = {
    name: 'PBKDF2',
    salt: salt,
    iterations: iter,
    hash: name
  };

  promise = subtle.importKey('raw', key, algo, false, use);

  return promise.then(function(key) {
    return subtle.deriveBits(options, key, length);
  }).then(function(result) {
    return new Buffer(result);
  });
};

if (!subtle.deriveBits)
  backend.pbkdf2Async = util.promisify(backend.pbkdf2);

/*
 * Ciphers
 */

backend.encipher = function encipher(data, key, iv) {
  return aes.cbc.encrypt(data, key, iv);
};

backend.decipher = function decipher(data, key, iv) {
  try {
    return aes.cbc.decrypt(data, key, iv);
  } catch (e) {
    throw new Error('Bad key for decryption.');
  }
};

/*
 * Misc
 */

backend.randomBytes = function randomBytes(n) {
  var data = new Uint8Array(n);
  crypto.getRandomValues(data);
  return new Buffer(data.buffer);
};

if (!crypto.getRandomValues) {
  // Out of luck here. Use bad randomness for now.
  backend.randomBytes = function randomBytes(n) {
    var data = new Buffer(n);
    var i;

    for (i = 0; i < data.length; i++)
      data[i] = Math.floor(Math.random() * 256);

    return data;
  };
}

backend.getHash = function getHash(name) {
  switch (name) {
    case 'sha1':
      return 'SHA-1';
    case 'sha256':
      return 'SHA-256';
    case 'sha384':
      return 'SHA-384';
    case 'sha512':
      return 'SHA-512';
    default:
      throw new Error('Algorithm not supported: ' + name);
  }
};

backend.crypto = crypto;
backend.subtle = subtle;
