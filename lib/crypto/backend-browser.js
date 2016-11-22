/*!
 * backend-browser.js - browser crypto backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var hashjs = require('hash.js');
var util = require('../utils/util');
var aes = require('./aes');
var global = util.global;
var crypto = global.crypto || global.msCrypto || {};
var subtle = crypto.subtle && crypto.subtle.importKey ? crypto.subtle : {};
var backend = exports;

/*
 * Hashing
 */

backend._hash = function _hash(alg, data) {
  var hash = hashjs[alg];
  assert(hash != null, 'Unknown algorithm.');
  return hash().update(data).digest();
};

backend.hash = function _hash(alg, data) {
  return new Buffer(backend._hash(alg, data));
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
  var hash = backend._hash('sha256', data);
  return backend.hash('ripemd160', hash);
};

backend.hash256 = function hash256(data) {
  var hash = backend._hash('sha256', data);
  return backend.hash('sha256', hash);
};

backend.hmac = function _hmac(alg, data, key) {
  var hash = hashjs[alg];
  var hmac;

  assert(hash != null, 'Unknown algorithm.');

  hmac = hashjs.hmac(hash, key);

  return new Buffer(hmac.update(data).digest());
};

backend.hashAsync = function hashAsync(alg, data) {
  var name = backend.getHash(alg);
  var result;

  if (!name) {
    try {
      result = backend.hash(alg, data);
    } catch (e) {
      return Promise.reject(e);
    }
    return Promise.resolve(result);
  }

  return subtle.digest(name, data).then(function(hash) {
    return new Buffer(hash);
  });
};

if (!subtle.digest)
  backend.hashAsync = util.promisify(backend.hash);

backend.hash256Async = function hash256Async(data) {
  return backend.hashAsync('sha256', data).then(function(hash) {
    return backend.hashAsync('sha256', hash);
  });
};

backend.hmacAsync = function _hmacAsync(alg, data, key) {
  var name = backend.getHash(alg);
  var use = ['sign'];
  var algo, promise, result;

  if (!name) {
    try {
      result = backend.hmac(alg, data, key);
    } catch (e) {
      return Promise.reject(e);
    }
    return Promise.resolve(result);
  }

  algo = {
    name: 'HMAC',
    hash: name
  };

  promise = subtle.importKey('raw', key, algo, true, use);

  return promise.then(function(key) {
    return subtle.sign('HMAC', key, data);
  }).then(function(data) {
    return new Buffer(data);
  });
};

if (!subtle.sign)
  backend.hmacAsync = util.promisify(backend.hmac);

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
  var options, promise, result;

  if (!name) {
    try {
      result = backend.pbkdf2(key, salt, iter, len, alg);
    } catch (e) {
      return Promise.reject(e);
    }
    return Promise.resolve(result);
  }

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

backend.encipherAsync = function encipherAsync(data, key, iv) {
  var algo = { name: 'AES-CBC' };
  var use = ['encrypt'];
  var options = { name: 'AES-CBC', iv: iv };
  var promise;

  promise = subtle.importKey('raw', key, algo, false, use);

  return promise.then(function(key) {
    return subtle.encrypt(options, key, data);
  }).then(function(result) {
    return new Buffer(result);
  });
};

if (!subtle.encrypt)
  backend.encipherAsync = util.promisify(backend.encipher);

backend.decipherAsync = function decipherAsync(data, key, iv) {
  var algo = { name: 'AES-CBC' };
  var use = ['decrypt'];
  var options = { name: 'AES-CBC', iv: iv };
  var promise;

  promise = subtle.importKey('raw', key, algo, false, use);

  return promise.then(function(key) {
    return subtle.decrypt(options, key, data);
  }).then(function(result) {
    return new Buffer(result);
  });
};

if (!subtle.decrypt)
  backend.decipherAsync = util.promisify(backend.decipher);

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
      return null;
  }
};

backend.crypto = crypto;
backend.subtle = subtle;
