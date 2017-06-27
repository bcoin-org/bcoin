/*!
 * pbkdf2.js - pbkdf2 for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto.pbkdf2-browser
 * @ignore
 */

var digest = require('./digest');
var crypto = global.crypto || global.msCrypto || {};
var subtle = crypto.subtle && crypto.subtle.importKey ? crypto.subtle : {};

/**
 * Perform key derivation using PBKDF2.
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @returns {Buffer}
 */

exports.derive = function derive(key, salt, iter, len, alg) {
  var size = digest.hash(alg, Buffer.alloc(0)).length;
  var blocks = Math.ceil(len / size);
  var out = Buffer.allocUnsafe(len);
  var buf = Buffer.allocUnsafe(salt.length + 4);
  var block = Buffer.allocUnsafe(size);
  var pos = 0;
  var i, j, k, mac;

  salt.copy(buf, 0);

  for (i = 0; i < blocks; i++) {
    buf.writeUInt32BE(i + 1, salt.length, true);
    mac = digest.hmac(alg, buf, key);
    mac.copy(block, 0);
    for (j = 1; j < iter; j++) {
      mac = digest.hmac(alg, mac, key);
      for (k = 0; k < size; k++)
        block[k] ^= mac[k];
    }
    block.copy(out, pos);
    pos += size;
  }

  return out;
};

/**
 * Execute pbkdf2 asynchronously.
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @returns {Promise}
 */

exports.deriveAsync = function deriveAsync(key, salt, iter, len, alg) {
  var algo = { name: 'PBKDF2' };
  var use = ['deriveBits'];
  var name = getHash(alg);
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
    return Buffer.from(result);
  });
};

if (!subtle.deriveBits)
  exports.pbkdf2Async = exports.pbkdf2;

/*
 * Helpers
 */

function getHash(name) {
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
}
