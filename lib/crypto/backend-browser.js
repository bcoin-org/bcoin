/*!
 * backend-browser.js - browser crypto backend for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* jshint worker: true */

'use strict';

var assert = require('assert');
var hashjs = require('hash.js');
var aes = require('./aes');
var backend = exports;
var crypto, global;

if (typeof window !== 'undefined')
  global = window;
else if (typeof self !== 'undefined')
  global = self;

if (global)
  crypto = global.crypto || global.msCrypto;

backend.hash = function hash(alg, data) {
  return new Buffer(hashjs[alg]().update(data).digest());
};

backend.hmac = function hmac(alg, data, salt) {
  var hash = hashjs[alg];
  var hmac;

  assert(hash != null, 'Unknown algorithm.');

  hmac = hashjs.hmac(hash, salt);

  return new Buffer(hmac.update(data).digest());
};

backend.pbkdf2 = null;

backend.pbkdf2Async = null;

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

backend.randomBytes = function randomBytes(n) {
  var data = new Uint8Array(n);
  crypto.getRandomValues(data);
  return new Buffer(data.buffer);
};

if (!crypto || !crypto.getRandomValues) {
  // Out of luck here. Use bad randomness for now.
  backend.randomBytes = function randomBytes(n) {
    var data = new Buffer(n);
    var i;

    for (i = 0; i < data.length; i++)
      data[i] = Math.floor(Math.random() * 256);

    return data;
  };
}
