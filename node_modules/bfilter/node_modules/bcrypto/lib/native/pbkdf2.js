/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding');
const backend = binding.pbkdf2;

/**
 * Perform key derivation using PBKDF2.
 * @param {Function} hash
 * @param {Buffer} pass
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Buffer}
 */

function derive(hash, pass, salt, iter, len) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  return backend.derive(binding.hash(hash), pass, salt, iter, len);
}

/**
 * Execute pbkdf2 asynchronously.
 * @param {Function} hash
 * @param {Buffer} pass
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Promise}
 */

async function deriveAsync(hash, pass, salt, iter, len) {
  if (typeof pass === 'string')
    pass = Buffer.from(pass, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = Buffer.alloc(0);

  return new Promise((resolve, reject) => {
    const cb = (err, key) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(key);
    };

    try {
      backend.deriveAsync(binding.hash(hash), pass, salt, iter, len, cb);
    } catch (e) {
      reject(e);
    }
  });
}

/*
 * Expose
 */

exports.native = 2;
exports.derive = derive;
exports.deriveAsync = deriveAsync;
