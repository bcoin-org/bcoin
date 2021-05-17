/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

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
    salt = binding.NULL;

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  return binding.pbkdf2_derive(binding.hash(hash), pass, salt, iter, len);
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
    salt = binding.NULL;

  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  return binding.pbkdf2_derive_async(binding.hash(hash), pass, salt, iter, len);
}

/*
 * Expose
 */

exports.native = 2;
exports.derive = derive;
exports.deriveAsync = deriveAsync;
