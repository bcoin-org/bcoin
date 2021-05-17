/*!
 * scrypt.js - scrypt for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * Perform scrypt key derivation.
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Buffer}
 */

function derive(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = binding.NULL;

  assert(Buffer.isBuffer(passwd));
  assert(Buffer.isBuffer(salt));
  assert((N >>> 0) === N);
  assert((r >>> 0) === r);
  assert((p >>> 0) === p);
  assert((len >>> 0) === len);

  return binding.scrypt_derive(passwd, salt, N, r, p, len);
}

/**
 * Perform scrypt key derivation (async).
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Promise}
 */

async function deriveAsync(passwd, salt, N, r, p, len) {
  if (typeof passwd === 'string')
    passwd = Buffer.from(passwd, 'utf8');

  if (typeof salt === 'string')
    salt = Buffer.from(salt, 'utf8');

  if (salt == null)
    salt = binding.NULL;

  assert(Buffer.isBuffer(passwd));
  assert(Buffer.isBuffer(salt));
  assert((N >>> 0) === N);
  assert((r >>> 0) === r);
  assert((p >>> 0) === p);
  assert((len >>> 0) === len);

  return binding.scrypt_derive_async(passwd, salt, N, r, p, len);
}

/*
 * Expose
 */

exports.native = 2;
exports.derive = derive;
exports.deriveAsync = deriveAsync;
