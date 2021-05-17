/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/PBKDF2
 *   https://tools.ietf.org/html/rfc2898
 *   https://tools.ietf.org/html/rfc2898#section-5.2
 *   https://tools.ietf.org/html/rfc6070
 *   https://www.emc.com/collateral/white-papers/h11302-pkcs5v2-1-password-based-cryptography-standard-wp.pdf
 *   http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 */

'use strict';

const assert = require('../internal/assert');
const crypto = global.crypto || global.msCrypto || {};
const subtle = crypto.subtle || {};

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

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const size = hash.size;
  const blocks = Math.ceil(len / size);
  const out = Buffer.alloc(blocks * size);
  const state = Buffer.alloc(salt.length + 4);

  salt.copy(state, 0);

  // Preemptively shorten key.
  if (pass.length > hash.blockSize) {
    pass = hash.digest(pass);
    assert(pass.length <= hash.blockSize);
  }

  for (let i = 0; i < blocks; i++) {
    const round = i + 1;

    state[salt.length + 0] = round >>> 24;
    state[salt.length + 1] = round >>> 16;
    state[salt.length + 2] = round >>> 8;
    state[salt.length + 3] = round;

    const block = hash.mac(state, pass);

    let mac = block;

    for (let j = 1; j < iter; j++) {
      mac = hash.mac(mac, pass);

      for (let k = 0; k < size; k++)
        block[k] ^= mac[k];
    }

    block.copy(out, i * size);
  }

  return out.slice(0, len);
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

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(pass));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const name = getHash(hash);

  if (!subtle.importKey || !subtle.deriveBits || !name)
    return derive(hash, pass, salt, iter, len);

  const algo = { name: 'PBKDF2' };
  const use = ['deriveBits'];

  const options = {
    name: 'PBKDF2',
    salt: salt,
    iterations: iter,
    hash: name
  };

  const key = await subtle.importKey('raw', pass, algo, false, use);
  const out = await subtle.deriveBits(options, key, len * 8);

  return Buffer.from(out);
}

/*
 * Helpers
 */

function getHash(hash) {
  switch (hash.id) {
    case 'SHA1':
      return 'SHA-1';
    case 'SHA256':
      return 'SHA-256';
    case 'SHA384':
      return 'SHA-384';
    case 'SHA512':
      return 'SHA-512';
    default:
      return null;
  }
}

/*
 * Expose
 */

exports.native = 0;
exports.derive = derive;
exports.deriveAsync = deriveAsync;
