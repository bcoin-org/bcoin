/*!
 * pbkdf2.js - pbkdf2 for bcrypto
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = global.crypto || global.msCrypto || {};
const subtle = crypto.subtle || {};

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

exports.native = 0;

/**
 * Perform key derivation using PBKDF2.
 * @param {Function} hash
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Buffer}
 */

exports.derive = function derive(hash, key, salt, iter, len) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const size = hash.size;
  const blocks = Math.ceil(len / size);
  const out = Buffer.allocUnsafe(len);
  const buf = Buffer.allocUnsafe(salt.length + 4);
  const block = Buffer.allocUnsafe(size);

  let pos = 0;

  salt.copy(buf, 0);

  for (let i = 0; i < blocks; i++) {
    buf.writeUInt32BE(i + 1, salt.length);

    let mac = hash.mac(buf, key);
    mac.copy(block, 0);

    for (let j = 1; j < iter; j++) {
      mac = hash.mac(mac, key);
      for (let k = 0; k < size; k++)
        block[k] ^= mac[k];
    }

    block.copy(out, pos);
    pos += size;
  }

  return out;
};

/**
 * Execute pbkdf2 asynchronously.
 * @param {Function} hash
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @returns {Promise}
 */

exports.deriveAsync = async function deriveAsync(hash, key, salt, iter, len) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(salt));
  assert((iter >>> 0) === iter);
  assert((len >>> 0) === len);

  const algo = { name: 'PBKDF2' };
  const use = ['deriveBits'];
  const name = getHash(hash);

  if (!subtle.importKey || !subtle.deriveBits || !name)
    return exports.derive(hash, key, salt, iter, len);

  const options = {
    name: 'PBKDF2',
    salt: salt,
    iterations: iter,
    hash: name
  };

  const imported = await subtle.importKey('raw', key, algo, false, use);
  const data = await subtle.deriveBits(options, imported, len * 8);

  return Buffer.from(data);
};

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
