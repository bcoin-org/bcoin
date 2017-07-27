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

const digest = require('./digest');
const crypto = global.crypto || global.msCrypto || {};
const subtle = crypto.subtle || {};

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
  const size = digest.hash(alg, Buffer.alloc(0)).length;
  const blocks = Math.ceil(len / size);
  const out = Buffer.allocUnsafe(len);
  const buf = Buffer.allocUnsafe(salt.length + 4);
  const block = Buffer.allocUnsafe(size);
  let pos = 0;

  salt.copy(buf, 0);

  for (let i = 0; i < blocks; i++) {
    buf.writeUInt32BE(i + 1, salt.length, true);
    let mac = digest.hmac(alg, buf, key);
    mac.copy(block, 0);
    for (let j = 1; j < iter; j++) {
      mac = digest.hmac(alg, mac, key);
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
 * @param {Buffer} key
 * @param {Buffer} salt
 * @param {Number} iter
 * @param {Number} len
 * @param {String} alg
 * @returns {Promise}
 */

exports.deriveAsync = async function deriveAsync(key, salt, iter, len, alg) {
  const algo = { name: 'PBKDF2' };
  const use = ['deriveBits'];

  if (!subtle.importKey || !subtle.deriveBits)
    return exports.derive(key, salt, iter, len, alg);

  const options = {
    name: 'PBKDF2',
    salt: salt,
    iterations: iter,
    hash: getHash(alg)
  };

  const imported = await subtle.importKey('raw', key, algo, false, use);
  const data = await subtle.deriveBits(options, imported, len * 8);

  return Buffer.from(data);
};

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
      throw new Error(`Algorithm not supported: ${name}.`);
  }
}
