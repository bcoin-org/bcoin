/*!
 * onion.js - onion utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on node-ip.
 * https://github.com/indutny/node-ip
 * Copyright (c) 2012, Fedor Indutny (MIT License).
 */

/* eslint no-unreachable: "off" */

'use strict';

const assert = require('bsert');
const base32 = require('bs32');
const onion = exports;

/**
 * Test whether a string is an onion address.
 * @param {String?} str
 * @returns {Boolean}
 */

onion.isString = function isString(str) {
  return onion.isLegacyString(str) || onion.isNGString(str);
};

/**
 * Test whether the buffer is a tor onion.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

onion.is = function is(raw) {
  return onion.isLegacy(raw) || onion.isNG(raw);
};

/**
 * Encode onion address.
 * @param {Buffer} key
 * @param {Function} sha3
 * @returns {String}
 */

onion.encode = function encode(raw, sha3) {
  if (onion.isLegacy(raw))
    return onion.encodeLegacy(raw);

  if (onion.isNG(raw))
    return onion.encodeNG(raw, sha3);

  throw new Error('Not an onion buffer.');
};

/**
 * Decode onion address.
 * @param {String} str
 * @param {Function} sha3
 * @returns {Buffer}
 */

onion.decode = function decode(str, sha3) {
  if (onion.isLegacyString(str))
    return onion.decodeLegacy(str);

  if (onion.isNGString(str))
    return onion.decodeNG(str, sha3);

  throw new Error('Not an onion string.');
};

/**
 * Normalize onion address.
 * @param {String} str
 * @param {Function} sha3
 * @returns {String}
 */

onion.normalize = function normalize(str, sha3) {
  if (onion.isLegacyString(str))
    return onion.normalizeLegacy(str);

  if (onion.isNGString(str))
    return onion.normalizeNG(str, sha3);

  throw new Error('Not an onion string.');
};

/**
 * Test whether a string is an onion address.
 * @param {String?} str
 * @returns {Boolean}
 */

onion.isLegacyString = function isLegacyString(str) {
  assert(typeof str === 'string');

  if (str.length !== 16 + 6)
    return false;

  return str.slice(-6).toLowerCase() === '.onion';
};

/**
 * Test whether the buffer is a tor onion.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

onion.isLegacy = function isLegacy(raw) {
  assert(Buffer.isBuffer(raw));
  return raw.length === 10;
};

/**
 * Encode onion address.
 * @param {Buffer} key
 * @returns {String}
 */

onion.encodeLegacy = function encodeLegacy(raw) {
  assert(onion.isLegacy(raw));
  const host = base32.encode(raw);
  return `${host}.onion`;
};

/**
 * Decode onion address.
 * @param {String} str
 * @returns {Buffer}
 */

onion.decodeLegacy = function decodeLegacy(str) {
  assert(onion.isLegacyString(str));
  const data = base32.decode(str.slice(0, -6));
  assert(data.length === 10, 'Invalid onion address.');
  return data;
};

/**
 * Normalize onion address.
 * @param {String} str
 * @returns {String}
 */

onion.normalizeLegacy = function normalizeLegacy(str) {
  return onion.encodeLegacy(onion.decodeLegacy(str));
};

/**
 * Test whether a string is an onion-ng address.
 * @param {String?} str
 * @returns {Boolean}
 */

onion.isNGString = function isNGString(str) {
  assert(typeof str === 'string');

  if (str.length !== 56 + 6)
    return false;

  return str.slice(-6).toLowerCase() === '.onion';
};

/**
 * Test whether the address
 * is an onion-ng buffer.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

onion.isNG = function isNG(raw) {
  assert(Buffer.isBuffer(raw));
  return raw.length === 33;
};

/**
 * Encode onion-ng address.
 * @see https://github.com/torproject/torspec/blob/master/proposals/224-rend-spec-ng.txt
 * @see https://github.com/torproject/tor/blob/master/src/or/hs_common.c
 * @param {Buffer} key
 * @param {Function} sha3
 * @returns {String}
 */

onion.encodeNG = function encodeNG(key, sha3) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 33);

  // onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
  const data = Buffer.alloc(32 + 2 + 1);

  // Ed25519 Pubkey
  key.copy(data, 0, 1, 33);

  // Checksum
  const chk = checksum(key, sha3);
  data[32] = chk >>> 8;
  data[33] = chk & 0xff;

  // Version
  data[34] = key[0];

  const host = base32.encode(data);

  return `${host}.onion`;
};

/**
 * Decode onion-ng address.
 * @see https://github.com/torproject/torspec/blob/master/proposals/224-rend-spec-ng.txt
 * @see https://github.com/torproject/tor/blob/master/src/or/hs_common.c
 * @param {String} str
 * @param {Function} sha3
 * @returns {Buffer}
 */

onion.decodeNG = function decodeNG(str, sha3) {
  // onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
  assert(onion.isNGString(str), 'Invalid onion address.');

  const data = base32.decode(str.slice(0, -6));
  assert(data.length === 35, 'Invalid onion address.');

  // Ed25519 Pubkey
  const key = Buffer.alloc(1 + 32);

  // Version
  key[0] = data[34];

  // Key
  data.copy(key, 1, 0, 32);

  // Checksum
  assert(verify(key, data, sha3), 'Invalid checksum for onion address.');

  return key;
};

/**
 * Normalize onion-ng address.
 * @param {String} str
 * @param {Function} sha3
 * @returns {String}
 */

onion.normalizeNG = function normalizeNG(str, sha3) {
  return onion.encodeNG(onion.decodeNG(str, sha3), sha3);
};

/*
 * Helpers
 */

function checksum(key, sha3) {
  assert(Buffer.isBuffer(key));
  assert(key.length === 33);

  if (sha3 == null)
    return 0;

  assert(typeof sha3 === 'function');

  // CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
  const buf = Buffer.alloc(15 + 32 + 1);
  buf.write('.onion checksum', 0, 15, 'ascii');
  key.copy(buf, 15, 1, 33);
  buf[47] = key[0];

  return sha3(buf).readUInt16BE(0);
}

function verify(key, data, sha3) {
  assert(Buffer.isBuffer(data));
  assert(data.length === 35);

  if (sha3 == null)
    return true;

  const chk = data.readUInt16BE(32);
  return chk === checksum(key, sha3);
}
