/*!
 * bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

// See: https://github.com/nodejs/node/issues/31442
const crypto = require('crypto');
const randomBytes = crypto.randomBytes.bind(crypto);

const assert = require('../internal/assert');
const binding = require('loady')('bcrypto', __dirname);

binding.hashes = {
  __proto__: null,
  BLAKE2B160: 0,
  BLAKE2B256: 1,
  BLAKE2B384: 2,
  BLAKE2B512: 3,
  BLAKE2S128: 4,
  BLAKE2S160: 5,
  BLAKE2S224: 6,
  BLAKE2S256: 7,
  GOST94: 8,
  HASH160: 9,
  HASH256: 10,
  KECCAK224: 11,
  KECCAK256: 12,
  KECCAK384: 13,
  KECCAK512: 14,
  MD2: 15,
  MD4: 16,
  MD5: 17,
  MD5SHA1: 18,
  RIPEMD160: 19,
  SHA1: 20,
  SHA224: 21,
  SHA256: 22,
  SHA384: 23,
  SHA512: 24,
  SHA3_224: 25,
  SHA3_256: 26,
  SHA3_384: 27,
  SHA3_512: 28,
  SHAKE128: 29,
  SHAKE256: 30,
  WHIRLPOOL: 31
};

// eslint-disable-next-line
binding.hash = function _hash(hash) {
  assert(hash && typeof hash.id === 'string');

  const type = binding.hashes[hash.id];

  assert((type >>> 0) === type);

  return type;
};

binding.entropy = function entropy() {
  return randomBytes(32);
};

binding.hint = function hint() {
  const bytes = randomBytes(2);
  return bytes[0] * 0x100 + bytes[1];
};

binding.encode = function encode(items) {
  assert(Array.isArray(items));

  let size = 0;

  for (const item of items) {
    assert(item == null || Buffer.isBuffer(item));

    size += 2;

    if (item) {
      assert(item.length <= 0xffff);
      size += item.length;
    }
  }

  const out = Buffer.alloc(size);

  let pos = 0;

  for (const item of items) {
    if (!item) {
      out[pos++] = 0x00;
      out[pos++] = 0x00;
      continue;
    }

    out[pos++] = item.length >> 8;
    out[pos++] = item.length;

    pos += item.copy(out, pos);
  }

  return out;
};

binding.decode = function decode(data, length) {
  assert(Buffer.isBuffer(data));
  assert((length >>> 0) === length);

  const items = [];

  let pos = 0;

  for (let i = 0; i < length; i++) {
    assert(pos + 2 <= data.length);

    const size = data[pos++] * 0x100 + data[pos++];

    assert(pos + size <= data.length);

    items.push(data.slice(pos, pos + size));

    pos += size;
  }

  return items;
};

Object.freeze(binding);

module.exports = binding;
