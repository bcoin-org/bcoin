/*!
 * binding.js - bindings for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const random = require('./random');
const binding = require('loady')('bcrypto', __dirname);

/*
 * Constants (for libtorsion)
 */

binding.hashes = {
  __proto__: null,
  NONE: 0,
  BLAKE2B160: 1,
  BLAKE2B256: 2,
  BLAKE2B384: 3,
  BLAKE2B512: 4,
  BLAKE2S128: 5,
  BLAKE2S160: 6,
  BLAKE2S224: 7,
  BLAKE2S256: 8,
  GOST94: 9,
  HASH160: 10,
  HASH256: 11,
  KECCAK224: 12,
  KECCAK256: 13,
  KECCAK384: 14,
  KECCAK512: 15,
  MD2: 16,
  MD4: 17,
  MD5: 18,
  MD5SHA1: 19,
  RIPEMD160: 20,
  SHA1: 21,
  SHA224: 22,
  SHA256: 23,
  SHA384: 24,
  SHA512: 25,
  SHA3_224: 26,
  SHA3_256: 27,
  SHA3_384: 28,
  SHA3_512: 29,
  SHAKE128: 30,
  SHAKE256: 31,
  WHIRLPOOL: 32
};

binding.curves = {
  wei: {
    __proto__: null,
    P192: 0,
    P224: 1,
    P256: 2,
    P384: 3,
    P521: 4,
    SECP256K1: 5
  },
  mont: {
    __proto__: null,
    X25519: 0,
    X448: 1
  },
  edwards: {
    __proto__: null,
    ED25519: 0,
    ED448: 1,
    ED1174: 2
  }
};

binding.ciphers = {
  __proto__: null,
  AES128: 0,
  AES192: 1,
  AES256: 2,
  ARC2: 3,
  ARC2_GUTMANN: 4,
  ARC2_40: 5,
  ARC2_64: 6,
  ARC2_128: 7,
  ARC2_128_GUTMANN: 8,
  BLOWFISH: 9,
  CAMELLIA128: 10,
  CAMELLIA192: 11,
  CAMELLIA256: 12,
  CAST5: 13,
  DES: 14,
  DES_EDE: 15,
  DES_EDE3: 16,
  IDEA: 17,
  SERPENT128: 18,
  SERPENT192: 19,
  SERPENT256: 20,
  TWOFISH128: 21,
  TWOFISH192: 22,
  TWOFISH256: 23
};

binding.modes = {
  __proto__: null,
  RAW: 0,
  ECB: 1,
  CBC: 2,
  CTS: 3,
  XTS: 4,
  CTR: 5,
  CFB: 6,
  OFB: 7,
  GCM: 8,
  CCM: 9,
  EAX: 10
};

// OpenSSL style cipher names.
binding.algorithms = {
  __proto__: null,
  'AES-128': 0,
  'AES-192': 1,
  'AES-256': 2,
  'ARC2': 3,
  'ARC2-GUTMANN': 4,
  'ARC2-40': 5,
  'ARC2-64': 6,
  'ARC2-128': 7,
  'ARC2-128-GUTMANN': 8,
  'BF': 9,
  'BLOWFISH': 9,
  'CAMELLIA-128': 10,
  'CAMELLIA-192': 11,
  'CAMELLIA-256': 12,
  'CAST5': 13,
  'DES': 14,
  'DES-EDE': 15,
  'DES-EDE3': 16,
  'IDEA': 17,
  'SERPENT-128': 18,
  'SERPENT-192': 19,
  'SERPENT-256': 20,
  'TWOFISH-128': 21,
  'TWOFISH-192': 22,
  'TWOFISH-256': 23
};

/*
 * Helpers
 */

binding.NULL = Buffer.alloc(0);

binding.ternary = function ternary(val) {
  if (val == null)
    return -1;

  assert(typeof val === 'boolean');

  return val | 0;
};

// eslint-disable-next-line
binding.hash = function _hash(hash) {
  assert(hash && typeof hash.id === 'string');

  const type = binding.hashes[hash.id];

  assert((type >>> 0) === type);

  return type;
};

const curveCaches = {
  wei: {
    __proto__: null
  },
  mont: {
    __proto__: null
  },
  edwards: {
    __proto__: null
  }
};

binding.curve = function curve(type, name) {
  assert(typeof type === 'string');
  assert(typeof name === 'string');

  const cache = curveCaches[type];

  assert(cache);

  if (cache[name])
    return cache[name];

  const curves = binding.curves[type];

  assert(curves);

  const id = curves[name];

  assert((id >>> 0) === id);

  let handle;

  switch (type) {
    case 'wei':
      handle = binding.wei_curve_create(id);
      binding.wei_curve_randomize(handle, binding.entropy());
      break;
    case 'mont':
      handle = binding.mont_curve_create(id);
      break;
    case 'edwards':
      handle = binding.edwards_curve_create(id);
      binding.edwards_curve_randomize(handle, binding.entropy());
      break;
  }

  cache[name] = handle;

  return handle;
};

let secpHandle = null;

binding.secp256k1 = function secp256k1() {
  if (!secpHandle) {
    secpHandle = binding.secp256k1_context_create();
    binding.secp256k1_context_randomize(secpHandle, binding.entropy(32));
  }
  return secpHandle;
};

binding.entropy = function entropy(size = binding.ENTROPY_SIZE) {
  return random.randomBytes(size);
};

binding.hint = function hint() {
  return random.randomInt() & 0xffff;
};

binding.copy = function copy(data) {
  assert(Buffer.isBuffer(data));

  const out = Buffer.allocUnsafeSlow(data.length);

  assert(data.copy(out, 0) === data.length);

  return out;
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

  const out = Buffer.allocUnsafeSlow(size);

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

  assert(pos === size);

  return out;
};

binding.decode = function decode(data, length) {
  assert(Buffer.isBuffer(data));
  assert((length >>> 0) === length);

  const items = new Array(length);

  let pos = 0;

  for (let i = 0; i < length; i++) {
    assert(pos + 2 <= data.length);

    const size = data[pos++] * 0x100 + data[pos++];

    assert(pos + size <= data.length);

    const item = Buffer.allocUnsafeSlow(size);

    assert(data.copy(item, 0, pos, pos + size) === size);

    items[i] = item;

    pos += size;
  }

  assert(pos === data.length);

  binding.cleanse(data);

  return items;
};

/*
 * Expose
 */

module.exports = binding;
