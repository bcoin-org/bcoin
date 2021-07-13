/*!
 * hash.js - hash implementation for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Hash
 */

class Hash {
  constructor(type) {
    assert((type >>> 0) === type);

    this._handle = binding.hash_create(type);
  }

  init() {
    assert(this instanceof Hash);

    binding.hash_init(this._handle);

    return this;
  }

  update(data) {
    assert(this instanceof Hash);
    assert(Buffer.isBuffer(data));

    binding.hash_update(this._handle, data);

    return this;
  }

  final() {
    assert(this instanceof Hash);
    return binding.hash_final(this._handle);
  }

  static hash(type) {
    return new Hash(type);
  }

  static hmac(type) {
    return new HMAC(type);
  }

  static digest(type, data) {
    assert((type >>> 0) === type);
    assert(Buffer.isBuffer(data));

    return binding.hash_digest(type, data);
  }

  static root(type, left, right) {
    assert((type >>> 0) === type);
    assert(Buffer.isBuffer(left));
    assert(Buffer.isBuffer(right));

    return binding.hash_root(type, left, right);
  }

  static multi(type, x, y, z) {
    if (z == null)
      z = binding.NULL;

    assert((type >>> 0) === type);
    assert(Buffer.isBuffer(x));
    assert(Buffer.isBuffer(y));
    assert(Buffer.isBuffer(z));

    return binding.hash_multi(type, x, y, z);
  }

  static mac(type, data, key) {
    return HMAC.digest(type, data, key);
  }
}

/*
 * HMAC
 */

class HMAC {
  constructor(type) {
    assert((type >>> 0) === type);

    this._handle = binding.hmac_create(type);
  }

  init(key) {
    assert(this instanceof HMAC);
    assert(Buffer.isBuffer(key));

    binding.hmac_init(this._handle, key);

    return this;
  }

  update(data) {
    assert(this instanceof HMAC);
    assert(Buffer.isBuffer(data));

    binding.hmac_update(this._handle, data);

    return this;
  }

  final() {
    assert(this instanceof HMAC);
    return binding.hmac_final(this._handle);
  }

  static digest(type, data, key) {
    assert((type >>> 0) === type);
    assert(Buffer.isBuffer(data));
    assert(Buffer.isBuffer(key));

    return binding.hmac_digest(type, data, key);
  }
}

/*
 * Expose
 */

exports.Hash = Hash;
exports.HMAC = HMAC;
exports.hashes = binding.hashes;
