/*!
 * blake2s.js - BLAKE2s implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');
const HMAC = require('../internal/hmac');

/**
 * BLAKE2s
 */

class BLAKE2s {
  constructor() {
    this._handle = binding.blake2s_create();
  }

  init(size, key) {
    if (size == null)
      size = 32;

    if (key == null)
      key = binding.NULL;

    assert(this instanceof BLAKE2s);
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(key));

    binding.blake2s_init(this._handle, size, key);

    return this;
  }

  update(data) {
    assert(this instanceof BLAKE2s);
    assert(Buffer.isBuffer(data));

    binding.blake2s_update(this._handle, data);

    return this;
  }

  final() {
    assert(this instanceof BLAKE2s);
    return binding.blake2s_final(this._handle);
  }

  static hash() {
    return new BLAKE2s();
  }

  static hmac(size) {
    return new HMAC(BLAKE2s, 64, [size]);
  }

  static digest(data, size, key) {
    if (size == null)
      size = 32;

    if (key == null)
      key = binding.NULL;

    assert(Buffer.isBuffer(data));
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(key));

    return binding.blake2s_digest(data, size, key);
  }

  static root(left, right, size, key) {
    if (size == null)
      size = 32;

    if (key == null)
      key = binding.NULL;

    assert(Buffer.isBuffer(left));
    assert(Buffer.isBuffer(right));
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(key));

    return binding.blake2s_root(left, right, size, key);
  }

  static multi(x, y, z, size, key) {
    if (z == null)
      z = binding.NULL;

    if (size == null)
      size = 32;

    if (key == null)
      key = binding.NULL;

    assert(Buffer.isBuffer(x));
    assert(Buffer.isBuffer(y));
    assert(Buffer.isBuffer(z));
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(key));

    return binding.blake2s_multi(x, y, z, size, key);
  }

  static mac(data, key, size) {
    return BLAKE2s.hmac(size).init(key).update(data).final();
  }
}

/*
 * Static
 */

BLAKE2s.native = 2;
BLAKE2s.id = 'BLAKE2S256';
BLAKE2s.size = 32;
BLAKE2s.bits = 256;
BLAKE2s.blockSize = 64;
BLAKE2s.zero = Buffer.alloc(32, 0x00);
BLAKE2s.ctx = new BLAKE2s();

/*
 * Expose
 */

module.exports = BLAKE2s;
