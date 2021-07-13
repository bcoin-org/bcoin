/*!
 * blake2b.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');
const HMAC = require('../internal/hmac');

/**
 * BLAKE2b
 */

class BLAKE2b {
  constructor() {
    this._handle = binding.blake2b_create();
  }

  init(size, key) {
    if (size == null)
      size = 32;

    if (key == null)
      key = binding.NULL;

    assert(this instanceof BLAKE2b);
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(key));

    binding.blake2b_init(this._handle, size, key);

    return this;
  }

  update(data) {
    assert(this instanceof BLAKE2b);
    assert(Buffer.isBuffer(data));

    binding.blake2b_update(this._handle, data);

    return this;
  }

  final() {
    assert(this instanceof BLAKE2b);
    return binding.blake2b_final(this._handle);
  }

  static hash() {
    return new BLAKE2b();
  }

  static hmac(size) {
    return new HMAC(BLAKE2b, 128, [size]);
  }

  static digest(data, size, key) {
    if (size == null)
      size = 32;

    if (key == null)
      key = binding.NULL;

    assert(Buffer.isBuffer(data));
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(key));

    return binding.blake2b_digest(data, size, key);
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

    return binding.blake2b_root(left, right, size, key);
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

    return binding.blake2b_multi(x, y, z, size, key);
  }

  static mac(data, key, size) {
    return BLAKE2b.hmac(size).init(key).update(data).final();
  }
}

/*
 * Static
 */

BLAKE2b.native = 2;
BLAKE2b.id = 'BLAKE2B256';
BLAKE2b.size = 32;
BLAKE2b.bits = 256;
BLAKE2b.blockSize = 128;
BLAKE2b.zero = Buffer.alloc(32, 0x00);
BLAKE2b.ctx = new BLAKE2b();

/*
 * Expose
 */

module.exports = BLAKE2b;
