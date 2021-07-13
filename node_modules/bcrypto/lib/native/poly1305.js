/*!
 * poly1305.js - poly1305 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * Poly1305
 */

class Poly1305 {
  constructor() {
    this._handle = binding.poly1305_create();
  }

  init(key) {
    assert(this instanceof Poly1305);
    assert(Buffer.isBuffer(key));

    binding.poly1305_init(this._handle, key);

    return this;
  }

  update(data) {
    assert(this instanceof Poly1305);
    assert(Buffer.isBuffer(data));

    binding.poly1305_update(this._handle, data);

    return this;
  }

  final() {
    assert(this instanceof Poly1305);
    return binding.poly1305_final(this._handle);
  }

  destroy() {
    assert(this instanceof Poly1305);

    binding.poly1305_destroy(this._handle);

    return this;
  }

  verify(tag) {
    assert(this instanceof Poly1305);
    assert(Buffer.isBuffer(tag));

    return binding.poly1305_verify(this._handle, tag);
  }
}

/*
 * Static
 */

Poly1305.native = 2;

/*
 * Expose
 */

module.exports = Poly1305;
