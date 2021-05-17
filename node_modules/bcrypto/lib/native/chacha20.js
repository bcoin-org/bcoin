/*!
 * chacha20.js - chacha20 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * ChaCha20
 */

class ChaCha20 {
  constructor() {
    this._handle = binding.chacha20_create();
  }

  init(key, nonce, counter) {
    if (counter == null)
      counter = 0;

    assert(this instanceof ChaCha20);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));
    assert(Number.isSafeInteger(counter));

    binding.chacha20_init(this._handle, key, nonce, counter);

    return this;
  }

  encrypt(data) {
    assert(this instanceof ChaCha20);
    assert(Buffer.isBuffer(data));

    binding.chacha20_crypt(this._handle, data);

    return data;
  }

  destroy() {
    assert(this instanceof ChaCha20);

    binding.chacha20_destroy(this._handle);

    return this;
  }

  static derive(key, nonce) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));

    return binding.chacha20_derive(key, nonce);
  }
}

/*
 * Static
 */

ChaCha20.native = 2;

/*
 * Expose
 */

module.exports = ChaCha20;
