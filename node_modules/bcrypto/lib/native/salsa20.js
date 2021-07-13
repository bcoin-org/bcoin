/*!
 * salsa20.js - salsa20 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * Salsa20
 */

class Salsa20 {
  constructor() {
    this._handle = binding.salsa20_create();
  }

  init(key, nonce, counter) {
    if (counter == null)
      counter = 0;

    assert(this instanceof Salsa20);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));
    assert(Number.isSafeInteger(counter));

    binding.salsa20_init(this._handle, key, nonce, counter);

    return this;
  }

  encrypt(data) {
    assert(this instanceof Salsa20);
    assert(Buffer.isBuffer(data));

    binding.salsa20_crypt(this._handle, data);

    return data;
  }

  destroy() {
    assert(this instanceof Salsa20);

    binding.salsa20_destroy(this._handle);

    return this;
  }

  static derive(key, nonce) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));

    return binding.salsa20_derive(key, nonce);
  }
}

/*
 * Static
 */

Salsa20.native = 2;

/*
 * Expose
 */

module.exports = Salsa20;
