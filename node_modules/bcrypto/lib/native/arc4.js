/*!
 * arc4.js - ARC4 for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * ARC4
 */

class ARC4 {
  constructor() {
    this._handle = binding.arc4_create();
  }

  init(key) {
    assert(this instanceof ARC4);
    assert(Buffer.isBuffer(key));

    binding.arc4_init(this._handle, key);

    return this;
  }

  encrypt(data) {
    assert(this instanceof ARC4);
    assert(Buffer.isBuffer(data));

    binding.arc4_crypt(this._handle, data);

    return data;
  }

  destroy() {
    assert(this instanceof ARC4);

    binding.arc4_destroy(this._handle);

    return this;
  }
}

/*
 * Static
 */

ARC4.native = 2;

/*
 * Expose
 */

module.exports = ARC4;
