/*!
 * ctr-drbg.js - ctr-drbg implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * CtrDRBG
 */

class CtrDRBG {
  constructor(bits, derivation, entropy, nonce, pers) {
    assert((bits >>> 0) === bits);
    assert(typeof derivation === 'boolean');

    this._handle = binding.ctr_drbg_create(bits, derivation);

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  init(entropy, nonce, pers) {
    if (pers == null)
      pers = binding.NULL;

    assert(this instanceof CtrDRBG);
    assert(Buffer.isBuffer(entropy));
    assert(nonce == null || Buffer.isBuffer(nonce));
    assert(Buffer.isBuffer(pers));

    if (nonce)
      entropy = Buffer.concat([entropy, nonce]);

    binding.ctr_drbg_init(this._handle, entropy, pers);

    return this;
  }

  reseed(entropy, add) {
    if (add == null)
      add = binding.NULL;

    assert(this instanceof CtrDRBG);
    assert(Buffer.isBuffer(entropy));
    assert(Buffer.isBuffer(add));

    binding.ctr_drbg_reseed(this._handle, entropy, add);

    return this;
  }

  generate(len, add) {
    if (add == null)
      add = binding.NULL;

    assert(this instanceof CtrDRBG);
    assert((len >>> 0) === len);
    assert(Buffer.isBuffer(add));

    return binding.ctr_drbg_generate(this._handle, len, add);
  }

  randomBytes(size) {
    return this.generate(size);
  }
}

/*
 * Static
 */

CtrDRBG.native = 2;

/*
 * Expose
 */

module.exports = CtrDRBG;
