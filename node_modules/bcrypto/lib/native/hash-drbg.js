/*!
 * hash-drbg.js - hash-drbg implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * HashDRBG
 */

class HashDRBG {
  constructor(hash, entropy, nonce, pers) {
    this._handle = binding.hash_drbg_create(binding.hash(hash));

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  init(entropy, nonce, pers) {
    assert(this instanceof HashDRBG);
    assert(Buffer.isBuffer(entropy));
    assert(nonce == null || Buffer.isBuffer(nonce));
    assert(pers == null || Buffer.isBuffer(pers));

    if (nonce && pers)
      entropy = Buffer.concat([entropy, nonce, pers]);
    else if (nonce)
      entropy = Buffer.concat([entropy, nonce]);
    else if (pers)
      entropy = Buffer.concat([entropy, pers]);

    binding.hash_drbg_init(this._handle, entropy);

    return this;
  }

  reseed(entropy, add) {
    assert(this instanceof HashDRBG);
    assert(Buffer.isBuffer(entropy));
    assert(add == null || Buffer.isBuffer(add));

    if (add)
      entropy = Buffer.concat([entropy, add]);

    binding.hash_drbg_reseed(this._handle, entropy);

    return this;
  }

  generate(len, add) {
    if (add == null)
      add = binding.NULL;

    assert(this instanceof HashDRBG);
    assert((len >>> 0) === len);
    assert(Buffer.isBuffer(add));

    return binding.hash_drbg_generate(this._handle, len, add);
  }

  randomBytes(size) {
    return this.generate(size);
  }
}

/*
 * Static
 */

HashDRBG.native = 2;

/*
 * Expose
 */

module.exports = HashDRBG;
