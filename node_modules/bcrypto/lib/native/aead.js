/*!
 * aead.js - aead for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * AEAD
 */

class AEAD {
  constructor() {
    this._handle = binding.aead_create();
  }

  init(key, iv) {
    assert(this instanceof AEAD);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));

    binding.aead_init(this._handle, key, iv);

    return this;
  }

  aad(data) {
    assert(this instanceof AEAD);
    assert(Buffer.isBuffer(data));

    binding.aead_aad(this._handle, data);

    return this;
  }

  encrypt(data) {
    assert(this instanceof AEAD);
    assert(Buffer.isBuffer(data));

    binding.aead_encrypt(this._handle, data);

    return data;
  }

  decrypt(data) {
    assert(this instanceof AEAD);
    assert(Buffer.isBuffer(data));

    binding.aead_decrypt(this._handle, data);

    return data;
  }

  auth(data) {
    assert(this instanceof AEAD);
    assert(Buffer.isBuffer(data));

    binding.aead_auth(this._handle, data);

    return data;
  }

  final() {
    assert(this instanceof AEAD);
    return binding.aead_final(this._handle);
  }

  destroy() {
    assert(this instanceof AEAD);

    binding.aead_destroy(this._handle);

    return this;
  }

  verify(tag) {
    assert(this instanceof AEAD);
    assert(Buffer.isBuffer(tag));

    return binding.aead_verify(this._handle, tag);
  }

  static encrypt(key, iv, msg, aad) {
    if (aad == null)
      aad = binding.NULL;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(aad));

    return binding.aead_static_encrypt(key, iv, msg, aad);
  }

  static decrypt(key, iv, msg, tag, aad) {
    if (aad == null)
      aad = binding.NULL;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(tag));
    assert(Buffer.isBuffer(aad));

    return binding.aead_static_decrypt(key, iv, msg, tag, aad);
  }

  static auth(key, iv, msg, tag, aad) {
    if (aad == null)
      aad = binding.NULL;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(tag));
    assert(Buffer.isBuffer(aad));

    return binding.aead_static_auth(key, iv, msg, tag, aad);
  }
}

/*
 * Static
 */

AEAD.native = 2;

/*
 * Expose
 */

module.exports = AEAD;
