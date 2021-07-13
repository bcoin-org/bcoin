/*!
 * ecdh.js - ECDH for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://cr.yp.to/ecdh.html
 *   https://cr.yp.to/ecdh/curve25519-20060209.pdf
 *   https://tools.ietf.org/html/rfc7748
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * ECDH
 */

class ECDH {
  constructor(name) {
    assert(binding.curves.mont[name] != null);

    this.id = name;
    this.type = 'ecdh';
    this.native = 2;
    this._ctx = null;
  }

  get _handle() {
    if (!this._ctx)
      this._ctx = binding.curve('mont', this.id);

    return this._ctx;
  }

  get size() {
    assert(this instanceof ECDH);
    return binding.mont_curve_field_size(this._handle);
  }

  get bits() {
    assert(this instanceof ECDH);
    return binding.mont_curve_field_bits(this._handle);
  }

  privateKeyGenerate() {
    assert(this instanceof ECDH);
    return binding.ecdh_privkey_generate(this._handle, binding.entropy());
  }

  privateKeyVerify(key) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    return binding.ecdh_privkey_verify(this._handle, key);
  }

  privateKeyExport(key, sign) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    sign = binding.ternary(sign);

    const pub = binding.ecdh_pubkey_create(this._handle, key);
    const [x, y] = binding.ecdh_pubkey_export(this._handle, pub, sign);

    return {
      d: binding.copy(key),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(this instanceof ECDH);
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.d));

    return binding.ecdh_privkey_import(this._handle, json.d);
  }

  publicKeyCreate(key) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    return binding.ecdh_pubkey_create(this._handle, key);
  }

  publicKeyConvert(key, sign) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    sign = binding.ternary(sign);

    return binding.ecdh_pubkey_convert(this._handle, key, sign);
  }

  publicKeyFromUniform(bytes) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(bytes));

    return binding.ecdh_pubkey_from_uniform(this._handle, bytes);
  }

  publicKeyToUniform(key, hint = binding.hint()) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));
    assert((hint >>> 0) === hint);

    return binding.ecdh_pubkey_to_uniform(this._handle, key, hint);
  }

  publicKeyFromHash(bytes, pake = false) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(bytes));
    assert(typeof pake === 'boolean');

    return binding.ecdh_pubkey_from_hash(this._handle, bytes, pake);
  }

  publicKeyToHash(key, subgroup = binding.hint()) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));
    assert((subgroup >>> 0) === subgroup);

    return binding.ecdh_pubkey_to_hash(this._handle,
                                       key,
                                       subgroup,
                                       binding.entropy());
  }

  publicKeyVerify(key) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    return binding.ecdh_pubkey_verify(this._handle, key);
  }

  publicKeyIsSmall(key) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    return binding.ecdh_pubkey_is_small(this._handle, key);
  }

  publicKeyHasTorsion(key) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    return binding.ecdh_pubkey_has_torsion(this._handle, key);
  }

  publicKeyExport(key, sign) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(key));

    sign = binding.ternary(sign);

    const [x, y] = binding.ecdh_pubkey_export(this._handle, key, sign);

    return { x, y };
  }

  publicKeyImport(json) {
    assert(this instanceof ECDH);
    assert(json && typeof json === 'object');

    let {x, y} = json;

    if (x == null)
      x = binding.NULL;

    if (y == null)
      y = binding.NULL;

    assert(Buffer.isBuffer(x));
    assert(Buffer.isBuffer(y));

    return binding.ecdh_pubkey_import(this._handle, x, y);
  }

  derive(pub, priv) {
    assert(this instanceof ECDH);
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));

    return binding.ecdh_derive(this._handle, pub, priv);
  }
}

/*
 * Expose
 */

module.exports = ECDH;
