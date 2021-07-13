/*!
 * ecdsa.js - ecdsa wrapper for libtorsion
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(binding.curves.wei[name] != null);

    this.id = name;
    this.type = 'ecdsa';
    this.native = 2;
    this._ctx = null;
  }

  get _handle() {
    if (!this._ctx)
      this._ctx = binding.curve('wei', this.id);

    return this._ctx;
  }

  get size() {
    assert(this instanceof ECDSA);
    return binding.wei_curve_field_size(this._handle);
  }

  get bits() {
    assert(this instanceof ECDSA);
    return binding.wei_curve_field_bits(this._handle);
  }

  privateKeyGenerate() {
    assert(this instanceof ECDSA);
    return binding.ecdsa_privkey_generate(this._handle, binding.entropy());
  }

  privateKeyVerify(key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_privkey_verify(this._handle, key);
  }

  privateKeyExport(key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));

    const pub = binding.ecdsa_pubkey_create(this._handle, key, false);
    const [x, y] = binding.ecdsa_pubkey_export(this._handle, pub);

    return {
      d: binding.copy(key),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(this instanceof ECDSA);
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.d));

    return binding.ecdsa_privkey_import(this._handle, json.d);
  }

  privateKeyTweakAdd(key, tweak) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.ecdsa_privkey_tweak_add(this._handle, key, tweak);
  }

  privateKeyTweakMul(key, tweak) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.ecdsa_privkey_tweak_mul(this._handle, key, tweak);
  }

  privateKeyNegate(key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_privkey_negate(this._handle, key);
  }

  privateKeyInvert(key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_privkey_invert(this._handle, key);
  }

  publicKeyCreate(key, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_pubkey_create(this._handle, key, compress);
  }

  publicKeyConvert(key, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_pubkey_convert(this._handle, key, compress);
  }

  publicKeyFromUniform(bytes, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(bytes));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_pubkey_from_uniform(this._handle, bytes, compress);
  }

  publicKeyToUniform(key, hint = binding.hint()) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert((hint >>> 0) === hint);

    return binding.ecdsa_pubkey_to_uniform(this._handle, key, hint);
  }

  publicKeyFromHash(bytes, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(bytes));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_pubkey_from_hash(this._handle, bytes, compress);
  }

  publicKeyToHash(key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_pubkey_to_hash(this._handle, key, binding.entropy());
  }

  publicKeyVerify(key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_pubkey_verify(this._handle, key);
  }

  publicKeyExport(key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));

    const [x, y] = binding.ecdsa_pubkey_export(this._handle, key);

    return { x, y };
  }

  publicKeyImport(json, compress = true) {
    assert(this instanceof ECDSA);
    assert(json && typeof json === 'object');
    assert(typeof compress === 'boolean');

    let {x, y, sign} = json;

    if (x == null)
      x = binding.NULL;

    if (y == null)
      y = binding.NULL;

    sign = binding.ternary(sign);

    assert(Buffer.isBuffer(x));
    assert(Buffer.isBuffer(y));

    return binding.ecdsa_pubkey_import(this._handle, x, y, sign, compress);
  }

  publicKeyTweakAdd(key, tweak, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_pubkey_tweak_add(this._handle, key, tweak, compress);
  }

  publicKeyTweakMul(key, tweak, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_pubkey_tweak_mul(this._handle, key, tweak, compress);
  }

  publicKeyCombine(keys, compress = true) {
    assert(this instanceof ECDSA);
    assert(Array.isArray(keys));
    assert(typeof compress === 'boolean');

    for (const key of keys)
      assert(Buffer.isBuffer(key));

    return binding.ecdsa_pubkey_combine(this._handle, keys, compress);
  }

  publicKeyNegate(key, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_pubkey_negate(this._handle, key, compress);
  }

  signatureNormalize(sig) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(sig));

    return binding.ecdsa_signature_normalize(this._handle, sig);
  }

  signatureNormalizeDER(sig) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(sig));

    return binding.ecdsa_signature_normalize_der(this._handle, sig);
  }

  signatureExport(sig) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(sig));

    return binding.ecdsa_signature_export(this._handle, sig);
  }

  signatureImport(sig) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(sig));

    return binding.ecdsa_signature_import(this._handle, sig);
  }

  isLowS(sig) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(sig));

    return binding.ecdsa_is_low_s(this._handle, sig);
  }

  isLowDER(sig) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(sig));

    return binding.ecdsa_is_low_der(this._handle, sig);
  }

  sign(msg, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_sign(this._handle, msg, key);
  }

  signRecoverable(msg, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_sign_recoverable(this._handle, msg, key);
  }

  signDER(msg, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_sign_der(this._handle, msg, key);
  }

  signRecoverableDER(msg, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_sign_recoverable_der(this._handle, msg, key);
  }

  verify(msg, sig, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_verify(this._handle, msg, sig, key);
  }

  verifyDER(msg, sig, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    return binding.ecdsa_verify_der(this._handle, msg, sig, key);
  }

  recover(msg, sig, param, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert(typeof compress === 'boolean');

    return binding.ecdsa_recover(this._handle, msg, sig, param, compress);
  }

  recoverDER(msg, sig, param, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert(typeof compress === 'boolean');

    return binding.ecdsa_recover_der(this._handle, msg, sig, param, compress);
  }

  derive(pub, priv, compress = true) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));
    assert(typeof compress === 'boolean');

    return binding.ecdsa_derive(this._handle, pub, priv, compress);
  }

  schnorrSign(msg, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));

    return binding.schnorr_legacy_sign(this._handle, msg, key);
  }

  schnorrVerify(msg, sig, key) {
    assert(this instanceof ECDSA);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    return binding.schnorr_legacy_verify(this._handle, msg, sig, key);
  }

  schnorrVerifyBatch(batch) {
    assert(this instanceof ECDSA);
    assert(Array.isArray(batch));

    for (const item of batch) {
      assert(Array.isArray(item));
      assert(item.length === 3);
      assert(Buffer.isBuffer(item[0]));
      assert(Buffer.isBuffer(item[1]));
      assert(Buffer.isBuffer(item[2]));
    }

    return binding.schnorr_legacy_verify_batch(this._handle, batch);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
