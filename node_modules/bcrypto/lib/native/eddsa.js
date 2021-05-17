/*!
 * eddsa.js - EdDSA for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * EDDSA
 */

class EDDSA {
  constructor(name) {
    assert(binding.curves.edwards[name] != null);

    this.id = name;
    this.type = 'eddsa';
    this.native = 2;
    this._ctx = null;
  }

  get _handle() {
    if (!this._ctx)
      this._ctx = binding.curve('edwards', this.id);

    return this._ctx;
  }

  get size() {
    assert(this instanceof EDDSA);
    return binding.eddsa_pubkey_size(this._handle);
  }

  get bits() {
    assert(this instanceof EDDSA);
    return binding.edwards_curve_field_bits(this._handle);
  }

  privateKeyGenerate() {
    assert(this instanceof EDDSA);
    return binding.eddsa_privkey_generate(this._handle, binding.entropy());
  }

  scalarGenerate() {
    assert(this instanceof EDDSA);
    return binding.eddsa_scalar_generate(this._handle, binding.entropy());
  }

  privateKeyExpand(secret) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(secret));

    return binding.eddsa_privkey_expand(this._handle, secret);
  }

  privateKeyConvert(secret) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(secret));

    return binding.eddsa_privkey_convert(this._handle, secret);
  }

  privateKeyVerify(secret) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(secret));

    return binding.eddsa_privkey_verify(this._handle, secret);
  }

  scalarVerify(scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_scalar_verify(this._handle, scalar);
  }

  scalarIsZero(scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_scalar_is_zero(this._handle, scalar);
  }

  scalarClamp(scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_scalar_clamp(this._handle, scalar);
  }

  privateKeyExport(secret) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(secret));

    const pub = binding.eddsa_pubkey_create(this._handle, secret);
    const [x, y] = binding.eddsa_pubkey_export(this._handle, pub);

    return {
      d: binding.copy(secret),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(this instanceof EDDSA);
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.d));

    return binding.eddsa_privkey_import(this._handle, json.d);
  }

  scalarTweakAdd(scalar, tweak) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));
    assert(Buffer.isBuffer(tweak));

    return binding.eddsa_scalar_tweak_add(this._handle, scalar, tweak);
  }

  scalarTweakMul(scalar, tweak) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));
    assert(Buffer.isBuffer(tweak));

    return binding.eddsa_scalar_tweak_mul(this._handle, scalar, tweak);
  }

  scalarReduce(scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_scalar_reduce(this._handle, scalar);
  }

  scalarNegate(scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_scalar_negate(this._handle, scalar);
  }

  scalarInvert(scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_scalar_invert(this._handle, scalar);
  }

  publicKeyCreate(secret) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(secret));

    return binding.eddsa_pubkey_create(this._handle, secret);
  }

  publicKeyFromScalar(scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_pubkey_from_scalar(this._handle, scalar);
  }

  publicKeyConvert(key) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));

    return binding.eddsa_pubkey_convert(this._handle, key);
  }

  publicKeyFromUniform(bytes) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(bytes));

    return binding.eddsa_pubkey_from_uniform(this._handle, bytes);
  }

  publicKeyToUniform(key, hint = binding.hint()) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));
    assert((hint >>> 0) === hint);

    return binding.eddsa_pubkey_to_uniform(this._handle, key, hint);
  }

  publicKeyFromHash(bytes, pake = false) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(bytes));
    assert(typeof pake === 'boolean');

    return binding.eddsa_pubkey_from_hash(this._handle, bytes, pake);
  }

  publicKeyToHash(key, subgroup = binding.hint()) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));
    assert((subgroup >>> 0) === subgroup);

    return binding.eddsa_pubkey_to_hash(this._handle,
                                        key,
                                        subgroup,
                                        binding.entropy());
  }

  publicKeyVerify(key) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));

    return binding.eddsa_pubkey_verify(this._handle, key);
  }

  publicKeyIsInfinity(key) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));

    return binding.eddsa_pubkey_is_infinity(this._handle, key);
  }

  publicKeyIsSmall(key) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));

    return binding.eddsa_pubkey_is_small(this._handle, key);
  }

  publicKeyHasTorsion(key) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));

    return binding.eddsa_pubkey_has_torsion(this._handle, key);
  }

  publicKeyExport(key) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));

    const [x, y] = binding.eddsa_pubkey_export(this._handle, key);

    return { x, y };
  }

  publicKeyImport(json) {
    assert(this instanceof EDDSA);
    assert(json && typeof json === 'object');

    let {x, y, sign} = json;

    if (x == null)
      x = binding.NULL;

    if (y == null)
      y = binding.NULL;

    sign = binding.ternary(sign);

    assert(Buffer.isBuffer(x));
    assert(Buffer.isBuffer(y));

    return binding.eddsa_pubkey_import(this._handle, x, y, sign);
  }

  publicKeyTweakAdd(key, tweak) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.eddsa_pubkey_tweak_add(this._handle, key, tweak);
  }

  publicKeyTweakMul(key, tweak) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.eddsa_pubkey_tweak_mul(this._handle, key, tweak);
  }

  publicKeyCombine(keys) {
    assert(this instanceof EDDSA);
    assert(Array.isArray(keys));

    for (const key of keys)
      assert(Buffer.isBuffer(key));

    return binding.eddsa_pubkey_combine(this._handle, keys);
  }

  publicKeyNegate(key) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(key));

    return binding.eddsa_pubkey_negate(this._handle, key);
  }

  sign(msg, secret, ph, ctx) {
    assert(this instanceof EDDSA);

    ph = binding.ternary(ph);

    if (ctx == null)
      ctx = binding.NULL;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(Buffer.isBuffer(ctx));

    return binding.eddsa_sign(this._handle, msg, secret, ph, ctx);
  }

  signWithScalar(msg, scalar, prefix, ph, ctx) {
    assert(this instanceof EDDSA);

    ph = binding.ternary(ph);

    if (ctx == null)
      ctx = binding.NULL;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(scalar));
    assert(Buffer.isBuffer(prefix));
    assert(Buffer.isBuffer(ctx));

    return binding.eddsa_sign_with_scalar(this._handle, msg,
                                          scalar, prefix, ph, ctx);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    assert(this instanceof EDDSA);

    ph = binding.ternary(ph);

    if (ctx == null)
      ctx = binding.NULL;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(Buffer.isBuffer(tweak));
    assert(Buffer.isBuffer(ctx));

    return binding.eddsa_sign_tweak_add(this._handle, msg,
                                        secret, tweak, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    assert(this instanceof EDDSA);

    ph = binding.ternary(ph);

    if (ctx == null)
      ctx = binding.NULL;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(Buffer.isBuffer(tweak));
    assert(Buffer.isBuffer(ctx));

    return binding.eddsa_sign_tweak_mul(this._handle, msg,
                                        secret, tweak, ph, ctx);
  }

  verify(msg, sig, key, ph, ctx) {
    assert(this instanceof EDDSA);

    ph = binding.ternary(ph);

    if (ctx == null)
      ctx = binding.NULL;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(ctx));

    return binding.eddsa_verify(this._handle, msg, sig, key, ph, ctx);
  }

  verifySingle(msg, sig, key, ph, ctx) {
    assert(this instanceof EDDSA);

    ph = binding.ternary(ph);

    if (ctx == null)
      ctx = binding.NULL;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(ctx));

    return binding.eddsa_verify_single(this._handle, msg, sig, key, ph, ctx);
  }

  verifyBatch(batch, ph, ctx) {
    assert(this instanceof EDDSA);

    ph = binding.ternary(ph);

    if (ctx == null)
      ctx = binding.NULL;

    assert(Array.isArray(batch));
    assert(Buffer.isBuffer(ctx));

    for (const item of batch) {
      assert(Array.isArray(item));
      assert(item.length === 3);
      assert(Buffer.isBuffer(item[0]));
      assert(Buffer.isBuffer(item[1]));
      assert(Buffer.isBuffer(item[2]));
    }

    return binding.eddsa_verify_batch(this._handle, batch, ph, ctx);
  }

  derive(pub, secret) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(secret));

    return binding.eddsa_derive(this._handle, pub, secret);
  }

  deriveWithScalar(pub, scalar) {
    assert(this instanceof EDDSA);
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(scalar));

    return binding.eddsa_derive_with_scalar(this._handle, pub, scalar);
  }
}

/*
 * Expose
 */

module.exports = EDDSA;
