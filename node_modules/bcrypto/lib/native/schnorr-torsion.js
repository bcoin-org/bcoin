/*!
 * schnorr-torsion.js - schnorr for bcrypto (libtorsion)
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * Schnorr
 */

class Schnorr {
  constructor(name) {
    assert(binding.curves.ecdsa[name] != null);

    this.id = name;
    this.type = 'schnorr';
    this.native = 2;
    this._ctx = null;
  }

  get _handle() {
    assert(this instanceof Schnorr);

    if (!this._ctx) {
      const type = binding.curves.ecdsa[this.id] | 0;

      this._ctx = binding.schnorr_create(type);

      binding.schnorr_randomize(this._ctx, binding.entropy());
    }

    return this._ctx;
  }

  get size() {
    assert(this instanceof Schnorr);
    return binding.schnorr_size(this._handle);
  }

  get bits() {
    assert(this instanceof Schnorr);
    return binding.schnorr_bits(this._handle);
  }

  privateKeyGenerate() {
    assert(this instanceof Schnorr);
    return binding.schnorr_privkey_generate(this._handle, binding.entropy());
  }

  privateKeyVerify(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    return binding.schnorr_privkey_verify(this._handle, key);
  }

  privateKeyExport(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    const [d, x, y] = binding.schnorr_privkey_export(this._handle, key);

    return { d, x, y };
  }

  privateKeyImport(json) {
    assert(this instanceof Schnorr);
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.d));

    return binding.schnorr_privkey_import(this._handle, json.d);
  }

  privateKeyTweakAdd(key, tweak) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.schnorr_privkey_tweak_add(this._handle, key, tweak);
  }

  privateKeyTweakMul(key, tweak) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.schnorr_privkey_tweak_mul(this._handle, key, tweak);
  }

  privateKeyReduce(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    return binding.schnorr_privkey_reduce(this._handle, key);
  }

  privateKeyInvert(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    return binding.schnorr_privkey_invert(this._handle, key);
  }

  publicKeyCreate(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    return binding.schnorr_pubkey_create(this._handle, key);
  }

  publicKeyFromUniform(bytes) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(bytes));

    return binding.schnorr_pubkey_from_uniform(this._handle, bytes);
  }

  publicKeyToUniform(key, hint = binding.hint()) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));
    assert((hint >>> 0) === hint);

    return binding.schnorr_pubkey_to_uniform(this._handle, key, hint);
  }

  publicKeyFromHash(bytes) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(bytes));

    return binding.schnorr_pubkey_from_hash(this._handle, bytes);
  }

  publicKeyToHash(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    return binding.schnorr_pubkey_to_hash(this._handle, key, binding.entropy());
  }

  publicKeyVerify(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    return binding.schnorr_pubkey_verify(this._handle, key);
  }

  publicKeyExport(key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));

    const [x, y] = binding.schnorr_pubkey_export(this._handle, key);

    return { x, y };
  }

  publicKeyImport(json) {
    assert(this instanceof Schnorr);
    assert(json && typeof json === 'object');
    assert(Buffer.isBuffer(json.x));

    return binding.schnorr_pubkey_import(this._handle, json.x);
  }

  publicKeyTweakAdd(key, tweak) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.schnorr_pubkey_tweak_add(this._handle, key, tweak);
  }

  publicKeyTweakMul(key, tweak) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.schnorr_pubkey_tweak_mul(this._handle, key, tweak);
  }

  publicKeyTweakSum(key, tweak) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));

    return binding.schnorr_pubkey_tweak_sum(this._handle, key, tweak);
  }

  publicKeyTweakTest(key, tweak, expect, negated) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(Buffer.isBuffer(expect));
    assert(typeof negated === 'boolean');

    return binding.schnorr_pubkey_tweak_test(this._handle, key,
                                             tweak, expect, negated);
  }

  publicKeyCombine(keys) {
    assert(this instanceof Schnorr);
    assert(Array.isArray(keys));

    for (const key of keys)
      assert(Buffer.isBuffer(key));

    return binding.schnorr_pubkey_combine(this._handle, keys);
  }

  sign(msg, key, aux = binding.entropy(32)) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(aux));

    return binding.schnorr_sign(this._handle, msg, key, aux);
  }

  verify(msg, sig, key) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    return binding.schnorr_verify(this._handle, msg, sig, key);
  }

  verifyBatch(batch) {
    assert(this instanceof Schnorr);
    assert(Array.isArray(batch));

    return binding.schnorr_verify_batch(this._handle, batch);
  }

  derive(pub, priv) {
    assert(this instanceof Schnorr);
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));

    return binding.schnorr_derive(this._handle, pub, priv);
  }
}

/*
 * Expose
 */

module.exports = new Schnorr('SECP256K1');
