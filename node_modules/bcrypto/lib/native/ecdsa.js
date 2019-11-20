/*!
 * ecdsa.js - ecdsa wrapper for openssl
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ecdsa;

if (!binding)
  throw new Error('ECDSA native support not available.');

const eckey = require('../internal/eckey');
const curves = require('../internal/curves');
const Signature = require('../internal/signature');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    const ec = curves[name];
    assert(ec);

    this.id = name;
    this.type = ec.type;
    this.size = ec.size;
    this.bits = ec.bits;
    this.zero = Buffer.alloc(this.size, 0x00);
    this.order = Buffer.from(ec.order, 'hex');
    this.half = Buffer.from(ec.half, 'hex');
    this.native = 2;
  }

  privateKeyGenerate() {
    return binding.privateKeyGenerate(this.id);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    if (key.equals(this.zero))
      return false;

    return key.compare(this.order) < 0;
  }

  privateKeyExport(key, compress) {
    return binding.privateKeyExport(this.id, key, compress);
  }

  privateKeyImport(raw) {
    return binding.privateKeyImport(this.id, raw);
  }

  privateKeyExportPKCS8(key, compress) {
    return binding.privateKeyExportPKCS8(this.id, key, compress);
  }

  privateKeyImportPKCS8(raw) {
    return binding.privateKeyImportPKCS8(this.id, raw);
  }

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  privateKeyTweakAdd(key, tweak) {
    return binding.privateKeyTweakAdd(this.id, key, tweak);
  }

  privateKeyTweakMul(key, tweak) {
    return binding.privateKeyTweakMul(this.id, key, tweak);
  }

  privateKeyNegate(key) {
    return binding.privateKeyNegate(this.id, key);
  }

  privateKeyInverse(key) {
    return binding.privateKeyInverse(this.id, key);
  }

  publicKeyCreate(key, compress) {
    return binding.publicKeyCreate(this.id, key, compress);
  }

  publicKeyConvert(key, compress) {
    return binding.publicKeyConvert(this.id, key, compress);
  }

  publicKeyVerify(key) {
    return binding.publicKeyVerify(this.id, key);
  }

  publicKeyExport(key) {
    return this.publicKeyConvert(key, false).slice(1);
  }

  publicKeyImport(raw, compress) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size * 2);

    const key = Buffer.allocUnsafe(1 + raw.length);
    key[0] = 0x04;
    raw.copy(key, 1);

    return this.publicKeyConvert(key, compress);
  }

  publicKeyExportSPKI(key, compress) {
    return binding.publicKeyExportSPKI(this.id, key, compress);
  }

  publicKeyImportSPKI(raw, compress) {
    return binding.publicKeyImportSPKI(this.id, raw, compress);
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json, compress) {
    return eckey.publicKeyImportJWK(this, json, compress);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    return binding.publicKeyTweakAdd(this.id, key, tweak, compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    return binding.publicKeyTweakMul(this.id, key, tweak, compress);
  }

  publicKeyAdd(key1, key2, compress) {
    return binding.publicKeyAdd(this.id, key1, key2, compress);
  }

  publicKeyNegate(key, compress) {
    return binding.publicKeyNegate(this.id, key, compress);
  }

  signatureExport(sig) {
    return Signature.toDER(sig, this.size);
  }

  signatureImport(sig) {
    return Signature.toRS(sig, this.size);
  }

  _sign(msg, key) {
    const sig = new Signature();

    [sig.r, sig.s] = binding.sign(this.id, msg, key);

    return sig;
  }

  _signRecoverable(msg, key) {
    const sig = this._sign(msg, key);
    const Q = this.publicKeyCreate(key, false);

    let param = -1;

    for (let i = 0; i < 4; i++) {
      const Qprime = binding.recover(this.id, msg, sig.r, sig.s, i, false);

      if (!Qprime)
        continue;

      if (Qprime.equals(Q)) {
        param = i;
        break;
      }
    }

    if (param === -1)
      throw new Error('Unable to find valid recovery factor.');

    sig.param = param;

    return sig;
  }

  sign(msg, key) {
    const sig = this._sign(msg, key);
    return sig.encode(this.size);
  }

  signRecoverable(msg, key) {
    const sig = this._signRecoverable(msg, key);
    return {
      signature: sig.encode(this.size),
      recovery: sig.param
    };
  }

  signDER(msg, key) {
    const sig = this._sign(msg, key);
    return sig.toDER(this.size);
  }

  signRecoverableDER(msg, key) {
    const sig = this._signRecoverable(msg, key);
    return {
      signature: sig.toDER(this.size),
      recovery: sig.param
    };
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(sig));

    if (sig.length !== this.size * 2)
      return false;

    const r = sig.slice(0, this.size);
    const s = sig.slice(this.size, this.size * 2);

    return binding.verify(this.id, msg, r, s, key);
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(sig));

    // OpenSSL's DER parsing is known
    // to be buggy, so we do it ourselves.
    let s;
    try {
      s = Signature.fromDER(sig, this.size);
    } catch (e) {
      return false;
    }

    return binding.verify(this.id, msg, s.r, s.s, key);
  }

  recover(msg, sig, param, compress) {
    assert(Buffer.isBuffer(sig));

    if (sig.length !== this.size * 2)
      return false;

    const r = sig.slice(0, this.size);
    const s = sig.slice(this.size, this.size * 2);

    return binding.recover(this.id, msg, r, s, param, compress);
  }

  recoverDER(msg, sig, param, compress) {
    assert(Buffer.isBuffer(sig));

    // OpenSSL's DER parsing is known
    // to be buggy, so we do it ourselves.
    let s;
    try {
      s = Signature.fromDER(sig, this.size);
    } catch (e) {
      return false;
    }

    return binding.recover(this.id, msg, s.r, s.s, param, compress);
  }

  derive(pub, priv, compress) {
    return binding.derive(this.id, pub, priv, compress);
  }

  isLowS(sig) {
    return Signature.isLowS(sig, this.size, this.half);
  }

  isLowDER(sig) {
    return Signature.isLowDER(sig, this.size, this.half);
  }

  /*
   * Compat
   */

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  fromDER(sig) {
    return this.signatureImport(sig);
  }

  toDER(sig) {
    return this.signatureExport(sig);
  }

  ecdh(pub, priv, compress) {
    return this.derive(pub, priv, compress);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
