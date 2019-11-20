/*!
 * ed448.js - ed448 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ed448;
const random = require('./random');
const asn1 = require('../internal/asn1-mini');
const eckey = require('../internal/eckey');
const ed448 = exports;

/*
 * Constants
 */

const CURVE_OID = Buffer.from('2b6571', 'hex');

/**
 * Name of the curve.
 * @const {String}
 */

ed448.id = 'ED448';

/**
 * Curve type.
 * @const {String}
 */

ed448.type = 'edwards';

/**
 * Size of the curve's prime in bits.
 * @const {Number}
 */

ed448.bits = 448;

/**
 * Curve encoding length in bytes.
 * @const {Buffer}
 */

ed448.size = 57;

/**
 * Serialized curve cofactor.
 * @const {Buffer}
 */

ed448.cofactor = Buffer.alloc(56, 0x00);
ed448.cofactor[0] = 4;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

ed448.native = 2;

/**
 * Generate a secret.
 * @returns {Buffer}
 */

ed448.privateKeyGenerate = function privateKeyGenerate() {
  return random.randomBytes(57);
};

/**
 * Generate a clamped scalar.
 * @returns {Buffer}
 */

ed448.scalarGenerate = function scalarGenerate() {
  const scalar = random.randomBytes(56);

  scalar[0] &= -4;
  scalar[55] &= 0xff;
  scalar[55] |= 0x80;

  return scalar;
};

/**
 * Create a private key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.privateKeyConvert = function privateKeyConvert(secret) {
  return binding.privateKeyConvert(secret);
};

/**
 * Validate a secret.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

ed448.privateKeyVerify = function privateKeyVerify(secret) {
  assert(Buffer.isBuffer(secret));
  return secret.length === 57;
};

/**
 * Validate a scalar.
 * @param {Buffer} scalar
 * @returns {Boolean}
 */

ed448.scalarVerify = function scalarVerify(scalar) {
  assert(Buffer.isBuffer(scalar));

  if (scalar.length !== 56)
    return false;

  if (scalar[0] & ~-4)
    return false;

  if (scalar[55] & ~0xff)
    return false;

  if (!(scalar[55] & 0x80))
    return false;

  return true;
};

/**
 * Clamp a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed448.scalarClamp = function scalarClamp(scalar) {
  assert(Buffer.isBuffer(scalar));
  assert(scalar.length === 56);

  if (!ed448.scalarVerify(scalar)) {
    scalar = Buffer.from(scalar);
    scalar[0] &= -4;
    scalar[55] &= 0xff;
    scalar[55] |= 0x80;
  }

  return scalar;
};

/**
 * Export a private key to ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.privateKeyExport = function privateKeyExport(secret) {
  if (!ed448.privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return asn1.encodeOct(secret);
};

/**
 * Import a private key from ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed448.privateKeyImport = function privateKeyImport(raw) {
  const secret = asn1.decodeOct(raw);

  if (!ed448.privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return secret;
};

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.privateKeyExportPKCS8 = function privateKeyExportPKCS8(secret) {
  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: ed448.privateKeyExport(secret)
  });
};

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed448.privateKeyImportPKCS8 = function privateKeyImportPKCS8(raw) {
  const pki = asn1.decodePKCS8(raw);

  assert(pki.version === 0 || pki.version === 1);
  assert(pki.algorithm.oid.equals(CURVE_OID));
  assert(pki.algorithm.type === asn1.NULL);

  return ed448.privateKeyImport(pki.key);
};

/**
 * Export a private key to JWK JSON format.
 * @param {Buffer} secret
 * @returns {Object}
 */

ed448.privateKeyExportJWK = function privateKeyExportJWK(secret) {
  return eckey.privateKeyExportJWK(ed448, secret);
};

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

ed448.privateKeyImportJWK = function privateKeyImportJWK(json) {
  return eckey.privateKeyImportJWK(ed448, json);
};

/**
 * Add tweak value to scalar.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed448.scalarTweakAdd = function scalarTweakAdd(scalar, tweak) {
  return binding.scalarTweakAdd(scalar, tweak);
};

/**
 * Multiply scalar by tweak value.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed448.scalarTweakMul = function scalarTweakMul(scalar, tweak) {
  return binding.scalarTweakMul(scalar, tweak);
};

/**
 * Compute (-scalar mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed448.scalarNegate = function scalarNegate(scalar) {
  return binding.scalarNegate(scalar);
};

/**
 * Compute (scalar^-1 mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed448.scalarInverse = function scalarInverse(scalar) {
  return binding.scalarInverse(scalar);
};

/**
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed448.publicKeyCreate = function publicKeyCreate(secret) {
  return binding.publicKeyCreate(secret);
};

/**
 * Create a public key from a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed448.publicKeyFromScalar = function publicKeyFromScalar(scalar) {
  return binding.publicKeyFromScalar(scalar);
};

/**
 * Convert key to an X448 key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed448.publicKeyConvert = function publicKeyConvert(key) {
  return binding.publicKeyConvert(key);
};

/**
 * Convert key from an X448 key.
 * @param {Buffer} key
 * @param {Boolean} [sign=false]
 * @returns {Buffer}
 */

ed448.publicKeyDeconvert = function publicKeyDeconvert(key, sign) {
  return binding.publicKeyDeconvert(key, sign);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed448.publicKeyVerify = function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
};

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed448.publicKeyExport = function publicKeyExport(key) {
  if (!ed448.publicKeyVerify(key))
    throw new Error('Invalid public key.');

  return Buffer.from(key);
};

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed448.publicKeyImport = function publicKeyImport(raw) {
  if (!ed448.publicKeyVerify(raw))
    throw new Error('Invalid public key.');

  return Buffer.from(raw);
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed448.publicKeyExportSPKI = function publicKeyExportSPKI(key) {
  return asn1.encodeSPKI({
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: ed448.publicKeyExport(key)
  });
};

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed448.publicKeyImportSPKI = function publicKeyImportSPKI(raw) {
  const spki = asn1.decodeSPKI(raw);

  assert(spki.algorithm.oid.equals(CURVE_OID));
  assert(spki.algorithm.type === asn1.NULL);
  assert(spki.key.length === 57);

  return ed448.publicKeyImport(spki.key);
};

/**
 * Export a public key to JWK JSON format.
 * @param {Buffer} key
 * @returns {Object}
 */

ed448.publicKeyExportJWK = function publicKeyExportJWK(key) {
  return eckey.publicKeyExportJWK(ed448, key);
};

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

ed448.publicKeyImportJWK = function publicKeyImportJWK(json) {
  return eckey.publicKeyImportJWK(ed448, json);
};

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed448.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak) {
  return binding.publicKeyTweakAdd(key, tweak);
};

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed448.publicKeyTweakMul = function publicKeyTweakMul(key, tweak) {
  return binding.publicKeyTweakMul(key, tweak);
};

/**
 * Add two public keys.
 * @param {Buffer} key1
 * @param {Buffer} key2
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

ed448.publicKeyAdd = function publicKeyAdd(key1, key2, compress) {
  return binding.publicKeyAdd(key1, key2, compress);
};

/**
 * Negate public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

ed448.publicKeyNegate = function publicKeyNegate(key, compress) {
  return binding.publicKeyNegate(key, compress);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed448.sign = function sign(msg, secret, ph, ctx) {
  return binding.sign(msg, secret, ph, ctx);
};

/**
 * Sign a message with a scalar and raw prefix.
 * @param {Buffer} msg
 * @param {Buffer} scalar
 * @param {Buffer} prefix
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed448.signWithScalar = function signWithScalar(msg, scalar, prefix, ph, ctx) {
  return binding.signWithScalar(msg, scalar, prefix, ph, ctx);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed448.signTweakAdd = function signTweakAdd(msg, secret, tweak, ph, ctx) {
  return binding.signTweakAdd(msg, secret, tweak, ph, ctx);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @param {Buffer} tweak
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Buffer}
 */

ed448.signTweakMul = function signTweakMul(msg, secret, tweak, ph, ctx) {
  return binding.signTweakMul(msg, secret, tweak, ph, ctx);
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @param {Boolean|null} ph
 * @param {Buffer|null} ctx
 * @returns {Boolean}
 */

ed448.verify = function verify(msg, sig, key, ph, ctx) {
  return binding.verify(msg, sig, key, ph, ctx);
};

/**
 * Batch verify signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

ed448.batchVerify = function batchVerify(batch, ph, ctx) {
  assert(Array.isArray(batch));

  // Not implemented in C (yet?).
  for (const item of batch) {
    assert(Array.isArray(item) && item.length === 3);

    const [msg, sig, key] = item;

    if (!ed448.verify(msg, sig, key, ph, ctx))
      return false;
  }

  return true;
};

/**
 * Perform an ECDH.
 * @param {Buffer} pub - ED448 key.
 * @param {Buffer} secret - ED448 secret.
 * @returns {Buffer}
 */

ed448.derive = function derive(pub, secret) {
  return binding.derive(pub, secret);
};

/**
 * Perform an ECDH with a raw scalar.
 * @param {Buffer} pub - ED448 key.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed448.deriveWithScalar = function deriveWithScalar(pub, scalar) {
  return binding.deriveWithScalar(pub, scalar);
};

/**
 * Perform an ECDH (X448).
 * @param {Buffer} pub - X448 key (little endian).
 * @param {Buffer} secret - ED448 secret.
 * @returns {Buffer}
 */

ed448.exchange = function exchange(pub, secret) {
  return binding.exchange(pub, secret);
};

/**
 * Perform an ECDH (X448) with a raw scalar.
 * @param {Buffer} pub - X448 key (little endian).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed448.exchangeWithScalar = function exchangeWithScalar(pub, scalar) {
  return binding.exchangeWithScalar(pub, scalar);
};

/*
 * Compat
 */

ed448.ecdh = ed448.derive;
