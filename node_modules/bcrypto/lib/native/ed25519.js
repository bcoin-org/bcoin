/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ed25519;
const random = require('./random');
const asn1 = require('../internal/asn1-mini');
const eckey = require('../internal/eckey');
const ed25519 = exports;

/*
 * Constants
 */

const CURVE_OID = Buffer.from('2b6570', 'hex');

/**
 * Name of the curve.
 * @const {String}
 */

ed25519.id = 'ED25519';

/**
 * Curve type.
 * @const {String}
 */

ed25519.type = 'edwards';

/**
 * Size of the curve's prime in bits.
 * @const {Number}
 */

ed25519.bits = 255;

/**
 * Curve encoding length in bytes.
 * @const {Buffer}
 */

ed25519.size = 32;

/**
 * Serialized curve cofactor.
 * @const {Buffer}
 */

ed25519.cofactor = Buffer.alloc(32, 0x00);
ed25519.cofactor[0] = 8;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

ed25519.native = 2;

/**
 * Generate a secret.
 * @returns {Buffer}
 */

ed25519.privateKeyGenerate = function privateKeyGenerate() {
  return random.randomBytes(32);
};

/**
 * Generate a clamped scalar.
 * @returns {Buffer}
 */

ed25519.scalarGenerate = function scalarGenerate() {
  const scalar = random.randomBytes(32);

  scalar[0] &= -8;
  scalar[31] &= 0x7f;
  scalar[31] |= 0x40;

  return scalar;
};

/**
 * Create a private key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyConvert = function privateKeyConvert(secret) {
  return binding.privateKeyConvert(secret);
};

/**
 * Validate a secret.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

ed25519.privateKeyVerify = function privateKeyVerify(secret) {
  assert(Buffer.isBuffer(secret));
  return secret.length === 32;
};

/**
 * Validate a scalar.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

ed25519.scalarVerify = function scalarVerify(scalar) {
  assert(Buffer.isBuffer(scalar));

  if (scalar.length !== 32)
    return false;

  if (scalar[0] & ~-8)
    return false;

  if (scalar[31] & ~0x7f)
    return false;

  if (!(scalar[31] & 0x40))
    return false;

  return true;
};

/**
 * Clamp a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.scalarClamp = function scalarClamp(scalar) {
  assert(Buffer.isBuffer(scalar));
  assert(scalar.length === 32);

  if (!ed25519.scalarVerify(scalar)) {
    scalar = Buffer.from(scalar);
    scalar[0] &= -8;
    scalar[31] &= 0x7f;
    scalar[31] |= 0x40;
  }

  return scalar;
};

/**
 * Export a private key to ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyExport = function privateKeyExport(secret) {
  if (!ed25519.privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return asn1.encodeOct(secret);
};

/**
 * Import a private key from ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.privateKeyImport = function privateKeyImport(raw) {
  const secret = asn1.decodeOct(raw);

  if (!ed25519.privateKeyVerify(secret))
    throw new Error('Invalid private key.');

  return secret;
};

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyExportPKCS8 = function privateKeyExportPKCS8(secret) {
  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: ed25519.privateKeyExport(secret)
  });
};

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.privateKeyImportPKCS8 = function privateKeyImportPKCS8(raw) {
  const pki = asn1.decodePKCS8(raw);

  assert(pki.version === 0 || pki.version === 1);
  assert(pki.algorithm.oid.equals(CURVE_OID));
  assert(pki.algorithm.type === asn1.NULL);

  return ed25519.privateKeyImport(pki.key);
};

/**
 * Export a private key to JWK JSON format.
 * @param {Buffer} secret
 * @returns {Object}
 */

ed25519.privateKeyExportJWK = function privateKeyExportJWK(secret) {
  return eckey.privateKeyExportJWK(ed25519, secret);
};

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

ed25519.privateKeyImportJWK = function privateKeyImportJWK(json) {
  return eckey.privateKeyImportJWK(ed25519, json);
};

/**
 * Add tweak value to scalar.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.scalarTweakAdd = function scalarTweakAdd(scalar, tweak) {
  return binding.scalarTweakAdd(scalar, tweak);
};

/**
 * Multiply scalar by tweak value.
 * @param {Buffer} scalar
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.scalarTweakMul = function scalarTweakMul(scalar, tweak) {
  return binding.scalarTweakMul(scalar, tweak);
};

/**
 * Compute (-scalar mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.scalarNegate = function scalarNegate(scalar) {
  return binding.scalarNegate(scalar);
};

/**
 * Compute (scalar^-1 mod n).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.scalarInverse = function scalarInverse(scalar) {
  return binding.scalarInverse(scalar);
};

/**
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.publicKeyCreate = function publicKeyCreate(secret) {
  return binding.publicKeyCreate(secret);
};

/**
 * Create a public key from a scalar.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.publicKeyFromScalar = function publicKeyFromScalar(scalar) {
  return binding.publicKeyFromScalar(scalar);
};

/**
 * Convert key to an X25519 key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyConvert = function publicKeyConvert(key) {
  return binding.publicKeyConvert(key);
};

/**
 * Convert key from an X25519 key.
 * @param {Buffer} key
 * @param {Boolean} [sign=false]
 * @returns {Buffer}
 */

ed25519.publicKeyDeconvert = function publicKeyDeconvert(key, sign) {
  return binding.publicKeyDeconvert(key, sign);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed25519.publicKeyVerify = function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
};

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyExport = function publicKeyExport(key) {
  if (!ed25519.publicKeyVerify(key))
    throw new Error('Invalid public key.');

  return Buffer.from(key);
};

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.publicKeyImport = function publicKeyImport(raw) {
  if (!ed25519.publicKeyVerify(raw))
    throw new Error('Invalid public key.');

  return Buffer.from(raw);
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyExportSPKI = function publicKeyExportSPKI(key) {
  return asn1.encodeSPKI({
    algorithm: {
      oid: CURVE_OID,
      type: asn1.NULL,
      params: null
    },
    key: ed25519.publicKeyExport(key)
  });
};

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

ed25519.publicKeyImportSPKI = function publicKeyImportSPKI(raw) {
  const spki = asn1.decodeSPKI(raw);

  assert(spki.algorithm.oid.equals(CURVE_OID));
  assert(spki.algorithm.type === asn1.NULL);
  assert(spki.key.length === 32);

  return ed25519.publicKeyImport(spki.key);
};

/**
 * Export a public key to JWK JSON format.
 * @param {Buffer} key
 * @returns {Object}
 */

ed25519.publicKeyExportJWK = function publicKeyExportJWK(key) {
  return eckey.publicKeyExportJWK(ed25519, key);
};

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

ed25519.publicKeyImportJWK = function publicKeyImportJWK(json) {
  return eckey.publicKeyImportJWK(ed25519, json);
};

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak) {
  return binding.publicKeyTweakAdd(key, tweak);
};

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

ed25519.publicKeyTweakMul = function publicKeyTweakMul(key, tweak) {
  return binding.publicKeyTweakMul(key, tweak);
};

/**
 * Add two public keys.
 * @param {Buffer} key1
 * @param {Buffer} key2
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

ed25519.publicKeyAdd = function publicKeyAdd(key1, key2, compress) {
  return binding.publicKeyAdd(key1, key2, compress);
};

/**
 * Negate public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

ed25519.publicKeyNegate = function publicKeyNegate(key, compress) {
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

ed25519.sign = function sign(msg, secret, ph, ctx) {
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

ed25519.signWithScalar = function signWithScalar(msg, scalar, prefix, ph, ctx) {
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

ed25519.signTweakAdd = function signTweakAdd(msg, secret, tweak, ph, ctx) {
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

ed25519.signTweakMul = function signTweakMul(msg, secret, tweak, ph, ctx) {
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

ed25519.verify = function verify(msg, sig, key, ph, ctx) {
  return binding.verify(msg, sig, key, ph, ctx);
};

/**
 * Batch verify signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

ed25519.batchVerify = function batchVerify(batch, ph, ctx) {
  return binding.batchVerify(batch, ph, ctx);
};

/**
 * Perform an ECDH.
 * @param {Buffer} pub - ED25519 key.
 * @param {Buffer} secret - ED25519 secret.
 * @returns {Buffer}
 */

ed25519.derive = function derive(pub, secret) {
  return binding.derive(pub, secret);
};

/**
 * Perform an ECDH with a raw scalar.
 * @param {Buffer} pub - ED25519 key.
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.deriveWithScalar = function deriveWithScalar(pub, scalar) {
  return binding.deriveWithScalar(pub, scalar);
};

/**
 * Perform an ECDH (X25519).
 * @param {Buffer} pub - X25519 key (little endian).
 * @param {Buffer} secret - ED25519 secret.
 * @returns {Buffer}
 */

ed25519.exchange = function exchange(pub, secret) {
  return binding.exchange(pub, secret);
};

/**
 * Perform an ECDH (X25519) with a raw scalar.
 * @param {Buffer} pub - X25519 key (little endian).
 * @param {Buffer} scalar
 * @returns {Buffer}
 */

ed25519.exchangeWithScalar = function exchangeWithScalar(pub, scalar) {
  return binding.exchangeWithScalar(pub, scalar);
};

/*
 * Compat
 */

ed25519.ecdh = ed25519.derive;
