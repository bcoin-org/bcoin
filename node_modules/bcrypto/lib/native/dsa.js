/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/**
 * Create params from key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function paramsCreate(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_params_create(key);
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

function paramsGenerate(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  return binding.dsa_params_generate(bits, binding.entropy());
}

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

async function paramsGenerateAsync(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  return binding.dsa_params_generate_async(bits, binding.entropy());
}

/**
 * Get params prime size in bits.
 * @param {Buffer} params
 * @returns {Number}
 */

function paramsBits(params) {
  assert(Buffer.isBuffer(params));
  return binding.dsa_params_bits(params);
}

/**
 * Get params scalar size in bits.
 * @param {Buffer} params
 * @returns {Number}
 */

function paramsScalarBits(params) {
  assert(Buffer.isBuffer(params));
  return binding.dsa_params_qbits(params);
}

/**
 * Verify params.
 * @param {Buffer} params
 * @returns {Boolean}
 */

function paramsVerify(params) {
  assert(Buffer.isBuffer(params));
  return binding.dsa_params_verify(params);
}

/**
 * Import params from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function paramsImport(json) {
  assert(json && typeof json === 'object');

  const raw = binding.encode([
    json.p,
    json.q,
    json.g
  ]);

  return binding.dsa_params_import(raw);
}

/**
 * Export params to an object.
 * @param {Buffer} params
 * @returns {Object}
 */

function paramsExport(params) {
  assert(Buffer.isBuffer(params));

  const raw = binding.dsa_params_export(params);
  const items = binding.decode(raw, 3);

  return {
    p: items[0],
    q: items[1],
    g: items[2]
  };
}

/**
 * Generate private key from params.
 * @param {Buffer} params
 * @returns {Buffer}
 */

function privateKeyCreate(params) {
  assert(Buffer.isBuffer(params));
  return binding.dsa_privkey_create(params, binding.entropy());
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

function privateKeyGenerate(bits) {
  const params = paramsGenerate(bits);
  return privateKeyCreate(params);
}

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer}
 */

async function privateKeyGenerateAsync(bits) {
  const params = await paramsGenerateAsync(bits);
  return privateKeyCreate(params);
}

/**
 * Get private key prime size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function privateKeyBits(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_privkey_bits(key);
}

/**
 * Get private key scalar size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function privateKeyScalarBits(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_privkey_qbits(key);
}

/**
 * Verify a private key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_privkey_verify(key);
}

/**
 * Import a private key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function privateKeyImport(json) {
  assert(json && typeof json === 'object');

  const raw = binding.encode([
    json.p,
    json.q,
    json.g,
    json.y,
    json.x
  ]);

  return binding.dsa_privkey_import(raw);
}

/**
 * Export a private key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function privateKeyExport(key) {
  assert(Buffer.isBuffer(key));

  const raw = binding.dsa_privkey_export(key);
  const items = binding.decode(raw, 5);

  return {
    p: items[0],
    q: items[1],
    g: items[2],
    y: items[3],
    x: items[4]
  };
}

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyCreate(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_pubkey_create(key);
}

/**
 * Get public key prime size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function publicKeyBits(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_pubkey_bits(key);
}

/**
 * Get public key scalar size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function publicKeyScalarBits(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_pubkey_qbits(key);
}

/**
 * Verify a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.dsa_pubkey_verify(key);
}

/**
 * Import a public key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function publicKeyImport(json) {
  assert(json && typeof json === 'object');

  const raw = binding.encode([
    json.p,
    json.q,
    json.g,
    json.y
  ]);

  return binding.dsa_pubkey_import(raw);
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  assert(Buffer.isBuffer(key));

  const raw = binding.dsa_pubkey_export(key);
  const items = binding.decode(raw, 4);

  return {
    p: items[0],
    q: items[1],
    g: items[2],
    y: items[3]
  };
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} R/S-formatted signature.
 */

function signatureImport(sig, size) {
  if (size == null)
    size = 0;

  assert(Buffer.isBuffer(sig));
  assert((size >>> 0) === size);

  return binding.dsa_signature_import(sig, size);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} DER-formatted signature.
 */

function signatureExport(sig, size) {
  if (size == null)
    size = 0;

  assert(Buffer.isBuffer(sig));
  assert((size >>> 0) === size);

  return binding.dsa_signature_export(sig, size);
}

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.dsa_sign(msg, key, binding.entropy());
}

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.dsa_sign_der(msg, key, binding.entropy());
}

/**
 * Verify a signature (R/S).
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  return binding.dsa_verify(msg, sig, key);
}

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  return binding.dsa_verify_der(msg, sig, key);
}

/**
 * Perform a diffie-hellman.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  assert(Buffer.isBuffer(pub));
  assert(Buffer.isBuffer(priv));

  return binding.dsa_derive(pub, priv);
}

/*
 * Expose
 */

exports.native = 2;
exports.paramsCreate = paramsCreate;
exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.paramsBits = paramsBits;
exports.paramsScalarBits = paramsScalarBits;
exports.paramsVerify = paramsVerify;
exports.paramsImport = paramsImport;
exports.paramsExport = paramsExport;
exports.privateKeyCreate = privateKeyCreate;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyBits = privateKeyBits;
exports.privateKeyScalarBits = privateKeyScalarBits;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExport = privateKeyExport;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyBits = publicKeyBits;
exports.publicKeyScalarBits = publicKeyScalarBits;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExport = publicKeyExport;
exports.signatureImport = signatureImport;
exports.signatureExport = signatureExport;
exports.sign = sign;
exports.signDER = signDER;
exports.verify = verify;
exports.verifyDER = verifyDER;
exports.derive = derive;
