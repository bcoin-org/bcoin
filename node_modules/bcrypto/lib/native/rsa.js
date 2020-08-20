/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Constants
 */

const DEFAULT_BITS = 2048;
const DEFAULT_EXP = 65537;
const MIN_BITS = 512;
const MAX_BITS = 16384;
const MIN_EXP = 3;
const MAX_EXP = (2 ** 33) - 1;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

function privateKeyGenerate(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  return binding.rsa_privkey_generate(bits, exponent, binding.entropy());
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

async function privateKeyGenerateAsync(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent & 1) === 0)
    throw new RangeError('"exponent" must be odd.');

  return binding.rsa_privkey_generate_async(bits, exponent, binding.entropy());
}

/**
 * Get a private key's modulus size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function privateKeyBits(key) {
  assert(Buffer.isBuffer(key));
  return binding.rsa_privkey_bits(key);
}

/**
 * Verify a private key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.rsa_privkey_verify(key);
}

/**
 * Import a private key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function privateKeyImport(json) {
  assert(json && typeof json === 'object');

  const raw = binding.encode([
    json.n,
    json.e,
    json.d,
    json.p,
    json.q,
    json.dp,
    json.dq,
    json.qi
  ]);

  return binding.rsa_privkey_import(raw, binding.entropy());
}

/**
 * Export a private key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function privateKeyExport(key) {
  assert(Buffer.isBuffer(key));

  const raw = binding.rsa_privkey_export(key);
  const items = binding.decode(raw, 8);

  return {
    n: items[0],
    e: items[1],
    d: items[2],
    p: items[3],
    q: items[4],
    dp: items[5],
    dq: items[6],
    qi: items[7]
  };
}

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyCreate(key) {
  assert(Buffer.isBuffer(key));
  return binding.rsa_pubkey_create(key);
}

/**
 * Get a public key's modulus size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function publicKeyBits(key) {
  assert(Buffer.isBuffer(key));
  return binding.rsa_pubkey_bits(key);
}

/**
 * Verify a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.rsa_pubkey_verify(key);
}

/**
 * Import a public key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function publicKeyImport(json) {
  assert(json && typeof json === 'object');

  const raw = binding.encode([
    json.n,
    json.e
  ]);

  return binding.rsa_pubkey_import(raw);
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  assert(Buffer.isBuffer(key));

  const raw = binding.rsa_pubkey_export(key);
  const items = binding.decode(raw, 2);

  return {
    n: items[0],
    e: items[1]
  };
}

/**
 * Sign a message (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

function sign(hash, msg, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  if (hash == null)
    hash = -1;
  else
    hash = binding.hashes[hash];

  assert((hash | 0) === hash);
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.rsa_sign(hash, msg, key, binding.entropy());
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(hash, msg, sig, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  if (hash == null)
    hash = -1;
  else
    hash = binding.hashes[hash];

  assert((hash | 0) === hash);
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.rsa_verify(hash, msg, sig, key);
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function encrypt(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.rsa_encrypt(msg, key, binding.entropy());
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function decrypt(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.rsa_decrypt(msg, key, binding.entropy());
}

/**
 * Sign a message (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Buffer} PSS-formatted signature.
 */

function signPSS(hash, msg, key, saltLen = -1) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert((saltLen | 0) === saltLen);

  return binding.rsa_sign_pss(binding.hash(hash),
                              msg,
                              key,
                              saltLen,
                              binding.entropy());
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {Buffer} key
 * @param {Number} [saltLen=SALT_LENGTH_HASH]
 * @returns {Boolean}
 */

function verifyPSS(hash, msg, sig, key, saltLen = -1) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));
  assert((saltLen | 0) === saltLen);

  return binding.rsa_verify_pss(binding.hash(hash),
                                msg,
                                sig,
                                key,
                                saltLen);
}

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function encryptOAEP(hash, msg, key, label) {
  if (label == null)
    label = binding.NULL;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(label));

  return binding.rsa_encrypt_oaep(binding.hash(hash),
                                  msg,
                                  key,
                                  label,
                                  binding.entropy());
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEP(hash, msg, key, label) {
  if (label == null)
    label = binding.NULL;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(label));

  return binding.rsa_decrypt_oaep(binding.hash(hash),
                                  msg,
                                  key,
                                  label,
                                  binding.entropy());
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {Buffer} key
 * @returns {Buffer}
 */

function veil(msg, bits, key) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);
  assert(Buffer.isBuffer(key));

  return binding.rsa_veil(msg, bits, key, binding.entropy());
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {Buffer} key
 * @returns {Buffer}
 */

function unveil(msg, bits, key) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);
  assert(Buffer.isBuffer(key));

  return binding.rsa_unveil(msg, bits, key);
}

/*
 * Expose
 */

exports.native = 2;
exports.SALT_LENGTH_AUTO = 0;
exports.SALT_LENGTH_HASH = -1;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyBits = privateKeyBits;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExport = privateKeyExport;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyBits = publicKeyBits;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExport = publicKeyExport;
exports.sign = sign;
exports.verify = verify;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.signPSS = signPSS;
exports.verifyPSS = verifyPSS;
exports.encryptOAEP = encryptOAEP;
exports.decryptOAEP = decryptOAEP;
exports.veil = veil;
exports.unveil = unveil;
