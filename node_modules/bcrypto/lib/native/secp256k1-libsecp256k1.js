/*!
 * secp256k1-libsecp256k1.js - secp256k1 for bcrypto (libsecp256k1)
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');
const handle = binding.secp256k1;

/**
 * Generate a private key.
 * @returns {Buffer}
 */

function privateKeyGenerate() {
  return binding.secp256k1_seckey_generate(handle(), binding.entropy());
}

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.secp256k1_seckey_verify(handle(), key);
}

/**
 * Export a private key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function privateKeyExport(key) {
  assert(Buffer.isBuffer(key));

  const pub = binding.secp256k1_pubkey_create(handle(), key, false);
  const [x, y] = binding.secp256k1_pubkey_export(handle(), pub);

  return {
    d: binding.copy(key),
    x,
    y
  };
}

/**
 * Import a private key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function privateKeyImport(json) {
  assert(json && typeof json === 'object');
  assert(Buffer.isBuffer(json.d));

  return binding.secp256k1_seckey_import(handle(), json.d);
}

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function privateKeyTweakAdd(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));

  return binding.secp256k1_seckey_tweak_add(handle(), key, tweak);
}

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function privateKeyTweakMul(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));

  return binding.secp256k1_seckey_tweak_mul(handle(), key, tweak);
}

/**
 * Compute (-key mod n).
 * @param {Buffer} key
 * @returns {Buffer}
 */

function privateKeyNegate(key) {
  assert(Buffer.isBuffer(key));
  return binding.secp256k1_seckey_negate(handle(), key);
}

/**
 * Compute (key^-1 mod n).
 * @param {Buffer} key
 * @returns {Buffer}
 */

function privateKeyInvert(key) {
  assert(Buffer.isBuffer(key));
  return binding.secp256k1_seckey_invert(handle(), key);
}

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyCreate(key, compress = true) {
  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_pubkey_create(handle(), key, compress);
}

/**
 * Compress or decompress public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyConvert(key, compress = true) {
  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_pubkey_convert(handle(), key, compress);
}

/**
 * Run uniform bytes through Shallue-van de Woestijne.
 * @param {Buffer} bytes
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyFromUniform(bytes, compress = true) {
  assert(Buffer.isBuffer(bytes));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_pubkey_from_uniform(handle(), bytes, compress);
}

/**
 * Run public key through Shallue-van de Woestijne inverse.
 * @param {Buffer} key
 * @param {Number?} hint
 * @returns {Buffer}
 */

function publicKeyToUniform(key, hint = binding.hint()) {
  assert(Buffer.isBuffer(key));
  assert((hint >>> 0) === hint);

  return binding.secp256k1_pubkey_to_uniform(handle(), key, hint);
}

/**
 * Create public key from a 64 byte hash.
 * @param {Buffer} bytes
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyFromHash(bytes, compress = true) {
  assert(Buffer.isBuffer(bytes));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_pubkey_from_hash(handle(), bytes, compress);
}

/**
 * Create a 64 byte hash from a public key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyToHash(key) {
  assert(Buffer.isBuffer(key));
  return binding.secp256k1_pubkey_to_hash(handle(), key, binding.entropy());
}

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.secp256k1_pubkey_verify(handle(), key);
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  assert(Buffer.isBuffer(key));

  const [x, y] = binding.secp256k1_pubkey_export(handle(), key);

  return { x, y };
}

/**
 * Import a public key from an object.
 * @param {Object} json
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyImport(json, compress = true) {
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

  return binding.secp256k1_pubkey_import(handle(), x, y, sign, compress);
}

/**
 * Compute ((g * tweak) + key).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyTweakAdd(key, tweak, compress = true) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_pubkey_tweak_add(handle(), key, tweak, compress);
}

/**
 * Compute (key * tweak).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyTweakMul(key, tweak, compress = true) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_pubkey_tweak_mul(handle(), key, tweak, compress);
}

/**
 * Combine public keys.
 * @param {Buffer[]} keys
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyCombine(keys, compress = true) {
  assert(Array.isArray(keys));
  assert(typeof compress === 'boolean');

  for (const key of keys)
    assert(Buffer.isBuffer(key));

  return binding.secp256k1_pubkey_combine(handle(), keys, compress);
}

/**
 * Negate public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyNegate(key, compress = true) {
  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_pubkey_negate(handle(), key, compress);
}

/**
 * Normalize R/S signature (ensure low S value).
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureNormalize(sig) {
  assert(Buffer.isBuffer(sig));
  return binding.secp256k1_signature_normalize(handle(), sig);
}

/**
 * Normalize DER signature (ensure low S value).
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureNormalizeDER(sig) {
  assert(Buffer.isBuffer(sig));
  return binding.secp256k1_signature_normalize_der(handle(), sig);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureExport(sig) {
  assert(Buffer.isBuffer(sig));
  return binding.secp256k1_signature_export(handle(), sig);
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureImport(sig) {
  assert(Buffer.isBuffer(sig));
  return binding.secp256k1_signature_import(handle(), sig);
}

/**
 * Test whether a signature has a low S value (R/S).
 * @param {Buffer} sig
 * @returns {Boolean}
 */

function isLowS(sig) {
  assert(Buffer.isBuffer(sig));
  return binding.secp256k1_is_low_s(handle(), sig);
}

/**
 * Test whether a signature has a low S value (DER).
 * @param {Buffer} sig
 * @returns {Boolean}
 */

function isLowDER(sig) {
  assert(Buffer.isBuffer(sig));
  return binding.secp256k1_is_low_der(handle(), sig);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_sign(handle(), msg, key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Array}
 */

function signRecoverable(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_sign_recoverable(handle(), msg, key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function signDER(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_sign_der(handle(), msg, key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Array}
 */

function signRecoverableDER(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_sign_recoverable_der(handle(), msg, key);
}

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_verify(handle(), msg, sig, key);
}

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_verify_der(handle(), msg, sig, key);
}

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} param
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

function recover(msg, sig, param, compress = true) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert((param >>> 0) === param);
  assert(typeof compress === 'boolean');

  return binding.secp256k1_recover(handle(), msg, sig, param, compress);
}

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} param
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

function recoverDER(msg, sig, param, compress = true) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert((param >>> 0) === param);
  assert(typeof compress === 'boolean');

  return binding.secp256k1_recover_der(handle(), msg, sig, param, compress);
}

/**
 * Perform an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function derive(pub, priv, compress = true) {
  assert(Buffer.isBuffer(pub));
  assert(Buffer.isBuffer(priv));
  assert(typeof compress === 'boolean');

  return binding.secp256k1_derive(handle(), pub, priv, compress);
}

/**
 * Sign a message (schnorr).
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Buffer}
 */

function schnorrSign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_schnorr_legacy_sign(handle(), msg, key);
}

/**
 * Verify a schnorr signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

function schnorrVerify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_schnorr_legacy_verify(handle(), msg, sig, key);
}

/**
 * Batch verify schnorr signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

function schnorrVerifyBatch(batch) {
  assert(Array.isArray(batch));

  for (const item of batch) {
    assert(Array.isArray(item));
    assert(item.length === 3);
    assert(Buffer.isBuffer(item[0]));
    assert(Buffer.isBuffer(item[1]));
    assert(Buffer.isBuffer(item[2]));
  }

  return binding.secp256k1_schnorr_legacy_verify_batch(handle(), batch);
}

/*
 * Expose
 */

exports.id = 'SECP256K1';
exports.type = 'ecdsa';
exports.size = 32;
exports.bits = 256;
exports.native = 2;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyExport = privateKeyExport;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyTweakAdd = privateKeyTweakAdd;
exports.privateKeyTweakMul = privateKeyTweakMul;
exports.privateKeyNegate = privateKeyNegate;
exports.privateKeyInvert = privateKeyInvert;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyConvert = publicKeyConvert;
exports.publicKeyFromUniform = publicKeyFromUniform;
exports.publicKeyToUniform = publicKeyToUniform;
exports.publicKeyFromHash = publicKeyFromHash;
exports.publicKeyToHash = publicKeyToHash;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyExport = publicKeyExport;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyTweakAdd = publicKeyTweakAdd;
exports.publicKeyTweakMul = publicKeyTweakMul;
exports.publicKeyCombine = publicKeyCombine;
exports.publicKeyNegate = publicKeyNegate;
exports.signatureNormalize = signatureNormalize;
exports.signatureNormalizeDER = signatureNormalizeDER;
exports.signatureExport = signatureExport;
exports.signatureImport = signatureImport;
exports.isLowS = isLowS;
exports.isLowDER = isLowDER;
exports.sign = sign;
exports.signRecoverable = signRecoverable;
exports.signDER = signDER;
exports.signRecoverableDER = signRecoverableDER;
exports.verify = verify;
exports.verifyDER = verifyDER;
exports.recover = recover;
exports.recoverDER = recoverDER;
exports.derive = derive;
exports.schnorrSign = schnorrSign;
exports.schnorrVerify = schnorrVerify;
exports.schnorrVerifyBatch = schnorrVerifyBatch;
