/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');
const backend = new binding.Secp256k1();

/*
 * Randomize
 */

backend._randomize(binding.entropy(32));

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

function privateKeyGenerate() {
  return backend.privateKeyGenerate(binding.entropy());
}

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

function privateKeyVerify(key) {
  return backend.privateKeyVerify(key);
}

/**
 * Export a private key to SEC1 ASN.1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  const pub = backend.publicKeyCreate(key, false);
  const [x, y] = backend.publicKeyExport(pub);

  return {
    d: Buffer.from(key),
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
  return backend.privateKeyImport(json.d);
}

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

function privateKeyTweakAdd(key, tweak) {
  return backend.privateKeyTweakAdd(key, tweak);
}

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

function privateKeyTweakMul(key, tweak) {
  return backend.privateKeyTweakMul(key, tweak);
}

/**
 * Compute (key mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

function privateKeyReduce(key) {
  return backend.privateKeyReduce(key);
}

/**
 * Compute (-key mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

function privateKeyNegate(key) {
  return backend.privateKeyNegate(key);
}

/**
 * Compute (key^-1 mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

function privateKeyInvert(key) {
  return backend.privateKeyInvert(key);
}

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyCreate(key, compress) {
  return backend.publicKeyCreate(key, compress);
}

/**
 * Compress or decompress public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyConvert(key, compress) {
  return backend.publicKeyConvert(key, compress);
}

/**
 * Run uniform bytes through Shallue-van de Woestijne.
 * @param {Buffer} bytes
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyFromUniform(bytes, compress) {
  return backend.publicKeyFromUniform(bytes, compress);
}

/**
 * Run public key through Shallue-van de Woestijne inverse.
 * @param {Buffer} key
 * @param {Number?} hint
 * @returns {Buffer}
 */

function publicKeyToUniform(key, hint = binding.hint()) {
  return backend.publicKeyToUniform(key, hint);
}

/**
 * Create public key from a 64 byte hash.
 * @param {Buffer} bytes
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyFromHash(bytes, compress) {
  return backend.publicKeyFromHash(bytes, compress);
}

/**
 * Create a 64 byte hash from a public key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyToHash(key) {
  return backend.publicKeyToHash(key, binding.entropy());
}

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

function publicKeyVerify(key) {
  return backend.publicKeyVerify(key);
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  const [x, y] = backend.publicKeyExport(key);
  return { x, y };
}

/**
 * Import a public key from an object.
 * @param {Object} json
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyImport(json, compress) {
  assert(json && typeof json === 'object');
  return backend.publicKeyImport(json.x, json.y, json.sign, compress);
}

/**
 * Compute ((g * tweak) + key).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer} key
 */

function publicKeyTweakAdd(key, tweak, compress) {
  return backend.publicKeyTweakAdd(key, tweak, compress);
}

/**
 * Compute (key * tweak).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer} key
 */

function publicKeyTweakMul(key, tweak, compress) {
  return backend.publicKeyTweakMul(key, tweak, compress);
}

/**
 * Combine public keys.
 * @param {Buffer[]} keys
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyCombine(keys, compress) {
  return backend.publicKeyCombine(keys, compress);
}

/**
 * Negate public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function publicKeyNegate(key, compress) {
  return backend.publicKeyNegate(key, compress);
}

/**
 * Normalize R/S signature (ensure low S value).
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureNormalize(sig) {
  return backend.signatureNormalize(sig);
}

/**
 * Normalize DER signature (ensure low S value).
 * @param {Buffer} sig
 * @returns {Buffer}
 */

function signatureNormalizeDER(sig) {
  return backend.signatureNormalizeDER(sig);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

function signatureExport(sig) {
  return backend.signatureExport(sig);
}

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

function signatureImport(sig) {
  return backend.signatureImport(sig);
}

/**
 * Test whether a signature has a low S value (R/S).
 * @param {Buffer} sig
 * @returns {Boolean}
 */

function isLowS(raw) {
  return backend.isLowS(raw);
}

/**
 * Test whether a signature has a low S value (DER).
 * @param {Buffer} sig
 * @returns {Boolean}
 */

function isLowDER(raw) {
  return backend.isLowDER(raw);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  return backend.sign(msg, key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Object} R/S-formatted signature and recovery ID.
 */

function signRecoverable(msg, key) {
  return backend.signRecoverable(msg, key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  return backend.signDER(msg, key);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Object} DER-formatted signature and recovery ID.
 */

function signRecoverableDER(msg, key) {
  return backend.signRecoverableDER(msg, key);
}

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  try {
    return backend.verify(msg, sig, key);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
}

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  try {
    return backend.verifyDER(msg, sig, key);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
}

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} param
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

function recover(msg, sig, param, compress) {
  try {
    return backend.recover(msg, sig, param, compress);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return null;
  }
}

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} param
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

function recoverDER(msg, sig, param, compress) {
  try {
    return backend.recoverDER(msg, sig, param, compress);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return null;
  }
}

/**
 * Perform an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

function derive(pub, priv, compress) {
  return backend.derive(pub, priv, compress);
}

/**
 * Sign a message (schnorr).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function schnorrSign(msg, key) {
  return backend.schnorrSign(msg, key);
}

/**
 * Verify a schnorr signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function schnorrVerify(msg, sig, key) {
  try {
    return backend.schnorrVerify(msg, sig, key);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
}

/**
 * Batch verify schnorr signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

function schnorrVerifyBatch(batch) {
  try {
    return backend.schnorrVerifyBatch(batch);
  } catch (e) {
    if (e instanceof TypeError)
      throw e;
    return false;
  }
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
exports.privateKeyReduce = privateKeyReduce;
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
