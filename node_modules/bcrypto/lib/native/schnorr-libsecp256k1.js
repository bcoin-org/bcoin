/*!
 * schnorr-libsecp256k1.js - schnorr for bcrypto (libsecp256k1)
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

  const [d, x, y] = binding.secp256k1_xonly_seckey_export(handle(), key);

  return { d, x, y };
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

  return binding.secp256k1_xonly_seckey_tweak_add(handle(), key, tweak);
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
 * @returns {Buffer}
 */

function publicKeyCreate(key) {
  assert(Buffer.isBuffer(key));

  return binding.secp256k1_xonly_create(handle(), key);
}

/**
 * Run uniform bytes through Shallue-van de Woestijne.
 * @param {Buffer} bytes
 * @returns {Buffer}
 */

function publicKeyFromUniform(bytes) {
  assert(Buffer.isBuffer(bytes));

  return binding.secp256k1_xonly_from_uniform(handle(), bytes);
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

  return binding.secp256k1_xonly_to_uniform(handle(), key, hint);
}

/**
 * Create public key from a 64 byte hash.
 * @param {Buffer} bytes
 * @returns {Buffer}
 */

function publicKeyFromHash(bytes) {
  assert(Buffer.isBuffer(bytes));

  return binding.secp256k1_xonly_from_hash(handle(), bytes);
}

/**
 * Create a 64 byte hash from a public key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function publicKeyToHash(key) {
  assert(Buffer.isBuffer(key));
  return binding.secp256k1_xonly_to_hash(handle(), key, binding.entropy());
}

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));
  return binding.secp256k1_xonly_verify(handle(), key);
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  assert(Buffer.isBuffer(key));

  const [x, y] = binding.secp256k1_xonly_export(handle(), key);

  return { x, y };
}

/**
 * Import a public key from an object.
 * @param {Object} json
 * @returns {Buffer}
 */

function publicKeyImport(json) {
  assert(json && typeof json === 'object');

  let {x, y} = json;

  if (x == null)
    x = binding.NULL;

  if (y == null)
    y = binding.NULL;

  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  return binding.secp256k1_xonly_import(handle(), x, y);
}

/**
 * Compute (key + (g * tweak)).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function publicKeyTweakAdd(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));

  return binding.secp256k1_xonly_tweak_add(handle(), key, tweak);
}

/**
 * Compute (key + (g * tweak)).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer}
 */

function publicKeyTweakMul(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));

  return binding.secp256k1_xonly_tweak_mul(handle(), key, tweak);
}

/**
 * Compute (key + (g * tweak)).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Array}
 */

function publicKeyTweakSum(key, tweak) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));

  return binding.secp256k1_xonly_tweak_sum(handle(), key, tweak);
}

/**
 * Test computation of (key + (g * tweak)).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Buffer} expect
 * @param {Boolean} negated
 * @returns {Boolean}
 */

function publicKeyTweakCheck(key, tweak, expect, negated) {
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(tweak));
  assert(Buffer.isBuffer(expect));
  assert(typeof negated === 'boolean');

  return binding.secp256k1_xonly_tweak_check(handle(),
                                             key,
                                             tweak,
                                             expect,
                                             negated);
}

/**
 * Combine public keys.
 * @param {Buffer[]} keys
 * @returns {Buffer}
 */

function publicKeyCombine(keys) {
  assert(Array.isArray(keys));

  for (const key of keys)
    assert(Buffer.isBuffer(key));

  return binding.secp256k1_xonly_combine(handle(), keys);
}

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Buffer?} aux
 * @returns {Buffer}
 */

function sign(msg, key, aux = binding.entropy(32)) {
  if (aux == null)
    aux = binding.NULL;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));
  assert(Buffer.isBuffer(aux));

  return binding.secp256k1_schnorr_sign(handle(), msg, key, aux);
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

  return binding.secp256k1_schnorr_verify(handle(), msg, sig, key);
}

/**
 * Batch verify signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

function verifyBatch(batch) {
  assert(Array.isArray(batch));

  for (const item of batch) {
    assert(Array.isArray(item));
    assert(item.length === 3);
    assert(Buffer.isBuffer(item[0]));
    assert(Buffer.isBuffer(item[1]));
    assert(Buffer.isBuffer(item[2]));
  }

  return binding.secp256k1_schnorr_verify_batch(handle(), batch);
}

/**
 * Perform an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  assert(Buffer.isBuffer(pub));
  assert(Buffer.isBuffer(priv));

  return binding.secp256k1_xonly_derive(handle(), pub, priv);
}

/*
 * Expose
 */

exports.id = 'SECP256K1';
exports.type = 'schnorr';
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
exports.publicKeyFromUniform = publicKeyFromUniform;
exports.publicKeyToUniform = publicKeyToUniform;
exports.publicKeyFromHash = publicKeyFromHash;
exports.publicKeyToHash = publicKeyToHash;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyExport = publicKeyExport;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyTweakAdd = publicKeyTweakAdd;
exports.publicKeyTweakMul = publicKeyTweakMul;
exports.publicKeyTweakSum = publicKeyTweakSum;
exports.publicKeyTweakCheck = publicKeyTweakCheck;
exports.publicKeyCombine = publicKeyCombine;
exports.sign = sign;
exports.verify = verify;
exports.verifyBatch = verifyBatch;
exports.derive = derive;
