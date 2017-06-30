/*!
 * secp256k1-native.js - wrapper for secp256k1-node
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const secp256k1 = require('secp256k1');
const random = require('./random');

/**
 * @exports crypto/secp256k1
 */

const ec = exports;

/*
 * Constants
 */

const ZERO_S = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);

const HALF_ORDER = Buffer.from(
  '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0',
  'hex');

/**
 * Whether we're using native bindings.
 * @const {Boolean}
 * @private
 */

ec.binding = true;

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

ec.generatePrivateKey = function generatePrivateKey() {
  let priv;

  do {
    priv = random.randomBytes(32);
  } while (!secp256k1.privateKeyVerify(priv));

  return priv;
};

/**
 * Create a public key from a private key.
 * @param {Buffer} priv
 * @param {Boolean?} compress
 * @returns {Buffer}
 */

ec.publicKeyCreate = function publicKeyCreate(priv, compress) {
  assert(Buffer.isBuffer(priv));
  return secp256k1.publicKeyCreate(priv, compress);
};

/**
 * Compress or decompress public key.
 * @param {Buffer} pub
 * @returns {Buffer}
 */

ec.publicKeyConvert = function publicKeyConvert(key, compress) {
  return secp256k1.publicKeyConvert(key, compress);
};

/**
 * ((tweak + key) % n)
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @returns {Buffer} privateKey
 */

ec.privateKeyTweakAdd = function privateKeyTweakAdd(privateKey, tweak) {
  return secp256k1.privateKeyTweakAdd(privateKey, tweak);
};

/**
 * ((g * tweak) + key)
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @returns {Buffer} publicKey
 */

ec.publicKeyTweakAdd = function publicKeyTweakAdd(publicKey, tweak, compress) {
  return secp256k1.publicKeyTweakAdd(publicKey, tweak, compress);
};

/**
 * Create an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

ec.ecdh = function ecdh(pub, priv) {
  let point = secp256k1.ecdhUnsafe(pub, priv, true);
  return point.slice(1, 33);
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number?} j
 * @param {Boolean?} compress
 * @returns {Buffer[]|Buffer|null}
 */

ec.recover = function recover(msg, sig, j, compress) {
  let key;

  if (!j)
    j = 0;

  try {
    sig = secp256k1.signatureImport(sig);
  } catch (e) {
    return;
  }

  try {
    key = secp256k1.recover(msg, sig, j, compress);
  } catch (e) {
    return;
  }

  return key;
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ec.verify = function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  if (sig.length === 0)
    return false;

  if (key.length === 0)
    return false;

  try {
    sig = secp256k1.signatureImportLax(sig);
    sig = secp256k1.signatureNormalize(sig);
    return secp256k1.verify(msg, sig, key);
  } catch (e) {
    return false;
  }
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

ec.publicKeyVerify = function publicKeyVerify(key) {
  return secp256k1.publicKeyVerify(key);
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

ec.privateKeyVerify = function privateKeyVerify(key) {
  return secp256k1.privateKeyVerify(key);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

ec.sign = function sign(msg, key) {
  let sig;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  // Sign message
  sig = secp256k1.sign(msg, key);

  // Ensure low S value
  sig = secp256k1.signatureNormalize(sig.signature);

  // Convert to DER
  return secp256k1.signatureExport(sig);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

ec.fromDER = function fromDER(sig) {
  assert(Buffer.isBuffer(sig));
  return secp256k1.signatureImport(sig);
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

ec.toDER = function toDER(sig) {
  assert(Buffer.isBuffer(sig));
  return secp256k1.signatureExport(sig);
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

ec.isLowS = function isLowS(sig) {
  let rs, s;

  try {
    rs = secp256k1.signatureImport(sig);
    s = rs.slice(32, 64);
  } catch (e) {
    return false;
  }

  if (s.equals(ZERO_S))
    return false;

  // If S is greater than half the order,
  // it's too high.
  if (s.compare(HALF_ORDER) > 0)
    return false;

  return true;
};
