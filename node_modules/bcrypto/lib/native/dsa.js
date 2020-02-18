/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');
const backend = binding.dsa;

/**
 * Create params from key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

function paramsCreate(key) {
  return backend.paramsCreate(key);
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

  return backend.paramsGenerate(bits, binding.entropy());
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

  return new Promise((resolve, reject) => {
    const cb = (err, raw) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(raw);
    };

    try {
      backend.paramsGenerateAsync(bits, binding.entropy(), cb);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * Get params prime size in bits.
 * @param {Buffer} params
 * @returns {Number}
 */

function paramsBits(params) {
  return backend.paramsBits(params);
}

/**
 * Verify params.
 * @param {Buffer} params
 * @returns {Boolean}
 */

function paramsVerify(params) {
  return backend.paramsVerify(params);
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

  return backend.paramsImport(raw);
}

/**
 * Export params to an object.
 * @param {Buffer} params
 * @returns {Object}
 */

function paramsExport(params) {
  const raw = backend.paramsExport(params);
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
  return backend.privateKeyCreate(params, binding.entropy());
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
  return backend.privateKeyBits(key);
}

/**
 * Verify a private key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  return backend.privateKeyVerify(key);
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

  return backend.privateKeyImport(raw);
}

/**
 * Export a private key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function privateKeyExport(key) {
  const raw = backend.privateKeyExport(key);
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
  return backend.publicKeyCreate(key);
}

/**
 * Get public key prime size in bits.
 * @param {Buffer} key
 * @returns {Number}
 */

function publicKeyBits(key) {
  return backend.publicKeyBits(key);
}

/**
 * Verify a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  return backend.publicKeyVerify(key);
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

  return backend.publicKeyImport(raw);
}

/**
 * Export a public key to an object.
 * @param {Buffer} key
 * @returns {Object}
 */

function publicKeyExport(key) {
  const raw = backend.publicKeyExport(key);
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
  return backend.signatureImport(sig, size);
}

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} DER-formatted signature.
 */

function signatureExport(sig, size) {
  return backend.signatureExport(sig, size);
}

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

function sign(msg, key) {
  return backend.sign(msg, key, binding.entropy());
}

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

function signDER(msg, key) {
  return backend.signDER(msg, key, binding.entropy());
}

/**
 * Verify a signature (R/S).
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verify(msg, sig, key) {
  return backend.verify(msg, sig, key);
}

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

function verifyDER(msg, sig, key) {
  return backend.verifyDER(msg, sig, key);
}

/**
 * Perform a diffie-hellman.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

function derive(pub, priv) {
  return backend.derive(pub, priv);
}

/*
 * Expose
 */

exports.native = 2;
exports.paramsCreate = paramsCreate;
exports.paramsGenerate = paramsGenerate;
exports.paramsGenerateAsync = paramsGenerateAsync;
exports.paramsBits = paramsBits;
exports.paramsVerify = paramsVerify;
exports.paramsImport = paramsImport;
exports.paramsExport = paramsExport;
exports.privateKeyCreate = privateKeyCreate;
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
exports.signatureImport = signatureImport;
exports.signatureExport = signatureExport;
exports.sign = sign;
exports.signDER = signDER;
exports.verify = verify;
exports.verifyDER = verifyDER;
exports.derive = derive;
