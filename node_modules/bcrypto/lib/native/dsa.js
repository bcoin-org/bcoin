/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').dsa;

if (!binding)
  throw new Error('DSA native support not available.');

const dsakey = require('../internal/dsakey');
const Signature = require('../internal/signature');
const dsa = exports;

const {
  DSAKey,
  DSAParams,
  DSAPublicKey,
  DSAPrivateKey
} = dsakey;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

dsa.native = 2;

/**
 * DSAParams
 */

dsa.DSAParams = DSAParams;

/**
 * DSAKey
 */

dsa.DSAKey = DSAKey;

/**
 * DSAPublicKey
 */

dsa.DSAPublicKey = DSAPublicKey;

/**
 * DSAPrivateKey
 */

dsa.DSAPrivateKey = DSAPrivateKey;

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

dsa.paramsGenerate = function paramsGenerate(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  const items = binding.paramsGenerate(bits);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
};

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

dsa.paramsGenerateAsync = async function paramsGenerateAsync(bits) {
  if (bits == null)
    bits = 2048;

  assert((bits >>> 0) === bits);

  if (bits < 1024 || bits > 3072)
    throw new RangeError('`bits` must range between 1024 and 3072.');

  return new Promise((resolve, reject) => {
    const cb = (err, items) => {
      if (err) {
        reject(err);
        return;
      }

      const params = new DSAParams();

      [
        params.p,
        params.q,
        params.g
      ] = items;

      resolve(params);
    };

    try {
      binding.paramsGenerateAsync(bits, cb);
    } catch (e) {
      reject(e);
    }
  });
};

/**
 * Verify params.
 * @param {DSAParams} params
 * @returns {Boolean}
 */

dsa.paramsVerify = function paramsVerify(params) {
  assert(params instanceof DSAParams);

  return binding.paramsVerify(
    params.p,
    params.q,
    params.g
  );
};

/**
 * Export params in OpenSSL ASN.1 format.
 * @param {DSAParams} params
 * @returns {Buffer}
 */

dsa.paramsExport = function paramsExport(params) {
  assert(params instanceof DSAParams);
  return binding.paramsExport(params.p, params.q, params.g);
};

/**
 * Import params in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAParams}
 */

dsa.paramsImport = function paramsImport(raw) {
  const items = binding.paramsImport(raw);
  const params = new DSAParams();

  [
    params.p,
    params.q,
    params.g
  ] = items;

  return params;
};

/**
 * Export a public key to JWK JSON format.
 * @param {DSAParams} key
 * @returns {Object}
 */

dsa.paramsExportJWK = function paramsExportJWK(key) {
  assert(key instanceof DSAParams);
  return key.toParams().toJSON();
};

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPublicKey}
 */

dsa.paramsImportJWK = function paramsImportJWK(json) {
  return DSAParams.fromJSON(json);
};

/**
 * Generate private key from params.
 * @param {DSAParams} params
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyCreate = function privateKeyCreate(params) {
  assert(params instanceof DSAParams);

  const items = binding.privateKeyCreate(
    params.p,
    params.q,
    params.g
  );

  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
};

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyGenerate = function privateKeyGenerate(bits) {
  const params = dsa.paramsGenerate(bits);
  return dsa.privateKeyCreate(params);
};

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyGenerateAsync = async function privateKeyGenerateAsync(bits) {
  const params = await dsa.paramsGenerateAsync(bits);
  return dsa.privateKeyCreate(params);
};

/**
 * Pre-compute a private key.
 * @param {DSAPrivateKey}
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyCompute = function privateKeyCompute(key) {
  assert(key instanceof DSAPrivateKey);

  const y = binding.privateKeyCompute(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );

  if (y)
    key.y = y;

  return key;
};

/**
 * Verify a private key.
 * @param {DSAPrivateKey} key
 * @returns {Boolean}
 */

dsa.privateKeyVerify = function privateKeyVerify(key) {
  assert(key instanceof DSAPrivateKey);

  return binding.privateKeyVerify(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
};

/**
 * Export a private key in OpenSSL ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

dsa.privateKeyExport = function privateKeyExport(key) {
  assert(key instanceof DSAPrivateKey);

  return binding.privateKeyExport(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
};

/**
 * Import a private key in OpenSSL ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyImport = function privateKeyImport(raw) {
  const items = binding.privateKeyImport(raw);
  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
};

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {DSAPrivateKey} key
 * @returns {Buffer}
 */

dsa.privateKeyExportPKCS8 = function privateKeyExportPKCS8(key) {
  assert(key instanceof DSAPrivateKey);

  return binding.privateKeyExportPKCS8(
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );
};

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyImportPKCS8 = function privateKeyImportPKCS8(raw) {
  const items = binding.privateKeyImportPKCS8(raw);
  const key = new DSAPrivateKey();

  [
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  ] = items;

  return key;
};

/**
 * Export a private key to JWK JSON format.
 * @param {DSAPrivateKey} key
 * @returns {Object}
 */

dsa.privateKeyExportJWK = function privateKeyExportJWK(key) {
  assert(key instanceof DSAPrivateKey);
  return key.toJSON();
};

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyImportJWK = function privateKeyImportJWK(json) {
  const key = DSAPrivateKey.fromJSON(json);

  dsa.privateKeyCompute(key);

  return key;
};

/**
 * Create a public key from a private key.
 * @param {DSAPrivateKey} key
 * @returns {DSAPublicKey}
 */

dsa.publicKeyCreate = function publicKeyCreate(key) {
  assert(key instanceof DSAPrivateKey);

  const pub = new DSAPublicKey();

  pub.p = key.p;
  pub.q = key.q;
  pub.g = key.g;
  pub.y = key.y;

  return pub;
};

/**
 * Verify a public key.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa.publicKeyVerify = function publicKeyVerify(key) {
  assert(key instanceof DSAKey);

  return binding.publicKeyVerify(
    key.p,
    key.q,
    key.g,
    key.y
  );
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

dsa.publicKeyExport = function publicKeyExport(key) {
  assert(key instanceof DSAKey);

  return binding.publicKeyExport(
    key.p,
    key.q,
    key.g,
    key.y
  );
};

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

dsa.publicKeyImport = function publicKeyImport(raw) {
  const items = binding.publicKeyImport(raw);
  const key = new DSAPublicKey();

  [
    key.p,
    key.q,
    key.g,
    key.y
  ] = items;

  return key;
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {DSAKey} key
 * @returns {Buffer}
 */

dsa.publicKeyExportSPKI = function publicKeyExportSPKI(key) {
  assert(key instanceof DSAKey);

  return binding.publicKeyExportSPKI(
    key.p,
    key.q,
    key.g,
    key.y
  );
};

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {DSAPublicKey}
 */

dsa.publicKeyImportSPKI = function publicKeyImportSPKI(raw) {
  const items = binding.publicKeyImportSPKI(raw);
  const key = new DSAPublicKey();

  [
    key.p,
    key.q,
    key.g,
    key.y
  ] = items;

  return key;
};

/**
 * Export a public key to JWK JSON format.
 * @param {DSAKey} key
 * @returns {Object}
 */

dsa.publicKeyExportJWK = function publicKeyExportJWK(key) {
  assert(key instanceof DSAKey);
  return key.toPublic().toJSON();
};

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {DSAPublicKey}
 */

dsa.publicKeyImportJWK = function publicKeyImportJWK(json) {
  return DSAPublicKey.fromJSON(json);
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} DER-formatted signature.
 */

dsa.signatureExport = function signatureExport(sig, size) {
  if (size == null) {
    assert(Buffer.isBuffer(sig));
    assert((sig.length & 1) === 0);
    size = sig.length >>> 1;
  }

  return Signature.toDER(sig, size);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @param {Number} size
 * @returns {Buffer} R/S-formatted signature.
 */

dsa.signatureImport = function signatureImport(sig, size) {
  return Signature.toRS(sig, size);
};

/**
 * Sign a message.
 * @private
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key
 * @returns {Signature}
 */

dsa._sign = function _sign(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof DSAPrivateKey);

  const [r, s] = binding.sign(
    msg,
    key.p,
    key.q,
    key.g,
    key.y,
    key.x
  );

  const sig = new Signature();
  const size = key.size();

  sig.setR(r, size);
  sig.setS(s, size);

  return sig;
};

/**
 * Sign a message (R/S).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

dsa.sign = function sign(msg, key) {
  const sig = dsa._sign(msg, key);
  return sig.encode(key.size());
};

/**
 * Sign a message (DER).
 * @param {Buffer} msg
 * @param {DSAPrivateKey} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

dsa.signDER = function signDER(msg, key) {
  const sig = dsa._sign(msg, key);
  return sig.toDER(key.size());
};

/**
 * Verify a signature.
 * @private
 * @param {Buffer} msg
 * @param {Signature} sig
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa._verify = function _verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(sig instanceof Signature);
  assert(key instanceof DSAKey);

  return binding.verify(
    msg,
    sig.r,
    sig.s,
    key.p,
    key.q,
    key.g,
    key.y
  );
};

/**
 * Verify a signature (R/S).
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa.verify = function verify(msg, sig, key) {
  assert(Buffer.isBuffer(sig));
  assert(key instanceof DSAKey);

  if (sig.length !== key.size() * 2)
    return false;

  const s = Signature.decode(sig, key.size());

  return dsa._verify(msg, s, key);
};

/**
 * Verify a signature (DER).
 * @param {Buffer} msg
 * @param {Buffer} sig - DER-formatted.
 * @param {DSAKey} key
 * @returns {Boolean}
 */

dsa.verifyDER = function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(sig));
  assert(key instanceof DSAKey);

  let s;
  try {
    s = Signature.fromDER(sig, key.size());
  } catch (e) {
    return false;
  }

  return dsa._verify(msg, s, key);
};

/**
 * Perform a diffie-hellman.
 * @param {DSAKey} pub
 * @param {DSAPrivateKey} priv
 * @returns {Buffer}
 */

dsa.derive = function derive(pub, priv) {
  assert(pub instanceof DSAKey);
  assert(priv instanceof DSAPrivateKey);

  return binding.derive(
    pub.p,
    pub.q,
    pub.g,
    pub.y,
    priv.p,
    priv.q,
    priv.g,
    priv.y,
    priv.x
  );
};

/*
 * Compat
 */

dsa.dh = dsa.derive;
