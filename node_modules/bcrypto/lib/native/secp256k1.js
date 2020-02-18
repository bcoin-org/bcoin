/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').secp256k1;
const random = require('./random');
const eckey = require('../internal/eckey');
const asn1 = require('../internal/asn1-mini');
const secp256k1 = exports;

/*
 * Constants
 */

const ZERO = Buffer.alloc(32, 0x00);

const ORDER = Buffer.from(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  'hex');

const HALF_ORDER = Buffer.from(
  '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0',
  'hex');

const CURVE_OID = Buffer.from('2b8104000a', 'hex');

/**
 * Name of the curve.
 * @const {String}
 */

secp256k1.id = 'SECP256K1';

/**
 * Curve type.
 * @const {String}
 */

secp256k1.type = 'short';

/**
 * Size of the curve's prime in bits.
 * @const {Number}
 */

secp256k1.bits = 256;

/**
 * Curve encoding length in bytes.
 * @const {Buffer}
 */

secp256k1.size = 32;

/**
 * Zero value of the curve.
 * @const {Buffer}
 */

secp256k1.zero = ZERO;

/**
 * Order of the curve.
 * @const {Buffer}
 */

secp256k1.order = ORDER;

/**
 * Half-order of the curve.
 * @const {Buffer}
 */

secp256k1.half = HALF_ORDER;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

secp256k1.native = 2;

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

secp256k1.privateKeyGenerate = function privateKeyGenerate() {
  const key = Buffer.allocUnsafe(32);

  do {
    random.randomFill(key, 0, 32);
  } while (!binding.privateKeyVerify(key));

  return key;
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

secp256k1.privateKeyVerify = function privateKeyVerify(key) {
  return binding.privateKeyVerify(key);
};

/**
 * Export a private key to SEC1 ASN.1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.privateKeyExport = function privateKeyExport(key, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  const pub = secp256k1.publicKeyCreate(key, compress);

  return asn1.encodeSEC1({
    version: 1,
    key,
    oid: CURVE_OID,
    pub
  });
};

/**
 * Import a private key from SEC1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

secp256k1.privateKeyImport = function privateKeyImport(raw) {
  const pki = asn1.decodeSEC1(raw);

  assert(pki.version === 1);
  assert(!pki.oid || pki.oid.equals(CURVE_OID));

  if (!secp256k1.privateKeyVerify(pki.key))
    throw new Error('Invalid private key.');

  return pki.key;
};

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.privateKeyExportPKCS8 = function privateKeyExportPKCS8(key, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  const pub = secp256k1.publicKeyCreate(key, compress);

  return asn1.encodePKCS8({
    version: 0,
    algorithm: {
      oid: asn1.ECDSA_OID,
      type: asn1.OID,
      params: CURVE_OID
    },
    key: asn1.encodeSEC1({
      version: 1,
      key,
      oid: null,
      pub
    })
  });
};

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

secp256k1.privateKeyImportPKCS8 = function privateKeyImportPKCS8(raw) {
  const pki = asn1.decodePKCS8(raw);

  assert(pki.version === 0);
  assert(pki.algorithm.oid.equals(asn1.ECDSA_OID));

  if (pki.algorithm.type === asn1.OID)
    assert(pki.algorithm.params.equals(CURVE_OID));
  else
    assert(pki.algorithm.type === asn1.NULL);

  return secp256k1.privateKeyImport(pki.key);
};

/**
 * Export a private key to JWK JSON format.
 * @param {Buffer} key
 * @returns {Object}
 */

secp256k1.privateKeyExportJWK = function privateKeyExportJWK(key) {
  return eckey.privateKeyExportJWK(secp256k1, key);
};

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {Buffer}
 */

secp256k1.privateKeyImportJWK = function privateKeyImportJWK(json) {
  return eckey.privateKeyImportJWK(secp256k1, json);
};

/**
 * Compute ((tweak + key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

secp256k1.privateKeyTweakAdd = function privateKeyTweakAdd(key, tweak) {
  return binding.privateKeyTweakAdd(key, tweak);
};

/**
 * Compute ((tweak * key) mod n).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @returns {Buffer} key
 */

secp256k1.privateKeyTweakMul = function privateKeyTweakMul(key, tweak) {
  return binding.privateKeyTweakMul(key, tweak);
};

/**
 * Compute (-key mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

secp256k1.privateKeyNegate = function privateKeyNegate(key) {
  return binding.privateKeyNegate(key);
};

/**
 * Compute (key^-1 mod n).
 * @param {Buffer} key
 * @returns {Buffer} key
 */

secp256k1.privateKeyInverse = function privateKeyInverse(key) {
  return binding.privateKeyInverse(key);
};

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyCreate = function publicKeyCreate(key, compress) {
  return binding.publicKeyCreate(key, compress);
};

/**
 * Compress or decompress public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyConvert = function publicKeyConvert(key, compress) {
  return binding.publicKeyConvert(key, compress);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

secp256k1.publicKeyVerify = function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
};

/**
 * Export a public key to X/Y format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

secp256k1.publicKeyExport = function publicKeyExport(key) {
  return secp256k1.publicKeyConvert(key, false).slice(1);
};

/**
 * Import a public key from X/Y format.
 * @param {Buffer} raw
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyImport = function publicKeyImport(raw, compress) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 64);

  const key = Buffer.allocUnsafe(1 + raw.length);
  key[0] = 0x04;
  raw.copy(key, 1);

  return secp256k1.publicKeyConvert(key, compress);
};

/**
 * Export a public key to SubjectPublicKeyInfo ASN1 format.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyExportSPKI = function publicKeyExportSPKI(key, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(key));
  assert(typeof compress === 'boolean');

  return asn1.encodeSPKI({
    algorithm: {
      oid: asn1.ECDSA_OID,
      type: asn1.OID,
      params: CURVE_OID
    },
    key: secp256k1.publicKeyConvert(key, compress)
  });
};

/**
 * Import a public key from SubjectPublicKeyInfo ASN1 format.
 * @param {Buffer} raw
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyImportSPKI = function publicKeyImportSPKI(raw, compress) {
  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(raw));
  assert(typeof compress === 'boolean');

  const spki = asn1.decodeSPKI(raw);

  assert(spki.algorithm.oid.equals(asn1.ECDSA_OID));

  if (spki.algorithm.type === asn1.OID)
    assert(spki.algorithm.params.equals(CURVE_OID));
  else
    assert(spki.algorithm.type === asn1.NULL);

  return secp256k1.publicKeyConvert(spki.key, compress);
};

/**
 * Export a public key to JWK JSON format.
 * @param {Buffer} key
 * @returns {Object}
 */

secp256k1.publicKeyExportJWK = function publicKeyExportJWK(key) {
  return eckey.publicKeyExportJWK(secp256k1, key);
};

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyImportJWK = function publicKeyImportJWK(json, compress) {
  return eckey.publicKeyImportJWK(secp256k1, json, compress);
};

/**
 * Compute ((g * tweak) + key).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer} key
 */

secp256k1.publicKeyTweakAdd = function publicKeyTweakAdd(key, tweak, compress) {
  return binding.publicKeyTweakAdd(key, tweak, compress);
};

/**
 * Compute (key * tweak).
 * @param {Buffer} key
 * @param {Buffer} tweak
 * @param {Boolean} [compress=true]
 * @returns {Buffer} key
 */

secp256k1.publicKeyTweakMul = function publicKeyTweakMul(key, tweak, compress) {
  return binding.publicKeyTweakMul(key, tweak, compress);
};

/**
 * Add two public keys.
 * @param {Buffer} key1
 * @param {Buffer} key2
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyAdd = function publicKeyAdd(key1, key2, compress) {
  return binding.publicKeyCombine([key1, key2], compress);
};

/**
 * Negate public key.
 * @param {Buffer} key
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.publicKeyNegate = function publicKeyNegate(key, compress) {
  return binding.publicKeyNegate(key, compress);
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

secp256k1.signatureExport = function signatureExport(sig) {
  return binding.signatureExport(sig);
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

secp256k1.signatureImport = function signatureImport(sig) {
  return binding.signatureImportLax(sig);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

secp256k1.sign = function sign(msg, key) {
  // Sign message.
  const {signature} = binding.sign(truncate(msg), key);

  // Ensure low S value.
  return binding.signatureNormalize(signature);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Object} R/S-formatted signature and recovery ID.
 */

secp256k1.signRecoverable = function signRecoverable(msg, key) {
  // Sign message.
  const {signature, recovery} = binding.sign(truncate(msg), key);

  // Ensure low S value.
  return {
    signature: binding.signatureNormalize(signature),
    recovery: recovery
  };
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

secp256k1.signDER = function signDER(msg, key) {
  // Sign message.
  const sig = secp256k1.sign(msg, key);

  // Convert to DER.
  return binding.signatureExport(sig);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Object} DER-formatted signature and recovery ID.
 */

secp256k1.signRecoverableDER = function signRecoverableDER(msg, key) {
  const {signature, recovery} = secp256k1.signRecoverable(msg, key);

  return {
    signature: binding.signatureExport(signature),
    recovery: recovery
  };
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

secp256k1.verify = function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  try {
    const s = binding.signatureNormalize(sig);
    return binding.verify(truncate(msg), s, key);
  } catch (e) {
    return false;
  }
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

secp256k1.verifyDER = function verifyDER(msg, sig, key) {
  assert(Buffer.isBuffer(sig));

  let s;
  try {
    s = binding.signatureImportLax(sig);
  } catch (e) {
    return false;
  }

  return secp256k1.verify(msg, s, key);
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} [param=0]
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

secp256k1.recover = function recover(msg, sig, param, compress) {
  if (param == null)
    param = 0;

  if (compress == null)
    compress = true;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert((param >>> 0) === param);
  assert(typeof compress === 'boolean');

  try {
    return binding.recover(truncate(msg), sig, param, compress);
  } catch (e) {
    return null;
  }
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number} [param=0]
 * @param {Boolean} [compress=true]
 * @returns {Buffer|null}
 */

secp256k1.recoverDER = function recoverDER(msg, sig, param, compress) {
  assert(Buffer.isBuffer(sig));

  let s;
  try {
    s = binding.signatureImportLax(sig);
  } catch (e) {
    return null;
  }

  return secp256k1.recover(msg, s, param, compress);
};

/**
 * Perform an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @param {Boolean} [compress=true]
 * @returns {Buffer}
 */

secp256k1.derive = function derive(pub, priv, compress) {
  return binding.derive(pub, priv, compress);
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

secp256k1.isLowS = function isLowS(raw) {
  assert(Buffer.isBuffer(raw));

  if (raw.length !== 64)
    return false;

  const sig = raw.slice(32, 64);

  if (sig.equals(ZERO))
    return false;

  if (sig.compare(HALF_ORDER) > 0)
    return false;

  return true;
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

secp256k1.isLowDER = function isLowDER(raw) {
  assert(Buffer.isBuffer(raw));

  let sig;
  try {
    sig = binding.signatureImportLax(raw);
  } catch (e) {
    return false;
  }

  return secp256k1.isLowS(sig);
};

/**
 * Sign a message (schnorr).
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} R/S-formatted signature.
 */

secp256k1.schnorrSign = function schnorrSign(msg, key) {
  return binding.schnorrSign(msg, key);
};

/**
 * Verify a schnorr signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - R/S formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

secp256k1.schnorrVerify = function schnorrVerify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  try {
    return binding.schnorrVerify(msg, sig, key);
  } catch (e) {
    return false;
  }
};

/**
 * Batch verify schnorr signatures.
 * @param {Object[]} batch
 * @returns {Boolean}
 */

secp256k1.schnorrBatchVerify = function schnorrBatchVerify(batch) {
  assert(Array.isArray(batch));

  // Can't do real batching here unless we upgrade
  // to libsecp256k1-zkp, or a later version of
  // libsecp256k1 (with a backported schnorrsig module).
  // Not ready to do that just yet.
  for (const item of batch) {
    assert(Array.isArray(item) && item.length === 3);

    const [msg, sig, key] = item;

    if (!secp256k1.schnorrVerify(msg, sig, key))
      return false;
  }

  return true;
};

/*
 * Compat
 */

secp256k1.generatePrivateKey = secp256k1.privateKeyGenerate;
secp256k1.toDER = secp256k1.signatureExport;
secp256k1.fromDER = secp256k1.signatureImport;
secp256k1.ecdh = secp256k1.derive;

/*
 * Helpers
 */

function truncate(msg) {
  assert(Buffer.isBuffer(msg));

  if (msg.length < 32) {
    const out = Buffer.allocUnsafe(32);
    const pos = 32 - msg.length;

    out.fill(0x00, 0, pos);
    msg.copy(out, pos);

    return out;
  }

  if (msg.length > 32)
    return msg.slice(0, 32);

  return msg;
}
