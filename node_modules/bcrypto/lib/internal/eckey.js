/*!
 * eckey.js - jwk ec keys for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7517
 *   https://tools.ietf.org/html/rfc7518
 *   https://tools.ietf.org/html/draft-jones-webauthn-secp256k1-00
 *   https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-06#appendix-A.1
 *   https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-06#appendix-A.6
 */

'use strict';

const assert = require('bsert');
const base64 = require('../internal/base64');

/*
 * JWK
 */

function privateKeyExportJWK(curve, key) {
  assert(curve && typeof curve.publicKeyCreate === 'function');

  const pub = curve.publicKeyCreate(key, false);
  const json = publicKeyExportJWK(curve, pub);

  if (curve.type !== 'short') {
    return {
      kty: 'OKP',
      crv: json.crv,
      x: json.x,
      d: base64.encodeURL(key),
      ext: true
    };
  }

  return {
    kty: 'EC',
    crv: json.crv,
    x: json.x,
    y: json.y,
    d: base64.encodeURL(key),
    ext: true
  };
}

function privateKeyImportJWK(curve, json) {
  assert(curve && typeof curve.privateKeyVerify === 'function');
  assert(json && typeof json === 'object');

  if (json.kty !== getKTY(curve))
    throw new Error('Invalid key type.');

  if (json.crv != null && fromCurve(json.crv) !== curve.id)
    throw new Error('Invalid curve name.');

  const key = base64.decodeURL(json.d);

  if (!curve.privateKeyVerify(key))
    throw new Error('Invalid private key.');

  return key;
}

function publicKeyExportJWK(curve, key) {
  assert(curve && typeof curve.publicKeyExport === 'function');

  const pub = curve.publicKeyExport(key);

  if (curve.type !== 'short') {
    // Note: The RFC says to use only `x`
    // as the coordinate name even though
    // in reality it should probably be
    // `u` or `y`.
    return {
      kty: 'OKP',
      crv: toCurve(curve.id),
      x: base64.encodeURL(pub),
      ext: true
    };
  }

  const x = pub.slice(0, curve.size);
  const y = pub.slice(curve.size, curve.size * 2);

  return {
    kty: 'EC',
    crv: toCurve(curve.id),
    x: base64.encodeURL(x),
    y: base64.encodeURL(y),
    ext: true
  };
}

function publicKeyImportJWK(curve, json, compress) {
  assert(curve && typeof curve.publicKeyImport === 'function');
  assert(json && typeof json === 'object');

  if (json.kty !== getKTY(curve))
    throw new Error('Invalid key type.');

  if (json.crv != null && fromCurve(json.crv) !== curve.id)
    throw new Error('Invalid curve name.');

  if (curve.type !== 'short') {
    const x = base64.decodeURL(json.x);
    return curve.publicKeyImport(x);
  }

  const x = base64.decodeURL(json.x);
  const y = base64.decodeURL(json.y);

  if (x.length !== curve.size || y.length !== curve.size)
    throw new Error('Invalid public key.');

  const pub = Buffer.concat([x, y]);

  return curve.publicKeyImport(pub, compress);
}

/*
 * Helpers
 */

function getKTY(curve) {
  return curve.type === 'short' ? 'EC' : 'OKP';
}

function toCurve(id) {
  assert(typeof id === 'string');

  switch (id) {
    case 'P192':
      return 'P-192';
    case 'P224':
      return 'P-224';
    case 'P256':
      return 'P-256';
    case 'P384':
      return 'P-384';
    case 'P521':
      return 'P-521';
    case 'SECP256K1':
      return 'P-256K';
    case 'ED25519':
      return 'Ed25519';
    case 'ED448':
      return 'Ed448';
    default:
      return id;
  }
}

function fromCurve(crv) {
  assert(typeof crv === 'string');

  switch (crv) {
    case 'P-192':
      return 'P192';
    case 'P-224':
      return 'P224';
    case 'P-256':
      return 'P256';
    case 'P-384':
      return 'P384';
    case 'P-521':
      return 'P521';
    case 'P-256K':
      return 'SECP256K1';
    case 'Ed25519':
      return 'ED25519';
    case 'Ed448':
      return 'ED448';
    default:
      return crv;
  }
}

/*
 * Expose
 */

exports.privateKeyExportJWK = privateKeyExportJWK;
exports.privateKeyImportJWK = privateKeyImportJWK;
exports.publicKeyExportJWK = publicKeyExportJWK;
exports.publicKeyImportJWK = publicKeyImportJWK;
