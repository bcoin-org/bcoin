/*!
 * dsa.js - DSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const bio = require('bufio');
const dsakey = require('../internal/dsakey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const base = require('../js/dsa');
const dsa = Object.setPrototypeOf(exports, base);

const {
  DEFAULT_BITS,
  MIN_BITS,
  MAX_BITS,
  DSAPublicKey,
  DSAPrivateKey
} = dsakey;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

dsa.native = 1;

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

dsa.paramsGenerate = function paramsGenerate(bits) {
  if (!crypto.generateKeyPairSync)
    return base.paramsGenerate.call(dsa, bits);

  const options = createOptions(bits);
  const {publicKey} = crypto.generateKeyPairSync('dsa', options);

  return parseParams(publicKey);
};

/**
 * Generate params.
 * @param {Number} [bits=2048]
 * @returns {DSAParams}
 */

dsa.paramsGenerateAsync = async function paramsGenerateAsync(bits) {
  if (!crypto.generateKeyPair)
    return base.paramsGenerateAsync.call(dsa, bits);

  const options = createOptions(bits);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let params;
      try {
        params = parseParams(publicKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(params);
    };

    try {
      crypto.generateKeyPair('dsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
};

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyGenerate = function privateKeyGenerate(bits) {
  if (!crypto.generateKeyPairSync)
    return base.privateKeyGenerate.call(dsa, bits);

  const options = createOptions(bits);
  const {publicKey, privateKey} = crypto.generateKeyPairSync('dsa', options);

  return parsePrivateKey(publicKey, privateKey);
};

/**
 * Generate private key.
 * @param {Number} [bits=2048]
 * @returns {DSAPrivateKey}
 */

dsa.privateKeyGenerateAsync = async function privateKeyGenerateAsync(bits) {
  if (!crypto.generateKeyPair)
    return base.privateKeyGenerateAsync.call(dsa, bits);

  const options = createOptions(bits);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let key;
      try {
        key = parsePrivateKey(publicKey, privateKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(key);
    };

    try {
      crypto.generateKeyPair('dsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
};

/*
 * Helpers
 */

function createOptions(bits) {
  if (bits == null)
    bits = DEFAULT_BITS;

  assert((bits >>> 0) === bits);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  // OpenSSL behavior.
  const L = bits;
  const N = bits < 2048 ? 160 : 256;

  return {
    modulusLength: L,
    divisorLength: N,
    publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der'
    }
  };
}

function parseParams(publicKey) {
  const pub = parsePublicKey(publicKey);
  return pub.toParams();
}

function parsePublicKey(publicKey) {
  const spki = x509.SubjectPublicKeyInfo.decode(publicKey);
  const br = bio.read(spki.algorithm.parameters.node.value);
  const p = asn1.Unsigned.read(br);
  const q = asn1.Unsigned.read(br);
  const g = asn1.Unsigned.read(br);
  const y = asn1.Unsigned.decode(spki.publicKey.rightAlign());
  const key = new DSAPublicKey();

  key.p = p.value;
  key.q = q.value;
  key.g = g.value;
  key.y = y.value;

  return key;
}

function parsePrivateKey(publicKey, privateKey) {
  const pub = parsePublicKey(publicKey);
  const pki = pkcs8.PrivateKeyInfo.decode(privateKey);
  const x = asn1.Unsigned.decode(pki.privateKey.value);

  const key = new DSAPrivateKey();

  key.p = pub.p;
  key.q = pub.q;
  key.g = pub.g;
  key.y = pub.y;
  key.x = x.value;

  return key;
}
