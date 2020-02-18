/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const rsakey = require('../internal/rsakey');
const pkcs1 = require('../encoding/pkcs1');
const base = require('../js/rsa');
const rsa = Object.setPrototypeOf(exports, base);
const {constants} = crypto;

const {
  DEFAULT_BITS,
  DEFAULT_EXP,
  MIN_BITS,
  MAX_BITS,
  MIN_EXP,
  MAX_EXP,
  RSAKey,
  RSAPrivateKey
} = rsakey;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

rsa.native = 1;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

rsa.privateKeyGenerate = function privateKeyGenerate(bits, exponent) {
  if (!crypto.generateKeyPairSync || (exponent && exponent > 0xffffffff))
    return base.privateKeyGenerate.call(rsa, bits, exponent);

  const options = createOptions(bits, exponent);
  const {privateKey} = crypto.generateKeyPairSync('rsa', options);

  return rsa.privateKeyImport(privateKey);
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

rsa.privateKeyGenerateAsync = async function privateKeyGenerateAsync(bits, exponent) {
  if (!crypto.generateKeyPair || (exponent && exponent > 0xffffffff))
    return base.privateKeyGenerateAsync.call(rsa, bits, exponent);

  const options = createOptions(bits, exponent);

  return new Promise((resolve, reject) => {
    const cb = (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
        return;
      }

      let key;
      try {
        key = rsa.privateKeyImport(privateKey);
      } catch (e) {
        reject(e);
        return;
      }

      resolve(key);
    };

    try {
      crypto.generateKeyPair('rsa', options, cb);
    } catch (e) {
      reject(e);
    }
  });
};

/**
 * Raw encryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

rsa.encryptRaw = function encryptRaw(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);

  const pub = new pkcs1.RSAPublicKey(key.n, key.e);

  return crypto.publicEncrypt({
    key: pub.toPEM(),
    padding: constants.RSA_NO_PADDING
  }, msg);
};

/**
 * Raw decryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

rsa.decryptRaw = function decryptRaw(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  const priv = new pkcs1.RSAPrivateKey(
    0,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );

  return crypto.privateDecrypt({
    key: priv.toPEM(),
    padding: constants.RSA_NO_PADDING
  }, msg);
};

/*
 * Helpers
 */

function createOptions(bits, exponent) {
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

  if (exponent === 1 || (exponent % 2) === 0)
    throw new RangeError('"exponent" must be odd.');

  return {
    modulusLength: bits,
    publicExponent: exponent,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'der'
    }
  };
}
