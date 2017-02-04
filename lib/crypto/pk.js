/*!
 * pk.js - public key algorithms for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto/pk
 */

var assert = require('assert');
var nodeCrypto = require('crypto');
var elliptic = require('elliptic');
var PEM = require('../utils/pem');
var backend = require('./backend');
var rsa, ecdsa;

/**
 * RSA
 * @namespace module:crypto/pk.rsa
 */

rsa = {};

/**
 * Verify RSA signature.
 * @memberof module:crypto/pk.rsa
 * @param {String} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} sig - Signature.
 * @param {Buffer} key - ASN1 serialized RSA key.
 * @returns {Boolean}
 */

rsa.verify = function _verify(alg, msg, sig, key) {
  var pem = toPEM('rsa', key, null, 'public key');
  return verify('rsa', alg, msg, sig, pem);
};

/**
 * Sign message with RSA key.
 * @memberof module:crypto/pk.rsa
 * @param {String} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} key - ASN1 serialized RSA key.
 * @returns {Buffer} Signature (DER)
 */

rsa.sign = function _sign(alg, msg, key) {
  var pem = toPEM('rsa', key, null, 'private key');
  return sign('rsa', alg, msg, pem);
};

/**
 * ECDSA
 * @namespace module:crypto/pk.ecdsa
 */

ecdsa = {};

/**
 * Verify ECDSA signature.
 * @memberof module:crypto/pk.ecdsa
 * @param {String} curve - Curve name.
 * @param {String} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} sig - Signature.
 * @param {Buffer} key - ASN1 serialized ECDSA key.
 * @returns {Boolean}
 */

ecdsa.verify = function verify(curve, alg, msg, sig, key) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = backend.hash(alg, msg);

  return ec.verify(hash, sig, key);
};

/**
 * Sign message with ECDSA key.
 * @memberof module:crypto/pk.ecdsa
 * @param {String} curve - Curve name.
 * @param {String} alg - Hash algorithm.
 * @param {Buffer} msg - Signed message.
 * @param {Buffer} key - ASN1 serialized ECDSA key.
 * @returns {Buffer} Signature (DER)
 */

ecdsa.sign = function sign(curve, alg, msg, key) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = backend.hash(alg, msg);

  return new Buffer(ec.sign(hash, key));
};

/*
 * Helpers
 */

function verify(alg, hash, msg, sig, key) {
  var algo = normalizeAlg(alg, hash);
  var verifier = nodeCrypto.createVerify(algo);
  verifier.update(msg);
  return verifier.verify(key, sig);
}

function sign(alg, hash, msg, key) {
  var algo = normalizeAlg(alg, hash);
  var sig = nodeCrypto.createSign(algo);
  sig.update(msg);
  return sig.sign(key);
}

function toPEM(alg, key, params, type) {
  var tag, pem;

  switch (alg) {
    case 'rsa':
      tag = 'RSA';
      break;
    case 'ecdsa':
      tag = 'EC';
      break;
    default:
      throw new Error('Unsupported algorithm.');
  }

  pem = PEM.encode(key, tag, type);

  // Key parameters, usually present
  // if selecting an EC curve.
  if (params)
    pem += PEM.encode(params, tag, 'parameters');

  return pem;
}

function normalizeAlg(alg, hash) {
  var name = alg.toUpperCase() + '-' + hash.toUpperCase();

  switch (name) {
    case 'ECDSA-SHA1':
      name = 'ecdsa-with-SHA1';
      break;
    case 'ECDSA-SHA256':
      name = 'ecdsa-with-SHA256';
      break;
  }

  return name;
}

/*
 * Expose
 */

exports.rsa = rsa;
exports.ecdsa = ecdsa;
