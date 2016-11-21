/*!
 * pk.js - public key algorithms for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var PEM = require('../utils/pem');
var elliptic = require('elliptic');
var util = require('../utils/util');
var backend = require('./backend');
var nodeCrypto = require('crypto');
var dsa, rsa, ecdsa;

/*
 * DSA
 */

dsa = {};

dsa.verify = function _verify(alg, msg, sig, key, params) {
  var pem = toPEM('dsa', key, params, 'public key');
  return verify('dsa', alg, msg, sig, pem);
};

dsa.sign = function _sign(alg, msg, key, params) {
  var pem = toPEM('dsa', key, params, 'private key');
  return sign('dsa', alg, msg, pem);
};

dsa.verifyAsync = util.promisify(dsa.verify);
dsa.signAsync = util.promisify(dsa.sign);

/*
 * RSA
 */

rsa = {};

rsa.verify = function _verify(alg, msg, sig, key) {
  var pem = toPEM('rsa', key, null, 'public key');
  return verify('rsa', alg, msg, sig, pem);
};

rsa.sign = function _sign(alg, msg, key) {
  var pem = toPEM('rsa', key, null, 'private key');
  return sign('rsa', alg, msg, pem);
};

rsa.verifyAsync = util.promisify(rsa.verify);
rsa.signAsync = util.promisify(rsa.sign);

/*
 * ECDSA
 */

ecdsa = {};

ecdsa.verify = function verify(curve, msg, alg, key, sig) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = backend.hash(alg, msg);

  return ec.verify(hash, sig, key);
};

ecdsa.sign = function sign(curve, msg, alg, key) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = backend.hash(alg, msg);

  return new Buffer(ec.sign(hash, key));
};

ecdsa.verifyAsync = util.promisify(ecdsa.verify);
ecdsa.signAsync = util.promisify(ecdsa.sign);

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
    case 'dsa':
      tag = 'DSA';
      break;
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

exports.dsa = dsa;
exports.rsa = rsa;
exports.ecdsa = ecdsa;
