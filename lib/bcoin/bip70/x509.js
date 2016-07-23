/*!
 * x509.js - x509 handling for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var crypto = require('crypto');
var asn1 = require('./asn1');
var utils = require('../utils');
var x509 = exports;

x509.certs = [];
x509.trusted = {};

x509.getTrusted = function getTrusted(cert) {
  var hash;

  if (!Buffer.isBuffer(cert))
    cert = cert.raw;

  hash = utils.hash256(cert).toString('hex');

  return x509.trusted[hash];
};

x509.setTrust = function setTrust(certs) {
  var keys = Object.keys(certs);
  var i, key, cert, hash, pem;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    cert = certs[key];

    if (typeof cert === 'string') {
      pem = asn1.fromPEM(cert);
      assert(pem.type === 'certificate', 'Must add certificates to trust.');
      cert = pem.data;
    }

    assert(Buffer.isBuffer(cert), 'Certificates must be PEM or DER.');

    hash = utils.hash256(cert).toString('hex');

    cert = {
      name: key,
      fingerprint: hash,
      cert: asn1.parseCert(cert)
    };

    x509.certs.push(cert);
    x509.trusted[hash] = cert;
  }
};

/*
 * https://www.ietf.org/rfc/rfc2459.txt
 * https://tools.ietf.org/html/rfc3279
 * http://oid-info.com/get/1.2.840.10040.4
 * http://oid-info.com/get/1.2.840.113549.1.1
 * http://oid-info.com/get/1.2.840.10045.4.3
 */

x509.oid = {
  '1.2.840.10040.4.1'    : { key: 'dsa',   hash: null     },
  '1.2.840.10040.4.2'    : { key: 'dsa',   hash: null     },
  '1.2.840.10040.4.3'    : { key: 'dsa',   hash: 'sha1'   },
  '1.2.840.113549.1.1.1' : { key: 'rsa',   hash: null     },
  '1.2.840.113549.1.1.2' : { key: 'rsa',   hash: 'md2'    },
  '1.2.840.113549.1.1.3' : { key: 'rsa',   hash: 'md4'    },
  '1.2.840.113549.1.1.4' : { key: 'rsa',   hash: 'md5'    },
  '1.2.840.113549.1.1.5' : { key: 'rsa',   hash: 'sha1'   },
  '1.2.840.113549.1.1.11': { key: 'rsa',   hash: 'sha256' },
  '1.2.840.113549.1.1.12': { key: 'rsa',   hash: 'sha384' },
  '1.2.840.113549.1.1.13': { key: 'rsa',   hash: 'sha512' },
  '1.2.840.113549.1.1.14': { key: 'rsa',   hash: 'sha224' },
  '1.2.840.10045.2.1'    : { key: 'ecdsa', hash: null     },
  '1.2.840.10045.4.1'    : { key: 'ecdsa', hash: 'sha1'   },
  '1.2.840.10045.4.3.1'  : { key: 'ecdsa', hash: 'sha224' },
  '1.2.840.10045.4.3.2'  : { key: 'ecdsa', hash: 'sha256' },
  '1.2.840.10045.4.3.3'  : { key: 'ecdsa', hash: 'sha384' },
  '1.2.840.10045.4.3.4'  : { key: 'ecdsa', hash: 'sha512' }
};

x509.getKeyAlgorithm = function getKeyAlgorithm(cert) {
  var alg = cert.tbs.pubkey.alg.alg;
  return x509.oid[alg];
};

x509.getSigAlgorithm = function getSigAlgorithm(cert) {
  var alg = cert.sigAlg.alg;
  return x509.oid[alg];
};

x509.parse = function parse(der) {
  try {
    return asn1.parseCert(der);
  } catch (e) {
    ;
  }
};

x509.getPublicKey = function getPublicKey(cert) {
  var alg = x509.getKeyAlgorithm(cert);
  var key, params, pem;

  if (!alg)
    return;

  key = cert.tbs.pubkey.pubkey;
  params = cert.tbs.pubkey.alg.params;

  pem = asn1.toPEM(key, alg.key + ' PUBLIC KEY');

  if (params)
    pem += asn1.toPEM(params, alg.key + ' PARAMETERS');

  return pem;
};

x509.verifyTime = function verifyTime(cert) {
  var time = cert.tbs.validity;
  var now = Math.floor(Date.now() / 1000);
  return now > time.notBefore && now < time.notAfter;
};

x509.signSubject = function signSubject(hash, msg, key, chain) {
  var cert, alg;

  assert(chain.length !== 0, 'No chain available.');

  cert = x509.parse(chain[0]);
  assert(cert, 'Could not parse certificate.');

  alg = x509.getKeyAlgorithm(cert);
  assert(alg, 'Certificate uses an unknown algorithm.');

  if (Buffer.isBuffer(key))
    key = asn1.toPEM(key, alg.key + ' PRIVATE KEY');

  return x509.sign(alg.key, hash, msg, key);
};

x509.verifySubject = function verifySubject(hash, msg, sig, chain) {
  var cert, key, alg;

  if (chain.length === 0)
    return false;

  cert = x509.parse(chain[0]);

  if (!cert)
    return false;

  key = x509.getPublicKey(cert);

  if (!key)
    return false;

  alg = x509.getKeyAlgorithm(cert);

  if (!alg)
    return false;

  return x509.verify(alg.key, hash, msg, sig, key);
};

x509.verifyChain = function verifyChain(chain, ignoreTime) {
  var i, child, parent, alg, key, sig, msg;

  if (chain.length < 2)
    return false;

  for (i = 1; i < chain.length; i++) {
    child = chain[i - 1];
    parent = chain[i];

    child = x509.parse(child);

    if (!child)
      return false;

    parent = x509.parse(parent);

    if (!parent)
      return false;

    if (!ignoreTime) {
      if (!x509.verifyTime(child))
        return false;

      if (!x509.verifyTime(parent))
        return false;
    }

    alg = x509.getSigAlgorithm(child);

    if (!alg || !alg.hash)
      return false;

    key = x509.getPublicKey(parent);

    if (!key)
      return false;

    sig = child.sig;
    msg = child.tbs.raw;

    if (!x509.verify(alg.key, alg.hash, msg, sig, key))
      return false;

    if (x509.getTrusted(parent))
      return true;
  }

  if (exports.certs.length === 0)
    return true;

  return false;
};

x509.verify = function verify(alg, hash, msg, sig, key) {
  var algo = alg.toUpperCase() + '-' + hash.toUpperCase();
  var verify;

  try {
    verify = crypto.createVerify(algo);
    verify.update(msg);
    return verify.verify(key, sig);
  } catch (e) {
    return false;
  }
};

x509.sign = function sign(alg, hash, msg, key) {
  var algo = alg.toUpperCase() + '-' + hash.toUpperCase();
  var sig = crypto.createSign(algo);
  sig.update(msg);
  return sig.sign(key);
};

x509.asn1 = asn1;
