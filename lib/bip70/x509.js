/*!
 * x509.js - x509 handling for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var asn1 = require('./asn1');
var utils = require('../utils/utils');
var crypto = require('../crypto/crypto');
var pk = require('./pk');
var x509 = exports;

x509.getSubjectOID = function getSubjectOID(cert, oid) {
  var subject = cert.tbs.subject;
  var i, entry;

  for (i = 0; i < subject.length; i++) {
    entry = subject[i];
    if (entry.type === oid)
      return entry.value;
  }
};

x509.getCAName = function getCAName(cert) {
  // This seems to work the best in practice
  // for getting a human-readable and
  // descriptive name for the CA.
  // See:
  //   http://oid-info.com/get/2.5.4
  // Precedence:
  //   (3) commonName
  //   (11) organizationUnitName
  //   (10) organizationName
  return x509.getSubjectOID(cert, '2.5.4.3')
    || x509.getSubjectOID(cert, '2.5.4.11')
    || x509.getSubjectOID(cert, '2.5.4.10')
    || 'Unknown';
};

x509.trusted = {};
x509.allowUntrusted = false;

x509.isTrusted = function isTrusted(cert) {
  var fingerprint = crypto.sha256(cert.raw);
  var hash = fingerprint.toString('hex');
  return x509.trusted[hash] === true;
};

x509.setTrust = function setTrust(certs) {
  var i, cert, pem, hash;

  if (!Array.isArray(certs))
    certs = [certs];

  for (i = 0; i < certs.length; i++) {
    cert = certs[i];

    if (isHash(cert)) {
      if (!Buffer.isBuffer(cert))
        cert = new Buffer(cert, 'hex');

      hash = cert.toString('hex');
      x509.trusted[hash] = true;

      continue;
    }

    if (typeof cert === 'string') {
      pem = asn1.fromPEM(cert);
      assert(pem.type === 'certificate', 'Must add certificates to trust.');
      cert = pem.data;
    }

    assert(Buffer.isBuffer(cert), 'Certificates must be PEM or DER.');

    cert = x509.parse(cert);
    assert(cert, 'Could not parse certificate.');

    hash = crypto.sha256(cert.raw).toString('hex');
    x509.trusted[hash] = true;
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

x509.curves = {
  '1.3.132.0.33': 'p224',
  '1.2.840.10045.3.1.7': 'p256',
  '1.3.132.0.34': 'p384',
  '1.3.132.0.35': 'p521'
};

x509.getKeyAlgorithm = function getKeyAlgorithm(cert) {
  var alg = cert.tbs.pubkey.alg.alg;
  return x509.oid[alg];
};

x509.getSigAlgorithm = function getSigAlgorithm(cert) {
  var alg = cert.sigAlg.alg;
  return x509.oid[alg];
};

x509.getCurve = function getCurve(params) {
  var oid;

  if (!params)
    return;

  try {
    oid = asn1.parseOID(params);
  } catch (e) {
    return;
  }

  return x509.curves[oid];
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
  var key, params, curve;

  if (!alg)
    return;

  key = cert.tbs.pubkey.pubkey;
  params = cert.tbs.pubkey.alg.params;

  if (alg.key === 'ecdsa')
    curve = x509.getCurve(params);

  return {
    alg: alg.key,
    data: key,
    params: params,
    curve: curve
  };
};

x509.verifyTime = function verifyTime(cert) {
  var time = cert.tbs.validity;
  var now = Math.floor(Date.now() / 1000);
  return now > time.notBefore && now < time.notAfter;
};

x509.signSubject = function signSubject(hash, msg, key, chain) {
  var cert, pub, curve;

  assert(chain.length !== 0, 'No chain available.');

  cert = x509.parse(chain[0]);
  assert(cert, 'Could not parse certificate.');

  if (typeof key === 'string') {
    key = asn1.fromPEM(key);
    if (key.alg === 'ecdsa')
      curve = x509.getCurve(key.params);
    key = {
      alg: key.alg,
      data: key.data,
      params: key.params,
      curve: curve
    };
  } else {
    pub = x509.getPublicKey(cert);
    assert(pub, 'Certificate uses an unknown algorithm.');
    key = {
      alg: pub.alg,
      data: key,
      params: pub.params,
      curve: pub.curve
    };
  }

  return pk.sign(hash, msg, key);
};

x509.verifySubject = function verifySubject(hash, msg, sig, chain) {
  var cert, key;

  if (chain.length === 0)
    return false;

  cert = x509.parse(chain[0]);

  if (!cert)
    return false;

  key = x509.getPublicKey(cert);

  if (!key)
    return false;

  return pk.verify(hash, msg, sig, key);
};

x509.verifyChain = function verifyChain(chain) {
  var i, child, parent, alg, key, sig, msg;

  chain = chain.slice();

  // Parse certificates and
  // check validity time.
  for (i = 0; i < chain.length; i++) {
    child = x509.parse(chain[i]);

    if (!child)
      return false;

    chain[i] = child;

    if (!x509.verifyTime(child))
      return false;
  }

  // Verify signatures.
  for (i = 1; i < chain.length; i++) {
    child = chain[i - 1];
    parent = chain[i];

    alg = x509.getSigAlgorithm(child);
    msg = child.tbs.raw;
    sig = child.sig;
    key = x509.getPublicKey(parent);

    if (!alg || !alg.hash)
      return false;

    if (!key)
      return false;

    if (!pk.verify(alg.hash, msg, sig, key))
      return false;
  }

  // If trust hasn't been
  // setup, just return.
  if (x509.allowUntrusted)
    return true;

  // Make sure we trust one
  // of the certs in the chain.
  for (i = 0; i < chain.length; i++) {
    child = chain[i];

    // If any certificate in the chain
    // is trusted, assume we also trust
    // the parent.
    if (x509.isTrusted(child))
      return true;
  }

  // No trusted certs present.
  return false;
};

x509.asn1 = asn1;

function isHash(data) {
  if (typeof data === 'string')
    return utils.isHex(data) && data.length === 64;

  if (Buffer.isBuffer(data))
    return data.length === 32;

  return false;
}

x509.setTrust(require('../../etc/certs.json'));
