/*!
 * x509.js - x509 handling for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bn = require('bn.js');
var asn1 = require('./asn1');
var elliptic = require('elliptic');
var utils = require('../utils');

var crypto;

try {
  crypto = require('cryp' + 'to');
} catch (e) {
  ;
}

var pk = exports;
var rsa = {};
var ecdsa = {};
var native = {};

rsa.prefixes = {
  md5: new Buffer('3020300c06082a864886f70d020505000410', 'hex'),
  sha1: new Buffer('3021300906052b0e03021a05000414', 'hex'),
  sha224: new Buffer('302d300d06096086480165030402040500041c', 'hex'),
  sha256: new Buffer('3031300d060960864801650304020105000420', 'hex'),
  sha384: new Buffer('3041300d060960864801650304020205000430', 'hex'),
  sha512: new Buffer('3051300d060960864801650304020305000440', 'hex'),
  md5sha1: new Buffer(0),
  ripemd160: new Buffer('30203008060628cf060300310414', 'hex')
};

// Ported from:
// https://github.com/golang/go/blob/master/src/crypto/rsa/pkcs1v15.go

rsa.verify = function verify(hashAlg, msg, sig, key) {
  var hash = utils.hash(hashAlg, msg);
  var prefix = rsa.prefixes[hashAlg];
  var len = prefix.length + hash.length;
  var pub = asn1.parseRSAPublic(key);
  var N = new bn(pub.modulus);
  var e = new bn(pub.publicExponent);
  var k = Math.ceil(N.bitLength() / 8);
  var m, em, ok, i;

  if (k < len + 11)
    throw new Error('Message too long.');

  m = rsa.encrypt(N, e, sig);
  em = leftpad(m, k);

  ok = ceq(em[0], 0x00);
  ok &= ceq(em[1], 0x01);
  ok &= utils.ccmp(em.slice(k - hash.length, k), hash);
  ok &= utils.ccmp(em.slice(k - len, k - hash.length), prefix);
  ok &= ceq(em[k - len - 1], 0x00);

  for (i = 2; i < k - len - 1; i++)
    ok &= ceq(em[i], 0xff);

  return ok === 1;
};

rsa.sign = function sign(hashAlg, msg, key) {
  var hash = utils.hash(hashAlg, msg);
  var prefix = rsa.prefixes[hashAlg];
  var len = prefix.length + hash.length;
  var priv = asn1.parseRSAPrivate(key);
  var N = new bn(priv.modulus);
  var D = new bn(priv.privateExponent);
  var k = Math.ceil(N.bitLength() / 8);
  var i, em;

  if (k < len + 11)
    throw new Error('Message too long.');

  em = new Buffer(k);
  em.fill(0);

  em[1] = 0x01;
  for (i = 2; i < k - len - 1; i++)
    em[i] = 0xff;

  prefix.copy(em, k - len);
  hash.copy(em, k - hash.length);

  return rsa.decrypt(N, D, em);
};

rsa.decrypt = function decrypt(N, D, m) {
  var c = new bn(m);

  if (c.cmp(N) > 0)
    throw new Error('Cannot decrypt.');

  return c
    .toRed(bn.red(N))
    .redPow(D)
    .fromRed()
    .toArrayLike(Buffer, 'be');
};

rsa.encrypt = function encrypt(N, e, m) {
  return new bn(m)
    .toRed(bn.red(N))
    .redPow(e)
    .fromRed()
    .toArrayLike(Buffer, 'be');
};

ecdsa.verify = function verify(curve, msg, hashAlg, key, sig) {
  var hash = utils.hash(hashAlg, msg);
  var ec = elliptic.ec(curve);
  return ec.verify(hash, sig, key);
};

ecdsa.sign = function sign(curve, msg, hashAlg, key) {
  var hash = utils.hash(hashAlg, msg);
  var ec = elliptic.ec(curve);
  return ec.sign(hash, key);
};

native.verify = function verify(alg, hash, msg, sig, key) {
  var algo, verify;

  if (!crypto)
    return false;

  algo = normalizeAlg(alg, hash);
  verify = crypto.createVerify(algo);
  verify.update(msg);

  return verify.verify(key, sig);
};

native.sign = function _sign(alg, hash, msg, key) {
  var algo, sig;

  if (!crypto)
    return false;

  algo = normalizeAlg(alg, hash);
  sig = crypto.createSign(algo);
  sig.update(msg);
  return sig.sign(key);
};

pk.pemTag = {
  dsa: 'DSA',
  rsa: 'RSA',
  ecdsa: 'EC'
};

pk.toPEM = function toPEM(key, type) {
  var tag = pk.pemTag[key.alg];
  var pem = asn1.toPEM(key.data, tag, type);

  // Key parameters, usually present
  // if selecting an EC curve.
  if (key.params)
    pem += asn1.toPEM(key.params, tag, 'parameters');

  return pem;
};

pk._verify = function verify(hash, msg, sig, key) {
  var pem;
  switch (key.alg) {
    case 'dsa':
      pem = pk.toPEM(key, 'public key');
      return native.verify(key.alg, hash, msg, sig, pem);
    case 'rsa':
      if (crypto) {
        pem = pk.toPEM(key, 'public key');
        return native.verify(key.alg, hash, msg, sig, pem);
      }
      return rsa.verify(hash, msg, sig, key.data);
    case 'ecdsa':
      if (!key.curve)
        throw new Error('No curve present.');
      return ecdsa.verify(key.curve, hash, msg, sig, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
};

pk.verify = function verify(hash, msg, sig, key) {
  try {
    return pk._verify(hash, msg, sig, key);
  } catch (e) {
    return false;
  }
};

pk.sign = function sign(hash, msg, key) {
  var pem;
  switch (key.alg) {
    case 'dsa':
      pem = pk.toPEM(key, 'private key');
      return native.sign(key.alg, hash, msg, pem);
    case 'rsa':
      if (crypto) {
        pem = pk.toPEM(key, 'private key');
        return native.sign(key.alg, hash, msg, pem);
      }
      return rsa.sign(hash, msg, key.data);
    case 'ecdsa':
      if (!key.curve)
        throw new Error('No curve present.');
      return ecdsa.sign(key.curve, hash, msg, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
};

function ceq(a, b) {
  var r = ~(a ^ b) & 0xff;
  r &= r >>> 4;
  r &= r >>> 2;
  r &= r >>> 1;
  return r === 1;
}

function leftpad(input, size) {
  var n = input.length;
  var out;

  if (n > size)
    n = size;

  out = new Buffer(size);
  out.fill(0);

  input.copy(out, out.length - n);

  return out;
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

pk.rsa = rsa;
pk.ecdsa = ecdsa;
pk.native = native;
