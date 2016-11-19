/*!
 * pk-browser.js - public key algorithms for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var BN = require('bn.js');
var ASN1 = require('../utils/asn1');
var elliptic = require('elliptic');
var crypto = require('../crypto/crypto');
var dsa, rsa, ecdsa;

/*
 * DSA
 */

dsa = {};

dsa.verify = function verify(alg, msg, sig, key, params) {
  throw new Error('DSA not implemented.');
};

dsa.sign = function sign(alg, msg, key, params) {
  throw new Error('DSA not implemented.');
};

/*
 * RSA
 */

rsa = {};

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

rsa.verify = function verify(alg, msg, sig, key) {
  var prefix = rsa.prefixes[alg];
  var hash, len, pub;
  var N, e, k, m, em, ok, i;

  if (!prefix)
    throw new Error('Unknown PKCS prefix.');

  hash = crypto.hash(alg, msg);
  len = prefix.length + hash.length;
  pub = ASN1.parseRSAPublic(key);

  N = new BN(pub.modulus);
  e = new BN(pub.publicExponent);
  k = Math.ceil(N.bitLength() / 8);

  if (k < len + 11)
    throw new Error('Message too long.');

  m = rsa.encrypt(N, e, sig);
  em = leftpad(m, k);

  ok = crypto.ceq(em[0], 0x00);
  ok &= crypto.ceq(em[1], 0x01);
  ok &= crypto.ccmp(em.slice(k - hash.length, k), hash);
  ok &= crypto.ccmp(em.slice(k - len, k - hash.length), prefix);
  ok &= crypto.ceq(em[k - len - 1], 0x00);

  for (i = 2; i < k - len - 1; i++)
    ok &= crypto.ceq(em[i], 0xff);

  return ok === 1;
};

rsa.sign = function sign(alg, msg, key) {
  var prefix = rsa.prefixes[alg];
  var hash, len, priv;
  var N, D, k, i, em;

  if (!prefix)
    throw new Error('Unknown PKCS prefix.');

  hash = crypto.hash(alg, msg);
  len = prefix.length + hash.length;
  priv = ASN1.parseRSAPrivate(key);

  N = new BN(priv.modulus);
  D = new BN(priv.privateExponent);
  k = Math.ceil(N.bitLength() / 8);

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
  var c = new BN(m);

  if (c.cmp(N) > 0)
    throw new Error('Cannot decrypt.');

  return c
    .toRed(BN.red(N))
    .redPow(D)
    .fromRed()
    .toArrayLike(Buffer, 'be');
};

rsa.encrypt = function encrypt(N, e, m) {
  return new BN(m)
    .toRed(BN.red(N))
    .redPow(e)
    .fromRed()
    .toArrayLike(Buffer, 'be');
};

/*
 * ECDSA
 */

ecdsa = {};

ecdsa.verify = function verify(curve, msg, alg, key, sig) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = crypto.hash(alg, msg);

  return ec.verify(hash, sig, key);
};

ecdsa.sign = function sign(curve, msg, alg, key) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = crypto.hash(alg, msg);

  return new Buffer(ec.sign(hash, key));
};

/*
 * Helpers
 */

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

/*
 * Expose
 */

exports.dsa = dsa;
exports.rsa = rsa;
exports.ecdsa = ecdsa;
