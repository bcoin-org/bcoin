/*!
 * pk-browser.js - public key algorithms for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var BN = require('bn.js');
var ASN1 = require('../utils/asn1');
var util = require('../utils/util');
var co = require('../utils/co');
var elliptic = require('elliptic');
var backend = require('./backend');
var subtle = backend.subtle;
var dsa, rsa, ecdsa;

/*
 * DSA
 */

dsa = {};

dsa.verify = function verify(alg, msg, sig, key, params) {
  throw new Error('DSA not implemented.');
};

dsa.verifyAsync = util.promisify(dsa.verify);

dsa.sign = function sign(alg, msg, key, params) {
  throw new Error('DSA not implemented.');
};

dsa.signAsync = util.promisify(dsa.sign);

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

  hash = backend.hash(alg, msg);
  len = prefix.length + hash.length;
  pub = ASN1.parseRSAPublic(key);

  N = new BN(pub.modulus);
  e = new BN(pub.publicExponent);
  k = Math.ceil(N.bitLength() / 8);

  if (k < len + 11)
    throw new Error('Message too long.');

  m = rsa.encrypt(N, e, sig);
  em = leftpad(m, k);

  ok = ceq(em[0], 0x00);
  ok &= ceq(em[1], 0x01);
  ok &= backend.ccmp(em.slice(k - hash.length, k), hash);
  ok &= backend.ccmp(em.slice(k - len, k - hash.length), prefix);
  ok &= ceq(em[k - len - 1], 0x00);

  for (i = 2; i < k - len - 1; i++)
    ok &= ceq(em[i], 0xff);

  return ok === 1;
};

rsa.sign = function sign(alg, msg, key) {
  var prefix = rsa.prefixes[alg];
  var hash, len, priv;
  var N, D, k, i, em;

  if (!prefix)
    throw new Error('Unknown PKCS prefix.');

  hash = backend.hash(alg, msg);
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

rsa.verifyAsync = co(function* verifyAsync(alg, msg, sig, key) {
  var use = ['verify'];
  var name = backend.getHash(alg);
  var pub, data, algo, ckey;

  if (!name)
    return rsa.verify(alg, msg, sig, key);

  pub = ASN1.parseRSAPublic(key);

  data = {
    kty: 'RSA',
    n: toBase64(pub.modulus),
    e: toBase64(pub.publicExponent),
    alg: 'RS256',
    ext: true
  };

  algo = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: name }
  };

  ckey = yield subtle.importKey('jwk', data, algo, false, use);

  algo = {
    name: 'RSASSA-PKCS1-v1_5',
  };

  return yield subtle.verify(algo, ckey, sig, msg);
});

if (!subtle.verify)
  rsa.verifyAsync = util.promisify(rsa.verify);

rsa.signAsync = co(function* signAsync(alg, msg, key) {
  var use = ['sign'];
  var name = backend.getHash(alg);
  var pub, data, algo, ckey;

  if (!name)
    return rsa.sign(alg, msg, key);

  pub = ASN1.parseRSAPrivate(key);

  data = {
    kty: 'RSA',
    n: toBase64(pub.modulus),
    e: toBase64(pub.publicExponent),
    d: toBase64(pub.privateExponent),
    p: toBase64(pub.prime1),
    q: toBase64(pub.prime2),
    dp: toBase64(pub.exponent1),
    dq: toBase64(pub.exponent2),
    qi: toBase64(pub.coefficient),
    alg: 'RS256',
    ext: true
  };

  algo = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: { name: name }
  };

  ckey = yield subtle.importKey('jwk', data, algo, false, use);

  algo = {
    name: 'RSASSA-PKCS1-v1_5',
  };

  return yield subtle.sign(algo, ckey, msg);
});

if (!subtle.sign)
  rsa.signAsync = util.promisify(rsa.sign);

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

ecdsa.verify = function verify(curve, alg, msg, key, sig) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = backend.hash(alg, msg);

  return ec.verify(hash, sig, key);
};

ecdsa.sign = function sign(curve, alg, msg, key) {
  var ec, hash;

  assert(curve, 'No curve selected.');

  ec = elliptic.ec(curve);
  hash = backend.hash(alg, msg);

  return new Buffer(ec.sign(hash, key));
};

ecdsa.verifyAsync = co(function* verifyAsync(curve, alg, msg, sig, key) {
  var use = ['verify'];
  var name = backend.getHash(alg);
  var curveName = getCurve(curve);
  var pub, data, algo, ckey;

  if (!name || !curveName)
    return ecdsa.verify(curve, alg, msg, sig, key);

  pub = parseECPublic(key, curve);

  data = {
    kty: 'EC',
    x: toBase64(pub.x),
    y: toBase64(pub.y),
    ext: true
  };

  algo = {
    name: 'ECDSA',
    namedCurve: curveName
  };

  ckey = yield subtle.importKey('jwk', data, algo, false, use);

  algo = {
    name: 'ECDSA',
    hash: name
  };

  return yield subtle.verify(algo, ckey, sig, msg);
});

if (!subtle.verify)
  ecdsa.verifyAsync = util.promisify(ecdsa.verify);

ecdsa.signAsync = co(function* signAsync(curve, alg, msg, key) {
  var use = ['sign'];
  var name = backend.getHash(alg);
  var curveName = getCurve(curve);
  var algo, ckey;

  if (!name || !curveName)
    return ecdsa.sign(curve, alg, msg, key);

  algo = {
    name: 'ECDSA',
    namedCurve: curveName
  };

  ckey = yield subtle.importKey('raw', key, algo, false, use);

  algo = {
    name: 'ECDSA',
    hash: name
  };

  return yield subtle.sign(algo, ckey, msg);
});

if (!subtle.sign)
  ecdsa.signAsync = util.promisify(ecdsa.sign);

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

function toBase64(data) {
  var str = data.toString('base64');
  str = str.replace(/\+/g, '-');
  str = str.replace(/\//g, '_');
  str = str.replace(/=+$/, '');
  return str;
}

function getCurve(name) {
  switch (name) {
    case 'p256':
      return 'P-256';
    case 'p384':
      return 'P-384';
    case 'p521':
      return 'P-521';
    default:
      return null;
  }
}

function parseECPublic(data, curve) {
  var ec = elliptic.ec(curve).curve;
  var point = ec.decodePoint(data);
  return {
    x: point.toArrayLike(Buffer, 'be', 32),
    y: point.toArrayLike(Buffer, 'be', 32)
  };
}

function ceq(a, b) {
  var r = ~(a ^ b) & 0xff;
  r &= r >>> 4;
  r &= r >>> 2;
  r &= r >>> 1;
  return r === 1;
}

/*
 * Expose
 */

exports.dsa = dsa;
exports.rsa = rsa;
exports.ecdsa = ecdsa;
