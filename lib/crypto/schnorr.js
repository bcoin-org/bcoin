/*!
 * schnorr.js - schnorr signatures for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var BN = require('bn.js');
var elliptic = require('elliptic');
var Signature = require('elliptic/lib/elliptic/ec/signature');
var hmacDRBG = require('elliptic/lib/elliptic/hmac-drbg');
var sha256 = require('./backend').sha256;
var secp256k1 = elliptic.ec('secp256k1');
var curve = secp256k1.curve;
var curves = elliptic.curves;
var hash = curves.secp256k1.hash;

/**
 * @exports crypto/schnorr
 */

var schnorr = exports;

/**
 * Hash (r | M).
 * @param {Buffer} msg
 * @param {BN} r
 * @param {Function?} hash
 * @returns {Buffer}
 */

schnorr.hash = function _hash(msg, r, hash) {
  var R = r.toArrayLike(Buffer, 'be', 32);
  var B = new Buffer(64);
  var H;

  if (!hash)
    hash = sha256;

  R.copy(B, 0);
  msg.copy(B, 32);
  H = hash(B);

  return new BN(H);
};

/**
 * Sign message.
 * @private
 * @param {Buffer} msg
 * @param {BN} priv
 * @param {BN} k
 * @param {Function|null} hash
 * @param {Buffer} pubnonce
 * @returns {Signature|null}
 */

schnorr._sign = function _sign(msg, prv, k, hash, pubnonce) {
  var r, pn, h, s;

  if (k.cmpn(0) === 0)
    return;

  if (k.cmp(curve.n) >= 0)
    return;

  r = curve.g.mul(k);

  if (pubnonce) {
    pn = curve.decodePoint(pubnonce);
    r = r.add(pn);
  }

  if (r.y.isOdd()) {
    k = k.umod(curve.n);
    k = curve.n.sub(k);
  }

  h = schnorr.hash(msg, r.getX(), hash);

  if (h.cmpn(0) === 0)
    return;

  if (h.cmp(curve.n) >= 0)
    return;

  s = h.imul(prv);
  s = k.isub(s);
  s = s.umod(curve.n);

  if (s.cmpn(0) === 0)
    return;

  return new Signature({ r: r.getX(), s: s });
};

/**
 * Sign message.
 * @param {Buffer} msg
 * @param {Buffer} key
 * @param {Function?} hash
 * @param {Buffer} pubnonce
 * @returns {Signature}
 */

schnorr.sign = function sign(msg, key, hash, pubnonce) {
  var prv = new BN(key);
  var k, sig, drbg;

  if (prv.cmpn(0) === 0)
    throw new Error('Bad private key.');

  if (prv.cmp(curve.n) >= 0)
    throw new Error('Bad private key.');

  drbg = schnorr.drbg(msg, key, pubnonce);

  while (!sig) {
    k = new BN(drbg.generate(curve.n.byteLength()));
    sig = schnorr._sign(msg, prv, k, hash, pubnonce);
  }

  return sig;
};

/**
 * Verify signature.
 * @param {Buffer} msg
 * @param {Buffer} signature
 * @param {Buffer} key
 * @param {Function?} hash
 * @returns {Buffer}
 */

schnorr.verify = function verify(msg, signature, key, hash) {
  var sig = new Signature(signature);
  var h = schnorr.hash(msg, sig.r, hash);
  var k, l, r, rl;

  if (h.cmp(curve.n) >= 0)
    throw new Error('Invalid hash.');

  if (h.cmpn(0) === 0)
    throw new Error('Invalid hash.');

  if (sig.s.cmp(curve.n) >= 0)
    throw new Error('Invalid S value.');

  if (sig.r.cmp(curve.p) > 0)
    throw new Error('Invalid R value.');

  k = curve.decodePoint(key);
  l = k.mul(h);
  r = curve.g.mul(sig.s);
  rl = l.add(r);

  if (rl.y.isOdd())
    throw new Error('Odd R value.');

  return rl.getX().cmp(sig.r) === 0;
};

/**
 * Recover public key.
 * @param {Buffer} msg
 * @param {Buffer} signature
 * @param {Function?} hash
 * @returns {Buffer}
 */

schnorr.recover = function recover(signature, msg, hash) {
  var sig = new Signature(signature);
  var h = schnorr.hash(msg, sig.r, hash);
  var hinv, s, R, l, r, k, rl;

  if (h.cmp(curve.n) >= 0)
    throw new Error('Invalid hash.');

  if (h.cmpn(0) === 0)
    throw new Error('Invalid hash.');

  if (sig.s.cmp(curve.n) >= 0)
    throw new Error('Invalid S value.');

  if (sig.r.cmp(curve.p) > 0)
    throw new Error('Invalid R value.');

  hinv = h.invm(curve.n);
  hinv = hinv.umod(curve.n);

  s = sig.s;
  s = curve.n.sub(s);
  s = s.umod(curve.n);

  s = s.imul(hinv);
  s = s.umod(curve.n);

  R = curve.pointFromX(sig.r, false);
  l = R.mul(hinv);
  r = curve.g.mul(s);
  k = l.add(r);

  l = k.mul(h);
  r = curve.g.mul(sig.s);
  rl = l.add(r);

  if (rl.y.isOdd())
    throw new Error('Odd R value.');

  if (rl.getX().cmp(sig.r) !== 0)
    throw new Error('Could not recover pubkey.');

  return new Buffer(k.encode('array', true));
};

/**
 * Combine signatures.
 * @param {Buffer[]} sigs
 * @returns {Signature}
 */

schnorr.combineSigs = function combineSigs(sigs) {
  var s = new BN(0);
  var i, r, sig, last;

  for (i = 0; i < sigs.length; i++) {
    sig = new Signature(sigs[i]);

    if (sig.s.cmpn(0) === 0)
      throw new Error('Bad S value.');

    if (sig.s.cmp(curve.n) >= 0)
      throw new Error('Bad S value.');

    if (!r)
      r = sig.r;

    if (last && last.r.cmp(sig.r) !== 0)
      throw new Error('Bad signature combination.');

    s = s.iadd(sig.s);
    s = s.umod(curve.n);

    last = sig;
  }

  if (s.cmpn(0) === 0)
    throw new Error('Bad combined signature.');

  return new Signature({ r: r, s: s });
};

/**
 * Combine public keys.
 * @param {Buffer[]} keys
 * @returns {Buffer}
 */

schnorr.combineKeys = function combineKeys(keys) {
  var i, key, point;

  if (keys.length === 0)
    throw new Error();

  if (keys.length === 1)
    return keys[0];

  point = curve.decodePoint(keys[0]);

  for (i = 1; i < keys.length; i++) {
    key = curve.decodePoint(keys[i]);
    point = point.add(key);
  }

  return new Buffer(point.encode('array', true));
};

/**
 * Partially sign.
 * @param {Buffer} msg
 * @param {Buffer} priv
 * @param {Buffer} privnonce
 * @param {Buffer} pubs
 * @param {Function?} hash
 * @returns {Buffer}
 */

schnorr.partialSign = function partialSign(msg, priv, privnonce, pubs, hash) {
  var prv = new BN(priv);
  var sig;

  if (prv.cmpn(0) === 0)
    throw new Error('Bad private key.');

  if (prv.cmp(curve.n) >= 0)
    throw new Error('Bad private key.');

  sig = schnorr._sign(msg, prv, new BN(privnonce), hash, pubs);

  if (!sig)
    throw new Error('Bad K value.');

  return sig;
};

/**
 * Schnorr personalization string.
 * @const {Buffer}
 */

schnorr.alg = new Buffer('Schnorr+SHA256  ', 'ascii');

/**
 * Instantiate an HMAC-DRBG.
 * @param {Buffer} msg
 * @param {Buffer} priv
 * @param {Buffer} data
 * @returns {HmacDRBG}
 */

schnorr.drbg = function drbg(msg, priv, data) {
  var kdata = new Buffer(112);
  var prv, pers;

  kdata.fill(0);

  priv.copy(kdata, 0);
  msg.copy(kdata, 32);

  if (data)
    data.copy(kdata, 64);

  schnorr.alg.copy(kdata, 96);

  prv = toArray(kdata.slice(0, 32));
  msg = toArray(kdata.slice(32, 64));
  pers = toArray(kdata.slice(64));

  return new hmacDRBG({
    hash: hash,
    entropy: prv,
    nonce: msg,
    pers: pers
  });
};

/**
 * Perform hmac drbg according to rfc6979.
 * @param {Buffer} msg
 * @param {Buffer} priv
 * @param {Buffer} data
 * @returns {Buffer}
 */

schnorr.rfc6979 = function rfc6979(msg, priv, data) {
  var drbg = schnorr.drbg(msg, priv, data);
  var bytes = drbg.generate(curve.n.byteLength());
  return new Buffer(bytes);
};

/**
 * Create a schnorr nonce with a nonce callback.
 * @param {Buffer} msg
 * @param {Buffer} priv
 * @param {Buffer} data
 * @param {Function?} ncb
 * @returns {BN}
 */

schnorr.nonce = function nonce(msg, priv, data, ncb) {
  var pubnonce;

  if (!ncb)
    ncb = schnorr.rfc6979;

  pubnonce = ncb(msg, priv, data);

  return new BN(pubnonce);
};

/**
 * Generate pub+priv nonce pair.
 * @param {Buffer} msg
 * @param {Buffer} priv
 * @param {Buffer} data
 * @param {Function?} ncb
 * @returns {Buffer}
 */

schnorr.generateNoncePair = function generateNoncePair(msg, priv, data, ncb) {
  var k = schnorr.nonce(priv, msg, data, ncb);

  if (k.cmpn(0) === 0)
    throw new Error('Bad nonce.');

  if (k.cmp(curve.n) >= 0)
    throw new Error('Bad nonce.');

  return new Buffer(curve.g.mul(k).encode('array', true));
};

/*
 * Helpers
 */

function toArray(obj) {
  return Array.prototype.slice.call(obj);
}
