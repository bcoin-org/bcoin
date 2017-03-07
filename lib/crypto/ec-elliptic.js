/*!
 * ec.js - ecdsa wrapper for elliptic
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var elliptic = require('elliptic');
var secp256k1 = elliptic.ec('secp256k1');
var Signature = require('elliptic/lib/elliptic/ec/signature');
var curve = secp256k1.curve;
var BN = require('bn.js');

/**
 * @exports crypto/ec-elliptic
 * @ignore
 */

var ec = exports;

/**
 * Whether we're using native bindings.
 * @const {Boolean}
 */

ec.binding = false;

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

ec.generatePrivateKey = function generatePrivateKey() {
  var key = secp256k1.genKeyPair();
  var priv = key.getPrivate().toArrayLike(Buffer, 'be', 32);
  return priv;
};

/**
 * Create a public key from a private key.
 * @param {Buffer} priv
 * @param {Boolean?} compressed
 * @returns {Buffer}
 */

ec.publicKeyCreate = function publicKeyCreate(priv, compressed) {
  var key;

  assert(Buffer.isBuffer(priv));

  key = secp256k1.keyPair({ priv: priv });
  key = key.getPublic(compressed !== false, 'array');

  return new Buffer(key);
};

/**
 * Compress or decompress public key.
 * @param {Buffer} pub
 * @returns {Buffer}
 */

ec.publicKeyConvert = function publicKeyConvert(key, compressed) {
  var point = curve.decodePoint(key);
  return new Buffer(point.encode('array', compressed !== false));
};

/**
 * ((tweak + key) % n)
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @returns {Buffer} privateKey
 */

ec.privateKeyTweakAdd = function privateKeyTweakAdd(privateKey, tweak) {
  var key = new BN(tweak)
    .add(new BN(privateKey))
    .mod(curve.n)
    .toArrayLike(Buffer, 'be', 32);

  // Only a 1 in 2^127 chance of happening.
  if (!ec.privateKeyVerify(key))
    throw new Error('Private key is invalid.');

  return key;
};

/**
 * ((g * tweak) + key)
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @returns {Buffer} publicKey
 */

ec.publicKeyTweakAdd = function publicKeyTweakAdd(publicKey, tweak, compressed) {
  var key = curve.decodePoint(publicKey);
  var point = curve.g.mul(new BN(tweak)).add(key);
  var pub = new Buffer(point.encode('array', compressed !== false));

  if (!ec.publicKeyVerify(pub))
    throw new Error('Public key is invalid.');

  return pub;
};

/**
 * Create an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

ec.ecdh = function ecdh(pub, priv) {
  priv = secp256k1.keyPair({ priv: priv });
  pub = secp256k1.keyPair({ pub: pub });
  return priv.derive(pub.getPublic()).toArrayLike(Buffer, 'be', 32);
};

/**
 * Recover a public key.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Number?} j
 * @param {Boolean?} compressed
 * @returns {Buffer[]|Buffer|null}
 */

ec.recover = function recover(msg, sig, j, compressed) {
  var point, key;

  if (!j)
    j = 0;

  try {
    point = secp256k1.recoverPubKey(msg, sig, j);
  } catch (e) {
    return;
  }

  key = point.encode('array', compressed !== false);

  return new Buffer(key);
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @param {Boolean?} - Whether this should be treated as a
 * "historical" signature. This allows signatures to be of
 * odd lengths.
 * @param {Boolean?} high - Allow high S value.
 * @returns {Boolean}
 */

ec.verify = function verify(msg, sig, key, historical, high) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  if (sig.length === 0)
    return false;

  if (key.length === 0)
    return false;

  // Attempt to normalize the signature
  // length before passing to elliptic.
  // Note: We only do this for historical data!
  // https://github.com/indutny/elliptic/issues/78
  if (historical)
    sig = normalizeLength(sig);

  // Make elliptic mimic secp256k1's
  // failure with high S values.
  if (!high && !ec.isLowS(sig))
    return false;

  try {
    return secp256k1.verify(msg, sig, key);
  } catch (e) {
    return false;
  }
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

ec.publicKeyVerify = function publicKeyVerify(key) {
  try {
    return secp256k1.keyPair({ pub: key }).validate();
  } catch (e) {
    return false;
  }
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

ec.privateKeyVerify = function privateKeyVerify(key) {
  if (key.length !== 32)
    return false;

  key = new BN(key);

  return key.cmpn(0) !== 0 && key.cmp(curve.n) < 0;
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

ec.sign = function sign(msg, key) {
  var sig;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  // Sign message and ensure low S value
  sig = secp256k1.sign(msg, key, { canonical: true });

  // Convert to DER array
  return new Buffer(sig.toDER());
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

ec.fromDER = function fromDER(sig) {
  var out;

  assert(Buffer.isBuffer(sig));

  sig = new Signature(sig);
  out = new Buffer(64);

  sig.r.toArrayLike(Buffer, 'be', 32).copy(out, 0);
  sig.s.toArrayLike(Buffer, 'be', 32).copy(out, 32);

  return out;
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

ec.toDER = function toDER(sig) {
  var out;

  assert(Buffer.isBuffer(sig));

  out = new Signature({
    r: new BN(sig.slice(0, 32), 'be'),
    s: new BN(sig.slice(32, 64), 'be')
  });

  return new Buffer(out.toDER());
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

ec.isLowS = function isLowS(sig) {
  try {
    sig = new Signature(sig);
  } catch (e) {
    return false;
  }

  if (sig.s.cmpn(0) === 0)
    return false;

  // If S is greater than half the order,
  // it's too high.
  if (sig.s.cmp(secp256k1.nh) > 0)
    return false;

  return true;
};

/*
 * Helpers
 */

function normalizeLength(sig) {
  var data = sig;
  var p = { place: 0 };
  var len, rlen, slen;

  if (data[p.place++] !== 0x30)
    return sig;

  len = getLength(data, p);

  if (data.length > len + p.place)
    data = data.slice(0, len + p.place);

  if (data[p.place++] !== 0x02)
    return sig;

  rlen = getLength(data, p);
  p.place += rlen;

  if (data[p.place++] !== 0x02)
    return sig;

  slen = getLength(data, p);
  if (data.length > slen + p.place)
    data = data.slice(0, slen + p.place);

  return data;
}

function getLength(buf, p) {
  var initial = buf[p.place++];
  var octetLen, val, i, off;

  if (!(initial & 0x80))
    return initial;

  octetLen = initial & 0xf;
  val = 0;

  for (i = 0, off = p.place; i < octetLen; i++, off++) {
    val <<= 8;
    val |= buf[off];
  }

  p.place = off;

  return val;
}
