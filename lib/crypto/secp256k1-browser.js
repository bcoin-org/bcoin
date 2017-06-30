/*!
 * secp256k1-elliptic.js - wrapper for elliptic
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const elliptic = require('elliptic');
const secp256k1 = elliptic.ec('secp256k1');
const Signature = require('elliptic/lib/elliptic/ec/signature');
const BN = require('./bn');
const curve = secp256k1.curve;

/**
 * @exports crypto/secp256k1-elliptic
 * @ignore
 */

const ec = exports;

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
  let key = secp256k1.genKeyPair();
  return key.getPrivate().toArrayLike(Buffer, 'be', 32);
};

/**
 * Create a public key from a private key.
 * @param {Buffer} priv
 * @param {Boolean?} compress
 * @returns {Buffer}
 */

ec.publicKeyCreate = function publicKeyCreate(priv, compress) {
  let key;

  assert(Buffer.isBuffer(priv));

  if (compress == null)
    compress = true;

  key = secp256k1.keyPair({ priv: priv });

  return Buffer.from(key.getPublic(compress, 'array'));
};

/**
 * Compress or decompress public key.
 * @param {Buffer} pub
 * @returns {Buffer}
 */

ec.publicKeyConvert = function publicKeyConvert(key, compress) {
  let point = curve.decodePoint(key);

  if (compress == null)
    compress = true;

  return Buffer.from(point.encode('array', compress));
};

/**
 * ((tweak + key) % n)
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @returns {Buffer} privateKey
 */

ec.privateKeyTweakAdd = function privateKeyTweakAdd(privateKey, tweak) {
  let key = new BN(tweak)
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

ec.publicKeyTweakAdd = function publicKeyTweakAdd(publicKey, tweak, compress) {
  let key = curve.decodePoint(publicKey);
  let point = curve.g.mul(new BN(tweak)).add(key);
  let pub;

  if (compress == null)
    compress = true;

  pub = Buffer.from(point.encode('array', compress));

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
 * @param {Boolean?} compress
 * @returns {Buffer[]|Buffer|null}
 */

ec.recover = function recover(msg, sig, j, compress) {
  let point;

  if (!j)
    j = 0;

  if (compress == null)
    compress = true;

  try {
    point = secp256k1.recoverPubKey(msg, sig, j);
  } catch (e) {
    return;
  }

  return Buffer.from(point.encode('array', compress));
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ec.verify = function verify(msg, sig, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(Buffer.isBuffer(key));

  if (sig.length === 0)
    return false;

  if (key.length === 0)
    return false;

  // Attempt to normalize the signature
  // length before passing to elliptic.
  // https://github.com/indutny/elliptic/issues/78
  sig = normalizeLength(sig);

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
  let sig;

  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  // Sign message and ensure low S value
  sig = secp256k1.sign(msg, key, { canonical: true });

  // Convert to DER
  return Buffer.from(sig.toDER());
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} sig
 * @returns {Buffer} R/S-formatted signature.
 */

ec.fromDER = function fromDER(sig) {
  let out;

  assert(Buffer.isBuffer(sig));

  sig = new Signature(sig);
  out = Buffer.allocUnsafe(64);

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
  let out;

  assert(Buffer.isBuffer(sig));

  out = new Signature({
    r: new BN(sig.slice(0, 32), 'be'),
    s: new BN(sig.slice(32, 64), 'be')
  });

  return Buffer.from(out.toDER());
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
  let data = sig;
  let p = { place: 0 };
  let len, rlen, slen;

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
  let initial = buf[p.place++];
  let len = initial & 0xf;
  let off = p.place;
  let val = 0;

  if (!(initial & 0x80))
    return initial;

  for (let i = 0; i < len; i++, off++) {
    val <<= 8;
    val |= buf[off];
  }

  p.place = off;

  return val;
}
