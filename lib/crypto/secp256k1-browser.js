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
  const key = secp256k1.genKeyPair();
  return key.getPrivate().toBuffer('be', 32);
};

/**
 * Create a public key from a private key.
 * @param {Buffer} priv
 * @param {Boolean?} compress
 * @returns {Buffer}
 */

ec.publicKeyCreate = function publicKeyCreate(priv, compress) {
  assert(Buffer.isBuffer(priv));

  if (compress == null)
    compress = true;

  const key = secp256k1.keyPair({ priv: priv });

  return Buffer.from(key.getPublic(compress, 'array'));
};

/**
 * Compress or decompress public key.
 * @param {Buffer} pub
 * @returns {Buffer}
 */

ec.publicKeyConvert = function publicKeyConvert(key, compress) {
  const point = curve.decodePoint(key);

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
  const key = new BN(tweak)
    .add(new BN(privateKey))
    .mod(curve.n)
    .toBuffer('be', 32);

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
  const key = curve.decodePoint(publicKey);
  const point = curve.g.mul(new BN(tweak)).add(key);

  if (compress == null)
    compress = true;

  const pub = Buffer.from(point.encode('array', compress));

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
  return priv.derive(pub.getPublic()).toBuffer('be', 32);
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
  if (!j)
    j = 0;

  if (compress == null)
    compress = true;

  let point;
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
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(key));

  // Sign message and ensure low S value
  const sig = secp256k1.sign(msg, key, { canonical: true });

  // Convert to DER
  return Buffer.from(sig.toDER());
};

/**
 * Convert DER signature to R/S.
 * @param {Buffer} raw
 * @returns {Buffer} R/S-formatted signature.
 */

ec.fromDER = function fromDER(raw) {
  assert(Buffer.isBuffer(raw));

  const sig = new Signature(raw);
  const out = Buffer.allocUnsafe(64);

  sig.r.toBuffer('be', 32).copy(out, 0);
  sig.s.toBuffer('be', 32).copy(out, 32);

  return out;
};

/**
 * Convert R/S signature to DER.
 * @param {Buffer} sig
 * @returns {Buffer} DER-formatted signature.
 */

ec.toDER = function toDER(raw) {
  assert(Buffer.isBuffer(raw));

  const sig = new Signature({
    r: new BN(raw.slice(0, 32), 'be'),
    s: new BN(raw.slice(32, 64), 'be')
  });

  return Buffer.from(sig.toDER());
};

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

ec.isLowS = function isLowS(raw) {
  let sig;
  try {
    sig = new Signature(raw);
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
  const p = { place: 0 };

  if (data[p.place++] !== 0x30)
    return sig;

  const len = getLength(data, p);

  if (data.length > len + p.place)
    data = data.slice(0, len + p.place);

  if (data[p.place++] !== 0x02)
    return sig;

  const rlen = getLength(data, p);
  p.place += rlen;

  if (data[p.place++] !== 0x02)
    return sig;

  const slen = getLength(data, p);
  if (data.length > slen + p.place)
    data = data.slice(0, slen + p.place);

  return data;
}

function getLength(buf, p) {
  const initial = buf[p.place++];
  const len = initial & 0xf;
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
