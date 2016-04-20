/*!
 * ec.js - ecdsa wrapper for secp256k1 and elliptic
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var elliptic = require('elliptic');
var utils = require('./utils');
var assert = utils.assert;
var crypto, secp256k1;

if (!utils.isBrowser)
  crypto = require('cry' + 'pto');

try {
  secp256k1 = require('secp' + '256k1');
} catch (e) {
  ;
}

/**
 * @exports ec
 */

var ec = exports;

/**
 * elliptic.js secp256k1 curve.
 * @type {Object}
 */

ec.elliptic = elliptic.ec('secp256k1');

/**
 * elliptic.js signature constructor.
 * @static
 */

ec.signature = require('elliptic/lib/elliptic/ec/signature');

/**
 * elliptic.js keypair constructor.
 * @static
 */

ec.keypair = require('elliptic/lib/elliptic/ec/key');

/**
 * Generate a private key.
 * @returns {Buffer} Private key.
 */

ec.generatePrivateKey = function generatePrivateKey() {
  var key, priv;

  if (secp256k1 && crypto) {
    do {
      priv = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(priv));
  } else {
    key = ec.elliptic.genKeyPair();
    priv = key.getPrivate().toBuffer('be', 32);
  }

  return priv;
};

/**
 * Create a public key from a private key.
 * @param {Buffer} priv
 * @param {Boolean?} compressed
 * @returns {Buffer}
 */

ec.publicKeyCreate = function publicKeyCreate(priv, compressed) {
  assert(Buffer.isBuffer(priv));

  if (secp256k1)
    return secp256k1.publicKeyCreate(priv, compressed);

  priv = ec.elliptic.keyPair({ priv: priv }).getPublic(compressed, 'array');
  return new Buffer(priv);
};

/**
 * Generate some random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

ec.random = function random(size) {
  if (crypto)
    return crypto.randomBytes(size);
  return new Buffer(ec.elliptic.rand(size));
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
  if (!Buffer.isBuffer(sig))
    return false;

  if (sig.length === 0)
    return false;

  if (key.getPublicKey)
    key = key.getPublicKey();

  if (key.length === 0)
    return false;

  // Attempt to normalize the signature
  // length before passing to elliptic.
  // Note: We only do this for historical data!
  // https://github.com/indutny/elliptic/issues/78
  if (historical)
    sig = ec.normalizeLength(sig);

  try {
    if (secp256k1) {
      // secp256k1 fails on high s values. This is
      // bad for verifying historical data.
      if (high)
        sig = ec.toLowS(sig);

      // Import from DER.
      sig = secp256k1.signatureImport(sig);

      return secp256k1.verify(msg, sig, key);
    }
    // Make elliptic mimic secp256k1's
    // failure with high S values.
    if (!high && !ec.isLowS(sig))
      return false;
    return ec.elliptic.verify(msg, sig, key);
  } catch (e) {
    // if (!ec.publicKeyVerify(key))
    //   bcoin.debug('Public key is invalid.');
    return false;
  }
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

ec.publicKeyVerify = function publicKeyVerify(key) {
  if (secp256k1)
    return secp256k1.publicKeyVerify(key);
  return ec.elliptic.keyPair({ pub: key }).validate();
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} DER-formatted signature.
 */

ec.sign = function sign(msg, key) {
  var sig;

  if (key.getPrivateKey)
    key = key.getPrivateKey();

  if (secp256k1) {
    // Sign message
    sig = secp256k1.sign(msg, key);

    // Ensure low S value
    sig = secp256k1.signatureNormalize(sig.signature);

    // Convert to DER array
    sig = secp256k1.signatureExport(sig);
  } else {
    // Sign message and ensure low S value
    sig = ec.elliptic.sign(msg, key, { canonical: true });

    // Convert to DER array
    sig = new Buffer(sig.toDER());
  }

  return sig;
};

/**
 * Normalize the length of a signature
 * (only done for historical data).
 * @param {Buffer} sig - DER formatted signature.
 * @returns {Buffer} Signature.
 */

ec.normalizeLength = function normalizeLength(sig) {
  var data, p, len, rlen, slen;

  data = sig.slice();
  p = { place: 0 };

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
};

function getLength(buf, p) {
  var initial = buf[p.place++];
  if (!(initial & 0x80)) {
    return initial;
  }
  var octetLen = initial & 0xf;
  var val = 0;
  for (var i = 0, off = p.place; i < octetLen; i++, off++) {
    val <<= 8;
    val |= buf[off];
  }
  p.place = off;
  return val;
}

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

ec.isLowS = function isLowS(sig) {
  if (!sig.s) {
    assert(Buffer.isBuffer(sig));

    try {
      sig = new ec.signature(sig);
    } catch (e) {
      return false;
    }
  }

  // Technically a negative S value is low,
  // but we don't want to ever use negative
  // S values in bitcoin.
  if (sig.s.cmpn(0) <= 0)
    return false;

  // If S is greater than half the order,
  // it's too high.
  if (sig.s.cmp(ec.elliptic.nh) > 0)
    return false;

  return true;
};

/**
 * Lower the S value of a signature (used
 * for verifying historical data).
 * @param {Buffer} sig - DER formatted.
 * @returns {Buffer}
 */

ec.toLowS = function toLowS(sig) {
  if (!sig.s) {
    assert(Buffer.isBuffer(sig));

    try {
      sig = new ec.signature(sig);
    } catch (e) {
      return sig;
    }
  }

  // If S is greater than half the order,
  // it's too high.
  if (sig.s.cmp(ec.elliptic.nh) > 0)
    sig.s = ec.elliptic.n.sub(sig.s);

  return new Buffer(sig.toDER());
};
