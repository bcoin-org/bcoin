/*!
 * ec.js - ecdsa wrapper for secp256k1 and elliptic
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var elliptic = require('elliptic');
var bn = require('bn.js');
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
    priv = key.getPrivate().toArrayLike(Buffer, 'be', 32);
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
 * Decode a point.
 * @param {Buffer} key
 * @returns {elliptic.Point}
 */

ec.decodePoint = function decodePoint(key) {
  var hybrid, point;

  if (key[0] === 0x06 || key[0] === 0x07) {
    hybrid = key[0];
    key[0] = 0x04;
  }

  point = ec.elliptic.curve.decodePoint(key);

  if (hybrid != null)
    key[0] = hybrid;

  return point;
};

/**
 * Compress or decompress public key.
 * @param {Buffer} pub
 * @returns {Buffer}
 */

ec.publicKeyConvert = function(key, compressed) {
  var point;

  if (secp256k1)
    return secp256k1.publicKeyConvert(key, compressed);

  switch (key[0]) {
    case 0x02:
    case 0x03:
      if (compressed)
        return key;
      point = ec.decodePoint(key);
      return new Buffer(point.encode('array', false));
    case 0x04:
    case 0x06:
    case 0x07:
      if (compressed) {
        point = ec.decodePoint(key);
        return new Buffer(point.encode('array', true));
      }
      return key;
    default:
      throw new Error('Bad point format.');
  }
};

/**
 * Compress a public key to coins compression format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ec.compress = function compress(key) {
  var out;

  // We can't compress it if it's not valid.
  if (!ec.publicKeyVerify(key))
    return;

  switch (key[0]) {
    case 0x02:
    case 0x03:
      // Key is already compressed.
      out = key;
      break;
    case 0x04:
    case 0x06:
    case 0x07:
      // Compress the key normally.
      out = ec.publicKeyConvert(key, true);
      // Store the original format (which
      // may be a hybrid byte) in the hi
      // 3 bits so we can restore it later.
      // The hi bits being set also lets us
      // know that this key was originally
      // decompressed.
      out[0] |= key[0] << 2;
      break;
    default:
      throw new Error('Bad point format.');
  }

  assert(out.length === 33);

  return out;
};

/**
 * Decompress a public key from the coins compression format.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ec.decompress = function decompress(key) {
  var format = key[0] >>> 2;
  var out;

  assert(key.length === 33);

  // Hi bits are not set. This key
  // is not meant to be decompressed.
  if (format === 0)
    return key;

  // Decompress the key, and off the
  // low bits so publicKeyConvert
  // actually understands it.
  key[0] &= 0x03;
  out = ec.publicKeyConvert(key, false);

  // Reset the hi bits so as not to
  // mutate the original buffer.
  key[0] |= format << 2;

  // Set the original format, which
  // may have been a hybrid prefix byte.
  out[0] = format;

  return out;
};

/**
 * Create an ecdh.
 * @param {Buffer} pub
 * @param {Buffer} priv
 * @returns {Buffer}
 */

ec.ecdh = function ecdh(pub, priv) {
  if (secp256k1)
    return secp256k1.ecdh(pub, priv);

  priv = ec.elliptic.keyPair({ priv: priv });
  pub = ec.elliptic.keyPair({ pub: pub });

  return priv.derive(pub.getPublic()).toArrayLike(Buffer, 'be', 32);
};

/**
 * Generate some random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

ec.random = function random(size) {
  if (crypto)
    return crypto.randomBytes(size);
  return new Buffer(elliptic.rand(size));
};

/**
 * Generate a random number within a range.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

ec.rand = function rand(min, max) {
  var num = ec.random(4).readUInt32LE(0, true);
  return Math.floor((num / 0x100000000) * (max - min) + min);
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
  var hybrid, result;

  if (key.getPublicKey)
    key = key.getPublicKey();

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
    sig = ec.normalizeLength(sig);

  if (secp256k1) {
    // secp256k1 fails on high s values. This is
    // bad for verifying historical data.
    if (high)
      sig = ec.toLowS(sig);

    try {
      // Import from DER.
      sig = secp256k1.signatureImport(sig);
      result = secp256k1.verify(msg, sig, key);
    } catch (e) {
      result = false;
    }

    return result;
  }

  // Make elliptic mimic secp256k1's
  // failure with high S values.
  if (!high && !ec.isLowS(sig))
    return false;

  // Elliptic does not support
  // openssl's "hybrid" keys yet.
  if (key[0] === 0x06 || key[0] === 0x07) {
    hybrid = key[0];
    key[0] = 0x04;
  }

  try {
    result = ec.elliptic.verify(msg, sig, key);
  } catch (e) {
    result = false;
  }

  // Reset the byte if we need to.
  if (hybrid != null)
    key[0] = hybrid;

  return result;
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

ec.publicKeyVerify = function publicKeyVerify(key) {
  var result, hybrid;

  if (secp256k1)
    return secp256k1.publicKeyVerify(key);

  if (key[0] === 0x06 || key[0] === 0x07) {
    hybrid = key[0];
    key[0] = 0x04;
  }

  try {
    result = ec.elliptic.keyPair({ pub: key }).validate();
  } catch (e) {
    result = false;
  }

  if (hybrid != null)
    key[0] = hybrid;

  return result;
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

ec.privateKeyVerify = function privateKeyVerify(key) {
  if (secp256k1)
    return secp256k1.privateKeyVerify(key);

  key = new bn(key);

  return key.cmpn(0) !== 0 && key.cmp(ec.elliptic.curve.n) < 0;
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
};

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

/**
 * Test whether a signature has a low S value.
 * @param {Buffer} sig
 * @returns {Boolean}
 */

ec.isLowS = function isLowS(sig) {
  if (Buffer.isBuffer(sig)) {
    try {
      sig = new ec.signature(sig);
    } catch (e) {
      return false;
    }
  }

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
  if (Buffer.isBuffer(sig)) {
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
