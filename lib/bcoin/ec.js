/**
 * ec.js - ecdsa wrapper for secp256k1 and elliptic
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var elliptic = require('elliptic');
var utils = require('./utils');
var assert = utils.assert;
var ec = exports;
var crypto, secp256k1;

if (!bcoin.isBrowser)
  crypto = require('cry' + 'pto');

try {
  secp256k1 = require('secp' + '256k1');
} catch (e) {
  ;
}

ec.elliptic = elliptic.ec('secp256k1');
ec.signature = require('elliptic/lib/elliptic/ec/signature');
ec.keypair = require('elliptic/lib/elliptic/ec/key');

/**
 * EC
 */

ec.generatePrivateKey = function generatePrivateKey() {
  var key, priv;

  if (secp256k1 && crypto) {
    do {
      priv = crypto.randomBytes(32);
    } while (!secp256k1.privateKeyVerify(priv));
  } else {
    key = ec.elliptic.genKeyPair();
    priv = new Buffer(key.getPrivate().toArray('be', 32));
  }

  return priv;
};

ec.publicKeyCreate = function publicKeyCreate(priv, compressed) {
  assert(Buffer.isBuffer(priv));

  if (secp256k1)
    return secp256k1.publicKeyCreate(priv, compressed);

  priv = ec.elliptic.keyPair({ priv: priv }).getPublic(compressed, 'array');
  return new Buffer(priv);
};

ec.random = function random(size) {
  if (crypto)
    return crypto.randomBytes(size);
  return new Buffer(elliptic.rand(size));
};

ec.verify = function verify(msg, sig, key, historical) {
  if (!Buffer.isBuffer(sig))
    return false;

  if (sig.length === 0)
    return false;

  if (key.getPublicKey)
    key = key.getPublicKey();

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
      if (historical)
        sig = ec.toLowS(sig);

      // Import from DER.
      sig = secp256k1.signatureImport(sig);

      // This is supposed to lower the S value
      // but it doesn't seem to work.
      // if (historical)
      //   sig = bcoin.secp256k1.signatureNormalize(sig);

      return secp256k1.verify(msg, sig, key);
    }
    return ec.elliptic.verify(msg, sig, key);
  } catch (e) {
    utils.debug('Elliptic threw during verification:');
    utils.debug(e.stack + '');
    utils.debug({
      msg: utils.toHex(msg),
      sig: utils.toHex(sig),
      key: utils.toHex(key)
    });
    return false;
  }
};

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
