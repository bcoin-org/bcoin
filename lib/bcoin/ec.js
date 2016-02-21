/**
 * ec.js - ecdsa wrapper for secp256k1 and elliptic
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;
var assert = utils.assert;
var ec = exports;

/**
 * EC
 */

ec.generate = function generate(options) {
  var priv, pub;

  if (bcoin.secp256k1 && bcoin.crypto) {
    do {
      priv = bcoin.crypto.randomBytes(32);
    } while (!bcoin.secp256k1.privateKeyVerify(priv));
    pub = bcoin.secp256k1.publicKeyCreate(priv, true);
    priv = utils.toArray(priv);
    pub = utils.toArray(pub);
    return bcoin.ecdsa.keyPair({ priv: priv, pub: pub });
  }

  return bcoin.ecdsa.genKeyPair(options);
};

ec.verify = function verify(msg, sig, key, historical) {
  if (key.getPublic)
    key = key.getPublic(true, 'array');

  if (!utils.isBuffer(sig))
    return false;

  if (sig.length === 0)
    return false;

  // Attempt to normalize the signature
  // length before passing to elliptic.
  // Note: We only do this for historical data!
  // https://github.com/indutny/elliptic/issues/78
  if (historical)
    sig = bcoin.ec.normalizeLength(sig);

  try {
    if (bcoin.secp256k1) {
      // secp256k1 fails on low s values. This is
      // bad for verifying historical data.
      if (historical)
        sig = bcoin.ec.toLowS(sig);

      msg = new Buffer(msg);
      sig = new Buffer(sig);
      key = new Buffer(key)

      // Import from DER.
      sig = bcoin.secp256k1.signatureImport(sig);

      // This is supposed to lower the S value
      // but it doesn't seem to work.
      // if (historical)
      //   sig = bcoin.secp256k1.signatureNormalize(sig);

      return bcoin.secp256k1.verify(msg, sig, key);
    }
    return bcoin.ecdsa.verify(msg, sig, key);
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

  if (bcoin.secp256k1) {
    msg = new Buffer(msg);
    key = new Buffer(key.getPrivate().toArray('be', 32));

    // Sign message
    sig = bcoin.secp256k1.sign(msg, key);

    // Ensure low S value
    sig = bcoin.secp256k1.signatureNormalize(sig.signature);

    // Convert to DER array
    sig = bcoin.secp256k1.signatureExport(sig);

    sig = utils.toArray(sig);
  } else {
    // Sign message and ensure low S value
    sig = bcoin.ecdsa.sign(msg, key.priv, { canonical: true });

    // Convert to DER array
    sig = sig.toDER();
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
    if (!utils.isBuffer(sig))
      return false;

    try {
      sig = new bcoin.ecdsa.signature(sig);
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
  if (sig.s.cmp(bcoin.ecdsa.nh) > 0)
    return false;

  return true;
};

ec.toLowS = function toLowS(sig) {
  if (!sig.s) {
    assert(utils.isBuffer(sig));

    try {
      sig = new bcoin.ecdsa.signature(sig);
    } catch (e) {
      return sig;
    }
  }

  // If S is greater than half the order,
  // it's too high.
  if (sig.s.cmp(bcoin.ecdsa.nh) > 0)
    sig.s = bcoin.ecdsa.n.sub(sig.s);

  return sig.toDER();
};
