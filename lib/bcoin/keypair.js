/**
 * keypair.js - keypair object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * KeyPair
 */

function KeyPair(options) {
  if (!(this instanceof KeyPair))
    return new KeyPair(options);

  if (!options)
    options = {};

  if (options instanceof KeyPair)
    return options;

  if (options.key instanceof KeyPair)
    return options.key;

  this.options = options;
  this.pair = null;
  this.compressed = options.compressed !== false;

  if (options.key)
    options.pair = options.key;

  if (options.priv)
    options.privateKey = options.priv;

  if (options.pub)
    options.publicKey = options.pub;

  if (options.passphrase)
    options.entropy = utils.sha256(options.passphrase);

  if (options.privateKey instanceof bcoin.hd.privateKey) {
    this.pair = options.privateKey.pair;
  } else if (options.publicKey instanceof bcoin.hd.publicKey) {
    this.pair = options.publicKey.pair;
  } else if (options.pair) {
    assert(options.pair instanceof bcoin.ecdsa.keypair);
    this.pair = options.pair;
  } else if (options.privateKey || options.publicKey) {
    this.pair = bcoin.ecdsa.keyPair({
      priv: options.privateKey,
      pub: options.publicKey
    });
  } else {
    this.pair = bcoin.ecdsa.genKeyPair({
      pers: options.personalization,
      entropy: options.entropy
    });
  }
}

KeyPair.prototype.__defineGetter__('priv', function() {
  return this.pair.getPrivate();
});

KeyPair.prototype.__defineGetter__('pub', function() {
  return this.pair.getPublic();
});

KeyPair.prototype.__defineGetter__('privateKey', function() {
  return this.pair.getPrivate();
});

KeyPair.prototype.__defineGetter__('publicKey', function() {
  return this.pair.getPublic();
});

KeyPair.prototype.getPrivate = function getPrivate(enc) {
  var priv = this.pair.getPrivate();

  if (!priv)
    return;

  priv = priv.toArray();

  if (enc === 'base58')
    return KeyPair.toSecret(priv, this.compressed);

  if (enc === 'hex')
    return utils.toHex(priv);

  return priv;
};

KeyPair.prototype.getPublic = function getPublic(enc) {
  var pub = this.pair.getPublic(this.compressed, 'array');

  if (enc === 'base58')
    return utils.toBase58(pub);

  if (enc === 'hex')
    return utils.toHex(pub);

  return pub;
};

KeyPair.prototype.toSecret = function toSecret() {
  return KeyPair.toSecret(this.getPrivate(), this.compressed);
};

KeyPair.toSecret = function toSecret(priv, compressed) {
  var arr, chk;

  // We'll be using ncompressed public key as an address
  arr = [network.prefixes.privkey];

  // 0-pad key
  while (arr.length + priv.length < 33)
    arr.push(0);

  arr = arr.concat(priv);

  if (compressed !== false)
    arr.push(1);

  chk = utils.checksum(arr);

  return utils.toBase58(arr.concat(chk));
};

KeyPair.fromSecret = function fromSecret(priv) {
  var key, compressed;

  key = utils.fromBase58(priv);
  assert(utils.isEqual(key.slice(-4), utils.checksum(key.slice(0, -4))));
  assert.equal(key[0], network.prefixes.privkey);

  key = key.slice(0, -4);
  if (key.length === 34) {
    assert.equal(key[33], 1);
    priv = key.slice(1, -1);
    compressed = true;
  } else {
    priv = key.slice(1);
    compressed = false;
  }

  return new KeyPair({
    privateKey: priv,
    compressed: compressed
  });
};

KeyPair.prototype.toJSON = function toJSON(encrypt) {
  var json = {
    v: 1,
    name: 'keypair',
    encrypted: encrypt ? true : false
  };

  if (this.pair.priv) {
    json.priv = encrypt
      ? encrypt(this.getPrivate('base58'))
      : this.getPrivate('base58');
    return json;
  }

  json.pub = this.getPublic('hex');
  return json;
};

KeyPair.fromJSON = function fromJSON(json, decrypt) {
  var key, priv, pub, compressed, xprivkey;
  var path = {};

  assert.equal(json.v, 1);
  assert.equal(json.name, 'keypair');

  if (json.encrypted && !decrypt)
    throw new Error('Cannot decrypt address');

  if (json.priv) {
    priv = json.priv;
    if (json.encrypted)
      priv = decrypt(priv);

    key = KeyPair.fromSecret(json.priv);
    priv = key.priv;
    compressed = key.compressed;
    return new KeyPair({
      privateKey: priv,
      compressed: compressed
    });
  }

  if (json.pub) {
    pub = bcoin.utils.toArray(json.pub, 'hex');
    compressed = pub[0] !== 0x04;
    return new KeyPair({
      publicKey: pub,
      compressed: compressed
    });
  }

  assert(false);
};

/**
 * Expose
 */

module.exports = KeyPair;
