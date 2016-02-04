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

  if (options instanceof bcoin.ecdsa.keypair)
    options = { pair: options };

  if (options.key)
    options.pair = options.key;

  if (options.priv)
    options.privateKey = options.priv;

  if (options.pub)
    options.publicKey = options.pub;

  if (options.key instanceof KeyPair)
    return options.key;

  this.options = options;
  this.pair = null;
  this.compressed = options.compressed !== false;

  if (options.passphrase)
    options.entropy = utils.sha256(options.passphrase);

  if (options.privateKey instanceof bcoin.hd.privateKey) {
    this.pair = options.privateKey.pair;
  } else if (options.publicKey instanceof bcoin.hd.publicKey) {
    this.pair = options.publicKey.pair;
  } else if (options.pair instanceof bcoin.hd.privateKey) {
    this.pair = options.pair.pair;
  } else if (options.pair instanceof bcoin.hd.publicKey) {
    this.pair = options.pair.pair;
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
  return this.pair.priv;
});

KeyPair.prototype.__defineGetter__('pub', function() {
  return this.pair.pub;
});

KeyPair.prototype.__defineGetter__('privateKey', function() {
  return this.getPrivateKey();
});

KeyPair.prototype.__defineGetter__('publicKey', function() {
  return this.getPublicKey();
});

KeyPair.prototype.validate = function validate() {
  return this.pair.validate.apply(this.pair, arguments);
};

KeyPair.prototype.sign = function sign(msg) {
  return this.pair.sign.apply(this.pair, arguments);
};

KeyPair.prototype.verify = function verify(msg, signature) {
  return this.pair.verify.apply(this.pair, arguments);
};

KeyPair.prototype.getPrivate =
KeyPair.prototype.getPrivateKey = function getPrivateKey(enc) {
  var privateKey = this.pair.getPrivate();

  if (!privateKey)
    return;

  privateKey = privateKey.toArray();

  if (enc === 'base58')
    return KeyPair.toSecret(privateKey, this.compressed);

  if (enc === 'hex')
    return utils.toHex(privateKey);

  return privateKey;
};

KeyPair.prototype.getPublic =
KeyPair.prototype.getPublicKey = function getPublicKey(enc) {
  var publicKey = this.pair.getPublic(this.compressed, 'array');

  if (enc === 'base58')
    return utils.toBase58(publicKey);

  if (enc === 'hex')
    return utils.toHex(publicKey);

  return publicKey;
};

KeyPair.prototype.toSecret = function toSecret() {
  return KeyPair.toSecret(this.getPrivate(), this.compressed);
};

KeyPair.toSecret = function toSecret(privateKey, compressed) {
  var arr, chk;

  // We'll be using ncompressed public key as an address
  arr = [network.prefixes.privkey];

  // 0-pad key
  while (arr.length + privateKey.length < 33)
    arr.push(0);

  arr = arr.concat(privateKey);

  if (compressed !== false)
    arr.push(1);

  chk = utils.checksum(arr);

  return utils.toBase58(arr.concat(chk));
};

KeyPair.fromSecret = function fromSecret(privateKey) {
  var key, compressed;

  key = utils.fromBase58(privateKey);
  assert(utils.isEqual(key.slice(-4), utils.checksum(key.slice(0, -4))));
  assert.equal(key[0], network.prefixes.privkey);

  key = key.slice(0, -4);
  if (key.length === 34) {
    assert.equal(key[33], 1);
    privateKey = key.slice(1, -1);
    compressed = true;
  } else {
    privateKey = key.slice(1);
    compressed = false;
  }

  return new KeyPair({
    privateKey: privateKey,
    compressed: compressed
  });
};

KeyPair.verify = function verify(msg, sig, key) {
  try {
    return bcoin.ecdsa.verify(msg, sig, key);
  } catch (e) {
    return false;
  }
};

KeyPair.sign = function sign(msg, key) {
  return bcoin.ecdsa.sign(msg, key.priv);
};

KeyPair.prototype.toJSON = function toJSON(encrypt) {
  var json = {
    v: 1,
    name: 'keypair',
    encrypted: encrypt ? true : false
  };

  if (this.pair.priv) {
    json.privateKey = encrypt
      ? encrypt(this.toSecret())
      : this.toSecret();
    return json;
  }

  json.publicKey = this.getPublicKey('base58');

  return json;
};

KeyPair.fromJSON = function fromJSON(json, decrypt) {
  var privateKey, publicKey, compressed;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'keypair');

  if (json.encrypted && !decrypt)
    throw new Error('Cannot decrypt address');

  if (json.privateKey) {
    privateKey = json.privateKey;
    if (json.encrypted)
      privateKey = decrypt(privateKey);
    return KeyPair.fromSecret(privateKey);
  }

  if (json.publicKey) {
    publicKey = utils.fromBase58(json.publicKey);
    compressed = publicKey[0] !== 0x04;
    return new KeyPair({
      publicKey: publicKey,
      compressed: compressed
    });
  }

  assert(false);
};

/**
 * Expose
 */

module.exports = KeyPair;
