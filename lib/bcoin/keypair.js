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

  if (options.pair instanceof KeyPair)
    return options.pair;

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
    this.pair = bcoin.ec.generate({
      pers: options.personalization,
      entropy: options.entropy
    });
  }
}

KeyPair.prototype.__defineGetter__('privatePoint', function() {
  return this.pair.getPrivate();
});

KeyPair.prototype.__defineGetter__('publicPoint', function() {
  return this.pair.getPublic();
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

KeyPair.prototype.getPrivateKey = function getPrivateKey(enc) {
  var privateKey;

  if (!this._privateKey) {
    privateKey = this.pair.getPrivate();

    if (!privateKey)
      return;

    privateKey = new Buffer(privateKey.toArray('be', 32));

    this._privateKey = privateKey;
  }

  privateKey = this._privateKey;

  if (enc === 'base58')
    return KeyPair.toSecret(privateKey, this.compressed);

  if (enc === 'hex')
    return utils.toHex(privateKey);

  return privateKey;
};

KeyPair.prototype.getPublicKey = function getPublicKey(enc) {
  var publicKey;

  if (!this._publicKey)
    this._publicKey = new Buffer(this.pair.getPublic(this.compressed, 'array'));

  publicKey = this._publicKey;

  if (enc === 'base58')
    return utils.toBase58(publicKey);

  if (enc === 'hex')
    return utils.toHex(publicKey);

  return publicKey;
};

KeyPair.prototype.toSecret = function toSecret() {
  return KeyPair.toSecret(this.getPrivateKey(), this.compressed);
};

KeyPair.toSecret = function toSecret(privateKey, compressed) {
  var buf = new Buffer(1 + privateKey.length + (compressed ? 1 : 0) + 4);
  var off = 0;
  var chk;

  off += utils.writeU8(buf, network.prefixes.privkey, 0);
  off += utils.copy(privateKey, buf, off);

  if (compressed !== false)
    off += utils.writeU8(buf, 1, off);

  utils.copy(utils.checksum(buf.slice(0, off)), buf, off);

  return utils.toBase58(buf);
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
    return bcoin.ec.verify(msg, sig, key);
  } catch (e) {
    return false;
  }
};

KeyPair.sign = function sign(msg, key) {
  return bcoin.ec.sign(msg, key.priv);
};

KeyPair.prototype.toJSON = function toJSON(passphrase) {
  var json = {
    v: 1,
    name: 'keypair',
    encrypted: passphrase ? true : false
  };

  if (this.pair.priv) {
    json.privateKey = passphrase
      ? utils.encrypt(this.toSecret(), passphrase)
      : this.toSecret();
    return json;
  }

  json.publicKey = this.getPublicKey('base58');

  return json;
};

KeyPair.fromJSON = function fromJSON(json, passphrase) {
  var privateKey, publicKey, compressed;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'keypair');

  if (json.encrypted && !passphrase)
    throw new Error('Cannot decrypt address');

  if (json.privateKey) {
    privateKey = json.privateKey;
    if (json.encrypted)
      privateKey = utils.decrypt(privateKey, passphrase);
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
