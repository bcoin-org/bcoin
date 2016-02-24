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

  this.options = options;
  this.key = null;
  this.compressed = options.compressed !== false;

  if (!options.privateKey && !options.publicKey)
    throw new Error('No options for keypair');

  assert(!options.privateKey || Buffer.isBuffer(options.privateKey));
  assert(!options.publicKey || Buffer.isBuffer(options.publicKey));

  this.privateKey = options.privateKey;
  this.publicKey = options.publicKey;
}

KeyPair.generate = function() {
  return new KeyPair({ privateKey: bcoin.ec.generatePrivateKey() });
};

KeyPair.prototype.sign = function sign(msg) {
  return bcoin.ec.sign(msg, this.getPrivateKey());
};

KeyPair.prototype.verify = function verify(msg, sig) {
  return bcoin.ec.verify(msg, sig, this.getPublicKey());
};

KeyPair.prototype.getPrivateKey = function getPrivateKey(enc) {
  if (!this.privateKey)
    return;

  if (enc === 'base58')
    return this.toSecret();

  if (enc === 'hex')
    return utils.toHex(this.privateKey);

  return this.privateKey;
};

KeyPair.prototype.getPublicKey = function getPublicKey(enc) {
  if (!this.publicKey) {
    if (!this.privateKey)
      return;

    this.publicKey = bcoin.ec.publicKeyCreate(
      this.privateKey, this.compressed
    );
  }

  if (enc === 'base58')
    return utils.toBase58(this.publicKey);

  if (enc === 'hex')
    return utils.toHex(this.publicKey);

  return this.publicKey;
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

KeyPair._fromSecret = function _fromSecret(privateKey) {
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

  return {
    privateKey: privateKey,
    compressed: compressed
  };
};

KeyPair.fromSecret = function fromSecret(privateKey) {
  return new KeyPair(KeyPair._fromSecret(privateKey));
};

KeyPair.prototype.toJSON = function toJSON(passphrase) {
  var json = {
    v: 1,
    name: 'keypair',
    encrypted: passphrase ? true : false
  };

  if (this.key.priv) {
    json.privateKey = passphrase
      ? utils.encrypt(this.toSecret(), passphrase)
      : this.toSecret();
    return json;
  }

  json.publicKey = this.getPublicKey('base58');

  return json;
};

KeyPair._fromJSON = function _fromJSON(json, passphrase) {
  var privateKey, publicKey, compressed;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'keypair');

  if (json.encrypted && !passphrase)
    throw new Error('Cannot decrypt address');

  if (json.privateKey) {
    privateKey = json.privateKey;
    if (json.encrypted)
      privateKey = utils.decrypt(privateKey, passphrase);
    return KeyPair._fromSecret(privateKey);
  }

  if (json.publicKey) {
    publicKey = utils.fromBase58(json.publicKey);
    compressed = publicKey[0] !== 0x04;
    return {
      publicKey: publicKey,
      compressed: compressed
    };
  }

  assert(false);
};

KeyPair.fromJSON = function fromJSON(json, passphrase) {
  return new KeyPair(KeyPair._fromJSON(json, passphrase));
};

/**
 * Expose
 */

module.exports = KeyPair;
