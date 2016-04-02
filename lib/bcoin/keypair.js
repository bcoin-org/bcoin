/**
 * keypair.js - keypair object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var network = bcoin.protocol.network;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

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
  this._publicKey = options.publicKey;
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

KeyPair.prototype.__defineGetter__('publicKey', function() {
  if (!this._publicKey) {
    if (!this.privateKey)
      return;

    this._publicKey = bcoin.ec.publicKeyCreate(
      this.privateKey, this.compressed
    );
  }

  return this._publicKey;
});

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
  var p = new BufferWriter();

  p.writeU8(network.prefixes.privkey);
  p.writeBytes(privateKey);

  if (compressed !== false)
    p.writeU8(1);

  p.writeChecksum();

  return utils.toBase58(p.render());
};

KeyPair._fromSecret = function _fromSecret(secret) {
  var data = utils.fromBase58(secret);
  var p = new BufferReader(data, true);
  var compressed = false;
  var privateKey;

  assert(p.readU8() === network.prefixes.privkey, 'Bad network.');

  privateKey = p.readBytes(32);

  if (p.left() > 1) {
    assert(p.readU8() === 1);
    compressed = true;
  }

  p.verifyChecksum();

  return {
    privateKey: privateKey,
    compressed: compressed
  };
};

KeyPair.fromSecret = function fromSecret(secret) {
  return new KeyPair(KeyPair._fromSecret(secret));
};

KeyPair.prototype.toJSON = function toJSON(passphrase) {
  var json = {
    v: 1,
    name: 'keypair',
    encrypted: passphrase ? true : false
  };

  if (this.key.privateKey) {
    json.privateKey = passphrase
      ? utils.encrypt(this.toSecret(), passphrase)
      : this.toSecret();
    return json;
  }

  json.publicKey = this.getPublicKey('base58');

  return json;
};

KeyPair._fromJSON = function _fromJSON(json, passphrase) {
  var privateKey, publicKey;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'keypair');

  if (json.encrypted && !passphrase)
    throw new Error('Cannot decrypt key.');

  if (json.privateKey) {
    privateKey = json.privateKey;
    if (json.encrypted)
      privateKey = utils.decrypt(privateKey, passphrase);
    return KeyPair._fromSecret(privateKey);
  }

  if (json.publicKey) {
    publicKey = utils.fromBase58(json.publicKey);
    return {
      publicKey: publicKey,
      compressed: publicKey[0] !== 0x04
    };
  }

  assert(false, 'Could not parse KeyPair JSON.');
};

KeyPair.fromJSON = function fromJSON(json, passphrase) {
  return new KeyPair(KeyPair._fromJSON(json, passphrase));
};

/**
 * Expose
 */

module.exports = KeyPair;
