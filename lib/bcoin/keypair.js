/*!
 * keypair.js - keypair object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var network = bcoin.protocol.network;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

/**
 * Represents an ecdsa keypair.
 * @exports KeyPair
 * @constructor
 * @param {Object} options
 * @param {Buffer?} options.privateKey
 * @param {Buffer?} options.publicKey
 * @param {Boolean?} options.compressed
 * @param {(Network|NetworkType)?} options.network
 * @property {Buffer} privateKey
 * @property {Buffer} publicKey
 * @property {Boolean} compressed
 * @property {Network} network
 */

function KeyPair(options) {
  if (!(this instanceof KeyPair))
    return new KeyPair(options);

  this.network = bcoin.network.get();
  this.compressed = true;
  this.privateKey = null;
  this.publicKey = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

KeyPair.prototype.fromOptions = function fromOptions(options) {
  if (options.privateKey) {
    return this.fromPrivate(
      options.privateKey,
      options.compressed,
      options.network);
  }

  if (options.publicKey)
    return this.fromPublic(options.publicKey, options.network);

  throw new Error('Must provide a key.');
};

/**
 * Instantiate key pair from options object.
 * @param {Object} options
 * @returns {KeyPair}
 */

KeyPair.fromOptions = function fromOptions(options) {
  return new KeyPair().fromOptions(options);
};

/**
 * Generate a keypair.
 * @param {(Network|NetworkType)?} network
 * @returns {KeyPair}
 */

KeyPair.generate = function(network) {
  var key = new KeyPair();
  key.network = bcoin.network.get(network);
  key.privateKey = bcoin.ec.generatePrivateKey();
  key.publicKey = bcoin.ec.publicKeyCreate(key.privateKey, true);
  return key;
};

/**
 * Inject data from private key.
 * @private
 * @param {Buffer} privateKey
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network}) network
 */

KeyPair.prototype.fromPrivate = function fromPrivate(privateKey, compressed, network) {
  assert(Buffer.isBuffer(privateKey));
  this.network = bcoin.network.get(network);
  this.privateKey = privateKey;
  this.compressed = compressed !== false;
  this.publicKey = bcoin.ec.publicKeyCreate(this.privateKey, this.compressed);
  return this;
};

/**
 * Instantiate key pair from a private key.
 * @param {Buffer} privateKey
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network}) network
 * @returns {KeyPair}
 */

KeyPair.fromPrivate = function fromPrivate(privateKey, compressed, network) {
  return new KeyPair().fromPrivate(privateKey, compressed, network);
};

/**
 * Inject data from public key.
 * @private
 * @param {Buffer} privateKey
 * @param {(NetworkType|Network}) network
 */

KeyPair.prototype.fromPublic = function fromPublic(publicKey, network) {
  assert(Buffer.isBuffer(publicKey));
  this.network = bcoin.network.get(network);
  this.publicKey = publicKey;
  this.compressed = publicKey[0] <= 0x03;
  return this;
};

/**
 * Instantiate key pair from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network}) network
 * @returns {KeyPair}
 */

KeyPair.fromPublic = function fromPublic(publicKey, network) {
  return new KeyPair().fromPublic(publicKey, network);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @returns {Buffer} Signature in DER format.
 */

KeyPair.prototype.sign = function sign(msg) {
  assert(this.privateKey, 'Cannot sign without private key.');
  return bcoin.ec.sign(msg, this.getPrivateKey());
};

/**
 * Verify a message.
 * @param {Buffer} msg
 * @param {Buffer} sig - Signature in DER format.
 * @returns {Boolean}
 */

KeyPair.prototype.verify = function verify(msg, sig) {
  return bcoin.ec.verify(msg, sig, this.getPublicKey());
};

/**
 * Get private key.
 * @param {String?} enc - Can be `"hex"`, `"base58"`, or `null`.
 * @returns {Buffer} Private key.
 */

KeyPair.prototype.getPrivateKey = function getPrivateKey(enc) {
  if (!this.privateKey)
    return;

  if (enc === 'base58')
    return this.toSecret();

  if (enc === 'hex')
    return this.privateKey.toString('hex');

  return this.privateKey;
};

/**
 * Get public key.
 * @param {String?} enc - Can be `"hex"`, or `null`.
 * @returns {Buffer} Public key.
 */

KeyPair.prototype.getPublicKey = function getPublicKey(enc) {
  if (enc === 'base58')
    return utils.toBase58(this.publicKey);

  if (enc === 'hex')
    return this.publicKey.toString('hex');

  return this.publicKey;
};

/**
 * Convert key to a CBitcoinSecret.
 * @param {(Network|NetworkType)?} network
 * @returns {Buffer}
 */

KeyPair.prototype.toRaw = function toRaw(network, writer) {
  var p = new BufferWriter(writer);

  assert(this.privateKey, 'Cannot serialize without private key.');

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);

  p.writeU8(network.keyPrefix.privkey);
  p.writeBytes(this.getPrivateKey());

  if (this.compressed)
    p.writeU8(1);

  p.writeChecksum();

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Convert key to a CBitcoinSecret.
 * @param {(Network|NetworkType)?} network
 * @returns {Base58String}
 */

KeyPair.prototype.toSecret = function toSecret(network) {
  return utils.toBase58(this.toRaw(network));
};

/**
 * Inject properties from serialized CBitcoinSecret.
 * @private
 * @param {Buffer} data
 */

KeyPair.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data, true);
  var i, prefix, version, type, key, compressed;

  version = p.readU8();

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].keyPrefix.privkey;
    if (version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  key = p.readBytes(32);

  if (p.left() > 4) {
    assert(p.readU8() === 1, 'Bad compression flag.');
    compressed = true;
  } else {
    compressed = false;
  }

  p.verifyChecksum();

  assert(bcoin.ec.privateKeyVerify(key));

  return this.fromPrivate(key, compressed, type);
};

/**
 * Inject properties from serialized CBitcoinSecret.
 * @private
 * @param {Base58String} secret
 */

KeyPair.prototype.fromSecret = function fromSecret(secret) {
  return this.fromRaw(utils.fromBase58(secret));
};

/**
 * Instantiate a key pair from a serialized CBitcoinSecret.
 * @param {Buffer} data
 * @returns {KeyPair}
 */

KeyPair.fromRaw = function fromRaw(data) {
  return new KeyPair().fromRaw(data);
};

/**
 * Instantiate a key pair from a serialized CBitcoinSecret.
 * @param {Base58String} secret
 * @returns {KeyPair}
 */

KeyPair.fromSecret = function fromSecret(secret) {
  return new KeyPair().fromSecret(secret);
};

/**
 * Convert the keypair to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

KeyPair.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    compressed: this.compressed,
    privateKey: this.privateKey ? this.toSecret() : null,
    publicKey: this.getPublicKey('base58')
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 */

KeyPair.prototype.fromJSON = function fromJSON(json) {
  var key;

  if (json.privateKey)
    return this.fromSecret(json.privateKey);

  if (json.publicKey) {
    key = utils.fromBase58(json.publicKey);
    assert(bcoin.ec.publicKeyVerify(key));
    return this.fromPublic(key, json.network);
  }

  assert(false, 'Could not parse KeyPair JSON.');
};

/**
 * Instantiate a key pair from a jsonified object.
 * @param {Object} json - The jsonified key pair object.
 * @returns {KeyPair}
 */

KeyPair.fromJSON = function fromJSON(json) {
  return new KeyPair().fromJSON(json);
};

/**
 * Test whether an object is a key pair.
 * @param {Object?} obj
 * @returns {Boolean}
 */

KeyPair.isKeyPair = function isKeyPair(obj) {
  return obj
    && obj.privateKey !== undefined
    && typeof obj.fromSecret === 'function';
};

/*
 * Expose
 */

module.exports = KeyPair;
