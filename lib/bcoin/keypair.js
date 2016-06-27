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
 * @property {Buffer?} privateKey
 * @property {Buffer} publicKey
 */

function KeyPair(options) {
  if (!(this instanceof KeyPair))
    return new KeyPair(options);

  this.network = null;
  this.compressed = true;
  this.privateKey = null;
  this._publicKey = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

KeyPair.prototype.fromOptions = function fromOptions(options) {
  if (!options)
    options = {};

  this.compressed = options.compressed !== false;
  this.network = bcoin.network.get(options.network);

  if (!options.privateKey && !options.publicKey)
    throw new Error('No options for keypair');

  assert(!options.privateKey || Buffer.isBuffer(options.privateKey));
  assert(!options.publicKey || Buffer.isBuffer(options.publicKey));

  this.privateKey = options.privateKey;
  this._publicKey = options.publicKey;

  return this;
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
  return key;
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @returns {Buffer} Signature in DER format.
 */

KeyPair.prototype.sign = function sign(msg) {
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

  if (!network)
    network = this.network;

  network = bcoin.network.get(network);

  p.writeU8(network.prefixes.privkey);
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
  var i, prefix, version, type;

  version = p.readU8();

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.privkey;
    if (version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  this.network = bcoin.network.get(type);
  this.privateKey = p.readBytes(32);

  if (p.left() > 4) {
    assert(p.readU8() === 1, 'Bad compression flag.');
    this.compressed = true;
  }

  p.verifyChecksum();

  return this;
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
  this.network = bcoin.network.get(json.network);
  this.compressed = json.compressed;

  if (json.privateKey)
    return this.fromSecret(json.privateKey);

  if (json.publicKey) {
    this.publicKey = utils.fromBase58(json.publicKey);
    this.compressed = this.publicKey[0] !== 0x04;
    return this;
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
    && obj._privateKey !== undefined
    && typeof obj.fromSecret === 'function';
};

/*
 * Expose
 */

module.exports = KeyPair;
