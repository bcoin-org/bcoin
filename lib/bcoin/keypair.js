/*!
 * keypair.js - keypair object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

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

  if (!options)
    options = {};

  this.options = options;
  this.key = null;
  this.compressed = options.compressed !== false;
  this.network = bcoin.network.get(options.network);

  if (!options.privateKey && !options.publicKey)
    throw new Error('No options for keypair');

  assert(!options.privateKey || Buffer.isBuffer(options.privateKey));
  assert(!options.publicKey || Buffer.isBuffer(options.publicKey));

  this.privateKey = options.privateKey;
  this._publicKey = options.publicKey;
}

/**
 * Generate a keypair.
 * @returns {KeyPair}
 */

KeyPair.generate = function() {
  return new KeyPair({ privateKey: bcoin.ec.generatePrivateKey() });
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
 * @returns {Base58String}
 */

KeyPair.prototype.toSecret = function toSecret() {
  return KeyPair.toSecret(this.getPrivateKey(), this.compressed, this.network);
};

/**
 * Convert key to a CBitcoinSecret.
 * @param {Buffer} privateKey
 * @param {Boolean?} compressed
 * @returns {Base58String}
 */

KeyPair.toSecret = function toSecret(privateKey, compressed, network) {
  var p = new BufferWriter();

  network = bcoin.network.get(network);
  p.writeU8(network.prefixes.privkey);
  p.writeBytes(privateKey);

  if (compressed !== false)
    p.writeU8(1);

  p.writeChecksum();

  return utils.toBase58(p.render());
};

/**
 * Parse a serialized CBitcoinSecret.
 * @param {Base58String} secret
 * @returns {Object} A "naked" keypair object.
 */

KeyPair.parseSecret = function parseSecret(secret) {
  var data = utils.fromBase58(secret);
  var p = new BufferReader(data, true);
  var compressed = false;
  var prefix, type, privateKey;

  prefix = p.readU8();

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.privkey;
    if (data.version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  privateKey = p.readBytes(32);

  if (p.left() > 4) {
    assert(p.readU8() === 1);
    compressed = true;
  }

  p.verifyChecksum();

  return {
    network: type,
    privateKey: privateKey,
    compressed: compressed
  };
};

/**
 * Instantiate a transaction from a serialized CBitcoinSecret.
 * @param {Base58String} secret
 * @returns {Keypair}
 */

KeyPair.fromSecret = function fromSecret(secret) {
  return new KeyPair(KeyPair.parseSecret(secret));
};

/**
 * Convert the keypair to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

KeyPair.prototype.toJSON = function toJSON(passphrase) {
  var json = {
    v: 1,
    name: 'keypair',
    encrypted: passphrase ? true : false
  };

  if (this.key.privateKey) {
    json.privateKey = passphrase
      ? utils.encrypt(this.toSecret(), passphrase).toString('hex')
      : this.toSecret();
    return json;
  }

  json.publicKey = this.getPublicKey('base58');

  return json;
};

/**
 * Handle a deserialized JSON keypair object.
 * @param {Object} json
 * @returns {Object} A "naked" keypair (a
 * plain javascript object which is suitable
 * for passing to the KeyPair constructor).
 */

KeyPair.parseJSON = function parseJSON(json, passphrase) {
  var privateKey, publicKey;

  assert.equal(json.v, 1);
  assert.equal(json.name, 'keypair');

  if (json.encrypted && !passphrase)
    throw new Error('Cannot decrypt key.');

  if (json.privateKey) {
    privateKey = json.privateKey;
    if (json.encrypted)
      privateKey = utils.decrypt(privateKey, passphrase).toString('utf8');
    return KeyPair.parseSecret(privateKey);
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

/**
 * Instantiate a transaction from a jsonified keypair object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {KeyPair}
 */

KeyPair.fromJSON = function fromJSON(json, passphrase) {
  return new KeyPair(KeyPair.parseJSON(json, passphrase));
};

module.exports = KeyPair;
