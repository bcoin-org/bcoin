/*!
 * walletkey.js - walletkey object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var constants = require('../protocol/constants');
var KeyRing = require('../primitives/keyring');
var utils = require('../utils/utils');

/**
 * Represents a key ring which amounts to an address.
 * @exports WalletKey
 * @constructor
 * @param {Object} options
 * @param {HDPrivateKey|HDPublicKey|Buffer} options.key
 * @param {Buffer[]} options.keys - Shared multisig keys.
 * @param {Number?} options.m - Multisig `m` value.
 * @param {Number?} options.n - Multisig `n` value.
 * @param {Boolean?} options.witness - Whether witness programs are enabled.
 */

function WalletKey(options, network) {
  if (!(this instanceof WalletKey))
    return new WalletKey(options, network);

  KeyRing.call(this, options, network);

  this.path = null;
}

utils.inherits(WalletKey, KeyRing);

/**
 * Instantiate key ring from options.
 * @param {Object} options
 * @returns {WalletKey}
 */

WalletKey.fromOptions = function fromOptions(options) {
  return new WalletKey().fromOptions(options);
};

/**
 * Instantiate keyring from a private key.
 * @param {Buffer} key
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network}) network
 * @returns {WalletKey}
 */

WalletKey.fromPrivate = function fromPrivate(key, compressed, network) {
  return new WalletKey().fromPrivate(key, compressed, network);
};

/**
 * Generate a keyring.
 * @param {(Network|NetworkType)?} network
 * @returns {WalletKey}
 */

WalletKey.generate = function(compressed, network) {
  return new WalletKey().generate(compressed, network);
};

/**
 * Instantiate keyring from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network}) network
 * @returns {WalletKey}
 */

WalletKey.fromPublic = function fromPublic(key, network) {
  return new WalletKey().fromPublic(key, network);
};

/**
 * Instantiate keyring from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network}) network
 * @returns {WalletKey}
 */

WalletKey.fromKey = function fromKey(key, compressed, network) {
  return new WalletKey().fromKey(key, compressed, network);
};

/**
 * Instantiate keyring from script.
 * @param {Buffer} key
 * @param {Script} script
 * @param {(NetworkType|Network}) network
 * @returns {WalletKey}
 */

WalletKey.fromScript = function fromScript(key, script, compressed, network) {
  return new WalletKey().fromScript(key, script, compressed, network);
};

/**
 * Instantiate a keyring from a serialized CBitcoinSecret.
 * @param {Base58String} secret
 * @returns {WalletKey}
 */

WalletKey.fromSecret = function fromSecret(data) {
  return new WalletKey().fromSecret(data);
};

/**
 * Convert an WalletKey to a more json-friendly object.
 * @returns {Object}
 */

WalletKey.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    witness: this.witness,
    publicKey: this.publicKey.toString('hex'),
    script: this.script ? this.script.toRaw().toString('hex') : null,
    type: constants.scriptTypesByVal[this.type].toLowerCase(),
    wid: this.path.wid,
    id: this.path.id,
    name: this.path.name,
    account: this.path.account,
    change: this.path.change,
    index: this.path.index,
    address: this.getAddress('base58'),
    programAddress: this.getProgramAddress('base58')
  };
};

/**
 * Instantiate an WalletKey from a jsonified transaction object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {WalletKey}
 */

WalletKey.fromJSON = function fromJSON(json) {
  return new WalletKey().fromJSON(json);
};

/**
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.fromRaw = function fromRaw(data) {
  return new WalletKey().fromRaw(data);
};

/**
 * Test whether an object is a WalletKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

WalletKey.isWalletKey = function isWalletKey(obj) {
  return obj
    && obj.path !== undefined
    && Buffer.isBuffer(obj.publicKey)
    && typeof obj.toSecret === 'function';
};

/*
 * Expose
 */

module.exports = WalletKey;
