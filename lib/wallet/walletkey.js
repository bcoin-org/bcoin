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
var Path = require('./path');

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

  this.keyType = Path.types.HD;

  this.id = null;
  this.wid = -1;
  this.name = null;
  this.account = -1;
  this.branch = -1;
  this.index = -1;
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
    nested: this.nested,
    publicKey: this.publicKey.toString('hex'),
    script: this.script ? this.script.toRaw().toString('hex') : null,
    program: this.program ? this.program.toRaw().toString('hex') : null,
    type: constants.scriptTypesByVal[this.type].toLowerCase(),
    wid: this.wid,
    id: this.id,
    name: this.name,
    account: this.account,
    branch: this.branch,
    index: this.index,
    address: this.getAddress('base58')
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
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.prototype.fromHD = function fromHD(account, key, branch, index) {
  this.keyType = Path.types.HD;
  this.id = account.id;
  this.wid = account.wid;
  this.name = account.name;
  this.account = account.accountIndex;
  this.branch = branch;
  this.index = index;
  this.witness = account.witness;
  this.nested = branch === 2;

  if (key.privateKey)
    return this.fromPrivate(key.privateKey, key.network);

  return this.fromPublic(key.publicKey, key.network);
};

/**
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.fromHD = function fromHD(account, key, branch, index) {
  return new WalletKey().fromHD(account, key, branch, index);
};

/**
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.prototype.fromImport = function fromImport(account, data, network) {
  this.keyType = Path.types.KEY;
  this.id = account.id;
  this.wid = account.wid;
  this.name = account.name;
  this.account = account.accountIndex;
  this.witness = account.witness;
  return this.fromRaw(data, network);
};

/**
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.fromImport = function fromImport(account, data, network) {
  return new WalletKey().fromImport(account, data, network);
};

/**
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.prototype.fromRing = function fromRing(account, ring) {
  this.keyType = Path.types.KEY;
  this.id = account.id;
  this.wid = account.wid;
  this.name = account.name;
  this.account = account.accountIndex;
  this.witness = account.witness;
  return this.fromOptions(ring, ring.network);
};

/**
 * Instantiate a keyring from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.fromRing = function fromRing(account, ring) {
  return new WalletKey().fromRing(account, ring);
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

/**
 * Test whether an object is a WalletKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

WalletKey.prototype.toPath = function toPath() {
  var path = new Path();

  path.id = this.id;
  path.wid = this.wid;
  path.name = this.name;
  path.account = this.account;

  switch (this.keyType) {
    case Path.types.HD:
      path.branch = this.branch;
      path.index = this.index;
      break;
    case Path.types.KEY:
      path.data = this.toRaw();
      break;
  }

  path.keyType = this.keyType;

  path.version = this.getVersion();
  path.type = this.getType();
  path.hash = this.getHash('hex');

  return path;
};

/*
 * Expose
 */

module.exports = WalletKey;
