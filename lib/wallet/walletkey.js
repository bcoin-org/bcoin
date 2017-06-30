/*!
 * walletkey.js - walletkey object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const Address = require('../primitives/address');
const KeyRing = require('../primitives/keyring');
const Path = require('./path');

/**
 * Represents a key ring which amounts to an address.
 * @alias module:wallet.WalletKey
 * @constructor
 * @param {Object} options
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

util.inherits(WalletKey, KeyRing);

/**
 * Instantiate key ring from options.
 * @param {Object} options
 * @returns {WalletKey}
 */

WalletKey.fromOptions = function fromOptions(options) {
  return new WalletKey().fromOptions(options);
};

/**
 * Instantiate wallet key from a private key.
 * @param {Buffer} key
 * @param {Boolean?} compressed
 * @param {(NetworkType|Network)} network
 * @returns {WalletKey}
 */

WalletKey.fromPrivate = function fromPrivate(key, compressed, network) {
  return new WalletKey().fromPrivate(key, compressed, network);
};

/**
 * Generate a wallet key.
 * @param {(Network|NetworkType)?} network
 * @returns {WalletKey}
 */

WalletKey.generate = function generate(compressed, network) {
  return new WalletKey().generate(compressed, network);
};

/**
 * Instantiate wallet key from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network)} network
 * @returns {WalletKey}
 */

WalletKey.fromPublic = function fromPublic(key, network) {
  return new WalletKey().fromPublic(key, network);
};

/**
 * Instantiate wallet key from a public key.
 * @param {Buffer} publicKey
 * @param {(NetworkType|Network)} network
 * @returns {WalletKey}
 */

WalletKey.fromKey = function fromKey(key, compressed, network) {
  return new WalletKey().fromKey(key, compressed, network);
};

/**
 * Instantiate wallet key from script.
 * @param {Buffer} key
 * @param {Script} script
 * @param {(NetworkType|Network)} network
 * @returns {WalletKey}
 */

WalletKey.fromScript = function fromScript(key, script, compressed, network) {
  return new WalletKey().fromScript(key, script, compressed, network);
};

/**
 * Instantiate a wallet key from a serialized CBitcoinSecret.
 * @param {Base58String} secret
 * @param {Network?} network
 * @returns {WalletKey}
 */

WalletKey.fromSecret = function fromSecret(data, network) {
  return new WalletKey().fromSecret(data, network);
};

/**
 * Convert an WalletKey to a more json-friendly object.
 * @returns {Object}
 */

WalletKey.prototype.toJSON = function toJSON() {
  return {
    network: this.network.type,
    wid: this.wid,
    id: this.id,
    name: this.name,
    account: this.account,
    branch: this.branch,
    index: this.index,
    witness: this.witness,
    nested: this.nested,
    publicKey: this.publicKey.toString('hex'),
    script: this.script ? this.script.toRaw().toString('hex') : null,
    program: this.witness ? this.getProgram().toRaw().toString('hex') : null,
    type: Address.typesByVal[this.getType()].toLowerCase(),
    address: this.getAddress('string')
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
 * Instantiate a wallet key from serialized data.
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.fromRaw = function fromRaw(data) {
  return new WalletKey().fromRaw(data);
};

/**
 * Inject properties from hd key.
 * @private
 * @param {Account} account
 * @param {HDPrivateKey|HDPublicKey} key
 * @param {Number} branch
 * @param {Number} index
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
    return this.fromPrivate(key.privateKey, account.network);

  return this.fromPublic(key.publicKey, account.network);
};

/**
 * Instantiate a wallet key from hd key.
 * @param {Account} account
 * @param {HDPrivateKey|HDPublicKey} key
 * @param {Number} branch
 * @param {Number} index
 * @returns {WalletKey}
 */

WalletKey.fromHD = function fromHD(account, key, branch, index) {
  return new WalletKey().fromHD(account, key, branch, index);
};

/**
 * Inject properties from imported data.
 * @private
 * @param {Account} account
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.prototype.fromImport = function fromImport(account, data) {
  this.keyType = Path.types.KEY;
  this.id = account.id;
  this.wid = account.wid;
  this.name = account.name;
  this.account = account.accountIndex;
  this.witness = account.witness;
  return this.fromRaw(data, account.network);
};

/**
 * Instantiate a wallet key from imported data.
 * @param {Account} account
 * @param {Buffer} data
 * @returns {WalletKey}
 */

WalletKey.fromImport = function fromImport(account, data) {
  return new WalletKey().fromImport(account, data);
};

/**
 * Inject properties from key.
 * @private
 * @param {Account} account
 * @param {KeyRing} ring
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
 * Instantiate a wallet key from regular key.
 * @param {Account} account
 * @param {KeyRing} ring
 * @returns {WalletKey}
 */

WalletKey.fromRing = function fromRing(account, ring) {
  return new WalletKey().fromRing(account, ring);
};

/**
 * Convert wallet key to a path.
 * @returns {Path}
 */

WalletKey.prototype.toPath = function toPath() {
  let path = new Path();

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

/**
 * Test whether an object is a WalletKey.
 * @param {Object} obj
 * @returns {Boolean}
 */

WalletKey.isWalletKey = function isWalletKey(obj) {
  return obj
    && Buffer.isBuffer(obj.publicKey)
    && typeof obj.index === 'number'
    && typeof obj.toPath === 'function';
};

/*
 * Expose
 */

module.exports = WalletKey;
