/*!
 * walletkey.js - walletkey object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Address = require('../primitives/address');
const KeyRing = require('../primitives/keyring');
const Path = require('./path');

/**
 * Wallet Key
 * Represents a key ring which amounts to an address.
 * @alias module:wallet.WalletKey
 * @extends KeyRing
 */

class WalletKey extends KeyRing {
  /**
   * Create a wallet key.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    super(options);

    this.keyType = Path.types.HD;

    this.name = null;
    this.account = -1;
    this.branch = -1;
    this.index = -1;
  }

  /**
   * Convert an WalletKey to a more json-friendly object.
   * @returns {Object}
   */

  toJSON(network) {
    return {
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
      address: this.getAddress('string', network)
    };
  }

  /**
   * Inject properties from hd key.
   * @private
   * @param {Account} account
   * @param {HDPrivateKey|HDPublicKey} key
   * @param {Number} branch
   * @param {Number} index
   * @returns {WalletKey}
   */

  fromHD(account, key, branch, index) {
    this.keyType = Path.types.HD;
    this.name = account.name;
    this.account = account.accountIndex;
    this.branch = branch;
    this.index = index;
    this.witness = account.witness;
    this.nested = branch === 2;

    if (key.privateKey)
      return this.fromPrivate(key.privateKey);

    return this.fromPublic(key.publicKey);
  }

  /**
   * Instantiate a wallet key from hd key.
   * @param {Account} account
   * @param {HDPrivateKey|HDPublicKey} key
   * @param {Number} branch
   * @param {Number} index
   * @returns {WalletKey}
   */

  static fromHD(account, key, branch, index) {
    return new this().fromHD(account, key, branch, index);
  }

  /**
   * Inject properties from imported data.
   * @private
   * @param {Account} account
   * @param {Buffer} data
   * @returns {WalletKey}
   */

  fromImport(account, data) {
    this.keyType = Path.types.KEY;
    this.name = account.name;
    this.account = account.accountIndex;
    this.witness = account.witness;
    return this.fromRaw(data);
  }

  /**
   * Instantiate a wallet key from imported data.
   * @param {Account} account
   * @param {Buffer} data
   * @returns {WalletKey}
   */

  static fromImport(account, data) {
    return new this().fromImport(account, data);
  }

  /**
   * Inject properties from key.
   * @private
   * @param {Account} account
   * @param {KeyRing} ring
   * @returns {WalletKey}
   */

  fromRing(account, ring) {
    this.keyType = Path.types.KEY;
    this.name = account.name;
    this.account = account.accountIndex;
    this.witness = account.witness;
    return this.fromOptions(ring);
  }

  /**
   * Instantiate a wallet key from regular key.
   * @param {Account} account
   * @param {KeyRing} ring
   * @returns {WalletKey}
   */

  static fromRing(account, ring) {
    return new this().fromRing(account, ring);
  }

  /**
   * Convert wallet key to a path.
   * @returns {Path}
   */

  toPath() {
    const path = new Path();

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
  }

  /**
   * Test whether an object is a WalletKey.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isWalletKey(obj) {
    return obj instanceof WalletKey;
  }
}

/*
 * Expose
 */

module.exports = WalletKey;
