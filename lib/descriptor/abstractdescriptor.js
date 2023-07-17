/*!
 * abstractdescriptor.js - abstract descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const common = require('./common');
const Network = require('../protocol/network');
const KeyProvider = require('./keyprovider');

/**
 * Constants
 */

/**
 * String type for key in a descriptor.
 * stringType.PUBLIC for descriptor with public key(s)
 * stringType.PRIVATE for descriptor with private key(s)
 * @const {Object}
 */

const stringType = {
  PUBLIC: 'PUBLIC',
  PRIVATE: 'PRIVATE'
};

/**
 * AbstractDescriptor
 * The class which all descriptor-like objects inherit from.
 * Represents an output script.
 * @alias module:descriptor.AbstractDescriptor
 * @see https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
 * @property {String} type - script expression of descriptor function.
 * @property {KeyProvider[]} keyProviders - parsed key arguments
 * for the descriptor
 * (size 1 for PK, PKH, WPKH; any size for WSH and Multisig).
 * @property {AbstractDescriptor[]} subdescriptors - sub-descriptor arguments
 * for the descriptor (empty for everything but SH and WSH)
 * @property {String} scriptContext
 * @property {Network} network
 */

class AbstractDescriptor {
  /**
   * Create a abstract descriptor.
   * @constructor
   */

  constructor() {
    this.type = null;
    this.keyProviders = [];
    this.subdescriptors = [];
    this.scriptContext = common.scriptContext.TOP;
    this.network = null;
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {AbstractDescriptor}
   */

  fromOptions(options) {
    throw new Error('Abstract method.');
  }

  /**
   * Inject properties from string.
   * @param {String} desc
   * @returns {AbstractDescriptor}
   */

  fromString(desc) {
    throw new Error('Abstract method.');
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  parseOptions(options) {
    assert(options, 'Required options for descriptor');

    this.network = Network.get(options.network);

    if (options.keyProviders) {
      assert(Array.isArray(options.keyProviders));
      for (const provider of options.keyProviders) {
        assert(provider instanceof KeyProvider);
        assert(provider.network === this.network);
      }
      this.keyProviders = options.keyProviders;
    }

    if (options.subdescriptors) {
      assert(Array.isArray(options.subdescriptors));
      for (const desc of options.subdescriptors) {
        assert(desc instanceof AbstractDescriptor);
        assert(desc.network === this.network);
      }
      this.subdescriptors = options.subdescriptors;
    }

    return this;
  }

  /**
   * Test whether the descriptor contains any private key.
   * @returns {Boolean}
   */

  hasPrivateKeys() {
    return this.keyProviders.some(key => key.hasPrivateKey())
      || this.subdescriptors.some(desc => desc.hasPrivateKeys());
  }

  /**
   * Test whether the descriptor contains public/private keys
   * in the form of HD chains
   * @returns {Boolean}
   */

  isRange() {
    return this.keyProviders.some(key => key.isRange())
      || this.subdescriptors.some(desc => desc.isRange());
  }

  /**
   * Whether this descriptor has all information about signing
   * (ignoring private keys).
   * Returns false only for `addr` and `raw` type.
   * @returns {Boolean}
   */

  isSolvable() {
    return this.subdescriptors.every(desc => desc.isSolvable());
  }

  /**
   * Get string form for address and raw descriptors.
   * Also returns threshold string for multisig.
   * Used once in toStringHelper()
   * @returns {String}
   */

  toStringExtra() {
    return '';
  }

  _toStringSubScript(type) {
    let res = '';
    let pos = 0;

    for (const subdesc of this.subdescriptors) {
      if (pos++) {
        res += ',';
      }
      res += subdesc._toString(type);
    }

    return res;
  }

  /**
   * Helper function to get a descriptor in string form based on string type
   * (Public, Private, Normalized)
   * @param {String} type
   * @returns {String}
   */

  _toString(type) {
    const extra = this.toStringExtra();
    let pos = extra.length === 0 ? 0 : 1;
    let res = this.type + '(' + extra;

    for (const provider of this.keyProviders) {
      if (pos++) {
        res += ',';
      }
      switch (type) {
        case stringType.PUBLIC:
          res += provider.toString();
          break;
        case stringType.PRIVATE: {
          const privkey = provider.toPrivateString();
          const pubkey = provider.toString();
          assert(privkey, `Private key not available for ${pubkey}`);
          res += privkey;
        }
      }
    }

    const subdesc = this._toStringSubScript(type);

    if (pos && subdesc.length) {
      res += ',';
    }

    res += subdesc + ')';
    return res;
  }

  /**
   * Get a descriptor string (public keys only)
   * @returns {String}
   */

  toString() {
    const res = this._toString(stringType.PUBLIC);
    return common.addChecksum(res);
  }

  /**
   * Get descriptor string including private keys if available
   * @returns {String}
   */

  toPrivateString() {
    const res = this._toString(stringType.PRIVATE);
    return common.addChecksum(res);
  }

  /**
   * Test whether this descriptor will return one scriptPubKey or
   * multiple (aka is or is not combo)
   * @returns {Boolean}
   */

  isSingleType() {
    return true;
  }

  /**
   * Get scripts for the descriptor at a specified position.
   * @param {Number} pos
   * @returns {Script[]}
   */

  generateScripts(pos) {
    const pubkeys = [];
    const subscripts = [];

    for (const subdesc of this.subdescriptors) {
      const outscripts = subdesc.generateScripts(pos);
      assert(outscripts.length === 1);
      subscripts.push(outscripts[0]);
    }

    for (const provider of this.keyProviders) {
      const pubkey = provider.getPublicKey(pos);
      pubkeys.push(pubkey);
    }

    return this._getScripts(pubkeys, subscripts);
  }

  /**
   * Get the scripts (helper function).
   * @returns {Script[]}
   */

  _getScripts() {
    throw new Error('Abstract method.');
  }

  /**
   * Derive addresses for the descriptor at a specified position.
   * @param {Number} pos
   * @returns {Address[]}
   */

  getAddresses(pos) {
    const scripts = this.generateScripts(pos);
    const addresses = [];

    for (const script of scripts) {
      const address = script.getAddress();
      assert(address, 'Descriptor does not have a corresponding address');
      addresses.push(address.toString(this.network));
    }

    return addresses;
  }
}

/*
 * Expose
 */

module.exports = AbstractDescriptor;
