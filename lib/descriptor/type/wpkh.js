/*!
 * wpkh.js - witness public key hash descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AbstractDescriptor = require('../abstractdescriptor');
const common = require('../common');
const {isType, strip, checkChecksum, types, scriptContext} = common;
const KeyProvider = require('../keyprovider');
const Network = require('../../protocol/network');
const assert = require('bsert');

/**
 * WPKHDescriptor
 * Represents a P2WPKH output script.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0382.mediawiki#wpkh
 * @property {String} type
 * @property {KeyProvider[]} keyProviders
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class WPKHDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.WPKH;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {WPKHDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.WPKH);
    }

    assert(this.subdescriptors.length === 0);
    assert(
      this.keyProviders.length === 1,
      'Can only have one key inside wpkh()'
    );

    return this;
  }

  /**
   * Instantiate wpkh descriptor from options object.
   * @param {Object} options
   * @returns {WPKHDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Instantiate wpkh descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {WPKHDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.WPKH, str), 'Invalid wpkh descriptor.');

    assert(
      [scriptContext.TOP, scriptContext.P2SH].includes(context),
      'Can only have wpkh() at top level or inside sh()'
    );

    str = strip(str);
    context = scriptContext.P2WPKH;
    const provider = KeyProvider.fromString(str, network, context);

    this.keyProviders = [provider];
    this.network = Network.get(network);

    return this;
  }

  /**
   * Instantiate wpkh descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {WPKHDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }
}

/*
 * Expose
 */

module.exports = WPKHDescriptor;
