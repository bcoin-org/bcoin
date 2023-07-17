/*!
 * combo.js - combo descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const AbstractDescriptor = require('../abstractdescriptor');
const common = require('../common');
const {isType, strip, checkChecksum, scriptContext, types} = common;
const KeyProvider = require('../keyprovider');
const Network = require('../../protocol/network');

/**
 * ComboDescriptor
 * Represents a P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH output scripts.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
 * @property {String} type
 * @property {KeyProvider[]} keyProviders
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class ComboDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.COMBO;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {ComboDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.COMBO);
    }

    assert(this.subdescriptors.length === 0);
    assert(
      this.keyProviders.length === 1,
      'Can only have one key inside combo()'
    );

    return this;
  }

  /**
   * Instantiate combo descriptor from options.
   * @param {Object} options
   * @returns {ComboDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {ComboDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.COMBO, str), 'Invalid combo descriptor');
    assert(context === scriptContext.TOP, 'Can only have combo() at top level');

    str = strip(str);
    const provider = KeyProvider.fromString(str, network, context);

    this.keyProviders = [provider];
    this.network = Network.get(network);

    return this;
  }

  /**
   * Instantiate combo descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {ComboDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }

  isSingleType() {
    return false;
  }

  isSolvable() {
    return true;
  }
}

/*
 * Expose
 */

module.exports = ComboDescriptor;
