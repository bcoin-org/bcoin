/*!
 * pk.js - public key descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AbstractDescriptor = require('../abstractdescriptor');
const common = require('../common');
const {isType, strip, checkChecksum, scriptContext, types} = common;
const assert = require('bsert');
const KeyProvider = require('../keyprovider');
const Network = require('../../protocol/network');
const Script = require('../../script/script');

/**
 * PKDescriptor
 * Represents a P2PK output script.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki#pk
 * @property {String} type
 * @property {String} scriptContext
 * @property {KeyProvider[]} keyProviders
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class PKDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.PK;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {PKDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.PK);
    }

    assert(this.subdescriptors.length === 0);
    assert(
      this.keyProviders.length === 1,
      'Can only have one key inside pk()'
    );

    return this;
  }

  /**
   * Instantiate pk descriptor from options object.
   * @param {Object} options
   * @returns {PKDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {PKDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.PK, str), 'Invalid pk descriptor');

    str = strip(str);
    const provider = KeyProvider.fromString(str, network, context);

    this.keyProviders = [provider];
    this.network = Network.get(network);
    this.scriptContext = context;

    return this;
  }

  /**
   * Instantiate pk descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {PKDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }

  /**
   * Get the scripts (helper function).
   * @param {Buffer[]} pubkeys
   * @returns {Script[]}
   */

  _getScripts(pubkeys) {
    assert(Array.isArray(pubkeys) && pubkeys.length === 1);
    assert(Buffer.isBuffer(pubkeys[0]));

    return [Script.fromPubkey(pubkeys[0])];
  }
}

/*
 * Expose
 */

module.exports = PKDescriptor;
