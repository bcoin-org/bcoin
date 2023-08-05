/*!
 * pkh.js - public key hash descriptor object for bcoin
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
const hash160 = require('bcrypto/lib/hash160');
const Script = require('../../script/script');

/**
 * PKHDescriptor
 * Represents a P2PKH output script.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki#pkh
 * @property {String} type
 * @property {String} scriptContext
 * @property {Network} network
 * @property {KeyProvider[]} keyProviders
 * @extends AbstractDescriptor
 */

class PKHDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.PKH;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {PKHDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.PKH);
    }

    assert(this.subdescriptors.length === 0);
    assert(
      this.keyProviders.length === 1,
      'Can only have one key inside pkh()'
    );

    return this;
  }

  /**
   * Instantiate pkh descriptor from options object.
   * @param {Object} options
   * @returns {PKHDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Instantiate pkh descriptor from a string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {PKHDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.PKH, str), 'Invalid pkh descriptor');

    const valid = [scriptContext.TOP, scriptContext.P2SH, scriptContext.P2WSH];

    assert(
      valid.includes(context),
      'Can only have pkh() at top level, in sh(), or in wsh()'
    );

    str = strip(str);
    const provider = KeyProvider.fromString(str, network, context);

    this.keyProviders = [provider];
    this.network = Network.get(network);
    this.scriptContext = context;

    return this;
  }

  /**
   * Instantiate pkh descriptor from a string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {PKHDescriptor}
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

    const pubkeyhash = hash160.digest(pubkeys[0]);
    return [Script.fromPubkeyhash(pubkeyhash)];
  }
}

/*
 * Expose
 */

module.exports = PKHDescriptor;
