/*!
 * sh.js - script hash descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AbstractDescriptor = require('../abstractdescriptor');
const PKDescriptor = require('./pk');
const PKHDescriptor = require('./pkh');
const WPKHDescriptor = require('./wpkh');
const MultisigDescriptor = require('./multisig');
const WSHDescriptor = require('./wsh');
const assert = require('bsert');
const common = require('../common');
const {isType, strip, getType, scriptContext, checkChecksum, types} = common;

const Network = require('../../protocol/network');

/**
 * SHDescriptor
 * Represents a P2SH output script.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0381.mediawiki#sh
 * @property {String} type
 * @property {Descriptor[]} subdescriptors
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class SHDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.SH;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {SHDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.SH);
    }

    assert(this.keyProviders.length === 0);
    assert(
      this.subdescriptors.length === 1,
      'Must pass only 1 subdescriptor'
    );

    const subdesc = options.subdescriptors[0];
    const isValid = this.isValidSubdescriptor(subdesc.type);

    assert(isValid, `Can not have ${subdesc.type}() inside sh()`);

    return this;
  }

  /**
   * Instantiate sh descriptor from options object.
   * @param {Object} options
   * @returns {SHDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {SHDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.SH, str), 'Invalid sh descriptor.');
    assert(context === scriptContext.TOP, 'Can only have sh() at top level');

    str = strip(str);
    const subtype = getType(str);

    let subdesc = {};
    context = scriptContext.P2SH;

    switch (subtype) {
      case types.PK:
        subdesc = PKDescriptor.fromString(str, network, context);
        break;
      case types.PKH:
        subdesc = PKHDescriptor.fromString(str, network, context);
        break;
      case types.WPKH:
        subdesc = WPKHDescriptor.fromString(str, network, context);
        break;
      case types.WSH:
        subdesc = WSHDescriptor.fromString(str, network, context);
        break;
      case types.MULTI:
      case types.SORTEDMULTI:
        subdesc = MultisigDescriptor.fromString(str, network, context);
        break;
      default:
        if (Object.values(types).includes(subtype)) {
          throw new Error(`Can not have ${subtype}() inside sh()`);
        } else {
          throw new Error('A valid function is needed inside sh()');
        }
    }

    this.subdescriptors = [subdesc];
    this.network = Network.get(network);

    return this;
  }

  /**
   * Instantiate sh descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {SHDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }

  isValidSubdescriptor(type) {
    const validSubTypes = [
      types.PK,
      types.PKH,
      types.WPKH,
      types.MULTI,
      types.SORTEDMULTI,
      types.WSH
    ];

    return validSubTypes.includes(type);
  }
}

/*
 * Expose
 */

module.exports = SHDescriptor;
