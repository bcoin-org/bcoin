/*!
 * wsh.js - witness script hash descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AbstractDescriptor = require('../abstractdescriptor');
const PKDescriptor = require('./pk');
const PKHDescriptor = require('./pkh');
const MultisigDescriptor = require('./multisig');
const assert = require('bsert');
const common = require('../common');
const {isType, getType, strip, scriptContext, checkChecksum, types} = common;
const Network = require('../../protocol/network');
const Script = require('../../script/script');

/**
 * WSHDescriptor
 * Represents a P2WSH output script.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0382.mediawiki#wsh
 * @property {String} type
 * @property {String} scriptContext
 * @property {Descriptor[]} subdescriptors - Subdescriptors
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class WSHDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.WSH;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {WSHDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.WSH);
    }

    assert(this.keyProviders.length === 0);
    assert(
      this.subdescriptors.length === 1,
      'Must pass only 1 subdescriptor'
    );

    const subdesc = options.subdescriptors[0];
    subdesc.scriptContext = scriptContext.P2WSH;
    const isValid = this.isValidSubdescriptor(subdesc.type);

    assert(isValid, `Can not have ${subdesc.type}() inside sh()`);

    return this;
  }

  /**
   * Instantiate wsh descriptor from options object.
   * @param {Object} options
   * @returns {WSHDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {WSHDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.WSH, str), 'Invalid WSH descriptor');
    assert(
      [scriptContext.TOP, scriptContext.P2SH].includes(context),
      'Can only have wsh() at top level or inside sh()'
    );

    str = strip(str);
    const subtype = getType(str);
    let subdesc = {};
    this.scriptContext = context;
    context = scriptContext.P2WSH;

    switch (subtype) {
      case types.PK:
        subdesc = PKDescriptor.fromString(str, network, context);
        break;
      case types.PKH:
        subdesc = PKHDescriptor.fromString(str, network, context);
        break;
      case types.MULTI:
      case types.SORTEDMULTI:
        subdesc = MultisigDescriptor.fromString(str, network, context);
        break;
      default:
        if (Object.values(types).includes(subtype)) {
          throw new Error(`Can not have ${subtype}() inside wsh()`);
        } else {
          throw new Error('A valid function is needed inside wsh()');
        }
    }

    this.subdescriptors = [subdesc];
    this.network = Network.get(network);

    return this;
  }

  /**
   * Instantiate wsh descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {WSHDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }

  isValidSubdescriptor(type) {
    const validSubTypes = [
      types.PK,
      types.PKH,
      types.MULTI,
      types.SORTEDMULTI
    ];

    return validSubTypes.includes(type);
  }

  /**
   * Get the scripts (helper function).
   * @param {Buffer[]} pubkeys
   * @param {Script} subscripts
   * @returns {Script[]}
   */

  _getScripts(pubkeys, subscripts) {
    assert(Array.isArray(pubkeys) && pubkeys.length === 0);
    assert(Array.isArray(subscripts) && subscripts.length === 1);
    assert(subscripts[0] instanceof Script);

    return [(Script.fromProgram(0, subscripts[0].sha256()))];
  }
}

/*
 * Expose
 */

module.exports = WSHDescriptor;
