/*!
 * addr.js - address descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AbstractDescriptor = require('../abstractdescriptor');
const assert = require('bsert');
const common = require('../common');
const {isType, strip, checkChecksum, scriptContext, types} = common;
const Address = require('../../primitives/address');
const Network = require('../../protocol/network');

/**
 * AddressDescriptor
 * Represents the output script produced by the address in the descriptor.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0385.mediawiki#addr
 * @property {String} type
 * @property {Address} address
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class AddressDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.ADDR;
    this.address = null;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {AddressDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.ADDR);
    }

    assert(options.address instanceof Address, 'Invalid address in descriptor');
    assert(this.subdescriptors.length === 0);
    assert(this.keyProviders.length === 0);

    this.address = options.address;

    return this;
  }

  /**
   * Instantiate address descriptor from options.
   * @param {Object} options
   * @returns {AddressDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {AddressDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.ADDR, str), 'Invalid addr descriptor');
    assert(context === scriptContext.TOP, 'Can only have addr() at top level');

    this.network = Network.get(network);

    str = strip(str);
    const address = Address.fromString(str, this.network);

    this.address = address;

    return this;
  }

  /**
   * Instantiate address descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {AddressDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }

  toPrivateString() {
    return null;
  }

  toStringExtra() {
    return this.address.toString(this.network);
  }

  isSolvable() {
    return false;
  }
}

/*
 * Expose
 */

module.exports = AddressDescriptor;
