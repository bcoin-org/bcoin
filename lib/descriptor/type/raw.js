/*!
 * raw.js - raw descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AbstractDescriptor = require('../abstractdescriptor');
const common = require('../common');
const {isType, strip, checkChecksum, types, scriptContext} = common;
const Script = require('../../script/script');
const Network = require('../../protocol/network');
const assert = require('bsert');

/**
 * Raw Descriptor
 * Represents the script represented by HEX in input.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0385.mediawiki#raw
 * @property {String} type
 * @property {Script} script
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class RawDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.RAW;
    this.script = null;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {RawDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    if (options.type) {
      assert(options.type === types.RAW);
    }

    assert(this.subdescriptors.length === 0);
    assert(this.keyProviders.length === 0);
    assert(options.script, 'Must pass script');
    assert(options.script instanceof Script, 'Invalid script in raw()');

    this.script = options.script;

    return this;
  }

  /**
   * Instantiate raw descriptor from options object.
   * @param {Object} options
   * @returns {RawDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {RawDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    assert(isType(types.RAW, str), 'Invalid raw descriptor');
    assert(context === scriptContext.TOP, 'Can only have raw() at top level');

    str = strip(str);
    const script = Script.fromRaw(str, 'hex');
    assert(script.length, 'Raw script is not hex');

    this.script = script;
    this.network = Network.get(network);

    return this;
  }

  /**
   * Instantiate raw descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {RawDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }

  isSolvable() {
    return false;
  }

  toStringExtra() {
    return this.script.toJSON();
  }
}

/*
 * Expose
 */

module.exports = RawDescriptor;
