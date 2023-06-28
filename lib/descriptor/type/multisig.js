/*!
 * multisig.js - multisig descriptor object for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const AbstractDescriptor = require('../abstractdescriptor');
const common = require('../common');
const {isType, strip, checkChecksum, scriptContext, types} = common;
const consensus = require('../../protocol/consensus');
const {MAX_SCRIPT_PUSH, MAX_MULTISIG_PUBKEYS} = consensus;
const KeyProvider = require('../keyprovider');
const Network = require('../../protocol/network');
const assert = require('bsert');

/**
 * MultisigDescriptor
 * Represents a multisig output script.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0383.mediawiki
 * @property {String} type
 * @property {KeyProvider[]} keyProviders
 * @property {Number} threshold
 * @property {Boolean} isSorted - true if descriptor is sortedmulti
 * @property {Network} network
 * @extends AbstractDescriptor
 */

class MultisigDescriptor extends AbstractDescriptor {
  /**
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();
    this.type = types.SORTEDMULTI;
    this.isSorted = false;
    this.threshold = 0;

    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @param {Object} options
   * @returns {MultisigDescriptor}
   */

  fromOptions(options) {
    this.parseOptions(options);

    assert(this.subdescriptors.length === 0);
    assert(this.keyProviders.length > 0, 'Must pass at least one pubkey');
    assert(typeof options.threshold === 'number');
    assert(typeof options.isSorted === 'boolean');

    if (options.type) {
      if (options.isSorted) {
        assert(options.type === types.SORTEDMULTI);
      } else {
        assert(options.type === types.MULTI);
      }
    }

    const m = options.threshold;
    const n = options.keyProviders.length;

    assert(
      (m & 0xff) === m && m > 0 && m <= MAX_MULTISIG_PUBKEYS,
      `Multisig threshold '${m}' is not valid`
    );

    assert(isValidMultisig(m, n, options.keyProviders));

    this.isSorted = options.isSorted;
    this.type = this.isSorted ? types.SORTEDMULTI : types.MULTI;
    this.threshold = options.threshold;

    return this;
  }

  /**
   * Instantiate multisig descriptor from options object.
   * @param {Object} options
   * @returns {MultisigDescriptor}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from string.
   * @param {String} str
   * @param {Network} network
   * @param {String} context
   * @returns {MultisigDescriptor}
   */

  fromString(str, network, context) {
    str = checkChecksum(str);

    const multisigTypes = [types.SORTEDMULTI, types.MULTI];
    const isMultisig = multisigTypes.some(type => isType(type, str));

    assert(isMultisig, 'Invalid multisig descriptor');

    const valid = [scriptContext.TOP, scriptContext.P2SH, scriptContext.P2WSH];

    assert(
       valid.includes(context),
      'Can only have multi/sortedmulti at top level, in sh(), or in wsh()'
    );

    const isSorted = isType(types.SORTEDMULTI, str); // check if sortedmulti
    str = strip(str);
    const descArray = str.split(',');

    const providers = []; // for storing KeyProviders of this multisig
    const threshold = descArray[0];
    const m = parseInt(threshold, 10); // threshold of multisig

    assert(
      (m & 0xff) === m && m > 0 && m <= MAX_MULTISIG_PUBKEYS,
      `Multisig threshold '${threshold}' is not valid`
    );

    for (let i = 1; i < descArray.length; i++) {
      const provider = KeyProvider.fromString(
        descArray[i],
        network,
        context
      );
      providers.push(provider);
    }

    // total number of keys in multisig
    const n = providers.length;

    assert(isValidMultisig(m, n, providers, context));

    this.type = isSorted ? types.SORTEDMULTI : types.MULTI;
    this.threshold = m;
    this.keyProviders = providers;
    this.isSorted = isSorted;
    this.network = Network.get(network);

    return this;
  }

  /**
   * Instantiate multisig descriptor from string.
   * @param {String} str
   * @param {Network} network
   * @param {String?} context
   * @returns {MultisigDescriptor}
   */

  static fromString(str, network, context = scriptContext.TOP) {
    return new this().fromString(str, network, context);
  }

  toStringExtra() {
    return this.threshold.toString();
  }
}

/**
 * Helpers
 */

/**
 * Check if multisig is valid.
 * @param {Number} m threshold of multisig
 * @param {Number} n total number of keys in multisig
 * @param {KeyProvider[]} providers parsed keys in multisig descriptor
 * @param {String} context script context
 * @returns
 */

function isValidMultisig(m, n, providers, context = scriptContext.TOP) {
    let scriptSize = 0;
    for (const provider of providers) {
      scriptSize = scriptSize + provider.getSize() + 1;
    }

  assert(
    n && n <= MAX_MULTISIG_PUBKEYS,
    `Keys in multisig must be between 1-${MAX_MULTISIG_PUBKEYS} inclusive`
  );

  assert(m <= n, `Threshold greater than number of keys (${m} > ${n})`);

  if (context === scriptContext.TOP) {
    assert(n <= 3, `At most 3 pubkeys allowed in bare multisig not ${n}`);
  }

  if (context === scriptContext.P2SH) {
    assert(
      scriptSize + 3 <= MAX_SCRIPT_PUSH,
      `P2SH script is too large (${scriptSize + 3} > ${MAX_SCRIPT_PUSH})`
    );
  }
  return true;
};

/*
 * Expose
 */

module.exports = MultisigDescriptor;
