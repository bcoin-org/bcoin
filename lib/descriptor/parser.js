/*!
 * parser.js -  descriptor parser for bcoin
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const PKDescriptor = require('./type/pk');
const PKHDescriptor = require('./type/pkh');
const WPKHDescriptor = require('./type/wpkh');
const SHDescriptor = require('./type/sh');
const WSHDescriptor = require('./type/wsh');
const ComboDescriptor = require('./type/combo');
const AddressDescriptor = require('./type/addr');
const MultisigDescriptor = require('./type/multisig');
const RawDescriptor = require('./type/raw');
const common = require('./common');
const assert = require('bsert');
const {getType, checkChecksum, types} = common;

/**
 * Parse the descriptor string based on script expression.
 * @param {String} desc
 * @param {Network} network
 * @returns {Descriptor}
 * @throws parse error
 */

function parseType(desc, network) {
  const type = getType(desc);

  switch (type) {
    case types.PK:
      return PKDescriptor.fromString(desc, network);
    case types.PKH:
      return PKHDescriptor.fromString(desc, network);
    case types.WPKH:
      return WPKHDescriptor.fromString(desc, network);
    case types.SH:
      return SHDescriptor.fromString(desc, network);
    case types.WSH:
      return WSHDescriptor.fromString(desc, network);
    case types.COMBO:
      return ComboDescriptor.fromString(desc, network);
    case types.ADDR:
      return AddressDescriptor.fromString(desc, network);
    case types.MULTI:
    case types.SORTEDMULTI:
      return MultisigDescriptor.fromString(desc, network);
    case types.RAW:
      return RawDescriptor.fromString(desc, network);
    default:
      throw new Error(`'${desc}' is not a valid descriptor function`);
  }
};

/**
 * Initial step for parsing a descriptor from string.
 * @param {String} desc
 * @param {Network} network
 * @param {Boolean} requireChecksum
 * @returns {Descriptor} return the parsed descriptor object
 * @throws parse error
 */

exports.parse = function parse(desc, network, requireChecksum) {
  assert(typeof desc === 'string');
  desc = checkChecksum(desc, requireChecksum);
  return parseType(desc, network);
};
