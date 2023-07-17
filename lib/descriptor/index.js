/*!
 * descriptor/index.js - Output script descriptor for bcoin.
 * Copyright (c) 2023, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module descriptor
 */

const {parse} = require('./parser');

exports.AbstractDescriptor = require('./abstractdescriptor');
exports.parse = parse;
exports.PKDescriptor = require('./type/pk');
exports.PKHDescriptor = require('./type/pkh');
exports.WPKHDescriptor = require('./type/wpkh');
exports.SHDescriptor = require('./type/sh');
exports.WSHDescriptor = require('./type/wsh');
exports.ComboDescriptor = require('./type/combo');
exports.MultisigDescriptor = require('./type/multisig');
exports.RawDescriptor = require('./type/raw');
exports.AddressDescriptor = require('./type/addr');
exports.KeyProvider = require('./keyprovider');
exports.common = require('./common');
