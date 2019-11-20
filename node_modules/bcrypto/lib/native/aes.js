/*!
 * aes.js - aes for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding');

exports.native = 2;
exports.encipher = binding.aes.encipher;
exports.decipher = binding.aes.decipher;
