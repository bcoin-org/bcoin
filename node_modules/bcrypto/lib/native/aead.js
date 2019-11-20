/*!
 * aead.js - aead for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {AEAD} = require('./binding');

AEAD.native = 2;

module.exports = AEAD;
