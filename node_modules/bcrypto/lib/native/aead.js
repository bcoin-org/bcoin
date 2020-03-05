/*!
 * aead.js - aead for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {AEAD} = require('./binding');

AEAD.native = 2;

/*
 * Expose
 */

module.exports = AEAD;
