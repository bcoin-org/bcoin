/*!
 * base58.js - base58 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {base58} = require('./binding');

base58.native = 2;

/*
 * Expose
 */

module.exports = base58;
