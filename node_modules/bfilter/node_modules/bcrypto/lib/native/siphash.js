/*!
 * siphash.js - siphash for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const {siphash} = require('./binding');

siphash.native = 2;

/*
 * Expose
 */

module.exports = siphash;
