/*!
 * x448.js - x448 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDH = require('./ecdh');

/*
 * Expose
 */

module.exports = new ECDH('X448');
