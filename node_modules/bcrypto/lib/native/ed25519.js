/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const EDDSA = require('./eddsa');

/*
 * Expose
 */

module.exports = new EDDSA('ED25519');
