/*!
 * p256.js - ECDSA-P256 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');
const SHA256 = require('../sha256');

/*
 * Expose
 */

module.exports = new ECDSA('P256', SHA256, SHA256);
