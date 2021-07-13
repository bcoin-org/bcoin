/*!
 * p224.js - ECDSA-P224 for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = require('./ecdsa');
const SHA256 = require('../sha256');

/*
 * Expose
 */

module.exports = new ECDSA('P224', SHA256, SHA256);
